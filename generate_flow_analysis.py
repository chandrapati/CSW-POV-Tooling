#!/usr/bin/env python3
"""
generate_flow_analysis.py — CSW Deep Flow Analysis Report
----------------------------------------------------------
Queries the CSW flow search API for a live sample of flows and generates
a self-contained HTML report with deep analysis:

  - Policy verdicts (PERMITTED / REJECTED / ESCAPED)
  - Protocol distribution with visual bars
  - TCP performance (handshake times, retransmissions, latency)
  - TLS version and cipher suite analysis (weak cipher detection)
  - Rejected flow detail table
  - Top destination ports with known service names and risk flags
  - Top consumer-to-provider scope pairs
  - Top source-to-destination host pairs
  - Process strings observed in flows
  - Named user accounts observed in flows

Usage:
    python3 generate_flow_analysis.py
    python3 generate_flow_analysis.py --limit 5000
    python3 generate_flow_analysis.py --hours 48 --out reports/flow-48h.html

Requirements:
    csw_api.py in the same directory with .env credentials configured.
    API key must have flow_inventory_query capability.
"""

import json
import os
import sys
import time
import argparse
from datetime import datetime, timezone
from collections import Counter, defaultdict

# Ensure csw_api.py (sibling module) is importable regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csw_api

# Load .env file so CSW_API_URL / CSW_API_KEY / CSW_API_SECRET are available
csw_api._load_dotenv()

# ──────────────────────────────────────────────────────────────
# Lookup tables for port/protocol labelling and risk flagging
# ──────────────────────────────────────────────────────────────

# Maps numeric port → human-readable service name for the report tables
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5985: "WinRM",
    5986: "WinRM-S", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "Prometheus",
    27017: "MongoDB",
}

# Ports flagged with a red RISK badge in the report — remote admin and DB ports
# that should not be broadly exposed
RISKY_PORTS = {
    22, 23, 20, 21, 25, 139, 445, 1433, 1521, 3306, 3389, 5432,
}

# TLS versions considered insecure — flagged as WEAK in the TLS analysis section
WEAK_TLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}

# Cipher suite substrings that indicate weak encryption algorithms
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}

# IP protocol number → readable name (CSW returns numeric proto field)
PROTO_MAP = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}


# ──────────────────────────────────────────────────────────────
# API interaction helpers
# ──────────────────────────────────────────────────────────────


def get_root_scope():
    """
    Discover the cluster root scope name dynamically.

    The root scope is identified as the one with no parent_app_scope_id.
    Falls back to "Default" if the API call fails or no root is found,
    which is the conventional root scope name on most CSW clusters.
    """
    r = csw_api.make_request("GET", "/openapi/v1/app_scopes")
    if r.get("status") != 200:
        return "Default"
    scopes = r.get("data", [])
    if not isinstance(scopes, list):
        return "Default"
    # The root scope has no parent — it sits at the top of the scope hierarchy
    root = next((s for s in scopes if isinstance(s, dict) and not s.get("parent_app_scope_id")), None)
    return root["name"] if root else "Default"


def fetch_flows(root_scope, hours, limit):
    """
    Download flows from the cluster in paginated batches via /openapi/v1/flowsearch.

    The flowsearch API requires:
      - t0/t1: epoch integer timestamps defining the time window
      - scopeName: root scope for the query context
      - filter: a subnet filter (0.0.0.0/0 matches all source addresses)
      - limit: max results per page (API caps at 100)
      - offset: opaque pagination cursor returned by the previous page

    Returns a list of flow dicts up to `limit` total.
    """
    t1 = int(time.time())
    t0 = t1 - (hours * 3600)
    # API maximum per page is 100; respect that ceiling
    batch_size = min(limit, 100)

    all_flows = []
    offset = ""
    page = 0

    while len(all_flows) < limit:
        page += 1
        body = {
            "t0": t0, "t1": t1,
            # Wildcard subnet filter — matches every flow in the scope
            "filter": {"type": "subnet", "field": "src_address", "value": "0.0.0.0/0"},
            "scopeName": root_scope,
            "limit": batch_size,
        }
        # Include pagination cursor from the previous page response
        if offset:
            body["offset"] = offset

        r = csw_api.make_request("POST", "/openapi/v1/flowsearch", body=body)
        if r.get("status") != 200:
            print(f"    Flow search returned HTTP {r.get('status')} — stopping.", file=sys.stderr)
            break

        data = r.get("data", {})
        if not isinstance(data, dict):
            break

        results = data.get("results", [])
        if not results:
            break

        all_flows.extend(results)
        print(f"\r    Page {page}: +{len(results)} flows (total: {len(all_flows):,})", end="", flush=True, file=sys.stderr)

        # Stop if we got fewer results than requested (last page) or no cursor
        if len(results) < batch_size or not data.get("offset"):
            break
        offset = data.get("offset", "")
        # Brief delay between pages to avoid API rate-limiting
        time.sleep(0.15)

    print(file=sys.stderr)
    return all_flows[:limit]


# ──────────────────────────────────────────────────────────────
# Flow data analysis
# ──────────────────────────────────────────────────────────────

def shorten_scope(name):
    """
    Extract the leaf segment from a colon-separated scope path.

    CSW scope names are hierarchical (e.g. "Root:Internal:AppScope").
    For readability we display only the last segment ("BuilderApps").
    """
    return name.split(":")[-1] if name else "?"


def analyse(flows):
    """
    Perform deep multi-dimensional analysis on a list of raw flow dicts.

    Examines every flow across 10 dimensions:
      1. Policy verdicts (fwd/rev PERMITTED/REJECTED/ESCAPED)
      2. Protocol distribution (TCP, UDP, ICMP, etc.)
      3. Destination port frequency and risk classification
      4. TCP performance (handshake latency, retransmissions)
      5. TLS version and cipher suite security posture
      6. Consumer → Provider scope traffic pairs
      7. Source → Destination host pair volumes
      8. Total byte volume transferred
      9. Process strings (agent-reported executable names)
     10. Named user accounts observed in Windows flow metadata

    Returns a dict keyed by section name for use by render_html().
    """
    total = len(flows)

    # ── Policy verdict accumulators ──
    fwd_permitted = fwd_rejected = fwd_escaped = 0
    rev_permitted = rev_rejected = 0

    # ── Frequency counters for distribution analysis ──
    proto_counter = Counter()      # IP protocol name → count
    port_counter = Counter()       # destination port number → count
    scope_pairs = Counter()        # (src_scope_leaf, dst_scope_leaf) → count
    host_pairs = Counter()         # (src_host, dst_host, proto/svc) → count
    tls_versions = Counter()       # TLS version string → count
    cipher_suites = Counter()      # cipher suite name → count
    weak_tls_flows = []            # individual flows using deprecated TLS/ciphers
    rejected_flows = []            # individual flows with REJECTED verdict
    process_counter = Counter()    # process executable name → count
    user_counter = Counter()       # Windows user account → count

    # ── TCP performance metrics ──
    tcp_count = 0
    tcp_handshake_us = []          # list of handshake RTT values in microseconds
    tcp_retrans = 0                # cumulative retransmission count
    tcp_high_lat = 0               # flows with handshake > 50ms threshold
    total_bytes = 0

    for f in flows:
        # ── 1. Protocol identification ──
        proto_num = f.get("proto", 0)
        proto_name = PROTO_MAP.get(proto_num, str(proto_num))
        proto_counter[proto_name] += 1

        dst_port = f.get("dst_port", 0)
        if dst_port:
            port_counter[dst_port] += 1

        # ── 2. Policy verdicts (forward and reverse directions) ──
        # CSW evaluates policy in both directions; "ESCAPED" means the flow
        # didn't match any explicit policy and fell through to the catch-all.
        fwd = f.get("fwd_policy_id", "")
        fwd_act = (f.get("fwd_policy_action") or "").upper()
        if "REJECT" in fwd_act:
            fwd_rejected += 1
            rejected_flows.append(f)
        elif "ESCAPE" in fwd_act:
            fwd_escaped += 1
        else:
            fwd_permitted += 1

        rev_act = (f.get("rev_policy_action") or "").upper()
        if "REJECT" in rev_act:
            rev_rejected += 1
        else:
            rev_permitted += 1

        # ── 3. Scope pair extraction ──
        # src_scope_name can be a string OR a list of strings depending on
        # the cluster version — handle both forms gracefully.
        src_scope = shorten_scope(f.get("src_scope_name", "") if isinstance(f.get("src_scope_name"), str)
                                   else (f.get("src_scope_name", [""])[0] if isinstance(f.get("src_scope_name"), list) and f.get("src_scope_name") else ""))
        dst_scope = shorten_scope(f.get("dst_scope_name", "") if isinstance(f.get("dst_scope_name"), str)
                                   else (f.get("dst_scope_name", [""])[0] if isinstance(f.get("dst_scope_name"), list) and f.get("dst_scope_name") else ""))
        if src_scope and dst_scope:
            scope_pairs[(src_scope, dst_scope)] += 1

        # ── 4. Host pair tracking ──
        # Prefer hostname over raw IP for readability in reports
        src_host = f.get("src_hostname") or f.get("src_address", "?")
        dst_host = f.get("dst_hostname") or f.get("dst_address", "?")
        svc = WELL_KNOWN_PORTS.get(dst_port, str(dst_port)) if dst_port else "?"
        host_pairs[(src_host, dst_host, f"{proto_name}/{svc}")] += 1

        # ── 5. Byte volume ──
        # Combine forward and reverse packet bytes for total transfer volume
        total_bytes += (f.get("fwd_pkts_bytes", 0) or 0) + (f.get("rev_pkts_bytes", 0) or 0)

        # ── 6. TCP performance metrics ──
        if proto_num == 6:
            tcp_count += 1
            # srtt_usec = smoothed round-trip time in microseconds (TCP handshake)
            hs = f.get("srtt_usec", 0) or 0
            if hs > 0:
                tcp_handshake_us.append(hs)
            # Sum both directions' retransmission counts
            tcp_retrans += (f.get("fwd_tcp_retransmit_count", 0) or 0) + (f.get("rev_tcp_retransmit_count", 0) or 0)
            # 50ms threshold flags potentially problematic latency
            if hs > 50000:
                tcp_high_lat += 1

        # ── 7. TLS version and cipher suite security analysis ──
        # CSW may report TLS info from either client or server side
        tls_ver = f.get("tls_client_version") or f.get("tls_server_version") or ""
        if tls_ver:
            tls_versions[tls_ver] += 1
        cipher = f.get("tls_server_cipher_suite") or ""
        if cipher:
            cipher_suites[cipher] += 1
        # Flag flows using deprecated TLS versions or weak cipher algorithms
        if tls_ver in WEAK_TLS or any(w in cipher.upper() for w in WEAK_CIPHERS):
            if tls_ver or cipher:
                weak_tls_flows.append(f)

        # ── 8. Process string extraction ──
        # CSW agents report the process name on both src and dst endpoints
        for side in ("src", "dst"):
            ps = f.get(f"{side}_process_name") or ""
            if ps and ps not in ("", "unknown"):
                process_counter[ps] += 1

        # ── 9. Windows user account extraction ──
        # Filter out built-in system accounts that are not actionable
        for side in ("src", "dst"):
            user = f.get(f"user_{side}_UserName_Windows") or f.get(f"user_{side}_username") or ""
            if user and user not in ("", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                user_counter[user] += 1

    # ── Aggregate TCP performance statistics ──
    avg_hs = int(sum(tcp_handshake_us) / len(tcp_handshake_us)) if tcp_handshake_us else 0
    max_hs = max(tcp_handshake_us) if tcp_handshake_us else 0

    def fmt_bytes(b):
        """Format byte count into human-readable units (KB/MB/GB)."""
        if b >= 1_000_000_000:
            return f"{b/1_000_000_000:.1f} GB"
        if b >= 1_000_000:
            return f"{b/1_000_000:.1f} MB"
        if b >= 1_000:
            return f"{b/1_000:.1f} KB"
        return f"{b} B"

    tls_total = sum(tls_versions.values())

    return {
        "total": total,
        "fwd_permitted": fwd_permitted, "fwd_rejected": fwd_rejected, "fwd_escaped": fwd_escaped,
        "rev_permitted": rev_permitted, "rev_rejected": rev_rejected,
        "proto_counter": proto_counter,
        "port_counter": port_counter,
        "scope_pairs": scope_pairs,
        "host_pairs": host_pairs,
        "tcp_count": tcp_count, "tcp_hs_count": len(tcp_handshake_us),
        "avg_hs": avg_hs, "max_hs": max_hs,
        "tcp_retrans": tcp_retrans, "tcp_high_lat": tcp_high_lat,
        "tls_total": tls_total, "tls_versions": tls_versions,
        "cipher_suites": cipher_suites, "weak_tls_flows": weak_tls_flows,
        "rejected_flows": rejected_flows,
        "process_counter": process_counter,
        "user_counter": user_counter,
        "total_bytes": fmt_bytes(total_bytes),
    }


# ──────────────────────────────────────────────────────────────
# HTML report rendering
# ──────────────────────────────────────────────────────────────

def render_html(stats, cluster, scope, hours, generated):
    """
    Build a self-contained HTML flow analysis report from analysed stats.

    The report uses:
      - Inter font for body text, Fira Code for code/cipher strings
      - Cisco brand colours (#005073 header, #0EA5E9 accent)
      - CSS grid layout with responsive breakpoints
      - Print-friendly @media query for PDF export
      - No external JS dependencies — fully self-contained

    Args:
        stats:     dict returned by analyse()
        cluster:   cluster hostname for the page title
        scope:     root scope name used for the flow query
        hours:     lookback window in hours
        generated: timestamp string for the report footer
    """
    s = stats

    # ── KPI summary row (top of report) ──
    # Each tuple: (css_class, value, label)
    kpis = [
        ("", s["total"], "Flows Sampled"),
        ("ok", s["fwd_permitted"], "Fwd PERMITTED"),
        ("warn" if s["fwd_rejected"] else "ok", s["fwd_rejected"], "Fwd REJECTED"),
        ("ok", s["fwd_escaped"], "Fwd ESCAPED"),
        ("", s["tls_total"], "TLS Flows"),
        ("warn" if s["weak_tls_flows"] else "ok", len(s["weak_tls_flows"]), "Weak TLS Flows"),
        ("", s["tcp_count"], "TCP Flows"),
        ("warn" if s["tcp_retrans"] else "ok", s["tcp_retrans"], "TCP Retransm."),
        ("ok", s["tcp_high_lat"], "High-Lat >50ms"),
        ("", s["total_bytes"], "Total Bytes"),
        ("", len(s["process_counter"]), "Process-tagged"),
    ]
    # Build KPI cards — use :, formatting for integers, plain for strings (e.g. "102.4 MB")
    kpi_html = ""
    for cls, val, lbl in kpis:
        kpi_html += f'<div class="kpi {cls}"><div class="val">{val:,}</div><div class="lbl">{lbl}</div></div>' if isinstance(val, int) else f'<div class="kpi {cls}"><div class="val">{val}</div><div class="lbl">{lbl}</div></div>'

    # ── Protocol distribution bar chart ──
    # Bars are scaled relative to the most common protocol
    proto_max = max(s["proto_counter"].values()) if s["proto_counter"] else 1
    proto_html = ""
    for name, cnt in s["proto_counter"].most_common():
        pct = int(cnt / proto_max * 100)
        proto_html += f'<div class="bar-row"><span class="bar-lbl">{name}</span><div class="bar-wrap"><div class="bar" style="width:{pct}%"></div></div><span class="bar-val">{cnt:,}</span></div>'

    # ── Policy verdicts table ──
    # Pre-build badge HTML outside the f-string (Python <3.12 cannot use
    # backslash-escaped quotes inside f-string expressions)
    ok_badge = '<span class="badge badge-ok">ok</span>'
    err_badge = '<span class="badge badge-err">alert</span>'
    fwd_p_b = ok_badge if s["fwd_permitted"] else ""
    fwd_r_b = err_badge if s["fwd_rejected"] else ""
    rev_r_b = err_badge if s["rev_rejected"] else ""
    verdict_rows = (
        f"<tr><td>Forward</td><td>PERMITTED</td><td>{s['fwd_permitted']:,}</td><td>{fwd_p_b}</td></tr>"
        f"<tr><td>Forward</td><td>REJECTED</td><td>{s['fwd_rejected']:,}</td><td>{fwd_r_b}</td></tr>"
        f"<tr><td>Forward</td><td>ESCAPED</td><td>{s['fwd_escaped']:,}</td><td></td></tr>"
        f"<tr><td>Reverse</td><td>PERMITTED</td><td>{s['rev_permitted']:,}</td><td></td></tr>"
        f"<tr><td>Reverse</td><td>REJECTED</td><td>{s['rev_rejected']:,}</td><td>{rev_r_b}</td></tr>"
    )

    # ── TCP performance KPI cards ──
    # Avg handshake > 20ms and max > 1s trigger "warn" highlighting
    tcp_html = f"""<div class="kpi-grid">
      <div class="kpi"><div class="val">{s['tcp_count']:,}</div><div class="lbl">TCP Flows</div></div>
      <div class="kpi"><div class="val">{s['tcp_hs_count']:,}</div><div class="lbl">With Handshake Data</div></div>
      <div class="kpi {'warn' if s['avg_hs'] > 20000 else ''}"><div class="val">{s['avg_hs']:,} us</div><div class="lbl">Avg Handshake</div></div>
      <div class="kpi {'warn' if s['max_hs'] > 1000000 else ''}"><div class="val">{s['max_hs']:,} us</div><div class="lbl">Max Handshake</div></div>
      <div class="kpi {'warn' if s['tcp_retrans'] else 'ok'}"><div class="val">{s['tcp_retrans']:,}</div><div class="lbl">Retransmissions</div></div>
      <div class="kpi ok"><div class="val">{s['tcp_high_lat']:,}</div><div class="lbl">High Latency (>50ms)</div></div>
    </div>"""

    # ── TLS versions table ──
    # Each version gets an OK or WEAK badge based on the WEAK_TLS set
    tls_ver_rows = ""
    for ver, cnt in s["tls_versions"].most_common():
        badge = "badge-err" if ver in WEAK_TLS else "badge-ok"
        label = "WEAK" if ver in WEAK_TLS else "OK"
        tls_ver_rows += f"<tr><td>{ver}</td><td>{cnt:,}</td><td><span class='badge {badge}'>{label}</span></td></tr>"

    # ── Cipher suites table (top 10 by frequency) ──
    # Checks cipher name for known-weak algorithm substrings
    cipher_rows = ""
    for cipher, cnt in s["cipher_suites"].most_common(10):
        is_weak = any(w in cipher.upper() for w in WEAK_CIPHERS)
        badge = "badge-err" if is_weak else "badge-ok"
        label = "WEAK" if is_weak else "OK"
        cipher_rows += f"<tr><td><code>{cipher}</code></td><td>{cnt:,}</td><td><span class='badge {badge}'>{label}</span></td></tr>"

    # ── Weak TLS detail table — individual flows using deprecated crypto ──
    weak_rows = ""
    if s["weak_tls_flows"]:
        for f in s["weak_tls_flows"][:30]:
            src = f.get("src_hostname") or f.get("src_address", "?")
            dst = f.get("dst_hostname") or f.get("dst_address", "?")
            ver = f.get("tls_client_version") or f.get("tls_server_version") or "?"
            cipher = f.get("tls_server_cipher_suite") or "?"
            weak_rows += f"<tr><td>{src}</td><td>{dst}</td><td>{ver}</td><td><code>{cipher}</code></td></tr>"
    else:
        weak_rows = "<tr><td colspan='4' style='color:#059669;font-weight:600'>No weak TLS flows detected</td></tr>"

    # ── Rejected flows detail — flows blocked by enforced policy ──
    # Capped at 50 rows to keep report size manageable
    rej_rows = ""
    if s["rejected_flows"]:
        for f in s["rejected_flows"][:50]:
            ts_val = f.get("timestamp", 0)
            ts_str = datetime.fromtimestamp(ts_val, tz=timezone.utc).strftime("%H:%M:%S") if ts_val else "?"
            src = f.get("src_hostname") or f.get("src_address", "?")
            dst = f.get("dst_hostname") or f.get("dst_address", "?")
            src_scope = shorten_scope(f.get("src_scope_name", "?") if isinstance(f.get("src_scope_name"), str) else "?")
            dst_scope = shorten_scope(f.get("dst_scope_name", "?") if isinstance(f.get("dst_scope_name"), str) else "?")
            port = f.get("dst_port", "?")
            proto = PROTO_MAP.get(f.get("proto", 0), "?")
            rej_rows += f"<tr><td>{ts_str}</td><td>{src}</td><td>{src_scope}</td><td>{dst}</td><td>{dst_scope}</td><td>{proto}/{port}</td></tr>"
    else:
        rej_rows = "<tr><td colspan='6' style='text-align:center;color:#059669;font-weight:600'>No REJECTED flows found</td></tr>"

    # ── Top destination ports table ──
    # Ports in RISKY_PORTS get a red RISK badge (remote admin, DB ports)
    port_rows = ""
    for port, cnt in s["port_counter"].most_common(20):
        svc = WELL_KNOWN_PORTS.get(port, str(port))
        risk = ""
        if port in RISKY_PORTS:
            risk = " <span class='badge badge-err'>RISK</span>"
        port_rows += f"<tr><td>{port}</td><td>{svc}{risk}</td><td>{cnt:,}</td></tr>"

    # ── Consumer → Provider scope pairs (top 30) ──
    scope_rows = ""
    for (src_s, dst_s), cnt in s["scope_pairs"].most_common(30):
        scope_rows += f"<tr><td>{src_s}</td><td>&rarr;</td><td>{dst_s}</td><td>{cnt:,}</td></tr>"

    # ── Source → Destination host pairs (top 30) ──
    host_rows = ""
    for (src_h, dst_h, svc), cnt in s["host_pairs"].most_common(30):
        host_rows += f"<tr><td>{src_h}</td><td>{dst_h}</td><td>{svc}</td><td>{cnt:,}</td></tr>"

    # ── Process strings (top 20 executables by frequency) ──
    proc_html = ""
    for ps, cnt in s["process_counter"].most_common(20):
        proc_html += f'<div class="process-card"><strong>&times;{cnt}</strong> &nbsp; <code>{ps}</code></div>'
    if not proc_html:
        proc_html = '<div style="color:#94A3B8;font-size:.85rem">No process strings observed in this sample.</div>'

    # ── Named user accounts (top 20, excludes built-in system accounts) ──
    user_rows = ""
    for user, cnt in s["user_counter"].most_common(20):
        user_rows += f"<tr><td><code>{user}</code></td><td>{cnt:,}</td></tr>"
    if not user_rows:
        user_rows = "<tr><td colspan='2' style='color:#94A3B8'>No named user accounts observed.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Flow Analysis — {cluster}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {{
  --bg:#F8FAFC; --card:#fff; --header:#005073; --accent:#0EA5E9;
  --text:#020617; --text2:#475569; --text3:#94A3B8;
  --red:#dc2626; --amber:#d97706; --green:#059669;
  --border:#E2E8F0; --radius:10px; --transition:200ms ease;
  --shadow-sm:0 1px 2px rgba(0,0,0,.04),0 1px 3px rgba(0,0,0,.06);
  --shadow-md:0 4px 6px rgba(0,0,0,.04),0 10px 15px rgba(0,0,0,.06);
}}
*,*::before,*::after {{ box-sizing:border-box; margin:0; padding:0 }}
body {{ font-family:'Inter',system-ui,sans-serif; background:var(--bg);
       color:var(--text); font-size:14px; line-height:1.6; -webkit-font-smoothing:antialiased }}
header {{ background:linear-gradient(135deg,#00bceb 0%,var(--header) 100%); color:#fff; padding:1.5rem 2rem;
         display:flex; align-items:center; gap:1rem }}
header h1 {{ font-size:1.3rem; font-weight:700 }}
header small {{ opacity:.85; font-size:.8rem; display:block; margin-top:.3rem }}
.cisco-logo {{ font-size:1.5rem; font-weight:800; letter-spacing:-1px; opacity:.95 }}
main {{ padding:1.5rem 2rem; display:grid;
       grid-template-columns: repeat(auto-fill,minmax(340px,1fr));
       gap:1.25rem; max-width:1300px; margin:0 auto }}
.full {{ grid-column: 1 / -1 }}
.card {{ background:var(--card); border-radius:var(--radius);
        border:1px solid var(--border); padding:1.25rem;
        box-shadow:var(--shadow-sm); transition:box-shadow var(--transition) }}
.card:hover {{ box-shadow:var(--shadow-md) }}
.card h2 {{ font-size:.88rem; font-weight:700; margin-bottom:.85rem;
           border-bottom:2px solid var(--accent); padding-bottom:6px; color:var(--text) }}
.kpi-grid {{ display:flex; flex-wrap:wrap; gap:10px }}
.kpi {{ background:var(--bg); border-radius:8px; padding:10px 16px;
       min-width:120px; text-align:center; flex:1; border:1px solid var(--border) }}
.kpi .val {{ font-size:1.5rem; font-weight:700; color:var(--accent); font-family:'Inter',sans-serif }}
.kpi .lbl {{ font-size:.68rem; color:var(--text3); margin-top:2px; text-transform:uppercase; letter-spacing:.4px; font-weight:500 }}
.kpi.warn .val {{ color:var(--amber) }}
.kpi.ok .val   {{ color:var(--green) }}
table {{ width:100%; border-collapse:collapse; font-size:.8rem }}
thead {{ background:#F1F5F9 }}
th {{ padding:.5rem .7rem; text-align:left; font-size:.7rem; text-transform:uppercase;
     letter-spacing:.4px; color:var(--text2); border-bottom:2px solid var(--border); font-weight:600 }}
td {{ padding:.5rem .7rem; border-bottom:1px solid #F1F5F9; vertical-align:middle }}
tr:last-child td {{ border-bottom:none }}
tbody tr:nth-child(even) td {{ background:#FAFBFC }}
tbody tr:hover td {{ background:#EFF6FF; transition:background var(--transition) }}
.badge {{ display:inline-block; padding:2px 8px; border-radius:20px;
         font-size:.69rem; font-weight:600 }}
.badge-ok   {{ background:#d1fae5; color:#065f46 }}
.badge-warn {{ background:#fef3c7; color:#92400e }}
.badge-err  {{ background:#fee2e2; color:#991b1b }}
code {{ font-family:'Fira Code','Cascadia Code',monospace; font-size:.72rem;
       background:#F1F5F9; padding:2px 6px; border-radius:4px; word-break:break-all }}
.bar-wrap {{ background:#E2E8F0; border-radius:4px; height:10px; flex:1 }}
.bar      {{ background:var(--accent); border-radius:4px; height:10px; transition:width .3s ease }}
.bar-row  {{ display:flex; align-items:center; gap:8px; margin:4px 0 }}
.bar-lbl  {{ width:120px; font-size:.78rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text2) }}
.bar-val  {{ width:50px; text-align:right; font-size:.78rem; color:var(--text3); font-weight:600 }}
.process-card {{ background:#FAFBFC; border-radius:6px; padding:8px 12px;
                margin:4px 0; font-size:.78rem; border-left:3px solid var(--accent);
                transition:background var(--transition) }}
.process-card:hover {{ background:#EFF6FF }}
footer {{ text-align:center; padding:1.5rem; color:var(--text3); font-size:.75rem;
         border-top:1px solid var(--border); margin-top:1rem }}
footer strong {{ color:var(--text2) }}
@media print {{
  body {{ background:#fff; -webkit-print-color-adjust:exact; print-color-adjust:exact }}
  header {{ background:var(--header) !important; -webkit-print-color-adjust:exact }}
  .card {{ box-shadow:none; break-inside:avoid }}
  .card:hover {{ box-shadow:none }}
}}
@media (max-width:720px) {{ main {{ grid-template-columns:1fr }} }}
</style>
</head>
<body>
<header>
  <div class="cisco-logo">Cisco</div>
  <div>
    <h1>Secure Workload — Flow Analysis</h1>
    <small>Scope: {scope} &nbsp;|&nbsp; Window: Last {hours}h &nbsp;|&nbsp;
           Sample: {s['total']:,} flows &nbsp;|&nbsp; Generated: {generated}</small>
  </div>
</header>
<main>

<div class="card full">
  <h2>Summary KPIs</h2>
  <div class="kpi-grid">{kpi_html}</div>
</div>

<div class="card">
  <h2>Policy Verdicts</h2>
  <table><tr><th>Direction</th><th>Verdict</th><th>Count</th><th>Status</th></tr>{verdict_rows}</table>
</div>

<div class="card">
  <h2>Protocol Distribution</h2>
  {proto_html}
</div>

<div class="card full">
  <h2>TCP Performance</h2>
  {tcp_html}
</div>

<div class="card full">
  <h2>TLS Analysis</h2>
  <div style="display:grid;grid-template-columns:1fr 2fr;gap:1.25rem">
    <div>
      <strong style="font-size:.75rem;color:var(--text3);text-transform:uppercase;letter-spacing:.4px">TLS Versions</strong>
      <table style="margin-top:8px"><tr><th>Version</th><th>Flows</th><th>Status</th></tr>{tls_ver_rows if tls_ver_rows else "<tr><td colspan='3' style='color:var(--text3)'>No TLS flows detected</td></tr>"}</table>
    </div>
    <div>
      <strong style="font-size:.75rem;color:var(--text3);text-transform:uppercase;letter-spacing:.4px">Cipher Suites (top 10)</strong>
      <table style="margin-top:8px"><tr><th>Cipher</th><th>Flows</th><th>Status</th></tr>{cipher_rows if cipher_rows else "<tr><td colspan='3' style='color:var(--text3)'>No cipher data available</td></tr>"}</table>
    </div>
  </div>
</div>

<div class="card full">
  <h2>Weak TLS Flows <span style="font-size:.72rem;font-weight:400;color:var(--text3)">(TLSv1.0/1.1, RC4, DES, NULL)</span></h2>
  <table><tr><th>Source Host</th><th>Destination Host</th><th>TLS Version</th><th>Cipher</th></tr>{weak_rows}</table>
</div>

<div class="card full">
  <h2>REJECTED Flows (Forward Direction)</h2>
  <table><tr><th>Timestamp</th><th>Source Host</th><th>Src Scope</th><th>Dest Host</th><th>Dst Scope</th><th>Proto/Port</th></tr>{rej_rows}</table>
</div>

<div class="card">
  <h2>Top Destination Ports</h2>
  <table><tr><th>Port</th><th>Service</th><th>Flows</th></tr>{port_rows}</table>
</div>

<div class="card">
  <h2>Top Consumer &rarr; Provider Scope Pairs</h2>
  <table><tr><th>Consumer Scope</th><th></th><th>Provider Scope</th><th>Flows</th></tr>{scope_rows}</table>
</div>

<div class="card full">
  <h2>Top Source &rarr; Destination Host Flows (top 30)</h2>
  <table><tr><th>Source Host</th><th>Destination Host</th><th>Proto/Port</th><th>Flows</th></tr>{host_rows}</table>
</div>

<div class="card">
  <h2>Process Strings Observed</h2>
  {proc_html}
</div>

<div class="card">
  <h2>Named User Accounts in Flows</h2>
  <table><tr><th>Account</th><th>Flows</th></tr>{user_rows}</table>
</div>

</main>
<footer>
  <strong>Cisco Secure Workload</strong> — Flow Analysis Report &nbsp;|&nbsp;
  {generated} &nbsp;|&nbsp; Scope: {scope}
  <br><span style="margin-top:.3rem;display:block">Generated by <code>generate_flow_analysis.py</code> &middot; Cisco SE Toolkit</span>
</footer>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────

def main():
    """
    CLI entry point: fetch flows → analyse → write HTML report.

    Three-phase pipeline:
      [1/3] Discover the root scope so flowsearch queries the entire cluster
      [2/3] Paginate through the flowsearch API to collect up to --limit flows
      [3/3] Run the 10-dimension analysis and render to a self-contained HTML file

    All progress is printed to stderr so stdout remains clean for piping.
    """
    parser = argparse.ArgumentParser(description="CSW Deep Flow Analysis Report Generator")
    parser.add_argument("--limit", type=int, default=2000, help="Max flows to sample (default: 2000)")
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours (default: 24)")
    parser.add_argument("--out", "-o", default=None, help="Output HTML path (default: reports/flow-analysis-<date>.html)")
    args = parser.parse_args()

    # Extract cluster hostname from the env var for the page title
    cluster = os.environ.get("CSW_API_URL", "?").replace("https://", "").split("/")[0]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    date_tag = datetime.now().strftime("%Y-%m-%d")

    print(f"  Cluster:  {cluster}", file=sys.stderr)
    print(f"  Window:   Last {args.hours}h", file=sys.stderr)
    print(f"  Limit:    {args.limit:,} flows", file=sys.stderr)

    # Phase 1: Discover root scope dynamically
    print(f"\n  [1/3] Discovering root scope...", file=sys.stderr, end="", flush=True)
    root_scope = get_root_scope()
    print(f" '{root_scope}'", file=sys.stderr)

    # Phase 2: Fetch flows from the cluster via paginated API
    print(f"  [2/3] Fetching flows...", file=sys.stderr)
    flows = fetch_flows(root_scope, args.hours, args.limit)
    print(f"    Downloaded {len(flows):,} flows", file=sys.stderr)

    if not flows:
        print("  No flows returned. Check API key capabilities.", file=sys.stderr)
        sys.exit(1)

    # Phase 3: Analyse all dimensions and render HTML
    print(f"  [3/3] Analysing...", file=sys.stderr)
    stats = analyse(flows)

    out_path = args.out or f"reports/flow-analysis-{date_tag}.html"
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    html = render_html(stats, cluster, root_scope, args.hours, generated)
    with open(out_path, "w", encoding="utf-8") as fout:
        fout.write(html)

    print(f"\n  HTML report: {out_path}", file=sys.stderr)
    print(f"  Open: open {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
