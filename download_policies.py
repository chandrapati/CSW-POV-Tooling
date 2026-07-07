#!/usr/bin/env python3
"""
download_policies.py — CSW Policy & Workload Downloader
--------------------------------------------------------
Downloads all policies from every workspace in the CSW cluster,
performs inventory lookups for each unique consumer/provider scope,
and generates:

  snapshots/policies-all.json          ← raw policy data
  snapshots/scope-workloads.json       ← workloads per scope
  snapshots/policy-workload-report.md  ← Markdown report
  reports/policy-workload-report-<date>.html  ← interactive HTML report

Usage:
    python3 download_policies.py
    python3 download_policies.py --out reports/my-report.html

Requirements:
    No extra packages — uses csw_api.py (same directory) for authentication.
    Credentials must be set in .env (copy .env.example to get started).

API capabilities required on your CSW API key:
    - app_policy_management   (for workspace and policy data)
    - flow_inventory_query    (for inventory / workload search)
    - sensor_management       (for agent data — optional)
"""

import json
import sys
import os
import time
import argparse
import collections
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csw_api

csw_api._load_dotenv()

# ── constants ──────────────────────────────────────────────────────────────

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 0: "Any"}

RISKY_PORT_NUMBERS = {
    3389: ("CRITICAL", "RDP"),   22:   ("CRITICAL", "SSH"),
    23:   ("CRITICAL", "Telnet"),20:   ("HIGH",     "FTP-data"),
    21:   ("HIGH",     "FTP"),   139:  ("HIGH",     "NetBIOS"),
    445:  ("CRITICAL", "SMB"),   25:   ("HIGH",     "SMTP"),
    3306: ("CRITICAL", "MySQL"), 1433: ("CRITICAL", "MSSQL"),
    1521: ("CRITICAL", "Oracle"),5432: ("CRITICAL", "PostgreSQL"),
}

DATE_TAG  = datetime.now().strftime("%Y-%m-%d")
TIMESTAMP = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M UTC")

# Pastel backgrounds rotated for per-workspace summary tiles in the HTML report.
_WORKSPACE_SUMMARY_PALETTE = (
    "#dbeafe", "#ede9fe", "#d1fae5", "#fef3c7", "#ffe4e6", "#e0e7ff",
    "#ccfbf1", "#ffedd5", "#e0f2fe", "#fae8ff", "#dcfce7", "#fee2e2",
)


# ── helpers ────────────────────────────────────────────────────────────────

def shorten(full_name: str) -> str:
    """Return the leaf segment of a colon-separated scope path."""
    return full_name.split(":")[-1] if full_name else "?"


def workspace_summary_colors(ws_meta: list) -> dict:
    """Map each workspace full name to a distinct pastel color for summary cards."""
    return {
        ws["name"]: _WORKSPACE_SUMMARY_PALETTE[i % len(_WORKSPACE_SUMMARY_PALETTE)]
        for i, ws in enumerate(ws_meta)
    }


def fmt_ports(l4_params: list) -> str:
    """Format a list of l4_params dicts into a readable port/protocol string."""
    parts = []
    for p in l4_params or []:
        proto = PROTO_MAP.get(p.get("proto", 0), str(p.get("proto", "?")))
        port  = p.get("port", [])
        if port:
            # CSW uses [low, high]; equal bounds mean a single port, not a range.
            parts.append(f"{proto}/{port[0]}" if port[0] == port[1] else f"{proto}/{port[0]}-{port[1]}")
        else:
            parts.append(proto)
    return ", ".join(parts) if parts else "Any"


def _extract_port_number(segment: str) -> int | None:
    """Extract the port number from a segment like 'TCP/1433' or 'UDP/3389'."""
    if "/" not in segment:
        return None
    port_str = segment.split("/", 1)[1]
    if "-" in port_str:
        # Single-port risk lookup only; ranges like TCP/1000-2000 are not classified here.
        return None
    try:
        return int(port_str)
    except ValueError:
        return None


def highlight_risky_ports_html(ports_str: str) -> str:
    """Wrap risky port segments in red-highlighted spans for HTML rendering."""
    parts = [s.strip() for s in ports_str.split(",")]
    out = []
    for part in parts:
        pn = _extract_port_number(part)
        if pn and pn in RISKY_PORT_NUMBERS:
            out.append(
                f'<span style="background:#fee2e2;color:#991b1b;padding:1px 5px;'
                f'border-radius:4px;font-weight:600">{part}</span>'
            )
        else:
            out.append(part)
    return ", ".join(out)


def policy_has_risky_port(ports_str: str) -> list[int]:
    """Return list of risky port numbers found in a policy ports string."""
    found = []
    for segment in ports_str.split(","):
        pn = _extract_port_number(segment.strip())
        if pn and pn in RISKY_PORT_NUMBERS:
            found.append(pn)
    return found


def clean_workloads(raw_list: list) -> list:
    """
    Filter raw inventory results to unique, real host entries.
    Drops subnet addresses (e.g. 10.x.x.0/24), broadcast (.255),
    management IPs (.100, .200) and de-duplicates by hostname/IP.
    """
    seen  = set()
    clean = []
    for w in raw_list:
        hn  = w.get("host_name") or ""
        ip  = w.get("ip") or ""
        os_ = w.get("os") or ""
        # Skip CIDR-style rows, empty placeholders, broadcast, common non-workload endpoints,
        # and occasional network-address artifacts from inventory responses.
        skip = (
            "/24" in ip or "/16" in ip
            or ip in ("", "?")
            or ip.endswith(".255")
            or ip.endswith(".100")
            or ip.endswith(".200")
        )
        if skip:
            continue
        key = hn or ip
        if key in seen:
            continue
        seen.add(key)
        clean.append({"host": hn, "ip": ip, "os": os_})
    return clean


# ── API helpers ────────────────────────────────────────────────────────────

def get_workspaces() -> list[dict]:
    """Return list of all application workspaces."""
    r = csw_api.make_request("GET", "/openapi/v1/applications")
    if r.get("status") != 200:
        print(f"  ❌  GET /applications failed: HTTP {r.get('status')}")
        sys.exit(1)
    data = r.get("data", [])
    return data if isinstance(data, list) else data.get("results", [])


def get_root_scope() -> str:
    """Return the name of the root scope (cluster name)."""
    r = csw_api.make_request("GET", "/openapi/v1/app_scopes")
    if r.get("status") != 200:
        return "Root"
    scopes = r.get("data", [])
    if not isinstance(scopes, list):
        return "Root"
    # Cluster root is the scope with no parent in the hierarchy returned by the API.
    roots = [s for s in scopes if isinstance(s, dict) and not s.get("parent_app_scope_id")]
    return roots[0].get("name", "Root") if roots else "Root"


def get_policies(app_id: str) -> tuple[list, list, str]:
    """
    Fetch policies for one workspace.
    Returns (absolute_policies, default_policies, catch_all_action).
    """
    r = csw_api.make_request("GET", f"/openapi/v1/applications/{app_id}/policies")
    if r.get("status") != 200:
        return [], [], "DENY"
    data = r.get("data", {})
    if not isinstance(data, dict):
        return [], [], "DENY"
    return (
        data.get("absolute_policies", []),
        data.get("default_policies", []),
        data.get("catch_all_action", "DENY"),
    )


def inventory_search(query: dict, root_scope: str, limit: int = 200) -> list:
    """Search inventory for workloads matching a scope filter query."""
    # scopeName must be the cluster root; per-scope filters live in "filter".
    body = {"filter": query, "scopeName": root_scope, "limit": limit}
    r    = csw_api.make_request("POST", "/openapi/v1/inventory/search", body=body)
    if r.get("status") != 200:
        return []
    data = r.get("data", {})
    return data.get("results", []) if isinstance(data, dict) else []


# ── main data collection ───────────────────────────────────────────────────

def collect(args) -> dict:
    """
    Fetch every workspace's policies, then inventory-search each distinct consumer/provider
    scope used in those policies.

    Returns a dict with: date, timestamp, root_scope, workspaces (metadata list),
    all_policies (flattened rows for JSON/reporting), scope_workloads (full scope name
    to cleaned workload list). The args namespace is reserved for CLI-driven options
    (e.g. future rate limits); collection currently uses environment configuration only.
    """
    print(f"\n📡  Connecting to: {os.environ.get('CSW_API_URL','?')}")
    print(f"📅  Report date: {DATE_TAG}\n")

    # 1. Discover workspaces
    print("  [1/3] Fetching workspaces...")
    workspaces = get_workspaces()
    print(f"        {len(workspaces)} workspaces found")

    root_scope = get_root_scope()
    print(f"        Root scope: '{root_scope}'")

    # 2. Download all policies
    print("\n  [2/3] Downloading policies...")
    all_policies = []
    ws_meta      = []

    for ws in workspaces:
        ws_name = ws.get("name", "?")
        ws_id   = ws.get("id", "")
        abs_pol, def_pol, catch_all = get_policies(ws_id)
        total = len(abs_pol) + len(def_pol)

        print(f"        {ws_name}: {len(abs_pol)} absolute + {len(def_pol)} default (catch-all={catch_all})")

        ws_meta.append({
            "id":           ws_id,
            "name":         ws_name,
            "policy_count": total,
            "catch_all":    catch_all,
            "enforcement":  ws.get("enforcement_enabled", False),
            "primary":      ws.get("primary", False),
        })

        for p in abs_pol + def_pol:
            cf  = p.get("consumer_filter", {}) or {}
            pf  = p.get("provider_filter", {}) or {}
            all_policies.append({
                "workspace":       ws_name,
                "rank":            p.get("rank", "?"),
                "action":          p.get("action", "?"),
                "consumer_full":   cf.get("name", "?"),
                "provider_full":   pf.get("name", "?"),
                "consumer":        shorten(cf.get("name", "")),
                "provider":        shorten(pf.get("name", "")),
                "consumer_query":  cf.get("query", {}),
                "provider_query":  pf.get("query", {}),
                "ports":           fmt_ports(p.get("l4_params", [])),
                "priority":        p.get("priority", ""),
            })

    print(f"\n        Total policies: {len(all_policies)}")

    # 3. Inventory lookup per unique scope
    print("\n  [3/3] Fetching workloads for each consumer/provider scope...")
    scope_queries = {}
    for p in all_policies:
        for side in ("consumer", "provider"):
            name  = p[f"{side}_full"]
            query = p[f"{side}_query"]
            if name and name != "?" and query:
                scope_queries[name] = query

    scope_workloads = {}
    for i, (scope_name, query) in enumerate(scope_queries.items(), 1):
        short = shorten(scope_name)
        raw   = inventory_search(query, root_scope)
        clean = clean_workloads(raw)
        scope_workloads[scope_name] = clean
        print(f"        [{i:02d}/{len(scope_queries):02d}] {short}: {len(clean)} workloads")
        time.sleep(0.1)  # gentle on the API

    return {
        "date":             DATE_TAG,
        "timestamp":        TIMESTAMP,
        "root_scope":       root_scope,
        "workspaces":       ws_meta,
        "all_policies":     all_policies,
        "scope_workloads":  scope_workloads,
    }


# ── Markdown report ────────────────────────────────────────────────────────

def render_markdown(data: dict) -> str:
    """
    Build the stakeholder Markdown report: scope inventory tables, policies grouped by
    workspace (ALLOW before DENY via sort key), and a consumer→provider flow map using
    the workspace with the most policies as the diagram context.
    """
    all_policies    = data["all_policies"]
    scope_workloads = data["scope_workloads"]
    ws_meta         = data["workspaces"]

    by_ws = collections.defaultdict(list)
    for p in all_policies:
        by_ws[p["workspace"]].append(p)

    scope_names_ordered = sorted(scope_workloads.keys())

    lines = [
        "# CSW Policy & Workload Report",
        f"**Cluster:** `{os.environ.get('CSW_API_URL','?').replace('https://','')}`  ",
        f"**Report Date:** {data['date']}  ",
        f"**Total Policies:** {len(all_policies)}  ",
        f"**Workspaces:** {len(ws_meta)}  ",
        "",
        "---",
        "",
        "## Section 1 — Scope Workload Inventory",
        "",
    ]

    for full_name in scope_names_ordered:
        short = shorten(full_name)
        wls   = scope_workloads.get(full_name, [])
        lines.append(f"### {short}  ({len(wls)} workloads)")
        if wls:
            lines += ["", "| Hostname | IP Address | OS |", "|---|---|---|"]
            for w in wls:
                hn  = f'`{w["host"]}`' if w["host"] else "*(agentless)*"
                ip  = f'`{w["ip"]}`'   if w["ip"]   else "—"
                os_ = w["os"] or "—"
                lines.append(f"| {hn} | {ip} | {os_} |")
        else:
            lines.append("*(no workloads returned)*")
        lines.append("")

    lines += ["---", "", "## Section 2 — Policies by Workspace", ""]

    for ws in ws_meta:
        name     = ws["name"]
        policies = sorted(by_ws.get(name, []), key=lambda x: (x["action"] != "ALLOW", x.get("priority", 999)))
        if not policies:
            continue
        lines.append(f"### Workspace: `{name}`  ({len(policies)} policies)")
        lines += ["", "| # | Rank | Action | Consumer | Provider | Ports |", "|---|---|---|---|---|---|"]
        for i, p in enumerate(policies, 1):
            icon = "✅ ALLOW" if p["action"] == "ALLOW" else "🚫 DENY"
            lines.append(f"| {i} | {p['rank']} | {icon} | `{p['consumer']}` | `{p['provider']}` | {p['ports']} |")
        lines.append("")

    lines += ["---", "", "## Section 3 — Consumer → Provider Flow Map", ""]

    # Use the workspace with the most policies for the flow map
    largest_ws = max(by_ws.keys(), key=lambda k: len(by_ws[k]), default="")
    consumer_map = collections.defaultdict(list)
    for p in by_ws.get(largest_ws, []):
        if p["action"] == "ALLOW":
            consumer_map[p["consumer"]].append(p)

    lines.append(f"*(Flow map for workspace: `{largest_ws}`)*")
    lines.append("")

    for consumer in sorted(consumer_map.keys()):
        cps    = consumer_map[consumer]
        c_full = next((p["consumer_full"] for p in cps), "")
        c_wls  = scope_workloads.get(c_full, [])
        hosts  = ", ".join(w["host"] or w["ip"] for w in c_wls[:5]) or "*(no workloads)*"
        lines.append(f"#### Consumer: `{consumer}`")
        lines.append(f"> **Workloads:** {hosts}")
        lines += ["", "| Provider | Provider Workloads | Ports |", "|---|---|---|"]
        for p in sorted(cps, key=lambda x: x["provider"]):
            pv_wls   = scope_workloads.get(p["provider_full"], [])
            pv_hosts = ", ".join(w["host"] or w["ip"] for w in pv_wls[:4]) or "*(agentless/external)*"
            lines.append(f"| `{p['provider']}` | {pv_hosts} | {p['ports']} |")
        lines.append("")

    return "\n".join(lines)


# ── HTML report ────────────────────────────────────────────────────────────

def render_html(data: dict) -> str:
    """
    Assemble a single-page interactive HTML report: KPI header, scope inventory cards,
    tabbed policy tables and flow maps per workspace (footer showT/showF scripts toggle the
    .on class so only one .ws-tab panel is visible per card), summary tiles, and an optional
    high-risk port section when policy port strings match RISKY_PORT_NUMBERS.
    """
    all_policies    = data["all_policies"]
    scope_workloads = data["scope_workloads"]
    ws_meta         = data["workspaces"]
    cluster         = os.environ.get("CSW_API_URL", "?").replace("https://", "")

    by_ws = collections.defaultdict(list)
    for p in all_policies:
        by_ws[p["workspace"]].append(p)

    total_allow = sum(1 for p in all_policies if p["action"] == "ALLOW")
    total_deny  = sum(1 for p in all_policies if p["action"] == "DENY")

    scope_names_ordered = sorted(scope_workloads.keys())
    ws_order     = [ws["name"] for ws in ws_meta]

    # Build per-workspace consumer maps (all workspaces)
    ws_consumer_maps = {}
    for ws_name in by_ws:
        cmap = collections.defaultdict(list)
        for p in by_ws[ws_name]:
            if p["action"] == "ALLOW":
                cmap[p["consumer"]].append(p)
        if cmap:
            ws_consumer_maps[ws_name] = cmap

    def wl_pills(full_name, limit=6):
        wls = scope_workloads.get(full_name, [])[:limit]
        if not wls:
            return '<span style="color:#94a3b8;font-size:.76rem">no workloads</span>'
        return "".join(
            '<span class="pill">' + (w["host"] or w["ip"]) + "</span>"
            for w in wls
        )

    def action_badge(action):
        if action == "ALLOW":
            return '<span class="badge green">&#10003; ALLOW</span>'
        return '<span class="badge red">&#10006; DENY</span>'

    parts = []

    # ── CSS ──
    parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Policy & Workload Report</title>
<style>
:root{--bg:#f0f4f8;--card:#fff;--border:#dde4ee;--text:#0f172a;--text2:#475569;--sh:0 1px 3px rgba(0,0,0,.08)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
.hdr{background:linear-gradient(135deg,#00bceb,#0070c8);color:#fff;padding:2rem}
.hdr h1{font-size:1.65rem;font-weight:700}
.meta{margin-top:.7rem;font-size:.81rem;opacity:.85;display:flex;flex-wrap:wrap;gap:1.4rem}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:1px;background:var(--border)}
.kpi{background:#fff;padding:.9rem;text-align:center}
.kval{font-size:1.55rem;font-weight:700}
.klbl{font-size:.67rem;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;margin-top:.15rem}
.wrap{max-width:1200px;margin:1.5rem auto;padding:0 1.5rem;display:grid;gap:1.5rem}
.card{background:#fff;border:1px solid var(--border);border-radius:12px;box-shadow:var(--sh);overflow:hidden}
.ch{padding:.85rem 1.2rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.6rem}
.ch h2{font-size:.93rem;font-weight:600}
.cb{padding:1rem 1.2rem}
.badge{padding:2px 9px;border-radius:999px;font-size:.69rem;font-weight:600}
.green{background:#d1fae5;color:#065f46}
.red{background:#fee2e2;color:#991b1b}
.blue{background:#dbeafe;color:#1e40af}
table{width:100%;border-collapse:collapse;font-size:.8rem}
thead{background:#f8fafc}
th{padding:.42rem .7rem;text-align:left;font-size:.69rem;text-transform:uppercase;letter-spacing:.4px;color:var(--text2);border-bottom:1px solid var(--border)}
td{padding:.42rem .7rem;border-bottom:1px solid #f1f5f9;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:#fafbff}
code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:.75rem}
.pill{display:inline-block;background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe;padding:1px 7px;border-radius:5px;font-size:.7rem;margin:1px;font-family:monospace}
.tab-nav{display:flex;flex-wrap:wrap;gap:.35rem;padding:.65rem 1.2rem;border-bottom:1px solid var(--border);background:#f8fafc}
.tb{padding:.33rem .85rem;border-radius:6px;cursor:pointer;font-size:.78rem;font-weight:500;border:1px solid var(--border);background:#fff}
.tb.on{background:#0070c8;color:#fff;border-color:#0070c8}
.ws-tab{display:none}
.ws-tab.on{display:block}
.fc{background:#f8fafc;border:1px solid var(--border);border-radius:8px;margin-bottom:.8rem;overflow:hidden}
.sc{background:#fff;border:1px solid var(--border);border-radius:8px;margin-bottom:.65rem;overflow:hidden}
.sch{padding:.45rem .9rem;background:#f8fafc;border-bottom:1px solid var(--border);font-weight:600;font-size:.8rem;display:flex;align-items:center;gap:.4rem}
footer{text-align:center;padding:1.8rem 1rem;font-size:.73rem;color:var(--text2);border-top:1px solid var(--border);margin-top:1.5rem}
</style>
</head>
<body>""")

    # ── Header + KPIs ──
    parts.append(
        f'<div class="hdr"><div style="max-width:1200px;margin:0 auto">'
        f'<h1>Cisco Secure Workload &mdash; CSW Policy &amp; Workload Report</h1>'
        f'<div class="meta"><span>Cluster: {cluster}</span>'
        f'<span>Date: {data["date"]}</span>'
        f'<span>Observation Mode &mdash; No Enforcement</span></div>'
        f'</div></div>'
        f'<div class="kpis">'
        f'<div class="kpi"><div class="kval">{len(all_policies)}</div><div class="klbl">Total Policies</div></div>'
        f'<div class="kpi"><div class="kval" style="color:#059669">{total_allow}</div><div class="klbl">Allow</div></div>'
        f'<div class="kpi"><div class="kval" style="color:#dc2626">{total_deny}</div><div class="klbl">Deny</div></div>'
        f'<div class="kpi"><div class="kval">{len(ws_meta)}</div><div class="klbl">Workspaces</div></div>'
        f'<div class="kpi"><div class="kval">{len(scope_workloads)}</div><div class="klbl">App Scopes</div></div>'
        f'<div class="kpi"><div class="kval" style="color:#059669">0</div><div class="klbl">Enforced</div></div>'
        f'</div>'
    )

    parts.append('<div class="wrap">')

    # ── Section 1: Scope inventory ──
    parts.append(
        '<div class="card">'
        '<div class="ch"><span>&#128421;</span><h2>Section 1 &mdash; Scope Workload Inventory</h2></div>'
        '<div class="cb"><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:1rem">'
    )
    for full_name in scope_names_ordered:
        short = shorten(full_name)
        wls   = scope_workloads.get(full_name, [])
        if not wls:
            continue
        rows = ""
        for w in wls[:30]:
            hn  = w["host"] or "(agentless)"
            ip  = w["ip"]
            os_ = w["os"].replace("MSServer", "WS").replace("Standard", "") if w["os"] else "-"
            rows += f'<tr><td><code style="font-size:.72rem">{hn}</code></td><td><code style="font-size:.72rem;color:#0369a1">{ip}</code></td><td style="color:#64748b;font-size:.7rem">{os_}</td></tr>'
        more = (
            f'<div style="font-size:.7rem;color:#94a3b8;padding:.22rem 0">... {len(wls)-30} more</div>'
            if len(wls) > 30 else ""
        )
        parts.append(
            f'<div class="sc">'
            f'<div class="sch"><span>&#128193;</span><span>{short}</span>'
            f'<span class="badge blue" style="margin-left:auto">{len(wls)} workloads</span></div>'
            f'<div style="padding:.4rem .8rem">'
            f'<table><thead><tr><th>Hostname</th><th>IP Address</th><th>OS</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>{more}</div></div>'
        )
    parts.append('</div></div></div>')

    # Section 2: tab bar + one .ws-tab div per workspace; showT() adds .on to the matching
    # button (#policy-tabs) and panel (id t-{safe}) inside the same .card only.
    # ── Section 2: Policies (tabbed by workspace) ──
    parts.append(
        '<div class="card">'
        '<div class="ch"><span>&#128203;</span><h2>Section 2 &mdash; Policies by Workspace</h2></div>'
        '<div class="tab-nav" id="policy-tabs">'
    )
    for idx, ws in enumerate(ws_order):
        cnt   = len(by_ws.get(ws, []))
        short = ws.split(":")[-1]
        safe  = ws.replace(":", "-")
        cls   = "tb on" if idx == 0 else "tb"
        parts.append(
            f'<button class="{cls}" onclick="showT(\'{safe}\')" id="b-{safe}">'
            f'{short} <span class="badge blue">{cnt}</span></button>'
        )
    parts.append('</div>')

    for idx, ws in enumerate(ws_order):
        safe  = ws.replace(":", "-")
        cls   = "ws-tab on" if idx == 0 else "ws-tab"
        pols  = sorted(by_ws.get(ws, []), key=lambda x: (x["action"] != "ALLOW", x.get("priority", 999)))
        al    = sum(1 for p in pols if p["action"] == "ALLOW")
        dn    = sum(1 for p in pols if p["action"] == "DENY")
        rows  = ""
        for i, p in enumerate(pols, 1):
            rows += (
                f'<tr>'
                f'<td style="color:#94a3b8;font-size:.72rem">{i}</td>'
                f'<td style="font-size:.7rem;color:#64748b">{p["rank"]}</td>'
                f'<td>{action_badge(p["action"])}</td>'
                f'<td><code>{p["consumer"]}</code></td>'
                f'<td><code>{p["provider"]}</code></td>'
                f'<td style="font-family:monospace;font-size:.72rem;color:#0369a1">{highlight_risky_ports_html(p["ports"])}</td>'
                f'</tr>'
            )
        parts.append(
            f'<div class="{cls}" id="t-{safe}">'
            f'<div style="padding:.5rem 1.2rem;border-bottom:1px solid var(--border);font-size:.79rem;color:var(--text2)">'
            f'<strong>{len(pols)}</strong> policies &nbsp;&middot;&nbsp; '
            f'&#10003; {al} allow &nbsp;&middot;&nbsp; &#10006; {dn} deny</div>'
            f'<div style="overflow-x:auto">'
            f'<table><thead><tr><th>#</th><th>Rank</th><th>Action</th><th>Consumer</th><th>Provider</th><th>Ports</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></div>'
        )
    parts.append('</div>')

    # Section 3: same tab pattern as Section 2, but panel/element ids use an "f-" prefix so
    # ids do not collide with Section 2's t-{safe} / b-{safe} pairs.
    # ── Section 3: Consumer → Provider flow map (all workspaces, tabbed) ──
    parts.append(
        '<div class="card">'
        '<div class="ch"><span>&#8644;</span>'
        '<h2>Section 3 &mdash; Consumer &rarr; Provider Flow Map (All Workspaces)</h2></div>'
        '<div class="tab-nav" id="flow-tabs">'
    )
    flow_ws_order = [ws["name"] for ws in ws_meta if ws["name"] in ws_consumer_maps]
    for idx, ws_name in enumerate(flow_ws_order):
        short = ws_name.split(":")[-1]
        safe  = "f-" + ws_name.replace(":", "-")
        n_consumers = len(ws_consumer_maps[ws_name])
        cls   = "tb on" if idx == 0 else "tb"
        parts.append(
            f'<button class="{cls}" onclick="showF(\'{safe}\')" id="fb-{safe}">'
            f'{short} <span class="badge blue">{n_consumers} consumers</span></button>'
        )
    parts.append('</div>')

    for idx, ws_name in enumerate(flow_ws_order):
        safe  = "f-" + ws_name.replace(":", "-")
        cls   = "ws-tab on" if idx == 0 else "ws-tab"
        cmap  = ws_consumer_maps[ws_name]
        n_allow = sum(1 for p in by_ws[ws_name] if p["action"] == "ALLOW")
        n_deny  = sum(1 for p in by_ws[ws_name] if p["action"] == "DENY")
        catch   = next((ws["catch_all"] for ws in ws_meta if ws["name"] == ws_name), "DENY")
        parts.append(
            f'<div class="{cls}" id="t-{safe}">'
            f'<div style="padding:.5rem 1.2rem;border-bottom:1px solid var(--border);'
            f'font-size:.79rem;color:var(--text2);background:#fafafa">'
            f'<strong>{len(by_ws[ws_name])}</strong> policies &nbsp;&middot;&nbsp; '
            f'&#10003; {n_allow} allow &nbsp;&middot;&nbsp; &#10006; {n_deny} deny'
            f' &nbsp;&middot;&nbsp; catch-all: <strong>{catch}</strong></div>'
            f'<div class="cb">'
            f'<p style="font-size:.79rem;color:var(--text2);margin-bottom:.85rem">'
            f'Each block shows a consumer scope, its enrolled workloads, and all provider '
            f'scopes it is permitted to reach.</p>'
        )
        for consumer in sorted(cmap.keys()):
            cps    = cmap[consumer]
            c_full = next((p["consumer_full"] for p in cps), "")
            c_wls  = scope_workloads.get(c_full, [])
            c_p    = wl_pills(c_full, 8)
            pv_rows = ""
            for p in sorted(cps, key=lambda x: x["provider"]):
                pv_p = wl_pills(p["provider_full"], 5)
                pv_rows += (
                    f'<tr>'
                    f'<td><code>{p["provider"]}</code></td>'
                    f'<td>{pv_p}</td>'
                    f'<td style="font-family:monospace;font-size:.72rem;color:#0369a1;white-space:nowrap">{highlight_risky_ports_html(p["ports"])}</td>'
                    f'</tr>'
                )
            parts.append(
                f'<div class="fc">'
                f'<div style="padding:.5rem 1rem;border-bottom:1px solid var(--border);'
                f'display:flex;align-items:center;gap:.5rem;font-weight:600;font-size:.82rem;background:#eff6ff">'
                f'<span>&#128228;</span><code>{consumer}</code>'
                f'<span style="font-weight:400;font-size:.75rem;color:var(--text2);margin-left:.35rem">'
                f'({len(c_wls)} workloads)</span></div>'
                f'<div style="padding:.5rem 1rem .45rem">'
                f'<div style="font-size:.72rem;color:var(--text2);margin-bottom:.3rem">Workloads:</div>'
                f'<div style="margin-bottom:.55rem">{c_p}</div>'
                f'<table><thead><tr><th>Provider Scope</th><th>Provider Workloads</th><th>Ports</th></tr></thead>'
                f'<tbody>{pv_rows}</tbody></table></div></div>'
            )
        parts.append('</div></div>')  # close tab panel

    parts.append('</div>')  # close card

    # ── Section 4: Summary ──
    ws_bg_colors = workspace_summary_colors(ws_meta)
    sum_cards = ""
    for ws in ws_meta:
        name  = ws["name"]
        pols  = by_ws.get(name, [])
        al    = sum(1 for p in pols if p["action"] == "ALLOW")
        dn    = sum(1 for p in pols if p["action"] == "DENY")
        cu    = len(set(p["consumer"] for p in pols))
        pv    = len(set(p["provider"] for p in pols))
        short = name.split(":")[-1]
        col   = ws_bg_colors.get(name, "#f8fafc")
        sum_cards += (
            f'<div style="background:{col};border:1px solid var(--border);border-radius:8px;padding:.9rem">'
            f'<div style="font-weight:600;font-size:.83rem;margin-bottom:.35rem">{short}</div>'
            f'<div style="font-size:.76rem;color:var(--text2)">Total: <strong>{len(pols)}</strong>'
            f' &nbsp; Allow: <strong style="color:#059669">{al}</strong>'
            f' &nbsp; Deny: <strong style="color:#dc2626">{dn}</strong></div>'
            f'<div style="font-size:.76rem;color:var(--text2);margin-top:.18rem">'
            f'Consumers: {cu} &nbsp;&middot;&nbsp; Providers: {pv}</div></div>'
        )
    parts.append(
        '<div class="card">'
        '<div class="ch"><span>&#128202;</span><h2>Section 4 &mdash; Summary Statistics</h2></div>'
        '<div class="cb"><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem">'
        + sum_cards +
        '</div></div></div>'
    )

    # ── Section 5: High-Risk Port Policy Summary ──
    risky_policy_map = collections.defaultdict(list)
    for p in all_policies:
        for rp in policy_has_risky_port(p["ports"]):
            risky_policy_map[rp].append(p)

    if risky_policy_map:
        risky_sec_rows = ""
        for rport in sorted(risky_policy_map, key=lambda x: -len(risky_policy_map[x])):
            sev, svc_name = RISKY_PORT_NUMBERS[rport]
            pols_for_port = risky_policy_map[rport]
            allow_count = sum(1 for p in pols_for_port if p["action"] == "ALLOW")
            deny_count  = sum(1 for p in pols_for_port if p["action"] == "DENY")
            sev_bg, sev_fg = ("#fee2e2", "#991b1b") if sev == "CRITICAL" else ("#fef3c7", "#92400e")
            risky_sec_rows += (
                f'<tr style="border-bottom:2px solid #e2e8f0">'
                f'<td style="font-weight:700;font-size:.88rem">{rport}</td>'
                f'<td>{svc_name}</td>'
                f'<td><span style="background:{sev_bg};color:{sev_fg};padding:2px 9px;border-radius:999px;font-size:.69rem;font-weight:600">{sev}</span></td>'
                f'<td style="font-weight:600">{len(pols_for_port)}</td>'
                f'<td style="color:#059669;font-weight:600">{allow_count}</td>'
                f'<td style="color:#dc2626;font-weight:600">{deny_count}</td>'
                f'</tr>'
            )
            for pol in pols_for_port[:8]:
                action_cls = "green" if pol["action"] == "ALLOW" else "red"
                risky_sec_rows += (
                    f'<tr style="font-size:.76rem;color:#475569">'
                    f'<td></td><td colspan="2">'
                    f'<code>{pol["consumer"]}</code> &rarr; <code>{pol["provider"]}</code></td>'
                    f'<td><span class="badge {action_cls}">{"&#10003;" if pol["action"]=="ALLOW" else "&#10006;"} {pol["action"]}</span></td>'
                    f'<td colspan="2" style="font-family:monospace;font-size:.7rem">{pol["workspace"].split(":")[-1]}</td>'
                    f'</tr>'
                )
            if len(pols_for_port) > 8:
                risky_sec_rows += (
                    f'<tr style="font-size:.72rem;color:#94a3b8">'
                    f'<td></td><td colspan="5">... and {len(pols_for_port)-8} more policies</td></tr>'
                )

        total_risky_policies = sum(len(v) for v in risky_policy_map.values())
        total_risky_allow = sum(
            1 for pols in risky_policy_map.values() for p in pols if p["action"] == "ALLOW"
        )
        parts.append(
            '<div class="card" style="border-left:4px solid #dc2626">'
            '<div class="ch"><span>&#9888;</span>'
            f'<h2>Section 5 &mdash; High-Risk Port Policy Summary ({len(risky_policy_map)} risky ports)</h2></div>'
            '<div class="cb">'
            f'<div style="margin-bottom:1rem;font-size:0.85rem;color:#7f1d1d;background:#fef2f2;border:1px solid #fca5a5;padding:.75rem 1rem;border-radius:8px">'
            f'<strong>Security Alert:</strong> {total_risky_policies} policies reference high-risk ports '
            f'({total_risky_allow} ALLOW rules). '
            f'Review these policies and restrict access to bastion hosts, application-specific sources, '
            f'and least-privilege network segments.</div>'
            '<div style="overflow-x:auto"><table>'
            '<thead><tr><th>Port</th><th>Service</th><th>Severity</th><th>Policies</th><th>Allow</th><th>Deny</th></tr></thead>'
            f'<tbody>{risky_sec_rows}</tbody></table></div>'
            '</div></div>'
        )

    parts.append("</div>")  # /wrap
    parts.append(
        f'<footer><strong>Cisco Secure Workload</strong> &mdash; Policy &amp; Workload Report'
        f' &nbsp;|&nbsp; Cluster: <code>{cluster}</code>'
        f' &nbsp;|&nbsp; {data["date"]}</footer>'
    )
    parts.append(
        '<script>'
        # Policy workspace tabs — scope to the policy card only
        'function showT(s){'
        'var nav=document.getElementById("policy-tabs");'
        'var card=nav.closest(".card");'
        'card.querySelectorAll(".ws-tab").forEach(t=>t.classList.remove("on"));'
        'nav.querySelectorAll(".tb").forEach(b=>b.classList.remove("on"));'
        'var t=document.getElementById("t-"+s);var b=document.getElementById("b-"+s);'
        'if(t)t.classList.add("on");if(b)b.classList.add("on");}'
        # Flow map workspace tabs
        'function showF(s){'
        'var nav=document.getElementById("flow-tabs");'
        'nav.parentElement.querySelectorAll(".ws-tab").forEach(t=>t.classList.remove("on"));'
        'nav.querySelectorAll(".tb").forEach(b=>b.classList.remove("on"));'
        'var t=document.getElementById("t-"+s);var b=document.getElementById("fb-"+s);'
        'if(t)t.classList.add("on");if(b)b.classList.add("on");}'
        '</script>'
        '</body></html>'
    )
    return "".join(parts)


# ── entry point ────────────────────────────────────────────────────────────

def main():
    """Parse CLI flags, run collect(), then write JSON snapshots, Markdown, and optional HTML."""
    parser = argparse.ArgumentParser(
        description="Download CSW policies and generate a policy + workload report."
    )
    parser.add_argument(
        "--out", "-o",
        default=None,
        help="HTML output path (default: reports/policy-workload-report-<date>.html)"
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip HTML generation (Markdown + JSON only)"
    )
    args = parser.parse_args()

    os.makedirs("snapshots", exist_ok=True)
    os.makedirs("reports",   exist_ok=True)

    # Collect data
    data = collect(args)

    # Save raw JSON
    json_path = "snapshots/policies-all.json"
    with open(json_path, "w") as f:
        json.dump(data["all_policies"], f, indent=2)
    print(f"\n✅  JSON policies:      {json_path}")

    sw_path = "snapshots/scope-workloads.json"
    with open(sw_path, "w") as f:
        json.dump(data["scope_workloads"], f, indent=2)
    print(f"✅  JSON scope-wloads:  {sw_path}")

    # Markdown report
    md_path = "snapshots/policy-workload-report.md"
    with open(md_path, "w") as f:
        f.write(render_markdown(data))
    print(f"✅  Markdown report:    {md_path}")

    # HTML report
    if not args.no_html:
        html_path = args.out or f"reports/policy-workload-report-{DATE_TAG}.html"
        with open(html_path, "w") as f:
            f.write(render_html(data))
        size_kb = os.path.getsize(html_path) // 1024
        print(f"✅  HTML report:        {html_path}  ({size_kb} KB)")
        print("\n   Open in browser:")
        print(f"   open {html_path}   (macOS)")
        print(f"   start {html_path}  (Windows)")


if __name__ == "__main__":
    main()
