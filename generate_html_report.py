#!/usr/bin/env python3
"""
generate_html_report.py — CSW Snapshot → HTML Report Generator
---------------------------------------------------------------
Reads a JSON snapshot produced by cluster_snapshot.py and generates
a self-contained, styled HTML readout.

Usage:
    python3 generate_html_report.py
    python3 generate_html_report.py --snapshot snapshots/snapshot-2026-04-07.json
    python3 generate_html_report.py --snapshot snapshots/snapshot-2026-04-07.json --out reports/readout.html

Requirements:
    No extra packages — standard library only.
"""

import json
import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


RISKY_PORTS = {
    "3389": ("CRITICAL", "RDP — brute-force target for full system control"),
    "22":   ("CRITICAL", "SSH — brute-force target if weak credentials"),
    "23":   ("CRITICAL", "Telnet — cleartext credentials, no encryption"),
    "20":   ("HIGH",     "FTP-data — unencrypted data channel"),
    "21":   ("HIGH",     "FTP — unencrypted control, credential theft"),
    "139":  ("HIGH",     "NetBIOS — lateral movement, ransomware vector"),
    "445":  ("CRITICAL", "SMB — ransomware distribution, file-sharing exploits"),
    "25":   ("HIGH",     "SMTP — spam relay, phishing vector"),
    "3306": ("CRITICAL", "MySQL — SQL injection, data breach exposure"),
    "1433": ("CRITICAL", "MSSQL — SQL injection, data breach exposure"),
    "1521": ("CRITICAL", "Oracle DB — direct database exposure"),
    "5432": ("CRITICAL", "PostgreSQL — direct database exposure"),
}

# ── helpers ────────────────────────────────────────────────────────────────

def latest_snapshot(directory: str = "snapshots") -> str | None:
    """Return path to the most recent snapshot JSON file."""
    p = Path(directory)
    if not p.exists():
        return None
    jsons = sorted(p.glob("snapshot-*.json"), reverse=True)
    return str(jsons[0]) if jsons else None


def badge(text: str, colour: str = "blue") -> str:
    """Return a small pill-shaped HTML span with preset background/foreground pairs."""
    colours = {
        "green":  ("#d1fae5", "#065f46"),
        "red":    ("#fee2e2", "#991b1b"),
        "amber":  ("#fef3c7", "#92400e"),
        "blue":   ("#dbeafe", "#1e40af"),
        "violet": ("#ede9fe", "#5b21b6"),
        "sky":    ("#e0f2fe", "#0369a1"),
        "gray":   ("#f1f5f9", "#475569"),
    }
    bg, fg = colours.get(colour, colours["blue"])
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 10px;'
        f'border-radius:999px;font-size:0.75rem;font-weight:600;'
        f'white-space:nowrap">{text}</span>'
    )


def severity_badge(value, good_up=True) -> str:
    """For booleans, map to YES/NO badges (green when aligned with good_up); otherwise echo str(value)."""
    if isinstance(value, bool):
        return badge("YES" if value else "NO", "green" if value == good_up else "red")
    return str(value)


def table(headers: list[str], rows: list[list], style: str = "") -> str:
    """Build a scroll-wrapped HTML table; cells are inserted verbatim (callers supply badges/markup, not plain text)."""
    ths = "".join(f"<th>{h}</th>" for h in headers)
    trs = ""
    for row in rows:
        tds = "".join(f"<td>{c}</td>" for c in row)
        trs += f"<tr>{tds}</tr>"
    return f'<div class="table-wrap"><table style="{style}"><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>'


# ── main render ────────────────────────────────────────────────────────────

def render(snap: dict) -> str:
    """Turn a snapshot dict into one complete HTML document (KPIs, tables, scope tree, flow sections)."""
    cluster   = snap.get("cluster", "Unknown")
    ts        = snap.get("timestamp", "Unknown")
    root      = snap.get("root_scope", cluster)
    sensors   = snap.get("sensors", {})
    scopes    = snap.get("scopes", {})
    workspaces= snap.get("workspaces", {})
    flows     = snap.get("flows", {})
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total_agents   = sensors.get("total", 0)
    enforced       = sensors.get("enforcement", {}).get("count", 0)
    insecure       = sensors.get("insecure", [])
    health_warn    = sensors.get("health_warn", [])
    total_scopes   = scopes.get("total", 0)
    scope_tree     = scopes.get("tree", "")
    total_ws       = workspaces.get("total", 0)
    total_policies = workspaces.get("grand_policy_total", 0)
    ws_list        = workspaces.get("workspaces", [])
    versions       = sensors.get("versions", {})
    os_years       = sensors.get("os_years", {})
    pkg_vis        = sensors.get("pkg_vis", {}).get("count", 0)
    proc_vis       = sensors.get("proc_vis", {}).get("count", 0)
    forensics      = sensors.get("forensics", {}).get("count", 0)
    # If the snapshot omits health_ok, assume all counted agents are healthy (same number as total_agents).
    health_ok      = sensors.get("health_ok", total_agents)

    flow_total  = flows.get("total_sample", 0)
    permitted   = flows.get("permitted", 0)
    rejected    = flows.get("rejected", 0)
    top_svcs    = flows.get("top_services", {})
    top_ports   = flows.get("top_ports", {})
    protocols   = flows.get("protocols", {})

    # ── insecure cipher rows
    cipher_rows = []
    for h in insecure:
        ips = ", ".join(h.get("ips", []))
        cipher_rows.append([
            f'<code>{h["host"]}</code>',
            f'<code>{ips}</code>',
            badge("Win 2022", "amber"),
            badge("⚠ Insecure", "red"),
        ])

    # ── workspace rows
    ws_rows = []
    for ws in ws_list:
        enf = ws.get("enforcement_enabled", False)
        enf_badge = badge("🔴 OFF", "red") if not enf else badge("✅ ON", "green")
        primary = badge("Primary", "blue") if ws.get("primary") else badge("Alt", "gray")
        ws_rows.append([
            f'<code>{ws.get("name","?")}</code>',
            ws.get("policy_count", 0),
            primary,
            enf_badge,
        ])

    # ── health rows
    health_rows = []
    for w in health_warn:
        health_rows.append([f'<code>{w["host"]}</code>', badge(w["health"].upper(), "red")])

    # ── flow service rows
    svc_rows = [[svc, cnt] for svc, cnt in sorted(top_svcs.items(), key=lambda x: -x[1])]
    port_rows = []
    for p, cnt in sorted(top_ports.items(), key=lambda x: -x[1])[:10]:
        # RISKY_PORTS keys are strings; flow aggregates may use int port keys from JSON.
        risk_info = RISKY_PORTS.get(str(p))
        if risk_info:
            sev, _desc = risk_info
            colour = "red" if sev == "CRITICAL" else "amber"
            port_rows.append([f":{p} {badge(sev, colour)}", cnt])
        else:
            port_rows.append([f":{p}", cnt])

    risky_in_flows = {p: cnt for p, cnt in top_ports.items() if str(p) in RISKY_PORTS}
    risky_alert_rows = []
    for p in sorted(risky_in_flows, key=lambda x: -risky_in_flows[x]):
        sev, desc = RISKY_PORTS[str(p)]
        colour = "red" if sev == "CRITICAL" else "amber"
        risky_alert_rows.append([f":{p}", badge(sev, colour), desc, risky_in_flows[p]])

    # ── scope tree as pre block
    scope_tree_html = f'<pre style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:1rem;font-size:0.8rem;overflow-x:auto;line-height:1.6">{scope_tree}</pre>'

    # ── OS breakdown mini bars
    os_bars = ""
    total_os = sum(os_years.values()) or 1
    os_colours = {"Win 2016": "#94a3b8", "Win 2019": "#3b82f6", "Win 2022": "#0284c7"}
    for name, count in sorted(os_years.items()):
        pct = count / total_os * 100
        col = os_colours.get(name, "#64748b")
        os_bars += f"""
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <span style="width:80px;font-size:0.8rem;color:#475569">{name}</span>
          <div style="flex:1;background:#e2e8f0;border-radius:4px;height:14px;overflow:hidden">
            <div style="width:{pct:.0f}%;background:{col};height:100%;border-radius:4px"></div>
          </div>
          <span style="width:60px;font-size:0.8rem;font-weight:600;color:#0f172a">{count} ({pct:.0f}%)</span>
        </div>"""

    # ── version rows
    ver_rows = [[f'<code>{v}</code>', badge(str(c), "sky")] for v, c in versions.items()]

    # ── protocol rows
    proto_rows = [[p, badge(str(c), "blue")] for p, c in sorted(protocols.items(), key=lambda x: -x[1])]

    # Single f-string document keeps CSS inline so the file opens standalone (no linked assets or template engine).
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Cluster Readout — {cluster}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {{
  --bg:#F8FAFC; --bg2:#F0F4F8; --card:#ffffff; --border:#E2E8F0;
  --cisco:#00bceb; --cisco-dark:#005073; --green:#059669; --red:#dc2626; --amber:#d97706;
  --blue:#0369A1; --sky:#0EA5E9; --text:#020617; --text2:#475569; --text3:#94A3B8;
  --shadow-sm:0 1px 2px rgba(0,0,0,.04),0 1px 3px rgba(0,0,0,.06);
  --shadow-md:0 4px 6px rgba(0,0,0,.04),0 10px 15px rgba(0,0,0,.06);
  --shadow-lg:0 10px 15px rgba(0,0,0,.06),0 20px 25px rgba(0,0,0,.08);
  --radius:10px; --transition:200ms ease;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}}
a{{color:var(--blue);text-decoration:none}}
/* ── header */
.header{{background:linear-gradient(135deg,#00bceb 0%,#005073 100%);color:#fff;padding:2.5rem 2rem 2rem}}
.header h1{{font-size:1.75rem;font-weight:700;letter-spacing:-.3px}}
.header .sub{{opacity:.88;margin-top:.4rem;font-size:0.92rem;font-weight:400}}
.header .meta{{margin-top:1.2rem;display:flex;flex-wrap:wrap;gap:.6rem;font-size:0.78rem}}
.header .meta span{{background:rgba(255,255,255,.14);padding:4px 12px;border-radius:99px;backdrop-filter:blur(4px)}}
/* ── obs banner */
.obs{{background:#FFFBEB;border-left:4px solid #F59E0B;padding:0.9rem 1.4rem;display:flex;align-items:center;gap:.75rem;font-size:0.85rem;color:#78350f}}
/* ── kpi strip */
.kpi-strip{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:1px;background:var(--border);border-bottom:1px solid var(--border)}}
.kpi{{background:var(--card);padding:1.3rem 1rem;text-align:center;transition:background var(--transition)}}
.kpi:hover{{background:#F8FAFC}}
.kpi .val{{font-size:1.85rem;font-weight:700;color:var(--text);line-height:1;font-family:'Inter',sans-serif}}
.kpi .val.warn{{color:var(--red)}}
.kpi .val.ok{{color:var(--green)}}
.kpi .lbl{{font-size:0.68rem;color:var(--text3);margin-top:.35rem;text-transform:uppercase;letter-spacing:.6px;font-weight:500}}
/* ── layout */
.content{{max-width:1140px;margin:2rem auto;padding:0 1.5rem;display:grid;gap:1.5rem}}
/* ── cards */
.card{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow-sm);overflow:hidden;transition:box-shadow var(--transition)}}
.card:hover{{box-shadow:var(--shadow-md)}}
.card-header{{padding:0.85rem 1.4rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.75rem;background:#FAFBFC}}
.card-header h2{{font-size:0.92rem;font-weight:600;color:var(--text)}}
.card-icon{{width:30px;height:30px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:0.95rem;flex-shrink:0}}
.card-body{{padding:1.2rem 1.4rem}}
/* ── tables */
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:0.82rem}}
thead{{background:#F1F5F9}}
th{{padding:.55rem .9rem;text-align:left;font-size:0.7rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);border-bottom:2px solid var(--border);font-weight:600}}
td{{padding:.55rem .9rem;border-bottom:1px solid #F1F5F9;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tbody tr:nth-child(even) td{{background:#FAFBFC}}
tbody tr:hover td{{background:#EFF6FF;transition:background var(--transition)}}
code{{background:#F1F5F9;color:#0F172A;padding:2px 7px;border-radius:4px;font-size:0.78rem;font-family:'Fira Code','Cascadia Code',monospace}}
/* ── two-col */
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}}
@media(max-width:720px){{.two-col{{grid-template-columns:1fr}}}}
/* ── footer */
footer{{text-align:center;padding:2.5rem 1rem;font-size:0.75rem;color:var(--text3);border-top:1px solid var(--border);margin-top:2rem}}
footer strong{{color:var(--text2)}}
/* ── print */
@media print{{
  body{{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .header{{background:#005073 !important;-webkit-print-color-adjust:exact}}
  .card{{box-shadow:none;break-inside:avoid}}
  .card:hover{{box-shadow:none}}
  .kpi:hover{{background:var(--card)}}
  .obs{{border-left-color:#d97706 !important}}
  footer{{page-break-before:auto}}
}}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div style="max-width:1100px;margin:0 auto">
    <div style="display:flex;align-items:flex-start;gap:1.5rem;flex-wrap:wrap">
      <div>
        <!-- Cisco wordmark -->
        <svg width="80" height="28" viewBox="0 0 80 28" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-bottom:0.5rem;opacity:.95">
          <text x="0" y="22" font-family="Arial,sans-serif" font-size="24" font-weight="700" fill="white">CISCO</text>
        </svg>
        <h1>Cisco Secure Workload</h1>
        <div class="sub">Cluster Readout — <strong>{cluster}</strong></div>
        <div class="meta">
          <span>Snapshot: {ts}</span>
          <span>Generated: {generated}</span>
          <span>Root Scope: {root}</span>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- OBSERVATION BANNER -->
<div class="obs">
  <span style="font-size:1.2rem">👁</span>
  <div><strong>Observation Mode Active</strong> — All {total_agents} agents are in visibility-only mode.
  Enforcement is disabled. Policies are being learned via ADM. No traffic is being blocked.</div>
</div>

<!-- KPI STRIP -->
<div class="kpi-strip">
  <div class="kpi"><div class="val">{total_agents}</div><div class="lbl">Agents</div></div>
  <div class="kpi"><div class="val {'warn' if insecure else 'ok'}">{len(insecure)}</div><div class="lbl">Insecure Cipher</div></div>
  <div class="kpi"><div class="val {'warn' if health_warn else 'ok'}">{health_ok}</div><div class="lbl">Healthy Agents</div></div>
  <div class="kpi"><div class="val">{total_scopes}</div><div class="lbl">Scopes</div></div>
  <div class="kpi"><div class="val">{total_ws}</div><div class="lbl">Workspaces</div></div>
  <div class="kpi"><div class="val">{total_policies}</div><div class="lbl">ADM Policies</div></div>
  <div class="kpi"><div class="val ok">{enforced}</div><div class="lbl">Enforcement ON</div></div>
  <div class="kpi"><div class="val ok">{permitted}</div><div class="lbl">Flows Permitted</div></div>
</div>

<!-- MAIN CONTENT -->
<div class="content">

  <!-- Agent Overview -->
  <div class="two-col">
    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:#dbeafe">🖥</div>
        <h2>Agent Deployment</h2>
      </div>
      <div class="card-body">
        {table(["Capability", "Count", "Coverage"],
               [["Package Visibility", pkg_vis, badge(f"{int(pkg_vis/total_agents*100)}%","green")],
                ["Process Visibility", proc_vis, badge(f"{int(proc_vis/total_agents*100)}%","green")],
                ["Forensics", forensics, badge(f"{int(forensics/total_agents*100)}%","green")],
                ["Enforcement Active", enforced, badge("0% — Obs. Mode","amber") if not enforced else badge(f"{int(enforced/total_agents*100)}%","red")],
                ["Healthy / Active", health_ok, badge(f"{int(health_ok/total_agents*100)}%", "green" if health_ok==total_agents else "amber")],
               ])}
        <div style="margin-top:1.2rem">
          <div style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:.6rem">OS Distribution</div>
          {os_bars}
        </div>
        <div style="margin-top:1.2rem">
          {table(["Agent Version", "Hosts"], ver_rows)}
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:#fef3c7">🌐</div>
        <h2>Workspaces & Policies</h2>
      </div>
      <div class="card-body">
        <div style="margin-bottom:1rem;font-size:0.85rem;color:var(--text2)">
          <strong>{total_ws}</strong> workspaces · <strong>{total_policies}</strong> ADM-generated policies
        </div>
        {table(["Workspace", "Policies", "Type", "Enforcing"], ws_rows)}
        {"" if not health_warn else f'<div style="margin-top:1rem"><div style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.5px;color:#dc2626;margin-bottom:.5rem">⚠ Agent Health Warnings</div>{table(["Hostname","Status"],health_rows)}</div>'}
      </div>
    </div>
  </div>

  <!-- Insecure Cipher Hosts -->
  {"" if not insecure else f'''
  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#fee2e2">🔒</div>
      <h2>Insecure TLS Cipher Hosts ({len(insecure)})</h2>
    </div>
    <div class="card-body">
      <div style="margin-bottom:1rem;font-size:0.85rem;color:#7f1d1d;background:#fef2f2;border:1px solid #fca5a5;padding:.75rem 1rem;border-radius:8px">
        ⚠ These {len(insecure)} Windows Server 2022 hosts are communicating with deprecated TLS cipher suites.
        Remediate via Group Policy (GPO) or registry using the Microsoft Security Baseline or CIS Benchmark for Windows Server 2022.
      </div>
      {table(["Hostname","IP Address","OS","Status"],cipher_rows)}
    </div>
  </div>
  '''}

  <!-- Scope Hierarchy -->
  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#ede9fe">🗂</div>
      <h2>Scope Hierarchy ({total_scopes} scopes)</h2>
    </div>
    <div class="card-body">
      {scope_tree_html}
    </div>
  </div>

  <!-- Flow Analysis -->
  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#d1fae5">📊</div>
      <h2>Flow Analysis — 24-Hour Sample</h2>
    </div>
    <div class="card-body">
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem;text-align:center">
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:1rem">
          <div style="font-size:1.6rem;font-weight:700;color:#065f46">{flow_total}</div>
          <div style="font-size:0.72rem;color:#059669;margin-top:.2rem;text-transform:uppercase">Flows Sampled</div>
        </div>
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:1rem">
          <div style="font-size:1.6rem;font-weight:700;color:#065f46">{permitted}</div>
          <div style="font-size:0.72rem;color:#059669;margin-top:.2rem;text-transform:uppercase">Permitted</div>
        </div>
        <div style="background:{'#fef2f2' if rejected else '#f0fdf4'};border:1px solid {'#fca5a5' if rejected else '#bbf7d0'};border-radius:8px;padding:1rem">
          <div style="font-size:1.6rem;font-weight:700;color:{'#991b1b' if rejected else '#065f46'}">{rejected}</div>
          <div style="font-size:0.72rem;color:{'#dc2626' if rejected else '#059669'};margin-top:.2rem;text-transform:uppercase">Rejected</div>
        </div>
      </div>
      <div class="two-col">
        <div>
          <div style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:.6rem">Top Application Services</div>
          {table(["Service","Flows"],svc_rows)}
        </div>
        <div>
          <div style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:.6rem">Top Destination Ports</div>
          {table(["Port","Flows"],port_rows)}
          <div style="margin-top:1rem">
          <div style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:.6rem">Protocols</div>
          {table(["Protocol","Flows"],proto_rows)}
          </div>
        </div>
      </div>
    </div>
  </div>

  {"" if not risky_alert_rows else f'''
  <div class="card" style="border-left:4px solid var(--red)">
    <div class="card-header">
      <div class="card-icon" style="background:#fee2e2">&#9888;</div>
      <h2>High-Risk Port Communications Detected</h2>
    </div>
    <div class="card-body">
      <div style="margin-bottom:1rem;font-size:0.85rem;color:#7f1d1d;background:#fef2f2;border:1px solid #fca5a5;padding:.75rem 1rem;border-radius:8px">
        <strong>Security Alert:</strong> {len(risky_alert_rows)} high-risk port(s) with {sum(risky_in_flows.values())} total flows detected in the 24-hour sample.
        These ports are commonly targeted for brute-force attacks, data exfiltration, and ransomware.
      </div>
      {table(["Port", "Severity", "Risk Description", "Flows"], risky_alert_rows)}
    </div>
  </div>
  '''}

</div><!-- /content -->

<footer>
  <strong>Cisco Secure Workload</strong> — Auto-generated cluster readout<br>
  Cluster: <code>{cluster}</code> &nbsp;|&nbsp; Snapshot: {ts} &nbsp;|&nbsp; Report generated: {generated}<br>
  <span style="margin-top:.4rem;display:block">Generated by <code>generate_html_report.py</code> · Cisco SE Toolkit</span>
</footer>

</body>
</html>"""


# ── entry point ────────────────────────────────────────────────────────────

def main():
    """CLI: pick snapshot path, load JSON, write default or requested HTML under reports/."""
    parser = argparse.ArgumentParser(
        description="Generate an HTML readout from a CSW cluster snapshot JSON."
    )
    parser.add_argument(
        "--snapshot", "-s",
        default=None,
        help="Path to snapshot JSON (default: latest in snapshots/)"
    )
    parser.add_argument(
        "--out", "-o",
        default=None,
        help="Output HTML path (default: reports/readout-<date>.html)"
    )
    args = parser.parse_args()

    # Resolve snapshot path
    snap_path = args.snapshot or latest_snapshot()
    if not snap_path:
        print("❌  No snapshot found. Run cluster_snapshot.py first.")
        sys.exit(1)

    if not os.path.exists(snap_path):
        print(f"❌  Snapshot not found: {snap_path}")
        sys.exit(1)

    with open(snap_path) as f:
        snap = json.load(f)

    print(f"📂  Snapshot: {snap_path}")
    print(f"🏢  Cluster:  {snap.get('cluster','?')}")

    # Resolve output path
    date_tag = datetime.now().strftime("%Y-%m-%d")
    out_path = args.out or f"reports/readout-{date_tag}.html"
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    html = render(snap)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅  HTML report: {out_path}")
    print(f"\n   Open in browser:")
    print(f"   open {out_path}   (macOS)")
    print(f"   start {out_path}  (Windows)")


if __name__ == "__main__":
    main()
