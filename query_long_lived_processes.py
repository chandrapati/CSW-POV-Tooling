#!/usr/bin/env python3
"""
Quick summary: Runs one flowsearch per day across a window and ranks persistent vs
recurring vs transient processes per host (console table + HTML + optional JSON).

query_long_lived_processes.py — Identify persistent processes across the CSW cluster
-------------------------------------------------------------------------------------
Queries the CSW flowsearch API across multiple 24-hour windows and identifies
processes that appear consistently over time — indicating long-lived services,
agents, and daemons running on monitored hosts.

The CSW flowsearch API has a maximum query duration of 1 day, so this script
issues one query per day and aggregates the results across the full window.

Analysis dimensions:
  - Days observed (persistence score)
  - Total flow count per process+host
  - Destination ports and protocols used
  - Process categorisation (security agent, monitoring, database, backup, etc.)

Output:
  - Console summary table (always)
  - HTML report (default: reports/long-lived-processes-<date>.html)
  - JSON export (optional: snapshots/long-lived-processes-<date>.json)

Usage:
    python3 query_long_lived_processes.py
    python3 query_long_lived_processes.py --days 7
    python3 query_long_lived_processes.py --days 5 --min-days 3
    python3 query_long_lived_processes.py --limit 1000 --json
    python3 query_long_lived_processes.py --out reports/my-report.html

Requirements:
    csw_api.py in the same directory with .env credentials configured.
    API key must have flow_inventory_query capability.
"""

import argparse
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Ensure csw_api.py (sibling module) is importable regardless of cwd.
# This lets the script work whether you run it from the project root or via
# an absolute path from elsewhere.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csw_api

# Load .env credentials (CSW_API_URL, CSW_API_KEY, CSW_API_SECRET)
csw_api._load_dotenv()

# Today's date tag used in output filenames
DATE_TAG = datetime.now().strftime("%Y-%m-%d")

# CSW API pagination: max flows per page and max pages per 24h window.
# BATCH_SIZE of 500 is the practical maximum for the flowsearch endpoint.
# MAX_PAGES_PER_DAY caps total API calls per day to avoid excessive load.
BATCH_SIZE = 500
MAX_PAGES_PER_DAY = 10

# ──────────────────────────────────────────────────────────────────────────────
# Lookup tables for port labelling, risk flagging, and process classification
# ──────────────────────────────────────────────────────────────────────────────

# Maps numeric port → human-readable service name for console and HTML output
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5671: "AMQPS",
    5672: "AMQP", 5985: "WinRM", 5986: "WinRM-S", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9090: "Prometheus", 27017: "MongoDB",
}

# Ports flagged as security-sensitive — remote admin and database ports that
# should not be broadly exposed. Processes communicating on these are highlighted.
RISKY_PORTS = {22, 23, 20, 21, 25, 139, 445, 1433, 1521, 3306, 3389, 5432}

# Regex patterns to classify process command lines into categories.
# Evaluated in order — first match wins. Add new patterns at the end.
PROCESS_CATEGORIES = [
    (r"(?i)tetration|TetSen|TetUpdate|tet-main", "Cisco Tetration Agent"),
    (r"(?i)orbital", "Cisco Orbital"),
    (r"(?i)cisco.*amp|sfc\.exe", "Cisco AMP / Secure Endpoint"),
    (r"(?i)appdynamics|MachineAgentService", "AppDynamics Agent"),
    (r"(?i)datadog|process-agent", "Datadog Agent"),
    (r"(?i)promtail|prometheus", "Prometheus / Monitoring"),
    (r"(?i)rubrik|rba\.exe", "Rubrik Backup"),
    (r"(?i)commvault|cvd\.exe|cvfwd\.exe", "Commvault Backup"),
    (r"(?i)defender|SenseTracer", "Windows Defender ATP"),
    (r"(?i)AzureConnectedMachine|gc_service", "Azure Arc Agent"),
    (r"(?i)w3wp\.exe", "IIS Application Pool"),
    (r"(?i)svchost\.exe", "Windows Service Host"),
    (r"(?i)wmiprvse", "WMI Provider"),
    (r"(?i)conhost\.exe", "Console Host"),
    (r"(?i)mfserver\.exe|M-Files", "M-Files Server"),
    (r"(?i)InfoSphere|dmts64-java", "IBM Data Replication"),
    (r"(?i)VisualCron", "VisualCron Scheduler"),
    (r"(?i)ClickDimensions", "ClickDimensions Service"),
    (r"(?i)sqlservr\.exe", "SQL Server Engine"),
    (r"(?i)mysqld", "MySQL Server"),
    (r"(?i)postgres", "PostgreSQL Server"),
]


# ──────────────────────────────────────────────────────────────
# API helpers
# ──────────────────────────────────────────────────────────────

def get_root_scope():
    """Discover the cluster root scope name dynamically.

    The flowsearch API requires a valid scopeName parameter. Rather than
    hard-coding it (each cluster has a different root scope name), we
    fetch all scopes and find the one with no parent — that's the root.

    Returns:
        str: Root scope name (e.g. 'my-cluster-abc123'), or 'Default' as fallback.
    """
    r = csw_api.make_request("GET", "/openapi/v1/app_scopes")
    if r.get("status") != 200:
        return "Default"
    scopes = r.get("data", [])
    if not isinstance(scopes, list):
        return "Default"
    # The root scope is the only scope with no parent_app_scope_id
    root = next(
        (s for s in scopes if isinstance(s, dict) and not s.get("parent_app_scope_id")),
        None,
    )
    return root["name"] if root else "Default"


def fetch_day_flows(root_scope, t0, t1, limit):
    """Fetch up to `limit` flows for a single 24-hour window.

    Uses cursor-based pagination (offset token) to walk through large result
    sets. Each page returns up to BATCH_SIZE flows. Stops when:
      - We've collected `limit` flows, OR
      - The API returns fewer results than BATCH_SIZE (end of data), OR
      - We've hit MAX_PAGES_PER_DAY (safety cap)

    Args:
        root_scope: CSW root scope name for the query filter.
        t0: Start time (Unix epoch seconds).
        t1: End time (Unix epoch seconds). Must be <= t0 + 86400.
        limit: Maximum flows to retrieve for this day.

    Returns:
        list[dict]: Flow records with fields like src_address, dst_address,
                    fwd_process_string, rev_process_string, dst_port, proto.
    """
    flows = []
    offset = ""  # Cursor token for pagination; empty string = first page
    page = 0

    while len(flows) < limit and page < MAX_PAGES_PER_DAY:
        page += 1
        body = {
            "t0": t0,
            "t1": t1,
            "filter": {"type": "subnet", "field": "src_address", "value": "0.0.0.0/0"},
            "scopeName": root_scope,
            "limit": min(BATCH_SIZE, limit - len(flows)),
        }
        if offset:
            body["offset"] = offset

        r = csw_api.make_request("POST", "/openapi/v1/flowsearch", body=body)
        if r.get("status") != 200:
            err = r.get("data", {})
            msg = err.get("error", str(err)) if isinstance(err, dict) else str(err)
            print(f"      API error page {page}: HTTP {r.get('status')} — {msg}", file=sys.stderr)
            break

        data = r.get("data", {})
        if not isinstance(data, dict):
            break

        results = data.get("results", [])
        if not results:
            break

        flows.extend(results)

        if len(results) < BATCH_SIZE or not data.get("offset"):
            break
        offset = data.get("offset", "")
        time.sleep(0.15)

    return flows


def fetch_multi_day_flows(root_scope, days, limit_per_day):
    """Query flows across multiple 24-hour windows.

    The CSW flowsearch API enforces a maximum query duration of 1 day.
    To analyse longer periods, we issue one query per day, walking backward
    from the current time. Each flow is tagged with a _day_offset so the
    downstream analysis can determine on which day(s) a process appeared.

    Args:
        root_scope: CSW root scope name.
        days: Number of 24-hour windows to query (e.g. 3 = last 3 days).
        limit_per_day: Maximum flows to retrieve per day.

    Returns:
        list[dict]: Combined flow records from all days, each augmented
                    with a _day_offset field (0 = most recent day).
    """
    now = int(time.time())
    all_flows = []

    for day_offset in range(days):
        # Walk backward from now: day 0 = today, day 1 = yesterday, etc.
        t1 = now - (day_offset * 86400)
        t0 = t1 - 86400

        day_label = datetime.fromtimestamp(t0, tz=timezone.utc).strftime("%Y-%m-%d")
        print(f"    Day {day_offset + 1}/{days} ({day_label})...", end="", flush=True, file=sys.stderr)

        day_flows = fetch_day_flows(root_scope, t0, t1, limit_per_day)

        # Tag each flow with the day offset for persistence tracking
        for f in day_flows:
            f["_day_offset"] = day_offset

        all_flows.extend(day_flows)
        print(f" {len(day_flows):,} flows", file=sys.stderr)

    return all_flows


# ──────────────────────────────────────────────────────────────
# Analysis
# ──────────────────────────────────────────────────────────────

def categorise_process(proc_string):
    """Match a process string against known patterns and return a category label."""
    for pattern, label in PROCESS_CATEGORIES:
        if re.search(pattern, proc_string):
            return label
    return "Other"


def shorten_process(proc_string, max_len=80):
    """Truncate a long process command line for display."""
    if len(proc_string) <= max_len:
        return proc_string
    return proc_string[:max_len - 3] + "..."


def analyse_processes(flows, total_days):
    """Aggregate flows by process+host and compute persistence metrics.

    Returns a list of process records sorted by persistence (days seen desc,
    flow count desc), each containing:
      - process: full process command string
      - process_short: truncated display string
      - host: source or destination IP
      - flow_count: total flows observed
      - days_seen: set of day offsets where the process appeared
      - dst_ports: set of destination ports used
      - protocols: set of IP protocol numbers
      - category: classified process type
      - persistence: "persistent" / "recurring" / "transient"
    """
    # Accumulator keyed by (process_string, host_ip)
    proc_stats = {}

    for f in flows:
        day = f.get("_day_offset", 0)

        # Each flow has two process fields: fwd (source-side) and rev
        # (destination-side). We extract both to capture processes on
        # either end of the connection.
        for proc_field, ip_field in [
            ("fwd_process_string", "src_address"),
            ("rev_process_string", "dst_address"),
        ]:
            proc = f.get(proc_field)
            if not proc:
                continue
            ip = f.get(ip_field, "?")
            key = (proc, ip)

            if key not in proc_stats:
                proc_stats[key] = {
                    "process": proc,
                    "process_short": shorten_process(proc),
                    "host": ip,
                    "flow_count": 0,
                    "days_seen": set(),
                    "dst_ports": set(),
                    "protocols": set(),
                    "category": categorise_process(proc),
                }
            rec = proc_stats[key]
            rec["flow_count"] += 1
            rec["days_seen"].add(day)

            dst_port = f.get("dst_port")
            if dst_port is not None:
                try:
                    rec["dst_ports"].add(int(dst_port))
                except (ValueError, TypeError):
                    pass

            proto = f.get("proto")
            if proto is not None:
                try:
                    rec["protocols"].add(int(proto))
                except (ValueError, TypeError):
                    rec["protocols"].add(str(proto))

    # Classify each process by how often it appeared:
    #   persistent = every single day (strong indicator of a long-lived service)
    #   recurring  = at least half the days, or 2+ days (probable daemon/agent)
    #   transient  = seen on only 1 day (likely one-off or short-lived)
    for rec in proc_stats.values():
        n = len(rec["days_seen"])
        if n >= total_days:
            rec["persistence"] = "persistent"
        elif n >= max(2, total_days // 2):
            rec["persistence"] = "recurring"
        else:
            rec["persistence"] = "transient"

    # Sort by most-persistent first, then by flow volume as tiebreaker
    ranked = sorted(
        proc_stats.values(),
        key=lambda x: (-len(x["days_seen"]), -x["flow_count"]),
    )
    return ranked


# ──────────────────────────────────────────────────────────────
# Console output
# ──────────────────────────────────────────────────────────────

def print_summary(records, total_flows, total_days, min_days):
    """Print a formatted console summary of long-lived processes."""
    filtered = [r for r in records if len(r["days_seen"]) >= min_days]

    print(f"\n{'=' * 130}")
    print(f" LONG-LIVED PROCESSES — {total_flows:,} flows across {total_days} day(s)")
    print(f" Showing processes seen on {min_days}+ day(s)")
    print(f"{'=' * 130}\n")

    print(f"{'#':<4s} {'Days':<6s} {'Flows':<8s} {'Host':<18s} {'Category':<25s} {'Ports':<20s} {'Process':<50s}")
    print("-" * 130)

    for i, r in enumerate(filtered[:60], 1):
        ports_list = sorted(r["dst_ports"], key=int)[:5]
        ports_str = ",".join(
            f"{p}({WELL_KNOWN_PORTS[p]})" if p in WELL_KNOWN_PORTS else str(p)
            for p in ports_list
        )
        proc = shorten_process(r["process"], 48)
        days = len(r["days_seen"])
        print(f"{i:<4d} {days:<6d} {r['flow_count']:<8d} {r['host']:<18s} {r['category']:<25s} {ports_str:<20s} {proc}")

    persistent = len([r for r in records if r["persistence"] == "persistent"])
    recurring = len([r for r in records if r["persistence"] == "recurring"])
    transient = len([r for r in records if r["persistence"] == "transient"])

    print(f"\n--- Summary ---")
    print(f"Total unique process+host combinations: {len(records)}")
    print(f"Persistent (seen all {total_days} days):       {persistent}")
    print(f"Recurring  (seen {max(2, total_days // 2)}+ days):            {recurring}")
    print(f"Transient  (seen 1 day only):            {transient}")
    print(f"Matching filter (>={min_days} days):         {len(filtered)}")


# ──────────────────────────────────────────────────────────────
# HTML report
# ──────────────────────────────────────────────────────────────

def render_html(records, total_flows, total_days, cluster, generated):
    """Build a self-contained HTML report of long-lived process analysis."""

    persistent = [r for r in records if r["persistence"] == "persistent"]
    recurring = [r for r in records if r["persistence"] == "recurring"]
    transient = [r for r in records if r["persistence"] == "transient"]

    category_counter = Counter(r["category"] for r in records)
    host_counter = Counter(r["host"] for r in records)

    risky_procs = [
        r for r in records
        if r["dst_ports"] & RISKY_PORTS and len(r["days_seen"]) >= 2
    ]

    # KPI cards
    kpis = [
        ("", f"{total_flows:,}", "Total Flows Analysed"),
        ("", str(total_days), "Days Queried"),
        ("", str(len(records)), "Process+Host Combos"),
        ("ok", str(len(persistent)), f"Persistent ({total_days}/{total_days} days)"),
        ("", str(len(recurring)), "Recurring (2+ days)"),
        ("", str(len(transient)), "Transient (1 day)"),
        ("", str(len(host_counter)), "Unique Hosts"),
        ("", str(len(category_counter)), "Process Categories"),
        ("warn" if risky_procs else "ok", str(len(risky_procs)), "Risky Port Processes"),
    ]
    kpi_html = "".join(
        f'<div class="kpi {cls}"><div class="val">{val}</div><div class="lbl">{lbl}</div></div>'
        for cls, val, lbl in kpis
    )

    # Category breakdown table
    cat_rows = "".join(
        f"<tr><td>{cat}</td><td>{cnt}</td></tr>"
        for cat, cnt in category_counter.most_common()
    )

    # Persistent processes table
    def _proc_rows(proc_list, max_rows=60):
        rows = ""
        for i, r in enumerate(proc_list[:max_rows], 1):
            days = len(r["days_seen"])
            ports_list = sorted(r["dst_ports"], key=int)[:6]
            ports_str = ", ".join(
                f"<span class='port-risky'>{p}</span>" if p in RISKY_PORTS
                else f"{p}"
                for p in ports_list
            )
            badge_cls = "badge-ok" if r["persistence"] == "persistent" else "badge-warn" if r["persistence"] == "recurring" else ""
            badge_lbl = r["persistence"].upper()
            rows += (
                f"<tr>"
                f"<td>{i}</td>"
                f"<td><span class='badge {badge_cls}'>{days}/{total_days}</span></td>"
                f"<td>{r['flow_count']:,}</td>"
                f"<td>{r['host']}</td>"
                f"<td>{r['category']}</td>"
                f"<td>{ports_str}</td>"
                f"<td><code>{r['process_short']}</code></td>"
                f"</tr>"
            )
        return rows

    persistent_rows = _proc_rows(persistent)
    recurring_rows = _proc_rows(recurring)

    # Risky port processes
    risky_rows = ""
    if risky_procs:
        for r in sorted(risky_procs, key=lambda x: -x["flow_count"])[:30]:
            risky_ports_hit = sorted(r["dst_ports"] & RISKY_PORTS)
            port_labels = ", ".join(
                f"{p} ({WELL_KNOWN_PORTS.get(p, '?')})" for p in risky_ports_hit
            )
            risky_rows += (
                f"<tr><td>{r['host']}</td>"
                f"<td><code>{r['process_short']}</code></td>"
                f"<td>{port_labels}</td>"
                f"<td>{len(r['days_seen'])}/{total_days}</td>"
                f"<td>{r['flow_count']:,}</td></tr>"
            )
    else:
        risky_rows = "<tr><td colspan='5' style='color:#059669;font-weight:600'>No persistent processes communicating on risky ports</td></tr>"

    # Top hosts by process count
    host_rows = "".join(
        f"<tr><td>{host}</td><td>{cnt}</td></tr>"
        for host, cnt in host_counter.most_common(20)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Long-Lived Process Analysis — {cluster}</title>
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
       gap:1.25rem; max-width:1400px; margin:0 auto }}
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
.port-risky {{ color:var(--red); font-weight:700 }}
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
    <h1>Secure Workload — Long-Lived Process Analysis</h1>
    <small>Cluster: {cluster} &nbsp;|&nbsp; Window: {total_days} day(s) &nbsp;|&nbsp;
           Flows: {total_flows:,} &nbsp;|&nbsp; Generated: {generated}</small>
  </div>
</header>
<main>

<div class="card full">
  <h2>Summary</h2>
  <div class="kpi-grid">{kpi_html}</div>
</div>

<div class="card">
  <h2>Process Categories</h2>
  <table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>{cat_rows}</tbody></table>
</div>

<div class="card">
  <h2>Top Hosts by Process Count</h2>
  <table><thead><tr><th>Host IP</th><th>Processes</th></tr></thead><tbody>{host_rows}</tbody></table>
</div>

<div class="card full">
  <h2>Persistent Processes <span style="font-size:.72rem;font-weight:400;color:var(--text3)">(seen all {total_days} days)</span></h2>
  <table><thead><tr><th>#</th><th>Days</th><th>Flows</th><th>Host</th><th>Category</th><th>Ports</th><th>Process</th></tr></thead>
  <tbody>{persistent_rows if persistent_rows else "<tr><td colspan='7' style='color:var(--text3)'>No persistent processes found</td></tr>"}</tbody></table>
</div>

<div class="card full">
  <h2>Recurring Processes <span style="font-size:.72rem;font-weight:400;color:var(--text3)">(seen 2+ days but not every day)</span></h2>
  <table><thead><tr><th>#</th><th>Days</th><th>Flows</th><th>Host</th><th>Category</th><th>Ports</th><th>Process</th></tr></thead>
  <tbody>{recurring_rows if recurring_rows else "<tr><td colspan='7' style='color:var(--text3)'>No recurring processes found</td></tr>"}</tbody></table>
</div>

<div class="card full">
  <h2>Risky Port Processes <span style="font-size:.72rem;font-weight:400;color:var(--text3)">(persistent processes on high-risk ports)</span></h2>
  <table><thead><tr><th>Host</th><th>Process</th><th>Risky Ports</th><th>Days</th><th>Flows</th></tr></thead>
  <tbody>{risky_rows}</tbody></table>
</div>

</main>
<footer>
  <strong>Cisco Secure Workload</strong> — Long-Lived Process Analysis &nbsp;|&nbsp;
  {generated} &nbsp;|&nbsp; {total_days}-day window
  <br><span style="margin-top:.3rem;display:block">Generated by <code>query_long_lived_processes.py</code> &middot; Cisco SE Toolkit</span>
</footer>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────

def main():
    """CLI entry point: discover scope → fetch multi-day flows → analyse → export.

    Three-phase pipeline:
      [1/3] Auto-discover the cluster's root scope name from the app_scopes API
      [2/3] Fetch flows across N consecutive 24-hour windows (API limit workaround)
      [3/3] Aggregate flows by process+host, classify persistence, and export
    """
    parser = argparse.ArgumentParser(
        description="Identify long-lived / persistent processes across the CSW cluster.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 query_long_lived_processes.py
  python3 query_long_lived_processes.py --days 7
  python3 query_long_lived_processes.py --days 5 --min-days 3
  python3 query_long_lived_processes.py --limit 1000 --json
  python3 query_long_lived_processes.py --out reports/my-report.html
        """,
    )
    parser.add_argument(
        "--days", type=int, default=3,
        help="Number of days to look back (default: 3)",
    )
    parser.add_argument(
        "--min-days", type=int, default=2,
        help="Minimum days a process must appear to be shown in console output (default: 2)",
    )
    parser.add_argument(
        "--limit", type=int, default=2500,
        help="Max flows to fetch per day (default: 2500)",
    )
    parser.add_argument(
        "--out", "-o", default=None,
        help="Output HTML path (default: reports/long-lived-processes-<date>.html)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Also export raw process data as JSON",
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip HTML report generation (console output only)",
    )
    args = parser.parse_args()

    cluster = os.environ.get("CSW_API_URL", "?").replace("https://", "").split("/")[0]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(f"\n  Cluster:    {cluster}", file=sys.stderr)
    print(f"  Window:     Last {args.days} day(s)", file=sys.stderr)
    print(f"  Limit:      {args.limit:,} flows/day", file=sys.stderr)
    print(f"  Min days:   {args.min_days}", file=sys.stderr)

    # Phase 1: Discover root scope
    print(f"\n  [1/3] Discovering root scope...", end="", flush=True, file=sys.stderr)
    root_scope = get_root_scope()
    print(f" '{root_scope}'", file=sys.stderr)

    # Phase 2: Fetch flows across multiple days
    print(f"  [2/3] Fetching flows ({args.days} day(s))...", file=sys.stderr)
    flows = fetch_multi_day_flows(root_scope, args.days, args.limit)
    print(f"    Total: {len(flows):,} flows", file=sys.stderr)

    if not flows:
        print("  No flows returned. Check API key capabilities (flow_inventory_query).", file=sys.stderr)
        sys.exit(1)

    # Phase 3: Analyse
    print(f"  [3/3] Analysing processes...", file=sys.stderr)
    records = analyse_processes(flows, args.days)

    # Console output
    print_summary(records, len(flows), args.days, args.min_days)

    # HTML report
    if not args.no_html:
        html_path = args.out or f"reports/long-lived-processes-{DATE_TAG}.html"
        os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)
        html = render_html(records, len(flows), args.days, cluster, generated)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n  HTML report: {html_path}", file=sys.stderr)
        print(f"  Open: open {html_path}", file=sys.stderr)

    # JSON export
    if args.json:
        json_path = f"snapshots/long-lived-processes-{DATE_TAG}.json"
        os.makedirs("snapshots", exist_ok=True)
        export = []
        for r in records:
            export.append({
                "process": r["process"],
                "host": r["host"],
                "category": r["category"],
                "persistence": r["persistence"],
                "days_seen": len(r["days_seen"]),
                "flow_count": r["flow_count"],
                "dst_ports": sorted(r["dst_ports"], key=str),
                "protocols": sorted(r["protocols"], key=str),
            })
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2)
        print(f"  JSON export: {json_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
