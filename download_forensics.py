#!/usr/bin/env python3
"""
download_forensics.py — Download forensics configuration from the CSW cluster
------------------------------------------------------------------------------
Queries the CSW forensics configuration API to retrieve the full forensic
posture of the cluster: profiles, rules (MITRE ATT&CK detections), intents,
and intent ordering.

CSW forensics on SaaS clusters:
  - Raw forensic *events* (process traces, file events, network events) are
    NOT accessible via the public OpenAPI v1 on SaaS clusters — those endpoints
    return HTTP 404. This is a known SaaS limitation documented by Cisco.
  - What IS accessible: the forensic *configuration* — profiles, rules, and
    intents that define what the agents are looking for. These live under
    /openapi/v1/inventory_config/forensic_* and require the sensor_management
    API key capability.

This script downloads all four forensics configuration resources:
  1. Forensic Profiles — named collections of detection rules applied to agents
  2. Forensic Rules — individual detection rules (MITRE ATT&CK techniques,
     severity, actions like ALERT/RECORD, and clause-based match criteria)
  3. Forensic Intents — bindings that link a profile to a group of agents
     (defined by an inventory filter)
  4. Forensic Intent Orders — priority ordering when intents overlap

Output:
  - JSON export: snapshots/forensics-config-<date>.json
  - HTML report: reports/forensics-config-<date>.html
  - Console summary (always printed)

Usage:
    python3 download_forensics.py
    python3 download_forensics.py --out reports/my-forensics.html
    python3 download_forensics.py --no-html
    python3 download_forensics.py --json-out snapshots/my-forensics.json

Requirements:
    csw_api.py in the same directory with .env credentials configured.
    API key must have sensor_management capability.
"""

import argparse
import json
import os
import sys
import time
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


# ──────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK technique metadata
# ──────────────────────────────────────────────────────────────────────────────
# Maps MITRE technique IDs to tactic categories for the report.
# Extracted from the rule names returned by the CSW API (format: "T1xxx - Name").
# Only the most common techniques are listed; unknown IDs fall back to "Other".
MITRE_TACTICS = {
    "T1003": "Credential Access",
    "T1053": "Execution / Persistence",
    "T1059": "Execution",
    "T1064": "Execution",
    "T1086": "Execution",
    "T1117": "Defense Evasion",
    "T1118": "Defense Evasion",
    "T1121": "Defense Evasion",
    "T1127": "Defense Evasion",
    "T1170": "Defense Evasion",
    "T1191": "Defense Evasion",
    "T1196": "Defense Evasion",
    "T1197": "Persistence",
    "T1202": "Defense Evasion",
    "T1216": "Defense Evasion",
    "T1218": "Defense Evasion",
    "T1220": "Defense Evasion",
    "T1223": "Defense Evasion",
}


# ──────────────────────────────────────────────────────────────────────────────
# API fetchers — one function per forensics resource type
# ──────────────────────────────────────────────────────────────────────────────

def fetch_profiles():
    """Fetch all forensic profiles from the cluster.

    Forensic profiles are named collections of detection rules. Each profile
    contains a list of forensic_rules (fully expanded objects, not just IDs)
    and is scoped to a root_app_scope.

    Returns:
        list[dict]: Array of profile objects, or empty list on failure.
    """
    r = csw_api.make_request("GET", "/openapi/v1/inventory_config/forensic_profiles")
    if r.get("status") != 200:
        print(f"    Profiles: HTTP {r.get('status')} — {r.get('error', '?')}", file=sys.stderr)
        return []
    data = r.get("data", [])
    return data if isinstance(data, list) else []


def fetch_rules():
    """Fetch all forensic rules from the cluster.

    Forensic rules are individual detection signatures. Each rule has:
      - name: human-readable label, often MITRE ATT&CK technique IDs
      - type: PREDEFINED (built-in) or CUSTOM (user-created)
      - severity: LOW / MEDIUM / HIGH / CRITICAL
      - actions: list of ALERT, RECORD, SNAPSHOT
      - clause_chips: JSON-encoded filter expression defining the match logic
      - description: explanation of what the rule detects
      - reference_url: link to MITRE ATT&CK or other documentation

    Returns:
        list[dict]: Array of rule objects, or empty list on failure.
    """
    r = csw_api.make_request("GET", "/openapi/v1/inventory_config/forensic_rules")
    if r.get("status") != 200:
        print(f"    Rules: HTTP {r.get('status')} — {r.get('error', '?')}", file=sys.stderr)
        return []
    data = r.get("data", [])
    return data if isinstance(data, list) else []


def fetch_intents():
    """Fetch all forensic intents from the cluster.

    Forensic intents bind a profile to a group of agents. The agent group
    is defined by an inventory_filter_id (which references a scope or
    custom filter). When filters overlap, the intent order determines
    which profile takes precedence.

    Returns:
        list[dict]: Array of intent objects, or empty list on failure.
    """
    r = csw_api.make_request("GET", "/openapi/v1/inventory_config/forensic_intents")
    if r.get("status") != 200:
        print(f"    Intents: HTTP {r.get('status')} — {r.get('error', '?')}", file=sys.stderr)
        return []
    data = r.get("data", [])
    return data if isinstance(data, list) else []


def fetch_orders():
    """Fetch the forensic intent ordering from the cluster.

    The intent order determines precedence when multiple intents match
    the same agent. This endpoint may return 403 on some API key
    configurations — that is handled gracefully.

    Returns:
        dict | list | None: Order object, or None on failure.
    """
    r = csw_api.make_request("GET", "/openapi/v1/inventory_config/forensic_orders")
    if r.get("status") != 200:
        # 403 is common for this endpoint — not all API key capabilities include it
        return None
    return r.get("data")


# ──────────────────────────────────────────────────────────────────────────────
# Rule analysis helpers
# ──────────────────────────────────────────────────────────────────────────────

def extract_mitre_id(rule_name):
    """Extract a MITRE ATT&CK technique ID from a rule name.

    CSW rules follow the pattern "T1xxx - Description" or
    "T1xxx.yyy - Description" for sub-techniques.

    Args:
        rule_name: The forensic rule name string.

    Returns:
        str or None: The technique ID (e.g. "T1003") or None if not found.
    """
    import re
    match = re.match(r"(T\d{4}(?:\.\d{3})?)", rule_name or "")
    return match.group(1) if match else None


def parse_clause_summary(clause_chips_str):
    """Extract a human-readable summary from the clause_chips JSON string.

    The clause_chips field contains a JSON array of filter tokens that
    define the rule's match logic. We extract the key values and operators
    to produce a concise one-line summary.

    Args:
        clause_chips_str: JSON string from the rule's clause_chips field.

    Returns:
        str: A condensed human-readable version of the match logic.
    """
    if not clause_chips_str:
        return ""
    try:
        chips = json.loads(clause_chips_str)
    except (json.JSONDecodeError, TypeError):
        return ""

    # Collect the important filter values and operators
    parts = []
    for chip in chips:
        chip_type = chip.get("type", "")
        if chip_type == "filter":
            # Build a readable fragment like: "Exec Path contains cmstp.exe"
            facet = chip.get("facet", {}).get("title", "?")
            op = chip.get("operator", {}).get("label", "?")
            val = chip.get("displayValue", "?")
            parts.append(f"{facet} {op} {val}")
        elif chip_type == "operator":
            # Logical operators: and, or, with ancestor
            parts.append(chip.get("value", "?").upper())
    return " ".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
# Console output
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(profiles, rules, intents, orders):
    """Print a formatted console summary of the forensics configuration.

    Shows:
      - High-level counts (profiles, rules, intents)
      - Severity breakdown of rules
      - Rule type breakdown (predefined vs custom)
      - List of all rules with severity badges and MITRE technique IDs
      - Profile → rule count mapping
    """
    print(f"\n{'=' * 110}")
    print(f" FORENSICS CONFIGURATION — CSW Cluster")
    print(f"{'=' * 110}\n")

    # ── Overview counts ──
    print(f"  Forensic Profiles:  {len(profiles)}")
    print(f"  Forensic Rules:     {len(rules)}")
    print(f"  Forensic Intents:   {len(intents)}")
    print(f"  Intent Orders:      {'available' if orders else 'not accessible (403)'}")

    # ── Severity breakdown ──
    # Count rules by severity level for a quick risk posture overview
    severity_counts = {}
    type_counts = {}
    action_counts = {}
    for rule in rules:
        sev = rule.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        rtype = rule.get("type", "UNKNOWN")
        type_counts[rtype] = type_counts.get(rtype, 0) + 1
        for action in rule.get("actions", []):
            action_counts[action] = action_counts.get(action, 0) + 1

    print(f"\n  Severity breakdown: {dict(sorted(severity_counts.items()))}")
    print(f"  Rule types:         {dict(type_counts)}")
    print(f"  Action coverage:    {dict(action_counts)}")

    # ── Rules table ──
    print(f"\n  {'#':<4s} {'Severity':<10s} {'Type':<12s} {'Actions':<18s} {'Rule Name':<60s}")
    print(f"  {'-' * 104}")
    for i, rule in enumerate(sorted(rules, key=lambda r: r.get("name", "")), 1):
        name = rule.get("name", "?")[:58]
        sev = rule.get("severity", "?")
        rtype = rule.get("type", "?")
        actions = ",".join(rule.get("actions", []))
        print(f"  {i:<4d} {sev:<10s} {rtype:<12s} {actions:<18s} {name}")

    # ── Profiles overview ──
    print(f"\n  Profiles:")
    for p in profiles:
        rule_count = len(p.get("forensic_rules", []))
        print(f"    - {p.get('name', '?')} ({rule_count} rules)")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# HTML report generation
# ──────────────────────────────────────────────────────────────────────────────

def render_html(profiles, rules, intents, orders, cluster, generated):
    """Build a self-contained HTML report of the forensics configuration.

    The report follows the same visual style as other toolkit reports:
      - Cisco brand colours (#005073 header, #0EA5E9 accent)
      - Inter font for body, Fira Code for code/technical strings
      - CSS grid layout with responsive breakpoints
      - Print-friendly styles for PDF export

    Sections:
      1. Summary KPIs — profiles, rules, intents, severity counts
      2. Severity breakdown — visual badges per severity level
      3. Forensic Profiles — each profile with its rules listed
      4. Full Rule Inventory — all rules with severity, type, actions,
         MITRE ATT&CK links, descriptions, and match logic summaries
      5. Forensic Intents — profile-to-agent bindings

    Args:
        profiles: List of profile dicts from fetch_profiles()
        rules: List of rule dicts from fetch_rules()
        intents: List of intent dicts from fetch_intents()
        orders: Intent order object from fetch_orders() (may be None)
        cluster: Cluster hostname for the page title
        generated: Timestamp string for the report footer
    """
    # ── Compute severity stats for KPI cards ──
    severity_counts = {}
    type_counts = {}
    for rule in rules:
        sev = rule.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        rtype = rule.get("type", "UNKNOWN")
        type_counts[rtype] = type_counts.get(rtype, 0) + 1

    # Map severity levels to CSS colour classes for visual badges
    sev_class = {"CRITICAL": "badge-err", "HIGH": "badge-warn", "MEDIUM": "", "LOW": "badge-ok"}

    # ── KPI cards (top of report) ──
    kpis = [
        ("", str(len(profiles)), "Forensic Profiles"),
        ("", str(len(rules)), "Forensic Rules"),
        ("", str(len(intents)), "Forensic Intents"),
        ("warn" if severity_counts.get("CRITICAL", 0) else "",
         str(severity_counts.get("CRITICAL", 0)), "CRITICAL Rules"),
        ("warn", str(severity_counts.get("HIGH", 0)), "HIGH Rules"),
        ("", str(severity_counts.get("MEDIUM", 0)), "MEDIUM Rules"),
        ("ok", str(severity_counts.get("LOW", 0)), "LOW Rules"),
        ("", str(type_counts.get("PREDEFINED", 0)), "Predefined"),
        ("", str(type_counts.get("CUSTOM", 0)), "Custom"),
    ]
    kpi_html = "".join(
        f'<div class="kpi {cls}"><div class="val">{val}</div><div class="lbl">{lbl}</div></div>'
        for cls, val, lbl in kpis
    )

    # ── Profile cards — one per profile with rule listing ──
    profile_html = ""
    for p in profiles:
        p_rules = p.get("forensic_rules", [])
        rule_rows = ""
        for r in sorted(p_rules, key=lambda x: x.get("name", "")):
            sev = r.get("severity", "?")
            badge = sev_class.get(sev, "")
            mitre_id = extract_mitre_id(r.get("name", ""))
            mitre_link = ""
            if r.get("reference_url"):
                mitre_link = f" <a href='{r['reference_url']}' target='_blank' style='color:var(--accent);text-decoration:none;font-size:.72rem'>[ref]</a>"
            rule_rows += (
                f"<tr>"
                f"<td><span class='badge {badge}'>{sev}</span></td>"
                f"<td>{r.get('name', '?')}{mitre_link}</td>"
                f"<td>{','.join(r.get('actions', []))}</td>"
                f"<td style='font-size:.72rem;color:var(--text3)'>{r.get('description', '')[:100]}</td>"
                f"</tr>"
            )
        profile_html += f"""
        <div class="card full">
          <h2>Profile: {p.get('name', '?')} <span style="font-size:.72rem;font-weight:400;color:var(--text3)">({len(p_rules)} rules)</span></h2>
          <table><thead><tr><th>Severity</th><th>Rule Name</th><th>Actions</th><th>Description</th></tr></thead>
          <tbody>{rule_rows}</tbody></table>
        </div>"""

    # ── Full rule inventory table ──
    # This shows ALL rules (not just those in profiles), sorted by severity
    # then name, with MITRE ATT&CK tactic classification and clause summaries
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_rules = sorted(rules, key=lambda r: (
        severity_order.get(r.get("severity", ""), 9),
        r.get("name", ""),
    ))
    rule_rows = ""
    for i, r in enumerate(sorted_rules, 1):
        sev = r.get("severity", "?")
        badge = sev_class.get(sev, "")
        mitre_id = extract_mitre_id(r.get("name", ""))
        tactic = MITRE_TACTICS.get(mitre_id, "Other") if mitre_id else ""
        ref_link = ""
        if r.get("reference_url"):
            ref_link = f"<a href='{r['reference_url']}' target='_blank' style='color:var(--accent);text-decoration:none'>[link]</a>"
        clause_summary = parse_clause_summary(r.get("clause_chips", ""))
        # Truncate long clause summaries for readability
        if len(clause_summary) > 120:
            clause_summary = clause_summary[:117] + "..."
        rule_rows += (
            f"<tr>"
            f"<td>{i}</td>"
            f"<td><span class='badge {badge}'>{sev}</span></td>"
            f"<td>{r.get('type', '?')}</td>"
            f"<td>{r.get('name', '?')}</td>"
            f"<td>{tactic}</td>"
            f"<td>{','.join(r.get('actions', []))}</td>"
            f"<td style='font-size:.7rem'>{ref_link}</td>"
            f"<td style='font-size:.7rem;color:var(--text3)'>{r.get('description', '')[:80]}</td>"
            f"</tr>"
        )

    # ── Intents table ──
    # Show which profiles are bound to which agent groups
    intent_rows = ""
    # Build a quick lookup from profile ID → name for readable display
    profile_lookup = {p["id"]: p.get("name", "?") for p in profiles}
    for intent in intents:
        profile_id = intent.get("forensic_config_profile_id", "?")
        profile_name = profile_lookup.get(profile_id, profile_id[:12] + "...")
        created = datetime.fromtimestamp(
            intent.get("created_at", 0), tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M") if intent.get("created_at") else "?"
        intent_rows += (
            f"<tr>"
            f"<td><code>{intent.get('id', '?')[:16]}...</code></td>"
            f"<td>{profile_name}</td>"
            f"<td><code>{intent.get('inventory_filter_id', '?')[:16]}...</code></td>"
            f"<td>{created}</td>"
            f"</tr>"
        )
    if not intent_rows:
        intent_rows = "<tr><td colspan='4' style='color:var(--text3)'>No forensic intents configured</td></tr>"

    # ── Assemble the complete HTML document ──
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Forensics Configuration — {cluster}</title>
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
footer {{ text-align:center; padding:1.5rem; color:var(--text3); font-size:.75rem;
         border-top:1px solid var(--border); margin-top:1rem }}
footer strong {{ color:var(--text2) }}
@media print {{
  body {{ background:#fff; -webkit-print-color-adjust:exact; print-color-adjust:exact }}
  header {{ background:var(--header) !important; -webkit-print-color-adjust:exact }}
  .card {{ box-shadow:none; break-inside:avoid }}
}}
@media (max-width:720px) {{ main {{ grid-template-columns:1fr }} }}
</style>
</head>
<body>
<header>
  <div class="cisco-logo">Cisco</div>
  <div>
    <h1>Secure Workload — Forensics Configuration</h1>
    <small>Cluster: {cluster} &nbsp;|&nbsp; Profiles: {len(profiles)} &nbsp;|&nbsp;
           Rules: {len(rules)} &nbsp;|&nbsp; Intents: {len(intents)} &nbsp;|&nbsp;
           Generated: {generated}</small>
  </div>
</header>
<main>

<div class="card full">
  <h2>Summary</h2>
  <div class="kpi-grid">{kpi_html}</div>
</div>

{profile_html}

<div class="card full">
  <h2>Full Rule Inventory <span style="font-size:.72rem;font-weight:400;color:var(--text3)">({len(rules)} rules, sorted by severity)</span></h2>
  <table><thead><tr><th>#</th><th>Severity</th><th>Type</th><th>Rule Name</th><th>MITRE Tactic</th><th>Actions</th><th>Ref</th><th>Description</th></tr></thead>
  <tbody>{rule_rows}</tbody></table>
</div>

<div class="card full">
  <h2>Forensic Intents <span style="font-size:.72rem;font-weight:400;color:var(--text3)">(profile → agent group bindings)</span></h2>
  <table><thead><tr><th>Intent ID</th><th>Profile</th><th>Inventory Filter</th><th>Created</th></tr></thead>
  <tbody>{intent_rows}</tbody></table>
</div>

</main>
<footer>
  <strong>Cisco Secure Workload</strong> — Forensics Configuration Report &nbsp;|&nbsp;
  {generated}
  <br><span style="margin-top:.3rem;display:block">Generated by <code>download_forensics.py</code> &middot; Cisco SE Toolkit</span>
</footer>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    """CLI entry point: fetch forensics config → summarise → export JSON + HTML.

    Three-phase pipeline:
      [1/3] Fetch all forensics configuration resources from the API
      [2/3] Print console summary with severity breakdown and rule listing
      [3/3] Export JSON data file and render self-contained HTML report
    """
    parser = argparse.ArgumentParser(
        description="Download forensics configuration from the CSW cluster.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 download_forensics.py
  python3 download_forensics.py --out reports/my-forensics.html
  python3 download_forensics.py --no-html
  python3 download_forensics.py --json-out snapshots/my-forensics.json
        """,
    )
    parser.add_argument(
        "--out", "-o", default=None,
        help="Output HTML path (default: reports/forensics-config-<date>.html)",
    )
    parser.add_argument(
        "--json-out", default=None,
        help="Output JSON path (default: snapshots/forensics-config-<date>.json)",
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip HTML report generation (JSON + console only)",
    )
    args = parser.parse_args()

    # Extract cluster hostname for display and report titles
    cluster = os.environ.get("CSW_API_URL", "?").replace("https://", "").split("/")[0]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(f"\n  Cluster: {cluster}", file=sys.stderr)

    # ── Phase 1: Fetch all forensics configuration data ──
    print(f"\n  [1/3] Fetching forensics configuration...", file=sys.stderr)
    profiles = fetch_profiles()
    print(f"    Profiles: {len(profiles)}", file=sys.stderr)
    rules = fetch_rules()
    print(f"    Rules:    {len(rules)}", file=sys.stderr)
    intents = fetch_intents()
    print(f"    Intents:  {len(intents)}", file=sys.stderr)
    orders = fetch_orders()
    print(f"    Orders:   {'OK' if orders else 'not accessible'}", file=sys.stderr)

    if not rules and not profiles:
        print("\n  No forensics data returned. Check API key has sensor_management capability.", file=sys.stderr)
        sys.exit(1)

    # ── Phase 2: Console summary ──
    print(f"\n  [2/3] Analysing...", file=sys.stderr)
    print_summary(profiles, rules, intents, orders)

    # ── Phase 3: Export JSON + HTML ──
    print(f"  [3/3] Exporting...", file=sys.stderr)

    # JSON export — always generated (contains the raw API data for downstream use)
    json_path = args.json_out or f"snapshots/forensics-config-{DATE_TAG}.json"
    os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)
    export_data = {
        "cluster": cluster,
        "generated": generated,
        "profiles": profiles,
        "rules": rules,
        "intents": intents,
        "orders": orders,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)
    print(f"\n  JSON export: {json_path}", file=sys.stderr)

    # HTML report — optional but generated by default
    if not args.no_html:
        html_path = args.out or f"reports/forensics-config-{DATE_TAG}.html"
        os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)
        html = render_html(profiles, rules, intents, orders, cluster, generated)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  HTML report: {html_path}", file=sys.stderr)
        print(f"  Open: open {html_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
