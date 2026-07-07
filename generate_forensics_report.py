#!/usr/bin/env python3
"""
generate_forensics_report.py — CSW Forensics Posture Assessment Report
-----------------------------------------------------------------------
Combines forensics configuration data with live agent telemetry to produce
a comprehensive security posture report that answers three questions:

  1. WHAT are we watching for?  (forensic rules & profiles)
  2. WHERE are we watching?     (agent coverage & OS distribution)
  3. WHAT are we missing?       (MITRE ATT&CK coverage gaps)

The report correlates:
  - Forensic profiles, rules, and intents from the config API
  - Agent deployment data (forensics enablement, OS, versions)
  - MITRE ATT&CK framework mapping with tactic classification
  - Coverage gap analysis against commonly exploited techniques
  - Rule detection logic summaries (parsed from clause_chips)
  - Kill chain stage mapping for executive-level risk summary

Data sources:
  - /openapi/v1/inventory_config/forensic_profiles (profiles + embedded rules)
  - /openapi/v1/inventory_config/forensic_rules    (all rules, full detail)
  - /openapi/v1/inventory_config/forensic_intents  (profile → agent bindings)
  - /openapi/v1/sensors                            (agent telemetry)

Output:
  - reports/forensics-posture-<date>.html (self-contained HTML)

Usage:
    python3 generate_forensics_report.py
    python3 generate_forensics_report.py --out reports/my-report.html

Requirements:
    csw_api.py in the same directory with .env credentials configured.
    API key must have sensor_management capability.
"""

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csw_api

csw_api._load_dotenv()

DATE_TAG = datetime.now().strftime("%Y-%m-%d")


# ──────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Taxonomy
# ──────────────────────────────────────────────────────────────────────────────
# Maps technique IDs to their tactic category and kill chain stage.
# Kill chain stages follow the MITRE ATT&CK enterprise model:
#   Recon → Initial Access → Execution → Persistence → Priv Esc →
#   Defense Evasion → Credential Access → Discovery → Lateral Movement →
#   Collection → Exfiltration → Impact

MITRE_TACTICS = {
    "T1003": ("Credential Access", "Credential Harvesting"),
    "T1015": ("Persistence", "Persistence & Backdoors"),
    "T1053": ("Execution", "Execution & Scheduling"),
    "T1059": ("Execution", "Execution & Scheduling"),
    "T1064": ("Execution", "Execution & Scheduling"),
    "T1070": ("Defense Evasion", "Anti-Forensics"),
    "T1076": ("Lateral Movement", "Lateral Movement"),
    "T1081": ("Credential Access", "Credential Harvesting"),
    "T1085": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1086": ("Execution", "Execution & Scheduling"),
    "T1089": ("Defense Evasion", "Anti-Forensics"),
    "T1114": ("Collection", "Data Collection & Staging"),
    "T1117": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1118": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1121": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1127": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1128": ("Persistence", "Persistence & Backdoors"),
    "T1136": ("Persistence", "Account Manipulation"),
    "T1138": ("Persistence", "Persistence & Backdoors"),
    "T1140": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1158": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1170": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1180": ("Persistence", "Persistence & Backdoors"),
    "T1191": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1196": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1197": ("Persistence", "Persistence & Backdoors"),
    "T1201": ("Discovery", "Reconnaissance & Discovery"),
    "T1202": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1216": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1218": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1220": ("Defense Evasion", "Defense Evasion & Living off the Land"),
    "T1223": ("Defense Evasion", "Defense Evasion & Living off the Land"),
}

# Techniques that are commonly seen in real-world attacks and recommended
# for enterprise coverage. Used to generate the coverage gap analysis.
RECOMMENDED_TECHNIQUES = {
    "T1055": ("Process Injection", "Defense Evasion", "CRITICAL"),
    "T1059": ("Command and Scripting Interpreter", "Execution", "CRITICAL"),
    "T1021": ("Remote Services", "Lateral Movement", "CRITICAL"),
    "T1078": ("Valid Accounts", "Persistence", "CRITICAL"),
    "T1105": ("Ingress Tool Transfer", "Command & Control", "HIGH"),
    "T1036": ("Masquerading", "Defense Evasion", "HIGH"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion", "HIGH"),
    "T1547": ("Boot or Logon Autostart", "Persistence", "HIGH"),
    "T1543": ("Create or Modify System Process", "Persistence", "HIGH"),
    "T1562": ("Impair Defenses", "Defense Evasion", "HIGH"),
    "T1098": ("Account Manipulation", "Persistence", "MEDIUM"),
    "T1112": ("Modify Registry", "Defense Evasion", "MEDIUM"),
    "T1548": ("Abuse Elevation Control", "Privilege Escalation", "MEDIUM"),
    "T1560": ("Archive Collected Data", "Collection", "MEDIUM"),
    "T1569": ("System Services", "Execution", "MEDIUM"),
}

# Forensic event types that CSW agents can generate
FORENSIC_SIGNALS = {
    "CMD_NOT_SEEN": ("Unseen Command", "Detects previously unseen executables running on a host"),
    "FOLLOW_PROCESS": ("Follow Process", "Tracks process creation chains and parent-child relationships"),
    "PRIV_ESCALATION": ("Privilege Escalation", "Detects processes gaining elevated privileges"),
    "RAW_SOCKET_CREATION": ("Raw Socket", "Detects raw socket creation (potential packet sniffing or tunneling)"),
    "DATA_LEAK": ("Data Leak", "Detects potential data exfiltration patterns"),
    "ACCT_MGMT": ("Account Management", "Tracks user account creation, modification, and deletion"),
}


# ──────────────────────────────────────────────────────────────────────────────
# Data collection
# ──────────────────────────────────────────────────────────────────────────────

def fetch_all():
    """Fetch all forensics config + agent data from the cluster.

    Returns a dict with keys: profiles, rules, intents, sensors, cluster.
    """
    cluster = os.environ.get("CSW_API_URL", "?").replace("https://", "").split("/")[0]
    result = {"cluster": cluster}

    print("  [1/4] Fetching forensic profiles...", file=sys.stderr, end="", flush=True)
    r = csw_api.make_request("GET", "/openapi/v1/inventory_config/forensic_profiles")
    result["profiles"] = r.get("data", []) if r.get("status") == 200 else []
    print(f" {len(result['profiles'])}", file=sys.stderr)

    print("  [2/4] Fetching forensic rules...", file=sys.stderr, end="", flush=True)
    r = csw_api.make_request("GET", "/openapi/v1/inventory_config/forensic_rules")
    result["rules"] = r.get("data", []) if r.get("status") == 200 else []
    print(f" {len(result['rules'])}", file=sys.stderr)

    print("  [3/4] Fetching forensic intents...", file=sys.stderr, end="", flush=True)
    r = csw_api.make_request("GET", "/openapi/v1/inventory_config/forensic_intents")
    result["intents"] = r.get("data", []) if r.get("status") == 200 else []
    print(f" {len(result['intents'])}", file=sys.stderr)

    print("  [4/4] Fetching agent telemetry...", file=sys.stderr, end="", flush=True)
    r = csw_api.make_request("GET", "/openapi/v1/sensors")
    sensors_data = r.get("data", {}) if r.get("status") == 200 else {}
    if isinstance(sensors_data, dict):
        result["sensors"] = sensors_data.get("results", [])
    elif isinstance(sensors_data, list):
        result["sensors"] = sensors_data
    else:
        result["sensors"] = []
    print(f" {len(result['sensors'])}", file=sys.stderr)

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Analysis engine
# ──────────────────────────────────────────────────────────────────────────────

def extract_mitre_id(name):
    """Extract MITRE technique ID from a rule name like 'T1003 - Credential Dumping'."""
    m = re.match(r"(T\d{4}(?:\.\d{3})?)", name or "")
    return m.group(1) if m else None


def parse_clause_chips(chips_str):
    """Parse clause_chips JSON into a human-readable detection logic summary."""
    if not chips_str:
        return ""
    try:
        chips = json.loads(chips_str)
    except (json.JSONDecodeError, TypeError):
        return ""
    parts = []
    for c in chips:
        ct = c.get("type", "")
        if ct == "filter":
            title = c.get("facet", {}).get("title", "?")
            op = c.get("operator", {}).get("label", "?")
            val = c.get("displayValue", "?")
            parts.append(f"{title} {op} {val}")
        elif ct == "operator":
            parts.append(c.get("value", "?").upper())
    return " ".join(parts)


def analyse(data):
    """Run the full posture analysis across forensics config + agent data.

    Returns a comprehensive stats dict for the HTML renderer.
    """
    rules = data["rules"]
    profiles = data["profiles"]
    sensors = data["sensors"]

    # ── Rule statistics ──
    severity_counts = Counter(r.get("severity", "?") for r in rules)
    type_counts = Counter(r.get("type", "?") for r in rules)
    action_counts = Counter()
    for r in rules:
        for a in r.get("actions", []):
            action_counts[a] += 1

    # ── MITRE technique coverage ──
    covered_ids = set()
    tactic_counter = Counter()
    killchain_counter = Counter()
    for r in rules:
        mid = extract_mitre_id(r.get("name", ""))
        if mid:
            covered_ids.add(mid)
            base_id = mid.split(".")[0]
            tactic, kc = MITRE_TACTICS.get(base_id, ("Other", "Other"))
            tactic_counter[tactic] += 1
            killchain_counter[kc] += 1

    # ── Coverage gap analysis ──
    gaps = []
    for tid, (name, tactic, priority) in sorted(RECOMMENDED_TECHNIQUES.items()):
        if tid not in covered_ids:
            gaps.append({"id": tid, "name": name, "tactic": tactic, "priority": priority})

    # ── Agent statistics ──
    total_agents = len(sensors)
    forensics_on = sum(1 for s in sensors if s.get("enable_forensics"))
    proc_vis = sum(1 for s in sensors if s.get("enable_process_visibility"))
    pkg_vis = sum(1 for s in sensors if s.get("enable_package_visibility"))
    enforcing = sum(1 for s in sensors if s.get("enforcement_enabled"))
    os_dist = Counter(s.get("platform", "Unknown") for s in sensors)
    version_dist = Counter(s.get("current_sw_version", "unknown") for s in sensors)

    # Forensic export signals across fleet
    all_signals = set()
    for s in sensors:
        sig = s.get("forensics_export_signals", "")
        if sig:
            for x in sig.split(","):
                all_signals.add(x.strip())

    # ── Rule enrichment (add parsed logic + MITRE mapping) ──
    enriched_rules = []
    for r in rules:
        mid = extract_mitre_id(r.get("name", ""))
        base_id = mid.split(".")[0] if mid else None
        tactic, kc = MITRE_TACTICS.get(base_id, ("", "")) if base_id else ("", "")
        logic = parse_clause_chips(r.get("clause_chips", ""))
        if len(logic) > 150:
            logic = logic[:147] + "..."
        enriched_rules.append({
            **r,
            "_mitre_id": mid,
            "_tactic": tactic,
            "_killchain": kc,
            "_logic": logic,
        })

    # Sort: severity order then name
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    enriched_rules.sort(key=lambda x: (sev_order.get(x.get("severity", ""), 9), x.get("name", "")))

    return {
        "rules": enriched_rules,
        "profiles": profiles,
        "severity_counts": severity_counts,
        "type_counts": type_counts,
        "action_counts": action_counts,
        "covered_ids": covered_ids,
        "tactic_counter": tactic_counter,
        "killchain_counter": killchain_counter,
        "gaps": gaps,
        "total_agents": total_agents,
        "forensics_on": forensics_on,
        "proc_vis": proc_vis,
        "pkg_vis": pkg_vis,
        "enforcing": enforcing,
        "os_dist": os_dist,
        "version_dist": version_dist,
        "all_signals": all_signals,
    }


# ──────────────────────────────────────────────────────────────────────────────
# HTML report renderer
# ──────────────────────────────────────────────────────────────────────────────

def render_html(stats, cluster, generated):
    """Build a self-contained HTML forensics posture report.

    Report sections:
      1. Executive Summary — overall posture grade + KPI cards
      2. Agent Coverage — deployment stats, OS distribution, signals
      3. MITRE ATT&CK Heatmap — tactic coverage by kill chain stage
      4. Coverage Gap Analysis — missing high-priority techniques
      5. Forensic Profiles — profile membership details
      6. Full Rule Inventory — all rules with detection logic
    """
    s = stats

    # ── Posture grade calculation ──
    # A simple heuristic: deduct points for gaps, bonus for agent coverage
    gap_criticals = sum(1 for g in s["gaps"] if g["priority"] == "CRITICAL")
    gap_highs = sum(1 for g in s["gaps"] if g["priority"] == "HIGH")
    coverage_pct = (s["forensics_on"] * 100 // s["total_agents"]) if s["total_agents"] else 0

    score = 100
    score -= gap_criticals * 10
    score -= gap_highs * 5
    score -= (100 - coverage_pct) // 5
    if s["enforcing"] == 0:
        score -= 5
    score = max(0, min(100, score))

    if score >= 80:
        grade, grade_cls, grade_desc = "A", "grade-a", "Strong forensic coverage with minor gaps"
    elif score >= 65:
        grade, grade_cls, grade_desc = "B", "grade-b", "Good coverage but notable technique gaps exist"
    elif score >= 50:
        grade, grade_cls, grade_desc = "C", "grade-c", "Moderate coverage — critical gaps need attention"
    else:
        grade, grade_cls, grade_desc = "D", "grade-d", "Significant gaps — forensic posture needs improvement"

    # ── KPI cards ──
    kpis = [
        ("", str(len(s["rules"])), "Detection Rules"),
        ("", str(len(s["profiles"])), "Forensic Profiles"),
        ("ok" if coverage_pct == 100 else "warn", f"{coverage_pct}%", "Agent Coverage"),
        ("ok", str(s["total_agents"]), "Total Agents"),
        ("ok", str(len(s["covered_ids"])), "MITRE Techniques"),
        ("warn" if gap_criticals else "ok", str(gap_criticals), "CRITICAL Gaps"),
        ("warn" if gap_highs else "ok", str(gap_highs), "HIGH Gaps"),
        ("ok" if not s["enforcing"] else "", str(s["enforcing"]), "Enforcing"),
        ("", str(len(s["all_signals"])), "Signal Types"),
    ]
    kpi_html = "".join(
        f'<div class="kpi {c}"><div class="val">{v}</div><div class="lbl">{l}</div></div>'
        for c, v, l in kpis
    )

    # ── Severity breakdown ──
    sev_class = {"CRITICAL": "badge-crit", "HIGH": "badge-high", "MEDIUM": "badge-med", "LOW": "badge-low"}
    sev_html = "".join(
        f'<div class="sev-card"><span class="badge {sev_class.get(sev, "")}">{sev}</span>'
        f'<span class="sev-count">{cnt}</span></div>'
        for sev, cnt in sorted(s["severity_counts"].items(), key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x[0], 9))
    )

    # ── Kill chain coverage ──
    killchain_stages = [
        "Execution & Scheduling", "Persistence & Backdoors", "Credential Harvesting",
        "Defense Evasion & Living off the Land", "Anti-Forensics",
        "Reconnaissance & Discovery", "Lateral Movement",
        "Data Collection & Staging", "Account Manipulation",
    ]
    kc_max = max(s["killchain_counter"].values()) if s["killchain_counter"] else 1
    kc_html = ""
    for stage in killchain_stages:
        cnt = s["killchain_counter"].get(stage, 0)
        pct = int(cnt / kc_max * 100) if kc_max else 0
        color = "#059669" if cnt >= 3 else ("#d97706" if cnt >= 1 else "#dc2626")
        kc_html += (
            f'<div class="kc-row">'
            f'<span class="kc-label">{stage}</span>'
            f'<div class="kc-bar-wrap"><div class="kc-bar" style="width:{pct}%;background:{color}"></div></div>'
            f'<span class="kc-val">{cnt}</span>'
            f'</div>'
        )

    # ── Tactic distribution ──
    tactic_rows = "".join(
        f"<tr><td>{tactic}</td><td>{cnt}</td></tr>"
        for tactic, cnt in s["tactic_counter"].most_common()
    )

    # ── OS distribution ──
    os_rows = "".join(
        f"<tr><td>{os_name}</td><td>{cnt}</td><td>{cnt * 100 // s['total_agents']}%</td></tr>"
        for os_name, cnt in s["os_dist"].most_common()
    )

    # ── Forensic signals ──
    signal_html = ""
    for sig_code in sorted(s["all_signals"]):
        sig_name, sig_desc = FORENSIC_SIGNALS.get(sig_code, (sig_code, ""))
        signal_html += (
            f'<div class="signal-card">'
            f'<div class="signal-code">{sig_code}</div>'
            f'<div class="signal-name">{sig_name}</div>'
            f'<div class="signal-desc">{sig_desc}</div>'
            f'</div>'
        )

    # ── Coverage gaps table ──
    gap_rows = ""
    for g in s["gaps"]:
        p_cls = "badge-crit" if g["priority"] == "CRITICAL" else ("badge-high" if g["priority"] == "HIGH" else "badge-med")
        gap_rows += (
            f"<tr>"
            f"<td><span class='badge {p_cls}'>{g['priority']}</span></td>"
            f"<td><code>{g['id']}</code></td>"
            f"<td>{g['name']}</td>"
            f"<td>{g['tactic']}</td>"
            f"<td><a href='https://attack.mitre.org/techniques/{g['id'].replace('.','/')}/' "
            f"target='_blank' class='ref-link'>MITRE</a></td>"
            f"</tr>"
        )
    if not gap_rows:
        gap_rows = "<tr><td colspan='5' class='all-clear'>All recommended techniques are covered</td></tr>"

    # ── Profile cards ──
    profile_html = ""
    sev_sort_key = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for p in s["profiles"]:
        p_rules = p.get("forensic_rules", [])
        sev_dist = Counter(r.get("severity", "?") for r in p_rules)
        sev_badges_parts = []
        for sv, c in sorted(sev_dist.items(), key=lambda x: sev_sort_key.get(x[0], 9)):
            badge_cls = sev_class.get(sv, "")
            sev_badges_parts.append(f"<span class='badge {badge_cls}'>{sv}: {c}</span>")
        sev_badges = " ".join(sev_badges_parts)
        rule_items = ""
        for r in sorted(p_rules, key=lambda x: x.get("name", "")):
            rule_sev = r.get("severity", "?")
            rule_badge_cls = sev_class.get(rule_sev, "")
            rule_name = r.get("name", "?")
            ref = ""
            ref_url = r.get("reference_url")
            if ref_url:
                ref = f" <a href='{ref_url}' target='_blank' class='ref-link'>[ref]</a>"
            rule_items += f"<li><span class='badge {rule_badge_cls}'>{rule_sev}</span> {rule_name}{ref}</li>"
        profile_html += f"""
        <div class="card">
          <h2>{p.get('name', '?')} <span class="card-sub">({len(p_rules)} rules)</span></h2>
          <div class="sev-row">{sev_badges}</div>
          <ul class="rule-list">{rule_items}</ul>
        </div>"""

    # ── Full rule inventory table ──
    rule_rows = ""
    for i, r in enumerate(s["rules"], 1):
        sev = r.get("severity", "?")
        mid = r.get("_mitre_id", "")
        tactic = r.get("_tactic", "")
        logic = r.get("_logic", "")
        ref = ""
        if r.get("reference_url"):
            ref = f"<a href='{r['reference_url']}' target='_blank' class='ref-link'>link</a>"
        rule_rows += (
            f"<tr>"
            f"<td>{i}</td>"
            f"<td><span class='badge {sev_class.get(sev, '')}'>{sev}</span></td>"
            f"<td>{r.get('name', '?')}</td>"
            f"<td>{tactic}</td>"
            f"<td>{','.join(r.get('actions', []))}</td>"
            f"<td>{ref}</td>"
            f"<td class='logic-cell'>{logic}</td>"
            f"</tr>"
        )

    # ── Version distribution ──
    ver_rows = "".join(
        f"<tr><td><code>{ver}</code></td><td>{cnt}</td></tr>"
        for ver, cnt in s["version_dist"].most_common()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Forensics Posture Assessment — {cluster}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {{
  --bg:#0F172A; --bg2:#1E293B; --card:#1E293B; --card-hover:#253449;
  --header:#005073; --accent:#0EA5E9; --accent2:#06B6D4;
  --text:#F8FAFC; --text2:#94A3B8; --text3:#64748B;
  --green:#22C55E; --amber:#F59E0B; --red:#EF4444; --crit:#DC2626;
  --border:#334155; --radius:12px;
  --shadow:0 4px 6px rgba(0,0,0,.3),0 10px 15px rgba(0,0,0,.2);
  --glow:0 0 20px rgba(14,165,233,.15);
}}
*,*::before,*::after {{ box-sizing:border-box; margin:0; padding:0 }}
body {{ font-family:'Inter',system-ui,sans-serif; background:var(--bg);
       color:var(--text); font-size:14px; line-height:1.6; -webkit-font-smoothing:antialiased }}
header {{ background:linear-gradient(135deg,#00bceb 0%,var(--header) 50%,#003d5c 100%);
         color:#fff; padding:2rem 2.5rem; position:relative; overflow:hidden }}
header::after {{ content:''; position:absolute; top:0; right:0; bottom:0; width:40%;
               background:linear-gradient(135deg,transparent 0%,rgba(14,165,233,.08) 100%); pointer-events:none }}
header h1 {{ font-size:1.5rem; font-weight:800; letter-spacing:-.5px }}
header small {{ opacity:.8; font-size:.82rem; display:block; margin-top:.4rem }}
.cisco-logo {{ font-size:1.6rem; font-weight:800; letter-spacing:-1px; opacity:.95; margin-bottom:.3rem }}
main {{ padding:2rem 2.5rem; display:grid;
       grid-template-columns: repeat(auto-fill,minmax(360px,1fr));
       gap:1.5rem; max-width:1500px; margin:0 auto }}
.full {{ grid-column: 1 / -1 }}
.card {{ background:var(--card); border-radius:var(--radius); border:1px solid var(--border);
        padding:1.5rem; box-shadow:var(--shadow); transition:all 200ms ease }}
.card:hover {{ border-color:var(--accent); box-shadow:var(--glow) }}
.card h2 {{ font-size:.92rem; font-weight:700; margin-bottom:1rem;
           border-bottom:2px solid var(--accent); padding-bottom:8px; color:var(--text);
           display:flex; align-items:center; gap:8px }}
.card-sub {{ font-size:.72rem; font-weight:400; color:var(--text2) }}
.kpi-grid {{ display:flex; flex-wrap:wrap; gap:12px }}
.kpi {{ background:var(--bg); border-radius:10px; padding:14px 18px;
       min-width:130px; text-align:center; flex:1; border:1px solid var(--border);
       transition:border-color 200ms }}
.kpi:hover {{ border-color:var(--accent) }}
.kpi .val {{ font-size:1.7rem; font-weight:800; color:var(--accent); font-family:'Inter',sans-serif }}
.kpi .lbl {{ font-size:.65rem; color:var(--text2); margin-top:4px; text-transform:uppercase;
            letter-spacing:.5px; font-weight:600 }}
.kpi.warn .val {{ color:var(--amber) }}
.kpi.ok .val   {{ color:var(--green) }}
table {{ width:100%; border-collapse:collapse; font-size:.8rem }}
thead {{ background:var(--bg) }}
th {{ padding:.6rem .8rem; text-align:left; font-size:.68rem; text-transform:uppercase;
     letter-spacing:.5px; color:var(--text2); border-bottom:2px solid var(--border); font-weight:700 }}
td {{ padding:.6rem .8rem; border-bottom:1px solid var(--border); vertical-align:middle; color:var(--text) }}
tr:last-child td {{ border-bottom:none }}
tbody tr:hover td {{ background:rgba(14,165,233,.06) }}
.badge {{ display:inline-block; padding:3px 10px; border-radius:20px;
         font-size:.65rem; font-weight:700; letter-spacing:.3px }}
.badge-crit {{ background:rgba(220,38,38,.2); color:#FCA5A5 }}
.badge-high {{ background:rgba(245,158,11,.15); color:#FCD34D }}
.badge-med  {{ background:rgba(14,165,233,.15); color:#7DD3FC }}
.badge-low  {{ background:rgba(34,197,94,.15); color:#86EFAC }}
code {{ font-family:'Fira Code','Cascadia Code',monospace; font-size:.72rem;
       background:var(--bg); padding:3px 7px; border-radius:5px; color:var(--accent2) }}
.logic-cell {{ font-size:.68rem; color:var(--text3); max-width:320px; overflow:hidden;
              text-overflow:ellipsis; white-space:nowrap }}
.ref-link {{ color:var(--accent); text-decoration:none; font-size:.72rem; font-weight:600 }}
.ref-link:hover {{ text-decoration:underline }}
.grade-ring {{ width:120px; height:120px; border-radius:50%; display:flex; align-items:center;
              justify-content:center; font-size:3rem; font-weight:800; margin:0 auto 1rem;
              border:4px solid; position:relative }}
.grade-a {{ border-color:var(--green); color:var(--green);
           box-shadow:0 0 30px rgba(34,197,94,.3), inset 0 0 20px rgba(34,197,94,.1) }}
.grade-b {{ border-color:var(--accent); color:var(--accent);
           box-shadow:0 0 30px rgba(14,165,233,.3), inset 0 0 20px rgba(14,165,233,.1) }}
.grade-c {{ border-color:var(--amber); color:var(--amber);
           box-shadow:0 0 30px rgba(245,158,11,.3), inset 0 0 20px rgba(245,158,11,.1) }}
.grade-d {{ border-color:var(--red); color:var(--red);
           box-shadow:0 0 30px rgba(239,68,68,.3), inset 0 0 20px rgba(239,68,68,.1) }}
.grade-desc {{ text-align:center; color:var(--text2); font-size:.85rem; margin-bottom:.5rem }}
.grade-score {{ text-align:center; color:var(--text3); font-size:.75rem }}
.sev-row {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:1rem }}
.sev-card {{ display:flex; align-items:center; gap:6px }}
.sev-count {{ font-size:1.1rem; font-weight:700; color:var(--text) }}
.rule-list {{ list-style:none; max-height:400px; overflow-y:auto; padding-right:4px }}
.rule-list li {{ padding:6px 0; border-bottom:1px solid var(--border); font-size:.8rem; display:flex; align-items:center; gap:8px }}
.rule-list li:last-child {{ border-bottom:none }}
.kc-row {{ display:flex; align-items:center; gap:10px; margin:6px 0 }}
.kc-label {{ width:220px; font-size:.78rem; color:var(--text2); overflow:hidden; text-overflow:ellipsis; white-space:nowrap }}
.kc-bar-wrap {{ background:var(--border); border-radius:4px; height:10px; flex:1 }}
.kc-bar {{ border-radius:4px; height:10px; transition:width .4s ease }}
.kc-val {{ width:30px; text-align:right; font-size:.78rem; color:var(--text3); font-weight:700 }}
.signal-card {{ background:var(--bg); border-radius:8px; padding:12px 16px; margin:6px 0;
               border-left:3px solid var(--accent); transition:border-color 200ms }}
.signal-card:hover {{ border-left-color:var(--green) }}
.signal-code {{ font-family:'Fira Code',monospace; font-size:.72rem; color:var(--accent2); font-weight:600 }}
.signal-name {{ font-size:.85rem; font-weight:600; color:var(--text); margin-top:2px }}
.signal-desc {{ font-size:.72rem; color:var(--text3); margin-top:2px }}
.all-clear {{ color:var(--green); font-weight:700; text-align:center; padding:1.5rem !important }}
.exec-grid {{ display:grid; grid-template-columns:1fr 2fr; gap:2rem; align-items:start }}
@media (max-width:900px) {{ .exec-grid {{ grid-template-columns:1fr }} }}
footer {{ text-align:center; padding:2rem; color:var(--text3); font-size:.75rem;
         border-top:1px solid var(--border); margin-top:1.5rem }}
footer strong {{ color:var(--text2) }}
@media print {{
  body {{ background:#fff; color:#000; -webkit-print-color-adjust:exact; print-color-adjust:exact }}
  header {{ background:var(--header) !important; -webkit-print-color-adjust:exact }}
  .card {{ box-shadow:none; break-inside:avoid; border-color:#ccc; background:#fff }}
  td, th {{ color:#000 }}
  .kpi {{ background:#f8f9fa }}
}}
@media (max-width:720px) {{ main {{ grid-template-columns:1fr; padding:1rem }} }}
</style>
</head>
<body>
<header>
  <div class="cisco-logo">Cisco</div>
  <h1>Secure Workload — Forensics Posture Assessment</h1>
  <small>Cluster: {cluster} &nbsp;&bull;&nbsp; Rules: {len(s['rules'])} &nbsp;&bull;&nbsp;
         Agents: {s['total_agents']} &nbsp;&bull;&nbsp; MITRE Techniques: {len(s['covered_ids'])} &nbsp;&bull;&nbsp;
         Generated: {generated}</small>
</header>
<main>

<!-- ── Executive Summary ── -->
<div class="card full">
  <h2>Executive Summary</h2>
  <div class="exec-grid">
    <div>
      <div class="grade-ring {grade_cls}">{grade}</div>
      <div class="grade-desc">{grade_desc}</div>
      <div class="grade-score">Posture Score: {score}/100</div>
    </div>
    <div class="kpi-grid">{kpi_html}</div>
  </div>
</div>

<!-- ── Agent Coverage ── -->
<div class="card">
  <h2>Agent Coverage</h2>
  <table>
    <tr><td>Forensics Enabled</td><td><strong>{s['forensics_on']}/{s['total_agents']}</strong> ({coverage_pct}%)</td></tr>
    <tr><td>Process Visibility</td><td><strong>{s['proc_vis']}/{s['total_agents']}</strong></td></tr>
    <tr><td>Package Visibility</td><td><strong>{s['pkg_vis']}/{s['total_agents']}</strong></td></tr>
    <tr><td>Enforcement Active</td><td><strong>{s['enforcing']}/{s['total_agents']}</strong></td></tr>
  </table>
  <h2 style="margin-top:1.5rem">OS Distribution</h2>
  <table><thead><tr><th>Platform</th><th>Count</th><th>Share</th></tr></thead>
  <tbody>{os_rows}</tbody></table>
  <h2 style="margin-top:1.5rem">Agent Versions</h2>
  <table><thead><tr><th>Version</th><th>Count</th></tr></thead>
  <tbody>{ver_rows}</tbody></table>
</div>

<!-- ── Forensic Signals ── -->
<div class="card">
  <h2>Active Forensic Signals <span class="card-sub">({len(s['all_signals'])} types)</span></h2>
  {signal_html}
</div>

<!-- ── Kill Chain Coverage ── -->
<div class="card full">
  <h2>Kill Chain Coverage <span class="card-sub">(rules mapped to attack stages)</span></h2>
  <div style="max-width:800px">{kc_html}</div>
</div>

<!-- ── Severity Breakdown ── -->
<div class="card">
  <h2>Severity Breakdown</h2>
  <div class="sev-row">{sev_html}</div>
  <h2 style="margin-top:1rem">MITRE Tactic Distribution</h2>
  <table><thead><tr><th>Tactic</th><th>Rules</th></tr></thead>
  <tbody>{tactic_rows}</tbody></table>
</div>

<!-- ── Coverage Gaps ── -->
<div class="card">
  <h2>Coverage Gap Analysis <span class="card-sub">({len(s['gaps'])} missing techniques)</span></h2>
  <table><thead><tr><th>Priority</th><th>Technique</th><th>Name</th><th>Tactic</th><th>Ref</th></tr></thead>
  <tbody>{gap_rows}</tbody></table>
</div>

<!-- ── Forensic Profiles ── -->
{profile_html}

<!-- ── Full Rule Inventory ── -->
<div class="card full">
  <h2>Full Rule Inventory <span class="card-sub">({len(s['rules'])} rules, sorted by severity)</span></h2>
  <div style="overflow-x:auto">
  <table><thead><tr><th>#</th><th>Severity</th><th>Rule Name</th><th>Tactic</th><th>Actions</th><th>Ref</th><th>Detection Logic</th></tr></thead>
  <tbody>{rule_rows}</tbody></table>
  </div>
</div>

</main>
<footer>
  <strong>Cisco Secure Workload</strong> — Forensics Posture Assessment &nbsp;&bull;&nbsp;
  {generated} &nbsp;&bull;&nbsp; {cluster}
  <br><span style="margin-top:.4rem;display:block">Generated by <code>generate_forensics_report.py</code> &middot; Cisco SE Toolkit</span>
</footer>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    """CLI entry: fetch data → analyse posture → render HTML report."""
    parser = argparse.ArgumentParser(
        description="Generate a comprehensive forensics posture assessment report.",
    )
    parser.add_argument(
        "--out", "-o", default=None,
        help="Output HTML path (default: reports/forensics-posture-<date>.html)",
    )
    args = parser.parse_args()

    cluster = os.environ.get("CSW_API_URL", "?").replace("https://", "").split("/")[0]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(f"\n  Cluster: {cluster}", file=sys.stderr)
    print(f"  Fetching data...\n", file=sys.stderr)

    data = fetch_all()

    if not data["rules"]:
        print("  No forensics data. Check API key has sensor_management capability.", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Analysing posture...", file=sys.stderr)
    stats = analyse(data)

    html_path = args.out or f"reports/forensics-posture-{DATE_TAG}.html"
    os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)
    html = render_html(stats, cluster, generated)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  Posture Score: {100 - len(stats['gaps']) * 5}/100", file=sys.stderr)
    print(f"  MITRE Techniques Covered: {len(stats['covered_ids'])}", file=sys.stderr)
    print(f"  Coverage Gaps: {len(stats['gaps'])} ({sum(1 for g in stats['gaps'] if g['priority'] == 'CRITICAL')} CRITICAL)", file=sys.stderr)
    print(f"\n  HTML report: {html_path}", file=sys.stderr)
    print(f"  Open: open {html_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
