#!/usr/bin/env python3
"""
generate_vuln_report.py — CSW Vulnerability Assessment Report
--------------------------------------------------------------

What this script is for (plain English)
---------------------------------------
Every CSW agent on a Linux/Windows host enumerates the software packages
installed on that host (rpm/dpkg/Windows update inventory). CSW
correlates each of those package names + versions against a database of
public **CVEs** (Common Vulnerabilities and Exposures - the standardised
catalogue of known security flaws, e.g. ``CVE-2024-12345``). The result
is "host X has package Y, package Y has known flaw Z, here's the
severity".

This script pulls all of that data via the API, aggregates it, and
produces a customer-ready report. It is the answer to "give me a
spreadsheet of every vulnerable thing in my fleet, ranked by how scary
it is".

Three things make this richer than a vanilla CVE list:

  * **CVM** (Cisco Vulnerability Management, formerly Kenna): on top of
    the raw CVE severity (``CRITICAL``/``HIGH``/etc.), CSW exposes a
    risk score from CVM that incorporates real-world exploit
    intelligence. A medium-severity CVE that's actively being weaponised
    in the wild scores higher than a critical-severity one with no known
    exploit. Look for the fields ``cvm_score``,
    ``cvm_active_internet_breach``, and ``cvm_malware_exploitable``.
  * **Workload context**: the report rolls vulnerabilities up by host,
    so you can see "this one server has 47 CVEs, fix it first" rather
    than just a list of CVE IDs.
  * **Software inventory**: a side-output listing every package
    installed everywhere - useful for "do we have log4j anywhere?"
    type questions.

How the data flow works
-----------------------
  1. Get the list of every sensor in the cluster (one API call).
  2. For each sensor, ask the API for its vulnerabilities AND its
     installed packages (two API calls per host). This is where the
     bulk of the time goes - a 500-host fleet means 1000 API calls,
     which is why the script prints progress.
  3. Aggregate, sort, and emit HTML + CSV.

Outputs:

  1. A self-contained HTML report with:
     - Executive KPI summary (total hosts, CVEs, critical/high counts)
     - Severity distribution breakdown (CRITICAL / HIGH / MEDIUM / LOW)
     - Cisco CVM risk intelligence (exploitable, malware, active breach)
     - Top 20 most prevalent CVEs across the cluster
     - Most vulnerable hosts ranked by CVE count
     - Per-host vulnerability detail with affected packages
     - Software inventory summary

  2. A CSV export of all vulnerabilities for offline analysis (Excel-friendly)

Usage:
    python3 generate_vuln_report.py
    python3 generate_vuln_report.py --out reports/vuln-custom.html
    python3 generate_vuln_report.py --csv-only

API endpoints used:
    GET /openapi/v1/sensors                         — list all workloads
    GET /openapi/v1/workload/{uuid}/vulnerabilities  — CVEs per host
    GET /openapi/v1/workload/{uuid}/packages         — installed software

Requirements:
    csw_api.py in the same directory with .env credentials configured.
    API key must have sensor_management and flow_inventory_query capabilities.
"""

import csv
import json
import os
import sys
import time
import argparse
from datetime import datetime, timezone
from collections import Counter, defaultdict

# Ensure sibling csw_api module is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csw_api
import csw_helpers

# Load credentials from .env
csw_api._load_dotenv()


# ──────────────────────────────────────────────────────────────
# Data collection — scan all workloads for vulnerabilities
# ──────────────────────────────────────────────────────────────

# Sensor enumeration is handled by csw_helpers.fetch_all_sensors(), which
# transparently handles single-page and paginated cluster variants.
fetch_all_sensors = csw_helpers.fetch_all_sensors


def scan_host(uuid):
    """
    Query vulnerabilities and packages for a single workload by UUID.

    The CSW API does NOT have a "give me everything for every host" bulk
    endpoint - vulnerabilities and packages are scoped per-workload. So
    we issue two HTTP calls per host: one for CVEs, one for the package
    inventory. This is the slow part of the script; see the progress
    bar in ``main()``.

    On any per-host failure we return empty lists rather than aborting
    the whole scan. A single dead agent shouldn't break a 500-host
    sweep.

    Args:
        uuid: workload UUID (from the ``uuid`` field on a sensor record).

    Returns:
        (vulns, packages) — two lists of dicts. Empty if the API call
        failed or the host has nothing to report.
    """
    rv = csw_api.make_request("GET", f"/openapi/v1/workload/{uuid}/vulnerabilities")
    vulns = rv.get("data", []) if rv.get("status") == 200 else []

    rp = csw_api.make_request("GET", f"/openapi/v1/workload/{uuid}/packages")
    pkgs = rp.get("data", []) if rp.get("status") == 200 else []

    return vulns, pkgs


def collect_all(sensors):
    """
    Scan every sensor for vulnerabilities and packages.

    Prints a progress line per host to stderr. Collects per-host results
    and cluster-wide aggregates for the report.

    Returns:
        dict with keys: hosts, all_vulns, cve_counter, severity_counter,
        cvm_stats, host_vulns, host_pkgs, unique_cves
    """
    host_vulns = {}       # hostname → list of vuln dicts
    host_pkgs = {}        # hostname → list of package dicts
    cve_counter = Counter()       # cve_id → number of hosts affected
    severity_counter = Counter()  # severity string → total count
    cve_details = {}              # cve_id → full vuln dict (latest seen)

    # CVM (Cisco Vulnerability Management) intelligence counters
    cvm_easily_exploitable = 0
    cvm_malware_exploitable = 0
    cvm_active_breach = 0
    cvm_popular_target = 0
    cvm_fix_available = 0

    total = len(sensors)
    hosts_scanned = 0
    hosts_with_vulns = 0

    for i, sensor in enumerate(sensors):
        uuid = sensor.get("uuid", "")
        hostname = sensor.get("host_name", "?")
        if not uuid:
            continue

        vulns, pkgs = scan_host(uuid)
        hosts_scanned += 1

        host_vulns[hostname] = vulns
        host_pkgs[hostname] = pkgs

        if vulns:
            hosts_with_vulns += 1

        for v in vulns:
            cve_id = v.get("cve_id", "?")
            cve_counter[cve_id] += 1
            cve_details[cve_id] = v

            # Classify by the highest available severity
            sev = (v.get("v3_base_severity") or v.get("v2_severity") or "UNKNOWN").upper()
            severity_counter[sev] += 1

            # Aggregate CVM risk intelligence flags
            if v.get("cvm_easily_exploitable"):
                cvm_easily_exploitable += 1
            if v.get("cvm_malware_exploitable"):
                cvm_malware_exploitable += 1
            if v.get("cvm_active_internet_breach"):
                cvm_active_breach += 1
            if v.get("cvm_popular_target"):
                cvm_popular_target += 1
            if v.get("cvm_fix_available"):
                cvm_fix_available += 1

        marker = f"vulns={len(vulns):3d}" if vulns else "      "
        print(f"\r  [{i+1:3d}/{total}] {hostname:35s} {marker}  pkgs={len(pkgs):3d}", end="", flush=True, file=sys.stderr)
        # Small delay between hosts to avoid API throttling
        time.sleep(0.1)

    print(file=sys.stderr)

    total_vulns = sum(len(v) for v in host_vulns.values())
    unique_cves = set(cve_counter.keys())

    return {
        "hosts_scanned": hosts_scanned,
        "hosts_with_vulns": hosts_with_vulns,
        "total_vulns": total_vulns,
        "unique_cves": len(unique_cves),
        "severity_counter": severity_counter,
        "cve_counter": cve_counter,
        "cve_details": cve_details,
        "host_vulns": host_vulns,
        "host_pkgs": host_pkgs,
        "cvm": {
            "easily_exploitable": cvm_easily_exploitable,
            "malware_exploitable": cvm_malware_exploitable,
            "active_breach": cvm_active_breach,
            "popular_target": cvm_popular_target,
            "fix_available": cvm_fix_available,
        },
    }


# ──────────────────────────────────────────────────────────────
# CSV export
# ──────────────────────────────────────────────────────────────

def export_csv(stats, path):
    """
    Write all vulnerability data to a flat CSV file.

    Each row represents one CVE on one host, with full CVSS scores,
    CVM intelligence, and affected package information.
    """
    fieldnames = [
        "hostname", "cve_id", "cve_url",
        "v3_score", "v3_base_severity", "v3_attack_vector", "v3_attack_complexity",
        "v3_privileges_required", "v3_user_interaction",
        "v3_confidentiality_impact", "v3_integrity_impact", "v3_availability_impact",
        "v2_score", "v2_severity",
        "cvm_score", "cvm_severity",
        "cvm_easily_exploitable", "cvm_malware_exploitable",
        "cvm_active_internet_breach", "cvm_popular_target", "cvm_fix_available",
        "affected_packages",
    ]

    rows = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for hostname, vulns in stats["host_vulns"].items():
            for v in vulns:
                # Collect affected package names into a semicolon-separated string
                pkg_infos = v.get("package_infos", [])
                pkg_str = "; ".join(f"{p.get('name','')} {p.get('version','')}" for p in pkg_infos[:10])
                writer.writerow({
                    "hostname": hostname,
                    "cve_id": v.get("cve_id", ""),
                    "cve_url": v.get("cve_url", ""),
                    "v3_score": v.get("v3_score", ""),
                    "v3_base_severity": v.get("v3_base_severity", ""),
                    "v3_attack_vector": v.get("v3_attack_vector", ""),
                    "v3_attack_complexity": v.get("v3_attack_complexity", ""),
                    "v3_privileges_required": v.get("v3_privileges_required", ""),
                    "v3_user_interaction": v.get("v3_user_interaction", ""),
                    "v3_confidentiality_impact": v.get("v3_confidentiality_impact", ""),
                    "v3_integrity_impact": v.get("v3_integrity_impact", ""),
                    "v3_availability_impact": v.get("v3_availability_impact", ""),
                    "v2_score": v.get("v2_score", ""),
                    "v2_severity": v.get("v2_severity", ""),
                    "cvm_score": v.get("cvm_score", ""),
                    "cvm_severity": v.get("cvm_severity", ""),
                    "cvm_easily_exploitable": v.get("cvm_easily_exploitable", ""),
                    "cvm_malware_exploitable": v.get("cvm_malware_exploitable", ""),
                    "cvm_active_internet_breach": v.get("cvm_active_internet_breach", ""),
                    "cvm_popular_target": v.get("cvm_popular_target", ""),
                    "cvm_fix_available": v.get("cvm_fix_available", ""),
                    "affected_packages": pkg_str,
                })
                rows += 1

    return rows


# ──────────────────────────────────────────────────────────────
# HTML report rendering
# ──────────────────────────────────────────────────────────────

def severity_badge(sev):
    """Return an HTML badge span coloured by CVSS severity level."""
    colours = {
        "CRITICAL": ("badge-crit", "#7f1d1d", "#fecaca"),
        "HIGH":     ("badge-err",  "#991b1b", "#fee2e2"),
        "MEDIUM":   ("badge-warn", "#92400e", "#fef3c7"),
        "LOW":      ("badge-ok",   "#065f46", "#d1fae5"),
    }
    cls, fg, bg = colours.get(sev.upper(), ("badge-info", "#0c5460", "#d1ecf1"))
    return f'<span class="badge" style="background:{bg};color:{fg}">{sev}</span>'


def render_html(stats, cluster, generated):
    """
    Build a self-contained HTML vulnerability assessment report.

    Uses the same UI/UX design system as the other CSW reports:
    Inter + Fira Code fonts, Cisco brand gradient header, responsive
    CSS grid layout, and print-friendly media query.

    Args:
        stats:     dict returned by collect_all()
        cluster:   cluster hostname string
        generated: UTC timestamp string for the footer
    """
    s = stats
    cvm = s["cvm"]

    # ── KPI row ──
    crit_count = s["severity_counter"].get("CRITICAL", 0)
    high_count = s["severity_counter"].get("HIGH", 0)
    med_count = s["severity_counter"].get("MEDIUM", 0)
    low_count = s["severity_counter"].get("LOW", 0)

    kpi_data = [
        ("", s["hosts_scanned"], "Hosts Scanned"),
        ("warn" if s["hosts_with_vulns"] else "ok", s["hosts_with_vulns"], "Hosts Vulnerable"),
        ("", s["total_vulns"], "Total CVE Instances"),
        ("", s["unique_cves"], "Unique CVEs"),
        ("crit" if crit_count else "ok", crit_count, "Critical"),
        ("warn" if high_count else "ok", high_count, "High"),
        ("" if med_count else "ok", med_count, "Medium"),
        ("ok", low_count, "Low"),
    ]
    kpi_html = ""
    for cls, val, lbl in kpi_data:
        kpi_html += f'<div class="kpi {cls}"><div class="val">{val:,}</div><div class="lbl">{lbl}</div></div>'

    # ── Severity distribution bar chart ──
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#059669"}
    sev_max = max(s["severity_counter"].values()) if s["severity_counter"] else 1
    sev_bars = ""
    for sev in sev_order:
        cnt = s["severity_counter"].get(sev, 0)
        pct = int(cnt / sev_max * 100) if sev_max else 0
        color = sev_colors.get(sev, "#94A3B8")
        sev_bars += f'<div class="bar-row"><span class="bar-lbl">{sev}</span><div class="bar-wrap"><div class="bar" style="width:{pct}%;background:{color}"></div></div><span class="bar-val">{cnt:,}</span></div>'

    # ── CVM risk intelligence KPIs ──
    cvm_html = ""
    cvm_items = [
        ("warn" if cvm["easily_exploitable"] else "ok", cvm["easily_exploitable"], "Easily Exploitable"),
        ("crit" if cvm["malware_exploitable"] else "ok", cvm["malware_exploitable"], "Malware Exploitable"),
        ("crit" if cvm["active_breach"] else "ok", cvm["active_breach"], "Active Internet Breach"),
        ("warn" if cvm["popular_target"] else "ok", cvm["popular_target"], "Popular Target"),
        ("ok", cvm["fix_available"], "Fix Available"),
    ]
    for cls, val, lbl in cvm_items:
        cvm_html += f'<div class="kpi {cls}"><div class="val">{val:,}</div><div class="lbl">{lbl}</div></div>'

    # ── Top 20 most prevalent CVEs across the cluster ──
    top_cve_rows = ""
    for cve_id, host_count in s["cve_counter"].most_common(20):
        detail = s["cve_details"].get(cve_id, {})
        score = detail.get("v3_score") or detail.get("v2_score") or "?"
        sev = (detail.get("v3_base_severity") or detail.get("v2_severity") or "?").upper()
        url = detail.get("cve_url", "#")
        attack_vec = detail.get("v3_attack_vector", "?")
        fix = "Yes" if detail.get("cvm_fix_available") else "No"
        # List affected package names (deduplicated, max 3 shown)
        pkgs = detail.get("package_infos", [])
        pkg_names = list(dict.fromkeys(p.get("name", "") for p in pkgs))[:3]
        pkg_str = ", ".join(pkg_names) if pkg_names else "—"
        top_cve_rows += (
            f"<tr><td><a href='{url}' target='_blank'><code>{cve_id}</code></a></td>"
            f"<td>{score}</td><td>{severity_badge(sev)}</td>"
            f"<td>{attack_vec}</td><td>{host_count}</td>"
            f"<td>{fix}</td><td style='font-size:.72rem'>{pkg_str}</td></tr>"
        )

    # ── Most vulnerable hosts (top 30) ──
    host_ranked = sorted(s["host_vulns"].items(), key=lambda x: len(x[1]), reverse=True)
    host_rows = ""
    for hostname, vulns in host_ranked[:30]:
        if not vulns:
            continue
        vuln_count = len(vulns)
        crits = sum(1 for v in vulns if (v.get("v3_base_severity") or "").upper() == "CRITICAL")
        highs = sum(1 for v in vulns if (v.get("v3_base_severity") or "").upper() == "HIGH")
        top_score = max((v.get("v3_score") or v.get("v2_score") or 0) for v in vulns)
        exploitable = sum(1 for v in vulns if v.get("cvm_easily_exploitable"))
        pkg_count = len(s["host_pkgs"].get(hostname, []))
        host_rows += (
            f"<tr><td><strong>{hostname}</strong></td>"
            f"<td>{vuln_count}</td><td>{crits}</td><td>{highs}</td>"
            f"<td>{top_score}</td><td>{exploitable}</td><td>{pkg_count}</td></tr>"
        )

    # ── Per-host vulnerability detail (expandable, top 15 hosts) ──
    detail_html = ""
    for hostname, vulns in host_ranked[:15]:
        if not vulns:
            continue
        vuln_count = len(vulns)
        # Sort vulns by score descending
        sorted_vulns = sorted(vulns, key=lambda v: v.get("v3_score") or v.get("v2_score") or 0, reverse=True)
        vuln_rows = ""
        for v in sorted_vulns[:20]:
            cve_id = v.get("cve_id", "?")
            url = v.get("cve_url", "#")
            score = v.get("v3_score") or v.get("v2_score") or "?"
            sev = (v.get("v3_base_severity") or v.get("v2_severity") or "?").upper()
            av = v.get("v3_attack_vector", "?")
            fix = "Yes" if v.get("cvm_fix_available") else "No"
            vuln_rows += (
                f"<tr><td><a href='{url}' target='_blank'><code>{cve_id}</code></a></td>"
                f"<td>{score}</td><td>{severity_badge(sev)}</td>"
                f"<td>{av}</td><td>{fix}</td></tr>"
            )
        if len(sorted_vulns) > 20:
            remaining = len(sorted_vulns) - 20
            vuln_rows += f"<tr><td colspan='5' style='color:var(--text3);font-style:italic'>...and {remaining} more CVEs</td></tr>"

        detail_html += f"""<div class="card full">
  <h2>{hostname} <span style="font-size:.72rem;font-weight:400;color:var(--text3)">({vuln_count} CVEs)</span></h2>
  <table><thead><tr><th>CVE ID</th><th>Score</th><th>Severity</th><th>Attack Vector</th><th>Fix</th></tr></thead>
  <tbody>{vuln_rows}</tbody></table>
</div>"""

    # ── Software inventory summary ──
    pkg_counter = Counter()
    for hostname, pkgs in s["host_pkgs"].items():
        for p in pkgs:
            pkg_counter[p.get("name", "?")] += 1
    pkg_rows = ""
    for pkg_name, cnt in pkg_counter.most_common(25):
        pkg_rows += f"<tr><td><code>{pkg_name}</code></td><td>{cnt}</td></tr>"

    # ── Assemble the final HTML document ──
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Vulnerability Assessment — {cluster}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
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
header {{ background:linear-gradient(135deg,#dc2626 0%,var(--header) 100%); color:#fff; padding:1.5rem 2rem;
         display:flex; align-items:center; gap:1rem }}
header h1 {{ font-size:1.3rem; font-weight:700 }}
header small {{ opacity:.85; font-size:.8rem; display:block; margin-top:.3rem }}
.cisco-logo {{ font-size:1.5rem; font-weight:800; letter-spacing:-1px; opacity:.95 }}
main {{ padding:1.5rem 2rem; display:grid;
       grid-template-columns: repeat(auto-fill,minmax(360px,1fr));
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
       min-width:120px; text-align:center; flex:1; border:1px solid var(--border);
       transition:transform var(--transition) }}
.kpi:hover {{ transform:translateY(-2px) }}
.kpi .val {{ font-size:1.5rem; font-weight:700; color:var(--accent) }}
.kpi .lbl {{ font-size:.68rem; color:var(--text3); margin-top:2px; text-transform:uppercase; letter-spacing:.4px; font-weight:500 }}
.kpi.warn .val {{ color:var(--amber) }}
.kpi.ok .val   {{ color:var(--green) }}
.kpi.crit .val {{ color:var(--red) }}
table {{ width:100%; border-collapse:collapse; font-size:.8rem }}
thead {{ background:#F1F5F9 }}
th {{ padding:.5rem .7rem; text-align:left; font-size:.7rem; text-transform:uppercase;
     letter-spacing:.4px; color:var(--text2); border-bottom:2px solid var(--border); font-weight:600 }}
td {{ padding:.5rem .7rem; border-bottom:1px solid #F1F5F9; vertical-align:middle }}
tr:last-child td {{ border-bottom:none }}
tbody tr:nth-child(even) td {{ background:#FAFBFC }}
tbody tr:hover td {{ background:#EFF6FF; transition:background var(--transition) }}
a {{ color:var(--accent); text-decoration:none }}
a:hover {{ text-decoration:underline }}
.badge {{ display:inline-block; padding:2px 8px; border-radius:20px;
         font-size:.69rem; font-weight:600 }}
code {{ font-family:'Fira Code','Cascadia Code',monospace; font-size:.72rem;
       background:#F1F5F9; padding:2px 6px; border-radius:4px; word-break:break-all }}
.bar-wrap {{ background:#E2E8F0; border-radius:4px; height:12px; flex:1 }}
.bar      {{ border-radius:4px; height:12px; transition:width .3s ease }}
.bar-row  {{ display:flex; align-items:center; gap:8px; margin:6px 0 }}
.bar-lbl  {{ width:80px; font-size:.78rem; font-weight:600; color:var(--text2) }}
.bar-val  {{ width:50px; text-align:right; font-size:.78rem; color:var(--text3); font-weight:600 }}
.exec-summary {{ background:linear-gradient(135deg,#fef2f2,#fff7ed); border:1px solid #fecaca;
                border-radius:var(--radius); padding:1rem 1.25rem; margin-bottom:0; font-size:.85rem; line-height:1.7 }}
.exec-summary strong {{ color:var(--red) }}
footer {{ text-align:center; padding:1.5rem; color:var(--text3); font-size:.75rem;
         border-top:1px solid var(--border); margin-top:1rem }}
footer strong {{ color:var(--text2) }}
@media print {{
  body {{ background:#fff; -webkit-print-color-adjust:exact; print-color-adjust:exact }}
  header {{ background:var(--header) !important; -webkit-print-color-adjust:exact }}
  .card {{ box-shadow:none; break-inside:avoid }}
  .card:hover {{ box-shadow:none }}
  .kpi:hover {{ transform:none }}
}}
@media (max-width:720px) {{ main {{ grid-template-columns:1fr }} }}
</style>
</head>
<body>
<header>
  <div class="cisco-logo">Cisco</div>
  <div>
    <h1>Secure Workload — Vulnerability Assessment</h1>
    <small>Cluster: {cluster} &nbsp;|&nbsp; Hosts: {s['hosts_scanned']} &nbsp;|&nbsp;
           Generated: {generated}</small>
  </div>
</header>
<main>

<!-- Executive Summary -->
<div class="card full exec-summary">
  <strong>{s['hosts_with_vulns']}</strong> of {s['hosts_scanned']} hosts have known vulnerabilities.
  <strong>{s['unique_cves']}</strong> unique CVEs detected across
  <strong>{s['total_vulns']:,}</strong> total instances.
  <strong>{crit_count}</strong> critical and <strong>{high_count}</strong> high severity findings require immediate attention.
  {f'<br><strong>{cvm["active_breach"]}</strong> CVE instances are linked to active internet breaches.' if cvm["active_breach"] else ''}
  {f'<strong>{cvm["easily_exploitable"]}</strong> are easily exploitable.' if cvm["easily_exploitable"] else ''}
</div>

<!-- KPI Row -->
<div class="card full">
  <h2>Summary</h2>
  <div class="kpi-grid">{kpi_html}</div>
</div>

<!-- Severity Distribution -->
<div class="card">
  <h2>Severity Distribution</h2>
  {sev_bars}
</div>

<!-- CVM Risk Intelligence -->
<div class="card">
  <h2>Cisco CVM Risk Intelligence</h2>
  <div class="kpi-grid">{cvm_html}</div>
</div>

<!-- Top CVEs -->
<div class="card full">
  <h2>Top 20 Most Prevalent CVEs</h2>
  <table>
    <thead><tr><th>CVE ID</th><th>Score</th><th>Severity</th><th>Attack Vector</th><th>Hosts</th><th>Fix</th><th>Affected Packages</th></tr></thead>
    <tbody>{top_cve_rows}</tbody>
  </table>
</div>

<!-- Most Vulnerable Hosts -->
<div class="card full">
  <h2>Most Vulnerable Hosts</h2>
  <table>
    <thead><tr><th>Hostname</th><th>CVEs</th><th>Critical</th><th>High</th><th>Top Score</th><th>Exploitable</th><th>Packages</th></tr></thead>
    <tbody>{host_rows}</tbody>
  </table>
</div>

<!-- Per-Host Detail -->
{detail_html}

<!-- Software Inventory -->
<div class="card">
  <h2>Most Common Software (top 25)</h2>
  <table>
    <thead><tr><th>Package Name</th><th>Hosts</th></tr></thead>
    <tbody>{pkg_rows}</tbody>
  </table>
</div>

</main>
<footer>
  <strong>Cisco Secure Workload</strong> — Vulnerability Assessment Report &nbsp;|&nbsp;
  {generated} &nbsp;|&nbsp; Cluster: {cluster}
  <br><span style="margin-top:.3rem;display:block">Generated by <code>generate_vuln_report.py</code> &middot; Cisco SE Toolkit</span>
</footer>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────

def main():
    """
    CLI entry point: scan all hosts → analyse → write HTML + CSV reports.

    Four-phase pipeline:
      [1/4] Fetch sensor list from the cluster
      [2/4] Scan each host for vulnerabilities and packages (API-intensive)
      [3/4] Export raw data to CSV
      [4/4] Render the HTML vulnerability assessment report
    """
    parser = argparse.ArgumentParser(description="CSW Vulnerability Assessment Report Generator")
    parser.add_argument("--out", "-o", default=None, help="Output HTML path (default: reports/vuln-report-<date>.html)")
    parser.add_argument("--csv-only", action="store_true", help="Only export CSV, skip HTML report")
    args = parser.parse_args()

    cluster = os.environ.get("CSW_API_URL", "?").replace("https://", "").split("/")[0]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    date_tag = datetime.now().strftime("%Y-%m-%d")

    print(f"\n  Cluster: {cluster}", file=sys.stderr)

    # Phase 1: Fetch all sensors
    print(f"  [1/4] Fetching sensor list...", file=sys.stderr)
    sensors = fetch_all_sensors()
    print(f"    Found {len(sensors)} sensors", file=sys.stderr)

    if not sensors:
        print("  No sensors found. Check API key capabilities.", file=sys.stderr)
        sys.exit(1)

    # Phase 2: Scan each host
    print(f"  [2/4] Scanning hosts for vulnerabilities...", file=sys.stderr)
    stats = collect_all(sensors)
    print(f"    Scan complete: {stats['total_vulns']:,} CVE instances across {stats['hosts_with_vulns']} hosts", file=sys.stderr)

    os.makedirs("reports", exist_ok=True)
    os.makedirs("snapshots", exist_ok=True)

    # Phase 3: CSV export
    csv_path = f"snapshots/vulnerabilities-{date_tag}.csv"
    print(f"  [3/4] Exporting CSV...", file=sys.stderr)
    csv_rows = export_csv(stats, csv_path)
    print(f"    CSV: {csv_path} ({csv_rows:,} rows)", file=sys.stderr)

    if args.csv_only:
        print(f"\n  Done (CSV only).", file=sys.stderr)
        return

    # Phase 4: HTML report
    out_path = args.out or f"reports/vuln-report-{date_tag}.html"
    print(f"  [4/4] Rendering HTML report...", file=sys.stderr)
    html = render_html(stats, cluster, generated)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  HTML report: {out_path}", file=sys.stderr)
    print(f"  CSV data:    {csv_path}", file=sys.stderr)
    print(f"  Open: open {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
