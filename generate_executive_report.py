#!/usr/bin/env python3
"""
generate_executive_report.py — CSW POV Executive Summary
=========================================================

Produces a CISO-grade one-page report (HTML + Markdown) summarizing the
security posture of a Cisco Secure Workload (CSW) cluster. It aggregates
data from a cluster snapshot plus optional companion reports (vulnerability
CSV, conversations JSON, policies JSON) into a single executive narrative
with KPIs, posture scoring, and prioritized recommendations.

What this script is for (plain English)
---------------------------------------
The other scripts in this toolkit produce engineer-grade detail: lists of
sensors, lists of CVEs, lists of forensic rules. Useful for hands-on work,
but a CIO/CISO does not want a 2,000-row CSV — they want one page that says
"here is your blast radius, here is what to fix, here is the order to fix
it in." This script is that one page.

It computes a few high-level posture indicators in business language:

  * **Visibility coverage**       — what % of the estate is being watched
  * **Enforcement coverage**      — what % is actively protected, not just
                                    observed
  * **Blast radius score**        — proxy for how far an attacker could move
                                    laterally if they landed inside today
  * **Vulnerability exposure**    — count and severity of CVEs that matter
                                    (when a vuln CSV is present)
  * **Threat detection readiness**— forensic rules deployed (when forensics
                                    config is present)

It then turns those numbers into prioritized, time-bound recommendations.

Two data-source modes
---------------------
  --snapshot PATH    Use an existing cluster_snapshot.py JSON file
                     (offline, fast, deterministic — great for re-runs).
  (default)          Run cluster_snapshot.py live as a subprocess to
                     produce a fresh snapshot, then aggregate.
  --no-fetch-live    If no snapshot is available, error out instead of
                     running cluster_snapshot.py.

Companion reports (optional, auto-detected)
-------------------------------------------
If these files exist in ``snapshots/`` or ``reports/`` next to the script,
the executive report will fold their findings in automatically:

  * snapshots/vulnerabilities-YYYY-MM-DD.csv  (from generate_vuln_report.py)
  * snapshots/conversations-*-YYYY-MM-DD.json (from download_conversations.py)
  * snapshots/policies-all.json               (from download_policies.py)
  * snapshots/flows-*.csv                     (from download_flows.py)
  * reports/forensics-posture-*.html          (existence-only, links out)
  * reports/flow-analysis-*.html              (existence-only, links out)

Missing companions degrade the report gracefully — a section is skipped or
replaced with a "Run X to populate this section" call-out.

Outputs
-------
  reports/executive-summary-YYYY-MM-DD.html
  reports/executive-summary-YYYY-MM-DD.md

Usage
-----
    # Default: live snapshot + auto-discovered companions
    python3 generate_executive_report.py

    # Reuse an existing snapshot, skip live API call
    python3 generate_executive_report.py --snapshot snapshots/snapshot-2026-04-20.json

    # Customer-named report, MD only
    python3 generate_executive_report.py \\
        --prepared-for "ACME Corp" --prepared-by "CSW POV Team" --md-only

Requirements
------------
Standard library only.
"""

import argparse
import csv
import glob
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SNAPSHOT_SCRIPT = SCRIPT_DIR / "cluster_snapshot.py"


# ──────────────────────────────────────────────────────────────────────────
# 1. Snapshot loading
# ──────────────────────────────────────────────────────────────────────────

def latest_snapshot(snapshots_dir: Path) -> Path | None:
    """Return path to the most recent ``snapshot-*.json`` file, or None."""
    if not snapshots_dir.exists():
        return None
    candidates = sorted(snapshots_dir.glob("snapshot-*.json"), reverse=True)
    return candidates[0] if candidates else None


def run_live_snapshot(snapshots_dir: Path, skip_flows: bool = False) -> Path:
    """
    Invoke ``cluster_snapshot.py`` as a subprocess so we get a fresh snapshot
    using the canonical collection logic (no duplication). Writes JSON only.

    Why subprocess and not ``import cluster_snapshot``?  Because the snapshot
    script today does a lot of ``subprocess.run([csw_api.py ...])`` itself
    and parses argv at module level. Wrapping it as a subprocess keeps things
    decoupled and avoids surprising side-effects on import.
    """
    if not SNAPSHOT_SCRIPT.exists():
        raise FileNotFoundError(
            f"cluster_snapshot.py not found at {SNAPSHOT_SCRIPT}. "
            "Cannot generate a live snapshot."
        )

    snapshots_dir.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(SNAPSHOT_SCRIPT),
           "--output-dir", str(snapshots_dir), "--json-only"]
    if skip_flows:
        cmd.append("--skip-flows")

    print(f"[live] Generating fresh snapshot via cluster_snapshot.py "
          f"(this may take a couple of minutes)...")
    result = subprocess.run(cmd, cwd=str(SCRIPT_DIR))
    if result.returncode != 0:
        raise RuntimeError(
            f"cluster_snapshot.py exited with code {result.returncode}. "
            "Check credentials in .env and re-run."
        )

    fresh = latest_snapshot(snapshots_dir)
    if fresh is None:
        raise RuntimeError(
            "cluster_snapshot.py succeeded but produced no snapshot file."
        )
    return fresh


def load_snapshot(args) -> tuple[dict, Path]:
    """
    Resolve the data source according to CLI flags and return
    ``(snapshot_dict, snapshot_path)``.
    """
    snapshots_dir = Path(args.snapshots_dir)

    if args.snapshot:
        snap_path = Path(args.snapshot)
        if not snap_path.exists():
            sys.exit(f"ERROR: --snapshot file not found: {snap_path}")
    elif args.snapshot_latest:
        snap_path = latest_snapshot(snapshots_dir)
        if snap_path is None:
            sys.exit(f"ERROR: no snapshot-*.json files found in {snapshots_dir}")
        print(f"[auto] Using most recent snapshot: {snap_path}")
    else:
        # Default: try latest first; if absent, run live (unless --no-fetch-live).
        snap_path = latest_snapshot(snapshots_dir)
        if snap_path is None:
            if args.no_fetch_live:
                sys.exit(
                    f"ERROR: no snapshot in {snapshots_dir} and "
                    "--no-fetch-live was set. Run cluster_snapshot.py first "
                    "or remove --no-fetch-live."
                )
            snap_path = run_live_snapshot(snapshots_dir,
                                          skip_flows=args.skip_flows)
        elif args.refresh:
            print("[refresh] --refresh set; ignoring existing snapshot, "
                  "running cluster_snapshot.py live.")
            snap_path = run_live_snapshot(snapshots_dir,
                                          skip_flows=args.skip_flows)

    with open(snap_path, "r", encoding="utf-8") as f:
        snapshot = json.load(f)
    return snapshot, snap_path


# ──────────────────────────────────────────────────────────────────────────
# 2. Companion report discovery + parsers
# ──────────────────────────────────────────────────────────────────────────

def find_companions(snapshots_dir: Path, reports_dir: Path) -> dict:
    """
    Scan ``snapshots/`` and ``reports/`` for companion artefacts. Returns a
    dict mapping logical name → most-recent matching file (or None).

    All paths are returned as ``Path`` objects, so downstream code can call
    ``.exists()`` /  ``.read_text()`` directly.
    """

    def latest(pattern: str, base: Path) -> Path | None:
        if not base.exists():
            return None
        matches = sorted(base.glob(pattern), reverse=True)
        return matches[0] if matches else None

    return {
        "vuln_csv":        latest("vulnerabilities-*.csv", snapshots_dir),
        "conversations":   latest("conversations-*.json",  snapshots_dir),
        "policies":        snapshots_dir / "policies-all.json"
                           if (snapshots_dir / "policies-all.json").exists()
                           else None,
        "flows_csv":       latest("flows-*.csv",          snapshots_dir),
        "forensics_html":  latest("forensics-posture-*.html", reports_dir),
        "forensics_cfg":   latest("forensics-config-*.json",  snapshots_dir),
        "flow_analysis":   latest("flow-analysis-*.html",     reports_dir),
        "policy_workload": latest("policy-workload-report-*.html", reports_dir),
    }


def parse_vuln_csv(path: Path) -> dict:
    """
    Roll up a vulnerability CSV produced by ``generate_vuln_report.py`` into
    high-level KPIs.

    The CSV has one row per (host, CVE) tuple. We bucket by CVSSv3 base
    severity and count "exploitable in the wild" using the CVM intelligence
    columns the toolkit already populates (``easily_exploitable``,
    ``malware_exploitable``, ``active_internet_breach``).
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    exploitable = 0
    fix_available = 0
    host_severity: dict[str, dict[str, int]] = {}
    cve_freq: dict[str, int] = {}
    total_rows = 0

    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_rows += 1
            sev = (row.get("v3_base_severity") or
                   row.get("cvm_severity") or "UNKNOWN").upper().strip()
            if sev not in counts:
                sev = "UNKNOWN"
            counts[sev] += 1

            host = row.get("hostname", "(unknown)")
            host_severity.setdefault(host, {"CRITICAL": 0, "HIGH": 0,
                                            "MEDIUM": 0, "LOW": 0,
                                            "UNKNOWN": 0})
            host_severity[host][sev] += 1

            cve = row.get("cve_id", "")
            if cve:
                cve_freq[cve] = cve_freq.get(cve, 0) + 1

            def _truthy(v):
                # CVM booleans round-trip through CSV as the strings
                # "True"/"False"; treat anything else as falsy.
                return str(v).strip().lower() == "true"

            if (_truthy(row.get("cvm_easily_exploitable"))
                    or _truthy(row.get("cvm_malware_exploitable"))
                    or _truthy(row.get("cvm_active_internet_breach"))):
                exploitable += 1
            if _truthy(row.get("cvm_fix_available")):
                fix_available += 1

    # Top hosts by Critical+High count, top CVEs by frequency
    top_hosts = sorted(
        host_severity.items(),
        key=lambda kv: (-(kv[1]["CRITICAL"] + kv[1]["HIGH"]), kv[0])
    )[:5]
    top_cves = sorted(cve_freq.items(), key=lambda kv: -kv[1])[:5]

    return {
        "total_findings": total_rows,
        "by_severity": counts,
        "exploitable": exploitable,
        "fix_available": fix_available,
        "exposed_hosts": len(host_severity),
        "top_hosts": top_hosts,
        "top_cves": top_cves,
        "source_file": str(path),
    }


def parse_conversations_json(path: Path) -> dict:
    """
    Light parse of a conversations export. We just count records and try to
    extract the workspace name from the filename (the script's naming
    convention is ``conversations-<workspace>-<date>.json``).
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"available": False, "source_file": str(path)}

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("results") or data.get("items") or []
    else:
        records = []

    # Filename: conversations-<workspace_slug>-<date>.json
    stem = path.stem
    workspace = stem.replace("conversations-", "")
    workspace = workspace.rsplit("-", 3)[0] if workspace.count("-") >= 2 else workspace

    return {
        "available": True,
        "total_conversations": len(records),
        "workspace": workspace,
        "source_file": str(path),
    }


def parse_policies_json(path: Path) -> dict:
    """
    Count policies produced by ``download_policies.py``. The JSON is a list
    of policy objects keyed by workspace; we count by enforcement state.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"available": False, "source_file": str(path)}

    # The exact shape varies — sometimes a list, sometimes a dict of lists.
    total = 0
    if isinstance(data, list):
        total = len(data)
    elif isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                total += len(v)

    return {
        "available": True,
        "total_policies_in_export": total,
        "source_file": str(path),
    }


def parse_flows_csv(path: Path) -> dict:
    """Count rows in a flows CSV (cheap, just for the headline KPI)."""
    try:
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            count = sum(1 for _ in reader)
        return {"available": True, "row_count": count,
                "header_count": len(header) if header else 0,
                "source_file": str(path)}
    except Exception:
        return {"available": False, "source_file": str(path)}


# ──────────────────────────────────────────────────────────────────────────
# 3. KPI aggregation
# ──────────────────────────────────────────────────────────────────────────

def safe_pct(numerator: int, denominator: int) -> float:
    """Percentage helper that never divides by zero."""
    if not denominator:
        return 0.0
    return round(100.0 * numerator / denominator, 1)


def aggregate_metrics(snapshot: dict, companions: dict) -> dict:
    """
    Roll the snapshot + companion-report findings into the headline numbers
    the executive report will display.

    All percentages are 0-100 floats with one decimal place. All "score"
    fields are 0-100 integers, lower = worse. The report's narrative reads
    these and decides what colour/badge to use.
    """
    sensors    = snapshot.get("sensors", {}) or {}
    scopes     = snapshot.get("scopes", {}) or {}
    workspaces = snapshot.get("workspaces", {}) or {}
    flows      = snapshot.get("flows", {}) or {}

    total_agents   = int(sensors.get("total", 0) or 0)
    enforced_count = int(sensors.get("enforcement", {}).get("count", 0) or 0)
    pkg_vis        = int(sensors.get("pkg_vis", {}).get("count", 0) or 0)
    proc_vis       = int(sensors.get("proc_vis", {}).get("count", 0) or 0)
    forensics_on   = int(sensors.get("forensics", {}).get("count", 0) or 0)
    insecure       = sensors.get("insecure", []) or []
    health_warn    = sensors.get("health_warn", []) or []
    health_ok      = int(sensors.get("health_ok", total_agents) or 0)

    total_scopes     = int(scopes.get("total", 0) or 0)
    total_workspaces = int(workspaces.get("total", 0) or 0)
    total_policies   = int(workspaces.get("grand_policy_total", 0) or 0)
    enforcing_ws     = sum(1 for w in workspaces.get("workspaces", [])
                           if w.get("enforcing"))

    # Flow signals (only populated if flows were collected)
    flows_available  = bool(flows.get("available"))
    flow_total       = int(flows.get("total_sample", 0) or 0)
    flow_permitted   = int(flows.get("permitted", 0) or 0)
    flow_rejected    = int(flows.get("rejected", 0) or 0)
    risky_ports_seen = flows.get("risky_ports") or {}
    if isinstance(risky_ports_seen, dict):
        risky_port_count = len(risky_ports_seen)
    else:
        risky_port_count = len(risky_ports_seen) if risky_ports_seen else 0

    # Coverage percentages (all 0-100)
    enforcement_pct = safe_pct(enforced_count, total_agents)
    visibility_pct  = safe_pct(pkg_vis + proc_vis, 2 * total_agents)
    health_pct      = safe_pct(health_ok, total_agents)
    forensics_pct   = safe_pct(forensics_on, total_agents)

    # Blast-radius score (0=fully exposed, 100=fully contained). It's a
    # proxy: lateral movement is most constrained when (a) every workload is
    # under enforcement (not just visibility) and (b) policies actually exist
    # to enforce. We weight enforcement coverage 0.7 and policy maturity 0.3.
    policy_maturity = min(1.0, total_policies / max(1, 5 * total_workspaces))
    blast_radius_score = int(round(
        100 * (0.7 * (enforcement_pct / 100.0) + 0.3 * policy_maturity)
    ))

    # Vulnerability posture (only if a vuln CSV companion was found)
    vuln = None
    if companions.get("vuln_csv"):
        vuln = parse_vuln_csv(companions["vuln_csv"])

    # Conversations / policies / flows companion summaries
    convo_summary = (parse_conversations_json(companions["conversations"])
                     if companions.get("conversations") else None)
    policy_summary = (parse_policies_json(companions["policies"])
                      if companions.get("policies") else None)
    flows_csv_summary = (parse_flows_csv(companions["flows_csv"])
                         if companions.get("flows_csv") else None)

    return {
        # Basics
        "cluster":      snapshot.get("cluster", "Unknown cluster"),
        "snapshot_ts":  snapshot.get("timestamp", "Unknown"),
        "root_scope":   snapshot.get("root_scope", "Default"),
        # Coverage
        "total_agents":     total_agents,
        "enforced_count":   enforced_count,
        "enforcement_pct":  enforcement_pct,
        "visibility_pct":   visibility_pct,
        "health_pct":       health_pct,
        "forensics_pct":    forensics_pct,
        "insecure_hosts":   len(insecure),
        "health_warn":      len(health_warn),
        "pkg_vis":          pkg_vis,
        "proc_vis":         proc_vis,
        "forensics_on":     forensics_on,
        # Inventory
        "total_scopes":     total_scopes,
        "total_workspaces": total_workspaces,
        "enforcing_ws":     enforcing_ws,
        "total_policies":   total_policies,
        # Flows (snapshot probe)
        "flows_available":  flows_available,
        "flow_total":       flow_total,
        "flow_permitted":   flow_permitted,
        "flow_rejected":    flow_rejected,
        "risky_port_count": risky_port_count,
        "risky_ports":      risky_ports_seen,
        # Posture scores
        "blast_radius_score": blast_radius_score,
        "policy_maturity":    round(policy_maturity * 100, 1),
        # Companion data
        "vuln":              vuln,
        "convo_summary":     convo_summary,
        "policy_summary":    policy_summary,
        "flows_csv_summary": flows_csv_summary,
    }


# ──────────────────────────────────────────────────────────────────────────
# 4. Recommendations engine
# ──────────────────────────────────────────────────────────────────────────

def derive_recommendations(m: dict, companions: dict) -> list[dict]:
    """
    Turn KPI numbers into ordered, time-bound, business-language recs.

    Each recommendation is a dict with: priority, title, business_impact,
    action, owner, horizon. Priority drives ordering and HTML colour.
    """
    recs: list[dict] = []
    total = max(1, m["total_agents"])

    # ── 1. Enforcement gap ────────────────────────────────────────────────
    if m["enforcement_pct"] < 80:
        unprotected = total - m["enforced_count"]
        recs.append({
            "priority": "Critical" if m["enforcement_pct"] < 50 else "High",
            "title": f"Roll out enforcement to {unprotected} workload(s) "
                     f"still in visibility-only mode",
            "business_impact":
                f"Today {m['enforcement_pct']:.0f}% of the estate is "
                f"actively segmented; the remaining {100 - m['enforcement_pct']:.0f}% "
                f"can still be traversed laterally by an attacker who "
                f"compromises any one host.",
            "action": "Move agents from VISIBILITY mode to ENFORCER mode in "
                      "stages, beginning with high-value workspaces (DB, PCI, "
                      "PHI). Use ADM-suggested policies as the starting "
                      "ruleset.",
            "owner":   "SecOps + Application Owners",
            "horizon": "30–60 days",
        })

    # ── 2. Critical/exploitable CVEs ─────────────────────────────────────
    if m["vuln"]:
        v = m["vuln"]
        crit = v["by_severity"].get("CRITICAL", 0)
        high = v["by_severity"].get("HIGH", 0)
        if crit + high > 0:
            recs.append({
                "priority": "Critical" if crit > 0 else "High",
                "title": f"Remediate {crit} Critical and {high} High CVEs "
                         f"affecting {v['exposed_hosts']} workload(s)",
                "business_impact":
                    f"{v['exploitable']} of these findings are flagged as "
                    f"actively exploited or with known malware in the wild "
                    f"(CSW CVM intelligence). {v['fix_available']} have "
                    f"vendor patches available today.",
                "action": "Patch the top hosts listed in the executive "
                          "report's Vulnerability section; for unpatched "
                          "items, compensate with tighter segmentation rules "
                          "around the affected workloads.",
                "owner":   "Patch Management + SecOps",
                "horizon": "30 days for Critical, 60 days for High",
            })
    else:
        recs.append({
            "priority": "Medium",
            "title": "Run the vulnerability scan to quantify CVE exposure",
            "business_impact":
                "Without a vulnerability rollup, the report cannot tell "
                "leadership how much of the estate is exposed to known "
                "exploits. CVE data also drives the risk-based prioritization "
                "of which segments to enforce first.",
            "action": "Run `python3 generate_vuln_report.py` (writes a CSV "
                      "this report will pick up automatically on the next "
                      "run).",
            "owner":   "SecOps",
            "horizon": "Within the next reporting cycle",
        })

    # ── 3. Threat detection / forensics coverage ──────────────────────────
    forensics_pct = m["forensics_pct"]
    if forensics_pct < 80:
        recs.append({
            "priority": "High" if forensics_pct < 50 else "Medium",
            "title":
                f"Expand forensic-rule coverage — only "
                f"{forensics_pct:.0f}% of agents have forensics enabled",
            "business_impact":
                "Forensic rules are how CSW spots in-progress attacker "
                "behaviour (privilege escalation, fileless malware, lateral "
                "RDP sweeps). Hosts without forensics are blind spots for "
                "post-breach investigation.",
            "action": "Enable the default forensic profile cluster-wide and "
                      "extend with MITRE-aligned custom rules for the most "
                      "valuable workloads.",
            "owner":   "SOC + SecOps",
            "horizon": "60–90 days",
        })

    # ── 4. Insecure cipher / agent health ────────────────────────────────
    if m["insecure_hosts"] > 0:
        recs.append({
            "priority": "High",
            "title": f"Replace insecure agent ciphers on "
                     f"{m['insecure_hosts']} host(s)",
            "business_impact":
                "Hosts using deprecated TLS ciphers can leak agent telemetry "
                "or be downgraded by an in-network attacker, defeating the "
                "trust between sensor and CSW.",
            "action": "Upgrade affected agents to the latest supported "
                      "version and re-key TLS material.",
            "owner":   "Platform Engineering",
            "horizon": "30 days",
        })
    if m["health_warn"] > 0:
        recs.append({
            "priority": "Medium",
            "title": f"Investigate {m['health_warn']} unhealthy agent(s)",
            "business_impact":
                "Unhealthy agents may drop flow telemetry — gaps that look "
                "like an attacker's silence to the SOC.",
            "action": "Review the Agent Deployment table in the Cluster "
                      "Readout and triage with the platform team.",
            "owner":   "Platform Engineering",
            "horizon": "30 days",
        })

    # ── 5. Risky ports observed in flows ─────────────────────────────────
    if m["flows_available"] and m["risky_port_count"] > 0:
        recs.append({
            "priority": "High",
            "title": f"Lock down {m['risky_port_count']} high-risk service "
                     f"port(s) seen in live flows",
            "business_impact":
                "RDP, SMB, telnet, exposed databases — these are the "
                "lateral-movement and ransomware vectors cited in nearly "
                "every recent breach report.",
            "action": "For each risky port, add an explicit allow rule "
                      "between known consumers and providers, and a deny-all "
                      "catch-all elsewhere.",
            "owner":   "NetSec + Application Owners",
            "horizon": "30 days",
        })

    # ── 6. Policy maturity ────────────────────────────────────────────────
    if m["policy_maturity"] < 60:
        recs.append({
            "priority": "Medium",
            "title": "Mature the policy ruleset (currently early-stage)",
            "business_impact":
                "An average of fewer than 5 policies per workspace usually "
                "means ADM-suggested rules have been reviewed but not yet "
                "tightened. Generic rules permit more east-west traffic than "
                "needed.",
            "action": "Walk each workspace's ADM suggestions, tighten "
                      "consumer/provider scoping, and graduate the "
                      "workspace from 'Primary' to 'Enforcing'.",
            "owner":   "SecOps + Application Owners",
            "horizon": "60–90 days",
        })

    # ── 7. Always-on closing rec ─────────────────────────────────────────
    recs.append({
        "priority": "Ongoing",
        "title": "Schedule monthly snapshots and quarterly executive reviews",
        "business_impact":
            "The blast-radius and posture metrics in this report only become "
            "meaningful when tracked over time. Trend lines are what convince "
            "the board the program is working.",
        "action": "Cron `python3 cluster_snapshot.py` monthly and "
                  "`python3 generate_executive_report.py` after each. Use "
                  "`cluster_delta.py` between snapshots for change tracking.",
        "owner":   "SecOps",
        "horizon": "Ongoing",
    })

    # Stable priority order
    order = {"Critical": 0, "High": 1, "Medium": 2, "Ongoing": 3}
    recs.sort(key=lambda r: order.get(r["priority"], 9))
    return recs


# ──────────────────────────────────────────────────────────────────────────
# 5. Tiny rendering helpers (kept inline so the file is single-source)
# ──────────────────────────────────────────────────────────────────────────

PRIORITY_COLOURS = {
    "Critical": ("#fee2e2", "#991b1b"),
    "High":     ("#fef3c7", "#92400e"),
    "Medium":   ("#dbeafe", "#1e40af"),
    "Ongoing":  ("#f1f5f9", "#475569"),
}


def html_pill(text: str, palette: str = "blue") -> str:
    """Tailwind-ish pill badge, inline-styled for portability."""
    palettes = {
        "green": ("#d1fae5", "#065f46"),
        "red":   ("#fee2e2", "#991b1b"),
        "amber": ("#fef3c7", "#92400e"),
        "blue":  ("#dbeafe", "#1e40af"),
        "gray":  ("#f1f5f9", "#475569"),
    }
    bg, fg = palettes.get(palette, palettes["blue"])
    return (f'<span style="background:{bg};color:{fg};padding:2px 10px;'
            f'border-radius:999px;font-size:0.72rem;font-weight:600">'
            f'{text}</span>')


def html_priority_pill(priority: str) -> str:
    bg, fg = PRIORITY_COLOURS.get(priority, PRIORITY_COLOURS["Medium"])
    return (f'<span style="background:{bg};color:{fg};padding:3px 12px;'
            f'border-radius:6px;font-size:0.72rem;font-weight:700;'
            f'letter-spacing:.4px;text-transform:uppercase">{priority}</span>')


def html_table(headers: list[str], rows: list[list[str]]) -> str:
    ths = "".join(f"<th>{h}</th>" for h in headers)
    trs = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
                  for row in rows)
    return (f'<div class="table-wrap"><table><thead><tr>{ths}</tr></thead>'
            f'<tbody>{trs}</tbody></table></div>')


def score_colour(score: int, good_high: bool = True) -> str:
    """Map a 0-100 score to a CSS colour class. ``good_high`` flips polarity."""
    if good_high:
        if score >= 80: return "ok"
        if score >= 50: return "warn-amber"
        return "warn"
    else:
        if score <= 20: return "ok"
        if score <= 50: return "warn-amber"
        return "warn"


# ──────────────────────────────────────────────────────────────────────────
# 6. HTML renderer
# ──────────────────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Executive Summary — {cluster}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {{
  --bg:#F8FAFC; --card:#fff; --border:#E2E8F0;
  --cisco:#00bceb; --cisco-dark:#005073;
  --green:#059669; --red:#dc2626; --amber:#d97706; --blue:#0369A1;
  --text:#020617; --text2:#475569; --text3:#94A3B8;
  --shadow-sm:0 1px 3px rgba(0,0,0,.06); --shadow-md:0 4px 6px rgba(0,0,0,.06);
  --radius:10px;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);
     color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}}
.header{{background:linear-gradient(135deg,#00bceb 0%,#005073 100%);
         color:#fff;padding:2.5rem 2rem 2rem}}
.header .inner{{max-width:1140px;margin:0 auto}}
.header h1{{font-size:1.85rem;font-weight:800;letter-spacing:-.3px}}
.header .sub{{opacity:.92;margin-top:.4rem;font-size:.95rem}}
.header .meta{{margin-top:1.2rem;display:flex;flex-wrap:wrap;gap:.6rem;font-size:.8rem}}
.header .meta span{{background:rgba(255,255,255,.14);padding:4px 12px;
                    border-radius:99px;backdrop-filter:blur(4px)}}
.tldr{{background:#0c4a6e;color:#e0f2fe;padding:1.25rem 2rem}}
.tldr .inner{{max-width:1140px;margin:0 auto}}
.tldr h2{{font-size:.78rem;text-transform:uppercase;letter-spacing:1px;
         color:#bae6fd;margin-bottom:.6rem;font-weight:700}}
.tldr p{{font-size:1rem;line-height:1.65}}
.kpi-strip{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
            gap:1px;background:var(--border);border-bottom:1px solid var(--border)}}
.kpi{{background:var(--card);padding:1.4rem 1rem;text-align:center}}
.kpi .val{{font-size:2.05rem;font-weight:800;line-height:1}}
.kpi .val.ok{{color:var(--green)}}
.kpi .val.warn{{color:var(--red)}}
.kpi .val.warn-amber{{color:var(--amber)}}
.kpi .lbl{{font-size:.7rem;color:var(--text3);margin-top:.4rem;
          text-transform:uppercase;letter-spacing:.7px;font-weight:600}}
.kpi .sub{{font-size:.72rem;color:var(--text3);margin-top:.25rem}}
.content{{max-width:1140px;margin:2rem auto;padding:0 1.5rem;display:grid;gap:1.5rem}}
.card{{background:var(--card);border:1px solid var(--border);
       border-radius:var(--radius);box-shadow:var(--shadow-sm);overflow:hidden}}
.card-header{{padding:.95rem 1.5rem;border-bottom:1px solid var(--border);
              display:flex;align-items:center;gap:.75rem;background:#FAFBFC}}
.card-header h2{{font-size:1rem;font-weight:700}}
.card-icon{{width:32px;height:32px;border-radius:8px;display:flex;
            align-items:center;justify-content:center;font-size:1rem}}
.card-body{{padding:1.4rem 1.5rem}}
.card-body p{{margin-bottom:.75rem}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem}}
@media(max-width:720px){{.two-col{{grid-template-columns:1fr}}}}
.posture-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
               gap:1rem;margin-top:.5rem}}
.posture-card{{padding:1rem;border:1px solid var(--border);border-radius:8px;
              background:#FAFBFC}}
.posture-card .score{{font-size:1.7rem;font-weight:800;line-height:1}}
.posture-card .score.ok{{color:var(--green)}}
.posture-card .score.warn{{color:var(--red)}}
.posture-card .score.warn-amber{{color:var(--amber)}}
.posture-card .label{{font-size:.72rem;text-transform:uppercase;
                     letter-spacing:.6px;color:var(--text3);margin-top:.3rem}}
.posture-card .desc{{font-size:.78rem;color:var(--text2);margin-top:.5rem;line-height:1.4}}
.bar{{height:6px;background:#E2E8F0;border-radius:99px;overflow:hidden;margin-top:.4rem}}
.bar-fill{{height:100%;border-radius:99px}}
.bar-fill.ok{{background:var(--green)}}
.bar-fill.warn{{background:var(--red)}}
.bar-fill.warn-amber{{background:var(--amber)}}
.rec{{padding:1rem 1.25rem;border-left:4px solid #94A3B8;background:#fff;
      border-bottom:1px solid var(--border)}}
.rec:last-child{{border-bottom:none}}
.rec.crit{{border-left-color:var(--red)}}
.rec.high{{border-left-color:var(--amber)}}
.rec.med{{border-left-color:var(--blue)}}
.rec .top{{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}}
.rec h3{{font-size:.96rem;font-weight:700;color:var(--text)}}
.rec dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem;
        margin-top:.6rem;font-size:.85rem}}
.rec dt{{color:var(--text3);font-weight:600;text-transform:uppercase;
        letter-spacing:.4px;font-size:.7rem;align-self:start;padding-top:.15rem}}
.rec dd{{color:var(--text2)}}
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:.84rem}}
thead{{background:#F1F5F9}}
th{{padding:.55rem .9rem;text-align:left;font-size:.7rem;text-transform:uppercase;
   letter-spacing:.5px;color:var(--text2);border-bottom:2px solid var(--border);font-weight:600}}
td{{padding:.55rem .9rem;border-bottom:1px solid #F1F5F9}}
tbody tr:nth-child(even) td{{background:#FAFBFC}}
.callout{{background:#FFFBEB;border-left:4px solid var(--amber);
         padding:.85rem 1.25rem;font-size:.85rem;color:#78350f;border-radius:6px}}
.callout.info{{background:#EFF6FF;border-left-color:var(--blue);color:#1e40af}}
footer{{text-align:center;padding:2.5rem 1rem;font-size:.75rem;
        color:var(--text3);border-top:1px solid var(--border);margin-top:2rem}}
@media print{{
  body{{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .header,.tldr{{-webkit-print-color-adjust:exact}}
  .card,.rec{{break-inside:avoid}}
}}
</style>
</head>
<body>

<div class="header">
  <div class="inner">
    <div style="font-size:.75rem;font-weight:700;letter-spacing:2px;
                opacity:.9;margin-bottom:.3rem">CISCO SECURE WORKLOAD</div>
    <h1>Executive Security Posture Summary</h1>
    <div class="sub">Prepared for <strong>{prepared_for}</strong>
        &middot; Cluster <strong>{cluster}</strong></div>
    <div class="meta">
      <span>Snapshot: {snapshot_ts}</span>
      <span>Generated: {generated}</span>
      <span>Root Scope: {root_scope}</span>
      <span>Prepared by: {prepared_by}</span>
    </div>
  </div>
</div>

<div class="tldr">
  <div class="inner">
    <h2>Executive summary</h2>
    <p>{tldr_html}</p>
  </div>
</div>

<div class="kpi-strip">
{kpi_strip_html}
</div>

<div class="content">

  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#dbeafe">📊</div>
      <h2>Security Posture Scorecard</h2>
    </div>
    <div class="card-body">
      <p style="color:var(--text2);font-size:.88rem">
      The four indicators below summarize how the cluster is doing on the
      dimensions an executive cares about: how much of the estate is being
      watched, how much is actively defended, how mature the policy ruleset
      is, and how well the platform would detect a live attacker today.</p>
      <div class="posture-grid">
        {posture_cards_html}
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#fee2e2">🎯</div>
      <h2>Prioritized Recommendations</h2>
    </div>
    <div class="card-body" style="padding:0">
      {recommendations_html}
    </div>
  </div>

  <div class="two-col">
    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:#dbeafe">🛡</div>
        <h2>Visibility &amp; Enforcement</h2>
      </div>
      <div class="card-body">
        {coverage_table_html}
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:#ede9fe">📐</div>
        <h2>Segmentation Inventory</h2>
      </div>
      <div class="card-body">
        {segmentation_table_html}
      </div>
    </div>
  </div>

  {vuln_card_html}

  {flows_card_html}

  {sources_card_html}

</div>

<footer>
  <p><strong>Cisco Secure Workload — Executive Summary</strong></p>
  <p>Generated {generated} from snapshot {snapshot_path}</p>
  <p>This report aggregates data from cluster_snapshot.py and any companion
     reports found in the working directory. Methodology details are
     embedded in the script. Trend over time by re-running monthly.</p>
</footer>

</body>
</html>
"""


def render_html(metrics: dict, snapshot: dict, companions: dict,
                recommendations: list[dict], header_info: dict) -> str:
    m = metrics

    # ── TL;DR narrative ───────────────────────────────────────────────────
    if m["enforcement_pct"] >= 80:
        radius_phrase = "the lateral-movement blast radius is well-contained"
    elif m["enforcement_pct"] >= 50:
        radius_phrase = "the blast radius is partially contained"
    else:
        radius_phrase = ("most of the estate is observed but not yet "
                         "actively segmented — the blast radius is wide")
    crit_recs = sum(1 for r in recommendations if r["priority"] == "Critical")
    high_recs = sum(1 for r in recommendations if r["priority"] == "High")
    tldr = (
        f"Across <strong>{m['total_agents']}</strong> instrumented "
        f"workload(s) in <strong>{m['total_workspaces']}</strong> "
        f"workspace(s), {radius_phrase}: "
        f"<strong>{m['enforcement_pct']:.0f}%</strong> are under active "
        f"enforcement and <strong>{m['visibility_pct']:.0f}%</strong> are "
        f"under full visibility. The blast-radius score is "
        f"<strong>{m['blast_radius_score']}/100</strong> "
        f"({'good' if m['blast_radius_score'] >= 80 else 'needs work' if m['blast_radius_score'] >= 50 else 'priority area'}). "
        f"This report identifies "
        f"<strong>{crit_recs}</strong> Critical and "
        f"<strong>{high_recs}</strong> High-priority action(s) to close gaps."
    )

    # ── KPI strip ─────────────────────────────────────────────────────────
    kpi_cells = []
    def kpi(val, lbl, klass="", sub=""):
        sub_html = f'<div class="sub">{sub}</div>' if sub else ""
        kpi_cells.append(
            f'<div class="kpi"><div class="val {klass}">{val}</div>'
            f'<div class="lbl">{lbl}</div>{sub_html}</div>'
        )

    kpi(m["total_agents"], "Workloads")
    kpi(f"{m['enforcement_pct']:.0f}%",
        "Enforcement", score_colour(int(m["enforcement_pct"]), good_high=True))
    kpi(f"{m['visibility_pct']:.0f}%",
        "Visibility", score_colour(int(m["visibility_pct"]), good_high=True))
    kpi(m["blast_radius_score"],
        "Blast Radius", score_colour(m["blast_radius_score"], good_high=True),
        sub="0=exposed · 100=contained")
    kpi(m["total_workspaces"], "Workspaces")
    kpi(m["total_policies"], "Policies",
        sub=f"{m['enforcing_ws']} enforcing")
    if m["vuln"]:
        crit = m["vuln"]["by_severity"]["CRITICAL"]
        high = m["vuln"]["by_severity"]["HIGH"]
        kpi(crit + high, "Critical+High CVEs",
            "warn" if (crit + high) > 0 else "ok")
    kpi(m["forensics_on"], "Forensics ON",
        "ok" if m["forensics_pct"] >= 80
        else "warn-amber" if m["forensics_pct"] >= 50 else "warn")

    # ── Posture cards ────────────────────────────────────────────────────
    def posture_card(title: str, score: int, desc: str,
                     good_high: bool = True) -> str:
        klass = score_colour(score, good_high=good_high)
        bar = klass if klass != "warn-amber" else "warn-amber"
        return (
            f'<div class="posture-card">'
            f'<div class="score {klass}">{score}</div>'
            f'<div class="label">{title}</div>'
            f'<div class="bar"><div class="bar-fill {bar}" '
            f'style="width:{score}%"></div></div>'
            f'<div class="desc">{desc}</div>'
            f'</div>'
        )

    posture_cards = [
        posture_card("Visibility coverage", int(m["visibility_pct"]),
                     "Share of agents reporting both package and process "
                     "telemetry. Higher is better."),
        posture_card("Enforcement coverage", int(m["enforcement_pct"]),
                     "Share of agents actively enforcing segmentation "
                     "policy in the host kernel. Higher is better."),
        posture_card("Policy maturity", int(m["policy_maturity"]),
                     "Proxy for ruleset richness (avg policies per "
                     "workspace, capped at 5). Higher = more refined rules."),
        posture_card("Blast-radius containment", m["blast_radius_score"],
                     "How constrained lateral movement would be after a "
                     "compromise today. Higher = better contained."),
    ]

    # ── Coverage table ────────────────────────────────────────────────────
    coverage_rows = [
        ["Total workloads with agents", str(m["total_agents"])],
        ["Package visibility",
         f"{m['pkg_vis']} ({safe_pct(m['pkg_vis'], m['total_agents']):.0f}%)"],
        ["Process visibility",
         f"{m['proc_vis']} ({safe_pct(m['proc_vis'], m['total_agents']):.0f}%)"],
        ["Forensics enabled",
         f"{m['forensics_on']} ({m['forensics_pct']:.0f}%)"],
        ["Enforcement enabled",
         f"{m['enforced_count']} ({m['enforcement_pct']:.0f}%)"],
        ["Healthy agents",
         f"{int(m['health_pct'])}%  "
         f"({'all clear' if m['health_warn'] == 0 else str(m['health_warn']) + ' alerts'})"],
        ["Insecure-cipher hosts",
         html_pill(str(m["insecure_hosts"]),
                   "red" if m["insecure_hosts"] > 0 else "green")],
    ]
    coverage_table_html = html_table(["Indicator", "Value"], coverage_rows)

    # ── Segmentation table ────────────────────────────────────────────────
    seg_rows = [
        ["Total scopes (organisational tree)", str(m["total_scopes"])],
        ["Total workspaces", str(m["total_workspaces"])],
        ["Workspaces in enforcing mode",
         f"{m['enforcing_ws']} of {m['total_workspaces']}"],
        ["Total policies (all workspaces)", str(m["total_policies"])],
        ["Average policies per workspace",
         f"{(m['total_policies'] / max(1, m['total_workspaces'])):.1f}"],
    ]
    if m["convo_summary"] and m["convo_summary"]["available"]:
        seg_rows.append(
            ["Conversations exported",
             f"{m['convo_summary']['total_conversations']:,} "
             f"(workspace: {m['convo_summary']['workspace']})"]
        )
    if m["policy_summary"] and m["policy_summary"]["available"]:
        seg_rows.append(
            ["Policies in companion export",
             f"{m['policy_summary']['total_policies_in_export']:,}"]
        )
    segmentation_table_html = html_table(["Indicator", "Value"], seg_rows)

    # ── Recommendations card ──────────────────────────────────────────────
    rec_blocks = []
    css_map = {"Critical": "crit", "High": "high",
               "Medium": "med", "Ongoing": ""}
    for r in recommendations:
        rec_blocks.append(
            f'<div class="rec {css_map.get(r["priority"], "")}">'
            f'  <div class="top">'
            f'    <h3>{r["title"]}</h3>'
            f'    {html_priority_pill(r["priority"])}'
            f'  </div>'
            f'  <dl>'
            f'    <dt>Why</dt><dd>{r["business_impact"]}</dd>'
            f'    <dt>Action</dt><dd>{r["action"]}</dd>'
            f'    <dt>Owner</dt><dd>{r["owner"]}</dd>'
            f'    <dt>Horizon</dt><dd>{r["horizon"]}</dd>'
            f'  </dl>'
            f'</div>'
        )
    recommendations_html = "\n".join(rec_blocks)

    # ── Vulnerability card (optional) ─────────────────────────────────────
    if m["vuln"]:
        v = m["vuln"]
        sev = v["by_severity"]
        vuln_top_rows = [
            [host, str(stats["CRITICAL"]), str(stats["HIGH"]),
             str(stats["MEDIUM"]), str(stats["LOW"])]
            for host, stats in v["top_hosts"]
        ] or [["(no findings)", "0", "0", "0", "0"]]
        top_cve_rows = [
            [cve, str(count)] for cve, count in v["top_cves"]
        ] or [["(no findings)", "0"]]

        vuln_card_html = f"""
  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#fee2e2">🩹</div>
      <h2>Vulnerability Posture</h2>
    </div>
    <div class="card-body">
      <p style="font-size:.88rem;color:var(--text2);margin-bottom:.75rem">
        {v['total_findings']:,} findings across {v['exposed_hosts']:,}
        host(s). <strong>{v['exploitable']:,}</strong> are flagged as
        actively exploited or with malware in the wild;
        <strong>{v['fix_available']:,}</strong> have vendor patches
        available today.
      </p>
      {html_table(['Severity','Count'],[
          ['Critical', str(sev['CRITICAL'])],
          ['High',     str(sev['HIGH'])],
          ['Medium',   str(sev['MEDIUM'])],
          ['Low',      str(sev['LOW'])],
      ])}
      <div class="two-col" style="margin-top:1rem">
        <div>
          <h3 style="font-size:.85rem;text-transform:uppercase;
                     color:var(--text3);letter-spacing:.5px;
                     margin-bottom:.5rem">Top hosts (Critical + High)</h3>
          {html_table(['Host','Critical','High','Medium','Low'], vuln_top_rows)}
        </div>
        <div>
          <h3 style="font-size:.85rem;text-transform:uppercase;
                     color:var(--text3);letter-spacing:.5px;
                     margin-bottom:.5rem">Most-prevalent CVEs</h3>
          {html_table(['CVE','Hosts affected'], top_cve_rows)}
        </div>
      </div>
    </div>
  </div>"""
    else:
        vuln_card_html = """
  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#fef3c7">🩹</div>
      <h2>Vulnerability Posture</h2>
    </div>
    <div class="card-body">
      <div class="callout">
        No vulnerability data found in <code>snapshots/</code>. Run
        <code>python3 generate_vuln_report.py</code> to populate this section
        on the next run of this report.
      </div>
    </div>
  </div>"""

    # ── Flows card ────────────────────────────────────────────────────────
    if m["flows_available"]:
        permitted_rejected = (
            f"<strong>{m['flow_permitted']:,}</strong> permitted &middot; "
            f"<strong>{m['flow_rejected']:,}</strong> rejected"
            if (m["flow_permitted"] + m["flow_rejected"]) > 0 else
            "Decision counts not available in this snapshot."
        )
        risky_rows = []
        if isinstance(m["risky_ports"], dict):
            for port, info in m["risky_ports"].items():
                if isinstance(info, dict):
                    sev = info.get("severity", "")
                    svc = info.get("service", "")
                    cnt = info.get("count", "")
                else:
                    sev, svc, cnt = "", str(info), ""
                risky_rows.append([str(port), str(svc), str(sev), str(cnt)])
        risky_table = (html_table(["Port", "Service", "Severity", "Count"],
                                  risky_rows)
                       if risky_rows else
                       '<div class="callout info" style="margin-top:.5rem">'
                       'No risky-port flows observed in the sample window.'
                       '</div>')
        flows_card_html = f"""
  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#e0f2fe">🌊</div>
      <h2>East-West Traffic &amp; Risky Exposures</h2>
    </div>
    <div class="card-body">
      <p style="font-size:.88rem;color:var(--text2);margin-bottom:.75rem">
        {m['flow_total']:,} flow(s) observed in the snapshot window:
        {permitted_rejected}.
      </p>
      {risky_table}
    </div>
  </div>"""
    else:
        flows_card_html = """
  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#fef3c7">🌊</div>
      <h2>East-West Traffic &amp; Risky Exposures</h2>
    </div>
    <div class="card-body">
      <div class="callout">
        Flow data was not available in this snapshot (the cluster may not
        yet be receiving NetFlow-style telemetry, or the snapshot was run
        with <code>--skip-flows</code>). Re-run
        <code>cluster_snapshot.py</code> without that flag to populate.
      </div>
    </div>
  </div>"""

    # ── Sources card ──────────────────────────────────────────────────────
    src_rows = [
        ["Snapshot",            str(header_info.get("snapshot_path", "—"))],
    ]
    for label, key in [
        ("Vulnerability CSV",   "vuln_csv"),
        ("Conversations JSON",  "conversations"),
        ("Policies JSON",       "policies"),
        ("Flows CSV",           "flows_csv"),
        ("Forensics report",    "forensics_html"),
        ("Forensics config",    "forensics_cfg"),
        ("Flow analysis",       "flow_analysis"),
        ("Policy/workload report", "policy_workload"),
    ]:
        path = companions.get(key)
        src_rows.append(
            [label,
             f"<code>{path}</code>" if path
             else html_pill("not found", "gray")]
        )
    sources_card_html = f"""
  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#f1f5f9">📂</div>
      <h2>Data Sources &amp; Methodology</h2>
    </div>
    <div class="card-body">
      <p style="font-size:.88rem;color:var(--text2);margin-bottom:.75rem">
      This executive summary was assembled from the following artefacts.
      Missing items did not cause failure — corresponding sections were
      either skipped or annotated with a "Run X" call-out.
      </p>
      {html_table(["Artefact", "Path"], src_rows)}
    </div>
  </div>"""

    return HTML_TEMPLATE.format(
        cluster=m["cluster"],
        snapshot_ts=m["snapshot_ts"],
        snapshot_path=str(header_info.get("snapshot_path", "—")),
        root_scope=m["root_scope"],
        prepared_for=header_info.get("prepared_for", "Customer"),
        prepared_by=header_info.get("prepared_by", "CSW POV Team"),
        generated=header_info.get("generated"),
        tldr_html=tldr,
        kpi_strip_html="\n".join(kpi_cells),
        posture_cards_html="\n".join(posture_cards),
        coverage_table_html=coverage_table_html,
        segmentation_table_html=segmentation_table_html,
        recommendations_html=recommendations_html,
        vuln_card_html=vuln_card_html,
        flows_card_html=flows_card_html,
        sources_card_html=sources_card_html,
    )


# ──────────────────────────────────────────────────────────────────────────
# 7. Markdown renderer
# ──────────────────────────────────────────────────────────────────────────

def render_markdown(metrics: dict, snapshot: dict, companions: dict,
                    recommendations: list[dict], header_info: dict) -> str:
    m = metrics
    lines: list[str] = []

    lines.append(f"# CSW Executive Security Posture Summary")
    lines.append("")
    lines.append(f"**Prepared for:** {header_info.get('prepared_for')}  ")
    lines.append(f"**Prepared by:** {header_info.get('prepared_by')}  ")
    lines.append(f"**Cluster:** {m['cluster']}  ")
    lines.append(f"**Root scope:** {m['root_scope']}  ")
    lines.append(f"**Snapshot:** {m['snapshot_ts']}  ")
    lines.append(f"**Generated:** {header_info.get('generated')}  ")
    lines.append(f"**Source snapshot:** `{header_info.get('snapshot_path')}`")
    lines.append("")

    # TL;DR
    lines.append("## Executive summary")
    lines.append("")
    crit = sum(1 for r in recommendations if r["priority"] == "Critical")
    high = sum(1 for r in recommendations if r["priority"] == "High")
    lines.append(
        f"Across **{m['total_agents']}** instrumented workloads in "
        f"**{m['total_workspaces']}** workspaces, "
        f"**{m['enforcement_pct']:.0f}%** are under active enforcement and "
        f"**{m['visibility_pct']:.0f}%** are under full visibility. "
        f"Blast-radius score: **{m['blast_radius_score']}/100**. "
        f"This report identifies **{crit}** Critical and **{high}** "
        f"High-priority action(s)."
    )
    lines.append("")

    # Headline KPIs
    lines.append("## Headline indicators")
    lines.append("")
    lines.append("| Indicator | Value |")
    lines.append("|---|---|")
    lines.append(f"| Workloads with agents | {m['total_agents']} |")
    lines.append(f"| Enforcement coverage | {m['enforcement_pct']:.0f}% "
                 f"({m['enforced_count']}/{m['total_agents']}) |")
    lines.append(f"| Visibility coverage | {m['visibility_pct']:.0f}% |")
    lines.append(f"| Blast-radius score | {m['blast_radius_score']} / 100 |")
    lines.append(f"| Policy maturity | {m['policy_maturity']:.0f} / 100 |")
    lines.append(f"| Workspaces | {m['total_workspaces']} "
                 f"({m['enforcing_ws']} enforcing) |")
    lines.append(f"| Total policies | {m['total_policies']} |")
    lines.append(f"| Insecure-cipher hosts | {m['insecure_hosts']} |")
    if m["vuln"]:
        v = m["vuln"]
        lines.append(f"| Critical CVEs | {v['by_severity']['CRITICAL']} |")
        lines.append(f"| High CVEs | {v['by_severity']['HIGH']} |")
        lines.append(f"| Exploitable findings (CVM) | {v['exploitable']} |")
    lines.append("")

    # Recommendations
    lines.append("## Prioritized recommendations")
    lines.append("")
    for i, r in enumerate(recommendations, 1):
        lines.append(f"### {i}. [{r['priority']}] {r['title']}")
        lines.append("")
        lines.append(f"**Why it matters:** {r['business_impact']}")
        lines.append("")
        lines.append(f"**Action:** {r['action']}")
        lines.append("")
        lines.append(f"**Owner:** {r['owner']}  ")
        lines.append(f"**Horizon:** {r['horizon']}")
        lines.append("")

    # Coverage detail
    lines.append("## Visibility & enforcement detail")
    lines.append("")
    lines.append("| Indicator | Value |")
    lines.append("|---|---|")
    lines.append(f"| Package visibility | {m['pkg_vis']} "
                 f"({safe_pct(m['pkg_vis'], m['total_agents']):.0f}%) |")
    lines.append(f"| Process visibility | {m['proc_vis']} "
                 f"({safe_pct(m['proc_vis'], m['total_agents']):.0f}%) |")
    lines.append(f"| Forensics enabled | {m['forensics_on']} "
                 f"({m['forensics_pct']:.0f}%) |")
    lines.append(f"| Enforcement enabled | {m['enforced_count']} "
                 f"({m['enforcement_pct']:.0f}%) |")
    lines.append(f"| Healthy agents | {m['health_pct']:.0f}% |")
    lines.append(f"| Insecure-cipher hosts | {m['insecure_hosts']} |")
    lines.append("")

    # Vulnerability section (optional)
    if m["vuln"]:
        v = m["vuln"]
        lines.append("## Vulnerability posture")
        lines.append("")
        lines.append(f"- Total findings: **{v['total_findings']:,}** across "
                     f"**{v['exposed_hosts']:,}** host(s)")
        lines.append(f"- Critical: **{v['by_severity']['CRITICAL']}**, "
                     f"High: **{v['by_severity']['HIGH']}**, "
                     f"Medium: **{v['by_severity']['MEDIUM']}**, "
                     f"Low: **{v['by_severity']['LOW']}**")
        lines.append(f"- Exploitable in the wild (CVM): "
                     f"**{v['exploitable']:,}**")
        lines.append(f"- Fix available from vendor: **{v['fix_available']:,}**")
        lines.append("")
        lines.append("### Top hosts (Critical + High)")
        lines.append("")
        lines.append("| Host | Critical | High | Medium | Low |")
        lines.append("|---|---:|---:|---:|---:|")
        if v["top_hosts"]:
            for host, stats in v["top_hosts"]:
                lines.append(f"| {host} | {stats['CRITICAL']} "
                             f"| {stats['HIGH']} | {stats['MEDIUM']} "
                             f"| {stats['LOW']} |")
        else:
            lines.append("| (no findings) | 0 | 0 | 0 | 0 |")
        lines.append("")
        if v["top_cves"]:
            lines.append("### Most-prevalent CVEs")
            lines.append("")
            lines.append("| CVE | Hosts affected |")
            lines.append("|---|---:|")
            for cve, count in v["top_cves"]:
                lines.append(f"| {cve} | {count} |")
            lines.append("")
    else:
        lines.append("## Vulnerability posture")
        lines.append("")
        lines.append("> No vulnerability CSV found. Run "
                     "`python3 generate_vuln_report.py` to populate this "
                     "section on the next run.")
        lines.append("")

    # Flow section
    if m["flows_available"]:
        lines.append("## East-west traffic & risky exposures")
        lines.append("")
        lines.append(f"- Flows in sample: **{m['flow_total']:,}** "
                     f"(permitted: {m['flow_permitted']:,}, "
                     f"rejected: {m['flow_rejected']:,})")
        if isinstance(m["risky_ports"], dict) and m["risky_ports"]:
            lines.append("- High-risk service ports observed:")
            for port, info in m["risky_ports"].items():
                if isinstance(info, dict):
                    sev = info.get("severity", "")
                    svc = info.get("service", "")
                    cnt = info.get("count", "")
                    lines.append(f"  - **{port}** ({svc}, {sev}) — {cnt}")
                else:
                    lines.append(f"  - **{port}** — {info}")
        else:
            lines.append("- No high-risk port flows observed in this window.")
        lines.append("")

    # Data sources
    lines.append("## Data sources")
    lines.append("")
    lines.append(f"- Cluster snapshot: `{header_info.get('snapshot_path')}`")
    for label, key in [
        ("Vulnerability CSV",      "vuln_csv"),
        ("Conversations JSON",     "conversations"),
        ("Policies JSON",          "policies"),
        ("Flows CSV",              "flows_csv"),
        ("Forensics posture HTML", "forensics_html"),
        ("Forensics config JSON",  "forensics_cfg"),
        ("Flow analysis HTML",     "flow_analysis"),
        ("Policy/workload report", "policy_workload"),
    ]:
        path = companions.get(key)
        lines.append(f"- {label}: " + (f"`{path}`" if path else "_not found_"))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Generated by `generate_executive_report.py`. "
                 "Trend month-over-month for the most useful narrative._")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────
# 8. CLI
# ──────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Generate a CISO-grade executive summary from a CSW "
                    "cluster snapshot plus optional companion reports."
    )
    src = ap.add_argument_group("Data source")
    src.add_argument("--snapshot",
                     help="Path to a cluster_snapshot JSON file. Skips live "
                          "API calls.")
    src.add_argument("--snapshot-latest", action="store_true",
                     help="Use the most recent snapshot in the snapshots dir.")
    src.add_argument("--refresh", action="store_true",
                     help="Force a fresh live snapshot even if one exists.")
    src.add_argument("--no-fetch-live", action="store_true",
                     help="Refuse to call the live API; error if no "
                          "snapshot is available locally.")
    src.add_argument("--skip-flows", action="store_true",
                     help="When generating a live snapshot, skip flow "
                          "collection (faster).")

    paths = ap.add_argument_group("Paths")
    paths.add_argument("--snapshots-dir", default="snapshots",
                       help="Where to look for snapshot-*.json and most "
                            "companion files. Default: snapshots/")
    paths.add_argument("--reports-dir", default="reports",
                       help="Where to write outputs and look for HTML "
                            "companions. Default: reports/")
    paths.add_argument("--out-html",
                       help="Override HTML output path.")
    paths.add_argument("--out-md",
                       help="Override Markdown output path.")
    paths.add_argument("--html-only", action="store_true",
                       help="Only write the HTML output.")
    paths.add_argument("--md-only", action="store_true",
                       help="Only write the Markdown output.")

    cover = ap.add_argument_group("Cover info")
    cover.add_argument("--prepared-for", default="Customer",
                       help="Customer/recipient name on the report cover.")
    cover.add_argument("--prepared-by", default="CSW POV Team",
                       help="Name of the SE/team producing the report.")

    args = ap.parse_args()

    # ── Load snapshot + companions ───────────────────────────────────────
    snapshot, snap_path = load_snapshot(args)
    snapshots_dir = Path(args.snapshots_dir)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    companions = find_companions(snapshots_dir, reports_dir)

    metrics = aggregate_metrics(snapshot, companions)
    recs = derive_recommendations(metrics, companions)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header_info = {
        "prepared_for": args.prepared_for,
        "prepared_by":  args.prepared_by,
        "generated":    generated,
        "snapshot_path": snap_path,
    }

    out_html = Path(args.out_html) if args.out_html else (
        reports_dir / f"executive-summary-{today}.html")
    out_md   = Path(args.out_md)   if args.out_md   else (
        reports_dir / f"executive-summary-{today}.md")

    # ── Render + write ────────────────────────────────────────────────────
    if not args.md_only:
        html = render_html(metrics, snapshot, companions, recs, header_info)
        out_html.write_text(html, encoding="utf-8")
        print(f"✅ HTML report:    {out_html}")

    if not args.html_only:
        md = render_markdown(metrics, snapshot, companions, recs, header_info)
        out_md.write_text(md, encoding="utf-8")
        print(f"✅ Markdown:       {out_md}")

    # Console summary so the SE knows what was produced
    print()
    print("─── Executive summary ─────────────────────────────────────────")
    print(f"Cluster:        {metrics['cluster']}")
    print(f"Workloads:      {metrics['total_agents']}")
    print(f"Enforcement:    {metrics['enforcement_pct']:.0f}% "
          f"({metrics['enforced_count']}/{metrics['total_agents']})")
    print(f"Visibility:     {metrics['visibility_pct']:.0f}%")
    print(f"Blast radius:   {metrics['blast_radius_score']}/100")
    crit = sum(1 for r in recs if r['priority'] == 'Critical')
    high = sum(1 for r in recs if r['priority'] == 'High')
    print(f"Recommendations: {crit} Critical, {high} High, "
          f"{len(recs)} total")
    print("───────────────────────────────────────────────────────────────")


if __name__ == "__main__":
    main()
