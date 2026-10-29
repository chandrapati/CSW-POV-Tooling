#!/usr/bin/env python3
"""
Quick summary: Probes every major OpenAPI endpoint group and writes a Markdown
capability matrix showing what this API key / cluster can actually do.

api_test_suite.py — CSW API Capability Test Suite

Tests every major CSW OpenAPI v1 endpoint group to determine which capabilities
are available and working on a given cluster/API key. Produces a detailed
Markdown report suitable for TAC submissions or POC documentation.

Usage:
    python3 api_test_suite.py
    python3 api_test_suite.py --output api-test-results-2026-04-06.md
    python3 api_test_suite.py --quick          # skip deep-dive tests
    python3 api_test_suite.py --category agents scopes policies

Credentials are read from .env (copy .env.example → .env and fill in values).

Key fixes vs. TME version (informed by ACME SaaS cluster testing):
  - Root scope is discovered dynamically before running inventory tests
  - Inventory search bodies do NOT include "offset" (breaks on some SaaS clusters)
  - Flow search uses epoch integer timestamps + scopeName + non-empty filter
  - (Note: "now-1h" string and empty "and" filter both fail on SaaS clusters)
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
API_SCRIPT  = os.path.join(SCRIPT_DIR, "csw_api.py")


# ──────────────────────────────────────────────────────────────
# API Helper
# ──────────────────────────────────────────────────────────────

def api(method, path, body=None):
    """Call ``csw_api.py`` with the given HTTP verb and path; return its JSON object.

    On non-JSON stdout (timeouts, tracebacks, empty output), returns a synthetic
    dict with ``status`` 0 so callers can treat it like a failed HTTP response.
    """
    cmd = [sys.executable, API_SCRIPT, method, path]
    if body:
        cmd.append(json.dumps(body))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"status": 0, "error": r.stderr.strip() or "No output", "data": None}


def load_dotenv():
    """Load ``KEY=value`` pairs from ``.env`` next to this script into ``os.environ``.

    Ignores comments and blank lines; supports optional ``export `` prefix.
    Uses ``setdefault`` so variables already set in the process environment win.
    """
    env_path = os.path.join(SCRIPT_DIR, ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:]
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def get_root_scope_name():
    """Dynamically discover the root scope name from the cluster."""
    r = api("GET", "/openapi/v1/app_scopes")
    data = r.get("data") or []
    scopes = data if isinstance(data, list) else []
    root = next((s for s in scopes if not s.get("parent_app_scope_id")), None)
    return root["name"] if root else "Default"


# ──────────────────────────────────────────────────────────────
# Test Definitions
# ──────────────────────────────────────────────────────────────

STATUS_OK   = "✅ OK"
STATUS_FAIL = "❌ FAIL"
STATUS_WARN = "⚠️ WARN"
STATUS_SKIP = "⏭ SKIP"


def run_test(label, method, path, body=None, expect_status=200, data_check=None):
    """Execute one API test and return a result dict."""
    r      = api(method, path, body)
    status = r.get("status", 0)
    data   = r.get("data")
    error  = r.get("error", "")

    if status == expect_status:
        outcome = STATUS_OK
        note    = ""
        if data_check:
            try:
                result, note = data_check(data)
                outcome = STATUS_OK if result else STATUS_WARN
            except Exception as e:
                outcome = STATUS_WARN
                note    = str(e)
    elif status in (401, 403):
        outcome = STATUS_FAIL
        note    = f"HTTP {status} — API key missing required capability or unauthorized"
    elif status == 404:
        outcome = STATUS_FAIL
        note    = f"HTTP 404 — endpoint not available on this cluster/version"
    elif status == 400:
        # WARN (not FAIL): SaaS often returns 400 for unsupported body shapes; scope POST expects 400.
        outcome = STATUS_WARN
        err_msg = (data or {}).get("error", "") if isinstance(data, dict) else ""
        note    = f"HTTP 400 — Bad Request: {err_msg or str(data)[:100]}"
    elif status == 0:
        outcome = STATUS_FAIL
        note    = f"Connection error: {error}"
    else:
        outcome = STATUS_FAIL
        note    = f"HTTP {status}: {error}"

    return {
        "label":   label,
        "method":  method,
        "path":    path,
        "status":  status,
        "outcome": outcome,
        "note":    note,
        "data":    data,
    }


def count_check(min_count=1):
    """Verify the response is a non-empty list."""
    def check(data):
        lst = data if isinstance(data, list) else (data or {}).get("results", [])
        if isinstance(lst, list) and len(lst) >= min_count:
            return True, f"{len(lst)} item(s) returned"
        return False, f"Expected ≥{min_count} items, got: {type(data).__name__}"
    return check


def field_check(*fields):
    """Verify the response object contains specific keys."""
    def check(data):
        obj = data[0] if isinstance(data, list) and data else data
        if not obj or not isinstance(obj, dict):
            return False, "No data object to inspect"
        missing = [f for f in fields if f not in obj]
        if missing:
            return False, f"Missing fields: {missing}"
        return True, f"Fields present: {list(fields)}"
    return check


# ──────────────────────────────────────────────────────────────
# Test Categories
# ──────────────────────────────────────────────────────────────

def tests_agents():
    """Sensor inventory and read access checks for ``/openapi/v1/sensors``."""
    return [
        run_test("List all sensors/agents",       "GET", "/openapi/v1/sensors",   data_check=count_check(1)),
        run_test("Sensor management permission",  "GET", "/openapi/v1/sensors"),
    ]


def tests_scopes():
    """App scope listing plus a deliberate bad POST to distinguish 403 vs 400."""
    return [
        run_test("List app scopes", "GET", "/openapi/v1/app_scopes", data_check=count_check(1)),
        # Scope write check — expect 400 (bad body), not 403 (no permission)
        run_test("Scope write permission check", "POST", "/openapi/v1/app_scopes",
                 body={"__test__": True}, expect_status=400),
    ]


def tests_inventory(root_scope_name="Default"):
    """Inventory search tests.

    IMPORTANT: Do NOT include 'offset' in the request body — it causes HTTP 400
    on SaaS clusters (offset must be absent, not set to 0).
    Use the dynamically discovered root scope name, not the hardcoded "Default".
    """
    broad_filter = {"type": "and", "filters": [{"type": "subnet", "field": "ip", "value": "0.0.0.0/0"}]}
    return [
        run_test(
            f"Inventory search — broad filter (scope: {root_scope_name})",
            "POST", "/openapi/v1/inventory/search",
            body={"filter": broad_filter, "scopeName": root_scope_name, "limit": 5},
            data_check=field_check("results"),
        ),
        run_test(
            "Inventory search — Windows OS filter",
            "POST", "/openapi/v1/inventory/search",
            body={"filter": {"type": "contains", "field": "os", "value": "Windows"},
                  "scopeName": root_scope_name, "limit": 5},
        ),
        run_test(
            "Inventory search — packages dimension",
            "POST", "/openapi/v1/inventory/search",
            body={"filter": broad_filter, "scopeName": root_scope_name,
                  "limit": 3, "dimensions": ["packages"]},
        ),
        run_test(
            "Inventory search — listening_ports dimension",
            "POST", "/openapi/v1/inventory/search",
            body={"filter": broad_filter, "scopeName": root_scope_name,
                  "limit": 3, "dimensions": ["listening_ports"]},
        ),
        run_test(
            "Inventory search — vuln_severity dimension",
            "POST", "/openapi/v1/inventory/search",
            body={"filter": broad_filter, "scopeName": root_scope_name,
                  "limit": 3, "dimensions": ["vuln_severity"]},
        ),
    ]


def tests_workspaces(quick=False):
    """Applications (workspaces) list; in full mode, drills into first app details/policies."""
    results = [
        run_test("List workspaces (applications)", "GET", "/openapi/v1/applications", data_check=count_check(1)),
    ]
    if not quick:
        r = api("GET", "/openapi/v1/applications")
        apps = r.get("data", []) or []
        if isinstance(apps, list) and apps:
            # One representative workspace keeps the suite fast; swap index manually if needed.
            app_id   = apps[0]["id"]
            app_name = apps[0].get("name", app_id)
            results.append(run_test(
                f"Workspace details ({app_name})",
                "GET", f"/openapi/v1/applications/{app_id}/details",
            ))
            results.append(run_test(
                f"Workspace policies ({app_name})",
                "GET", f"/openapi/v1/applications/{app_id}/policies",
                data_check=field_check("default_policies"),
            ))
    return results


def tests_flow_search(root_scope_name="Default"):
    """Flow search tests.

    IMPORTANT fixes based on ACME SaaS cluster testing:
      1. Use epoch integer timestamps, NOT "now-1h" strings (causes HTTP 400)
      2. Always supply scopeName (required field on SaaS)
      3. Filter must be non-empty — empty 'and' clause causes HTTP 400
      4. Use 'src_address' field for subnet match on flows (not 'src_ip' or 'ip')
    """
    t1 = int(time.time())
    t0 = t1 - 86400  # last 24 hours

    return [
        run_test(
            "Flow search — last 24h (subnet filter)",
            "POST", "/openapi/v1/flowsearch",
            body={"t0": t0, "t1": t1,
                  "filter": {"type": "subnet", "field": "src_address", "value": "0.0.0.0/0"},
                  "scopeName": root_scope_name, "limit": 10},
        ),
        run_test(
            "Flow search — HTTPS flows only",
            "POST", "/openapi/v1/flowsearch",
            body={"t0": t0, "t1": t1,
                  "filter": {"type": "eq", "field": "dst_port", "value": 443},
                  "scopeName": root_scope_name, "limit": 10},
        ),
        run_test(
            "Flow search — policy rejected flows",
            "POST", "/openapi/v1/flowsearch",
            body={"t0": t0, "t1": t1,
                  "filter": {"type": "eq", "field": "fwd_policy_rejected", "value": "REJECTED"},
                  "scopeName": root_scope_name, "limit": 10},
        ),
    ]


def tests_vulnerabilities():
    """CVE/vuln read endpoints and the direct packages listing (may differ from inventory)."""
    return [
        run_test("Vulnerabilities list",       "GET", "/openapi/v1/vulnerabilities"),
        run_test("CVEs list",                  "GET", "/openapi/v1/cves"),
        run_test("Vulnerability filters",      "GET", "/openapi/v1/vulnerability_filters"),
        run_test("Software packages (direct)", "GET", "/openapi/v1/packages"),
    ]


def tests_forensics():
    """Forensics sub-resources and alerts; availability often gated by capability/SaaS."""
    return [
        run_test("Forensics events",       "GET", "/openapi/v1/forensics/events"),
        run_test("Forensics process_info", "GET", "/openapi/v1/forensics/process_info"),
        run_test("Forensics file_events",  "GET", "/openapi/v1/forensics/file_events"),
        run_test("Forensics net_events",   "GET", "/openapi/v1/forensics/network_events"),
        run_test("Alerts",                 "GET", "/openapi/v1/alerts"),
    ]


def tests_users_roles():
    """Directory-style reads for users and roles."""
    return [
        run_test("List users", "GET", "/openapi/v1/users", data_check=count_check(1)),
        run_test("List roles", "GET", "/openapi/v1/roles"),
    ]


def tests_connectors():
    """Integrations: connectors, orchestrators, and external orchestrator targets."""
    return [
        run_test("List connectors",    "GET", "/openapi/v1/connectors"),
        run_test("List orchestrators", "GET", "/openapi/v1/orchestrators"),
        run_test("External targets",   "GET", "/openapi/v1/ext_orchestrators"),
    ]


def tests_cluster():
    """Cluster health, nodes, dashboard-style metrics, and agent stats (often on-prem only)."""
    return [
        run_test("Cluster status",    "GET", "/openapi/v1/cluster/status"),
        run_test("Cluster nodes",     "GET", "/openapi/v1/cluster/nodes"),
        run_test("Dashboard metrics", "GET", "/openapi/v1/dashboard"),
        run_test("Agent stats",       "GET", "/openapi/v1/agents/stats"),
    ]


def tests_enforcement():
    """Enforcement configuration and high-level network policy reads."""
    return [
        run_test("Enforcement status", "GET", "/openapi/v1/enforcement_config"),
        run_test("Network policy",     "GET", "/openapi/v1/network_policy"),
    ]


# Category registry — order determines report order
ALL_CATEGORIES = {
    "agents":          ("Agents / Sensors",          None),
    "scopes":          ("Scopes",                     None),
    "inventory":       ("Inventory & Labels",         None),
    "workspaces":      ("Workspaces & Policies",      None),
    "flow":            ("Flow Search",                None),
    "vulnerabilities": ("Vulnerabilities / CVEs",     None),
    "forensics":       ("Forensics & Alerts",         None),
    "users":           ("Users & Roles",              None),
    "connectors":      ("Connectors & Orchestrators", None),
    "cluster":         ("Cluster / Dashboard",        None),
    "enforcement":     ("Enforcement Config",         None),
}


# ──────────────────────────────────────────────────────────────
# Report Renderer
# ──────────────────────────────────────────────────────────────

def render_report(all_results, cluster, ts, quick, root_scope_name):
    """Build Markdown: per-category tables, counts, and heuristic TAC hints for failures."""
    lines = []
    def h(level, text): lines.append(f"{'#' * level} {text}")
    def ln(*args):      lines.append(" ".join(str(a) for a in args))
    def br():           lines.append("")

    h(1, f"CSW API Capability Test Report — {cluster}")
    ln(f"**Date:** {ts}")
    ln(f"**Mode:** {'Quick (subset of tests)' if quick else 'Full test suite'}")
    ln(f"**Root scope detected:** `{root_scope_name}`")
    br()

    total = sum(len(v) for v in all_results.values())
    ok    = sum(1 for tests in all_results.values() for t in tests if t["outcome"] == STATUS_OK)
    fail  = sum(1 for tests in all_results.values() for t in tests if t["outcome"] == STATUS_FAIL)
    warn  = sum(1 for tests in all_results.values() for t in tests if t["outcome"] == STATUS_WARN)

    h(2, "Summary")
    ln("| Result | Count |")
    ln("|---|---|")
    ln(f"| {STATUS_OK} | {ok} |")
    ln(f"| {STATUS_WARN} | {warn} |")
    ln(f"| {STATUS_FAIL} | {fail} |")
    ln(f"| **Total tests** | **{total}** |")
    br()

    for cat_key, (cat_label, _) in ALL_CATEGORIES.items():
        tests = all_results.get(cat_key, [])
        if not tests:
            continue
        cat_ok   = sum(1 for t in tests if t["outcome"] == STATUS_OK)
        cat_fail = sum(1 for t in tests if t["outcome"] == STATUS_FAIL)
        icon = "✅" if cat_fail == 0 else ("⚠️" if cat_ok > 0 else "❌")

        h(2, f"{icon} {cat_label}")
        ln("| Test | Method | Path | Status | Notes |")
        ln("|---|---|---|---|---|")
        for t in tests:
            ln(f"| {t['label']} | `{t['method']}` | `{t['path']}` | {t['outcome']} | {t['note']} |")
        br()

    # Heuristic hints only — same path can fail for different reasons across clusters.
    failed_paths = {t["path"] for tests in all_results.values() for t in tests if t["outcome"] == STATUS_FAIL}
    if failed_paths:
        h(2, "Failures Requiring Investigation")
        ln("| Path | Likely Cause | Suggested Action |")
        ln("|---|---|---|")
        for path in sorted(failed_paths):
            if "/vulnerabilities" in path or "/cves" in path:
                cause  = "Data served via internal CVM — not exposed via public OpenAPI"
                action = "Contact TAC for data export options or use CVM API directly"
            elif "/forensics" in path:
                cause  = "Forensics data not exposed via public OpenAPI v1"
                action = "Enable data_export capability or use SIEM integration"
            elif "/packages" in path or "/ports" in path:
                cause  = "Deep visibility data not exposed via public OpenAPI v1"
                action = "Use inventory search with 'dimensions' field instead"
            elif "/dashboard" in path or "/stats" in path:
                cause  = "UI-only aggregations — no API equivalent on SaaS"
                action = "Use inventory search for workload counts"
            elif "/cluster" in path:
                cause  = "On-prem only — not available on SaaS clusters"
                action = "Skip for SaaS; available on dedicated Tetration appliances"
            elif any(t["status"] in (401, 403) for tests in all_results.values() for t in tests if t["path"] == path):
                # Any 401/403 on this path wins over generic "unavailable" messaging.
                cause  = "API key missing required capability"
                action = "Add capability in CSW UI → API Keys → Edit"
            else:
                cause  = "Endpoint unavailable on this cluster version"
                action = "Review CSW release notes or open a TAC case"
            ln(f"| `{path}` | {cause} | {action} |")
        br()

    ln("---")
    ln(f"_Report generated by `api_test_suite.py` (v2.0) on {ts}_")
    br()
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

def main():
    """Parse CLI, discover root scope, run selected categories, emit Markdown report."""
    load_dotenv()

    parser = argparse.ArgumentParser(description="CSW API Capability Test Suite")
    parser.add_argument("--output",       default=None, help="Write report to this file (default: stdout)")
    parser.add_argument("--quick",        action="store_true", help="Skip deep/slow tests")
    parser.add_argument("--category",     nargs="+", choices=list(ALL_CATEGORIES.keys()),
                        help=f"Run only specific categories: {', '.join(ALL_CATEGORIES.keys())}")
    args = parser.parse_args()

    # Show host (and optional port) only — full URL with path/query is rarely useful in reports.
    cluster = os.environ.get("CSW_API_URL", "unknown").replace("https://", "").split("/")[0]
    ts      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"🧪 CSW API Test Suite", file=sys.stderr)
    print(f"   Cluster : {cluster}", file=sys.stderr)
    print(f"   Mode    : {'Quick' if args.quick else 'Full'}", file=sys.stderr)

    # Discover root scope before running tests
    print(f"   Discovering root scope...", file=sys.stderr, end="", flush=True)
    root_scope_name = get_root_scope_name()
    print(f" '{root_scope_name}'", file=sys.stderr)
    print("", file=sys.stderr)

    categories = args.category or list(ALL_CATEGORIES.keys())
    print(f"   Running: {', '.join(categories)}", file=sys.stderr)
    print("", file=sys.stderr)

    all_results = {}
    for cat_key in categories:
        cat_label, _ = ALL_CATEGORIES[cat_key]
        print(f"  [{cat_key}] {cat_label}...", file=sys.stderr, end="", flush=True)

        if cat_key == "agents":
            results = tests_agents()
        elif cat_key == "scopes":
            results = tests_scopes()
        elif cat_key == "inventory":
            results = tests_inventory(root_scope_name)
        elif cat_key == "workspaces":
            results = tests_workspaces(quick=args.quick)
        elif cat_key == "flow":
            results = tests_flow_search(root_scope_name)
        elif cat_key == "vulnerabilities":
            results = tests_vulnerabilities()
        elif cat_key == "forensics":
            results = tests_forensics()
        elif cat_key == "users":
            results = tests_users_roles()
        elif cat_key == "connectors":
            results = tests_connectors()
        elif cat_key == "cluster":
            results = tests_cluster()
        elif cat_key == "enforcement":
            results = tests_enforcement()
        else:
            results = []

        all_results[cat_key] = results
        ok   = sum(1 for t in results if t["outcome"] == STATUS_OK)
        fail = sum(1 for t in results if t["outcome"] == STATUS_FAIL)
        print(f" {ok}/{len(results)} passed", file=sys.stderr)

    print("", file=sys.stderr)

    report = render_report(all_results, cluster, ts, args.quick, root_scope_name)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"✅ Report written to: {args.output}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
