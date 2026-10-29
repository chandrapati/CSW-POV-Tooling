#!/usr/bin/env python3
"""
Quick summary: Captures a full point-in-time cluster snapshot (agents, scopes,
workspaces, policies, 24h flow sample) as JSON + Markdown. The baseline for deltas
and every downstream report.

cluster_snapshot.py — CSW Cluster Full Snapshot Tool

Connects to a Cisco Secure Workload cluster and generates:
  1. A JSON snapshot file (snapshots/snapshot-YYYY-MM-DD.json)
  2. A Markdown report    (snapshots/snapshot-YYYY-MM-DD.md)

Usage:
    python3 cluster_snapshot.py
    python3 cluster_snapshot.py --output-dir ./my-snapshots
    python3 cluster_snapshot.py --json-only
    python3 cluster_snapshot.py --md-only

Credentials are read from .env (copy .env.example → .env and fill in values).

Key fixes vs. original TME version (informed by ACME SaaS cluster testing):
  - Root scope is discovered dynamically instead of hardcoded to "Default"
  - Inventory search bodies do NOT include "offset" (breaks on some SaaS clusters)
  - Flow search uses epoch integer timestamps + scopeName (not "now-1h" strings)
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
API_SCRIPT  = os.path.join(SCRIPT_DIR, "csw_api.py")

RISKY_PORTS = {
    3389: ("CRITICAL", "RDP"), 22: ("CRITICAL", "SSH"),
    23: ("CRITICAL", "Telnet"), 445: ("CRITICAL", "SMB"),
    3306: ("CRITICAL", "MySQL"), 1433: ("CRITICAL", "MSSQL"),
    1521: ("CRITICAL", "Oracle"), 5432: ("CRITICAL", "PostgreSQL"),
    20: ("HIGH", "FTP-data"), 21: ("HIGH", "FTP"),
    139: ("HIGH", "NetBIOS"), 25: ("HIGH", "SMTP"),
}


def api(method, path, body=None):
    """Call csw_api.py and return parsed JSON result."""
    cmd = [sys.executable, API_SCRIPT, method, path]
    if body:
        cmd.append(json.dumps(body))
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"status": 0, "error": r.stderr.strip() or "No output", "data": None}


def safe_list(r):
    """Extract a list from an API result, gracefully handling errors."""
    data = r.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "items", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def get_cluster_label():
    """Derive a cluster identifier from the CSW_API_URL environment variable."""
    url = os.environ.get("CSW_API_URL", "")
    if url:
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        return host
    return "unknown-cluster"


# ──────────────────────────────────────────────────────────────
# Data Collection
# ──────────────────────────────────────────────────────────────

def collect_sensors():
    """Return all CSW agents (sensors) from the cluster.

    Handles both list-shaped responses and dict payloads where rows live under
    ``data.results`` (varies by API version / deployment).
    """
    r = api("GET", "/openapi/v1/sensors")
    sensors = safe_list(r)
    if not sensors:
        data = r.get("data") or {}
        if isinstance(data, dict):
            sensors = data.get("results", [])
    return sensors


def collect_scopes():
    """Return all application scopes (segmentation boundaries) as a flat list."""
    r = api("GET", "/openapi/v1/app_scopes")
    return safe_list(r)


def collect_workspaces():
    """Return all workspaces (applications) that hold policies and segmentation context."""
    r = api("GET", "/openapi/v1/applications")
    return safe_list(r)


def collect_policies(app_id):
    """Fetch policy rows for one workspace, split into absolute vs default policy lists."""
    r = api("GET", f"/openapi/v1/applications/{app_id}/policies")
    data = r.get("data") or {}
    abs_p = data.get("absolute_policies", []) or []
    def_p = data.get("default_policies", []) or []
    return abs_p, def_p


def get_root_scope_name(scopes):
    """Return the name of the root (top-level) scope, or 'Default' as fallback."""
    root = next((s for s in scopes if not s.get("parent_app_scope_id")), None)
    return root["name"] if root else "Default"


def collect_inventory_sample(scope_name, limit=20):
    """Pull a small inventory sample — no 'offset' param (breaks on SaaS clusters)."""
    body = {
        "filter":    {"type": "and", "filters": [{"type": "subnet", "field": "ip", "value": "0.0.0.0/0"}]},
        "scopeName": scope_name,
        "limit":     limit,
    }
    r = api("POST", "/openapi/v1/inventory/search", body)
    data = r.get("data") or {}
    if isinstance(data, dict):
        return data.get("results", [])
    return []


def collect_flow_sample(scope_name, limit=20):
    """Pull a small flow sample for the last 24 hours.
    Uses epoch integer timestamps (required by SaaS clusters).
    Filter must be non-empty — uses a broad subnet match.
    """
    import time
    t1 = int(time.time())
    t0 = t1 - 86400
    body = {
        "t0":        t0,
        "t1":        t1,
        "filter":    {"type": "subnet", "field": "src_address", "value": "0.0.0.0/0"},
        "scopeName": scope_name,
        "limit":     limit,
    }
    r = api("POST", "/openapi/v1/flowsearch", body)
    data = r.get("data") or {}
    if isinstance(data, dict):
        return data.get("results", []), r.get("status", 0)
    return [], r.get("status", 0)


# ──────────────────────────────────────────────────────────────
# Analysis Helpers
# ──────────────────────────────────────────────────────────────

def analyse_sensors(sensors):
    """Aggregate sensor fields into counts, host lists, and health summaries for reporting."""
    versions    = {}
    os_years    = {}
    insecure    = []
    enforcement = []
    pkg         = []
    proc        = []
    forensics   = []
    health_ok   = 0
    health_warn = []

    for s in sensors:
        v = s.get("current_sw_version", "unknown")
        versions[v] = versions.get(v, 0) + 1

        hostname = s.get("host_name", "")
        # Heuristic only: hostname tokens like "16"/"19" often imply Windows build year; not OS telemetry.
        for yr in ["16", "19", "22", "12"]:
            if yr in hostname:
                label = f"Win 20{yr}"
                os_years[label] = os_years.get(label, 0) + 1
                break

        if s.get("insecure_cipher"):
            ifaces = s.get("interfaces") or []
            ips = [i.get("ip") for i in ifaces if i.get("ip") and not i["ip"].startswith(("127.", "::"))]
            insecure.append({"host": hostname, "ips": ips})

        if s.get("enforcement_enabled"):
            enforcement.append(hostname)
        if s.get("enable_package_visibility"):
            pkg.append(hostname)
        if s.get("enable_process_visibility"):
            proc.append(hostname)
        if s.get("enable_forensics"):
            forensics.append(hostname)

        h = s.get("health")
        if str(h) == "active":  # normalize: API may return non-string enum values
            health_ok += 1
        else:
            health_warn.append({"host": hostname, "health": h})

    return {
        "total":       len(sensors),
        "versions":    versions,
        "os_years":    os_years,
        "enforcement": {"count": len(enforcement), "hosts": enforcement},
        "pkg_vis":     {"count": len(pkg)},
        "proc_vis":    {"count": len(proc)},
        "forensics":   {"count": len(forensics)},
        "insecure":    insecure,
        "health_ok":   health_ok,
        "health_warn": health_warn,
    }


def analyse_scopes(scopes):
    """Build a nested scope tree from flat ``app_scopes`` rows (parent id links).

    Each node carries display ``short`` (last ``:`` segment of full name) and
    depth for reporting; roots have no ``parent_app_scope_id``.
    """
    id2scope = {s["id"]: s for s in scopes}
    roots    = [s for s in scopes if not s.get("parent_app_scope_id")]

    def build_tree(sid, depth=0):
        s = id2scope.get(sid)
        if not s:
            return []
        node = {
            "id":       sid,
            "name":     s.get("name", ""),
            "short":    s.get("name", "").split(":")[-1],
            "depth":    depth,
            "children": [],
        }
        children = [x for x in scopes if x.get("parent_app_scope_id") == sid]
        for c in sorted(children, key=lambda x: x.get("name", "")):
            node["children"].extend(build_tree(c["id"], depth + 1))
        # Single-element list so ``extend(build_tree(...))`` at the parent stays uniform.
        return [node]

    tree = []
    for rs in roots:
        tree.extend(build_tree(rs["id"]))

    return {"total": len(scopes), "tree": tree}


def analyse_workspaces(workspaces):
    """Per-workspace policy counts and flags; issues one policies GET per workspace."""
    results     = []
    grand_total = 0
    for app in workspaces:
        abs_p, def_p = collect_policies(app["id"])
        total         = len(abs_p) + len(def_p)
        grand_total  += total
        results.append({
            "id":           app["id"],
            "name":         app["name"],
            "primary":      app.get("primary", False),
            "enforcing":    app.get("enforcement_enabled", False),
            "policy_count": total,
            "absolute":     len(abs_p),
            "default":      len(def_p),
        })
    return {"total": len(workspaces), "grand_policy_total": grand_total, "workspaces": results}


def analyse_flows(flows):
    """Summarise a flow sample: protocol breakdown, top services, policy verdicts."""
    from collections import Counter
    if not flows:
        return {"available": False, "total_sample": 0}

    proto_ctr   = Counter((f.get("proto") or "?") for f in flows)
    svc_ctr     = Counter((f.get("service_name") or "unknown") for f in flows if f.get("service_name"))
    port_ctr    = Counter(f.get("dst_port", 0) for f in flows)
    permitted   = sum(1 for f in flows if (f.get("fwd_policy_permitted") or "") == "PERMITTED")
    rejected    = sum(1 for f in flows if (f.get("fwd_policy_rejected")  or "") == "REJECTED")

    risky_detected = {}
    for p, cnt in port_ctr.items():
        p_int = int(p) if isinstance(p, str) else p  # flow payloads may stringify ports
        if p_int in RISKY_PORTS:
            risky_detected[p_int] = cnt

    return {
        "available":      True,
        "total_sample":   len(flows),
        "protocols":      dict(proto_ctr.most_common()),
        "top_services":   dict(svc_ctr.most_common(10)),
        "top_ports":      dict(port_ctr.most_common(10)),
        "permitted":      permitted,
        "rejected":       rejected,
        "risky_ports":    risky_detected,
    }


# ──────────────────────────────────────────────────────────────
# Markdown Report Generator
# ──────────────────────────────────────────────────────────────

def render_markdown(snapshot):
    """Turn the in-memory snapshot dict into a human-readable Markdown report string."""
    ts      = snapshot["timestamp"]
    cluster = snapshot["cluster"]
    sa      = snapshot["sensors"]
    sc      = snapshot["scopes"]
    ws      = snapshot["workspaces"]
    fl      = snapshot.get("flows", {})

    lines = []
    def h(level, text):  lines.append(f"{'#' * level} {text}")
    def ln(*args):       lines.append(" ".join(str(a) for a in args))
    def br():            lines.append("")

    h(1, f"CSW Cluster Snapshot — {cluster}")
    ln(f"**Timestamp:** {ts}")
    ln(f"**Script:** cluster_snapshot.py v2.0")
    br()

    # ── Overview table ──────────────────────────────────────
    h(2, "Overview")
    ln("| Metric | Value |")
    ln("|---|---|")
    ln(f"| Cluster | `{cluster}` |")
    ln(f"| Total Agents | {sa['total']} |")
    ln(f"| Enforcement Active | {sa['enforcement']['count']}/{sa['total']} |")
    ln(f"| Total Scopes | {sc['total']} |")
    ln(f"| Total Workspaces | {ws['total']} |")
    ln(f"| Total Policies | {ws['grand_policy_total']} |")
    ln(f"| Insecure Cipher Hosts | {len(sa['insecure'])} |")
    if fl.get("available"):
        ln(f"| Flow Sample (24h) | {fl['total_sample']} flows · {fl['permitted']} permitted · {fl['rejected']} rejected |")
    br()

    # ── Agents ──────────────────────────────────────────────
    h(2, "Agents / Sensors")
    ln(f"**Total:** {sa['total']}")
    br()
    ln("| Feature | Enabled |")
    ln("|---|---|")
    ln(f"| Package Visibility  | {sa['pkg_vis']['count']}/{sa['total']} |")
    ln(f"| Process Visibility  | {sa['proc_vis']['count']}/{sa['total']} |")
    ln(f"| Forensics           | {sa['forensics']['count']}/{sa['total']} |")
    ln(f"| Enforcement         | {sa['enforcement']['count']}/{sa['total']} |")
    ln(f"| Healthy (active)    | {sa['health_ok']}/{sa['total']} |")
    br()

    if sa.get("versions"):
        ln("**Agent Versions:**")
        for v, cnt in sa["versions"].items():
            ln(f"- `{v}` — {cnt} host(s)")
        br()

    if sa.get("os_years"):
        ln("**OS Distribution (inferred from hostname):**")
        for os_y, cnt in sorted(sa["os_years"].items()):
            ln(f"- {os_y}: {cnt} host(s)")
        br()

    if sa["insecure"]:
        h(3, f"⚠️ Insecure Cipher Hosts ({len(sa['insecure'])})")
        ln("These hosts have been flagged with `insecure_cipher: true`.")
        ln("Remediation: apply TLS cipher hardening via GPO or registry.")
        br()
        ln("| Hostname | IP Addresses |")
        ln("|---|---|")
        for s in sa["insecure"]:
            ln(f"| `{s['host']}` | {', '.join(s['ips'])} |")
        br()

    if sa["health_warn"]:
        h(3, "⚠️ Agent Health Issues")
        for h_item in sa["health_warn"]:
            ln(f"- `{h_item['host']}` → health: `{h_item['health']}`")
        br()

    if sa["enforcement"]["hosts"]:
        h(3, "✅ Enforcement-Enabled Hosts")
        for host in sa["enforcement"]["hosts"]:
            ln(f"- `{host}`")
        br()

    # ── Scopes ──────────────────────────────────────────────
    h(2, "Scope Hierarchy")
    ln(f"**Total Scopes:** {sc['total']}")
    br()

    ln("```")
    def print_tree_text(nodes, acc, prefix=""):
        for i, node in enumerate(nodes):
            is_last   = (i == len(nodes) - 1)
            connector = "└─ " if is_last else "├─ "
            acc.append(prefix + connector + node["short"])
            child_prefix = prefix + ("   " if is_last else "│  ")
            if node.get("children"):
                print_tree_text(node["children"], acc, child_prefix)

    tree_lines = []
    for root_node in sc["tree"]:
        tree_lines.append(f"📂 {root_node['short']}")
        print_tree_text(root_node.get("children", []), tree_lines, "   ")
    lines.extend(tree_lines)
    ln("```")
    br()

    # ── Workspaces / Policies ────────────────────────────────
    h(2, "Workspaces & Policies")
    ln(f"**Total workspaces:** {ws['total']}  |  **Total policies:** {ws['grand_policy_total']}")
    br()
    ln("| Workspace | Policies | Absolute | Default | Primary | Enforcing |")
    ln("|---|---|---|---|---|---|")
    for w in ws["workspaces"]:
        prim = "✅" if w["primary"] else "—"
        enf  = "🟢 ON" if w["enforcing"] else "🔴 OFF"
        ln(f"| `{w['name']}` | {w['policy_count']} | {w['absolute']} | {w['default']} | {prim} | {enf} |")
    br()

    # ── Flow Summary (if available) ──────────────────────────
    if fl.get("available"):
        h(2, "Flow Analysis (24-hour sample)")
        ln(f"**Sample size:** {fl['total_sample']} flows")
        ln(f"**Policy verdicts:** {fl['permitted']} permitted · {fl['rejected']} rejected")
        br()
        if fl.get("top_services"):
            ln("**Top Application Services:**")
            for svc, cnt in list(fl["top_services"].items())[:8]:
                ln(f"- {svc}: {cnt}")
            br()
        if fl.get("protocols"):
            ln("**Protocols:**")
            for proto, cnt in fl["protocols"].items():
                ln(f"- {proto}: {cnt}")
            br()
        if fl.get("top_ports"):
            ln("**Top Destination Ports:**")
            for port, cnt in list(fl["top_ports"].items())[:8]:
                p_int = int(port) if isinstance(port, str) else port
                risk_info = RISKY_PORTS.get(p_int)
                flag = f" ⚠️ **{risk_info[0]}** ({risk_info[1]})" if risk_info else ""
                ln(f"- :{port} — {cnt} flows{flag}")
            br()

        risky = fl.get("risky_ports", {})
        if risky:
            h(3, f"⚠️ High-Risk Ports Detected ({len(risky)} ports)")
            ln("The following ports are commonly targeted for brute-force attacks, data exfiltration, and ransomware:")
            br()
            ln("| Port | Service | Severity | Flows |")
            ln("|---|---|---|---|")
            for port in sorted(risky, key=lambda x: -risky[x]):
                p_int = int(port) if isinstance(port, str) else port
                sev, svc = RISKY_PORTS.get(p_int, ("?", "?"))
                ln(f"| {port} | {svc} | {sev} | {risky[port]} |")
            br()

    # ── Footer ───────────────────────────────────────────────
    h(2, "Notes")
    ln("- Snapshot generated by `cluster_snapshot.py` (v2.0)")
    ln("- Raw JSON data saved alongside this file for delta comparison")
    ln("- Run `cluster_delta.py` to compare two snapshots over time")
    ln("- Run `api_test_suite.py` to validate full API key capabilities")
    ln("- Next recommended snapshot: _(schedule weekly or after major changes)_")
    br()

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

def main():
    """Load env, collect cluster data, write JSON and/or Markdown under ``--output-dir``."""
    parser = argparse.ArgumentParser(description="CSW Cluster Snapshot Tool")
    parser.add_argument("--output-dir", default="snapshots", help="Directory to write snapshot files")
    parser.add_argument("--json-only",  action="store_true", help="Only write the JSON snapshot")
    parser.add_argument("--md-only",    action="store_true", help="Only write the Markdown report")
    parser.add_argument("--skip-flows", action="store_true", help="Skip flow search (if capability not enabled)")
    args = parser.parse_args()

    # Load .env
    env_path = os.path.join(SCRIPT_DIR, ".env")
    if os.path.isfile(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[7:]
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

    cluster = get_cluster_label()
    now     = datetime.now(timezone.utc)
    date_s  = now.strftime("%Y-%m-%d")
    ts_s    = now.strftime("%Y-%m-%dT%H:%M:%S UTC")

    print(f"📡 Connecting to: {cluster}")
    print(f"📅 Snapshot date: {date_s}\n")

    print("  [1/5] Collecting agents...", end="", flush=True)
    sensors = collect_sensors()
    print(f" {len(sensors)} found")

    print("  [2/5] Collecting scopes...", end="", flush=True)
    scopes = collect_scopes()
    print(f" {len(scopes)} found")

    root_scope_name = get_root_scope_name(scopes)
    print(f"         Root scope: '{root_scope_name}'")

    print("  [3/5] Collecting workspaces & policies...", end="", flush=True)
    workspaces = collect_workspaces()
    print(f" {len(workspaces)} found")

    print("  [4/5] Collecting inventory sample...", end="", flush=True)
    inv_sample = collect_inventory_sample(root_scope_name, limit=50)
    print(f" {len(inv_sample)} workloads sampled")

    fl_data = {}
    if not args.skip_flows:
        print("  [5/5] Collecting flow sample (24h)...", end="", flush=True)
        flows, flow_status = collect_flow_sample(root_scope_name, limit=100)
        # Non-200 usually means missing API key capability (e.g. flow_inventory_query), not an empty result set.
        if flow_status == 200:
            fl_data = analyse_flows(flows)
            print(f" {len(flows)} flows · {fl_data['permitted']} permitted · {fl_data['rejected']} rejected")
        else:
            print(f" HTTP {flow_status} — skipped (add flow_inventory_query capability to API key)")
            fl_data = {"available": False, "http_status": flow_status}
    else:
        print("  [5/5] Flow collection skipped (--skip-flows)")

    print("\n  Analysing data...", end="", flush=True)
    sa = analyse_sensors(sensors)
    sc = analyse_scopes(scopes)
    ws = analyse_workspaces(workspaces)
    print(" done\n")

    snapshot = {
        "timestamp":      ts_s,
        "cluster":        cluster,
        "root_scope":     root_scope_name,
        "sensors":        sa,
        "scopes":         sc,
        "workspaces":     ws,
        "flows":          fl_data,
        "_raw": {
            "sensors":    sensors,
            "scopes":     scopes,
            "workspaces": workspaces,
            "inv_sample": inv_sample,
        },
    }

    os.makedirs(args.output_dir, exist_ok=True)
    base = os.path.join(args.output_dir, f"snapshot-{date_s}")

    if not args.md_only:
        json_path = f"{base}.json"
        with open(json_path, "w") as f:
            json.dump(snapshot, f, indent=2)
        print(f"✅ JSON snapshot: {json_path}")

    if not args.json_only:
        md = render_markdown(snapshot)
        md_path = f"{base}.md"
        with open(md_path, "w") as f:
            f.write(md)
        print(f"✅ Markdown report: {md_path}")

    print()
    print("Summary:")
    print(f"  Agents          : {sa['total']}")
    print(f"  Insecure cipher : {len(sa['insecure'])}")
    print(f"  Enforcement     : {sa['enforcement']['count']}/{sa['total']}")
    print(f"  Scopes          : {sc['total']}")
    print(f"  Workspaces      : {ws['total']}")
    print(f"  Total policies  : {ws['grand_policy_total']}")
    if fl_data.get("available"):
        print(f"  Flows (24h)     : {fl_data['total_sample']} sampled · {fl_data['permitted']} permitted · {fl_data['rejected']} rejected")
        risky = fl_data.get("risky_ports", {})
        if risky:
            print(f"  ⚠️  Risky ports  : {len(risky)} detected ({sum(risky.values())} flows)")


if __name__ == "__main__":
    main()
