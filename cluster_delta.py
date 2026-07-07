#!/usr/bin/env python3
"""
cluster_delta.py — CSW Cluster Change Detection Tool

Compares two JSON snapshots produced by cluster_snapshot.py and generates
a Markdown change report highlighting additions, removals, and metric changes.

Usage:
    python3 cluster_delta.py snapshots/snapshot-2026-04-06.json snapshots/snapshot-2026-04-13.json
    python3 cluster_delta.py --latest                   # auto-picks the two most recent snapshots
    python3 cluster_delta.py --latest --output my-delta.md

Snapshots are produced by:
    python3 cluster_snapshot.py
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone


# ──────────────────────────────────────────────────────────────
# Loader
# ──────────────────────────────────────────────────────────────

def load_snapshot(path):
    """Load a cluster snapshot JSON file and return its parsed object."""
    with open(path) as f:
        return json.load(f)


def find_latest_two(snapshot_dir="snapshots"):
    """Return paths to the second-newest and newest snapshot files in ``snapshot_dir``.

    Filenames are sorted lexicographically; ``snapshot-YYYY-MM-DD.json`` names
    therefore yield chronological order, so the last two entries are the pair
    to diff as baseline (older) and current (newer).
    """
    files = sorted(glob.glob(os.path.join(snapshot_dir, "snapshot-*.json")))
    if len(files) < 2:
        print(f"Error: Need at least 2 snapshot files in '{snapshot_dir}/'.", file=sys.stderr)
        print("       Run 'python3 cluster_snapshot.py' to generate snapshots.", file=sys.stderr)
        sys.exit(1)
    return files[-2], files[-1]


# ──────────────────────────────────────────────────────────────
# Delta Helpers
# ──────────────────────────────────────────────────────────────

def diff_sets(old_set, new_set, label):
    """Return ``(added, removed)`` as set differences: items only in *new* vs only in *old*.

    ``label`` is reserved for callers that may want to annotate logging or UI;
    it is not used in the computation.
    """
    added   = new_set - old_set
    removed = old_set - new_set
    return added, removed


def metric_delta(old_val, new_val):
    """Format a scalar for Markdown: unchanged, or new value with direction and delta text."""
    if old_val == new_val:
        return f"{new_val} _(no change)_"
    diff = new_val - old_val
    arrow = "⬆️" if diff > 0 else "⬇️"
    return f"{new_val} {arrow} _(was {old_val}, Δ {diff:+d})_"


def flatten_scope_names(tree_nodes):
    """Collect every scope ``short`` name from a nested ``tree`` (parent/children lists).

    Set comparison on these names matches how the snapshot represents scopes
    for add/remove detection, independent of tree depth or ordering.
    """
    names = set()
    def walk(nodes):
        for n in nodes:
            names.add(n["short"])
            if n.get("children"):
                walk(n["children"])
    walk(tree_nodes)
    return names


# ──────────────────────────────────────────────────────────────
# Report Generator
# ──────────────────────────────────────────────────────────────

def generate_delta(old_snap, new_snap):
    """Build the full Markdown report string from baseline and current snapshot dicts.

    Expects the same top-level keys as ``cluster_snapshot.py`` output:
    ``timestamp``, ``cluster``, ``sensors``, ``scopes``, ``workspaces``, and
    optionally ``_raw`` for per-sensor hostname detail in the agent section.
    """
    lines = []
    def h(level, text): lines.append(f"{'#' * level} {text}")
    def ln(*args):      lines.append(" ".join(str(a) for a in args))
    def br():           lines.append("")

    old_ts  = old_snap.get("timestamp", "unknown")
    new_ts  = new_snap.get("timestamp", "unknown")
    cluster = new_snap.get("cluster", "unknown")
    now_s   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    h(1, f"CSW Cluster Change Report — {cluster}")
    ln(f"**Report Generated:** {now_s}")
    ln(f"**Baseline Snapshot:** {old_ts}")
    ln(f"**Current Snapshot:**  {new_ts}")
    br()

    old_sa = old_snap["sensors"]
    new_sa = new_snap["sensors"]
    old_sc = old_snap["scopes"]
    new_sc = new_snap["scopes"]
    old_ws = old_snap["workspaces"]
    new_ws = new_snap["workspaces"]

    # ── Change summary table ──────────────────────────────────
    h(2, "Change Summary")
    ln("| Area | Previous | Current | Delta |")
    ln("|---|---|---|---|")
    ln(f"| **Total Agents** | {old_sa['total']} | {new_sa['total']} | {new_sa['total'] - old_sa['total']:+d} |")
    ln(f"| **Enforcement On** | {old_sa['enforcement']['count']} | {new_sa['enforcement']['count']} | {new_sa['enforcement']['count'] - old_sa['enforcement']['count']:+d} |")
    ln(f"| **Insecure Cipher** | {len(old_sa['insecure'])} | {len(new_sa['insecure'])} | {len(new_sa['insecure']) - len(old_sa['insecure']):+d} |")
    ln(f"| **Total Scopes** | {old_sc['total']} | {new_sc['total']} | {new_sc['total'] - old_sc['total']:+d} |")
    ln(f"| **Total Workspaces** | {old_ws['total']} | {new_ws['total']} | {new_ws['total'] - old_ws['total']:+d} |")
    ln(f"| **Total Policies** | {old_ws['grand_policy_total']} | {new_ws['grand_policy_total']} | {new_ws['grand_policy_total'] - old_ws['grand_policy_total']:+d} |")
    br()

    # ── Agents ────────────────────────────────────────────────
    h(2, "Agent Changes")

    # Aggregated ``sensors`` counts can move without listing hosts; host sets need ``_raw``.
    old_hosts = set()
    new_hosts = set()
    if "_raw" in old_snap:
        old_hosts = {s.get("host_name", "") for s in old_snap["_raw"].get("sensors", [])}
    if "_raw" in new_snap:
        new_hosts = {s.get("host_name", "") for s in new_snap["_raw"].get("sensors", [])}

    added_hosts   = new_hosts - old_hosts
    removed_hosts = old_hosts - new_hosts

    # If both totals match and hostnames are unchanged, treat agent inventory as stable.
    if not added_hosts and not removed_hosts and old_sa["total"] == new_sa["total"]:
        ln("_No agent additions or removals detected._")
    else:
        if added_hosts:
            h(3, f"🆕 New Agents (+{len(added_hosts)})")
            ln("| Hostname | Details |")
            ln("|---|---|")
            for hostname in sorted(added_hosts):
                sensor = next((s for s in new_snap["_raw"].get("sensors", []) if s.get("host_name") == hostname), {})
                # Omit loopback so the table shows routable addresses only.
                ips = [i["ip"] for i in sensor.get("interfaces", []) if i.get("ip") and not i["ip"].startswith(("127.", "::"))]
                cipher = "⚠️ insecure" if sensor.get("insecure_cipher") else "OK"
                ln(f"| `{hostname}` | IP: {', '.join(ips)} \\| Cipher: {cipher} |")
            br()

        if removed_hosts:
            h(3, f"❌ Removed Agents (-{len(removed_hosts)})")
            for hostname in sorted(removed_hosts):
                ln(f"- `{hostname}`")
            br()

    # Insecure cipher change
    old_insecure_hosts = {s["host"] for s in old_sa["insecure"]}
    new_insecure_hosts = {s["host"] for s in new_sa["insecure"]}
    remediated = old_insecure_hosts - new_insecure_hosts
    new_flagged = new_insecure_hosts - old_insecure_hosts

    if remediated or new_flagged:
        h(3, "TLS Cipher Suite Changes")
        if remediated:
            ln(f"**✅ Remediated ({len(remediated)}):** Hosts that resolved the insecure cipher issue:")
            for h_name in sorted(remediated):
                ln(f"  - `{h_name}`")
            br()
        if new_flagged:
            ln(f"**⚠️ Newly Flagged ({len(new_flagged)}):** Hosts now showing insecure_cipher:")
            for h_name in sorted(new_flagged):
                ln(f"  - `{h_name}`")
            br()
    else:
        ln(f"_Insecure cipher count unchanged: {len(old_sa['insecure'])} host(s)._")
    br()

    # Enforcement change
    old_enf = set(old_sa["enforcement"]["hosts"])
    new_enf = set(new_sa["enforcement"]["hosts"])
    enf_added   = new_enf - old_enf
    enf_removed = old_enf - new_enf
    if enf_added or enf_removed:
        h(3, "Enforcement Changes")
        if enf_added:
            ln(f"**🟢 Enforcement ENABLED on ({len(enf_added)}):**")
            for h_name in sorted(enf_added):
                ln(f"  - `{h_name}`")
        if enf_removed:
            ln(f"**🔴 Enforcement DISABLED on ({len(enf_removed)}):**")
            for h_name in sorted(enf_removed):
                ln(f"  - `{h_name}`")
        br()

    # ── Scopes ────────────────────────────────────────────────
    h(2, "Scope Changes")

    old_scope_names = flatten_scope_names(old_sc["tree"])
    new_scope_names = flatten_scope_names(new_sc["tree"])
    added_scopes   = new_scope_names - old_scope_names
    removed_scopes = old_scope_names - new_scope_names

    if not added_scopes and not removed_scopes:
        ln(f"_No scope additions or removals. Total: {new_sc['total']}_")
    else:
        if added_scopes:
            h(3, f"🆕 New Scopes (+{len(added_scopes)})")
            for name in sorted(added_scopes):
                ln(f"- `{name}`")
            br()
        if removed_scopes:
            h(3, f"❌ Removed Scopes (-{len(removed_scopes)})")
            for name in sorted(removed_scopes):
                ln(f"- `{name}`")
            br()
    br()

    # ── Workspaces / Policies ─────────────────────────────────
    h(2, "Workspace & Policy Changes")

    old_ws_map = {w["name"]: w for w in old_ws["workspaces"]}
    new_ws_map = {w["name"]: w for w in new_ws["workspaces"]}
    old_ws_names = set(old_ws_map.keys())
    new_ws_names = set(new_ws_map.keys())
    added_ws   = new_ws_names - old_ws_names
    removed_ws = old_ws_names - new_ws_names
    common_ws  = old_ws_names & new_ws_names

    if added_ws:
        h(3, f"🆕 New Workspaces (+{len(added_ws)})")
        for name in sorted(added_ws):
            w = new_ws_map[name]
            ln(f"- `{name}` — {w['policy_count']} policies, enforcing={w['enforcing']}")
        br()

    if removed_ws:
        h(3, f"❌ Removed Workspaces (-{len(removed_ws)})")
        for name in sorted(removed_ws):
            ln(f"- `{name}`")
        br()

    if common_ws:
        h(3, "Policy Count Changes (existing workspaces)")
        changed = False
        ln("| Workspace | Previous Policies | Current Policies | Delta |")
        ln("|---|---|---|---|")
        for name in sorted(common_ws):
            old_w = old_ws_map[name]
            new_w = new_ws_map[name]
            diff  = new_w["policy_count"] - old_w["policy_count"]
            marker = f" _{'+' if diff > 0 else ''}{diff}_" if diff != 0 else " _(no change)_"
            if diff != 0:
                changed = True
            ln(f"| `{name}` | {old_w['policy_count']} | {new_w['policy_count']} | {marker} |")
        # Table is always emitted; extra blank line separates the "no changes" note when every row matched.
        if not changed:
            br()
            ln("_No policy count changes in existing workspaces._")
        br()

    # ── Footer ────────────────────────────────────────────────
    h(2, "Recommendations")
    recs = []
    if len(new_sa["insecure"]) > 0:
        recs.append(f"🔴 Remediate remaining **{len(new_sa['insecure'])} insecure cipher hosts** — apply TLS GPO or registry fix.")
    if new_sa["enforcement"]["count"] == 0:
        recs.append("🟡 Enforcement is **not active** on any host — review policies before enabling.")
    if enf_added:
        recs.append(f"✅ Enforcement was enabled on {len(enf_added)} host(s) this period — monitor for drops.")
    if added_scopes:
        recs.append(f"🆕 {len(added_scopes)} new scope(s) added — confirm label queries are correctly populated.")
    if added_hosts:
        recs.append(f"🆕 {len(added_hosts)} new agent(s) enrolled — ensure correct scope membership.")
    if not recs:
        recs.append("_No urgent recommendations. Continue monitoring._")

    for rec in recs:
        ln(f"- {rec}")
    br()

    ln("---")
    ln(f"_Report generated by `cluster_delta.py` on {now_s}_")
    br()

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

def main():
    """Parse CLI args, load two snapshots, emit Markdown to stdout or ``--output``."""
    parser = argparse.ArgumentParser(description="CSW Cluster Change Detection Tool")
    parser.add_argument("baseline", nargs="?", help="Path to older (baseline) snapshot JSON")
    parser.add_argument("current",  nargs="?", help="Path to newer (current) snapshot JSON")
    parser.add_argument("--latest",     action="store_true", help="Auto-select the two most recent snapshots")
    parser.add_argument("--output",     default=None, help="Output file path (default: stdout)")
    parser.add_argument("--snapshot-dir", default="snapshots", help="Directory to search for snapshots")
    args = parser.parse_args()

    if args.latest:
        baseline_path, current_path = find_latest_two(args.snapshot_dir)
    elif args.baseline and args.current:
        baseline_path = args.baseline
        current_path  = args.current
    else:
        parser.print_help()
        print("\nError: Provide two snapshot files or use --latest", file=sys.stderr)
        sys.exit(1)

    print(f"Baseline : {baseline_path}", file=sys.stderr)
    print(f"Current  : {current_path}", file=sys.stderr)

    old_snap = load_snapshot(baseline_path)
    new_snap = load_snapshot(current_path)

    report = generate_delta(old_snap, new_snap)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"✅ Delta report written to: {args.output}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
