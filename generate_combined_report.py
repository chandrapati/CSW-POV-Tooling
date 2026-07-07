#!/usr/bin/env python3
"""
generate_combined_report.py — CSW Snapshot + Delta → Combined HTML Report
--------------------------------------------------------------------------
Reads two JSON snapshots (baseline + current) and generates a single
self-contained HTML report showing current cluster state AND change delta.

Usage:
    python3 generate_combined_report.py
    python3 generate_combined_report.py --baseline snapshots/snapshot-2026-04-07.json --current snapshots/snapshot-2026-04-09.json
    python3 generate_combined_report.py --latest
"""

import json
import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter


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


def find_latest_two(directory="snapshots"):
    """Return paths to the two newest ``snapshot-*.json`` files in *directory*.

    Files are ordered lexicographically (ISO date prefixes sort correctly).
    The tuple is ``(older, newer)`` — second-to-last and last in that order.
    ``(None, None)`` if the directory is missing or has fewer than two matches.
    """
    p = Path(directory)
    if not p.exists():
        return None, None
    jsons = sorted(p.glob("snapshot-*.json"))
    if len(jsons) < 2:
        return None, None
    return str(jsons[-2]), str(jsons[-1])


def flatten_scope_names(tree_nodes):
    """Collect unique scope labels from a nested ``tree`` list (snapshot ``scopes``).

    Each node contributes ``short`` if present, else ``name``; children are
    walked recursively so additions/removals can be compared as sets.
    """
    names = set()
    def walk(nodes):
        for n in nodes:
            names.add(n.get("short", n.get("name", "")))
            if n.get("children"):
                walk(n["children"])
    walk(tree_nodes)
    return names


def render_scope_tree_html(nodes, depth=0):
    """Render *nodes* as nested flex rows with tree connectors (no delta logic)."""
    html = ""
    for i, node in enumerate(nodes):
        name = node.get("short", node.get("name", ""))
        is_last = i == len(nodes) - 1
        indent = depth * 24
        icon = "📂" if node.get("children") else "📄"
        connector_color = "#cbd5e1"
        html += f'<div style="display:flex;align-items:center;padding:3px 0;margin-left:{indent}px">'
        if depth > 0:
            html += f'<span style="color:{connector_color};margin-right:6px;font-size:0.8rem">{"└─" if is_last else "├─"}</span>'
        html += f'<span style="margin-right:5px;font-size:0.85rem">{icon}</span>'
        html += f'<span style="font-size:0.82rem;color:#1e293b">{name}</span>'
        html += '</div>'
        if node.get("children"):
            html += render_scope_tree_html(node["children"], depth + 1)
    return html


def render(old_snap, new_snap):
    """Build the full self-contained HTML document for *new_snap* vs *old_snap*.

    Computes set- and numeric-based deltas, narrative change blocks, KPI styling,
    tables, and optional sections (e.g. flows) from the current snapshot only.
    """
    cluster = new_snap.get("cluster", "Unknown")
    new_ts = new_snap.get("timestamp", "Unknown")
    old_ts = old_snap.get("timestamp", "Unknown")
    root = new_snap.get("root_scope", cluster)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sa = new_snap.get("sensors", {})
    old_sa = old_snap.get("sensors", {})
    sc = new_snap.get("scopes", {})
    old_sc = old_snap.get("scopes", {})
    ws = new_snap.get("workspaces", {})
    old_ws = old_snap.get("workspaces", {})
    fl = new_snap.get("flows", {})

    total_agents = sa.get("total", 0)
    old_total_agents = old_sa.get("total", 0)
    enforced = sa.get("enforcement", {}).get("count", 0)
    old_enforced = old_sa.get("enforcement", {}).get("count", 0)
    insecure = sa.get("insecure", [])
    old_insecure = old_sa.get("insecure", [])
    health_warn = sa.get("health_warn", [])
    total_scopes = sc.get("total", 0)
    old_total_scopes = old_sc.get("total", 0)
    total_ws = ws.get("total", 0)
    old_total_ws = old_ws.get("total", 0)
    total_policies = ws.get("grand_policy_total", 0)
    old_total_policies = old_ws.get("grand_policy_total", 0)
    ws_list = ws.get("workspaces", [])
    old_ws_list = old_ws.get("workspaces", [])
    versions = sa.get("versions", {})
    os_years = sa.get("os_years", {})
    pkg_vis = sa.get("pkg_vis", {}).get("count", 0)
    proc_vis = sa.get("proc_vis", {}).get("count", 0)
    forensics_cnt = sa.get("forensics", {}).get("count", 0)
    # If the snapshot omits explicit healthy count, assume all agents are healthy.
    health_ok = sa.get("health_ok", total_agents)

    flow_total = fl.get("total_sample", 0)
    permitted = fl.get("permitted", 0)
    rejected = fl.get("rejected", 0)
    top_svcs = fl.get("top_services", {})
    top_ports = fl.get("top_ports", {})
    protocols = fl.get("protocols", {})

    # Numeric deltas: simple current minus baseline for headline KPIs and tables.
    agent_delta = total_agents - old_total_agents
    insecure_delta = len(insecure) - len(old_insecure)
    scope_delta = total_scopes - old_total_scopes
    ws_delta = total_ws - old_total_ws
    policy_delta = total_policies - old_total_policies
    enforced_delta = enforced - old_enforced

    # Host identity sets: list length can move for reasons other than add/remove
    # (e.g. same host dropping off the insecure list); set diff captures true churn.
    old_insecure_hosts = {h["host"] for h in old_insecure}
    new_insecure_hosts = {h["host"] for h in insecure}
    remediated_hosts = old_insecure_hosts - new_insecure_hosts
    new_flagged_hosts = new_insecure_hosts - old_insecure_hosts

    # Agent changes
    old_hosts = set()
    new_hosts = set()
    if "_raw" in old_snap:
        old_hosts = {s.get("host_name", "") for s in old_snap["_raw"].get("sensors", [])}
    if "_raw" in new_snap:
        new_hosts = {s.get("host_name", "") for s in new_snap["_raw"].get("sensors", [])}
    added_hosts = new_hosts - old_hosts
    removed_hosts = old_hosts - new_hosts

    # Scope changes
    old_scope_names = flatten_scope_names(old_sc.get("tree", []))
    new_scope_names = flatten_scope_names(sc.get("tree", []))
    added_scopes = new_scope_names - old_scope_names
    removed_scopes = old_scope_names - new_scope_names

    # Workspace policy changes
    old_ws_map = {w["name"]: w for w in old_ws_list}
    new_ws_map = {w["name"]: w for w in ws_list}
    added_ws = set(new_ws_map.keys()) - set(old_ws_map.keys())
    removed_ws_names = set(old_ws_map.keys()) - set(new_ws_map.keys())
    common_ws = set(old_ws_map.keys()) & set(new_ws_map.keys())

    # Enforcement changes
    old_enf_hosts = set(old_sa.get("enforcement", {}).get("hosts", []))
    new_enf_hosts = set(sa.get("enforcement", {}).get("hosts", []))
    enf_added = new_enf_hosts - old_enf_hosts
    enf_removed = old_enf_hosts - new_enf_hosts

    def delta_badge(val, color="blue"):
        if val == 0:
            return '<span style="color:#64748b;font-size:0.75rem">no change</span>'
        sign = "+" if val > 0 else ""
        # Default: up is green / down is red (inventory-style). color=="red"
        # inverts that for "bad when it goes up" metrics (e.g. insecure cipher count).
        c = "#059669" if val < 0 and color == "red" else "#dc2626" if val > 0 and color == "red" else "#059669" if val > 0 else "#dc2626"
        return f'<span style="color:{c};font-weight:700;font-size:0.85rem">{sign}{val}</span>'

    def kpi_delta_html(val):
        if val == 0:
            return ""
        sign = "+" if val > 0 else ""
        # KPI strip uses one convention: positive delta green, negative red
        # (even where the delta table uses delta_badge(..., "red") for insecure).
        color = "#059669" if val > 0 else "#dc2626"
        return f'<div style="font-size:0.72rem;color:{color};margin-top:2px;font-weight:600">{sign}{val}</div>'

    # Insecure cipher table rows
    cipher_rows = ""
    for h in insecure:
        ips = ", ".join(h.get("ips", []))
        cipher_rows += f"""<tr>
            <td><code>{h["host"]}</code></td>
            <td><code>{ips}</code></td>
            <td><span style="background:#fee2e2;color:#991b1b;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">Insecure</span></td>
        </tr>"""

    # Workspace table rows
    ws_rows = ""
    for w in ws_list:
        enf = w.get("enforcing", False)
        enf_html = '<span style="background:#d1fae5;color:#065f46;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">ON</span>' if enf else '<span style="background:#fee2e2;color:#991b1b;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">OFF</span>'
        primary = '<span style="background:#dbeafe;color:#1e40af;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">Primary</span>' if w.get("primary") else '<span style="background:#f1f5f9;color:#475569;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">Alt</span>'
        old_w = old_ws_map.get(w["name"])
        p_delta = ""
        if old_w:
            diff = w.get("policy_count", 0) - old_w.get("policy_count", 0)
            if diff != 0:
                sign = "+" if diff > 0 else ""
                color = "#059669" if diff > 0 else "#dc2626"
                p_delta = f' <span style="color:{color};font-weight:700;font-size:0.78rem">({sign}{diff})</span>'
        elif w["name"] in added_ws:
            p_delta = ' <span style="color:#059669;font-weight:700;font-size:0.78rem">NEW</span>'

        ws_rows += f"""<tr>
            <td><code>{w.get("name","?")}</code></td>
            <td>{w.get("policy_count", 0)}{p_delta}</td>
            <td>{w.get("absolute", 0)}</td>
            <td>{w.get("default", 0)}</td>
            <td>{primary}</td>
            <td>{enf_html}</td>
        </tr>"""

    # OS distribution bars
    os_bars = ""
    total_os = sum(os_years.values()) or 1
    os_colours = {"Win 2016": "#94a3b8", "Win 2019": "#3b82f6", "Win 2022": "#0284c7"}
    for name, count in sorted(os_years.items()):
        pct = count / total_os * 100
        col = os_colours.get(name, "#64748b")
        os_bars += f"""<div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <span style="width:80px;font-size:0.8rem;color:#475569">{name}</span>
          <div style="flex:1;background:#e2e8f0;border-radius:4px;height:14px;overflow:hidden">
            <div style="width:{pct:.0f}%;background:{col};height:100%;border-radius:4px"></div>
          </div>
          <span style="width:70px;font-size:0.8rem;font-weight:600;color:#0f172a">{count} ({pct:.0f}%)</span>
        </div>"""

    # Version rows
    ver_rows = ""
    for v, c in versions.items():
        ver_rows += f'<tr><td><code>{v}</code></td><td><span style="background:#e0f2fe;color:#0369a1;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">{c} hosts</span></td></tr>'

    # Scope tree
    scope_tree_html = render_scope_tree_html(sc.get("tree", []))

    # Flow service rows
    svc_rows = ""
    for svc, cnt in sorted(top_svcs.items(), key=lambda x: -x[1]):
        svc_rows += f"<tr><td>{svc}</td><td style='font-weight:600'>{cnt}</td></tr>"

    port_rows = ""
    risky_in_flows = {}
    for p, cnt in sorted(top_ports.items(), key=lambda x: -x[1])[:10]:
        risk_info = RISKY_PORTS.get(str(p))
        if risk_info:
            sev, _desc = risk_info
            bg, fg = ("#fee2e2", "#991b1b") if sev == "CRITICAL" else ("#fef3c7", "#92400e")
            sev_badge = f' <span style="background:{bg};color:{fg};padding:2px 8px;border-radius:99px;font-size:0.69rem;font-weight:600">{sev}</span>'
            risky_in_flows[p] = cnt
        else:
            sev_badge = ""
        port_rows += f"<tr><td>:{p}{sev_badge}</td><td style='font-weight:600'>{cnt}</td></tr>"

    proto_rows = ""
    for p, cnt in sorted(protocols.items(), key=lambda x: -x[1]):
        proto_rows += f"<tr><td>{p}</td><td><span style='background:#dbeafe;color:#1e40af;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600'>{cnt}</span></td></tr>"

    # Timeline: fixed-order narrative blocks appended to changes_html.
    # change_count aggregates magnitudes but is not wired into the HTML in this script.
    changes_html = ""
    change_count = 0

    if remediated_hosts:
        change_count += len(remediated_hosts)
        hosts_list = "".join(f'<span style="background:#d1fae5;color:#065f46;padding:2px 10px;border-radius:99px;font-size:0.78rem;font-weight:500;margin:2px 4px 2px 0;display:inline-block">{h}</span>' for h in sorted(remediated_hosts))
        changes_html += f"""<div style="display:flex;gap:1rem;padding:1rem 0;border-bottom:1px solid #f1f5f9">
            <div style="width:36px;height:36px;background:#d1fae5;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:1.1rem">✅</div>
            <div><div style="font-weight:600;color:#065f46;font-size:0.9rem">TLS Cipher Remediated ({len(remediated_hosts)} host{'s' if len(remediated_hosts)!=1 else ''})</div>
            <div style="font-size:0.82rem;color:#475569;margin-top:4px">Insecure cipher flag resolved — hosts now using compliant TLS suites.</div>
            <div style="margin-top:6px">{hosts_list}</div></div>
        </div>"""

    if new_flagged_hosts:
        change_count += len(new_flagged_hosts)
        hosts_list = "".join(f'<span style="background:#fee2e2;color:#991b1b;padding:2px 10px;border-radius:99px;font-size:0.78rem;font-weight:500;margin:2px 4px 2px 0;display:inline-block">{h}</span>' for h in sorted(new_flagged_hosts))
        changes_html += f"""<div style="display:flex;gap:1rem;padding:1rem 0;border-bottom:1px solid #f1f5f9">
            <div style="width:36px;height:36px;background:#fee2e2;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:1.1rem">⚠️</div>
            <div><div style="font-weight:600;color:#991b1b;font-size:0.9rem">New Insecure Cipher Hosts ({len(new_flagged_hosts)})</div>
            <div style="font-size:0.82rem;color:#475569;margin-top:4px">These hosts are now flagged with insecure TLS cipher suites.</div>
            <div style="margin-top:6px">{hosts_list}</div></div>
        </div>"""

    if policy_delta != 0:
        # One card for net policy movement; per-workspace lines only where counts moved.
        change_count += 1
        ws_detail = ""
        for name in sorted(common_ws):
            old_w = old_ws_map[name]
            new_w = new_ws_map[name]
            diff = new_w.get("policy_count", 0) - old_w.get("policy_count", 0)
            if diff != 0:
                sign = "+" if diff > 0 else ""
                ws_detail += f'<div style="font-size:0.82rem;color:#475569;margin-top:2px">• <code>{name}</code>: {old_w.get("policy_count",0)} → {new_w.get("policy_count",0)} ({sign}{diff})</div>'
        changes_html += f"""<div style="display:flex;gap:1rem;padding:1rem 0;border-bottom:1px solid #f1f5f9">
            <div style="width:36px;height:36px;background:#dbeafe;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:1.1rem">📋</div>
            <div><div style="font-weight:600;color:#1e40af;font-size:0.9rem">Policy Changes ({'+' if policy_delta > 0 else ''}{policy_delta} net)</div>
            <div style="font-size:0.82rem;color:#475569;margin-top:4px">ADM policies updated across workspaces.</div>
            {ws_detail}</div>
        </div>"""

    if added_hosts:
        change_count += len(added_hosts)
        hosts_list = "".join(f'<span style="background:#d1fae5;color:#065f46;padding:2px 10px;border-radius:99px;font-size:0.78rem;font-weight:500;margin:2px 4px 2px 0;display:inline-block">{h}</span>' for h in sorted(added_hosts))
        changes_html += f"""<div style="display:flex;gap:1rem;padding:1rem 0;border-bottom:1px solid #f1f5f9">
            <div style="width:36px;height:36px;background:#d1fae5;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:1.1rem">🆕</div>
            <div><div style="font-weight:600;color:#065f46;font-size:0.9rem">New Agents Enrolled (+{len(added_hosts)})</div>
            <div style="margin-top:6px">{hosts_list}</div></div>
        </div>"""

    if removed_hosts:
        change_count += len(removed_hosts)
        hosts_list = "".join(f'<span style="background:#fee2e2;color:#991b1b;padding:2px 10px;border-radius:99px;font-size:0.78rem;font-weight:500;margin:2px 4px 2px 0;display:inline-block">{h}</span>' for h in sorted(removed_hosts))
        changes_html += f"""<div style="display:flex;gap:1rem;padding:1rem 0;border-bottom:1px solid #f1f5f9">
            <div style="width:36px;height:36px;background:#fee2e2;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:1.1rem">❌</div>
            <div><div style="font-weight:600;color:#991b1b;font-size:0.9rem">Agents Removed (-{len(removed_hosts)})</div>
            <div style="margin-top:6px">{hosts_list}</div></div>
        </div>"""

    if added_scopes:
        change_count += len(added_scopes)
        changes_html += f"""<div style="display:flex;gap:1rem;padding:1rem 0;border-bottom:1px solid #f1f5f9">
            <div style="width:36px;height:36px;background:#ede9fe;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:1.1rem">🗂</div>
            <div><div style="font-weight:600;color:#5b21b6;font-size:0.9rem">New Scopes Added (+{len(added_scopes)})</div>
            <div style="font-size:0.82rem;color:#475569;margin-top:4px">{"".join(f"<div>• <code>{s}</code></div>" for s in sorted(added_scopes))}</div></div>
        </div>"""

    if added_ws:
        change_count += len(added_ws)
        changes_html += f"""<div style="display:flex;gap:1rem;padding:1rem 0;border-bottom:1px solid #f1f5f9">
            <div style="width:36px;height:36px;background:#fef3c7;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:1.1rem">🆕</div>
            <div><div style="font-weight:600;color:#92400e;font-size:0.9rem">New Workspaces (+{len(added_ws)})</div>
            <div style="font-size:0.82rem;color:#475569;margin-top:4px">{"".join(f"<div>• <code>{s}</code></div>" for s in sorted(added_ws))}</div></div>
        </div>"""

    if not changes_html:
        changes_html = """<div style="text-align:center;padding:2rem;color:#64748b;font-size:0.9rem">
            <div style="font-size:2rem;margin-bottom:0.5rem">✅</div>
            No significant changes detected between snapshots.
        </div>"""

    # Recommendations
    recs_html = ""
    if len(insecure) > 0:
        recs_html += f"""<div style="display:flex;gap:0.75rem;padding:0.75rem 0;border-bottom:1px solid #f1f5f9;align-items:flex-start">
            <span style="font-size:1rem">🔴</span>
            <div><span style="font-weight:600;color:#991b1b">Remediate {len(insecure)} insecure cipher hosts</span>
            <span style="font-size:0.82rem;color:#475569"> — Apply TLS cipher hardening via GPO or registry using CIS Benchmark for Windows Server.</span></div>
        </div>"""
    if enforced == 0:
        recs_html += f"""<div style="display:flex;gap:0.75rem;padding:0.75rem 0;border-bottom:1px solid #f1f5f9;align-items:flex-start">
            <span style="font-size:1rem">🟡</span>
            <div><span style="font-weight:600;color:#92400e">Enforcement not active</span>
            <span style="font-size:0.82rem;color:#475569"> — All {total_agents} agents are in observation mode. Review ADM-generated policies before enabling enforcement.</span></div>
        </div>"""
    if remediated_hosts:
        recs_html += f"""<div style="display:flex;gap:0.75rem;padding:0.75rem 0;border-bottom:1px solid #f1f5f9;align-items:flex-start">
            <span style="font-size:1rem">✅</span>
            <div><span style="font-weight:600;color:#065f46">{len(remediated_hosts)} host{'s' if len(remediated_hosts)!=1 else ''} remediated this period</span>
            <span style="font-size:0.82rem;color:#475569"> — Continue cipher remediation across remaining hosts.</span></div>
        </div>"""
    if policy_delta > 0:
        recs_html += f"""<div style="display:flex;gap:0.75rem;padding:0.75rem 0;border-bottom:1px solid #f1f5f9;align-items:flex-start">
            <span style="font-size:1rem">📋</span>
            <div><span style="font-weight:600;color:#1e40af">+{policy_delta} policies added</span>
            <span style="font-size:0.82rem;color:#475569"> — Review new policies for accuracy before moving toward enforcement.</span></div>
        </div>"""
    if health_warn:
        recs_html += f"""<div style="display:flex;gap:0.75rem;padding:0.75rem 0;border-bottom:1px solid #f1f5f9;align-items:flex-start">
            <span style="font-size:1rem">⚠️</span>
            <div><span style="font-weight:600;color:#dc2626">{len(health_warn)} agent(s) with health warnings</span>
            <span style="font-size:0.82rem;color:#475569"> — Investigate unhealthy agents: {"".join(f"<code>{w['host']}</code> " for w in health_warn)}</span></div>
        </div>"""
    # Full top_ports dict: recommendations card lists every known-risky port seen,
    # not only the top-10 rows shown in the flow table above.
    all_risky_in_flows = {p: cnt for p, cnt in top_ports.items() if str(p) in RISKY_PORTS}
    risky_total = sum(all_risky_in_flows.values())

    risky_card_rows = ""
    for rp in sorted(all_risky_in_flows, key=lambda x: -all_risky_in_flows[x]):
        rsev, rdesc = RISKY_PORTS[str(rp)]
        rbg, rfg = ("#fee2e2", "#991b1b") if rsev == "CRITICAL" else ("#fef3c7", "#92400e")
        risky_card_rows += (
            f'<tr><td>:{rp}</td>'
            f'<td><span style="background:{rbg};color:{rfg};padding:2px 8px;border-radius:99px;font-size:0.69rem;font-weight:600">{rsev}</span></td>'
            f'<td style="font-size:0.82rem;color:#475569">{rdesc}</td>'
            f'<td style="font-weight:600">{all_risky_in_flows[rp]}</td></tr>'
        )

    if all_risky_in_flows:
        risky_total = sum(all_risky_in_flows.values())
        risky_details = ", ".join(
            f":{p} ({RISKY_PORTS[str(p)][0]})"
            for p in sorted(all_risky_in_flows, key=lambda x: -all_risky_in_flows[x])
        )
        recs_html += f"""<div style="display:flex;gap:0.75rem;padding:0.75rem 0;border-bottom:1px solid #f1f5f9;align-items:flex-start">
            <span style="font-size:1rem">&#9888;</span>
            <div><span style="font-weight:600;color:#991b1b">{len(all_risky_in_flows)} high-risk port(s) detected ({risky_total} flows)</span>
            <span style="font-size:0.82rem;color:#475569"> — Risky ports observed: {risky_details}. Review policies to restrict access to bastion hosts and application-specific sources.</span></div>
        </div>"""

    if not recs_html:
        recs_html = '<div style="padding:1rem;color:#059669;font-size:0.9rem">No urgent recommendations. Continue monitoring.</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Cluster Report — {cluster}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {{
  --bg:#F8FAFC; --card:#ffffff; --border:#E2E8F0;
  --text:#020617; --text2:#475569; --text3:#94A3B8;
  --cisco:#00bceb; --cisco-dark:#005073;
  --blue:#0369A1; --sky:#0EA5E9; --green:#059669; --red:#dc2626; --amber:#d97706;
  --shadow-sm:0 1px 2px rgba(0,0,0,.04),0 1px 3px rgba(0,0,0,.06);
  --shadow-md:0 4px 6px rgba(0,0,0,.04),0 10px 15px rgba(0,0,0,.06);
  --radius:10px; --transition:200ms ease;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}}

.header{{background:linear-gradient(135deg,#00bceb 0%,#005073 100%);color:#fff;padding:2.5rem 2rem 2rem}}
.header-inner{{max-width:1200px;margin:0 auto}}
.header h1{{font-size:1.75rem;font-weight:700;letter-spacing:-.3px}}
.header .sub{{opacity:.88;margin-top:.4rem;font-size:0.92rem;font-weight:400}}
.header .meta{{margin-top:1rem;display:flex;flex-wrap:wrap;gap:.6rem;font-size:0.78rem}}
.header .meta span{{background:rgba(255,255,255,.14);padding:4px 12px;border-radius:99px;backdrop-filter:blur(4px)}}

.kpi-strip{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;background:var(--border);border-bottom:1px solid var(--border)}}
.kpi{{background:var(--card);padding:1.3rem 1rem;text-align:center;transition:background var(--transition)}}
.kpi:hover{{background:#F8FAFC}}
.kpi .val{{font-size:1.85rem;font-weight:700;line-height:1;font-family:'Inter',sans-serif}}
.kpi .val.warn{{color:var(--red)}}
.kpi .val.ok{{color:var(--green)}}
.kpi .lbl{{font-size:0.68rem;color:var(--text3);margin-top:.35rem;text-transform:uppercase;letter-spacing:.6px;font-weight:500}}

.content{{max-width:1200px;margin:2rem auto;padding:0 1.5rem;display:grid;gap:1.5rem}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow-sm);overflow:hidden;transition:box-shadow var(--transition)}}
.card:hover{{box-shadow:var(--shadow-md)}}
.card-header{{padding:0.85rem 1.4rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.75rem;background:#FAFBFC}}
.card-header h2{{font-size:0.92rem;font-weight:600}}
.card-icon{{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0}}
.card-body{{padding:1.2rem 1.4rem}}

table{{width:100%;border-collapse:collapse;font-size:0.8rem}}
thead{{background:#F1F5F9}}
th{{padding:.55rem .8rem;text-align:left;font-size:0.7rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);border-bottom:2px solid var(--border);font-weight:600}}
td{{padding:.55rem .8rem;border-bottom:1px solid #F1F5F9;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tbody tr:nth-child(even) td{{background:#FAFBFC}}
tbody tr:hover td{{background:#EFF6FF;transition:background var(--transition)}}
code{{background:#F1F5F9;color:#0F172A;padding:2px 7px;border-radius:4px;font-size:0.78rem;font-family:'Fira Code','Cascadia Code',monospace}}

.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}}
@media(max-width:720px){{.two-col{{grid-template-columns:1fr}}}}

.delta-banner{{background:linear-gradient(135deg,#F0F9FF 0%,#E0F2FE 100%);border:1px solid #BAE6FD;border-radius:var(--radius);padding:1.2rem 1.5rem;margin-bottom:0.5rem;display:flex;align-items:center;gap:1rem}}
.delta-banner .icon{{font-size:1.6rem}}
.delta-banner .text{{font-size:0.85rem;color:#0C4A6E}}
.delta-banner strong{{color:var(--blue)}}

footer{{text-align:center;padding:2.5rem 1rem;font-size:0.75rem;color:var(--text3);border-top:1px solid var(--border);margin-top:2rem}}
footer strong{{color:var(--text2)}}
@media print{{
  body{{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .header{{background:#005073 !important;-webkit-print-color-adjust:exact}}
  .card{{box-shadow:none;break-inside:avoid}}
  .card:hover{{box-shadow:none}}
  .kpi:hover{{background:var(--card)}}
  footer{{page-break-before:auto}}
}}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;opacity:.9">
      <svg width="70" height="24" viewBox="0 0 70 24"><text x="0" y="19" font-family="Arial,sans-serif" font-size="20" font-weight="700" fill="white">CISCO</text></svg>
      <span style="font-size:0.8rem;border-left:1px solid rgba(255,255,255,.4);padding-left:0.75rem">Secure Workload</span>
    </div>
    <h1>CSW Cluster Report</h1>
    <div class="sub">Combined snapshot readout &amp; change delta for <strong>{cluster}</strong></div>
    <div class="meta">
      <span>Baseline: {old_ts}</span>
      <span>Current: {new_ts}</span>
      <span>Root Scope: {root}</span>
      <span>Generated: {generated}</span>
    </div>
  </div>
</div>

<div class="kpi-strip">
  <div class="kpi"><div class="val">{total_agents}</div>{kpi_delta_html(agent_delta)}<div class="lbl">Agents</div></div>
  <div class="kpi"><div class="val {'warn' if insecure else 'ok'}">{len(insecure)}</div>{kpi_delta_html(insecure_delta)}<div class="lbl">Insecure Cipher</div></div>
  <div class="kpi"><div class="val {'warn' if health_warn else 'ok'}">{health_ok}</div><div class="lbl">Healthy</div></div>
  <div class="kpi"><div class="val">{total_scopes}</div>{kpi_delta_html(scope_delta)}<div class="lbl">Scopes</div></div>
  <div class="kpi"><div class="val">{total_ws}</div>{kpi_delta_html(ws_delta)}<div class="lbl">Workspaces</div></div>
  <div class="kpi"><div class="val">{total_policies}</div>{kpi_delta_html(policy_delta)}<div class="lbl">Policies</div></div>
  <div class="kpi"><div class="val {'ok' if enforced else 'warn'}">{enforced}</div><div class="lbl">Enforcing</div></div>
  <div class="kpi"><div class="val ok">{permitted}</div><div class="lbl">Flows Permitted</div></div>
</div>

<div class="content">

  <!-- Change Delta Section -->
  <div class="delta-banner">
    <div class="icon">🔄</div>
    <div class="text">
      <strong>Change Report</strong> — Comparing baseline ({old_ts.split('T')[0] if 'T' in old_ts else old_ts}) to current ({new_ts.split('T')[0] if 'T' in new_ts else new_ts})
    </div>
  </div>

  <div class="two-col">
    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:#e0f2fe">🔄</div>
        <h2>Changes Detected</h2>
      </div>
      <div class="card-body">
        <table>
          <thead><tr><th>Area</th><th>Previous</th><th>Current</th><th>Delta</th></tr></thead>
          <tbody>
            <tr><td style="font-weight:600">Total Agents</td><td>{old_total_agents}</td><td>{total_agents}</td><td>{delta_badge(agent_delta)}</td></tr>
            <tr><td style="font-weight:600">Enforcement</td><td>{old_enforced}</td><td>{enforced}</td><td>{delta_badge(enforced_delta)}</td></tr>
            <tr><td style="font-weight:600">Insecure Cipher</td><td>{len(old_insecure)}</td><td>{len(insecure)}</td><td>{delta_badge(insecure_delta, "red")}</td></tr>
            <tr><td style="font-weight:600">Total Scopes</td><td>{old_total_scopes}</td><td>{total_scopes}</td><td>{delta_badge(scope_delta)}</td></tr>
            <tr><td style="font-weight:600">Total Workspaces</td><td>{old_total_ws}</td><td>{total_ws}</td><td>{delta_badge(ws_delta)}</td></tr>
            <tr><td style="font-weight:600">Total Policies</td><td>{old_total_policies}</td><td>{total_policies}</td><td>{delta_badge(policy_delta)}</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:#fef3c7">📌</div>
        <h2>Recommendations</h2>
      </div>
      <div class="card-body">
        {recs_html}
      </div>
    </div>
  </div>

  <!-- Change Timeline -->
  <div class="card">
    <div class="card-header">
      <div class="card-icon" style="background:#ede9fe">📜</div>
      <h2>Change Timeline</h2>
    </div>
    <div class="card-body">
      {changes_html}
    </div>
  </div>

  <!-- Agent Overview -->
  <div class="two-col">
    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:#dbeafe">🖥</div>
        <h2>Agent Deployment</h2>
      </div>
      <div class="card-body">
        <table>
          <thead><tr><th>Capability</th><th>Count</th><th>Coverage</th></tr></thead>
          <tbody>
            <tr><td>Package Visibility</td><td>{pkg_vis}</td><td><span style="background:#d1fae5;color:#065f46;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">{int(pkg_vis/max(total_agents,1)*100)}%</span></td></tr>
            <tr><td>Process Visibility</td><td>{proc_vis}</td><td><span style="background:#d1fae5;color:#065f46;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">{int(proc_vis/max(total_agents,1)*100)}%</span></td></tr>
            <tr><td>Forensics</td><td>{forensics_cnt}</td><td><span style="background:#d1fae5;color:#065f46;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">{int(forensics_cnt/max(total_agents,1)*100)}%</span></td></tr>
            <tr><td>Enforcement Active</td><td>{enforced}</td><td><span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">{'0% — Obs. Mode' if not enforced else f'{int(enforced/max(total_agents,1)*100)}%'}</span></td></tr>
            <tr><td>Healthy / Active</td><td>{health_ok}</td><td><span style="background:{'#d1fae5' if health_ok==total_agents else '#fef3c7'};color:{'#065f46' if health_ok==total_agents else '#92400e'};padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:600">{int(health_ok/max(total_agents,1)*100)}%</span></td></tr>
          </tbody>
        </table>
        <div style="margin-top:1.2rem">
          <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:.6rem">OS Distribution</div>
          {os_bars}
        </div>
        <div style="margin-top:1rem">
          <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:.6rem">Agent Versions</div>
          <table><thead><tr><th>Version</th><th>Hosts</th></tr></thead><tbody>{ver_rows}</tbody></table>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:#fef3c7">🌐</div>
        <h2>Workspaces &amp; Policies</h2>
      </div>
      <div class="card-body">
        <div style="margin-bottom:1rem;font-size:0.85rem;color:var(--text2)">
          <strong>{total_ws}</strong> workspaces · <strong>{total_policies}</strong> ADM-generated policies
        </div>
        <div style="overflow-x:auto">
        <table>
          <thead><tr><th>Workspace</th><th>Policies</th><th>Absolute</th><th>Default</th><th>Type</th><th>Enforcing</th></tr></thead>
          <tbody>{ws_rows}</tbody>
        </table>
        </div>
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
        ⚠ {len(insecure)} host(s) communicating with deprecated TLS cipher suites.
        Remediate via Group Policy (GPO) or registry using the CIS Benchmark for Windows Server.
      </div>
      <div style="overflow-x:auto">
      <table>
        <thead><tr><th>Hostname</th><th>IP Address</th><th>Status</th></tr></thead>
        <tbody>{cipher_rows}</tbody>
      </table>
      </div>
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
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:1rem;overflow-x:auto">
        {scope_tree_html}
      </div>
    </div>
  </div>

  <!-- Flow Analysis -->
  {"" if not fl.get("available") else f'''
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
        <div style="background:{"#fef2f2" if rejected else "#f0fdf4"};border:1px solid {"#fca5a5" if rejected else "#bbf7d0"};border-radius:8px;padding:1rem">
          <div style="font-size:1.6rem;font-weight:700;color:{"#991b1b" if rejected else "#065f46"}">{rejected}</div>
          <div style="font-size:0.72rem;color:{"#dc2626" if rejected else "#059669"};margin-top:.2rem;text-transform:uppercase">Rejected</div>
        </div>
      </div>
      <div class="two-col">
        <div>
          <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:.6rem">Top Application Services</div>
          <table><thead><tr><th>Service</th><th>Flows</th></tr></thead><tbody>{svc_rows}</tbody></table>
        </div>
        <div>
          <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:.6rem">Top Destination Ports</div>
          <table><thead><tr><th>Port</th><th>Flows</th></tr></thead><tbody>{port_rows}</tbody></table>
          <div style="margin-top:1rem">
            <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:.6rem">Protocols</div>
            <table><thead><tr><th>Protocol</th><th>Flows</th></tr></thead><tbody>{proto_rows}</tbody></table>
          </div>
        </div>
      </div>
    </div>
  </div>
  '''}

  {"" if not all_risky_in_flows else f'''
  <div class="card" style="border-left:4px solid #dc2626">
    <div class="card-header">
      <div class="card-icon" style="background:#fee2e2">&#9888;</div>
      <h2>High-Risk Port Communications ({len(all_risky_in_flows)} risky ports — {risky_total} flows)</h2>
    </div>
    <div class="card-body">
      <div style="margin-bottom:1rem;font-size:0.85rem;color:#7f1d1d;background:#fef2f2;border:1px solid #fca5a5;padding:.75rem 1rem;border-radius:8px">
        <strong>Security Alert:</strong> The following high-risk ports were observed in flow telemetry.
        These ports are commonly targeted for brute-force attacks, data exfiltration, lateral movement, and ransomware distribution.
      </div>
      <table>
        <thead><tr><th>Port</th><th>Severity</th><th>Risk Description</th><th>Flows</th></tr></thead>
        <tbody>{risky_card_rows}</tbody>
      </table>
    </div>
  </div>
  '''}

</div>

<footer>
  <strong>Cisco Secure Workload</strong> — Combined Cluster Report<br>
  Cluster: <code>{cluster}</code> &nbsp;|&nbsp; Baseline: {old_ts} &nbsp;|&nbsp; Current: {new_ts}<br>
  <span style="margin-top:.4rem;display:block">Generated by <code>generate_combined_report.py</code> · Cisco SE Toolkit</span>
</footer>

</body>
</html>"""


def main():
    """Parse CLI args, load baseline/current JSON, write HTML under ``reports/`` (or ``--out``).

    With ``--latest`` or no paths, picks the two newest files from ``snapshots/``.
    """
    parser = argparse.ArgumentParser(description="Generate combined HTML readout + delta report.")
    parser.add_argument("--baseline", default=None, help="Path to baseline snapshot JSON")
    parser.add_argument("--current", default=None, help="Path to current snapshot JSON")
    parser.add_argument("--latest", action="store_true", help="Auto-pick the two most recent snapshots")
    parser.add_argument("--out", "-o", default=None, help="Output HTML path")
    args = parser.parse_args()

    # Default behavior matches --latest: auto-resolve when paths omitted.
    if args.latest or (not args.baseline and not args.current):
        baseline_path, current_path = find_latest_two()
        if not baseline_path or not current_path:
            print("Need at least 2 snapshot files in snapshots/. Run cluster_snapshot.py first.")
            sys.exit(1)
    else:
        baseline_path = args.baseline
        current_path = args.current

    for p in [baseline_path, current_path]:
        if not os.path.exists(p):
            print(f"Snapshot not found: {p}")
            sys.exit(1)

    with open(baseline_path) as f:
        old_snap = json.load(f)
    with open(current_path) as f:
        new_snap = json.load(f)

    print(f"📂  Baseline: {baseline_path}")
    print(f"📂  Current:  {current_path}")
    print(f"🏢  Cluster:  {new_snap.get('cluster', '?')}")

    date_tag = datetime.now().strftime("%Y-%m-%d")
    out_path = args.out or f"reports/cluster-report-{date_tag}.html"
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    html = render(old_snap, new_snap)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅  HTML report: {out_path}")
    print(f"\n   Open in browser:")
    print(f"   open {out_path}")


if __name__ == "__main__":
    main()
