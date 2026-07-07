#!/usr/bin/env python3
"""
risky_port_audit.py — Risky-Port Policy Auditor for Cisco Secure Workload
=========================================================================

Audit-only. Never POSTs/PUTs/DELETEs against the cluster.

Implements four CSW security recommendations against every policy in every
workspace (primary, secondary, and draft/ADM):

  1. Block East-West   — risky ports should never flow freely between two
                         INTERNAL workload scopes.
  2. Whitelist only    — a risky port may only be ALLOWed when BOTH sides
                         are narrow (leaf) scopes; broad scopes are flagged.
  3. Flag in ADM       — any risky port appearing in an ADM-discovered
                         policy (non-primary workspace) is suspect and
                         must be reviewed before promotion.
  4. PCI DSS boundary  — TCP/22, TCP/3389, TCP/445 crossing a CDE boundary
                         is an automatic audit finding.

Inputs
------
* Cluster credentials in .env (same format as the rest of the toolkit).
* Optional snapshots from `download_policies.py` (re-used if present to
  avoid hammering the cluster):
      snapshots/policies-all.json       (list of normalized policy dicts)
      snapshots/scope-workloads.json    (scope full_name -> [workloads])

Outputs
-------
  snapshots/risky-port-findings.json    machine-readable findings
  snapshots/risky-port-audit.md         markdown summary
  reports/risky-port-audit-<date>.html  interactive HTML report

Usage
-----
  python3 risky_port_audit.py                   # live API + write all reports
  python3 risky_port_audit.py --use-cache       # reuse snapshots/ if present
  python3 risky_port_audit.py --no-html         # skip HTML
  python3 risky_port_audit.py --pci-field user_pci_scope --pci-value true

CDE detection (PCI check)
-------------------------
A scope is treated as CDE if ANY of its workloads carries the configured
user annotation. The defaults match the most common convention:
  field = "user_pci_scope"     (any annotation starting with `user_` works)
  value = "true"
Override on the CLI if your environment uses a different label.

API capabilities required on the API key
----------------------------------------
  app_policy_management   - workspaces and policies
  flow_inventory_query    - inventory / annotations / CDE detection

Security note
-------------
This script is read-only and writes no policy changes back to CSW. It also
never logs API keys or secrets. Findings JSON includes scope NAMES (not
secrets). Treat the output reports as Confidential because they reveal
gaps in the policy posture.

Quick troubleshooting
---------------------
* "Missing environment variables" → copy `.env.example` to `.env` and fill in
  CSW_API_URL / CSW_API_KEY / CSW_API_SECRET. The script reads the file in
  the same directory as itself; run it from any cwd.
* CERTIFICATE_VERIFY_FAILED → set `CSW_VERIFY_SSL=false` in `.env` (lab/POV
  only). Proper fix is to trust the corporate root CA.
* HTTP 403 on /openapi/v1/applications → API key is missing the
  `app_policy_management` capability. Recreate the key in the CSW UI.
* HTTP 403 on /openapi/v1/inventory/search → API key is missing the
  `flow_inventory_query` capability.
* "0 CDE-tagged workloads" → either the target environment has no PCI tag
  applied yet, or the field/value differ. Pass `--pci-field user_<your_label>
  --pci-value <value>` (or set CSW_PCI_FIELD/CSW_PCI_VALUE in `.env`).
* Findings count seems too high → bump `BROAD_WORKLOAD_THRESHOLD` and
  `BROAD_DEPTH_THRESHOLD` near the top of this file.
* Re-run quickly without rehammering the API → run `download_policies.py`
  once to populate snapshots/, then this script with `--use-cache`.
"""

from __future__ import annotations

import argparse
import collections
import html
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csw_api  # noqa: E402  (sibling module after sys.path mod)

csw_api._load_dotenv()


# =============================================================================
# Risk catalog
# =============================================================================
#
# Keyed by (proto, port). Tier values: CRITICAL | HIGH | MEDIUM.
# Extend by adding new entries; nothing else needs to change.
#
# Why a tuple key (proto, port)? CSW policies always carry both, and the
# same port number can mean different things over TCP vs UDP (53, 161,
# 11211) so we want each protocol classified independently.

RISK_CATALOG: dict[tuple[str, int], tuple[str, str, str]] = {
    # ── CRITICAL — Always Restrict ────────────────────────────────────────
    ("TCP", 22):    ("CRITICAL", "SSH",        "Brute force, lateral movement"),
    ("TCP", 23):    ("CRITICAL", "Telnet",     "Cleartext credentials"),
    ("TCP", 135):   ("CRITICAL", "RPC/EPMAP",  "Lateral movement, recon"),
    ("UDP", 137):   ("CRITICAL", "NetBIOS-NS", "Lateral movement, recon"),
    ("UDP", 138):   ("CRITICAL", "NetBIOS-DS", "Lateral movement, recon"),
    ("TCP", 139):   ("CRITICAL", "NetBIOS-SSN","Lateral movement, recon"),
    ("TCP", 445):   ("CRITICAL", "SMB",        "WannaCry / NotPetya / ransomware spread"),
    ("TCP", 1433):  ("CRITICAL", "MSSQL",      "Direct DB exposure"),
    ("TCP", 3306):  ("CRITICAL", "MySQL",      "Direct DB exposure"),
    ("TCP", 3389):  ("CRITICAL", "RDP",        "#1 ransomware entry point"),
    ("TCP", 5432):  ("CRITICAL", "PostgreSQL", "Direct DB exposure"),
    # ── HIGH — Tightly Control ────────────────────────────────────────────
    ("TCP", 21):    ("HIGH",     "FTP",        "Cleartext, data exfil"),
    ("TCP", 25):    ("HIGH",     "SMTP",       "Spam relay, phishing"),
    ("TCP", 53):    ("HIGH",     "DNS-TCP",    "DNS tunneling, exfiltration"),
    ("UDP", 53):    ("HIGH",     "DNS",        "DNS tunneling, exfiltration"),
    ("TCP", 80):    ("HIGH",     "HTTP",       "Unencrypted, web attacks"),
    ("UDP", 161):   ("HIGH",     "SNMP",       "Network recon, v1/v2 cleartext"),
    ("UDP", 162):   ("HIGH",     "SNMP-trap",  "Network recon, v1/v2 cleartext"),
    ("TCP", 2375):  ("HIGH",     "Docker API", "Container escape (no TLS)"),
    ("TCP", 2376):  ("HIGH",     "Docker API", "Container escape"),
    ("TCP", 6379):  ("HIGH",     "Redis",      "Often left open, no auth"),
    ("TCP", 8080):  ("HIGH",     "HTTP-alt",   "Unencrypted, web attacks"),
    ("TCP", 9200):  ("HIGH",     "Elasticsearch", "Data exposure, no auth by default"),
    ("TCP", 9300):  ("HIGH",     "Elasticsearch", "Data exposure, no auth by default"),
    ("TCP", 27017): ("HIGH",     "MongoDB",    "Data exposure, no auth by default"),
    # ── MEDIUM — Monitor Closely ─────────────────────────────────────────
    ("TCP", 443):   ("MEDIUM",   "HTTPS",      "C2 over SSL, data exfil"),
    ("TCP", 4444):  ("MEDIUM",   "Metasploit", "Attacker tooling default"),
    ("TCP", 4445):  ("MEDIUM",   "Metasploit", "Attacker tooling default"),
    ("TCP", 5900):  ("MEDIUM",   "VNC",        "Remote access, often unencrypted"),
    ("TCP", 8443):  ("MEDIUM",   "HTTPS-alt",  "C2 over SSL, data exfil"),
    ("TCP", 11211): ("MEDIUM",   "Memcached",  "Amplification DDoS"),
    ("UDP", 11211): ("MEDIUM",   "Memcached",  "Amplification DDoS"),
}

# Subset that triggers the PCI boundary check (Check #4)
PCI_RESTRICTED_PORTS: set[tuple[str, int]] = {("TCP", 22), ("TCP", 3389), ("TCP", 445)}

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 0: "Any"}
PROTO_NUM = {v: k for k, v in PROTO_MAP.items()}

# Heuristic: scope leaf names that we treat as "external / untrusted"
# (i.e. NOT east-west). Match is case-insensitive substring.
EXTERNAL_NAME_HINTS = ("internet", "external", "untrusted", "public", "wan", "any", "world")

# Heuristic: scope leaf names that always count as "broad" regardless of size.
BROAD_NAME_HINTS = ("default", "any", "all", "root", "internet", "external", "world")

# Tunables for the broad-scope check.
BROAD_DEPTH_THRESHOLD = 2          # depth <= this is considered broad
BROAD_WORKLOAD_THRESHOLD = 50      # workload count > this is considered broad

DATE_TAG  = datetime.now().strftime("%Y-%m-%d")
TIMESTAMP = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M UTC")


# =============================================================================
# Small helpers
# =============================================================================

def shorten(full_name: str) -> str:
    """Return the leaf segment of a colon-separated scope path."""
    return full_name.split(":")[-1] if full_name else "?"


def scope_depth(full_name: str) -> int:
    """Depth in the scope tree. Root=1, root:Default=2, root:App:Web=3."""
    return len([p for p in (full_name or "").split(":") if p])


def fmt_ports_human(l4_params: list) -> str:
    """Render a CSW l4_params block as 'TCP/22, UDP/53, ...'."""
    parts = []
    for p in l4_params or []:
        proto = PROTO_MAP.get(p.get("proto", 0), str(p.get("proto", "?")))
        port  = p.get("port", []) or []
        if port:
            parts.append(f"{proto}/{port[0]}" if port[0] == port[1] else f"{proto}/{port[0]}-{port[1]}")
        else:
            parts.append(f"{proto}/Any")
    return ", ".join(parts) if parts else "Any/Any"


def looks_external(scope_full: str, scope_query: dict | None) -> bool:
    """A scope is external if its leaf name hints external OR its query is 0.0.0.0/0."""
    leaf = shorten(scope_full).lower()
    if any(h in leaf for h in EXTERNAL_NAME_HINTS):
        return True
    if scope_query:
        # Inventory filters for "the whole internet" usually look like
        # {"type":"eq","field":"address","value":"0.0.0.0/0"}.
        try:
            blob = json.dumps(scope_query).lower()
            if "0.0.0.0/0" in blob or "::/0" in blob:
                return True
        except (TypeError, ValueError):
            pass
    return False


def is_broad_scope(
    scope_full: str,
    scope_query: dict | None,
    workload_count: int,
) -> tuple[bool, list[str]]:
    """Check #2 helper. Returns (is_broad, list_of_reasons)."""
    reasons: list[str] = []
    leaf = shorten(scope_full).lower()
    if any(h in leaf for h in BROAD_NAME_HINTS):
        reasons.append(f"name '{shorten(scope_full)}' matches broad-scope keyword")
    if scope_depth(scope_full) <= BROAD_DEPTH_THRESHOLD:
        reasons.append(f"scope depth {scope_depth(scope_full)} <= {BROAD_DEPTH_THRESHOLD}")
    if workload_count > BROAD_WORKLOAD_THRESHOLD:
        reasons.append(f"contains {workload_count} workloads (> {BROAD_WORKLOAD_THRESHOLD})")
    if looks_external(scope_full, scope_query):
        reasons.append("scope appears to be Internet/External")
    return (len(reasons) > 0, reasons)


def explode_policy_ports(l4_params: list) -> list[tuple[str, int, tuple[int, int]]]:
    """
    Expand an l4_params block to a list of (proto_str, risky_port, range) tuples
    for every risky port the policy actually permits.

    A policy with no port specified (port == []) is treated as 'all ports' for
    the protocol — every risky port for that protocol matches.
    """
    matches: list[tuple[str, int, tuple[int, int]]] = []
    for p in l4_params or []:
        proto_int = p.get("proto", 0)
        proto = PROTO_MAP.get(proto_int, str(proto_int))
        port = p.get("port", []) or []
        if not port:
            # All ports of this protocol
            for (cat_proto, cat_port) in RISK_CATALOG:
                if cat_proto == proto or proto == "Any":
                    matches.append((cat_proto, cat_port, (0, 65535)))
            continue
        low, high = port[0], port[1]
        # Iterate the catalog (small) rather than the range (potentially large).
        for (cat_proto, cat_port) in RISK_CATALOG:
            if (cat_proto == proto or proto == "Any") and low <= cat_port <= high:
                matches.append((cat_proto, cat_port, (low, high)))
    return matches


# =============================================================================
# Snapshot loading / API fallback
# =============================================================================

def load_cached_snapshot(path: str) -> Any | None:
    """Return parsed JSON from path, or None if missing/unreadable."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  ⚠️   Could not read {path}: {exc}", file=sys.stderr)
        return None


def fetch_workspaces_and_policies() -> tuple[list[dict], list[dict], dict[str, str]]:
    """
    Hit the API and return:
      workspaces  - list of workspace metadata dicts
      policies    - flat list of normalized policy dicts (same shape that
                    download_policies.py emits to snapshots/policies-all.json)
      ws_origin   - mapping policy_id -> 'absolute' | 'default' (ADM-discovered)
    """
    print("  → GET /openapi/v1/applications")
    r = csw_api.make_request("GET", "/openapi/v1/applications")
    if r.get("status") != 200:
        print(f"  ❌  HTTP {r.get('status')} listing workspaces — aborting", file=sys.stderr)
        sys.exit(2)
    raw = r.get("data") or []
    workspaces = raw if isinstance(raw, list) else raw.get("results", [])

    policies: list[dict] = []
    ws_origin: dict[str, str] = {}

    for ws in workspaces:
        ws_id   = ws.get("id", "")
        ws_name = ws.get("name", "?")
        rr = csw_api.make_request("GET", f"/openapi/v1/applications/{ws_id}/policies")
        if rr.get("status") != 200:
            print(f"  ⚠️   workspace '{ws_name}': HTTP {rr.get('status')}", file=sys.stderr)
            continue
        data = rr.get("data") or {}
        if not isinstance(data, dict):
            continue

        for origin_key, origin_label in (("absolute_policies", "absolute"),
                                         ("default_policies",  "default")):
            for p in data.get(origin_key, []) or []:
                cf = p.get("consumer_filter") or {}
                pf = p.get("provider_filter") or {}
                pid = str(p.get("id") or f"{ws_id}-{len(policies)}")
                ws_origin[pid] = origin_label
                policies.append({
                    "id":              pid,
                    "workspace":       ws_name,
                    "workspace_id":    ws_id,
                    "primary":         bool(ws.get("primary", False)),
                    "enforced":        bool(ws.get("enforcement_enabled", False)),
                    "origin":          origin_label,
                    "rank":            p.get("rank", "?"),
                    "action":          p.get("action", "?"),
                    "priority":        p.get("priority", ""),
                    "consumer_full":   cf.get("name", "?"),
                    "provider_full":   pf.get("name", "?"),
                    "consumer_query":  cf.get("query", {}),
                    "provider_query":  pf.get("query", {}),
                    "l4_params":       p.get("l4_params", []),
                })
        time.sleep(0.05)

    print(f"  ✓ {len(workspaces)} workspaces, {len(policies)} policies")
    return workspaces, policies, ws_origin


def fetch_root_scope_name() -> str:
    """Best-effort root-scope name lookup; falls back to 'Root'."""
    r = csw_api.make_request("GET", "/openapi/v1/app_scopes")
    if r.get("status") != 200:
        return "Root"
    data = r.get("data") or []
    if not isinstance(data, list):
        return "Root"
    roots = [s for s in data if isinstance(s, dict) and not s.get("parent_app_scope_id")]
    return roots[0].get("name", "Root") if roots else "Root"


def inventory_search(query: dict, root_scope: str, limit: int = 200) -> list[dict]:
    """Wrapper for /openapi/v1/inventory/search returning the results list."""
    body = {"filter": query, "scopeName": root_scope, "limit": limit}
    r = csw_api.make_request("POST", "/openapi/v1/inventory/search", body=body)
    if r.get("status") != 200:
        return []
    data = r.get("data") or {}
    return data.get("results", []) if isinstance(data, dict) else []


def fetch_scope_workload_counts(
    policies: list[dict],
    root_scope: str,
) -> dict[str, list[dict]]:
    """For every distinct consumer/provider scope referenced by `policies`,
    look up its workloads. Returns {full_scope_name: [workload, ...]}.
    """
    distinct: dict[str, dict] = {}
    for p in policies:
        for side in ("consumer", "provider"):
            name = p[f"{side}_full"]
            q    = p[f"{side}_query"]
            if name and name != "?" and q and name not in distinct:
                distinct[name] = q

    out: dict[str, list[dict]] = {}
    print(f"  → Inventory lookup for {len(distinct)} unique scopes")
    for i, (name, q) in enumerate(distinct.items(), 1):
        out[name] = inventory_search(q, root_scope)
        if i % 10 == 0 or i == len(distinct):
            print(f"      [{i}/{len(distinct)}] {shorten(name)}: {len(out[name])} wls")
        time.sleep(0.05)
    return out


def fetch_cde_workload_keys(
    pci_field: str,
    pci_value: str,
    root_scope: str,
) -> set[str]:
    """
    Return the set of keys (host_name OR ip) of every workload tagged as CDE.

    The query asks the inventory for any workload whose user annotation
    `pci_field` equals `pci_value`. Field names beginning with `user_` are
    user-defined annotations; everything else is a CSW-managed attribute.
    """
    if not pci_field:
        return set()
    print(f"  → CDE detection: inventory where {pci_field} == '{pci_value}'")
    flt = {"type": "eq", "field": pci_field, "value": pci_value}
    rs  = inventory_search(flt, root_scope, limit=2000)
    keys: set[str] = set()
    for w in rs:
        k = w.get("host_name") or w.get("ip")
        if k:
            keys.add(k)
    print(f"      found {len(keys)} CDE-tagged workloads")
    return keys


# =============================================================================
# Audit core — the four checks
# =============================================================================

def workload_key(w: dict) -> str:
    return w.get("host") or w.get("host_name") or w.get("ip") or ""


def scope_is_cde(workloads: list[dict], cde_keys: set[str]) -> bool:
    """A scope is CDE if any of its workloads is in the CDE set."""
    if not cde_keys:
        return False
    for w in workloads:
        if workload_key(w) in cde_keys:
            return True
    return False


def audit_policies(
    policies: list[dict],
    scope_workloads: dict[str, list[dict]],
    cde_keys: set[str],
) -> list[dict]:
    """
    Apply checks #1–#4 to every ALLOW policy that opens a risky port.
    Returns a list of finding dicts ready to be serialized.

    DENY policies are skipped — they are the goal state, not a risk.

    Performance note: ``policies`` is typically O(hundreds–low thousands)
    and ``RISK_CATALOG`` is O(30). The inner loop is therefore O(n*30) with
    a few O(1) dict lookups per policy. No need for batching even on large
    clusters — a 5000-policy tenant audits in seconds.
    """
    findings: list[dict] = []

    for p in policies:
        # Step A: skip everything that isn't an ALLOW. DENYs are the goal
        # state — they REDUCE risk, so they never produce findings.
        if p.get("action") != "ALLOW":
            continue

        # Step B: does this rule actually open a port from our risk catalog?
        # If not, no further work needed. Fast path that eliminates ~90% of
        # policies in a typical tenant.
        risky_hits = explode_policy_ports(p.get("l4_params") or [])
        if not risky_hits:
            continue

        # Step C: gather the per-scope context once per policy, since a
        # single policy with multiple risky ports re-uses these values.
        c_full = p.get("consumer_full", "?")
        v_full = p.get("provider_full", "?")
        c_q    = p.get("consumer_query") or {}
        v_q    = p.get("provider_query") or {}
        c_wls  = scope_workloads.get(c_full, [])
        v_wls  = scope_workloads.get(v_full, [])

        c_external = looks_external(c_full, c_q)
        v_external = looks_external(v_full, v_q)
        c_broad, c_broad_reasons = is_broad_scope(c_full, c_q, len(c_wls))
        v_broad, v_broad_reasons = is_broad_scope(v_full, v_q, len(v_wls))
        c_cde = scope_is_cde(c_wls, cde_keys)
        v_cde = scope_is_cde(v_wls, cde_keys)

        for (proto, port, port_range) in risky_hits:
            tier, name, why = RISK_CATALOG[(proto, port)]
            checks_failed: list[dict] = []

            # --- CHECK #1: East-West --------------------------------------
            # Both sides internal → risky port should not be open broadly.
            # (Findings are still raised even if the scopes are narrow; the
            # whitelist-only check distinguishes "narrow east-west" later.)
            if not c_external and not v_external:
                checks_failed.append({
                    "check":  "east_west",
                    "title":  "East-West risky port allowed",
                    "detail": (
                        f"{proto}/{port} ({name}) is ALLOWed between two internal "
                        f"scopes ('{shorten(c_full)}' → '{shorten(v_full)}'). Risky "
                        f"ports must not flow freely between workload scopes."
                    ),
                })

            # --- CHECK #2: Whitelist only ---------------------------------
            # If either side is broad, the risky port is effectively open.
            if c_broad or v_broad:
                detail_bits: list[str] = []
                if c_broad:
                    detail_bits.append(f"consumer broad ({'; '.join(c_broad_reasons)})")
                if v_broad:
                    detail_bits.append(f"provider broad ({'; '.join(v_broad_reasons)})")
                checks_failed.append({
                    "check":  "whitelist_only",
                    "title":  "Risky port not whitelisted to a narrow pair",
                    "detail": (
                        f"{proto}/{port} ({name}) ALLOW from "
                        f"'{shorten(c_full)}' → '{shorten(v_full)}' — "
                        f"{'; '.join(detail_bits)}."
                    ),
                })

            # --- CHECK #3: ADM-discovered ---------------------------------
            # Non-primary (draft / secondary) workspace OR rule originated
            # from default_policies (ADM auto-suggested) → red flag.
            if (not p.get("primary")) or p.get("origin") == "default":
                checks_failed.append({
                    "check":  "adm_flag",
                    "title":  "Risky port appears in an ADM/draft policy",
                    "detail": (
                        f"{proto}/{port} ({name}) appears in workspace "
                        f"'{p.get('workspace')}' (primary={p.get('primary')}, "
                        f"origin={p.get('origin')}). Review before promoting."
                    ),
                })

            # --- CHECK #4: PCI DSS boundary -------------------------------
            # 22/3389/445 crossing the CDE boundary in either direction.
            if (proto, port) in PCI_RESTRICTED_PORTS:
                if (c_cde and not v_cde) or (v_cde and not c_cde):
                    direction = (
                        f"non-CDE → CDE ('{shorten(c_full)}' → '{shorten(v_full)}')"
                        if v_cde else
                        f"CDE → non-CDE ('{shorten(c_full)}' → '{shorten(v_full)}')"
                    )
                    checks_failed.append({
                        "check":  "pci_boundary",
                        "title":  "PCI DSS scope violation",
                        "detail": (
                            f"{proto}/{port} ({name}) crosses CDE boundary "
                            f"({direction}). Automatic audit finding."
                        ),
                    })

            if checks_failed:
                findings.append({
                    "workspace":       p.get("workspace"),
                    "workspace_id":    p.get("workspace_id"),
                    "policy_id":       p.get("id"),
                    "rank":            p.get("rank"),
                    "primary":         p.get("primary"),
                    "enforced":        p.get("enforced"),
                    "origin":          p.get("origin"),
                    "consumer":        c_full,
                    "consumer_short":  shorten(c_full),
                    "consumer_external": c_external,
                    "consumer_broad":  c_broad,
                    "consumer_cde":    c_cde,
                    "consumer_workloads": len(c_wls),
                    "provider":        v_full,
                    "provider_short":  shorten(v_full),
                    "provider_external": v_external,
                    "provider_broad":  v_broad,
                    "provider_cde":    v_cde,
                    "provider_workloads": len(v_wls),
                    "proto":           proto,
                    "port":            port,
                    "port_range":      list(port_range),
                    "tier":            tier,
                    "service":         name,
                    "why_risky":       why,
                    "checks":          checks_failed,
                    "human_ports":     fmt_ports_human(p.get("l4_params") or []),
                })
    return findings


# =============================================================================
# Reporting
# =============================================================================

TIER_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
CHECK_LABELS = {
    "east_west":       "East-West risky port",
    "whitelist_only":  "Broad scope (whitelist-only violation)",
    "adm_flag":        "ADM-discovered / draft",
    "pci_boundary":    "PCI DSS boundary",
}


# =============================================================================
# Flow-centric aggregation (Risk Matrix view)
# =============================================================================

def aggregate_into_flows(findings: list[dict]) -> list[dict]:
    """
    Collapse per-port findings into per-flow rows for the Risk Matrix.

    Grouping key is (workspace, consumer_full, provider_full) — i.e. the
    same allow rule (one workspace, one consumer scope, one provider scope)
    produces ONE row no matter how many risky ports it opens. Two
    workspaces authoring the same flow produce TWO rows so the trail back
    to the policy is preserved (per user choice: keep_separate).

    For each flow we surface:
      * the union of all risky ports allowed (deduped, tier-sorted)
      * the highest-tier (worst) port -> drives the row colour
      * blast_radius = consumer_workloads * provider_workloads
        (upper bound on how many host-pair combinations a single
        compromise could cross — order-of-magnitude only, not a precise
        attack count).
      * union of failed-check codes across all ports in the flow.
      * a 1-line "why_risky" sentence built from the worst service +
        the count of additional services if any.

    Returned list is sorted by blast_radius DESC so the worst-case flows
    surface first.
    """
    by_flow: dict[tuple[str, str, str], dict] = {}

    for f in findings:
        key = (f["workspace"], f["consumer"], f["provider"])
        flow = by_flow.get(key)
        if flow is None:
            flow = {
                "workspace":          f["workspace"],
                "workspace_id":       f.get("workspace_id", ""),
                "consumer":           f["consumer"],
                "consumer_short":     f["consumer_short"],
                "consumer_workloads": f["consumer_workloads"],
                "consumer_broad":     f["consumer_broad"],
                "consumer_external":  f["consumer_external"],
                "consumer_cde":       f["consumer_cde"],
                "provider":           f["provider"],
                "provider_short":     f["provider_short"],
                "provider_workloads": f["provider_workloads"],
                "provider_broad":     f["provider_broad"],
                "provider_external":  f["provider_external"],
                "provider_cde":       f["provider_cde"],
                "ports":              [],         # list of {proto,port,service,tier,why}
                "checks":             set(),      # union of check codes
                "primary":            f["primary"],
                "origin":             f["origin"],
                "tier":               f["tier"],  # will be tightened below
                "blast_radius":       max(1, f["consumer_workloads"]) *
                                      max(1, f["provider_workloads"]),
            }
            by_flow[key] = flow

        flow["ports"].append({
            "proto":   f["proto"],
            "port":    f["port"],
            "service": f["service"],
            "tier":    f["tier"],
            "why":     f["why_risky"],
        })
        for c in f["checks"]:
            flow["checks"].add(c["check"])
        # The flow's effective tier is the worst (lowest TIER_ORDER index)
        # of any of its ports.
        if TIER_ORDER.get(f["tier"], 9) < TIER_ORDER.get(flow["tier"], 9):
            flow["tier"] = f["tier"]

    # Finalise: dedupe ports, sort by tier, build a one-line "why".
    flows = list(by_flow.values())
    for fl in flows:
        seen = set()
        unique_ports = []
        for p in fl["ports"]:
            k = (p["proto"], p["port"])
            if k not in seen:
                seen.add(k)
                unique_ports.append(p)
        unique_ports.sort(key=lambda p: (TIER_ORDER.get(p["tier"], 9), p["proto"], p["port"]))
        fl["ports"] = unique_ports
        fl["checks"] = sorted(fl["checks"])

        worst = unique_ports[0]
        services = sorted({p["service"] for p in unique_ports})
        if len(services) == 1:
            fl["why_short"] = f"{services[0]} — {worst['why']}"
        else:
            other = len(services) - 1
            fl["why_short"] = (
                f"{worst['service']} (+{other} more service{'s' if other != 1 else ''}) — "
                f"{worst['why']}"
            )

    flows.sort(key=lambda fl: (-fl["blast_radius"], TIER_ORDER.get(fl["tier"], 9), fl["consumer_short"]))
    return flows


def render_markdown(findings: list[dict], context: dict) -> str:
    by_tier   = collections.Counter(f["tier"] for f in findings)
    by_check  = collections.Counter(c["check"] for f in findings for c in f["checks"])
    by_ws     = collections.Counter(f["workspace"] for f in findings)

    lines = [
        f"# CSW Risky-Port Audit — {context['root_scope']}",
        "",
        f"- **Cluster:** `{context['cluster']}`",
        f"- **Run date:** {context['date']}  ({context['timestamp']})",
        f"- **Policies analysed:** {context['n_policies']} across {context['n_workspaces']} workspaces",
        f"- **Total findings:** {len(findings)}",
        f"- **CDE workloads detected:** {context['n_cde']} via `{context['pci_field']} == {context['pci_value']}`",
        "",
        "## Findings by tier",
        "",
        "| Tier | Count |",
        "|---|---|",
    ]
    for tier in ("CRITICAL", "HIGH", "MEDIUM"):
        lines.append(f"| {tier} | {by_tier.get(tier, 0)} |")

    lines += [
        "",
        "## Findings by check",
        "",
        "| Check | Count |",
        "|---|---|",
    ]
    for k, label in CHECK_LABELS.items():
        lines.append(f"| {label} | {by_check.get(k, 0)} |")

    lines += ["", "## Findings by workspace", "", "| Workspace | Count |", "|---|---|"]
    for ws, n in by_ws.most_common():
        lines.append(f"| `{ws}` | {n} |")

    # ── Flow Risk Matrix (one row per consumer→provider→workspace) ────────
    flows = aggregate_into_flows(findings)
    lines += [
        "",
        "## Flow Risk Matrix",
        "",
        f"_{len(flows)} unique consumer→provider flows allowing one or more risky ports, "
        "sorted by blast radius (consumer\\_wls × provider\\_wls) descending._",
        "",
        "| Tier | Consumer (wls) | → | Provider (wls) | Risky ports allowed | Blast radius | Why risky | Failed checks | Workspace |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for fl in flows:
        ports_str = " · ".join(f"`{p['proto']}/{p['port']}` {p['service']}" for p in fl["ports"])
        checks_str = ", ".join(CHECK_LABELS.get(c, c) for c in fl["checks"])
        cde_marker = ""
        if fl["consumer_cde"]:
            cde_marker += " 🛡️CDE-c"
        if fl["provider_cde"]:
            cde_marker += " 🛡️CDE-p"
        lines.append(
            f"| **{fl['tier']}**{cde_marker} "
            f"| `{fl['consumer_short']}` ({fl['consumer_workloads']}) "
            f"| → "
            f"| `{fl['provider_short']}` ({fl['provider_workloads']}) "
            f"| {ports_str} "
            f"| {fl['blast_radius']:,} "
            f"| {fl['why_short']} "
            f"| {checks_str} "
            f"| `{fl['workspace']}` |"
        )

    lines += ["", "## Detailed findings", ""]

    sorted_findings = sorted(
        findings,
        key=lambda f: (TIER_ORDER.get(f["tier"], 9), f["workspace"], f["proto"], f["port"]),
    )
    for f in sorted_findings:
        lines += [
            f"### [{f['tier']}] {f['proto']}/{f['port']} ({f['service']}) — `{f['workspace']}`",
            "",
            f"- **Consumer:** `{f['consumer_short']}`  *(workloads={f['consumer_workloads']}, "
            f"broad={f['consumer_broad']}, external={f['consumer_external']}, cde={f['consumer_cde']})*",
            f"- **Provider:** `{f['provider_short']}`  *(workloads={f['provider_workloads']}, "
            f"broad={f['provider_broad']}, external={f['provider_external']}, cde={f['provider_cde']})*",
            f"- **Why risky:** {f['why_risky']}",
            f"- **Origin:** workspace primary={f['primary']}, enforced={f['enforced']}, origin={f['origin']}",
            "- **Failed checks:**",
        ]
        for c in f["checks"]:
            lines.append(f"  - **{CHECK_LABELS.get(c['check'], c['check'])}** — {c['detail']}")
        lines.append("")
    return "\n".join(lines)


# ── HTML rendering ────────────────────────────────────────────────────────

def _h(s: Any) -> str:
    """HTML-escape any value for safe embedding in templates.

    All user-controlled strings (scope names, workspace names, finding
    details) flow through this. Prevents stored/rendered XSS in the report
    if a CSW scope or annotation contains hostile characters.
    """
    return html.escape("" if s is None else str(s), quote=True)


def render_html(findings: list[dict], context: dict) -> str:
    by_tier  = collections.Counter(f["tier"] for f in findings)
    by_check = collections.Counter(c["check"] for f in findings for c in f["checks"])
    by_ws    = collections.Counter(f["workspace"] for f in findings)

    sorted_findings = sorted(
        findings,
        key=lambda f: (TIER_ORDER.get(f["tier"], 9), f["workspace"], f["proto"], f["port"]),
    )

    # Flow-aggregated view powers the new "Flow Risk Matrix" section. We
    # keep the per-finding view (sorted_findings) for the drill-down table
    # below, so users get both the executive picture and the raw evidence.
    flows = aggregate_into_flows(findings)

    tier_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04"}
    tier_class = {"CRITICAL": "crit",    "HIGH": "high",    "MEDIUM": "med"}
    check_color = {
        "east_west":      "#dc2626",
        "whitelist_only": "#ea580c",
        "adm_flag":       "#9333ea",
        "pci_boundary":   "#0f766e",
    }

    # ── Build the Flow Risk Matrix rows ──────────────────────────────────
    # Each row already represents a single (consumer→provider→workspace)
    # tuple; the cell content packs the per-port detail into colored pills.
    flow_rows: list[str] = []
    for fl in flows:
        port_pills = "".join(
            f'<span class="portpill {tier_class[p["tier"]]}" '
            f'title="{_h(p["service"])} — {_h(p["why"])}">'
            f'{_h(p["proto"])}/{_h(p["port"])} {_h(p["service"])}</span>'
            for p in fl["ports"]
        )
        check_pills = "".join(
            f'<span class="cpill" style="background:{check_color.get(c, "#475569")}">'
            f'{_h(CHECK_LABELS.get(c, c))}</span>'
            for c in fl["checks"]
        )
        cde_badges = ""
        if fl["consumer_cde"]:
            cde_badges += '<span class="badge teal">consumer in CDE</span>'
        if fl["provider_cde"]:
            cde_badges += '<span class="badge teal">provider in CDE</span>'
        # Consumer/provider sub-line shows broad/external/CDE flags so the
        # reader can tell which side is the "wide-open" side at a glance.
        c_flags = []
        if fl["consumer_broad"]:    c_flags.append("broad")
        if fl["consumer_external"]: c_flags.append("external")
        v_flags = []
        if fl["provider_broad"]:    v_flags.append("broad")
        if fl["provider_external"]: v_flags.append("external")
        c_flag_str = (" · " + " · ".join(c_flags)) if c_flags else ""
        v_flag_str = (" · " + " · ".join(v_flags)) if v_flags else ""
        flow_rows.append(
            f'<tr class="flow-row" data-tier="{_h(fl["tier"])}" '
            f'data-checks="{_h(",".join(fl["checks"]))}">'
            f'<td><span class="tpill" style="background:{tier_color[fl["tier"]]}">{_h(fl["tier"])}</span>'
            f'{cde_badges}</td>'
            f'<td><code>{_h(fl["consumer_short"])}</code><br>'
            f'<small>{_h(fl["consumer_workloads"])} wl{_h(c_flag_str)}</small></td>'
            f'<td class="flow-arrow">&rarr;</td>'
            f'<td><code>{_h(fl["provider_short"])}</code><br>'
            f'<small>{_h(fl["provider_workloads"])} wl{_h(v_flag_str)}</small></td>'
            f'<td>{port_pills}</td>'
            f'<td><span class="flow-blast">{fl["blast_radius"]:,}</span><br>'
            f'<small>{_h(fl["consumer_workloads"])} &times; {_h(fl["provider_workloads"])}</small></td>'
            f'<td style="font-size:.74rem;color:#334155">{_h(fl["why_short"])}</td>'
            f'<td>{check_pills}</td>'
            f'<td><code style="font-size:.7rem">{_h(fl["workspace"])}</code></td>'
            f'</tr>'
        )

    rows_html = []
    for f in sorted_findings:
        check_pills = "".join(
            f'<span class="cpill" style="background:{check_color.get(c["check"], "#475569")}">'
            f'{_h(CHECK_LABELS.get(c["check"], c["check"]))}</span>'
            for c in f["checks"]
        )
        # Each detail line is escaped; only our own static markup is raw HTML.
        details = "".join(
            f'<li><strong>{_h(CHECK_LABELS.get(c["check"], c["check"]))}:</strong> {_h(c["detail"])}</li>'
            for c in f["checks"]
        )
        cde_badges = ""
        if f["consumer_cde"]:
            cde_badges += '<span class="badge teal">consumer in CDE</span>'
        if f["provider_cde"]:
            cde_badges += '<span class="badge teal">provider in CDE</span>'
        rows_html.append(
            f'<tr class="finding-row" data-tier="{_h(f["tier"])}" '
            f'data-checks="{_h(",".join(c["check"] for c in f["checks"]))}">'
            f'<td><span class="tpill" style="background:{tier_color[f["tier"]]}">{_h(f["tier"])}</span></td>'
            f'<td><code>{_h(f["proto"])}/{_h(f["port"])}</code><br><small>{_h(f["service"])}</small></td>'
            f'<td><code>{_h(f["consumer_short"])}</code><br>'
            f'<small>{_h(f["consumer_workloads"])} wl{" · broad" if f["consumer_broad"] else ""}'
            f'{" · external" if f["consumer_external"] else ""}</small></td>'
            f'<td><code>{_h(f["provider_short"])}</code><br>'
            f'<small>{_h(f["provider_workloads"])} wl{" · broad" if f["provider_broad"] else ""}'
            f'{" · external" if f["provider_external"] else ""}</small></td>'
            f'<td><code>{_h(f["workspace"])}</code><br>'
            f'<small>primary={_h(f["primary"])} · origin={_h(f["origin"])}</small></td>'
            f'<td>{check_pills}{cde_badges}</td>'
            f'<td><details><summary>view</summary><ul style="margin:.4rem 0 .2rem 1rem">{details}</ul>'
            f'<div style="font-size:.7rem;color:#64748b">{_h(f["why_risky"])}</div></details></td>'
            f'</tr>'
        )

    summary_kpi = lambda label, val, color="#0f172a": (  # noqa: E731
        f'<div class="kpi"><div class="kval" style="color:{color}">{val}</div>'
        f'<div class="klbl">{label}</div></div>'
    )

    parts: list[str] = []
    parts.append(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSW Risky-Port Audit — {_h(context['root_scope'])}</title>
<style>
:root{{--bg:#f1f5f9;--card:#fff;--border:#dde4ee;--text:#0f172a;--text2:#475569}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}}
.hdr{{background:linear-gradient(135deg,#7f1d1d,#dc2626);color:#fff;padding:1.6rem 2rem}}
.hdr h1{{font-size:1.5rem;font-weight:700}}
.meta{{margin-top:.5rem;font-size:.8rem;opacity:.9;display:flex;flex-wrap:wrap;gap:1.4rem}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1px;background:var(--border)}}
.kpi{{background:#fff;padding:.9rem;text-align:center}}
.kval{{font-size:1.55rem;font-weight:700}}
.klbl{{font-size:.67rem;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;margin-top:.15rem}}
.wrap{{max-width:1240px;margin:1.5rem auto;padding:0 1.5rem;display:grid;gap:1.5rem}}
.card{{background:#fff;border:1px solid var(--border);border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.06);overflow:hidden}}
.ch{{padding:.85rem 1.2rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.5rem}}
.ch h2{{font-size:.95rem;font-weight:600}}
.cb{{padding:1rem 1.2rem}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
thead{{background:#f8fafc;position:sticky;top:0;z-index:1}}
th{{padding:.5rem .7rem;text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.4px;color:var(--text2);border-bottom:1px solid var(--border)}}
td{{padding:.5rem .7rem;border-bottom:1px solid #f1f5f9;vertical-align:top}}
tr:hover td{{background:#fafbff}}
code{{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:.74rem}}
.tpill{{padding:2px 9px;border-radius:999px;font-size:.68rem;font-weight:700;color:#fff}}
.cpill{{display:inline-block;padding:2px 7px;border-radius:5px;font-size:.66rem;color:#fff;margin:1px 2px 1px 0;font-weight:600}}
.badge{{display:inline-block;padding:2px 7px;border-radius:5px;font-size:.66rem;margin:1px 2px 1px 0;font-weight:600}}
.teal{{background:#ccfbf1;color:#115e59;border:1px solid #5eead4}}
.green{{background:#d1fae5;color:#065f46}}
.red{{background:#fee2e2;color:#991b1b}}
.filterbar{{display:flex;flex-wrap:wrap;gap:.35rem;padding:.65rem 1.2rem;border-bottom:1px solid var(--border);background:#f8fafc}}
.fbtn{{padding:.32rem .8rem;border-radius:6px;cursor:pointer;font-size:.76rem;font-weight:500;border:1px solid var(--border);background:#fff;color:var(--text)}}
.fbtn.on{{background:#dc2626;color:#fff;border-color:#dc2626}}
.portpill{{display:inline-block;padding:1px 6px;border-radius:4px;font-size:.7rem;font-family:'SF Mono',Menlo,monospace;margin:1px 2px 1px 0;border:1px solid transparent}}
.portpill.crit{{background:#fee2e2;color:#991b1b;border-color:#fca5a5}}
.portpill.high{{background:#ffedd5;color:#9a3412;border-color:#fdba74}}
.portpill.med{{background:#fef9c3;color:#854d0e;border-color:#fde047}}
.flow-arrow{{color:#94a3b8;font-weight:700;padding:0 .35rem}}
.flow-blast{{font-weight:700;color:#0f172a;font-family:'SF Mono',Menlo,monospace;font-size:.78rem}}
small{{color:#64748b;font-size:.7rem}}
footer{{text-align:center;padding:1.8rem 1rem;font-size:.73rem;color:var(--text2);border-top:1px solid var(--border);margin-top:1.5rem}}
</style></head><body>""")

    parts.append(
        f'<div class="hdr"><div style="max-width:1240px;margin:0 auto">'
        f'<h1>CSW Risky-Port Audit — {_h(context["root_scope"])}</h1>'
        f'<div class="meta"><span>Cluster: {_h(context["cluster"])}</span>'
        f'<span>Date: {_h(context["date"])}</span>'
        f'<span>Mode: AUDIT-ONLY (no policy changes pushed)</span></div>'
        f'</div></div>'
    )

    parts.append(
        '<div class="kpis">'
        + summary_kpi("Findings", len(findings))
        + summary_kpi("Critical", by_tier.get("CRITICAL", 0), "#dc2626")
        + summary_kpi("High",     by_tier.get("HIGH", 0),     "#ea580c")
        + summary_kpi("Medium",   by_tier.get("MEDIUM", 0),   "#ca8a04")
        + summary_kpi("East-West",     by_check.get("east_west", 0),      "#dc2626")
        + summary_kpi("Broad scope",   by_check.get("whitelist_only", 0), "#ea580c")
        + summary_kpi("ADM/draft",     by_check.get("adm_flag", 0),       "#9333ea")
        + summary_kpi("PCI boundary",  by_check.get("pci_boundary", 0),   "#0f766e")
        + summary_kpi("Workspaces",    context["n_workspaces"])
        + summary_kpi("CDE workloads", context["n_cde"], "#0f766e")
        + '</div>'
    )

    parts.append('<div class="wrap">')

    # ── Methodology ──
    parts.append(
        '<div class="card"><div class="ch"><span>&#x2139;</span><h2>Methodology &amp; thresholds</h2></div>'
        '<div class="cb" style="font-size:.82rem;color:#334155">'
        '<p style="margin-bottom:.5rem">An ALLOW policy generates a finding when the (proto, port) it permits '
        'is in the risk catalog AND it fails one or more of the four checks below:</p>'
        '<ul style="margin-left:1.2rem">'
        '<li><strong>East-West:</strong> consumer and provider are both internal (neither is Internet/External).</li>'
        f'<li><strong>Whitelist-only:</strong> consumer or provider is broad — leaf name in '
        f'<code>{_h(", ".join(BROAD_NAME_HINTS))}</code>, scope depth &le; <code>{BROAD_DEPTH_THRESHOLD}</code>, '
        f'or workload count &gt; <code>{BROAD_WORKLOAD_THRESHOLD}</code>.</li>'
        '<li><strong>ADM/draft:</strong> workspace is non-primary OR rule originated from <code>default_policies</code>.</li>'
        '<li><strong>PCI boundary:</strong> TCP/22, TCP/3389, or TCP/445 crosses a CDE boundary. CDE is detected via '
        f'inventory annotation <code>{_h(context["pci_field"])} == {_h(context["pci_value"])}</code>.</li>'
        '</ul></div></div>'
    )

    # ── Flow Risk Matrix (THE main risk view) ────────────────────────────
    # One row per consumer→provider→workspace, with all risky ports they
    # share collapsed into a single cell. Sorted by blast radius desc so
    # the worst flows surface first. This is the table customers should
    # screenshot.
    parts.append(
        '<div class="card">'
        '<div class="ch"><span>&#x1F525;</span><h2>Flow Risk Matrix &mdash; '
        'consumer &rarr; provider over risky port/protocol</h2></div>'
        '<div class="cb" style="font-size:.78rem;color:#475569;border-bottom:1px solid var(--border)">'
        f'<strong>{len(flows)}</strong> unique consumer&rarr;provider flows allow at least one risky port. '
        'Each row collapses every risky port that flow opens. <strong>Blast radius</strong> = '
        'consumer workloads &times; provider workloads (upper bound on host-pair combinations a single '
        'compromise could cross). Sorted by blast radius descending &mdash; worst-case first.'
        '</div>'
        '<div class="filterbar">'
        '<button class="fbtn on" data-flow-filter="all">All</button>'
        '<button class="fbtn" data-flow-filter="tier:CRITICAL">Critical</button>'
        '<button class="fbtn" data-flow-filter="tier:HIGH">High</button>'
        '<button class="fbtn" data-flow-filter="tier:MEDIUM">Medium</button>'
        '<button class="fbtn" data-flow-filter="check:east_west">East-West</button>'
        '<button class="fbtn" data-flow-filter="check:whitelist_only">Broad scope</button>'
        '<button class="fbtn" data-flow-filter="check:adm_flag">ADM/draft</button>'
        '<button class="fbtn" data-flow-filter="check:pci_boundary">PCI</button>'
        '</div>'
        '<div style="overflow-x:auto"><table><thead><tr>'
        '<th>Tier</th><th>Consumer (wls)</th><th></th><th>Provider (wls)</th>'
        '<th>Risky ports allowed</th><th>Blast radius</th><th>Why risky</th>'
        '<th>Failed checks</th><th>Workspace</th>'
        '</tr></thead><tbody>'
        + ("".join(flow_rows) if flow_rows else
           '<tr><td colspan="9" style="text-align:center;padding:2rem;color:#16a34a">No risky flows '
           '&mdash; every ALLOW policy passes all four checks.</td></tr>')
        + '</tbody></table></div></div>'
    )

    # ── Findings table with filter chips ──
    parts.append(
        '<div class="card">'
        '<div class="ch"><span>&#9888;</span><h2>Findings</h2></div>'
        '<div class="filterbar">'
        '<button class="fbtn on" data-filter="all">All</button>'
        '<button class="fbtn" data-filter="tier:CRITICAL">Critical</button>'
        '<button class="fbtn" data-filter="tier:HIGH">High</button>'
        '<button class="fbtn" data-filter="tier:MEDIUM">Medium</button>'
        '<button class="fbtn" data-filter="check:east_west">East-West</button>'
        '<button class="fbtn" data-filter="check:whitelist_only">Broad scope</button>'
        '<button class="fbtn" data-filter="check:adm_flag">ADM/draft</button>'
        '<button class="fbtn" data-filter="check:pci_boundary">PCI</button>'
        '</div>'
        '<div style="overflow-x:auto"><table><thead><tr>'
        '<th>Tier</th><th>Port</th><th>Consumer</th><th>Provider</th>'
        '<th>Workspace</th><th>Failed checks</th><th>Detail</th>'
        '</tr></thead><tbody>'
        + ("".join(rows_html) if rows_html else
           '<tr><td colspan="7" style="text-align:center;padding:2rem;color:#16a34a">No findings — every '
           'risky-port ALLOW policy passes all four checks.</td></tr>')
        + '</tbody></table></div></div>'
    )

    parts.append('</div>')  # /wrap

    parts.append(
        f'<footer><strong>CSW Risky-Port Audit</strong> &mdash; audit-only, '
        f'no policy changes pushed &nbsp;|&nbsp; Cluster: <code>{_h(context["cluster"])}</code> '
        f'&nbsp;|&nbsp; {_h(context["date"])}</footer>'
    )

    # Filter chips: each card scopes its own filter buttons to its own
    # rows via data-attribute name. Findings table uses data-filter +
    # .finding-row; Flow Risk Matrix uses data-flow-filter + .flow-row.
    parts.append(
        '<script>'
        # --- Findings table chips ---
        'document.querySelectorAll(".fbtn[data-filter]").forEach(b=>b.addEventListener("click",()=>{'
        'document.querySelectorAll(".fbtn[data-filter]").forEach(x=>x.classList.remove("on"));'
        'b.classList.add("on");'
        'var f=b.dataset.filter;'
        'document.querySelectorAll(".finding-row").forEach(r=>{'
        'if(f==="all"){r.style.display="";return}'
        'var [k,v]=f.split(":");'
        'if(k==="tier"){r.style.display=(r.dataset.tier===v)?"":"none";}'
        'else if(k==="check"){r.style.display=(r.dataset.checks||"").split(",").includes(v)?"":"none";}'
        '});}));'
        # --- Flow risk matrix chips ---
        'document.querySelectorAll(".fbtn[data-flow-filter]").forEach(b=>b.addEventListener("click",()=>{'
        'document.querySelectorAll(".fbtn[data-flow-filter]").forEach(x=>x.classList.remove("on"));'
        'b.classList.add("on");'
        'var f=b.dataset.flowFilter;'
        'document.querySelectorAll(".flow-row").forEach(r=>{'
        'if(f==="all"){r.style.display="";return}'
        'var [k,v]=f.split(":");'
        'if(k==="tier"){r.style.display=(r.dataset.tier===v)?"":"none";}'
        'else if(k==="check"){r.style.display=(r.dataset.checks||"").split(",").includes(v)?"":"none";}'
        '});}));'
        '</script></body></html>'
    )
    return "".join(parts)


# =============================================================================
# Entry point
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Audit CSW policies for risky-port exposure (audit-only).",
    )
    ap.add_argument("--use-cache", action="store_true",
                    help="Reuse snapshots/policies-all.json + scope-workloads.json if present.")
    ap.add_argument("--no-html", action="store_true",
                    help="Skip the HTML report (write JSON + Markdown only).")
    ap.add_argument("--out", "-o", default=None,
                    help="HTML output path (default: reports/risky-port-audit-<date>.html).")
    ap.add_argument("--pci-field", default=os.environ.get("CSW_PCI_FIELD", "user_pci_scope"),
                    help="Inventory annotation field that marks CDE workloads "
                         "(default: user_pci_scope).")
    ap.add_argument("--pci-value", default=os.environ.get("CSW_PCI_VALUE", "true"),
                    help="Value the PCI annotation must equal to count as CDE (default: true).")
    ap.add_argument("--root-scope", default=os.environ.get("CSW_ROOT_SCOPE", ""),
                    help="Override the root scope name (default: auto-detect).")
    args = ap.parse_args()

    # snapshots/ holds the inputs (cached policy/workload data) AND the
    # JSON+Markdown outputs. reports/ holds the HTML output. Both are
    # created up-front so that the script never half-runs and leaves the
    # caller wondering whether anything was produced.
    os.makedirs("snapshots", exist_ok=True)
    os.makedirs("reports",   exist_ok=True)

    cluster = os.environ.get("CSW_API_URL", "?").replace("https://", "").rstrip("/")
    print(f"\n📡  Connecting to: {cluster}")
    print(f"📅  Run date: {DATE_TAG}\n")

    # ── Step 1: policies + workloads ──────────────────────────────────────
    # Either reuse the snapshot files emitted by download_policies.py
    # (fast, offline) or pull fresh data from the cluster (slower, current).
    # `--use-cache` only takes effect if BOTH snapshot files are present.
    cached_pol = load_cached_snapshot("snapshots/policies-all.json") if args.use_cache else None
    cached_wls = load_cached_snapshot("snapshots/scope-workloads.json") if args.use_cache else None

    if cached_pol and cached_wls:
        print("  [1/3] Loaded policies + workloads from cache")
        # Older snapshots from download_policies.py omit some keys; backfill.
        for p in cached_pol:
            p.setdefault("primary", True)
            p.setdefault("origin", "absolute")
            p.setdefault("workspace_id", "")
            p.setdefault("enforced", False)
            p.setdefault("id", f"{p.get('workspace','?')}-{p.get('rank','?')}")
            # If l4_params wasn't preserved in the cache, parse from human ports.
            if "l4_params" not in p:
                p["l4_params"] = []
        policies = cached_pol
        scope_workloads = cached_wls
        n_workspaces = len({p["workspace"] for p in policies})
        root_scope = args.root_scope or "Root"
    else:
        print("  [1/3] Fetching workspaces and policies from cluster")
        workspaces, policies, _origin = fetch_workspaces_and_policies()
        n_workspaces = len(workspaces)
        root_scope = args.root_scope or fetch_root_scope_name()
        print(f"        Root scope: '{root_scope}'")
        print("\n  [2/3] Fetching workloads per scope")
        scope_workloads = fetch_scope_workload_counts(policies, root_scope)

    # ── Step 2: CDE membership ────────────────────────────────────────────
    print("\n  [2/3] Detecting CDE workloads")
    cde_keys = fetch_cde_workload_keys(args.pci_field, args.pci_value, root_scope or "Root")

    # ── Step 3: run the four checks ───────────────────────────────────────
    print("\n  [3/3] Running risk checks against policies")
    findings = audit_policies(policies, scope_workloads, cde_keys)
    print(f"        Generated {len(findings)} findings")

    # ── Persist outputs ───────────────────────────────────────────────────
    context = {
        "cluster":      cluster,
        "root_scope":   root_scope or "Root",
        "date":         DATE_TAG,
        "timestamp":    TIMESTAMP,
        "n_policies":   len(policies),
        "n_workspaces": n_workspaces,
        "n_cde":        len(cde_keys),
        "pci_field":    args.pci_field,
        "pci_value":    args.pci_value,
    }

    json_path = "snapshots/risky-port-findings.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"context": context, "findings": findings}, f, indent=2)
    print(f"\n✅  JSON findings:    {json_path}")

    md_path = "snapshots/risky-port-audit.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(findings, context))
    print(f"✅  Markdown report:  {md_path}")

    if not args.no_html:
        html_path = args.out or f"reports/risky-port-audit-{DATE_TAG}.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(render_html(findings, context))
        size_kb = os.path.getsize(html_path) // 1024
        print(f"✅  HTML report:      {html_path}  ({size_kb} KB)")
        print("\n   Open in browser:")
        print(f"   open {html_path}   (macOS)")
        print(f"   start {html_path}  (Windows)")

    # ── Console summary ───────────────────────────────────────────────────
    by_tier  = collections.Counter(f["tier"] for f in findings)
    by_check = collections.Counter(c["check"] for f in findings for c in f["checks"])
    print("\n── Summary ──")
    for tier in ("CRITICAL", "HIGH", "MEDIUM"):
        print(f"  {tier:9s} {by_tier.get(tier, 0)}")
    print()
    for k, label in CHECK_LABELS.items():
        print(f"  {label:38s} {by_check.get(k, 0)}")


if __name__ == "__main__":
    main()
