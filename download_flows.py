#!/usr/bin/env python3
"""
Quick summary: Exports raw flow records between two scopes (configurable
consumer/provider filter, NetFlow excluded by default) to CSV via flowsearch.

download_flows.py — Download filtered flow data from any CSW cluster
----------------------------------------------------------------------
Queries the CSW flowsearch API with a configurable scope-based filter
and downloads all matching flows to CSV. Scope names are
cluster-specific; pass the full scope strings from your environment.

Default filter (two-scope segmentation use-case):
  - Flows where EITHER endpoint is in scope A (consumer side)
  - AND EITHER endpoint is in scope B (provider side)
  - EXCLUDING flows sourced from NetFlow collectors (unless --include-netflow)

This matches a typical CSW UI filter for traffic between two scopes:
  ( Consumer scope = ...YourScopeA
    OR Provider scope = ...YourScopeA )
  AND ( Consumer scope = ...YourScopeB
    OR Provider scope = ...YourScopeB )
  AND NOT ( Consumer NETFLOW IDENTIFIED = TRUE
    OR Provider NETFLOW IDENTIFIED = TRUE )

Usage (run without scope flags once to print all scopes from the cluster):
    python3 download_flows.py
    python3 download_flows.py --consumer-scope "your-cluster:Internal:YourScopeA" \
        --provider-scope "your-cluster:Internal:YourScopeB"
    python3 download_flows.py --hours 48 --consumer-scope "your-cluster:Internal:YourScopeA" \
        --provider-scope "your-cluster:Internal:YourScopeB"
    python3 download_flows.py --include-netflow --consumer-scope "your-cluster:Internal:YourScopeA" \
        --provider-scope "your-cluster:Internal:YourScopeB"

``--root-scope`` is optional: when omitted, ``get_root_scope()`` queries
``GET /openapi/v1/app_scopes`` and picks the scope with no
``parent_app_scope_id`` (the cluster root), matching
``query_long_lived_processes.get_root_scope``.

When ``--consumer-scope`` or ``--provider-scope`` is omitted,
``discover_scopes()`` lists every scope ``name`` from the same endpoint so
you can copy the exact strings your cluster uses.

Output:
    snapshots/flows-<tag>-<date>.csv
"""

import argparse
import csv
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csw_api

csw_api._load_dotenv()

DATE_TAG = datetime.now().strftime("%Y-%m-%d")
BATCH_SIZE = 100

# Default scope names — set to None so the user must provide consumer and
# provider scopes via CLI arguments (each CSW cluster has different names).
# Omitting either flag triggers discover_scopes() + a printed listing instead
# of a download. Root scope defaults to None and is resolved at runtime via
# get_root_scope() (GET /openapi/v1/app_scopes, row with no parent_app_scope_id).
DEFAULT_CONSUMER_SCOPE = None
DEFAULT_PROVIDER_SCOPE = None
DEFAULT_ROOT_SCOPE = None

# CSV columns to export — covers network 5-tuple, scope membership,
# traffic volume, policy verdicts, process visibility, TLS metadata,
# latency, threat indicators, and user-defined annotations.
CSV_FIELDS = [
    "timestamp", "start_timestamp",
    "src_address", "src_hostname", "src_port", "src_scope_name",
    "dst_address", "dst_hostname", "dst_port", "dst_scope_name",
    "proto", "service_name",
    "fwd_bytes", "fwd_pkts", "rev_bytes", "rev_pkts",
    "fwd_policy_permitted", "fwd_policy_rejected", "fwd_policy_escaped",
    "src_process_name", "dst_process_name",
    "fwd_process_string", "rev_process_string",
    "src_is_internal", "dst_is_internal",
    "dst_domain_names", "dst_country",
    "tls_version", "tls_cipher",
    "fwd_tcp_handshake_usec", "total_network_latency_usec",
    "is_malicious_flow", "consumer_malicious", "provider_malicious",
    "consumer_sensor_type", "provider_sensor_type",
    "src_logged_in_user", "dst_logged_in_user",
    "user_src_NETFLOW_IDENTIFIED", "user_dst_NETFLOW_IDENTIFIED",
]


def discover_scopes():
    """Return all application scopes from ``GET /openapi/v1/app_scopes``.

    Used when ``--consumer-scope`` or ``--provider-scope`` is missing: the
    main program prints these rows so you can pick two full ``name`` values.

    Each row includes the full hierarchical ``name`` string (used with
    ``--consumer-scope`` / ``--provider-scope``), ``id``, and
    ``parent_app_scope_id`` for tree structure.

    Returns:
        tuple[ list[dict] | None, str | None ]: ``(scopes, None)`` on success
        (``scopes`` may be an empty list). ``(None, err)`` if the HTTP call
        failed or the payload was not a list.
    """
    r = csw_api.make_request("GET", "/openapi/v1/app_scopes")
    if r.get("status") != 200:
        err = r.get("data", {})
        if isinstance(err, dict):
            msg = str(err.get("error", err))
        else:
            msg = str(err)
        return None, f"HTTP {r.get('status')}: {msg}"
    data = r.get("data", [])
    if not isinstance(data, list):
        return None, "Unexpected response: app_scopes body is not a JSON list"
    return data, None


def get_root_scope():
    """Discover the cluster root scope name dynamically.

    The flowsearch API requires a valid ``scopeName`` parameter. Rather than
    hard-coding it (each cluster has a different root scope name), we query
    ``GET /openapi/v1/app_scopes`` and pick the row with no
    ``parent_app_scope_id`` — that is the root of the scope tree. This mirrors
    ``query_long_lived_processes.get_root_scope`` (same endpoint and parent
    check). ``discover_scopes()`` is a separate helper for listing scopes when
    CLI scope flags are omitted.

    Returns:
        str: Root scope name (e.g. cluster id string), or ``Default`` if the
        API call failed or no root row was found.
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


def build_scope_filter(consumer_scope, provider_scope, include_netflow=False):
    """Build a nested CSW flowsearch filter from scope names.

    The CSW flow data stores scope membership as arrays (each endpoint
    belongs to multiple scopes in the hierarchy).  The "contains" filter
    type checks whether the specified value appears anywhere in the array.

    Returns a dict suitable for the "filter" field of the flowsearch body.
    """
    filters = [
        # Clause 1: at least one endpoint must be in the consumer scope
        {
            "type": "or",
            "filters": [
                {"type": "contains", "field": "src_scope_name",
                 "value": consumer_scope},
                {"type": "contains", "field": "dst_scope_name",
                 "value": consumer_scope},
            ],
        },
        # Clause 2: at least one endpoint must be in the provider scope
        {
            "type": "or",
            "filters": [
                {"type": "contains", "field": "src_scope_name",
                 "value": provider_scope},
                {"type": "contains", "field": "dst_scope_name",
                 "value": provider_scope},
            ],
        },
    ]

    if not include_netflow:
        # Clause 3: exclude flows that were identified via NetFlow
        # (only keep agent-collected flows for higher fidelity)
        filters.append({
            "type": "not",
            "filter": {
                "type": "or",
                "filters": [
                    {"type": "eq", "field": "user_src_NETFLOW_IDENTIFIED",
                     "value": "TRUE"},
                    {"type": "eq", "field": "user_dst_NETFLOW_IDENTIFIED",
                     "value": "TRUE"},
                ],
            },
        })

    return {"type": "and", "filters": filters}


def download_flows(flow_filter, root_scope, t0, t1):
    """Paginate through the flowsearch API and collect all matching flows.

    The CSW API returns at most BATCH_SIZE flows per call and provides an
    opaque "offset" token for cursor-based pagination.  We loop until
    either fewer than BATCH_SIZE results are returned (last page) or the
    offset token is absent.
    """
    all_flows = []
    offset = ""
    page = 0

    while True:
        page += 1
        body = {
            "t0": t0,
            "t1": t1,
            "filter": flow_filter,
            "scopeName": root_scope,
            "limit": BATCH_SIZE,
        }
        if offset:
            body["offset"] = offset

        r = csw_api.make_request("POST", "/openapi/v1/flowsearch", body=body)
        status = r.get("status")

        if status != 200:
            print(f"\n  API error on page {page}: HTTP {status}")
            err = r.get("data", {})
            if isinstance(err, dict):
                print(f"      {err.get('error', err)}")
            break

        data = r.get("data", {})
        if not isinstance(data, dict):
            break

        results = data.get("results", [])
        all_flows.extend(results)
        print(
            f"\r  Page {page}: +{len(results)} flows "
            f"(total: {len(all_flows):,})",
            end="", flush=True,
        )

        if len(results) < BATCH_SIZE:
            break

        offset = data.get("offset", "")
        if not offset:
            break

        time.sleep(0.2)

    print()
    return all_flows


def write_csv(flows, csv_path):
    """Write flow records to a CSV file.

    Array-valued fields (scope names, domain names) are joined with
    semicolons so the CSV remains one-row-per-flow.
    """
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=CSV_FIELDS, extrasaction="ignore",
        )
        writer.writeheader()
        for fl in flows:
            row = dict(fl)
            for key in ("dst_domain_names", "src_domain_names",
                        "src_scope_name", "dst_scope_name"):
                val = row.get(key)
                if isinstance(val, list):
                    row[key] = "; ".join(str(x) for x in val)
            writer.writerow(row)


def print_stats(flows):
    """Print a quick statistical summary of the downloaded flow data."""
    protos = {}
    ports = {}
    permitted = rejected = escaped = 0

    for fl in flows:
        p = fl.get("proto", "?")
        protos[p] = protos.get(p, 0) + 1

        port = str(fl.get("dst_port", "?"))
        ports[port] = ports.get(port, 0) + 1

        if fl.get("fwd_policy_permitted"):
            permitted += 1
        if fl.get("fwd_policy_rejected"):
            rejected += 1
        if fl.get("fwd_policy_escaped"):
            escaped += 1

    top_ports = sorted(ports.items(), key=lambda x: -x[1])[:10]

    print(f"\n  Quick stats:")
    print(f"      Protocols: "
          f"{dict(sorted(protos.items(), key=lambda x: -x[1]))}")
    print(f"      Top 10 ports: {dict(top_ports)}")
    print(f"      Permitted: {permitted:,} | "
          f"Rejected: {rejected:,} | Escaped: {escaped:,}")


def _print_available_scopes_and_exit(scopes, err):
    """When scope flags are missing, show what the cluster exposes and exit."""
    print("\n  --consumer-scope and --provider-scope are required to download flows.")
    print("  Pick two full ``name`` values from your cluster (see below).\n")
    if err:
        print(f"  Could not list scopes from /openapi/v1/app_scopes: {err}")
        print("  Check CSW_API_URL, CSW_API_KEY, and CSW_API_SECRET in your environment.\n")
        sys.exit(1)
    if not scopes:
        print("  The app_scopes API returned an empty list.\n")
    else:
        print("  Available application scopes (copy the full ``name`` into your flags):\n")
        for s in sorted(scopes, key=lambda x: (x.get("name") or "")):
            if not isinstance(s, dict):
                continue
            name = s.get("name", "")
            sid = s.get("id", "")
            parent = s.get("parent_app_scope_id")
            root_mark = " [ROOT]" if not parent else ""
            print(f"    {name}{root_mark}")
            print(f"        id={sid!r}  parent_app_scope_id={parent!r}")
        print()
    print("  Example:")
    print("    python3 download_flows.py \\")
    print('        --consumer-scope "your-cluster:Internal:YourScopeA" \\')
    print('        --provider-scope "your-cluster:Internal:YourScopeB"')
    print()
    print("  If you omit --root-scope, the cluster root is auto-detected from app_scopes")
    print("  (the scope with no parent_app_scope_id), same as query_long_lived_processes.py.")
    print()
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Download filtered flow data from any CSW cluster.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 download_flows.py
  python3 download_flows.py --consumer-scope "your-cluster:Internal:YourScopeA" \
      --provider-scope "your-cluster:Internal:YourScopeB"
  python3 download_flows.py --hours 48 --consumer-scope "your-cluster:Internal:YourScopeA" \
      --provider-scope "your-cluster:Internal:YourScopeB"
  python3 download_flows.py --include-netflow --tag "all-sources" \
      --consumer-scope "your-cluster:Internal:YourScopeA" \
      --provider-scope "your-cluster:Internal:YourScopeB"
        """,
    )
    parser.add_argument(
        "--consumer-scope",
        default=DEFAULT_CONSUMER_SCOPE,
        help="Full scope name for the consumer/source side of the filter "
             "(required; run without this flag to list scopes from the cluster)",
    )
    parser.add_argument(
        "--provider-scope",
        default=DEFAULT_PROVIDER_SCOPE,
        help="Full scope name for the provider/destination side of the filter "
             "(required; run without this flag to list scopes from the cluster)",
    )
    parser.add_argument(
        "--root-scope",
        default=DEFAULT_ROOT_SCOPE,
        help="Root scope for the flowsearch query (optional; when omitted, "
             "auto-detected via get_root_scope() / app_scopes)",
    )
    parser.add_argument(
        "--hours", type=int, default=24,
        help="Number of hours to look back (default: 24)",
    )
    parser.add_argument(
        "--include-netflow", action="store_true",
        help="Include NetFlow-sourced flows (excluded by default)",
    )
    parser.add_argument(
        "--tag",
        default=None,
        help="Custom tag for the output filename "
             "(default: derived from scope names)",
    )
    parser.add_argument(
        "--out", "-o",
        default=None,
        help="Full output CSV path (overrides --tag)",
    )
    args = parser.parse_args()

    # Require both endpoint scopes; if either is missing, list app_scopes and exit.
    # Auto-detection for *which* scopes to filter is intentionally not done:
    # every cluster uses different names, so we fetch discover_scopes() and
    # print the full ``name`` field for copy/paste into --consumer-scope /
    # --provider-scope.
    if not args.consumer_scope or not args.provider_scope:
        scopes, err = discover_scopes()
        _print_available_scopes_and_exit(scopes or [], err)

    # Resolve flowsearch root: explicit --root-scope wins; otherwise
    # auto-detect via get_root_scope() (GET app_scopes, row with no parent).
    if not args.root_scope:
        args.root_scope = get_root_scope()
        print(f"  Auto-discovered root scope: {args.root_scope}")

    os.makedirs("snapshots", exist_ok=True)

    # Time window — epoch seconds required by the CSW API
    t1 = int(time.time())
    t0 = t1 - (args.hours * 3600)

    # Derive a short label for the consumer scope
    consumer_short = args.consumer_scope.split(":")[-1]
    provider_short = args.provider_scope.split(":")[-1]
    file_tag = args.tag or f"{consumer_short}_x_{provider_short}"

    flow_filter = build_scope_filter(
        args.consumer_scope,
        args.provider_scope,
        include_netflow=args.include_netflow,
    )

    print(f"\n  Cluster: {os.environ.get('CSW_API_URL', '?')}")
    print(f"  Date: {DATE_TAG}")
    print(f"  Flow window: last {args.hours} hours\n")
    print(f"  Filter:")
    print(f"      (Consumer scope = ...{consumer_short}"
          f"  OR  Provider scope = ...{consumer_short})")
    print(f"      AND (Consumer scope = ...{provider_short}"
          f"  OR  Provider scope = ...{provider_short})")
    if not args.include_netflow:
        print(f"      AND NOT (NETFLOW IDENTIFIED = TRUE)")
    print()

    flows = download_flows(flow_filter, args.root_scope, t0, t1)

    if not flows:
        print("  No flows found matching the filter.")
        return

    csv_path = args.out or f"snapshots/flows-{file_tag}-{DATE_TAG}.csv"
    write_csv(flows, csv_path)

    size_mb = os.path.getsize(csv_path) / (1024 * 1024)
    print(f"\n  Saved {len(flows):,} flows to {csv_path} ({size_mb:.1f} MB)")

    print_stats(flows)


if __name__ == "__main__":
    main()
