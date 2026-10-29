#!/usr/bin/env python3
"""
Count CSW (Tetration) software agents / sensors installed on the cluster.

Reads credentials from `.env` next to this script (CSW_API_URL, CSW_API_KEY,
CSW_API_SECRET, optional CSW_VERIFY_SSL). Never hardcodes secrets.

The script paginates `/openapi/v1/sensors`, then summarises by:
  - total agent count
  - agent_type (e.g. ENFORCER, DEEP_VISIBILITY, ANY_VISIBILITY, ERSPAN, ...)
  - platform / OS (best-effort across schema variants)
  - current_sw_version
  - desired_state (REGISTERED, UNREGISTERED, DELETED, ...) when present

Usage:
    python3 count_agents.py
    python3 count_agents.py --json        # full JSON dump of summary
    python3 count_agents.py --page 200    # page size (default 500, max 1000)
"""

import argparse
import json
import os
import sys
from collections import Counter

import csw_api


SENSORS_PATH = "/openapi/v1/sensors"


def fetch_all_sensors(page_size: int = 500):
    """Page through /openapi/v1/sensors until the cluster stops returning results.

    The CSW OpenAPI uses `offset` cursors returned in the response. We follow
    that cursor; if the cluster simply returns a flat list we fall back to a
    single request.
    """
    sensors = []
    offset = None
    pages = 0
    while True:
        params = {"limit": page_size}
        if offset:
            params["offset"] = offset
        result = csw_api.make_request("GET", SENSORS_PATH, params=params)
        status = result.get("status")
        data = result.get("data")
        if status != 200:
            print(json.dumps({
                "error": "Sensor list request failed",
                "status": status,
                "reason": result.get("error"),
                "body": data,
            }, indent=2), file=sys.stderr)
            sys.exit(2)

        if isinstance(data, dict) and "results" in data:
            batch = data.get("results") or []
            sensors.extend(batch)
            offset = data.get("offset")
            pages += 1
            if not offset or not batch:
                break
        elif isinstance(data, list):
            sensors.extend(data)
            pages += 1
            break
        else:
            print(json.dumps({
                "error": "Unexpected response shape",
                "data": data,
            }, indent=2), file=sys.stderr)
            sys.exit(2)

        if pages > 200:
            print(json.dumps({"warning": "stopped after 200 pages as a safety cap"}), file=sys.stderr)
            break
    return sensors


def _first(record, *keys, default="unknown"):
    """Return the first non-empty value among the given keys (schema-tolerant)."""
    for k in keys:
        v = record.get(k)
        if v not in (None, "", []):
            return v
    return default


def summarise(sensors):
    """Group sensors into useful buckets for an at-a-glance install count."""
    by_type = Counter()
    by_platform = Counter()
    by_version = Counter()
    by_state = Counter()
    by_enforcement = Counter()
    by_data_plane = Counter()
    for s in sensors:
        # agent_type_str ("ENFORCER", "DEEP_VISIBILITY", ...) is the human label
        # surfaced by current CSW; fall back to the numeric enum for older builds.
        by_type[_first(s, "agent_type_str", "agent_type", "type")] += 1
        by_platform[_first(s, "platform", "host_name_os", "os_version", "os")] += 1
        by_version[_first(s, "current_sw_version", "sw_version", "version")] += 1
        by_state[_first(s, "desired_state", "agent_state", "state", default="n/a")] += 1
        enforce = s.get("enforcement_enabled")
        if enforce is not None:
            by_enforcement["enforcing" if enforce else "monitoring_only"] += 1
        dp = s.get("data_plane_disabled")
        if dp is not None:
            by_data_plane["disabled" if dp else "active"] += 1
    summary = {
        "total_agents_installed": len(sensors),
        "by_agent_type": dict(by_type.most_common()),
        "by_platform": dict(by_platform.most_common()),
        "by_software_version": dict(by_version.most_common()),
        "by_state": dict(by_state.most_common()),
    }
    if by_enforcement:
        summary["by_enforcement"] = dict(by_enforcement.most_common())
    if by_data_plane:
        summary["by_data_plane"] = dict(by_data_plane.most_common())
    return summary


def print_human(summary):
    """Compact, terminal-friendly version of the summary."""
    print(f"Total agents installed: {summary['total_agents_installed']}")
    sections = (
        ("By agent type",        "by_agent_type"),
        ("By enforcement mode",  "by_enforcement"),
        ("By data-plane status", "by_data_plane"),
        ("By state",             "by_state"),
        ("By platform / OS",     "by_platform"),
        ("By software version",  "by_software_version"),
    )
    for title, key in sections:
        bucket = summary.get(key) or {}
        if not bucket:
            continue
        print(f"\n{title}:")
        for name, count in bucket.items():
            print(f"  {count:>6}  {name}")


def main():
    parser = argparse.ArgumentParser(description="Count CSW agents installed on the configured cluster.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable summary.")
    parser.add_argument("--page", type=int, default=500, help="Page size for /sensors (default 500).")
    args = parser.parse_args()

    csw_api._load_dotenv()  # TLS CA bundle is handled centrally in csw_api.make_request()
    sensors = fetch_all_sensors(page_size=args.page)
    summary = summarise(sensors)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_human(summary)


if __name__ == "__main__":
    main()
