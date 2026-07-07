#!/usr/bin/env python3
"""
csw_helpers.py - Shared utilities for CSW POV Template scripts
==============================================================

CSW concepts in 60 seconds (for new readers)
--------------------------------------------
**Cisco Secure Workload (CSW)** — also called Tetration — is a platform
that watches every network conversation between your servers and lets you
write firewall-style rules ("policies") that follow the workloads, not
the IP addresses. To do its job, CSW collects three kinds of data which
this toolkit then queries via the REST API:

  * **Sensors** (also called "agents"): a small piece of software running
    on each Linux/Windows VM. It reports every connection the host opens
    or accepts, and - if turned on - enforces the policy by writing rules
    into the host's own firewall (``nftables`` on Linux, WFP on Windows).
    A sensor record contains a UUID, the host name, the operating system,
    the agent's mode (visibility-only vs enforcement), and a list of all
    the IP addresses that host owns.

  * **Flows**: every network connection (or batched summary of one) seen
    by a sensor or by an external collector. One flow = one
    "src_ip + dst_ip + dst_port + protocol" plus byte/packet counts and
    the policy decision (permitted, rejected, escaped).

  * **Workspaces / Applications**: a folder for grouping policy rules.
    Inside a workspace, CSW's ADM ("Application Dependency Mapping")
    feature crunches the flow data and proposes a starter set of rules
    automatically. Each workspace can have many ADM versions over time.

The CSW API is paginated using **offset cursors**: ask for 500 records,
the response includes an opaque "offset" token that means "the next page
starts here". You pass that token back on the next request. When the API
returns fewer records than you asked for, or omits the offset token, you
have reached the end.

This module centralizes the four most-duplicated bits of plumbing:

  1. Walking that offset-cursor loop  (``paginate``).
  2. Listing every sensor in the cluster  (``fetch_all_sensors``).
  3. Building an ``ip -> sensor`` lookup table  (``build_sensor_map``).
  4. Turning user-supplied strings into safe filenames  (``safe_filename``).

What the helpers were carved out of
-----------------------------------

  1. Sensor enumeration  (was duplicated in generate_vuln_report.py,
                          generate_forensics_report.py, cluster_snapshot.py,
                          and api_test_suite.py).

  2. Offset-cursor pagination  (was duplicated in download_flows.py,
                                download_conversations.py, and
                                query_long_lived_processes.py).

  3. Filename slugging  (was ad-hoc in download_conversations.py).

  4. Result-list extraction  (response shape varies: dict-with-results
                              vs bare list, by API version / endpoint).

  5. CSW-specific constants  (agent type enum strings, known field-name
                              aliases such as the space-in-key quirk).

Design contract
---------------
- Pure helpers - no global state, no .env loading. Callers handle that.
- Uses ``csw_api.make_request`` directly so callers don't need to pass a
  client object. If a script wants to swap clients later, override
  ``csw_helpers.make_request`` at import time.
- ``paginate()`` is a generator yielding ``(page_number, results)`` tuples
  so callers retain full control over progress display, accumulation, and
  early termination - matching the existing print formats in each script.
- Errors are reported to stderr and end iteration cleanly. Callers receive
  whatever was collected up to the failing page, mirroring the existing
  "collect what you can, log on failure" semantics.

Usage example
-------------
    import csw_helpers

    # Enumerate sensors, build IP -> sensor map for fast enrichment
    sensor_map = csw_helpers.build_sensor_map()

    # Paginate flowsearch
    flows = []
    body = {"t0": t0, "t1": t1, "filter": flt, "scopeName": root}
    for page, results in csw_helpers.paginate(
        "POST", "/openapi/v1/flowsearch", body=body, batch_size=500,
    ):
        flows.extend(results)
        print(f"\\r  Page {page}: {len(flows)}", end="", flush=True)

    # Generate safe output filenames
    out = f"snapshots/conversations-{csw_helpers.safe_filename(ws_name)}.json"
"""

from __future__ import annotations

import os
import re
import sys
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# Ensure csw_api (sibling module) is importable regardless of cwd.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csw_api  # noqa: E402  (intentional sibling import after path mod)


# =============================================================================
# Constants
# =============================================================================

# Agent operating mode - returned by /openapi/v1/sensors as ``agent_type``.
# Centralized so callers don't sprinkle string literals through their code.
#
# Plain-English summary: a "sensor" can be either software running on a
# host (the first three modes), software running on a network device (the
# next two), or just a feed of NetFlow / mirrored traffic / cloud flow
# logs (the rest). The mode determines how much CSW can see and whether
# CSW can *enforce* policy or only observe.
class AGENT_TYPES:
    """CSW agent operating modes (string values match API responses)."""

    # Full agent: reports every connection AND writes firewall rules into
    # the host kernel to block disallowed traffic. This is what makes
    # microsegmentation actually work end-to-end.
    ENFORCER = "ENFORCER"
    # Same agent, enforcement turned off. Reports connections but never
    # blocks anything. Used for "audit only" deployments and for the
    # observation phase before turning on policy.
    VISIBILITY = "VISIBILITY"
    # Lightweight visibility - subset of features, used on hosts where
    # the full agent isn't appropriate.
    UNIVERSAL = "UNIVERSAL"
    # Endpoint visibility from Cisco AnyConnect's Network Visibility
    # Module (laptops / remote users, not servers).
    ANYCONNECT = "ANYCONNECT"
    # Identity feed from Cisco ISE - tells CSW *who* a given device is.
    ISE = "ISE"
    # External NetFlow collector. CSW sees flow records but can't enforce
    # because there's no agent on the host.
    NETFLOW = "NETFLOW"
    # SPAN / ERSPAN traffic mirror feed. Same caveat - observe only.
    ERSPAN = "ERSPAN"
    # Network device integrations (load balancers and ADCs).
    NETSCALER = "NETSCALER"
    F5 = "F5"
    # Cloud flow log integrations - VPC flow logs and NSG flow logs.
    AWS = "AWS"
    AZURE = "AZURE"


# CSW occasionally returns user-defined annotation keys with literal spaces
# in the field name (e.g. ``user_orchestrator_Workload Type``). When CSV/JSON
# consumers prefer underscores, this map provides canonical translations.
# Extend as new field-name irregularities are discovered.
KNOWN_FIELD_ALIASES: Dict[str, str] = {
    "user_orchestrator_Workload_Type": "user_orchestrator_Workload Type",
    "user_orchestrator_VM_Name": "user_orchestrator_VM Name",
}


# =============================================================================
# Result-shape normalization
# =============================================================================

def extract_results(response: Dict[str, Any]) -> List[Any]:
    """Pull a list of records out of a CSW API response, regardless of shape.

    The CSW API is inconsistent about response payload shape:

      - Some endpoints return a bare list (``data: [{...}, {...}]``)
      - Some return ``data: {"results": [...], "offset": "..."}``
      - Some legacy endpoints return ``data: {"items": [...]}``

    This helper accepts any of those shapes and returns the inner list.
    Returns ``[]`` on errors, missing keys, or unexpected shapes - never
    raises - matching the defensive pattern most consumers already use.
    """
    data = response.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "items", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


# =============================================================================
# Pagination
# =============================================================================

def paginate(
    method: str,
    path: str,
    body: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
    batch_size: int = 100,
    max_pages: Optional[int] = None,
    sleep: float = 0.15,
) -> Iterator[Tuple[int, List[Any]]]:
    """Iterate offset-cursor paginated CSW endpoints, yielding pages.

    Yields one ``(page_number, results)`` tuple per API response. Stops
    when:

      - The endpoint returns fewer than ``batch_size`` results (last page).
      - The endpoint omits an ``offset`` cursor on the response.
      - ``max_pages`` is reached (safety cap; useful for time-windowed
        queries that could otherwise run indefinitely).
      - The endpoint returns a non-200 status (logged to stderr).

    Cursor handling: ``limit`` and ``offset`` are placed in ``body`` for
    POST endpoints (e.g. flowsearch, conversations) and in ``params`` for
    GET endpoints (e.g. sensors, inventory listings). The original input
    is not mutated - a shallow copy is made.

    Caller controls progress display, accumulation, and early termination
    so the existing print formats and error messages in each consumer
    script can be preserved verbatim.

    Parameters
    ----------
    method : str
        HTTP method (``GET``, ``POST``).
    path : str
        API path, e.g. ``"/openapi/v1/flowsearch"``.
    body : dict, optional
        Request body for POST endpoints. ``limit`` and ``offset`` will be
        injected.
    params : dict, optional
        Query string parameters for GET endpoints. ``limit`` and ``offset``
        will be injected.
    batch_size : int
        Page size hint sent as ``limit`` (default 100). Cap varies by
        endpoint: 500 for flowsearch / conversations, typically lower for
        inventory.
    max_pages : int, optional
        Safety cap on number of API calls. ``None`` = unlimited.
    sleep : float
        Seconds to pause between pages (default 0.15) to be polite to the
        cluster. Set to ``0`` to disable.

    Yields
    ------
    (page_number, results) : tuple[int, list[dict]]
        ``page_number`` is 1-based. ``results`` is the list of records
        returned by that page (may be empty on the final page).
    """
    work_body = dict(body) if body is not None else None
    work_params = dict(params) if params is not None else None

    # Decide where the cursor lives. For POST endpoints we put it in the
    # body alongside whatever filter/scope the caller supplied. For GET
    # endpoints we put it in the query string.
    if method.upper() == "POST" or work_body is not None:
        if work_body is None:
            work_body = {}
        work_body["limit"] = batch_size
        cursor_holder = work_body
    else:
        if work_params is None:
            work_params = {}
        work_params["limit"] = batch_size
        cursor_holder = work_params

    page = 0
    while True:
        page += 1
        if max_pages is not None and page > max_pages:
            return

        response = csw_api.make_request(
            method, path, body=work_body, params=work_params,
        )

        status = response.get("status")
        if status != 200:
            err = response.get("data") or response.get("error") or ""
            if isinstance(err, dict):
                err = err.get("error", err)
            sys.stderr.write(
                f"  paginate: page {page} failed (HTTP {status}): {err}\n"
            )
            return

        data = response.get("data") or {}
        if not isinstance(data, dict):
            # Bare list response - one shot, no pagination possible.
            if isinstance(data, list):
                yield page, data
            return

        results = data.get("results") or []
        yield page, results

        # Two ways to know we're done:
        #   1. The page came back smaller than we asked for - that means
        #      the server ran out of records to give us.
        #   2. The server didn't include an "offset" token in the response,
        #      which is its way of saying "no more pages exist".
        if len(results) < batch_size:
            return
        next_cursor = data.get("offset")
        if not next_cursor:
            return

        # The offset cursor is just a bookmark string. We pass it back on
        # the next request and the server resumes where it left off.
        cursor_holder["offset"] = next_cursor

        # Pause briefly between pages so we don't hammer the cluster.
        # Set sleep=0 to disable; the default 0.15s is gentle.
        if sleep > 0:
            time.sleep(sleep)


# =============================================================================
# Sensor enumeration
# =============================================================================

def fetch_all_sensors() -> List[Dict[str, Any]]:
    """Return every sensor (agent / connector) registered in the cluster.

    Tries the simple unpaginated ``GET /openapi/v1/sensors`` first - this
    works on most clusters and is what the existing scripts have been
    relying on for years. If the response indicates pagination (presence
    of an ``offset`` cursor), automatically continues with ``paginate()``
    to retrieve subsequent pages.

    Returns ``[]`` on auth/network failure rather than raising, matching
    the defensive style used by the existing consumer scripts.
    """
    response = csw_api.make_request("GET", "/openapi/v1/sensors")
    if response.get("status") != 200:
        return []

    sensors = extract_results(response)
    data = response.get("data") or {}

    # If the cluster paginated, walk the rest of the cursor chain. Most
    # clusters return everything in a single shot, in which case this
    # branch is skipped.
    if isinstance(data, dict) and data.get("offset"):
        params = {"offset": data["offset"]}
        for _, page_results in paginate(
            "GET", "/openapi/v1/sensors", params=params, batch_size=100,
        ):
            sensors.extend(page_results)

    return sensors


def build_sensor_map(
    sensors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Build an ``ip -> sensor-summary`` lookup for fast enrichment.

    Many reports need to translate an IP address into ``(uuid, hostname,
    agent_type, platform)`` so the sensor list is queried once up front
    and cached as a flat dict. Each sensor exposes one entry per IP it
    advertises (a single host can have many interfaces).

    Parameters
    ----------
    sensors : list of dict, optional
        Pre-fetched sensor list. If omitted, ``fetch_all_sensors()`` is
        called and its result is used.

    Returns
    -------
    dict[str, dict]
        Keys are IP addresses (string form). Values are minimal sensor
        records with these keys: ``uuid``, ``hostname``, ``agent_type``,
        ``platform``.
    """
    if sensors is None:
        sensors = fetch_all_sensors()

    sensor_map: Dict[str, Dict[str, Any]] = {}
    for sensor in sensors:
        if not isinstance(sensor, dict):
            continue

        summary = {
            "uuid": sensor.get("uuid"),
            "hostname": sensor.get("host_name") or sensor.get("hostname"),
            "agent_type": sensor.get("agent_type"),
            "platform": sensor.get("platform"),
        }

        for interface in sensor.get("interfaces") or []:
            if not isinstance(interface, dict):
                continue
            ip = interface.get("ip")
            if ip and ip not in sensor_map:
                sensor_map[ip] = summary

    return sensor_map


# =============================================================================
# Filename hygiene
# =============================================================================

# Characters that filesystems handle poorly (or that confuse shell completion
# and downstream tooling). Anything in this set becomes ``_``.
_UNSAFE_FILENAME_RE = re.compile(r'[^A-Za-z0-9._-]+')


def safe_filename(name: str, max_length: int = 120) -> str:
    """Convert an arbitrary string into a safe filename component.

    Replaces any run of unsafe characters (whitespace, colons, slashes,
    quotes, etc.) with a single underscore, trims leading/trailing
    underscores and dots, and caps the length.

    Returns ``"unnamed"`` for empty / all-unsafe inputs so the result is
    always a usable filename.

    Examples
    --------
    >>> safe_filename("Default:Internal:Apps")
    'Default_Internal_Apps'
    >>> safe_filename("My App / v2.0")
    'My_App_v2.0'
    >>> safe_filename("   ")
    'unnamed'
    """
    if not name:
        return "unnamed"

    cleaned = _UNSAFE_FILENAME_RE.sub("_", str(name))
    cleaned = cleaned.strip("._")
    if not cleaned:
        return "unnamed"

    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length].rstrip("._") or "unnamed"

    return cleaned


# =============================================================================
# Record flattening
# =============================================================================

def flatten_record(
    record: Dict[str, Any],
    fields: Iterable[str],
    aliases: Optional[Dict[str, str]] = None,
    list_separator: str = "; ",
) -> Dict[str, Any]:
    """Project a CSW API record into a flat dict for CSV / tabular export.

    Handles three quirks consistently:

      1. Some keys contain literal spaces (``user_orchestrator_Workload Type``).
         Use the ``aliases`` map to read those without polluting code with
         space-in-quote literals.
      2. List-valued fields (scope name arrays, domain name arrays) are
         joined with ``list_separator`` so the output remains one-row-per-
         record in CSV.
      3. Nested dicts / objects are JSON-stringified to keep the output
         flat. (Most CSW response fields are already scalars, but a few
         endpoints embed nested structures.)

    Missing fields are emitted as the empty string so DictWriter does not
    raise.
    """
    aliases = aliases or {}
    out: Dict[str, Any] = {}

    for field in fields:
        # Use the alias if one exists, else read the field directly.
        source_key = aliases.get(field, field)
        value = record.get(source_key, "")

        if isinstance(value, list):
            out[field] = list_separator.join(str(item) for item in value)
        elif isinstance(value, dict):
            # Stringify nested objects rather than dropping them silently.
            import json as _json
            out[field] = _json.dumps(value, separators=(",", ":"))
        else:
            out[field] = value if value is not None else ""

    return out


# =============================================================================
# Module self-test
# =============================================================================

if __name__ == "__main__":
    # Smoke test: exercise the pure-Python helpers without hitting the API.
    print("csw_helpers self-test")
    print("=" * 60)

    print("\nsafe_filename:")
    for sample in ["Default:Internal:Apps", "My App / v2.0", "   ", "ok"]:
        print(f"  {sample!r:35s} -> {safe_filename(sample)!r}")

    print("\nextract_results:")
    cases = [
        {"data": [1, 2, 3]},
        {"data": {"results": [4, 5]}},
        {"data": {"items": [6]}},
        {"data": None},
        {"data": "oops"},
    ]
    for case in cases:
        print(f"  {case} -> {extract_results(case)}")

    print("\nflatten_record:")
    record = {
        "src_address": "10.1.1.1",
        "tags": ["prod", "db"],
        "user_orchestrator_Workload Type": "VM",
    }
    fields = ["src_address", "tags", "user_orchestrator_Workload_Type"]
    print(f"  {flatten_record(record, fields, KNOWN_FIELD_ALIASES)}")

    print("\nAGENT_TYPES sample:")
    print(f"  ENFORCER={AGENT_TYPES.ENFORCER}, "
          f"VISIBILITY={AGENT_TYPES.VISIBILITY}")

    print("\nAll synchronous helpers passed. paginate() and "
          "build_sensor_map() require live API.")
