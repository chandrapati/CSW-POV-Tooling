#!/usr/bin/env python3
"""
download_conversations.py — Download all conversations from a CSW workspace
---------------------------------------------------------------------------
Conversations are network flows that have been matched to ADM-generated
policies within a workspace.  Each conversation record includes the
src/dst IP pair, protocol, port, byte/packet counts, policy filter IDs,
and the ADM confidence score.

The script paginates through the CSW conversations API in batches of 500,
collects all records, and saves the full result set as JSON.  A quick
statistical summary (protocol distribution, top ports) is printed at the end.

Auto-discovery (no default workspace)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
There is no cluster-wide "current workspace" in the API credentials.  The
portable way to see which workspaces your API key can access is
``GET /openapi/v1/applications``, which returns a list of application objects
(``id``, ``name``, and other metadata).  When you omit both ``--workspace``
and ``--app-id``, this script:

1. Fetches that list once (see ``fetch_all_applications``).
2. If stdin is a TTY, prints a numbered catalog and waits for input: a number
   picks one workspace; ``a`` selects every workspace (same as ``--all``); ``q``
   exits.
3. If stdin is not a TTY (CI, cron, pipes), it cannot prompt safely; it prints
   the same catalog, reminds you to pass ``--workspace``, ``--app-id``, or
   ``--all``, and exits with code 2.

``--list`` only performs step (1) and prints the catalog.  ``--all`` skips the
prompt and downloads every returned application (one JSON file per workspace).

Usage:
    python3 download_conversations.py
        # Auto-discover workspaces; pick one or all when run in a TTY

    python3 download_conversations.py --list
        # List workspaces and exit

    python3 download_conversations.py --all
        # Download conversations for every workspace (one JSON file each)

    python3 download_conversations.py --workspace "MyWorkspace"
    python3 download_conversations.py --app-id 69caa4cab1eac266c4877aaa
    python3 download_conversations.py --version 3              # specific ADM version
    python3 download_conversations.py --out snapshots/custom.json

Output:
    snapshots/conversations-<workspace>-<date>.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csw_api

csw_api._load_dotenv()

DATE_TAG = datetime.now().strftime("%Y-%m-%d")

# The conversations API supports up to 500 results per request.
BATCH_SIZE = 500


def fetch_all_applications() -> list:
    """Return every workspace (application) visible to the API key.

    CSW exposes workspaces as "applications" in the OpenAPI surface.  The
    conversations endpoint is keyed by application ``id`` (a string identifier),
    while humans usually think in terms of ``name``.  This helper is the single
    HTTP call backing:

    - Interactive auto-discovery when neither ``--workspace`` nor ``--app-id``
      is provided (we need the full list before we can prompt).
    - ``--list`` (print catalog and exit).
    - ``--all`` (expand the list into one download job per workspace).

    Keeping discovery in one function avoids duplicate requests and guarantees
    every code path sees the same response shape: ``data`` must be a JSON array
    of objects with at least ``id`` and ``name`` for downstream logic.
    """
    r = csw_api.make_request("GET", "/openapi/v1/applications")
    if r.get("status") != 200:
        print(f"  GET /openapi/v1/applications failed: HTTP {r.get('status')}")
        sys.exit(1)
    apps = r.get("data", [])
    if not isinstance(apps, list):
        print("  Unexpected response: 'data' is not a list.")
        sys.exit(1)
    return apps


def print_workspace_catalog(apps: list, heading: str = "Available workspaces:") -> None:
    """Pretty-print workspace names and ids (shared by --list and discovery)."""
    print(f"\n  {heading}")
    if not apps:
        print("      (none returned by the API)")
        return
    for i, a in enumerate(apps, start=1):
        name = a.get("name", "?")
        aid = a.get("id", "?")
        print(f"      [{i:3d}] {name}")
        print(f"            id: {aid}")


def find_workspace(name: str) -> dict:
    """Look up a workspace (application) by name.

    Performs a case-insensitive match against the list of all workspaces
    in the cluster and returns the first match.
    """
    apps = fetch_all_applications()
    for a in apps:
        if a.get("name", "").lower() == name.lower():
            return a
    print(f"  Workspace '{name}' not found. Available:")
    for a in apps:
        print(f"      - {a.get('name')}")
    sys.exit(1)


def get_application(app_id: str) -> dict:
    """Fetch a single workspace record by id (name + latest_adm_version)."""
    r = csw_api.make_request("GET", f"/openapi/v1/applications/{app_id}")
    if r.get("status") != 200:
        print(f"  GET /openapi/v1/applications/{app_id} failed: HTTP {r.get('status')}")
        sys.exit(1)
    return r["data"]


def get_latest_version(app_id: str) -> int:
    """Retrieve the latest ADM version number for a workspace.

    The conversations API requires an explicit ADM version.  This fetches
    the workspace details and returns the latest_adm_version field.
    """
    data = get_application(app_id)
    return data.get("latest_adm_version", 1)


def download_all_conversations(app_id: str, version: int) -> list:
    """Paginate through the conversations API and collect all records.

    The API uses cursor-based pagination: each response includes an opaque
    "offset" token that must be passed in the next request to fetch the
    next batch.  Pagination ends when fewer than BATCH_SIZE results are
    returned or no offset token is present.
    """
    all_convos = []
    offset = None
    page = 0

    while True:
        page += 1
        body = {"version": version, "limit": BATCH_SIZE}
        if offset:
            body["offset"] = offset

        r = csw_api.make_request(
            "POST",
            f"/openapi/v1/conversations/{app_id}",
            body=body,
        )

        if r.get("status") != 200:
            print(f"\n  API error on page {page}: HTTP {r.get('status')}")
            err = r.get("data", {})
            if isinstance(err, dict):
                print(f"      {err.get('error', err)}")
            break

        data = r.get("data", {})
        results = data.get("results", [])
        all_convos.extend(results)

        batch_count = len(results)
        print(
            f"\r  Page {page}: +{batch_count} conversations "
            f"(total: {len(all_convos)})",
            end="", flush=True,
        )

        if batch_count < BATCH_SIZE:
            break

        offset = data.get("offset")
        if not offset:
            break

        # Gentle rate-limiting to avoid overloading the API
        time.sleep(0.15)

    print()
    return all_convos


def print_quick_stats(convos: list) -> None:
    """Protocol and port distribution summary (unchanged behavior)."""
    protos = {}
    ports = {}
    for c in convos:
        p = c.get("protocol", "?")
        protos[p] = protos.get(p, 0) + 1
        port = c.get("port", "?")
        ports[port] = ports.get(port, 0) + 1

    print(f"\n  Quick stats:")
    print(
        f"      Protocols: "
        f"{dict(sorted(protos.items(), key=lambda x: -x[1]))}"
    )
    top_ports = sorted(ports.items(), key=lambda x: -x[1])[:10]
    print(f"      Top 10 ports: {dict(top_ports)}")


def save_conversations_json(
    convos: list,
    ws_name: str,
    out_path_override: str | None,
) -> str:
    """Write conversations to JSON; return the path used."""
    safe_name = ws_name.replace(":", "_").replace(" ", "_")
    out_path = (
        out_path_override or f"snapshots/conversations-{safe_name}-{DATE_TAG}.json"
    )
    with open(out_path, "w") as f:
        json.dump(convos, f, indent=2)

    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(
        f"\n  Saved {len(convos):,} conversations "
        f"to {out_path} ({size_mb:.1f} MB)"
    )
    return out_path


def run_one_workspace(
    app_id: str,
    ws_name: str,
    version_override: int | None,
    out_path_override: str | None,
) -> None:
    """Download, save, and print stats for a single workspace."""
    version = version_override if version_override is not None else get_latest_version(app_id)
    print(f"  Workspace: {ws_name}")
    print(f"  App ID: {app_id}")
    print(f"  ADM version: {version}")
    print(f"  Batch size: {BATCH_SIZE}\n")

    convos = download_all_conversations(app_id, version)

    if not convos:
        print("  No conversations found.")
        return

    save_conversations_json(convos, ws_name, out_path_override)
    print_quick_stats(convos)


def prompt_select_workspaces(apps: list) -> list[dict]:
    """Interactive selection after auto-discovery.

    Preconditions: ``apps`` is the non-empty list from ``fetch_all_applications``.
    The caller (``main``) must only invoke this when ``sys.stdin.isatty()`` is
    true, so ``input()`` will not block indefinitely on an empty pipe or hang a
    batch job without a human present.

    Returns a list of workspace dicts (always non-empty on success):
    - One dict  → single-workspace download (honors ``--out`` if provided).
    - Many dicts → same loop as ``--all`` (per-workspace default filenames;
      ``--out`` is disallowed for multi-target runs elsewhere in ``main``).

    Input grammar:
    - Digits 1..N → that row from the printed table.
    - ``a`` / ``A`` → all rows (equivalent to non-interactive ``--all``).
    - ``q`` / ``Q`` → clean exit without calling the conversations API.
    """
    print_workspace_catalog(apps)
    raw = input(
        "\n  Enter workspace number (1-{}), 'a' for all, or 'q' to quit: "
        .format(len(apps))
    ).strip()
    if raw.lower() == "q":
        print("  Aborted.")
        sys.exit(0)
    if raw.lower() == "a":
        return list(apps)
    if not raw.isdigit():
        print("  Invalid input. Expected a number, 'a', or 'q'.")
        sys.exit(1)
    idx = int(raw)
    if idx < 1 or idx > len(apps):
        print(f"  Out of range: {idx}")
        sys.exit(1)
    return [apps[idx - 1]]


def main():
    parser = argparse.ArgumentParser(
        description="Download all conversations from a CSW workspace.",
    )
    parser.add_argument(
        "--workspace", "-w",
        default=None,
        help="Workspace name (default: unset — auto-discover or use --app-id / --all)",
    )
    parser.add_argument(
        "--app-id",
        default=None,
        help="Application/workspace ID (overrides --workspace)",
    )
    parser.add_argument(
        "--version", "-v",
        type=int,
        default=None,
        help="ADM version (default: latest per workspace)",
    )
    parser.add_argument(
        "--out", "-o",
        default=None,
        help="Output JSON path "
             "(default: snapshots/conversations-<workspace>-<date>.json; "
             "not used with --all)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List workspaces from GET /openapi/v1/applications and exit",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Download conversations for every workspace (separate JSON per workspace)",
    )
    args = parser.parse_args()

    # -------------------------------------------------------------------------
    # Workspace resolution order (after parse_args):
    #
    #   --list          → fetch applications, print, exit (no downloads).
    #   --all           → fetch applications, download each (no prompt).
    #   --app-id        → one workspace by id; optional --workspace only
    #                     overrides the display name (API still used if name
    #                     omitted to resolve the real workspace name).
    #   --workspace     → resolve id by case-insensitive name match.
    #   (none of above) → auto-discovery: fetch applications, then TTY prompt
    #                     or non-interactive error with catalog (exit 2).
    #
    # Conflicts: --all cannot combine with --workspace/--app-id; --out cannot
    # combine with --all (ambiguous which file would receive output).
    # -------------------------------------------------------------------------

    if args.list:
        print(f"\n  Connecting to: {os.environ.get('CSW_API_URL', '?')}")
        apps = fetch_all_applications()
        print_workspace_catalog(apps)
        print(f"\n  Total: {len(apps)} workspace(s).")
        return

    if args.all and (args.workspace or args.app_id):
        print("  Error: do not combine --all with --workspace or --app-id.")
        sys.exit(1)

    if args.all and args.out:
        print("  Error: --out is not supported with --all (each file uses the default naming pattern).")
        sys.exit(1)

    os.makedirs("snapshots", exist_ok=True)

    print(f"\n  Connecting to: {os.environ.get('CSW_API_URL', '?')}")
    print(f"  Date: {DATE_TAG}\n")

    targets: list[tuple[str, str]] = []  # (app_id, ws_name)

    if args.all:
        apps = fetch_all_applications()
        if not apps:
            print("  No workspaces returned by the API.")
            return
        targets = [(a["id"], a.get("name", a["id"])) for a in apps if a.get("id")]
    elif args.app_id:
        app_id = args.app_id
        if args.workspace:
            ws_name = args.workspace
        else:
            ws_name = get_application(app_id).get("name", app_id)
        targets = [(app_id, ws_name)]
    elif args.workspace:
        ws = find_workspace(args.workspace)
        targets = [(ws["id"], ws.get("name", ws["id"]))]
    else:
        # Neither --workspace nor --app-id: auto-discover via applications list.
        #
        # Why not default a hard-coded workspace name?  Different CSW clusters
        # (SaaS tenants, on-prem appliances, customer sandboxes) each have their
        # own application namespace; any baked-in default would be wrong almost
        # everywhere.  ``GET /openapi/v1/applications`` is authoritative for
        # "what can this key see right now on this CSW_API_URL".
        #
        # After we have ``apps``, behavior splits on whether a human is likely at
        # the keyboard.  ``isatty()`` is a simple heuristic: True for a normal
        # terminal session where ``input()`` is appropriate; False under systemd,
        # Jenkins, ``python script.py < /dev/null``, etc., where blocking on
        # stdin would be surprising—those callers must pass explicit flags.
        apps = fetch_all_applications()
        if not apps:
            print("  No workspaces returned; nothing to download.")
            return

        if sys.stdin.isatty():
            chosen = prompt_select_workspaces(apps)
        else:
            print(
                "  Non-interactive mode: provide --workspace, --app-id, or --all.\n"
                "  Re-run in a terminal to pick from the list, or choose explicitly:"
            )
            print_workspace_catalog(apps)
            sys.exit(2)

        targets = [(a["id"], a.get("name", a["id"])) for a in chosen if a.get("id")]

    # Single-workspace path preserves --out; multi-workspace (--all or multi-select) does not.
    single_out = args.out if len(targets) == 1 else None

    for i, (app_id, ws_name) in enumerate(targets, start=1):
        if len(targets) > 1:
            print(f"\n  --- [{i}/{len(targets)}] {ws_name} ---\n")
        run_one_workspace(app_id, ws_name, args.version, single_out)


if __name__ == "__main__":
    main()
