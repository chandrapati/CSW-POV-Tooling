# CSW POV Tooling

![Visitors](https://visitor-badge.laobi.icu/badge?page_id=chandrapati.CSW-POV-Tooling&left_text=visitors)

Customer-neutral, reusable tooling for Cisco Secure Workload (CSW / Tetration) proof-of-value engagements. Per-customer engagement repos (e.g. `{Customer}-CSW-POV`) use these scripts to pull data and generate reports against their own tenant, **without** mixing customer-specific artifacts into a shared codebase.

> **Customer isolation policy:** This repo MUST NOT contain anything customer-specific — no hostnames, tenant IDs, scope names, IP ranges, CMDB extracts, executive briefings, or customer business data. All of that lives in the per-customer repo.

## Quick start

1. Clone alongside (or inside) your per-customer engagement working directory.

2. Copy the credential template and fill in real values for the **target customer's tenant**. Keep this file local — `.env` is gitignored.

   ```bash
   cp .env.example .env
   # then edit .env and set CSW_API_URL, CSW_API_KEY, CSW_API_SECRET for the tenant
   ```

3. Sanity-check connectivity and count installed agents on the cluster:

   ```bash
   python3 count_agents.py            # human-readable summary
   python3 count_agents.py --json     # JSON, easy to pipe / grep
   ```

4. Make any other authenticated call via the generic client:

   ```bash
   python3 csw_api.py GET /openapi/v1/app_scopes
   python3 csw_api.py GET /openapi/v1/sensors --limit 50 --offset 0
   ```

## Script catalog

Each script carries the same one-line **Quick summary** at the top of its file
(`head -20 <script>.py`), plus a full docstring and `--help`. Grouped by role:

**Core / shared**

| Script | Quick summary |
|---|---|
| `csw_api.py` | Signed HMAC client for the CSW OpenAPI. Run any GET/POST from the CLI, or import `make_request()`. Handles auth, TLS CA bundle, timeout, and 429/5xx retries. Used by every other script. |
| `csw_helpers.py` | Shared helper library (no CLI). Offset pagination, sensor fetch/normalize, field-alias resolution, record flattening, safe filenames. |
| `count_agents.py` | Counts installed agents and breaks them down by type, OS/platform, version, and enforcement state. **Run first** to sanity-check connectivity. |
| `api_test_suite.py` | Probes every major OpenAPI endpoint group and writes a Markdown capability matrix showing what this API key / cluster can do. |

**Collect (pull data from the tenant)**

| Script | Quick summary |
|---|---|
| `cluster_snapshot.py` | Captures a full point-in-time snapshot (agents · scopes · workspaces · policies · 24h flow sample) as JSON + Markdown. Baseline for everything else. |
| `cluster_delta.py` | Diffs two snapshots and reports additions, removals, and metric changes as Markdown. |
| `download_flows.py` | Exports raw flow records between two scopes (configurable filter, NetFlow excluded by default) to CSV. |
| `download_conversations.py` | Exports ADM-matched conversations for one/all workspaces to JSON, with a protocol/port summary. Auto-discovers workspaces. |
| `download_forensics.py` | Exports the cluster's forensic configuration (profiles, rules, intents, intent order) to JSON. |
| `download_policies.py` | Exports every workspace's policies plus per-scope workload inventory to JSON, and a Markdown + HTML policy-workload report. |

**Analyze & report (render deliverables)**

| Script | Quick summary |
|---|---|
| `risky_port_audit.py` | Audit-only. Flags risky-port exposure — east-west, broad-scope allows, ADM rules, PCI CDE boundary — across all policies. JSON + HTML. |
| `generate_vuln_report.py` | Per-host CVE pull → per-CVE CSV + host-level severity / CVM-risk rollup HTML, ranked by exploitability. |
| `generate_flow_analysis.py` | Deep flow-sample HTML — verdicts, protocols, TCP perf, TLS posture, risky ports, top scope/host/process pairs. |
| `generate_forensics_report.py` | Forensics config + agent telemetry → HTML posture report with MITRE ATT&CK coverage and gap analysis. |
| `generate_html_report.py` | Single snapshot → styled, self-contained HTML readout (stdlib only). |
| `generate_combined_report.py` | Baseline + current snapshots → one HTML report showing current state and the change delta. |
| `generate_executive_report.py` | **The deliverable.** Rolls up the latest snapshot + every companion artifact into a CISO-grade one-page HTML + Markdown (visibility, enforcement, blast-radius KPIs + prioritized fixes). |
| `query_long_lived_processes.py` | One flowsearch per day over a window → ranks persistent vs recurring vs transient processes per host (table + HTML + JSON). |
| `parse_enforcer_timeline.py` | Offline log parser (no API creds). Enforcement timeline, on-host apply latency (ms), EFE delivery gaps (min) from `*_csw-logs` / `tet-enforcer.log`. See [docs/logs-check/](docs/logs-check/). |

**Supporting files**

| File | Purpose |
|---|---|
| `framework-scope-design.md` / `framework-scope-design-updated.md` | Generic scope-design framework templates. |
| `.env` | **Local only.** Tenant URL + API key + API secret. Gitignored. |
| `.env.example` | Template showing the variables that must be set. |
| `.gitignore` | Excludes `.env`, credential JSON, snapshots, reports, exports, and OS junk. |

## Recommended workflow

A typical engagement-day refresh against any tenant — produces every report needed for an
executive readout:

```bash
# 1) capture current state (1-2 min)
python3 cluster_snapshot.py

# 2) policy + workload inventory (30 s)
python3 download_policies.py

# 3) risky-port audit using cached policies (5 s)
python3 risky_port_audit.py --use-cache

# 4) forensics config (10 s)
python3 download_forensics.py

# 5) deep flow analysis (1 min)
python3 generate_flow_analysis.py --limit 2000 --hours 24

# 6) CVE rollup (1 min)
python3 generate_vuln_report.py

# 7) optional: ADM conversations per workspace
python3 download_conversations.py --workspace "<workspace-name>"

# 8) executive HTML+MD deliverable
python3 generate_executive_report.py --snapshot-latest \
    --prepared-for "Customer Name" \
    --prepared-by  "Your Team"

# 9) open the deliverable
open reports/executive-summary-$(date -u +%Y-%m-%d).html
```

### Enforcement validation (agent log bundles)

After policy publish + functional test, export `*_csw-logs` from the target agent and parse offline:

```bash
python3 parse_enforcer_timeline.py /path/to/host_uuid_epoch_csw-logs.zip --year 2026
```

Write findings to `{Customer}-CSW-POV/docs/enforcement-validation/`. Full workflow: [docs/logs-check/README.md](docs/logs-check/README.md).

All scripts read `.env` for credentials, paginate the OpenAPI safely, and write outputs
to `snapshots/` (raw JSON/CSV) and `reports/` (rendered HTML/MD). Use `--help` on any
script for the full CLI.

## API key capabilities required

| Capability | Used by |
|---|---|
| `sensor_management` | sensors, forensics, CVE rollup, long-lived processes |
| `flow_inventory_query` | snapshot, flow analysis, conversations, flows |
| `app_policy_management` | snapshot, policies, risky-port audit |
| `user_role_scope_management` | snapshot, risky-port audit |

All four are **read** capabilities. No write capability is required for this toolkit.

## Security notes

- API key + secret stay only in `.env`, which `.gitignore` excludes from every commit.
- Never paste keys into commit messages, code, screenshots, or chat history that is committed.
- If a key is exposed (e.g. accidentally pushed): rotate it immediately in the CSW UI
  (Platform → API Keys), remove from history (`git filter-repo` or BFG), and re-issue.
- `CSW_VERIFY_SSL` stays `true`. The shared client (`csw_api.make_request`) points Python at
  `certifi`'s CA bundle automatically so verification works on macOS framework Python builds
  that ship with an empty system trust store — every script benefits, not just one.

### Network resilience (shared client)

All API calls go through `csw_api.make_request`, which now:

- Enforces a per-request socket timeout (`CSW_API_TIMEOUT`, default `30`s) so a stalled
  connection can't hang a long report run.
- Retries HTTP `429` (throttling) and transient `5xx` (`502/503/504`) up to
  `CSW_API_MAX_RETRIES` (default `3`), honoring any `Retry-After` header, otherwise using
  exponential back-off with jitter. This aligns with the upcoming CSW **API DDoS throttling**
  behavior — scripts degrade gracefully instead of erroring out.
- Recomputes the HMAC timestamp + signature on every attempt (the signature is time-bound),
  so retries stay valid.
- Customer engagement findings (cluster baselines, agent counts, enforcement state) belong
  in the **per-customer repo**, not here.

## Used by

- Private, per-customer CSW POV engagement repos, each named `{Customer}-CSW-POV`.
- Each engagement repo consumes these scripts and keeps its own tenant configuration, findings, and deliverables in isolation — no customer data lives here.

## Provenance

Extracted from an earlier per-customer POV engagement on 2026-05-14. The scripts contain no customer-specific data — all tenant configuration is read from `.env` at runtime — so they were relocated here for shared reuse and to enforce per-customer repo isolation.
