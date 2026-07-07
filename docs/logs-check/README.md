# CSW agent log analysis

Analyze **CSW agent diagnostic exports** (`*_csw-logs` zip or directory) to answer:

- How long until policy is **live on the host**?
- Is delay **EFE delivery** (minutes) or **on-host apply** (milliseconds)?
- Did catch-all / specific rule land in proto + iptables/nft?
- What **test cutoff timestamp** should functional validation use?

No API credentials required — works offline on bundles exported from the CSW UI or `csw-agent` diagnostics.

## Quick start

```bash
# Unzip if needed, then parse (from repo root)
python3 parse_enforcer_timeline.py /path/to/host_uuid_epoch_csw-logs.zip --year 2026

# Or point at extracted folder or tet-enforcer.log directly
python3 parse_enforcer_timeline.py /path/to/*_csw-logs/log/tet-enforcer.log
```

Outputs markdown: event timeline, on-host apply (ms), EFE delivery gaps, latest applied version, functional test cutoff.

## Workflow

```text
1. Export *_csw-logs bundle from target agent
2. Run parse_enforcer_timeline.py
3. Read proto/latest_e2a_npc_proto_file — network_policy + catch_all ALLOW/DENY
4. Confirm on-host rule in policyagent-staged-nft or policyagent-staged4 / firewallDump
5. Write findings to {Customer}-CSW-POV/docs/enforcement-validation/ (per-customer repo)
```

## Key definitions

| Term | Log signal |
|------|------------|
| **Enforcement mode ON** | `Enforcement enabled: 1` |
| **Policy landed** | `Received Policy config version: N` |
| **Enforced on host** | `Staged rules have been committed` + `Policy config has been applied successfully` |
| **EFE delivery gap** | Time between consecutive `Received Policy config version` lines |
| **On-host apply** | Same version receive → apply (expect **<100 ms**) |

**Critical:** User-perceived slowness is usually **EFE delivery (5–10+ min between versions)**, not iptables commit (~30 ms). Wait **≥10 min after UI publish** before functional tests.

## Bundle layout

| Path | Purpose |
|------|---------|
| `log/tet-enforcer.log` | Policy receive, enforce mode, commit timestamps |
| `proto/latest_e2a_npc_proto_file` | Policy protobuf |
| `policyagent-staged-nft` | nftables rules (WAF) |
| `policyagent-staged4` / `firewallDump/iptables_v4` | iptables + ipset (WAF) |

## Further reading

- [reference.md](reference.md) — grep patterns, report templates, timing table
- [examples.md](examples.md) — worked examples (multi-publish, ICMP, two-host)

## Cursor skill

The same workflow is available as a Cursor agent skill: `csw-logs-check` in the CSW toolkit (`~/.cursor/skills/csw-logs-check/`). Source of truth for the parser is **`parse_enforcer_timeline.py`** in this repo.
