# CSW agent log analysis — reference

## Unzip bundle

```bash
BUNDLE_ZIP="/path/to/host_uuid_epoch_csw-logs.zip"
BUNDLE="/tmp/csw-logs-$$"
unzip -q -o "$BUNDLE_ZIP" -d "$BUNDLE"
LOG="$BUNDLE/log/tet-enforcer.log"
```

## Grep patterns (`tet-enforcer.log`)

```bash
LOG="$BUNDLE/log/tet-enforcer.log"

rg -n "Enforcement enabled" "$LOG"
rg -n "Received Policy config version" "$LOG"
rg -n "Processing network policy config from EFE" "$LOG"
rg -n "Firewall is now enabled" "$LOG"
rg -n "Staged rules have been committed" "$LOG"
rg -n "Policy config has been applied successfully" "$LOG"
rg -n "Policy deviation detected|reverted firewall" "$LOG"
rg -n "EFE is now connected" "$LOG"
```

## Policy protobuf

```bash
PROTO="$BUNDLE/proto/latest_e2a_npc_proto_file"
rg -n "version:|network_policy|catch_all" "$PROTO"
rg -n "id: |type: DROP|type: ALLOW|ICMP|INGRESS|EGRESS" "$PROTO"
```

**Catch-all:** `catch_all_ingress_policy` / `catch_all_egress_policy` → `type: ALLOW` or `type: DENY`.

## Host firewall

| Stack | Artifact | Confirm |
|-------|----------|---------|
| nftables | `policyagent-staged-nft` | `comment "id: N"` |
| iptables | `policyagent-staged4`, `firewallDump/iptables_v4` | ipset `ta_*`, `comment "id: N"` |

## Timing interpretation

| Observation | Typical cause | Action |
|-------------|---------------|--------|
| Receive → apply **<100 ms** | Normal on-host apply | Use apply timestamp as test cutoff |
| Receive → apply **minutes** | Monitor mode or pre-Enforce queue | Check enforce timeline |
| **5–10 min** between versions | EFE delivery | Wait ≥10 min after UI publish |
| Catch-all DENY in UI but ALLOW in proto | Not delivered yet | New bundle after wait |

## Report template (single host)

Write to `{Customer}-CSW-POV/docs/enforcement-validation/CSW-*-Log-Analysis-<host>.md`:

```markdown
# CSW [test name] — agent log analysis

**Log bundle:** `[folder]` · **Agent UUID:** `[uuid]` · **Host:** `[ip]`

## Executive summary

| Question | Answer |
|----------|--------|
| Policy in agent config? | … |
| On-host rule? | … |
| Applied? | version X at TIMESTAMP |
| On-host apply latency | ~XX ms |
| EFE delivery gap | ~X min |
| Logs prove deny? | Usually no — functional test |

## Test cutoff

Validate **after** [TIMESTAMP] for version [N].
```

## CSW UI cross-checks

- Scope mode: **Enforce** vs Monitor
- **Denied Connections** after test
- Policy version in UI vs enforcer log `current version`
