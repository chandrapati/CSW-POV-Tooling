# CSW agent log analysis — examples

## Example 1: Multi-publish timing (lab host)

**Bundle:** `ip-172-31-0-39_*_csw-logs.zip` (AWS lab EC2)  
**Stack:** iptables + ipset · CSW 4.0.3.13

### Question

"How long is policy enforcement taking? I changed catch-all from allow to deny multiple times."

### Command

```bash
python3 parse_enforcer_timeline.py /path/to/ip-172-31-0-39_*_csw-logs --year 2026
```

### Results

| Metric | Result |
|--------|--------|
| On-host apply (6 publishes) | **27–34 ms** each |
| EFE delivery between versions | **5.3 – 9.9 min** |
| First Enforce ON → firewall live | **~5 s** |
| Monitor → first apply | **~4 min** (queued until Enforce flip) |

### Catch-all finding

Latest proto still showed `catch_all_* → ALLOW`. Logs collected ~30 sec after last apply — DENY publish had not landed. **Recommendation:** wait ≥10 min, re-export logs, confirm new version + `type: DENY` in proto.

### Answer pattern

> On-host enforcement is **sub-second** (~30 ms). What feels slow is **CSW delivering new policy versions (5–10 min between publishes)**. Catch-all DENY must appear in `latest_e2a_npc_proto_file` before testing.

---

## Example 2: ICMP block (financial-services POV)

See the per-customer write-up in your engagement repo under `docs/enforcement-validation/` — e.g. `CSW-ICMP-Enforcement-Log-Analysis-Server-*.md`.

| Question | Typical answer |
|----------|----------------|
| ICMP DROP rule in proto? | Yes — network_policy id 1 |
| On-host nft/iptables rule? | Yes — `comment "id: 1"` |
| Applied on host? | Yes — version + timestamp in enforcer log |
| Prove ping failed? | No — need functional test + Denied Connections |

---

## Example 3: Two-host comparison

See `CSW-Enforcement-Timing-Comparison-*.md` in the customer POV repo. Both hosts: agent apply **<1 s** once policy arrives; difference is **EFE delivery** relative to enforce mode flip.

---

## Decision tree

```text
"Policy slow"
  ├─ Run parse_enforcer_timeline.py
  ├─ On-host apply <100ms? → EFE delivery is the wait
  ├─ Large receive→apply but enforce was 0? → Monitor mode queue
  ├─ catch-all wrong in proto? → publish not landed; wait + new bundle
  └─ Rule on host but traffic passes? → path/LB/upstream ACL
```
