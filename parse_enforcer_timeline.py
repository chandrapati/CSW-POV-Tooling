#!/usr/bin/env python3
"""Extract CSW enforcement timeline from tet-enforcer.log.

Supports log timestamp formats:
  - glog:  I0529 22:51:42.393419  (MMDD + time; year from bundle mtime or --year)
  - plain: 2026-05-29 22:51:42

Usage:
  python3 parse_enforcer_timeline.py /path/to/*_csw-logs
  python3 parse_enforcer_timeline.py /path/to/log/tet-enforcer.log
  python3 parse_enforcer_timeline.py /path/to/bundle --year 2026
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

# glog: I0529 22:51:42.393419 or I0529 22:51:42
GLOG_TS = re.compile(r"^[IWEF]\d{4}\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?")
# plain: 2026-05-29 22:51:42
PLAIN_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")

EVENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("enforcement_enabled", re.compile(r"Enforcement enabled:\s*(\d+)")),
    ("policy_received", re.compile(r"Received Policy config version:\s*(\d+)")),
    ("policy_processing", re.compile(r"Processing network policy config from EFE, version:\s*(\d+)")),
    ("firewall_enabled", re.compile(r"Firewall is now enabled")),
    ("rules_committed", re.compile(r"Staged rules have been committed")),
    ("policy_applied", re.compile(r"Policy config has been applied successfully.*?(\d+)")),
    ("policy_deviation", re.compile(r"Policy deviation detected")),
    ("policy_reverted", re.compile(r"Successfully reverted firewall to expected policy, version:\s*(\d+)")),
    ("efe_connected", re.compile(r"EFE is now connected to Agent")),
    ("agent_restart", re.compile(r"tet-enforcer:\s*version")),
]


def find_enforcer_log(path: Path) -> Path:
    path = path.resolve()
    if path.is_file() and path.name == "tet-enforcer.log":
        return path
    if path.is_dir():
        candidate = path / "log" / "tet-enforcer.log"
        if candidate.is_file():
            return candidate
        for p in path.rglob("tet-enforcer.log"):
            if "log" in p.parts:
                return p
    raise FileNotFoundError(f"tet-enforcer.log not found under {path}")


def infer_year(log_path: Path, explicit: int | None) -> int:
    if explicit:
        return explicit
    try:
        return datetime.fromtimestamp(log_path.stat().st_mtime).year
    except OSError:
        return datetime.now().year


def parse_timestamp(line: str, year: int) -> datetime | None:
    stripped = line.strip()
    m = PLAIN_TS.match(stripped)
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    m = GLOG_TS.match(stripped)
    if m:
        month = int(stripped[1:3])
        day = int(stripped[3:5])
        hour, minute, second = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return datetime(year, month, day, hour, minute, second)
    return None


def parse_events(lines: list[str], year: int) -> list[dict]:
    events: list[dict] = []
    for line in lines:
        ts = parse_timestamp(line, year)
        if ts is None:
            continue
        for label, pat in EVENT_PATTERNS:
            m = pat.search(line)
            if m:
                version = m.group(1) if m.lastindex else None
                events.append(
                    {
                        "ts": ts,
                        "label": label if label != "enforcement_enabled" else f"enforcement_enabled_{version}",
                        "version": version if label != "enforcement_enabled" else version,
                        "line": line.strip()[:140],
                    }
                )
                break
    return events


def fmt_delta(a: datetime, b: datetime) -> str:
    sec = (b - a).total_seconds()
    if sec < 0:
        return f"{sec:.0f} s"
    if sec < 1:
        return f"{sec * 1000:.0f} ms"
    if sec < 120:
        return f"{sec:.2f} s"
    if sec < 7200:
        return f"{sec / 60:.1f} min"
    return f"{sec / 3600:.2f} h"


def pair_receive_apply(events: list[dict]) -> list[tuple[dict, dict]]:
    """Match policy_received/processing to next policy_applied with same version."""
    pairs: list[tuple[dict, dict]] = []
    received: dict[str, datetime] = {}
    for e in events:
        if e["label"] in ("policy_received", "policy_processing") and e["version"]:
            received[e["version"]] = e["ts"]
        elif e["label"] == "policy_applied" and e["version"]:
            if e["version"] in received:
                pairs.append(({"version": e["version"], "ts": received[e["version"]]}, e))
                del received[e["version"]]
    return pairs


def efe_delivery_gaps(events: list[dict]) -> list[tuple[str, str, str]]:
    """Time between consecutive policy_received events."""
    recvs = [e for e in events if e["label"] == "policy_received" and e["version"]]
    gaps: list[tuple[str, str, str]] = []
    for i in range(1, len(recvs)):
        gaps.append(
            (
                recvs[i - 1]["version"] or "?",
                recvs[i]["version"] or "?",
                fmt_delta(recvs[i - 1]["ts"], recvs[i]["ts"]),
            )
        )
    return gaps


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    year_flag = None
    for a in sys.argv[1:]:
        if a.startswith("--year="):
            year_flag = int(a.split("=", 1)[1])
        elif a == "--year" and sys.argv[sys.argv.index(a) + 1 :]:
            year_flag = int(sys.argv[sys.argv.index(a) + 1])

    if not args:
        print(__doc__, file=sys.stderr)
        return 2

    log_path = find_enforcer_log(Path(args[0]))
    year = infer_year(log_path, year_flag)
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    events = parse_events(lines, year)

    print(f"# CSW enforcer timeline\n\n**Source:** `{log_path}`  \n**Year inferred:** {year}\n")
    if not events:
        print("_No matching events — check log format or pass `--year YYYY`._\n")
        return 1

    print("| Timestamp | Event | Version |")
    print("|-----------|--------|---------|")
    for e in events:
        ver = e["version"] or "—"
        print(f"| {e['ts']} | {e['label']} | {ver} |")

    enforce_on = next((e for e in events if e["label"] == "enforcement_enabled_1"), None)
    firewall = next((e for e in events if e["label"] == "firewall_enabled"), None)
    applies = [e for e in events if e["label"] == "policy_applied"]
    pairs = pair_receive_apply(events)
    gaps = efe_delivery_gaps(events)

    print("\n## Deltas\n")
    if enforce_on and firewall:
        print(f"- Enforce ON → firewall enabled: **{fmt_delta(enforce_on['ts'], firewall['ts'])}**")
    if enforce_on and applies:
        print(f"- Enforce ON → last policy applied: **{fmt_delta(enforce_on['ts'], applies[-1]['ts'])}**")

    if pairs:
        print("\n### On-host apply (receive → committed)\n")
        print("| Version | Receive → apply |")
        print("|---------|-----------------|")
        for recv, app in pairs:
            print(f"| {app['version']} | **{fmt_delta(recv['ts'], app['ts'])}** |")
        ms_vals = [(a["ts"] - r["ts"]).total_seconds() * 1000 for r, a in pairs]
        fast_ms = [v for v in ms_vals if v <= 60_000]
        if fast_ms:
            print(f"\nTypical on-host apply (excl. Monitor queue): **{min(fast_ms):.0f}–{max(fast_ms):.0f} ms**")
        slow = [p for p in pairs if (p[1]["ts"] - p[0]["ts"]).total_seconds() > 60]
        if slow:
            print("\nQueued applies (Monitor / pre-Enforce): " + ", ".join(p[1]["version"] for p in slow))

    if gaps:
        print("\n### EFE delivery (prior receive → next receive)\n")
        print("| From version | To version | Gap |")
        print("|--------------|------------|-----|")
        for v_from, v_to, gap in gaps:
            print(f"| {v_from} | {v_to} | **{gap}** |")
        print(
            "\n**Interpretation:** gaps >1 min are control-plane delivery delay, "
            "not host firewall slowness. Wait ≥10 min after UI publish before functional tests."
        )

    if applies:
        print(f"\n**Latest applied version:** `{applies[-1]['version']}` at `{applies[-1]['ts']}`")
        print(f"**Functional test cutoff:** after `{applies[-1]['ts']}`")

    deviations = [e for e in events if e["label"] == "policy_deviation"]
    if deviations:
        print(f"\n**Policy deviation events:** {len(deviations)} (agent reverted ipset/firewall mismatch)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
