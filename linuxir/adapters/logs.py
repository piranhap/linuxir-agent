"""Log analysis over a mounted evidence tree — auth.log, syslog, btmp, and timeline.

These are read-only text parsers (auth/syslog) plus graceful wrappers around `lastb`
(btmp is binary). They turn raw logs into the three things an IR timeline needs: *who got
in* (brute force -> first accepted), *what they did with privilege* (sudo/su), and *when*
(a merged chronological timeline + coverage-gap detection that can hint at log tampering).

Timestamps in classic syslog/auth.log have no year ("Jun  3 02:11:07"); we parse the
month/day/time for ordering. All reads are confined to evidence roots by construction, and
the gateway's ConstraintEnforcer has already validated any model-supplied path.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import run_binary, summarize
from .discover import discover
from .disk import read_text_file

# Two syslog stamp formats:
#   RFC3164 "Jun  3 02:11:07 host ..." (no year), and
#   RFC5424 "<86>1 2026-04-14T12:00:12.603346Z host ..." (journald/rsyslog default).
_TS_3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})\s")
_TS_5424 = re.compile(
    r"^(?:<\d+>\d?\s*)?(?P<Y>\d{4})-(?P<mo>\d{2})-(?P<day>\d{2})[T ](?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _event_key(line: str) -> tuple[int, int, int, int, int] | None:
    """Normalize either syslog format to a comparable (month, day, h, m, s); None if neither."""
    if m := _TS_3164.match(line):
        return (_MONTHS.get(m["mon"], 99), int(m["day"]), int(m["h"]), int(m["mi"]), int(m["s"]))
    if m := _TS_5424.match(line):
        return (int(m["mo"]), int(m["day"]), int(m["h"]), int(m["mi"]), int(m["s"]))
    return None

_AUTH_NAMES = ("var/log/auth.log", "var/log/auth.log.1", "var/log/secure")
_SYSLOG_NAMES = ("var/log/syslog", "var/log/syslog.1", "var/log/messages")

# Basename globs for collection-format triage trees (CylR/UAC/Velociraptor), where the
# standard relative paths don't exist. sshd/sudo lines often land in syslog.log on these.
_AUTH_GLOBS = ("auth.log", "auth.log.[0-9]", "secure", "secure.[0-9]", "syslog.log")
_SYSLOG_GLOBS = ("syslog", "syslog.[0-9]", "syslog.log", "messages", "messages.[0-9]")


def _find_auth(roots: list[Path]) -> list[Path]:
    fixed = [root / n for root in roots for n in _AUTH_NAMES if (root / n).is_file()]
    return sorted({*fixed, *discover(roots, _AUTH_GLOBS)}, key=str)


def _find_syslog(roots: list[Path]) -> list[Path]:
    fixed = [root / n for root in roots for n in _SYSLOG_NAMES if (root / n).is_file()]
    return sorted({*fixed, *discover(roots, _SYSLOG_GLOBS)}, key=str)


def _find_all_logs(roots: list[Path]) -> list[Path]:
    return sorted(set(_find_auth(roots)) | set(_find_syslog(roots)), key=str)

_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_INVALID = re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)")
_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+)")
_SUDO = re.compile(r"sudo:.*?(?P<who>\S+)\s*:.*COMMAND=(?P<cmd>.+)$")
_SU = re.compile(r"\bsu(?:\[\d+\])?:.*(?:session opened|to) ")


_SENTINEL = (99, 99, 99, 99, 99)


def _sort_key(line: str) -> tuple[int, int, int, int, int]:
    return _event_key(line) or _SENTINEL


def _find(roots: list[Path], names: tuple[str, ...]) -> list[Path]:
    return [root / n for root in roots for n in names if (root / n).is_file()]


def parse_auth(roots: list[Path]) -> str:
    """Parse auth.log/secure: brute force, first accepted (initial access), sudo/su."""
    files = _find_auth(roots)
    if not files:
        return "[no auth.log / secure files found in evidence scope]"

    failed_by_ip: dict[str, int] = {}
    invalid_users: set[str] = set()
    accepted: list[str] = []
    sudo: list[str] = []
    sessions: list[str] = []
    out_files: list[str] = []

    for f in files:
        lines = read_text_file(f).splitlines()
        bf: list[str] = []
        for ln in lines:
            if mf := _FAILED.search(ln):
                failed_by_ip[mf["ip"]] = failed_by_ip.get(mf["ip"], 0) + 1
                bf.append(ln)
                if mi := _INVALID.search(ln):
                    invalid_users.add(mi["user"])
            if _ACCEPTED.search(ln):
                accepted.append(ln)
            if _SUDO.search(ln):
                sudo.append(ln)
            if "session opened" in ln or "session closed" in ln or _SU.search(ln):
                sessions.append(ln)
        out_files.append(str(f))

    header = (f"[auth analysis across {len(files)} file(s): "
              f"{sum(failed_by_ip.values())} failed, {len(accepted)} accepted, "
              f"{len(sudo)} sudo event(s)]")
    parts = [header, f"files: {', '.join(out_files)}"]

    if failed_by_ip:
        ranked = sorted(failed_by_ip.items(), key=lambda kv: -kv[1])
        parts.append("\n== Source IPs (failed-login counts) ==")
        parts += [f"  {ip}: {n} failed" + ("   [brute force]" if n >= 5 else "")
                  for ip, n in ranked]
    if invalid_users:
        parts.append(f"\n== Invalid usernames tried ==\n  {', '.join(sorted(invalid_users))}")
    parts.append("\n== Initial access — first Accepted login ==")
    parts.append("  " + accepted[0] if accepted else "  (no successful logins observed)")
    if len(accepted) > 1:
        parts.append(f"  (+{len(accepted) - 1} more accepted login(s))")
    parts.append("\n== Privilege escalation (sudo/su) ==")
    parts += [f"  {ln}" for ln in sudo] or ["  (none)"]
    parts.append("\n== Sessions ==")
    parts += [f"  {ln}" for ln in sessions[:20]] or ["  (none)"]
    return "\n".join(parts)


def parse_lastb(roots: list[Path]) -> str:
    """Decode /var/log/btmp failed-login records via `lastb` (graceful if absent)."""
    btmp = [root / "var/log/btmp" for root in roots if (root / "var/log/btmp").is_file()]
    if not btmp:
        return ("[no /var/log/btmp found in evidence scope] "
                "(failed-login bursts are also visible via logs_parse_auth)")
    return "\n\n".join(f"=== {f} ===\n{summarize(run_binary(['lastb', '-f', str(f)]))}"
                       for f in btmp)


def parse_syslog(roots: list[Path]) -> str:
    """Surface syslog/messages daemon, cron, and systemd events (flagging odd tokens)."""
    files = _find_syslog(roots)
    if not files:
        return "[no syslog / messages files found in evidence scope]"
    from .disk import _flag  # reuse the suspicious-token flagger

    out: list[str] = []
    for f in files:
        rows = []
        for ln in read_text_file(f).splitlines():
            if not ln.strip():
                continue
            flags = _flag(ln)
            mark = f"   [SUSPICIOUS: {', '.join(flags)}]" if flags else ""
            rows.append(ln + mark)
        out.append(f"=== {f} ===\n" + "\n".join(rows))
    return "\n\n".join(out)


def build_timeline(roots: list[Path]) -> str:
    """Merge timestamped lines from auth + syslog into one chronological view.

    Uses log2timeline/plaso when available for a full super-timeline; otherwise builds an
    internal merge of the text logs (which is what the bundled evidence exercises).
    """
    files = _find_all_logs(roots)
    if not files:
        return "[no parseable text logs found for a timeline]"

    events: list[tuple[tuple[int, int, str], str, str]] = []
    for f in files:
        tag = f.name
        for ln in read_text_file(f).splitlines():
            if (k := _event_key(ln)) is not None:
                events.append((k, tag, ln.strip()))
    events.sort(key=lambda e: e[0])

    note = ""
    if not run_binary(["log2timeline.py", "--version"]).get("available"):
        note = ("(plaso/log2timeline not installed — internal text-log merge below; "
                "install plaso for a full filesystem super-timeline)\n")
    body = "\n".join(f"{tag:<12} | {line}" for _k, tag, line in events)
    return f"[merged timeline: {len(events)} events from {len(files)} log(s)]\n{note}{body}"


def find_gaps(roots: list[Path], gap_minutes: int = 60, anomaly_factor: int = 4,
              max_report: int = 15) -> str:
    """Detect *anomalous* coverage gaps in the logs — possible truncation / tampering.

    A naive "any delta >= N minutes" flags the normal hourly CRON heartbeat as a gap and
    drowns the signal. Instead a gap must be BOTH absolutely large (>= ``gap_minutes``) and
    anomalous relative to the file's own median inter-event interval (>= ``anomaly_factor``
    x median) — so an hourly-cron log (median ~60 min) only trips on multi-hour silences,
    not on every hour. Results are ranked largest-first and capped.
    """
    import statistics

    files = _find_all_logs(roots)
    if not files:
        return "[no logs to check for gaps]"

    gaps: list[tuple[int, str]] = []      # (minutes, description) for ranking
    notes: list[str] = []
    for f in files:
        if f.stat().st_size == 0:
            notes.append(f"{f}: file is EMPTY — possible truncation/tampering")
            continue
        stamped = [(k, ln.strip())
                   for ln in read_text_file(f).splitlines()
                   if (k := _event_key(ln)) is not None]
        if not stamped:
            notes.append(f"{f}: no timestamped lines (empty or non-standard format)")
            continue
        deltas = [d for (k1, _), (k2, _) in zip(stamped, stamped[1:])
                  if (d := _delta_minutes(k1, k2)) is not None and d >= 0]
        if not deltas:
            continue
        median = max(statistics.median(deltas), 1)
        threshold = max(gap_minutes, anomaly_factor * median)
        for (k1, l1), (k2, l2) in zip(stamped, stamped[1:]):
            mins = _delta_minutes(k1, k2)
            if mins is not None and mins >= threshold:
                gaps.append((mins, f"{f.name}: {mins} min gap (median cadence "
                                    f"{int(median)} min) between\n    {l1}\n    {l2}"))

    if not gaps and not notes:
        return (f"[no coverage gaps detected — no interval was both >= {gap_minutes} min "
                f"and >= {anomaly_factor}x the median cadence]")
    gaps.sort(key=lambda g: -g[0])
    shown = [d for _m, d in gaps[:max_report]]
    header = (f"[longest log silences — top {min(len(gaps), max_report)} of {len(gaps)} "
              f"interval(s) over threshold"
              + (f"; {len(notes)} file-level anomaly(ies)" if notes else "") + ". "
              "Long quiet windows in sparse event logs are often normal (overnight, "
              "weekends) — corroborate before concluding truncation/tampering.]")
    return header + "\n" + "\n".join(notes + shown)


def _delta_minutes(k1: tuple[int, ...], k2: tuple[int, ...]) -> int | None:
    """Minutes between two (month, day, h, m, s) keys; None if either is unparseable."""
    if k1[0] == 99 or k2[0] == 99:
        return None
    def to_min(k: tuple[int, ...]) -> int:
        return ((k[0] * 31 + k[1]) * 24 * 60) + k[2] * 60 + k[3]
    return to_min(k2) - to_min(k1)
