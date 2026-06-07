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
from .disk import read_text_file

# "Jun  3 02:11:07 host ..." — classic RFC3164 syslog stamp (no year).
_SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s"
)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_AUTH_NAMES = ("var/log/auth.log", "var/log/auth.log.1", "var/log/secure")
_SYSLOG_NAMES = ("var/log/syslog", "var/log/syslog.1", "var/log/messages")

_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_INVALID = re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)")
_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+)")
_SUDO = re.compile(r"sudo:.*?(?P<who>\S+)\s*:.*COMMAND=(?P<cmd>.+)$")
_SU = re.compile(r"\bsu(?:\[\d+\])?:.*(?:session opened|to) ")


def _sort_key(line: str) -> tuple[int, int, str]:
    m = _SYSLOG_TS.match(line)
    if not m:
        return (99, 99, "")
    return (_MONTHS.get(m["mon"], 99), int(m["day"]), m["time"])


def _find(roots: list[Path], names: tuple[str, ...]) -> list[Path]:
    return [root / n for root in roots for n in names if (root / n).is_file()]


def parse_auth(roots: list[Path]) -> str:
    """Parse auth.log/secure: brute force, first accepted (initial access), sudo/su."""
    files = _find(roots, _AUTH_NAMES)
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
    files = _find(roots, _SYSLOG_NAMES)
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
    files = _find(roots, _AUTH_NAMES) + _find(roots, _SYSLOG_NAMES)
    if not files:
        return "[no parseable text logs found for a timeline]"

    events: list[tuple[tuple[int, int, str], str, str]] = []
    for f in files:
        tag = f.name
        for ln in read_text_file(f).splitlines():
            if _SYSLOG_TS.match(ln):
                events.append((_sort_key(ln), tag, ln.strip()))
    events.sort(key=lambda e: e[0])

    note = ""
    if not run_binary(["log2timeline.py", "--version"]).get("available"):
        note = ("(plaso/log2timeline not installed — internal text-log merge below; "
                "install plaso for a full filesystem super-timeline)\n")
    body = "\n".join(f"{tag:<12} | {line}" for _k, tag, line in events)
    return f"[merged timeline: {len(events)} events from {len(files)} log(s)]\n{note}{body}"


def find_gaps(roots: list[Path], gap_minutes: int = 60) -> str:
    """Detect coverage gaps / truncation in auth.log — possible anti-forensic tampering."""
    files = _find(roots, _AUTH_NAMES) + _find(roots, _SYSLOG_NAMES)
    if not files:
        return "[no logs to check for gaps]"
    findings: list[str] = []
    for f in files:
        stamped = [(_sort_key(ln), ln.strip())
                   for ln in read_text_file(f).splitlines() if _SYSLOG_TS.match(ln)]
        if not stamped:
            findings.append(f"{f}: no timestamped lines (empty or non-standard format)")
            continue
        for (k1, l1), (k2, l2) in zip(stamped, stamped[1:]):
            mins = _delta_minutes(k1, k2)
            if mins is not None and mins >= gap_minutes:
                findings.append(
                    f"{f}: {mins} min gap between\n    {l1}\n    {l2}")
        if f.stat().st_size == 0:
            findings.append(f"{f}: file is EMPTY — possible truncation/tampering")
    if not findings:
        return f"[no coverage gaps >= {gap_minutes} min detected]"
    return f"[{len(findings)} potential coverage gap(s) / anomalies]\n" + "\n".join(findings)


def _delta_minutes(k1: tuple[int, int, str], k2: tuple[int, int, str]) -> int | None:
    """Minutes between two (month, day, HH:MM:SS) keys; None if either is unparseable."""
    if k1[0] == 99 or k2[0] == 99:
        return None
    def to_min(k: tuple[int, int, str]) -> int:
        h, m, s = (int(x) for x in k[2].split(":"))
        return ((k[0] * 31 + k[1]) * 24 * 60) + h * 60 + m
    return to_min(k2) - to_min(k1)
