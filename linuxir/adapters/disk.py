"""Disk / filesystem forensic operations over a mounted evidence tree.

These functions implement the *vertical-slice-complete* analysis path: cron and systemd
persistence discovery, SSH ``authorized_keys`` inspection, and scoped file reads. They
operate on a mounted evidence tree (evidence roots that mimic a filesystem root, e.g.
``/mnt/evidence`` containing ``etc/``, ``var/``, ``home/``). The sleuthkit wrappers
(``mmls``/``fls``/``icat``) run against raw images via :func:`run_binary`, returning a
graceful "unavailable" result when the binaries are absent.

All reads are confined to evidence roots by construction; the gateway's ConstraintEnforcer
has additionally validated any model-supplied path before these run.
"""

from __future__ import annotations

import os
from pathlib import Path

from .base import BinaryResult, run_binary, summarize

MAX_READ_BYTES = 256 * 1024

# Standard locations where cron persistence lives, relative to a filesystem root.
_CRON_LOCATIONS = (
    "etc/crontab",
    "etc/cron.d",
    "etc/cron.hourly",
    "etc/cron.daily",
    "etc/cron.weekly",
    "etc/cron.monthly",
    "var/spool/cron",
    "var/spool/cron/crontabs",
)

# Tokens in a cron/systemd line that commonly indicate a backdoor.
_SUSPICIOUS_TOKENS = (
    "curl", "wget", "nc ", "ncat", "/tmp/", "/dev/shm", "base64", "bash -i",
    "python -c", "perl -e", "/dev/tcp/", "mkfifo", "socat", "chmod +x",
)

_SYSTEMD_LOCATIONS = (
    "etc/systemd/system",
    "lib/systemd/system",
    "usr/lib/systemd/system",
    "run/systemd/system",
)


def read_text_file(path: Path, max_bytes: int = MAX_READ_BYTES) -> str:
    """Read a text file (best-effort decode, size-capped)."""
    p = Path(path)
    if not p.exists():
        return f"[not found] {p}"
    if not p.is_file():
        return f"[not a file] {p}"
    data = p.read_bytes()[:max_bytes]
    text = data.decode("utf-8", errors="replace")
    if p.stat().st_size > max_bytes:
        text += f"\n...[truncated at {max_bytes} bytes, file is {p.stat().st_size}]"
    return text


def list_dir(path: Path) -> str:
    p = Path(path)
    if not p.is_dir():
        return f"[not a directory] {p}"
    lines = []
    for child in sorted(p.iterdir()):
        try:
            st = child.stat()
            kind = "d" if child.is_dir() else "-"
            lines.append(f"{kind} {st.st_mode & 0o777:o} {st.st_size:>10} {child.name}")
        except OSError as exc:
            lines.append(f"? {child.name} ({exc})")
    return "\n".join(lines) or "(empty)"


def _flag(text: str) -> list[str]:
    low = text.lower()
    return [tok.strip() for tok in _SUSPICIOUS_TOKENS if tok in low]


def find_cron_persistence(roots: list[Path]) -> str:
    """Scan known cron locations across evidence roots and surface their contents."""
    out: list[str] = []
    for root in roots:
        for rel in _CRON_LOCATIONS:
            loc = root / rel
            if not loc.exists():
                continue
            files = [loc] if loc.is_file() else sorted(
                f for f in loc.rglob("*") if f.is_file()
            )
            for f in files:
                content = read_text_file(f)
                flags = _flag(content)
                marker = f"  [SUSPICIOUS tokens: {', '.join(flags)}]" if flags else ""
                out.append(f"=== {f}{marker} ===\n{content}")
    if not out:
        return "[no cron artifacts found in evidence scope]"
    return "\n\n".join(out)


def find_systemd_persistence(roots: list[Path]) -> str:
    """Scan systemd unit/timer locations and extract Exec* lines, flagging odd paths."""
    out: list[str] = []
    for root in roots:
        for rel in _SYSTEMD_LOCATIONS:
            loc = root / rel
            if not loc.is_dir():
                continue
            for unit in sorted(loc.rglob("*")):
                if not unit.is_file() or unit.suffix not in {".service", ".timer"}:
                    continue
                content = read_text_file(unit)
                exec_lines = [
                    ln.strip()
                    for ln in content.splitlines()
                    if ln.strip().startswith(("ExecStart", "ExecStartPre", "ExecStop"))
                ]
                flags = _flag(content)
                marker = f"  [SUSPICIOUS tokens: {', '.join(flags)}]" if flags else ""
                detail = "\n".join(exec_lines) if exec_lines else "(no Exec* lines)"
                out.append(f"=== {unit}{marker} ===\n{detail}")
    if not out:
        return "[no systemd units found in evidence scope]"
    return "\n\n".join(out)


def find_authorized_keys(roots: list[Path]) -> str:
    """Find every SSH ``authorized_keys`` under evidence roots (root + each home)."""
    out: list[str] = []
    for root in roots:
        candidates = [root / "root/.ssh/authorized_keys"]
        home = root / "home"
        if home.is_dir():
            candidates += [d / ".ssh/authorized_keys" for d in home.iterdir() if d.is_dir()]
        for ak in candidates:
            if ak.is_file():
                out.append(f"=== {ak} ===\n{read_text_file(ak)}")
    if not out:
        return "[no authorized_keys files found in evidence scope]"
    return "\n\n".join(out)


# -- sleuthkit raw-image wrappers (graceful fallback when binaries are absent) ------

def disk_partition_table(image: str) -> str:
    return summarize(run_binary(["mmls", image]))


def disk_list_files(image: str, inode: str | None = None, offset: str | None = None) -> str:
    argv = ["fls", "-r"]
    if offset:
        argv += ["-o", offset]
    argv.append(image)
    if inode:
        argv.append(inode)
    return summarize(run_binary(argv))


def disk_cat_inode(image: str, inode: str, offset: str | None = None) -> str:
    argv = ["icat"]
    if offset:
        argv += ["-o", offset]
    argv += [image, inode]
    return summarize(run_binary(argv))
