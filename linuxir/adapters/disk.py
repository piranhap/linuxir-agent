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
import re
import stat
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


# -- bash history -------------------------------------------------------------------

# (substring/regex, reason) — scored against each shell-history line. Substrings match
# case-insensitively; entries wrapped in re.compile are treated as regexes.
_HISTORY_SIGNATURES: tuple[tuple[object, str], ...] = (
    (re.compile(r"\b(curl|wget)\b.*\|\s*(ba)?sh"), "download piped directly to shell"),
    (re.compile(r"\b(curl|wget)\b.*https?://"), "remote download"),
    ("chmod +x", "made a file executable"),
    ("/tmp/", "activity in /tmp (world-writable)"),
    ("/dev/shm", "activity in /dev/shm (memory-backed, world-writable)"),
    ("sudo -i", "interactive root shell"),
    ("sudo su", "privilege escalation to root"),
    ("authorized_keys", "SSH key persistence"),
    ("cron.d", "cron persistence"),
    ("crontab", "cron persistence"),
    (re.compile(r"\bscp\b"), "file copied off-host (possible exfil)"),
    (re.compile(r"\btar\b.*\bcz?f?\b.*/tmp"), "staged archive in /tmp (possible exfil)"),
    ("/etc/shadow", "accessed password hashes"),
    ("history -c", "cleared shell history (anti-forensics)"),
    ("unset histfile", "disabled history logging (anti-forensics)"),
    (re.compile(r"\brm\b\s+-rf?\b.*/var/log"), "deleted logs (anti-forensics)"),
    ("/dev/tcp/", "bash /dev/tcp reverse shell"),
    ("bash -i", "interactive reverse shell"),
    ("mkfifo", "named-pipe reverse shell"),
    ("socat", "socat tunnel / reverse shell"),
    ("base64 -d", "decoded base64 payload"),
    ("nc -e", "netcat exec backdoor"),
    ("ncat", "ncat backdoor"),
)


def _score_history_line(line: str) -> list[str]:
    low = line.lower()
    reasons: list[str] = []
    for sig, reason in _HISTORY_SIGNATURES:
        hit = sig.search(low) if isinstance(sig, re.Pattern) else (sig.lower() in low)
        if hit and reason not in reasons:
            reasons.append(reason)
    return reasons


def _history_files(roots: list[Path]) -> list[Path]:
    names = (".bash_history", ".sh_history", ".zsh_history", ".ash_history")
    found: list[Path] = []
    for root in roots:
        for base in [root / "root", *( [d for d in (root / "home").iterdir() if d.is_dir()]
                                       if (root / "home").is_dir() else [] )]:
            for name in names:
                hf = base / name
                if hf.is_file():
                    found.append(hf)
    return found


def parse_bash_history(roots: list[Path]) -> str:
    """Read every shell-history file under evidence and score lines for attacker behavior."""
    files = _history_files(roots)
    if not files:
        return "[no shell history files found in evidence scope]"
    out: list[str] = []
    total_flags = 0
    for hf in files:
        content = read_text_file(hf)
        annotated: list[str] = []
        for n, raw in enumerate(content.splitlines(), 1):
            line = raw.rstrip()
            if not line:
                continue
            reasons = _score_history_line(line)
            if reasons:
                total_flags += 1
                annotated.append(f"{n:>4}: {line}\n      [FLAGGED: {'; '.join(reasons)}]")
            else:
                annotated.append(f"{n:>4}: {line}")
        out.append(f"=== {hf} ({total_flags} flagged) ===\n" + "\n".join(annotated))
    header = f"[{total_flags} suspicious command(s) flagged across {len(files)} history file(s)]"
    return header + "\n\n" + "\n\n".join(out)


# -- setuid / setgid ----------------------------------------------------------------

_SUSPICIOUS_SUID_DIRS = ("/tmp/", "/dev/shm", "/home/", "/var/tmp", "/run/")
# Interpreters/shells that should essentially never be setuid-root.
_SUID_SHELL_NAMES = frozenset(
    {"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby",
     "php", "nc", "ncat", "netcat", "find", "vim", "vi", "nmap", "awk"}
)


def find_setuid_binaries(roots: list[Path], max_files: int = 200_000) -> str:
    """Walk evidence and list setuid/setgid files, flagging shells & unusual locations."""
    rows: list[str] = []
    scanned = 0
    truncated = False
    for root in roots:
        for dirpath, _dirs, files in os.walk(root, followlinks=False):
            for fn in files:
                scanned += 1
                if scanned > max_files:
                    truncated = True
                    break
                p = Path(dirpath) / fn
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    continue
                bits = st.st_mode & (stat.S_ISUID | stat.S_ISGID)
                if not bits:
                    continue
                kind = []
                if st.st_mode & stat.S_ISUID:
                    kind.append("setuid")
                if st.st_mode & stat.S_ISGID:
                    kind.append("setgid")
                rel = "/" + str(p.relative_to(root))
                flags = []
                if any(d in rel for d in _SUSPICIOUS_SUID_DIRS):
                    flags.append("unusual location")
                if fn in _SUID_SHELL_NAMES and (st.st_mode & stat.S_ISUID):
                    flags.append("setuid interpreter/shell — strong privesc indicator")
                marker = f"  [SUSPICIOUS: {', '.join(flags)}]" if flags else ""
                rows.append(
                    f"{st.st_mode & 0o7777:04o} uid={st.st_uid} gid={st.st_gid} "
                    f"{'+'.join(kind)} {p}{marker}"
                )
            if truncated:
                break
    if not rows:
        return "[no setuid/setgid files found in evidence scope]"
    head = f"[{len(rows)} setuid/setgid file(s) found"
    head += " — scan truncated]" if truncated else "]"
    return head + "\n" + "\n".join(sorted(rows))


# -- rc / init / profile persistence ------------------------------------------------

_RC_FILES = (
    "etc/rc.local", "etc/rc.d/rc.local", "etc/profile", "etc/bash.bashrc",
    "etc/environment",
)
_RC_DIRS = ("etc/init.d", "etc/profile.d", "etc/rc.d", "etc/update-motd.d")
_HOME_RC = (".bashrc", ".bash_profile", ".profile", ".bash_login", ".zshrc")


def _emit_rc(p: Path, out: list[str]) -> None:
    content = read_text_file(p)
    flags = _flag(content)
    marker = f"  [SUSPICIOUS tokens: {', '.join(flags)}]" if flags else ""
    out.append(f"=== {p}{marker} ===\n{content}")


def find_rc_persistence(roots: list[Path]) -> str:
    """Scan rc.local, init.d, profile.d, and per-user shell rc files for run-on-* hooks."""
    out: list[str] = []
    for root in roots:
        for rel in _RC_FILES:
            p = root / rel
            if p.is_file():
                _emit_rc(p, out)
        for rel in _RC_DIRS:
            d = root / rel
            if d.is_dir():
                for f in sorted(d.rglob("*")):
                    if f.is_file():
                        _emit_rc(f, out)
        for base in [root / "root", *([d for d in (root / "home").iterdir() if d.is_dir()]
                                      if (root / "home").is_dir() else [])]:
            for name in _HOME_RC:
                p = base / name
                if p.is_file():
                    _emit_rc(p, out)
    if not out:
        return "[no rc/init/profile files found in evidence scope]"
    return "\n\n".join(out)


# -- LD_PRELOAD hijacking ------------------------------------------------------------

_LD_ENV_FILES = ("etc/ld.so.preload", "etc/environment", "etc/profile", "etc/bash.bashrc")


def find_ld_preload(roots: list[Path]) -> str:
    """Surface /etc/ld.so.preload and any LD_PRELOAD set in environment/profile files."""
    out: list[str] = []
    for root in roots:
        pre = root / "etc/ld.so.preload"
        if pre.is_file():
            content = read_text_file(pre).strip()
            flags = [ln for ln in content.splitlines()
                     if ln.strip() and any(d in ln for d in _SUSPICIOUS_SUID_DIRS)]
            marker = "  [SUSPICIOUS: preloads from world-writable path]" if flags else ""
            out.append(f"=== {pre} (present — global library preload){marker} ===\n"
                       f"{content or '(empty)'}")
        search_files = [root / rel for rel in _LD_ENV_FILES[1:]]
        pd = root / "etc/profile.d"
        if pd.is_dir():
            search_files += [f for f in sorted(pd.rglob("*")) if f.is_file()]
        for f in search_files:
            if not f.is_file():
                continue
            hits = [ln.strip() for ln in read_text_file(f).splitlines()
                    if "LD_PRELOAD" in ln and not ln.strip().startswith("#")]
            if hits:
                out.append(f"=== {f} [LD_PRELOAD set] ===\n" + "\n".join(hits))
    if not out:
        return "[no ld.so.preload or LD_PRELOAD environment entries found]"
    return "\n\n".join(out)


# -- /etc/passwd baseline diff -------------------------------------------------------

# Default accounts shipped on a stock Debian/Ubuntu system. An account NOT in this set,
# with a UID in the system range and a real login shell, is worth a human's attention.
_BASELINE_PASSWD_USERS = frozenset({
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
    "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
    "systemd-network", "systemd-resolve", "systemd-timesync", "messagebus",
    "syslog", "_apt", "tss", "uuidd", "tcpdump", "landscape", "pollinate", "sshd",
    "systemd-coredump", "lxd", "dnsmasq", "usbmux", "rtkit", "avahi", "ntp", "ftp",
})
_NOLOGIN_SHELLS = frozenset({"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "", "/dev/null"})


def diff_passwd(roots: list[Path]) -> str:
    """Parse /etc/passwd and flag UID-0 accounts != root and unexpected login users."""
    out: list[str] = []
    for root in roots:
        pw = root / "etc/passwd"
        if not pw.is_file():
            continue
        lines = read_text_file(pw).splitlines()
        rows: list[str] = []
        for ln in lines:
            if not ln.strip() or ln.startswith("#"):
                continue
            parts = ln.split(":")
            if len(parts) < 7:
                continue
            name, _pw, uid, gid, _gecos, home, shell = parts[:7]
            flags: list[str] = []
            try:
                uid_i = int(uid)
            except ValueError:
                uid_i = -1
            if uid_i == 0 and name != "root":
                flags.append("UID 0 but not 'root' — BACKDOOR ROOT ACCOUNT")
            has_login = shell.strip() not in _NOLOGIN_SHELLS
            if name not in _BASELINE_PASSWD_USERS and 0 < uid_i < 1000 and has_login:
                flags.append("non-baseline system account with a login shell")
            if name not in _BASELINE_PASSWD_USERS and uid_i >= 1000 and has_login:
                flags.append("non-baseline user (review if unexpected)")
            marker = f"  [SUSPICIOUS: {'; '.join(flags)}]" if flags else ""
            rows.append(f"{name}:uid={uid}:gid={gid}:home={home}:shell={shell}{marker}")
        if rows:
            out.append(f"=== {pw} ===\n" + "\n".join(rows))
    if not out:
        return "[no /etc/passwd found in evidence scope]"
    return "\n\n".join(out)


# -- wtmp / utmp login records (binary; needs `last` or `utmpdump`) ------------------

def parse_wtmp(roots: list[Path]) -> str:
    """Decode wtmp/btmp/utmp login records via `last`/`utmpdump` (graceful if absent)."""
    targets = ("var/log/wtmp", "var/log/btmp", "var/log/utmp", "run/utmp", "var/run/utmp")
    found = [root / rel for root in roots for rel in targets if (root / rel).is_file()]
    if not found:
        return "[no wtmp/btmp/utmp files found in evidence scope]"
    out: list[str] = []
    for f in found:
        res = summarize(run_binary(["last", "-f", str(f)]))
        if res.startswith("[tool unavailable]"):
            res = summarize(run_binary(["utmpdump", str(f)]))
        out.append(f"=== {f} ===\n{res}")
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
