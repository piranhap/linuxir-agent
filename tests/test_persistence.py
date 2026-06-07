"""Day-2 persistence checks: the six additions completing CLAUDE.md's persistence_server.

Adapter-level tests against the fixture tree, plus a tmp-built setuid file (git cannot
preserve the setuid bit, so that case is constructed at runtime).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from linuxir.adapters import disk

EVIDENCE = Path(__file__).parent / "fixtures" / "evidence"


def test_bash_history_scores_attack_chain() -> None:
    out = disk.parse_bash_history([EVIDENCE])
    assert "suspicious command(s) flagged" in out
    assert "remote download" in out                       # wget http://...
    assert "activity in /tmp" in out                      # /tmp/x.sh
    assert "interactive root shell" in out                # sudo -i
    assert "cleared shell history (anti-forensics)" in out  # history -c
    # a benign recon line stays unflagged
    assert "   1: id" in out


def test_bash_history_absent_is_graceful(tmp_path) -> None:
    assert disk.parse_bash_history([tmp_path]).startswith("[no shell history")


def test_rc_persistence_surfaces_rc_local() -> None:
    out = disk.find_rc_persistence([EVIDENCE])
    assert "rc.local" in out
    assert "185.220.101.47" in out
    assert "SUSPICIOUS" in out


def test_ld_preload_flags_world_writable() -> None:
    out = disk.find_ld_preload([EVIDENCE])
    assert "ld.so.preload" in out
    assert "/tmp/.x/libhook.so" in out
    assert "SUSPICIOUS" in out


def test_diff_passwd_flags_backdoor_root() -> None:
    out = disk.diff_passwd([EVIDENCE])
    assert "BACKDOOR ROOT ACCOUNT" in out          # support:x:0:0
    assert "support:uid=0" in out
    # baseline system accounts are NOT flagged
    assert "www-data:uid=33:gid=33:home=/var/www:shell=/usr/sbin/nologin\n" in out + "\n"
    assert "www-data" in out and "[SUSPICIOUS" not in out.split("www-data")[1].split("\n")[0]


def test_diff_passwd_absent_is_graceful(tmp_path) -> None:
    assert disk.diff_passwd([tmp_path]).startswith("[no /etc/passwd")


def test_setuid_flags_setuid_shell(tmp_path) -> None:
    # Build a minimal evidence tree with a setuid bash in /tmp (git can't store the s-bit).
    binp = tmp_path / "tmp" / ".hidden"
    binp.mkdir(parents=True)
    suid = binp / "bash"
    suid.write_text("#!/bin/sh\n")
    os.chmod(suid, 0o4755)  # setuid + rwxr-xr-x
    # a normal file should not appear
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "hosts").write_text("127.0.0.1 localhost\n")

    out = disk.find_setuid_binaries([tmp_path])
    assert "setuid" in out
    assert "bash" in out
    assert "unusual location" in out
    assert "setuid interpreter/shell" in out
    assert "hosts" not in out


def test_setuid_none_is_graceful(tmp_path) -> None:
    (tmp_path / "f").write_text("x")
    assert disk.find_setuid_binaries([tmp_path]).startswith("[no setuid/setgid")


def test_wtmp_absent_is_graceful() -> None:
    # No wtmp/utmp binary file in the fixture tree -> graceful, no crash.
    assert disk.parse_wtmp([EVIDENCE]).startswith("[no wtmp/btmp/utmp")
