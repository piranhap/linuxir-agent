"""Day-3 logs_server + memory_server: typed log parsing and vol3 wrappers.

Log parsers run against the fixture tree (auth.log + syslog). Volatility3 is usually
absent, so the memory tests assert graceful fallback; kernel-banner detection uses `grep`
and is verified against a tiny synthetic image built at runtime.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from linuxir.adapters import logs, memory

EVIDENCE = Path(__file__).parent / "fixtures" / "evidence"


# -- logs -------------------------------------------------------------------------

def test_parse_auth_brute_force_and_initial_access() -> None:
    out = logs.parse_auth([EVIDENCE])
    assert "185.220.101.47: 7 failed" in out
    assert "brute force" in out
    assert "admin" in out and "oracle" in out          # invalid users tried
    # first Accepted == initial access
    assert "Accepted password for victim from 185.220.101.47" in out
    assert "COMMAND=/bin/bash" in out                   # sudo escalation


def test_parse_auth_absent_is_graceful(tmp_path) -> None:
    assert logs.parse_auth([tmp_path]).startswith("[no auth.log")


def test_parse_syslog_flags_c2_cron() -> None:
    out = logs.parse_syslog([EVIDENCE])
    assert "CRON" in out and "185.220.101.47" in out
    assert "SUSPICIOUS" in out                          # curl flagged


def test_build_timeline_merges_and_sorts() -> None:
    out = logs.build_timeline([EVIDENCE])
    assert "merged timeline" in out
    # auth.log (02:11:07) sorts before syslog's 05:01 entry; both sources present
    assert "auth.log" in out and "syslog" in out
    pos_first_fail = out.find("Failed password for root")
    pos_apt = out.find("Daily apt download")
    assert 0 < pos_first_fail < pos_apt                 # chronological order


def test_find_gaps_detects_truncation_window() -> None:
    out = logs.find_gaps([EVIDENCE])
    assert "161 min gap" in out


def test_find_gaps_none_when_dense(tmp_path) -> None:
    log = tmp_path / "var/log/auth.log"
    log.parent.mkdir(parents=True)
    log.write_text(
        "Jun  3 02:11:07 h sshd[1]: x\nJun  3 02:11:20 h sshd[1]: y\n")
    assert "no coverage gaps" in logs.find_gaps([tmp_path])


# -- memory -----------------------------------------------------------------------

def test_kernel_banner_recovered_from_image(tmp_path) -> None:
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\x00\x00Linux version 5.15.0-124-generic (gcc 11)\x00\x00")
    out = memory.kernel_banner(str(img))
    if shutil.which("grep"):
        assert "Linux version 5.15.0-124-generic" in out
    else:                                               # no grep -> graceful
        assert out.startswith("[tool unavailable]")


@pytest.mark.skipif(memory._vol_binary() is not None, reason="vol3 installed")
def test_memory_plugins_graceful_without_vol3() -> None:
    for fn in (memory.pslist, memory.pstree, memory.malfind, memory.netstat,
               memory.bash, memory.lsmod, memory.check_modules, memory.cmdline):
        assert fn("/whatever.raw").startswith("[tool unavailable]")
