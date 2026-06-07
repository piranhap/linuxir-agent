"""Adapter tests: real reads against the fixture tree + graceful fallback for absent tools."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from linuxir.adapters import disk
from linuxir.adapters.base import run_binary, summarize

EVIDENCE = Path(__file__).parent / "fixtures" / "evidence"


def test_find_cron_persistence_surfaces_backdoor() -> None:
    out = disk.find_cron_persistence([EVIDENCE])
    assert "apache-monitor" in out
    assert "185.220.101.47" in out
    assert "SUSPICIOUS" in out  # curl|bash tokens flagged


def test_find_systemd_persistence_flags_tmp_execstart() -> None:
    out = disk.find_systemd_persistence([EVIDENCE])
    assert "dbus-update.service" in out
    assert "/dev/shm" in out or "/tmp/" in out
    assert "systemd-networkd.service" in out  # legit unit also listed (context for auditor)


def test_find_authorized_keys_finds_attacker_key() -> None:
    out = disk.find_authorized_keys([EVIDENCE])
    assert "root/.ssh/authorized_keys" in out
    assert "attacker@evil" in out


def test_read_text_file_and_missing() -> None:
    content = disk.read_text_file(EVIDENCE / "home/victim/.bash_history")
    assert "scp /tmp/loot.tgz" in content
    assert disk.read_text_file(EVIDENCE / "nope").startswith("[not found]")


def test_run_binary_missing_is_graceful() -> None:
    res = run_binary(["definitely-not-installed-xyz", "--help"])
    assert res["available"] is False
    assert "not installed" in res["reason"]
    assert summarize(res).startswith("[tool unavailable]")


@pytest.mark.skipif(shutil.which("mmls") is None, reason="sleuthkit not installed")
def test_run_binary_present_returns_output() -> None:
    # mmls on a non-image errors but still 'available' with a returncode — proves the
    # real-binary path executes when the tool exists.
    res = run_binary(["mmls", "/nonexistent.img"])
    assert res["available"] is True
    assert "returncode" in res
