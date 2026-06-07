"""Day-4 network_server: pcap tools.

tshark is usually absent on the test host, so live calls degrade gracefully. The Python
post-processing (exfil byte-summing, Tor-exit matching) is verified by stubbing run_binary
with synthetic tshark field output, and the tshark invocations are checked for the right
filters/fields.
"""

from __future__ import annotations

import pytest

from linuxir.adapters import network


@pytest.fixture
def captured(monkeypatch):
    """Stub run_binary; record argv and return a scripted result per call."""
    calls = {"argv": []}

    def fake(argv, **kw):
        calls["argv"].append(argv)
        if argv == calls.get("_exfil_argv") or ("ip.len" in argv):
            return {"available": True, "returncode": 0, "argv": argv,
                    "stdout": "185.220.101.47\t1400\n185.220.101.47\t2000000\n8.8.8.8\t60\n"}
        if argv[-1] == "ip.dst":  # find_tor_exits: trailing field is ip.dst
            return {"available": True, "returncode": 0, "argv": argv,
                    "stdout": "185.220.101.47\n8.8.8.8\n"}
        return {"available": True, "returncode": 0, "argv": argv, "stdout": "field\toutput\n"}

    monkeypatch.setattr(network, "run_binary", fake)
    return calls


def test_detect_exfil_sums_and_flags(captured) -> None:
    out = network.detect_exfil("/e.pcap", flag_bytes=1_000_000)
    assert "185.220.101.47: 2,001,400 bytes" in out
    assert "LARGE OUTBOUND" in out
    assert "8.8.8.8: 60 bytes" in out
    assert "8.8.8.8: 60 bytes   [LARGE" not in out  # small transfer not flagged


def test_find_tor_exits_matches_prefix(captured) -> None:
    out = network.find_tor_exits("/e.pcap")
    assert "185.220.101.47" in out and "Tor exit" in out
    assert "8.8.8.8" not in out


def test_extract_dns_builds_dns_filter(captured) -> None:
    network.extract_dns("/e.pcap")
    argv = captured["argv"][-1]
    assert "-Y" in argv and "dns" in argv
    assert "dns.qry.name" in argv


def test_extract_http_builds_request_filter(captured) -> None:
    network.extract_http("/e.pcap")
    argv = captured["argv"][-1]
    assert "http.request" in argv
    assert "http.user_agent" in argv


def test_extract_credentials_filter(captured) -> None:
    network.extract_credentials("/e.pcap")
    argv = captured["argv"][-1]
    disp = argv[argv.index("-Y") + 1]
    assert "http.authorization" in disp and "ftp.request.command" in disp


def test_network_graceful_without_tshark(monkeypatch) -> None:
    monkeypatch.setattr(network, "run_binary",
                        lambda argv, **kw: {"available": False, "reason": "tshark not installed"})
    for fn in (network.extract_dns, network.extract_http, network.detect_exfil,
               network.extract_credentials, network.find_tor_exits, network.pcap_summary):
        assert fn("/whatever.pcap").startswith("[tool unavailable]")
