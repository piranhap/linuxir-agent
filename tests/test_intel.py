"""Day-6 threat-intel adapter + gateway tools (local-first, no network by default)."""

from __future__ import annotations

from pathlib import Path

from linuxir.adapters import intel
from linuxir.audit import JSONLAuditLogger
from linuxir.config import CaseConfig
from linuxir.gateway import ToolGateway
from linuxir.tools import build_tools


def test_lookup_ip_classifies():
    assert intel.lookup_ip("10.130.8.153").verdict == "internal"      # RFC1918
    assert intel.lookup_ip("127.0.0.1").verdict == "benign"           # loopback
    tor = intel.lookup_ip("185.220.101.47")                           # known Tor exit
    assert tor.verdict == "malicious" and "tor-exit-list" in tor.sources
    pub = intel.lookup_ip("8.8.8.8")                                  # public, no local match
    assert pub.verdict == "unknown" and "local-only" in pub.sources
    assert intel.lookup_ip("999.1.1.1").verdict == "unknown"          # invalid


def test_lookup_ip_no_network_by_default(monkeypatch):
    # Even with an AbuseIPDB key, no egress unless explicitly allowed.
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    monkeypatch.delenv("LINUXIR_ALLOW_INTEL_NETWORK", raising=False)
    r = intel.lookup_ip("8.8.8.8")
    assert r.sources == ["local-only"]


def test_lookup_hash_baseline_and_unknown():
    known = next(iter(intel.KNOWN_BAD_HASHES))
    assert "known-hashes" in intel.lookup_hash(known).sources
    assert intel.lookup_hash("a" * 64).verdict == "unknown"


def test_lookup_domain_dga_heuristic():
    dga = intel.lookup_domain("kq3v9zx1c7mn4b8w.example.com")
    assert dga.verdict == "suspicious" and "dga-heuristic" in dga.sources
    assert intel.lookup_domain("google.com").verdict == "unknown"


def test_intel_tools_dispatch_through_gateway(tmp_path):
    ev = tmp_path / "ev"; ev.mkdir()
    case = CaseConfig(case_id="i", evidence_scope=(ev.resolve(),), workspace=tmp_path / "ws")
    case.ensure_workspace()
    gw = ToolGateway(case, JSONLAuditLogger(case.audit_dir))
    gw.register_all(build_tools())

    assert "MALICIOUS" in gw.dispatch("intel_lookup_ip", {"ip": "185.220.101.47"})
    assert "INTERNAL" in gw.dispatch("intel_lookup_ip", {"ip": "10.0.0.5"})
    assert "domain" in gw.dispatch("intel_lookup_domain", {"domain": "google.com"})
