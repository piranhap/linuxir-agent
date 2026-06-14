"""Day-6 Linux IR Expert: IOC extraction, intel enrichment, MITRE, re-analysis decision."""

from __future__ import annotations

import json
from pathlib import Path

from linuxir.agents import linux_ir_expert as expert
from linuxir.audit import JSONLAuditLogger
from linuxir.findings import Confidence, Finding

# A no-LLM narrative stub (the deterministic enrichment is what we assert).
ASK = lambda system, user: "narrative."  # noqa: E731


def _f(fid, agent, *, desc="", out="", tech=None) -> Finding:
    f = Finding(id=fid, title=fid, description=desc, technique=tech,
                confidence=Confidence.HIGH, source_tool_output=out)
    f.agent = agent
    return f


def test_extract_iocs_from_text_urls_and_emails():
    f = _f("x", "log",
           desc="beacon to 185.220.101.47 via http://evil.example/x.sh; mail user@corp.com",
           out="sha256 " + "ab" * 32)  # 64 hex
    iocs = expert.extract_iocs([f])
    assert "185.220.101.47" in iocs["ip"]
    assert ("ab" * 32) in iocs["hash"]
    assert "evil.example" in iocs["domain"] and "corp.com" in iocs["domain"]
    # the IP-literal URL host is NOT also treated as a domain
    assert "185.220.101.47" not in iocs["domain"]


def test_mitre_summary_normalizes_and_groups():
    f1 = _f("a", "disk", tech="T1053.003 (Cron)")
    f2 = _f("b", "log", tech="T1078 valid accounts")
    m = expert.mitre_summary([f1, f2])
    assert "T1053.003 (Persistence)" in m
    assert "T1078 (Initial Access)" in m


def _audit(tmp_path) -> JSONLAuditLogger:
    return JSONLAuditLogger(tmp_path)


def test_enrich_logs_intel_and_enriches(tmp_path):
    findings = [_f("ip-find", "log", desc="C2 to 185.220.101.47")]
    audit = _audit(tmp_path)
    res = expert.enrich(ASK, findings, audit=audit, correlations=["something"])
    verdicts = {m.indicator: m.verdict for m in res.ioc_matches}
    assert verdicts["185.220.101.47"] == "malicious"
    # intel_match audit events were written
    events = [json.loads(l) for l in (tmp_path / "tool-calls.jsonl").read_text().splitlines()]
    assert any(e.get("kind") == "intel_match" and e["indicator"] == "185.220.101.47"
               for e in events)
    assert res.polished_markdown.startswith("# Polished analysis")


def test_reanalysis_requested_on_uncorrelated_multiagent(tmp_path):
    findings = [_f("d", "disk", desc="/home/jdoe staged tooling"),
                _f("l", "log", desc="jdoe sudo to root")]
    res = expert.enrich(ASK, findings, audit=_audit(tmp_path), correlations=[])
    assert res.requests_reanalysis is True
    assert "disk" in res.reanalysis_reason and "log" in res.reanalysis_reason


def test_no_reanalysis_when_correlated(tmp_path):
    findings = [_f("d", "disk"), _f("l", "log")]
    res = expert.enrich(ASK, findings, audit=_audit(tmp_path),
                        correlations=["User 'jdoe' links disk, log"])
    assert res.requests_reanalysis is False


def test_no_reanalysis_when_disallowed_or_single_agent(tmp_path):
    two = [_f("d", "disk"), _f("l", "log")]
    assert expert.enrich(ASK, two, audit=_audit(tmp_path), correlations=[],
                         reanalysis_allowed=False).requests_reanalysis is False
    one = [_f("d", "disk"), _f("d2", "disk")]
    assert expert.enrich(ASK, one, audit=_audit(tmp_path),
                         correlations=[]).requests_reanalysis is False
