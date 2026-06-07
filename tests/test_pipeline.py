"""End-to-end offline pipeline test — coordinator → agents → auditor → report.

Runs the entire multi-agent flow against the bundled evidence fixture with a scripted
FakeClient (zero API spend) and asserts the behaviors the accuracy report claims:

* legitimate, evidence-backed findings are confirmed;
* an unsupported "meterpreter" claim is dropped by the auditor before the report;
* a LOW-confidence finding is flagged for human review;
* a single attacker IP is correlated across the disk and log agents;
* every tool call is logged, and no evidence-mutation slipped through.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from linuxir.agents.coordinator import Coordinator
from linuxir.config import CaseConfig
from linuxir.demo import demo_responder
from linuxir.llm import FakeClient
from linuxir.report import write_reports

EVIDENCE = Path(__file__).parent / "fixtures" / "evidence"


@pytest.fixture
def result(tmp_path: Path):
    case = CaseConfig(
        case_id="pipeline-test",
        evidence_scope=(EVIDENCE.resolve(),),
        workspace=tmp_path,
    )
    coord = Coordinator(case, FakeClient(responder=demo_responder))
    return coord.run()


def _ids(findings):
    return {f.id for f in findings}


def test_legit_findings_confirmed(result):
    confirmed = _ids(result.confirmed_findings)
    assert "cron-persistence-backdoor" in confirmed
    assert "ssh-bruteforce-initial-access" in confirmed
    assert "data-exfiltration-scp" in confirmed
    assert "ssh-authorized-key-backdoor" in confirmed


def test_hallucination_dropped_by_auditor(result):
    assert "meterpreter-implant" in _ids(result.all_findings)
    assert "meterpreter-implant" not in _ids(result.confirmed_findings)
    dropped = next(f for f in result.all_findings if f.id == "meterpreter-implant")
    assert dropped.audited and not dropped.confirmed
    assert dropped.hallucination_risk.value in {"moderate", "high"}


def test_low_confidence_flagged_for_review(result):
    low = next(f for f in result.confirmed_findings if f.id == "systemd-dbus-update-suspect")
    assert low.confidence.value == "LOW"
    assert low.requires_human_review is True


def test_cross_agent_correlation_on_attacker_ip(result):
    assert any("185.220.101.47" in c for c in result.correlations)


def test_findings_cite_real_tool_output(result):
    # Grounding is genuine: cited output came from the adapters, not the script.
    cron = next(f for f in result.confirmed_findings if f.id == "cron-persistence-backdoor")
    assert "apache-monitor" in cron.source_tool_output


def test_audit_log_complete_and_no_spoliation(result):
    audit = result.case.audit_dir / "audit.jsonl"
    kinds = [json.loads(l)["kind"] for l in audit.read_text().splitlines() if l.strip()]
    assert kinds.count("tool_call") >= 1
    assert "investigation_done" in kinds
    # No evidence-mutation attempts occurred during a normal run.
    spoliation = result.case.audit_dir / "spoliation-attempts.jsonl"
    assert not spoliation.exists() or spoliation.read_text().strip() == ""


def test_reports_written(result):
    report_path, notes = write_reports(result)
    assert report_path.exists()
    assert "Auditor-dropped findings" in report_path.read_text()
    assert any(n.name == "analysis-disk.md" for n in notes)
    assert any(n.name == "analysis-log.md" for n in notes)
