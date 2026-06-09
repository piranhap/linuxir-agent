"""Day-5 orchestrator: parallel dispatch, agent-messages.jsonl, iteration cap.

Asserts the orchestration contract: specialists run in parallel (each in its own gateway),
every inter-agent message is logged with timestamp/sender/receiver/type to a dedicated
stream, the corrections log is read at the start of each iteration, and the run degrades to
a partial report rather than looping past --max-iterations.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from linuxir.agents.coordinator import Coordinator
from linuxir.config import CaseConfig
from linuxir.demo import demo_responder
from linuxir.llm import FakeClient

EVIDENCE = Path(__file__).parent / "fixtures" / "evidence"


def _coord(tmp_path, **kw) -> Coordinator:
    case = CaseConfig(case_id="orch-test", evidence_scope=(EVIDENCE.resolve(),),
                      workspace=tmp_path)
    return Coordinator(case, FakeClient(responder=demo_responder), **kw)


def _events(case: CaseConfig) -> list[dict]:
    return [json.loads(l) for l in (case.audit_dir / "audit.jsonl").read_text().splitlines()]


def _messages(case: CaseConfig) -> list[dict]:
    f = case.audit_dir / "agent-messages.jsonl"
    return [json.loads(l) for l in f.read_text().splitlines()] if f.exists() else []


def test_single_pass_is_stable(tmp_path):
    res = _coord(tmp_path).run()
    assert res.iterations == 1
    assert res.partial is False


def test_specialists_run_in_parallel(tmp_path):
    res = _coord(tmp_path).run()
    agents = {r.agent for r in res.agent_results}
    assert {"disk", "log"} <= agents
    # both agents actually produced findings (both branches executed)
    assert any(f.agent == "disk" for f in res.all_findings)
    assert any(f.agent == "log" for f in res.all_findings)


def test_agent_messages_logged_well_formed(tmp_path):
    res = _coord(tmp_path).run()
    msgs = _messages(res.case)
    assert msgs, "agent-messages.jsonl should not be empty"
    for m in msgs:  # every message carries the required envelope
        assert m["kind"] == "agent_message"
        assert m["ts"] and m["sender"] and m["receiver"] and m["msg_type"]

    types = [(m["sender"], m["receiver"], m["msg_type"]) for m in msgs]
    assert ("orchestrator", "disk", "task_assignment") in types
    assert ("orchestrator", "log", "task_assignment") in types
    assert ("disk", "orchestrator", "finding_update") in types
    assert ("orchestrator", "auditor", "audit_request") in types
    assert ("auditor", "orchestrator", "finding_update") in types


def test_agent_messages_separate_from_tool_calls(tmp_path):
    """The agent-message stream must be distinct from the tool-call activity log."""
    res = _coord(tmp_path).run()
    activity = _events(res.case)
    assert not any(e.get("kind") == "agent_message" for e in activity)
    assert all(m.get("kind") == "tool_call" or "tool" not in m for m in _messages(res.case))


def test_corrections_read_each_iteration(tmp_path):
    res = _coord(tmp_path).run()
    starts = [e for e in _events(res.case) if e.get("kind") == "iteration_start"]
    assert len(starts) == res.iterations
    assert all("prior_corrections_chars" in e for e in starts)  # the log was read


def test_max_iterations_graceful_degradation(tmp_path):
    """If the run never stabilizes, it stops at the cap and flags a partial report."""
    class NeverStable(Coordinator):
        def _needs_reanalysis(self, result):  # force another iteration every time
            return True

    case = CaseConfig(case_id="cap", evidence_scope=(EVIDENCE.resolve(),), workspace=tmp_path)
    res = NeverStable(case, FakeClient(responder=demo_responder), max_iterations=3).run()
    assert res.iterations == 3
    assert res.partial is True
    assert any(e.get("kind") == "max_iterations_reached" for e in _events(case))


def test_max_iterations_floor(tmp_path):
    # 0/negative is clamped to at least one iteration (never a no-op).
    res = _coord(tmp_path, max_iterations=0).run()
    assert res.iterations == 1


def test_correlate_links_on_username():
    from linuxir.agents.coordinator import correlate_findings
    from linuxir.findings import Confidence, Finding

    def f(fid, agent, blob):
        x = Finding(id=fid, title=fid, description=blob, confidence=Confidence.HIGH)
        x.agent = agent
        return x

    notes = correlate_findings([
        f("d", "disk", "setuid tooling staged in /home/bmorse/.ssh"),
        f("l", "log", "sudo session opened for user bmorse"),
    ])
    assert any("User 'bmorse' links" in n for n in notes)

    # system accounts are not treated as correlating indicators
    sys_notes = correlate_findings([
        f("d", "disk", "config in /home/root"),
        f("l", "log", "session opened for user root"),
    ])
    assert not any("links" in n for n in sys_notes)


def test_expert_reanalysis_loop(tmp_path, monkeypatch):
    """Expert requests one re-analysis (multi-agent findings, no correlation) -> 2 iterations,
    bounded, with the reason recorded to the self-learning log."""
    import linuxir.agents.coordinator as coord
    monkeypatch.setattr(coord, "correlate_findings", lambda findings: [])  # force the gap

    res = _coord(tmp_path).run()
    assert res.iterations == 2          # one re-analysis honored, then stable
    assert res.partial is False
    assert res.expert is not None
    sll = (res.case.corrections_dir / "self-learning-log.md").read_text()
    assert "requested re-analysis" in sll
    # the reanalysis_request inter-agent message was logged
    assert any(m["msg_type"] == "reanalysis_request" for m in _messages(res.case))


def test_expert_pass_runs_and_writes_polished(tmp_path):
    res = _coord(tmp_path).run()
    assert res.expert is not None and res.expert.mitre_techniques
    assert (res.case.vault_path / "analysis-polished.md").exists()
    # IR-expert participated in the agent-message log
    senders = {m["sender"] for m in _messages(res.case)}
    assert "ir_expert" in senders
