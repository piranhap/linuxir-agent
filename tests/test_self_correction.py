"""Day-4 self-correction: the three recovery sequences, proven deterministically.

1. Volatility3 profile/symbol failure -> recovery (kernel banner + retry).
2. Empty persistence result -> pivot to the sibling checks.
3. Cross-artifact contradiction (memory-present / logs-absent) -> reconciliation, not discard.

Tested at three levels: the pure detector, the gateway dispatch (hint appended + logged),
and the live agent loop (the hint reaches the model on the next turn).
"""

from __future__ import annotations

import json
from pathlib import Path

from linuxir import selfcorrect
from linuxir.agents.loop import run_agent
from linuxir.audit import JSONLAuditLogger
from linuxir.config import CaseConfig
from linuxir.findings import Confidence, Finding
from linuxir.gateway import ToolGateway
from linuxir.llm import FakeClient, text, tool_call
from linuxir.tools import build_tools


# -- 1. the pure detector ---------------------------------------------------------

def test_recovery_hint_vol3_unavailable() -> None:
    c = selfcorrect.recovery_hint(
        "memory_pslist", "[tool unavailable] volatility3 (vol/vol3) is not installed")
    assert c and c.trigger == "vol3_symbol_or_unavailable"
    assert "memory_kernel_banner" in c.hint


def test_recovery_hint_vol3_symbol_failure() -> None:
    c = selfcorrect.recovery_hint(
        "memory_malfind", "Unable to validate the location of the kernel symbols")
    assert c and c.trigger == "vol3_symbol_or_unavailable"


def test_recovery_hint_empty_persistence_pivot() -> None:
    c = selfcorrect.recovery_hint("persistence_check_cron",
                                  "[no cron artifacts found in evidence scope]")
    assert c and c.trigger == "empty_persistence_result"
    # points at the sibling checks, not itself
    assert "persistence_check_systemd" in c.hint
    assert "run the sibling checks" in c.hint


def test_recovery_hint_path_error() -> None:
    c = selfcorrect.recovery_hint("read_evidence_file", "[not found] /x/y")
    assert c and c.trigger == "path_or_tool_error"
    assert "list_directory" in c.hint


def test_recovery_hint_none_on_normal_result() -> None:
    assert selfcorrect.recovery_hint("persistence_check_cron", "=== /etc/crontab ===\n...") is None
    assert selfcorrect.recovery_hint("memory_kernel_banner", "[tool unavailable] ...") is None


# -- 2. gateway integration: hint appended to result + recorded + audited ---------

def _empty_case(tmp_path: Path) -> CaseConfig:
    ev = tmp_path / "evidence"; ev.mkdir()
    return CaseConfig(case_id="sc", evidence_scope=(ev.resolve(),), workspace=tmp_path / "ws")


def test_dispatch_appends_hint_and_logs(tmp_path) -> None:
    case = _empty_case(tmp_path); case.ensure_workspace()
    gw = ToolGateway(case, JSONLAuditLogger(case.audit_dir)); gw.register_all(build_tools())

    out = gw.dispatch("persistence_check_cron", {}, agent="disk")
    assert "[self-correction]" in out                       # fed back to the model
    assert [c.trigger for c in gw.context.corrections] == ["empty_persistence_result"]

    events = [json.loads(l) for l in (case.audit_dir / "tool-calls.jsonl").read_text().splitlines()]
    assert any(e.get("kind") == "self_correction" and e["tool"] == "persistence_check_cron"
               for e in events)


# -- 3. reconciliation (sequence 3) -----------------------------------------------

def _finding(fid: str, agent: str, blob: str) -> Finding:
    f = Finding(id=fid, title=fid, description=blob, technique=None,
                confidence=Confidence.HIGH, evidence_refs=[], source_tool_output=blob)
    f.agent = agent
    return f


def test_reconcile_memory_present_logs_absent() -> None:
    findings = [
        _finding("mem-conn", "memory", "established connection to 185.220.101.47"),
        _finding("disk-cron", "disk", "cron beacon to 185.220.101.47"),
    ]
    notes = selfcorrect.reconcile(findings)
    assert any("185.220.101.47" in n and "log tampering" in n for n in notes)
    assert any("not discarded" in n for n in notes)


def test_reconcile_no_note_when_logs_corroborate() -> None:
    findings = [
        _finding("mem-conn", "memory", "connection to 9.9.9.9"),
        _finding("log-evt", "log", "auth.log shows 9.9.9.9"),
    ]
    assert selfcorrect.reconcile(findings) == []


# -- the loop actually feeds the hint to the model next turn ----------------------

def test_agent_loop_receives_self_correction(tmp_path) -> None:
    case = _empty_case(tmp_path); case.ensure_workspace()
    gw = ToolGateway(case, JSONLAuditLogger(case.audit_dir)); gw.register_all(build_tools())

    def responder(kwargs):
        # turn 0: call the (empty) cron check; turn 1: finish.
        assistants = sum(1 for m in kwargs["messages"] if m.get("role") == "assistant")
        if assistants == 0:
            return tool_call(("t1", "persistence_check_cron", {}))
        return text("done")

    res = run_agent(FakeClient(responder=responder), agent_name="disk",
                    system="host-based persistence", tool_names=["persistence_check_cron"],
                    task="find persistence", gateway=gw, model="m", thinking=False)
    # the tool_result returned to the model carries the recovery guidance
    tool_results = [b for m in res.messages if m.get("role") == "user"
                    and isinstance(m.get("content"), list)
                    for b in m["content"] if isinstance(b, dict) and b.get("type") == "tool_result"]
    assert any("[self-correction]" in tr["content"] for tr in tool_results)
