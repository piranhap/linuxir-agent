"""Hypothesis-before-execution: every tool call records, before it runs, what the agent
expected to find — and that expectation is stripped from the input the handler sees.

This is the CLAUDE.md constraint ("every tool call must record a hypothesis before
execution and an outcome after") made real in code, not asserted by a prompt: the gateway
pulls the ``hypothesis`` out of the tool input, logs it on the *pre-execution* record, and
the handler never receives it.
"""

from __future__ import annotations

import json
from pathlib import Path

from linuxir.audit import JSONLAuditLogger
from linuxir.config import CaseConfig
from linuxir.gateway import HYPOTHESIS_FIELD, ToolGateway, with_hypothesis
from linuxir.tools import build_tools


def _case(tmp_path: Path) -> CaseConfig:
    ev = tmp_path / "evidence"; ev.mkdir()
    return CaseConfig(case_id="hyp", evidence_scope=(ev.resolve(),), workspace=tmp_path / "ws")


def _gateway(tmp_path: Path) -> ToolGateway:
    case = _case(tmp_path); case.ensure_workspace()
    gw = ToolGateway(case, JSONLAuditLogger(case.audit_dir))
    gw.register_all(build_tools())
    return gw


def _calls(gw: ToolGateway) -> list[dict]:
    log = gw.audit.activity_log
    return [json.loads(l) for l in log.read_text().splitlines()
            if json.loads(l).get("kind") == "tool_call"]


# -- the schema carries the field on every tool ----------------------------------

def test_with_hypothesis_adds_required_field() -> None:
    schema = with_hypothesis({"type": "object", "properties": {"path": {"type": "string"}},
                              "required": ["path"]})
    assert HYPOTHESIS_FIELD in schema["properties"]
    assert HYPOTHESIS_FIELD in schema["required"]
    assert "path" in schema["required"]  # original requireds preserved


def test_every_registered_tool_schema_requires_hypothesis(tmp_path) -> None:
    gw = _gateway(tmp_path)
    for spec in gw.specs:
        assert HYPOTHESIS_FIELD in spec.schema_with_hypothesis["required"], spec.name


# -- dispatch records the hypothesis BEFORE execution and hides it from the handler

def test_hypothesis_logged_and_stripped_from_handler(tmp_path) -> None:
    gw = _gateway(tmp_path)
    gw.dispatch(
        "persistence_check_cron",
        {HYPOTHESIS_FIELD: "expect a malicious cron entry under /etc/cron.d"},
        agent="disk",
    )
    rec = _calls(gw)[0]
    assert rec["hypothesis"] == "expect a malicious cron entry under /etc/cron.d"
    # the handler must not see the hypothesis key in its validated input
    assert HYPOTHESIS_FIELD not in rec["input"]
    # an allowed call also captures the outcome excerpt (hypothesis -> outcome pair)
    assert rec["decision"] == "allowed"
    assert rec["outcome"] is not None


def test_blocked_call_still_records_hypothesis(tmp_path) -> None:
    gw = _gateway(tmp_path)
    # an unregistered/forbidden tool is blocked by the enforcer, but the hypothesis the model
    # committed to is still captured on the blocked record.
    gw.dispatch("write_evilness", {HYPOTHESIS_FIELD: "I expect to tamper with evidence"},
                agent="disk")
    rec = _calls(gw)[0]
    assert rec["decision"] == "blocked"
    assert rec["hypothesis"] == "I expect to tamper with evidence"


def test_missing_hypothesis_is_tolerated(tmp_path) -> None:
    # the field is required in the schema, but a model that omits it must not crash dispatch.
    gw = _gateway(tmp_path)
    gw.dispatch("persistence_check_cron", {}, agent="disk")
    assert _calls(gw)[0]["hypothesis"] is None
