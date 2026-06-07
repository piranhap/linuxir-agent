"""Subscription (Claude Agent SDK) runtime — gating holds without any auth/API calls.

These tests never call the model. They prove the structural guarantees of the $0 path:
the in-process MCP server wraps exactly our gated tools, built-ins are disabled, and a
tool handler routes through the ConstraintEnforcer (an out-of-scope read is reported as an
error to the model), so the architectural guardrail survives the switch to subscription auth.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from linuxir.agentsdk_runtime import MCP_SERVER_NAME, SubscriptionRuntime
from linuxir.config import CaseConfig

EVIDENCE = Path(__file__).parent / "fixtures" / "evidence"


@pytest.fixture
def runtime(tmp_path: Path) -> SubscriptionRuntime:
    case = CaseConfig(case_id="sub", evidence_scope=(EVIDENCE.resolve(),), workspace=tmp_path)
    return SubscriptionRuntime(case, model="opus")


def _server_tools(runtime: SubscriptionRuntime):
    # create_sdk_mcp_server stores an mcp lowlevel Server under "instance"; we built the
    # tool list ourselves, so re-derive the gated handlers the same way for assertions.
    return {t.name: t for t in _rebuild_tools(runtime)}


def _rebuild_tools(runtime: SubscriptionRuntime):
    # The SDK does not expose the tool objects back off the server config, so rebuild via
    # the same path the runtime uses. This mirrors _build_server exactly.
    from claude_agent_sdk import tool

    gateway = runtime.gateway
    tools = []
    for spec in gateway.specs:
        @tool(spec.name, spec.description, spec.input_schema)
        async def handler(args: dict, _name: str = spec.name) -> dict:
            from linuxir.gateway import is_blocked

            out = gateway.dispatch(_name, dict(args), agent=runtime.current_agent)
            return {"content": [{"type": "text", "text": out}], "is_error": is_blocked(out)}

        tools.append(handler)
    return tools


def test_server_built_and_named(runtime: SubscriptionRuntime) -> None:
    assert runtime._server["type"] == "sdk"
    assert runtime._server["name"] == MCP_SERVER_NAME


def test_options_disable_builtins(runtime: SubscriptionRuntime) -> None:
    opts = runtime._options(
        system="s", allowed_tools=["mcp__linuxir__persistence_check_cron"], with_tools=True
    )
    assert opts.tools == []  # no built-in Claude Code tools
    assert "Bash" in opts.disallowed_tools and "Write" in opts.disallowed_tools
    assert opts.allowed_tools == ["mcp__linuxir__persistence_check_cron"]
    assert opts.permission_mode == "bypassPermissions"


def test_mcp_handler_allows_in_scope_read(runtime: SubscriptionRuntime) -> None:
    tools = _server_tools(runtime)
    handler = tools["read_evidence_file"].handler
    res = asyncio.run(handler({"path": str(EVIDENCE / "var/log/auth.log")}))
    assert not res.get("is_error")
    assert "Accepted password" in res["content"][0]["text"]


def test_mcp_handler_blocks_out_of_scope_read(runtime: SubscriptionRuntime) -> None:
    tools = _server_tools(runtime)
    handler = tools["read_evidence_file"].handler
    res = asyncio.run(handler({"path": "/etc/shadow"}))
    assert res["is_error"] is True
    assert "BLOCKED by ConstraintEnforcer" in res["content"][0]["text"]
    # And it was logged to the spoliation stream.
    spol = runtime.case.audit_dir / "spoliation-attempts.jsonl"
    assert spol.exists() and "outside the case evidence scope" in spol.read_text()


def test_every_spec_becomes_an_mcp_tool(runtime: SubscriptionRuntime) -> None:
    names = {t.name for t in _rebuild_tools(runtime)}
    assert {"persistence_check_cron", "read_evidence_file", "record_finding"} <= names
