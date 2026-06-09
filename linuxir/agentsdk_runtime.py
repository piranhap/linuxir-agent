"""Subscription-auth runtime — run the agents on a Claude Pro/Max plan, $0 per-token.

This runtime drives the investigation through the **Claude Agent SDK** (which authenticates
with your Claude subscription via ``CLAUDE_CODE_OAUTH_TOKEN`` — no billed API key) instead
of the raw Messages API. The forensic tools are exposed as an **in-process MCP server**, so
the architectural guarantee is preserved end-to-end:

* every tool handler routes through :meth:`ToolGateway.dispatch`, so the ConstraintEnforcer
  vets each call before it runs — exactly as on the raw-API path;
* the built-in Claude Code tools (Bash/Read/Write/Edit/...) are **disabled** (``tools=[]``),
  and ``allowed_tools`` is restricted to ``mcp__linuxir__*``, so the model literally cannot
  touch the host filesystem except through our gated, read-only tools.

It reuses the same gateway, tool specs, specialist prompts, auditor, correlation, and
reporting as the raw-API :class:`~linuxir.agents.coordinator.Coordinator`. Only the model
transport differs.

Prerequisites on the run host (e.g. the SANS VM):
    1. Node + Claude Code CLI:  ``npm install -g @anthropic-ai/claude-code``
    2. A subscription OAuth token (generate on a machine with a browser):  ``claude setup-token``
       then on the VM:  ``export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...``
    3. Ensure ``ANTHROPIC_API_KEY`` is NOT set (it silently overrides the OAuth token).

This subscription path is licensed for **personal use** — run it yourself; do not ship it
as a multi-user service on subscription auth.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .agents.auditor import audit_findings
from .agents.coordinator import (
    InvestigationResult,
    correlate_findings,
    find_by_ext,
    _MEMORY_EXT,
    _PCAP_EXT,
)
from .agents.linux_ir_expert import enrich as expert_enrich
from .agents.disk_agent import make_disk_agent
from .agents.log_agent import make_log_agent
from .agents.loop import AgentResult
from .agents.memory_agent import make_memory_agent
from .agents.network_agent import make_network_agent
from .audit import JSONLAuditLogger
from .config import CaseConfig
from .gateway import ToolGateway, is_blocked
from .tools import build_tools

MCP_SERVER_NAME = "linuxir"
# Built-in Claude Code tools we explicitly forbid so the model cannot bypass the gateway.
_BUILTIN_DENY = ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Task"]


class SubscriptionRuntime:
    """Orchestrates the specialists/auditor via the Claude Agent SDK (subscription auth)."""

    def __init__(self, case: CaseConfig, *, model: str | None = None, effort: str | None = None,
                 max_iterations: int = 10):
        case.ensure_workspace()
        self.case = case
        self.model = model
        self.effort = effort
        self.max_iterations = max(1, int(max_iterations))
        self.audit = JSONLAuditLogger(case.audit_dir)
        self.gateway = ToolGateway(case, self.audit)
        self.gateway.register_all(build_tools())
        self.current_agent = "?"
        self._server = self._build_server()

    # -- in-process MCP server over the gateway -----------------------------------

    def _build_server(self) -> Any:
        from claude_agent_sdk import create_sdk_mcp_server, tool

        sdk_tools = []
        gateway = self.gateway
        runtime = self

        for spec in self.gateway.specs:
            @tool(spec.name, spec.description, spec.input_schema)
            async def handler(args: dict, _name: str = spec.name) -> dict:
                # The single chokepoint: dispatch runs the ConstraintEnforcer first.
                out = gateway.dispatch(_name, dict(args), agent=runtime.current_agent)
                return {"content": [{"type": "text", "text": out}], "is_error": is_blocked(out)}

            sdk_tools.append(handler)

        return create_sdk_mcp_server(MCP_SERVER_NAME, "0.1.0", sdk_tools)

    def _options(self, *, system: str | None, allowed_tools: list[str], with_tools: bool):
        from claude_agent_sdk import ClaudeAgentOptions

        kwargs: dict[str, Any] = {
            "system_prompt": system,
            "tools": [],  # disable ALL built-in Claude Code tools
            "mcp_servers": {MCP_SERVER_NAME: self._server} if with_tools else {},
            "allowed_tools": allowed_tools,
            "disallowed_tools": list(_BUILTIN_DENY),
            "permission_mode": "bypassPermissions",  # headless: no interactive prompts
            "setting_sources": None,  # don't load project/user CLAUDE.md or settings
            "max_turns": 30,
        }
        if self.model:
            kwargs["model"] = self.model
        if self.effort:
            kwargs["effort"] = self.effort
        return ClaudeAgentOptions(**kwargs)

    # -- query helpers ------------------------------------------------------------

    async def _run_specialist(self, *, agent_name, system, tool_names, task) -> str:
        from claude_agent_sdk import ResultMessage, query

        self.current_agent = agent_name
        allowed = [f"mcp__{MCP_SERVER_NAME}__{n}" for n in tool_names]
        options = self._options(system=system, allowed_tools=allowed, with_tools=True)
        final = ""
        async for msg in query(prompt=task, options=options):
            if isinstance(msg, ResultMessage):
                final = getattr(msg, "result", "") or final
        return final

    async def _ask_async(self, system: str, user: str) -> str:
        from claude_agent_sdk import ResultMessage, query

        options = self._options(system=system, allowed_tools=[], with_tools=False)
        final = ""
        async for msg in query(prompt=user, options=options):
            if isinstance(msg, ResultMessage):
                final = getattr(msg, "result", "") or final
        return final

    # -- orchestration ------------------------------------------------------------

    async def _run_specialists(self, result: InvestigationResult) -> None:
        roots = ", ".join(str(p) for p in self.case.evidence_scope)
        self.audit.log_event(kind="investigation_start", case=self.case.case_id,
                             evidence=roots, runtime="subscription")

        plan = [
            (make_disk_agent(),
             f"Evidence is mounted at: {roots}. Find all host-based persistence and on-disk "
             "attacker artifacts, then record findings."),
            (make_log_agent(),
             f"Evidence is mounted at: {roots}. Reconstruct the intrusion timeline from "
             "auth.log and the users' .bash_history; correlate source IPs to commands; "
             "record findings."),
        ]
        mem = find_by_ext(self.case.evidence_scope, _MEMORY_EXT)
        if mem:
            plan.append((make_memory_agent(),
                         f"A memory image is available at {mem}. Analyze it for injected "
                         "code, suspicious processes, and live connections; record findings."))
        pcap = find_by_ext(self.case.evidence_scope, _PCAP_EXT)
        if pcap:
            plan.append((make_network_agent(),
                         f"A packet capture is available at {pcap}. Analyze it for C2 "
                         "beaconing and exfiltration; record findings."))

        for agent, task in plan:
            self.audit.log_agent_message(
                sender="orchestrator", receiver=agent.name,
                msg_type="task_assignment", payload={"task": task[:200]})
            self.audit.log_event(kind="agent_start", agent=agent.name)
            start = len(self.gateway.context.findings)
            final = await self._run_specialist(
                agent_name=agent.name, system=agent.system,
                tool_names=agent.tool_names, task=task,
            )
            findings = self.gateway.context.findings[start:]
            for f in findings:
                if f.agent is None:
                    f.agent = agent.name
            result.agent_results.append(
                AgentResult(agent=agent.name, final_text=final, findings=findings, turns=0)
            )
            self.audit.log_event(kind="agent_done", agent=agent.name, findings=len(findings))
            self.audit.log_agent_message(
                sender=agent.name, receiver="orchestrator", msg_type="finding_update",
                payload={"count": len(findings), "ids": [f.id for f in findings]})

        result.all_findings = list(self.gateway.context.findings)
        result.self_corrections = list(self.gateway.context.corrections)

    def run(self) -> InvestigationResult:
        result = InvestigationResult(case=self.case)

        # Phase 1 (async): run the specialists through the Agent SDK.
        asyncio.run(self._run_specialists(result))

        # Phase 2: audit each finding. The auditor is sync; back its `ask` with a fresh
        # event loop per call (the specialist loop above has already finished, so this is
        # not a nested asyncio.run).
        def ask(system: str, user: str) -> str:
            return asyncio.run(self._ask_async(system, user))

        result.confirmed_findings = audit_findings(ask, result.all_findings, audit=self.audit)
        result.correlations = correlate_findings(result.confirmed_findings)
        for c in result.correlations:
            self.audit.log_event(kind="correlation", note=c)

        # Senior IR-expert review + threat-intel enrichment (parity with the Coordinator).
        self.audit.log_agent_message(
            sender="orchestrator", receiver="ir_expert", msg_type="task_assignment",
            payload={"confirmed": len(result.confirmed_findings)})
        result.expert = expert_enrich(
            ask, result.confirmed_findings, audit=self.audit,
            correlations=result.correlations)
        (self.case.vault_path / "analysis-polished.md").write_text(
            result.expert.polished_markdown, encoding="utf-8")
        self.audit.log_agent_message(
            sender="ir_expert", receiver="orchestrator", msg_type="intel_match",
            payload={"iocs": len(result.expert.ioc_matches),
                     "mitre": result.expert.mitre_techniques})

        self.audit.log_event(
            kind="investigation_done", runtime="subscription",
            total=len(result.all_findings), confirmed=len(result.confirmed_findings),
            correlations=len(result.correlations),
        )
        return result
