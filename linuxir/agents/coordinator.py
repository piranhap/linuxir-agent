"""Coordinator — orchestrates the specialist agents, the auditor, and cross-correlation.

The coordinator is deliberately Python orchestration rather than an LLM that delegates via
tool calls: it makes the multi-agent flow deterministic and testable while each *specialist*
remains a full LLM loop over the gated tool gateway. It:

1. registers the read-only tool set on the gateway;
2. decides which specialists to run (disk + log always; memory/network when the case
   contains a memory image / pcap);
3. runs each specialist, accumulating findings in the shared context;
4. audits every finding (drops unsubstantiated ones, flags LOW/risky for human review);
5. correlates confirmed findings that share an indicator (IP, path) across artifacts —
   including the memory-present / logs-absent pattern that indicates log tampering.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..audit import JSONLAuditLogger
from ..config import CaseConfig
from ..findings import Finding
from ..gateway import ToolGateway
from ..llm import MODEL_AUDITOR
from .. import selfcorrect
from ..tools import build_tools
from .auditor import audit_findings, messages_ask
from .disk_agent import make_disk_agent
from .log_agent import make_log_agent
from .loop import AgentResult
from .memory_agent import make_memory_agent
from .network_agent import make_network_agent

_MEMORY_EXT = {".lime", ".mem", ".raw", ".dmp", ".vmem", ".img.mem"}
_PCAP_EXT = {".pcap", ".pcapng", ".cap"}
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class InvestigationResult:
    case: CaseConfig
    agent_results: list[AgentResult] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)
    confirmed_findings: list[Finding] = field(default_factory=list)
    correlations: list[str] = field(default_factory=list)
    self_corrections: list = field(default_factory=list)  # Correction entries applied
    iterations: int = 0          # how many orchestration iterations ran
    partial: bool = False        # True if max_iterations hit before stabilizing


class Coordinator:
    def __init__(self, case: CaseConfig, client: Any, max_iterations: int = 10) -> None:
        self.case = case
        self.client = client
        self.max_iterations = max(1, int(max_iterations))
        case.ensure_workspace()
        self.audit = JSONLAuditLogger(case.audit_dir)

    # -- detection ----------------------------------------------------------------

    def _find_by_ext(self, exts: set[str]) -> Path | None:
        return find_by_ext(self.case.evidence_scope, exts)

    def _read_prior_corrections(self) -> str:
        """Read the self-learning log so each iteration can learn from earlier ones."""
        log = self.case.corrections_dir / "self-learning-log.md"
        try:
            return log.read_text(encoding="utf-8")
        except OSError:
            return ""

    def _build_plan(self) -> list[tuple[Any, str]]:
        roots = ", ".join(str(p) for p in self.case.evidence_scope)
        plan: list[tuple[Any, str]] = [
            (make_disk_agent(),
             f"Evidence is mounted at: {roots}. Find all host-based persistence and "
             "on-disk attacker artifacts, then record findings."),
            (make_log_agent(),
             f"Evidence is mounted at: {roots}. Reconstruct the intrusion timeline from "
             "auth.log and the users' .bash_history; correlate source IPs to commands; "
             "record findings."),
        ]
        mem = self._find_by_ext(_MEMORY_EXT)
        if mem:
            plan.append((make_memory_agent(),
                         f"A memory image is available at {mem}. Analyze it for injected "
                         "code, suspicious processes, and live connections; record findings."))
        pcap = self._find_by_ext(_PCAP_EXT)
        if pcap:
            plan.append((make_network_agent(),
                         f"A packet capture is available at {pcap}. Analyze it for C2 "
                         "beaconing and exfiltration; record findings."))
        return plan

    def _run_one_specialist(self, agent: Any, task: str) -> tuple[AgentResult, list]:
        """Run a single specialist in its OWN gateway/context (parallel-safe isolation).

        Each agent holding only its own gateway means concurrent agents never race on a
        shared findings list — the per-agent context partitioning the design relies on.
        The ConstraintEnforcer still gates every call, and the shared (locked) audit logger
        keeps one authoritative record across threads.
        """
        gateway = ToolGateway(self.case, self.audit)
        gateway.register_all(build_tools())
        self.audit.log_agent_message(
            sender="orchestrator", receiver=agent.name,
            msg_type="task_assignment", payload={"task": task[:200]},
        )
        self.audit.log_event(kind="agent_start", agent=agent.name)
        res = agent.run(self.client, gateway, task)
        for f in res.findings:
            if f.agent is None:
                f.agent = agent.name
        self.audit.log_event(kind="agent_done", agent=agent.name, turns=res.turns,
                             findings=len(res.findings))
        self.audit.log_agent_message(
            sender=agent.name, receiver="orchestrator", msg_type="finding_update",
            payload={"count": len(res.findings), "ids": [f.id for f in res.findings]},
        )
        return res, list(gateway.context.corrections)

    def _run_specialists_parallel(self, result: InvestigationResult) -> None:
        """Dispatch all specialists concurrently; merge their isolated results in order."""
        plan = self._build_plan()
        with ThreadPoolExecutor(max_workers=max(1, len(plan))) as ex:
            futures = [ex.submit(self._run_one_specialist, agent, task)
                       for agent, task in plan]
            for fut in futures:  # collect in submission order for deterministic output
                res, corrections = fut.result()
                result.agent_results.append(res)
                result.all_findings.extend(res.findings)
                result.self_corrections.extend(corrections)

    def _needs_reanalysis(self, result: InvestigationResult) -> bool:
        """Whether another iteration is warranted. No expert pass yet (Days 6-7), so a
        single pass is stable; this is the hook the IR-expert agent will later drive."""
        return False

    # -- orchestration ------------------------------------------------------------

    def run(self) -> InvestigationResult:
        result = InvestigationResult(case=self.case)
        roots = ", ".join(str(p) for p in self.case.evidence_scope)
        self.audit.log_event(kind="investigation_start", case=self.case.case_id,
                             evidence=roots, max_iterations=self.max_iterations)

        for iteration in range(1, self.max_iterations + 1):
            result.iterations = iteration
            # Read the corrections log BEFORE acting — close the learning loop.
            prior = self._read_prior_corrections()
            self.audit.log_event(kind="iteration_start", iteration=iteration,
                                 prior_corrections_chars=len(prior))

            if iteration == 1:
                self._run_specialists_parallel(result)

            # Audit: Haiku verifies each claim against its cited tool output.
            ask = messages_ask(self.client, MODEL_AUDITOR)
            self.audit.log_agent_message(
                sender="orchestrator", receiver="auditor", msg_type="audit_request",
                payload={"findings": len(result.all_findings)})
            result.confirmed_findings = audit_findings(
                ask, result.all_findings, audit=self.audit)
            self.audit.log_agent_message(
                sender="auditor", receiver="orchestrator", msg_type="finding_update",
                payload={"confirmed": len(result.confirmed_findings),
                         "dropped": len(result.all_findings) - len(result.confirmed_findings)})

            # Correlate confirmed findings across artifacts.
            result.correlations = correlate_findings(result.confirmed_findings)
            for c in result.correlations:
                self.audit.log_event(kind="correlation", note=c)

            if not self._needs_reanalysis(result):
                break
            self.audit.log_agent_message(
                sender="orchestrator", receiver="orchestrator",
                msg_type="reanalysis_request", payload={"after_iteration": iteration})
        else:
            # Loop exhausted without stabilizing — degrade gracefully to a partial report.
            result.partial = True
            self.audit.log_event(kind="max_iterations_reached", max=self.max_iterations)

        self.audit.log_event(
            kind="investigation_done",
            iterations=result.iterations,
            partial=result.partial,
            total=len(result.all_findings),
            confirmed=len(result.confirmed_findings),
            correlations=len(result.correlations),
        )
        return result


def find_by_ext(roots, exts: set[str]) -> Path | None:
    """First file under any evidence root whose suffix is in ``exts`` (or None)."""
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        for f in root.rglob("*"):
            if f.is_file() and f.suffix.lower() in exts:
                return f
    return None


def correlate_findings(findings: list[Finding]) -> list[str]:
    """Link confirmed findings that share an indicator (IP) across agents.

    Shared across both runtimes. Beyond corroboration, it surfaces the memory-present /
    logs-absent pattern that indicates log tampering rather than a contradiction to drop.
    """
    notes: list[str] = []
    by_ip: dict[str, list[Finding]] = {}
    for f in findings:
        blob = " ".join([f.title, f.description, f.source_tool_output, *f.evidence_refs])
        for ip in set(_IP_RE.findall(blob)):
            by_ip.setdefault(ip, []).append(f)

    for ip, group in by_ip.items():
        agents = sorted({f.agent or "?" for f in group})
        if len(agents) > 1:
            ids = ", ".join(f.id for f in group)
            notes.append(
                f"Indicator {ip} corroborated across {len(agents)} agents "
                f"({', '.join(agents)}): findings {ids}."
            )

    # Cross-artifact contradiction → reconciliation (self-correction sequence 3):
    # memory-present / logs-absent indicators are log tampering, not a contradiction to drop.
    notes.extend(selfcorrect.reconcile(findings))
    return notes
