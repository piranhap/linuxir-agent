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


class Coordinator:
    def __init__(self, case: CaseConfig, client: Any) -> None:
        self.case = case
        self.client = client
        case.ensure_workspace()
        self.audit = JSONLAuditLogger(case.audit_dir)
        self.gateway = ToolGateway(case, self.audit)
        self.gateway.register_all(build_tools())

    # -- detection ----------------------------------------------------------------

    def _find_by_ext(self, exts: set[str]) -> Path | None:
        return find_by_ext(self.case.evidence_scope, exts)

    # -- orchestration ------------------------------------------------------------

    def run(self) -> InvestigationResult:
        result = InvestigationResult(case=self.case)
        roots = ", ".join(str(p) for p in self.case.evidence_scope)
        self.audit.log_event(kind="investigation_start", case=self.case.case_id, evidence=roots)

        # 1. disk + log always run.
        plan: list[tuple[Any, str]] = [
            (make_disk_agent(),
             f"Evidence is mounted at: {roots}. Find all host-based persistence and "
             "on-disk attacker artifacts, then record findings."),
            (make_log_agent(),
             f"Evidence is mounted at: {roots}. Reconstruct the intrusion timeline from "
             "auth.log and the users' .bash_history; correlate source IPs to commands; "
             "record findings."),
        ]

        # 2. memory / network only when their evidence is present.
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

        # 3. run specialists.
        for agent, task in plan:
            self.audit.log_event(kind="agent_start", agent=agent.name)
            res = agent.run(self.client, self.gateway, task)
            result.agent_results.append(res)
            self.audit.log_event(
                kind="agent_done", agent=agent.name, turns=res.turns,
                findings=len(res.findings),
            )

        result.all_findings = list(self.gateway.context.findings)
        result.self_corrections = list(self.gateway.context.corrections)

        # 4. audit (Haiku verifies each claim against its cited tool output).
        ask = messages_ask(self.client, MODEL_AUDITOR)
        result.confirmed_findings = audit_findings(ask, result.all_findings, audit=self.audit)

        # 5. correlate.
        result.correlations = correlate_findings(result.confirmed_findings)
        for c in result.correlations:
            self.audit.log_event(kind="correlation", note=c)

        self.audit.log_event(
            kind="investigation_done",
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
