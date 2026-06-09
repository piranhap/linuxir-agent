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
from ..llm import MODEL_AUDITOR, MODEL_EXPERT
from .. import selfcorrect
from ..tools import build_tools
from .auditor import audit_findings, messages_ask
from .disk_agent import make_disk_agent
from .linux_ir_expert import ExpertResult, enrich as expert_enrich
from .log_agent import make_log_agent
from .loop import AgentResult
from .memory_agent import make_memory_agent
from .network_agent import make_network_agent

_MEMORY_EXT = {".lime", ".mem", ".raw", ".dmp", ".vmem", ".img.mem"}
_PCAP_EXT = {".pcap", ".pcapng", ".cap"}
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Usernames from home directories / SSH-key paths / sudo lines — the cross-artifact link
# that pure IP correlation misses (e.g. an insider acting across disk and log evidence).
_USER_RE = re.compile(r"(?:/home/([a-z_][a-z0-9_\-]{1,31})\b|"
                      r"\buser[= ]([a-z_][a-z0-9_\-]{1,31})\b|"
                      r"\bfor user ([a-z_][a-z0-9_\-]{1,31})\b)")


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
    expert: ExpertResult | None = None  # IR-expert review + threat-intel enrichment


class Coordinator:
    def __init__(self, case: CaseConfig, client: Any, max_iterations: int = 10) -> None:
        self.case = case
        self.client = client
        self.max_iterations = max(1, int(max_iterations))
        case.ensure_workspace()
        self.audit = JSONLAuditLogger(case.audit_dir)
        self._reanalysis_done = False  # the expert may request re-analysis at most once

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

    def _run_expert_pass(self, result: InvestigationResult) -> None:
        """Senior IR-expert review + threat-intel enrichment over the confirmed findings."""
        self.audit.log_agent_message(
            sender="orchestrator", receiver="ir_expert", msg_type="task_assignment",
            payload={"confirmed": len(result.confirmed_findings)})
        ask = messages_ask(self.client, MODEL_EXPERT)
        result.expert = expert_enrich(
            ask, result.confirmed_findings, audit=self.audit,
            correlations=result.correlations, reanalysis_allowed=not self._reanalysis_done)
        (self.case.vault_path / "analysis-polished.md").write_text(
            result.expert.polished_markdown, encoding="utf-8")
        self.audit.log_event(kind="agent_done", agent="ir_expert",
                             iocs=len(result.expert.ioc_matches),
                             reanalysis=result.expert.requests_reanalysis)
        self.audit.log_agent_message(
            sender="ir_expert", receiver="orchestrator", msg_type="intel_match",
            payload={"iocs": len(result.expert.ioc_matches),
                     "notable": len(result.expert.notable_iocs()),
                     "mitre": result.expert.mitre_techniques})

    def _append_self_learning(self, title: str, detail: str) -> None:
        """Append a self-learning entry (inline to avoid importing corrections.py = cycle)."""
        from datetime import datetime, timezone
        log = self.case.corrections_dir / "self-learning-log.md"
        log.parent.mkdir(parents=True, exist_ok=True)
        prefix = "# Self-learning log\n" if not log.exists() or log.stat().st_size == 0 else ""
        with log.open("a", encoding="utf-8") as fh:
            fh.write(f"{prefix}\n## {datetime.now(timezone.utc).isoformat()} — {title}\n\n{detail}\n")

    def _needs_reanalysis(self, result: InvestigationResult) -> bool:
        """Driven by the IR-expert pass: re-run when it flags an unresolved gap (bounded to
        one re-analysis by ``_reanalysis_done``, which gates the expert's own decision)."""
        return bool(result.expert and result.expert.requests_reanalysis)

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

            # Specialists + auditor run once; findings are then fixed. Subsequent
            # iterations re-correlate and re-run the expert with the learned context.
            if iteration == 1:
                self._run_specialists_parallel(result)
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

            # Correlate confirmed findings across artifacts (IP + user/path links).
            result.correlations = correlate_findings(result.confirmed_findings)
            for c in result.correlations:
                self.audit.log_event(kind="correlation", note=c)

            # Senior IR-expert review + threat-intel enrichment.
            self._run_expert_pass(result)

            if not self._needs_reanalysis(result):
                break
            # Honor one re-analysis: record the expert's reason (closing the learning loop)
            # and loop again. _reanalysis_done gates the expert from re-requesting.
            self._reanalysis_done = True
            reason = result.expert.reanalysis_reason or ""
            self._append_self_learning(
                f"Iteration {iteration} — IR expert requested re-analysis", reason)
            self.audit.log_agent_message(
                sender="ir_expert", receiver="orchestrator", msg_type="reanalysis_request",
                payload={"after_iteration": iteration, "reason": reason})
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
    """Link confirmed findings that share an indicator across agents.

    Correlates on IPs AND on usernames/paths — an insider or lateral-movement actor often
    appears as the same *user* across disk and log evidence without a shared IP, which pure
    IP correlation misses. Also surfaces the memory-present / logs-absent log-tampering
    pattern (self-correction sequence 3). Shared across both runtimes.
    """
    notes: list[str] = []

    def _group(extract, *, include_refs: bool = True) -> dict[str, list[Finding]]:
        idx: dict[str, list[Finding]] = {}
        for f in findings:
            parts = [f.title, f.description, f.source_tool_output]
            if include_refs:
                parts += f.evidence_refs
            for ind in extract(" ".join(parts)):
                idx.setdefault(ind, []).append(f)
        return idx

    by_ip = _group(lambda b: set(_IP_RE.findall(b)))
    for ip, group in by_ip.items():
        agents = sorted({f.agent or "?" for f in group})
        if len(agents) > 1:
            notes.append(f"Indicator {ip} corroborated across {len(agents)} agents "
                         f"({', '.join(agents)}): findings {', '.join(f.id for f in group)}.")

    def _users(blob: str) -> set[str]:
        return {u for m in _USER_RE.findall(blob) for u in m if u}

    # Exclude evidence_refs: those are host-absolute artifact paths (e.g. the analyst's own
    # /home/<user> where evidence is stored) and would create phantom "users".
    by_user = _group(_users, include_refs=False)
    _SYS_USERS = {"root", "daemon", "www-data", "nobody", "syslog", "sshd", "ubuntu"}
    for user, group in by_user.items():
        agents = sorted({f.agent or "?" for f in group})
        ids = {f.id for f in group}
        if len(agents) > 1 and len(ids) > 1 and user not in _SYS_USERS:
            notes.append(f"User '{user}' links {len(agents)} agents "
                         f"({', '.join(agents)}): findings {', '.join(sorted(ids))}.")

    # Cross-artifact contradiction → reconciliation (self-correction sequence 3):
    # memory-present / logs-absent indicators are log tampering, not a contradiction to drop.
    notes.extend(selfcorrect.reconcile(findings))
    return notes
