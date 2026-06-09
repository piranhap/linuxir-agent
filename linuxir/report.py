"""Report generation — Obsidian-style vault notes + a final cross-referenced report.

Writes only to the case workspace (vault), never to evidence, so these writes are ordinary
internal I/O outside the gateway. The final report includes the confidence distribution,
the confirmed findings (with the evidence each cites), the cross-artifact correlations, and
— for honesty — the findings the auditor dropped and the limitations of the run.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .agents import persona_builder, reporter
from .agents.coordinator import InvestigationResult
from .findings import Confidence, Finding


def _finding_md(f: Finding) -> str:
    review = "  ⚠️ **requires human review**" if f.requires_human_review else ""
    refs = ", ".join(f"`{r}`" for r in f.evidence_refs) or "—"
    cite = f.source_tool_output.strip()
    if len(cite) > 1500:
        cite = cite[:1500] + "\n...[truncated]"
    return (
        f"### {f.title}{review}\n"
        f"- **id:** `{f.id}`\n"
        f"- **confidence:** {f.confidence}\n"
        f"- **technique:** {f.technique or '—'}\n"
        f"- **hallucination_risk:** {f.hallucination_risk}\n"
        f"- **evidence:** {refs}\n\n"
        f"{f.description}\n\n"
        f"<details><summary>cited tool output</summary>\n\n```\n{cite}\n```\n\n</details>\n"
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_agent_notes(result: InvestigationResult) -> list[Path]:
    """One Obsidian note per agent (``analysis-<agent>.md``)."""
    vault = result.case.vault_path
    written: list[Path] = []
    for res in result.agent_results:
        confirmed_ids = {f.id for f in result.confirmed_findings}
        body = [f"# analysis-{res.agent}\n", f"*Agent turns:* {res.turns}\n"]
        body.append("## Findings\n")
        agent_findings = [f for f in result.all_findings if f.agent == res.agent]
        if not agent_findings:
            body.append("_No findings recorded._\n")
        for f in agent_findings:
            status = "confirmed" if f.id in confirmed_ids else "DROPPED by auditor"
            body.append(f"_({status})_\n\n{_finding_md(f)}")
        body.append("## Agent summary\n")
        body.append(res.final_text or "_(none)_")
        body.append("\n\n[[report|← back to report]]\n")
        path = vault / f"analysis-{res.agent}.md"
        _write(path, "\n".join(body))
        written.append(path)
    return written


def write_final_report(result: InvestigationResult) -> Path:
    """The cross-referenced ``report.md`` with confidence distribution and honesty section."""
    case = result.case
    confirmed = result.confirmed_findings
    dropped = [f for f in result.all_findings if f.audited and not f.confirmed]
    dist = Counter(f.confidence for f in confirmed)
    total = len(confirmed)

    lines = [
        f"# LinuxIR Report — case `{case.case_id}`\n",
        f"Evidence scope: {', '.join(f'`{p}`' for p in case.evidence_scope)}\n",
        "## Confidence distribution (confirmed findings)\n",
        "| Confidence | Count | % |",
        "|---|---|---|",
    ]
    for level in (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW, Confidence.UNVERIFIED):
        n = dist.get(level, 0)
        pct = f"{(100 * n / total):.1f}%" if total else "0.0%"
        lines.append(f"| {level} | {n} | {pct} |")

    lines.append(f"\n**{total} confirmed findings.** "
                 f"{sum(1 for f in confirmed if f.requires_human_review)} flagged for human review. "
                 f"{len(dropped)} findings dropped by the auditor (see below).\n")

    lines.append("## Key deliverables\n")
    lines.append("- **Mandatory IR answers:** [[compromise-answers]]")
    lines.append("- **IOC / IOA / TTP:** [[ioc-ttp]]")
    lines.append("- **Recommendations:** [[recommendations]]")
    lines.append("- **Attacker profile:** [[attacker-profile]] · **Timeline:** [[timeline]] · "
                 "**Narrative:** [[narrative]]")
    if result.expert is not None:
        lines.append("- **Expert analysis:** [[analysis-polished]]")
    lines.append("")

    lines.append("## Confirmed findings\n")
    if not confirmed:
        lines.append("_None confirmed._\n")
    for f in confirmed:
        lines.append(_finding_md(f))
        lines.append(f"_Source: [[analysis-{f.agent}]]_\n")

    lines.append("## Cross-artifact correlations\n")
    if result.correlations:
        for c in result.correlations:
            lines.append(f"- {c}")
    else:
        lines.append("_No cross-artifact correlations._")

    if result.expert is not None:
        e = result.expert
        notable = e.notable_iocs()
        lines.append("\n## Expert analysis & threat intel\n")
        lines.append("_Senior IR-expert review — full narrative in [[analysis-polished]]._\n")
        lines.append(f"**MITRE ATT&CK coverage:** {', '.join(e.mitre_techniques) or '—'}\n")
        lines.append(f"**Threat-intel IOCs:** {len(e.ioc_matches)} enriched, "
                     f"{len(notable)} notable (malicious/suspicious).\n")
        if e.ioc_matches:
            lines.append("| indicator | kind | verdict | detail |")
            lines.append("|---|---|---|---|")
            for m in e.ioc_matches:
                lines.append(f"| `{m.indicator}` | {m.kind} | **{m.verdict}** | {m.detail} |")
        if e.reanalysis_reason:
            lines.append(f"\n_Re-analysis was requested by the expert: {e.reanalysis_reason}_")

    lines.append("\n## Auditor-dropped findings (transparency)\n")
    if dropped:
        for f in dropped:
            lines.append(f"- **{f.title}** (`{f.id}`, from {f.agent}) — dropped: "
                         f"{f.audit_note} _(risk: {f.hallucination_risk})_")
    else:
        lines.append("_No findings were dropped._")

    lines.append("\n## Method & limitations\n")
    lines.append(
        "- Evidence was treated as **read-only**; every tool call was vetted by the "
        "ConstraintEnforcer before execution and logged to `audit/audit.jsonl`. Blocked "
        "evidence-mutation attempts (if any) are in `audit/spoliation-attempts.jsonl`.\n"
        "- Each finding was verified by an independent auditor pass against the verbatim "
        "tool output it cites; unsubstantiated claims were dropped.\n"
        "- Tools whose binaries are not installed on this host return an 'unavailable' "
        "result; affected analyses are necessarily incomplete (not absent-of-evidence).\n"
    )
    note_links = [f"[[analysis-{r.agent}]]" for r in result.agent_results]
    if result.expert is not None:
        note_links.append("[[analysis-polished]]")
    lines.append("\nAgent notes: " + ", ".join(note_links))

    path = case.vault_path / "report.md"
    _write(path, "\n".join(lines) + "\n")
    return path


def write_day7_notes(result: InvestigationResult) -> list[Path]:
    """Write the Persona/* and Report/* deliverables (mandatory IR answers, IOC/TTP, etc.).

    Foldered under the vault; Obsidian ``[[wiki links]]`` resolve by note name regardless of
    folder, so these cross-link cleanly with the flat analysis notes.
    """
    vault = result.case.vault_path
    docs = {
        "Report/compromise-answers.md": reporter.build_compromise_answers(result),
        "Report/ioc-ttp.md": reporter.build_ioc_ttp(result),
        "Report/recommendations.md": reporter.build_recommendations(result),
        "Persona/attacker-profile.md": persona_builder.build_attacker_profile(result),
        "Persona/timeline.md": persona_builder.build_timeline(result),
        "Persona/narrative.md": persona_builder.build_narrative(result),
    }
    written: list[Path] = []
    for rel, body in docs.items():
        path = vault / rel
        _write(path, body)
        written.append(path)
    return written


def write_reports(result: InvestigationResult) -> tuple[Path, list[Path]]:
    """Write the agent notes, the Day-7 deliverables, and the final report; return paths."""
    notes = write_agent_notes(result)
    notes += write_day7_notes(result)
    report = write_final_report(result)
    return report, notes
