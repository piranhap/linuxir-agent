"""Self-learning log — append notable self-corrections to Corrections/self-learning-log.md.

Captures the kind of sequences the accuracy report documents (a volatility profile retry,
an empty-cron pivot to systemd, a memory/log contradiction, a tool that was unavailable).
The coordinator and auditor write the structured events to the JSONL audit log; this module
distills the human-readable narrative from those events after a run.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .agents.coordinator import InvestigationResult


def record(case_corrections_dir: Path, title: str, detail: str) -> None:
    """Append a single self-correction entry."""
    log = case_corrections_dir / "self-learning-log.md"
    log.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    entry = f"\n## {ts} — {title}\n\n{detail}\n"
    with log.open("a", encoding="utf-8") as fh:
        if log.stat().st_size == 0:
            fh.seek(0)
            fh.write("# Self-learning log\n")
        fh.write(entry)


def distill(result: InvestigationResult) -> None:
    """Derive self-learning entries from an investigation's outcome."""
    cdir = result.case.corrections_dir

    dropped = [f for f in result.all_findings if f.audited and not f.confirmed]
    for f in dropped:
        record(
            cdir,
            f"Auditor dropped '{f.id}'",
            f"Agent `{f.agent}` asserted \"{f.title}\" but the auditor judged it "
            f"unsupported by the cited tool output: {f.audit_note}. "
            "Lesson: claims must be grounded in verbatim tool output, not inference.",
        )

    for c in result.correlations:
        if "log tampering" in c:
            record(cdir, "Cross-artifact contradiction", c)

    review = [f for f in result.confirmed_findings if f.requires_human_review]
    if review:
        ids = ", ".join(f.id for f in review)
        record(
            cdir,
            "Findings flagged for human review",
            f"{len(review)} confirmed findings carry LOW confidence or elevated "
            f"hallucination risk and require human review: {ids}.",
        )
