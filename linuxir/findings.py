"""The :class:`Finding` model and its confidence vocabulary.

A finding is the unit of output the agents produce and the auditor scrutinizes. Each one
must cite the raw tool output that supports it (``source_tool_output``) so the auditor can
verify the claim against evidence rather than against the model's prose — this is how
hallucinated claims get caught before the final report.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNVERIFIED = "UNVERIFIED"


class HallucinationRisk(StrEnum):
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class Finding(BaseModel):
    """A single investigative conclusion, with the evidence that backs it."""

    id: str = Field(description="Stable slug, e.g. 'cron-persistence-backdoor'.")
    title: str
    description: str
    technique: str | None = Field(
        default=None, description="MITRE ATT&CK or linux-techniques.md reference."
    )
    confidence: Confidence = Confidence.UNVERIFIED
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Paths / line references inside evidence_scope supporting this finding.",
    )
    source_tool_output: str = Field(
        default="",
        description="Verbatim tool output the claim rests on. The auditor checks the "
        "claim against THIS, not against the description.",
    )
    tool_call_id: str | None = Field(
        default=None, 
        description="The internal ID of the tool call that recorded this finding."
    )
    agent: str | None = Field(default=None, description="Which agent produced it.")

    # Set by the auditor pass.
    hallucination_risk: HallucinationRisk = HallucinationRisk.NONE
    requires_human_review: bool = False
    audited: bool = False
    audit_note: str | None = None
    confirmed: bool = True
    """False once the auditor judges the claim unsupported by ``source_tool_output``."""

    def short(self) -> str:
        return f"[{self.confidence}] {self.title} ({self.id})"
