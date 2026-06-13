"""Auditor pass — verifies each finding against the tool output it cites.

This is the system's anti-hallucination backstop. For every :class:`Finding`, a cheap
Haiku pass is shown the *claim* and the *verbatim tool output* the agent cited, and asked
the narrow question: does this output substantiate this claim? Findings that cannot be
substantiated are marked ``confirmed = False`` and dropped from the final report (the
report's "caught by auditor before final report" behavior); LOW-confidence or
elevated-risk findings are flagged ``requires_human_review``.

Crucially the auditor judges the claim against the **cited evidence text**, not against the
agent's prose — which is why it catches confident-but-unsupported assertions.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..audit import JSONLAuditLogger
from ..findings import Confidence, Finding, HallucinationRisk
from ..llm import MODEL_AUDITOR

# An ``ask`` takes (system_prompt, user_prompt) and returns the model's text reply.
# Decoupling the auditor from any specific client lets the same logic run on the raw
# Messages API path and on the subscription (Claude Agent SDK) path.
Ask = Callable[[str, str], str]


def messages_ask(client: Any, model: str = MODEL_AUDITOR) -> Ask:
    """Build an :data:`Ask` backed by a ``client.messages.create`` (raw-API / FakeClient)."""

    def ask(system: str, user: str) -> str:
        resp = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "\n".join(b.text for b in resp.content if getattr(b, "type", None) == "text")

    return ask

_AUDIT_SYSTEM = """\
You are a forensic finding auditor. You are given an analyst's CLAIM and the verbatim TOOL
OUTPUT they cited as evidence. Judge ONLY whether the tool output substantiates the claim.
Be skeptical: if the output does not contain what the claim asserts, it is unsupported,
even if the claim is plausible. Reward precise, evidenced claims; reject embellishment
(named malware families, geographies, or attribution not present in the output).

Respond with ONLY a JSON object, no prose:
{"supported": true|false,
 "hallucination_risk": "none"|"low"|"moderate"|"high",
 "suggested_confidence": "HIGH"|"MEDIUM"|"LOW"|"UNVERIFIED",
 "note": "<one sentence>"}
"""


@dataclass
class Verdict:
    supported: bool
    risk: HallucinationRisk
    suggested_confidence: Confidence | None
    note: str


def _extract_json(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"no JSON object in auditor response: {text!r}")
    return json.loads(match.group(0))


def _audit_one(ask: Ask, finding: Finding) -> Verdict:
    # A finding without a tool_call_id violates the traceability constraint.
    if not finding.tool_call_id:
        return Verdict(
            supported=False,
            risk=HallucinationRisk.HIGH,
            suggested_confidence=Confidence.UNVERIFIED,
            note="No tool_call_id; finding cannot be traced to the audit log.",
        )

    # A finding that cites no evidence cannot be substantiated — fail closed.
    if not finding.source_tool_output.strip():
        return Verdict(
            supported=False,
            risk=HallucinationRisk.MODERATE,
            suggested_confidence=Confidence.UNVERIFIED,
            note="No tool output cited; claim cannot be verified against evidence.",
        )

    prompt = (
        f"CLAIM (title): {finding.title}\n"
        f"CLAIM (description): {finding.description}\n"
        f"CLAIM (confidence asserted): {finding.confidence}\n\n"
        f"TOOL OUTPUT CITED:\n```\n{finding.source_tool_output}\n```\n"
    )
    text = ask(_AUDIT_SYSTEM, prompt)
    data = _extract_json(text)
    risk = HallucinationRisk(data.get("hallucination_risk", "none"))
    sugg = data.get("suggested_confidence")
    return Verdict(
        supported=bool(data["supported"]),
        risk=risk,
        suggested_confidence=Confidence(sugg) if sugg else None,
        note=str(data.get("note", "")),
    )


def audit_findings(
    ask: Ask,
    findings: list[Finding],
    *,
    audit: JSONLAuditLogger,
) -> list[Finding]:
    """Audit each finding in place; return the list of confirmed findings.

    ``ask`` abstracts the model call so this runs unchanged on the raw-API path
    (:func:`messages_ask`) and the subscription path (an SDK-backed ask).
    """
    for f in findings:
        verdict = _audit_one(ask, f)
        f.audited = True
        f.audit_note = verdict.note
        f.hallucination_risk = verdict.risk
        f.confirmed = verdict.supported

        # Downgrade (never silently upgrade) confidence on the auditor's advice.
        if verdict.suggested_confidence and _rank(verdict.suggested_confidence) < _rank(f.confidence):
            f.confidence = verdict.suggested_confidence

        if f.confidence == Confidence.LOW or verdict.risk in (
            HallucinationRisk.MODERATE,
            HallucinationRisk.HIGH,
        ):
            f.requires_human_review = True

        if not f.confirmed:
            audit.log_event(
                kind="auditor_dropped_finding",
                finding_id=f.id,
                reason=verdict.note,
                hallucination_risk=verdict.risk.value,
            )
        else:
            audit.log_event(
                kind="auditor_confirmed_finding",
                finding_id=f.id,
                confidence=f.confidence.value,
                requires_human_review=f.requires_human_review,
            )

    return [f for f in findings if f.confirmed]


_CONF_ORDER = {
    Confidence.UNVERIFIED: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}


def _rank(c: Confidence) -> int:
    return _CONF_ORDER[c]
