"""Deterministic self-correction — turn tool outcomes into recovery guidance.

The agent loop is model-driven, but hoping the model notices a failed tool call and pivots
is not enough. This module makes the common recovery sequences *deterministic*: pure
functions that inspect a tool's result and, when it matches a known failure shape, return a
concrete :class:`Correction` whose ``hint`` is fed back to the model on the next turn and
logged to the audit + self-learning log. The model still does the reasoning; the system
guarantees it is *prompted* to recover instead of silently concluding "nothing found".

Three sequences the accuracy report documents (see ``tests/test_self_correction.py``):

1. **Volatility3 profile/symbol failure → recovery.** vol3 cannot resolve kernel symbols
   → recover the kernel banner and retry with matching symbols (never invent process names).
2. **Empty persistence result → pivot.** One persistence location is empty → check the
   sibling locations before concluding there is no persistence.
3. **Cross-artifact contradiction → reconciliation.** An indicator present in memory but
   absent from logs is *log tampering* — keep both findings and flag, don't discard one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The persistence checks an agent should pivot across (sequence 2). Kept as a static list
# so this module never imports the tool registry (which imports the gateway, which imports
# this module — a cycle).
PERSISTENCE_CHECKS = (
    "persistence_check_cron", "persistence_check_systemd", "check_authorized_keys",
    "persistence_parse_bash_history", "persistence_check_setuid",
    "persistence_check_rc_files", "persistence_check_ld_preload",
    "persistence_diff_passwd", "persistence_parse_wtmp",
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class Correction:
    tool: str
    trigger: str  # short machine-readable reason (for the audit log)
    hint: str     # remediation text fed back to the model


def recovery_hint(tool_name: str, result: str) -> Correction | None:
    """Inspect a dispatched tool's result; return a recovery Correction if one applies.

    Returns None for normal results (the overwhelmingly common case), so callers can do
    ``if (c := recovery_hint(...)):`` cheaply.
    """
    low = result.lower()

    # 1. volatility3 could not resolve kernel symbols / is unavailable.
    if tool_name.startswith("memory_") and tool_name != "memory_kernel_banner":
        vol_unavailable = "[tool unavailable] volatility3" in result
        symbol_fail = ("unable to validate" in low or "no suitable" in low
                       or ("symbol" in low and ("not" in low or "fail" in low)))
        if vol_unavailable or symbol_fail:
            return Correction(
                tool_name, "vol3_symbol_or_unavailable",
                "volatility3 could not resolve the kernel. Run memory_kernel_banner to "
                "recover the 'Linux version' string, then retry with the matching symbols "
                "(e.g. an ISF / --os-name). Do NOT name processes or malware that no tool "
                "output shows.",
            )

    # 2. a persistence check found nothing — pivot to the siblings before concluding.
    if tool_name in PERSISTENCE_CHECKS and result.lstrip().startswith("[no "):
        siblings = ", ".join(t for t in PERSISTENCE_CHECKS if t != tool_name)
        return Correction(
            tool_name, "empty_persistence_result",
            f"{tool_name} found nothing. Absence in one location is not absence of "
            f"persistence — run the sibling checks before concluding: {siblings}.",
        )

    # 3. a path/tool error — find the real path rather than giving up.
    if result.lstrip().startswith(("[tool error]", "[not found]", "[not a directory]",
                                   "[not a file]")):
        return Correction(
            tool_name, "path_or_tool_error",
            "That path/tool call failed. Use list_directory on the parent directory to "
            "locate the correct path — the evidence layout may differ from a standard root.",
        )

    return None


def reconcile(findings) -> list[str]:
    """Sequence 3: reconcile cross-artifact contradictions instead of discarding them.

    When an indicator (IP) appears in a *memory* finding but in no *log* finding, that is a
    log-tampering signal — both findings are kept and the gap is surfaced for human review,
    rather than treating the disagreement as one finding being wrong.
    """
    by_ip: dict[str, list] = {}
    for f in findings:
        blob = " ".join([f.title, f.description, f.source_tool_output, *f.evidence_refs])
        for ip in set(_IP_RE.findall(blob)):
            by_ip.setdefault(ip, []).append(f)

    notes: list[str] = []
    for ip, group in by_ip.items():
        agents = {f.agent or "?" for f in group}
        if "memory" in agents and "log" not in agents:
            notes.append(
                f"Connection to {ip} appears in memory but not in logs — possible log "
                "tampering; both findings retained and surfaced for human review (not "
                "discarded as a contradiction)."
            )
    return notes
