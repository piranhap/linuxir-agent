"""Append-only JSONL audit logging.

Every tool call, every blocked spoliation attempt, and every recorded finding is written
as one JSON object per line. The audit trail is the integrity backstop: even if a note in
the Obsidian vault is mangled by a concurrent write, the JSONL log is the authoritative,
append-only record of what the agent did and what was blocked.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JSONLAuditLogger:
    """Writes newline-delimited JSON records to files under ``audit_dir``.

    Two streams are maintained:

    * ``audit.jsonl`` — the full activity log (every dispatch, allowed or not).
    * ``spoliation-attempts.jsonl`` — blocked write/delete/modify attempts only, so the
      evidence-integrity record stands alone and is trivial to audit.
    """

    def __init__(self, audit_dir: Path) -> None:
        self.audit_dir = audit_dir
        self.activity_log = audit_dir / "audit.jsonl"
        self.spoliation_log = audit_dir / "spoliation-attempts.jsonl"

    def _append(self, path: Path, record: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"ts": datetime.now(timezone.utc).isoformat(), **record}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    def log_call(
        self,
        *,
        tool: str,
        tool_input: dict[str, Any],
        decision: str,
        agent: str | None = None,
        detail: str | None = None,
    ) -> None:
        """Record a tool dispatch (``decision`` is ``"allowed"`` or ``"blocked"``)."""
        self._append(
            self.activity_log,
            {
                "kind": "tool_call",
                "agent": agent,
                "tool": tool,
                "input": tool_input,
                "decision": decision,
                "detail": detail,
            },
        )

    def log_spoliation(
        self,
        *,
        tool: str,
        tool_input: dict[str, Any],
        reason: str,
        agent: str | None = None,
    ) -> None:
        """Record a blocked evidence-mutation attempt to the dedicated stream."""
        self._append(
            self.spoliation_log,
            {
                "kind": "spoliation_blocked",
                "agent": agent,
                "tool": tool,
                "input": tool_input,
                "reason": reason,
            },
        )

    def log_finding(self, *, finding: dict[str, Any], agent: str | None = None) -> None:
        """Record a finding as it is captured (pre-audit)."""
        self._append(
            self.activity_log,
            {"kind": "finding", "agent": agent, "finding": finding},
        )

    def log_event(self, **fields: Any) -> None:
        """Record an arbitrary structured event (corrections, phase transitions, ...)."""
        self._append(self.activity_log, {"kind": "event", **fields})
