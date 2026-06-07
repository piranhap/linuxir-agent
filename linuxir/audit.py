"""Append-only JSONL audit logging.

Every tool call, every blocked spoliation attempt, and every recorded finding is written
as one JSON object per line. The audit trail is the integrity backstop: even if a note in
the Obsidian vault is mangled by a concurrent write, the JSONL log is the authoritative,
append-only record of what the agent did and what was blocked.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JSONLAuditLogger:
    """Writes newline-delimited JSON records to files under ``audit_dir``.

    Two streams are maintained:

    * ``audit.jsonl`` — the full activity log (every dispatch, allowed or not).
    * ``spoliation-attempts.jsonl`` — blocked write/delete/modify attempts only, so the
      evidence-integrity record stands alone and is trivial to audit.
    * ``agent-messages.jsonl`` — inter-agent communications (orchestrator ⇄ specialists ⇄
      auditor), kept separate from tool calls so the multi-agent conversation is auditable
      on its own.

    Writes are guarded by a lock so the logger is safe to share across the threads that run
    the specialist agents in parallel.
    """

    def __init__(self, audit_dir: Path) -> None:
        self.audit_dir = audit_dir
        self.activity_log = audit_dir / "audit.jsonl"
        self.spoliation_log = audit_dir / "spoliation-attempts.jsonl"
        self.agent_messages_log = audit_dir / "agent-messages.jsonl"
        self._lock = threading.Lock()

    def _append(self, path: Path, record: dict[str, Any]) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(), **record}
        line = json.dumps(record, default=str) + "\n"
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line)

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

    def log_agent_message(
        self,
        *,
        sender: str,
        receiver: str,
        msg_type: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Record one inter-agent communication to the dedicated agent-messages stream."""
        self._append(
            self.agent_messages_log,
            {
                "kind": "agent_message",
                "sender": sender,
                "receiver": receiver,
                "msg_type": msg_type,
                "payload": payload or {},
            },
        )
