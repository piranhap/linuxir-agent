"""The single subprocess helper every adapter reuses.

``run_binary`` is the only place in the codebase that spawns external processes. It gates
on ``shutil.which`` so that when a forensic tool (volatility3, tshark, ...) is not
installed, the adapter returns a structured "unavailable" result instead of crashing —
the agent then reasons about the gap rather than dying. This is what lets the whole
pipeline run end-to-end on a workstation that only has part of the toolchain installed.

Note: the enforcer has already validated the call by the time any adapter runs. This
helper is plumbing, not a second security layer.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, TypedDict


class BinaryResult(TypedDict, total=False):
    available: bool
    reason: str
    binary: str
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


def run_binary(
    argv: list[str],
    *,
    timeout: float = 120.0,
    input_text: str | None = None,
) -> BinaryResult:
    """Run ``argv`` if its binary exists; otherwise report it unavailable.

    Never raises on a missing binary or non-zero exit — always returns a dict so callers
    can branch on ``result["available"]`` / ``result["returncode"]``.
    """
    if not argv:
        return {"available": False, "reason": "empty argv"}

    binary = argv[0]
    resolved = shutil.which(binary)
    if resolved is None:
        return {
            "available": False,
            "reason": f"binary '{binary}' is not installed on this host",
            "binary": binary,
            "argv": argv,
        }

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "binary": binary,
            "argv": argv,
            "timed_out": True,
            "reason": f"'{binary}' exceeded {timeout}s timeout",
        }

    return {
        "available": True,
        "binary": binary,
        "argv": argv,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def summarize(result: BinaryResult, max_chars: int = 12000) -> str:
    """Render a BinaryResult as compact text for an LLM tool_result."""
    if not result.get("available", False):
        return f"[tool unavailable] {result.get('reason', 'unknown reason')}"
    if result.get("timed_out"):
        return f"[timed out] {result.get('reason', '')}"
    out = result.get("stdout", "") or ""
    err = result.get("stderr", "") or ""
    body = out if out else f"(no stdout)\nstderr:\n{err}"
    if len(body) > max_chars:
        body = body[:max_chars] + f"\n...[truncated, {len(body)} chars total]"
    rc = result.get("returncode")
    return f"$ {' '.join(result.get('argv', []))}\n(exit {rc})\n{body}"


def as_text(value: Any) -> str:
    return value if isinstance(value, str) else str(value)
