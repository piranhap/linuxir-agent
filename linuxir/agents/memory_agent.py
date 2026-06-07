"""Memory specialist — volatility3 process / injection / socket analysis.

Runs only when the case includes a memory image. Falls back gracefully when volatility3 is
not installed (the tools report unavailability and the agent says so rather than inventing
process names — a deliberate guard against the report's 'meterpreter' hallucination class).
"""

from __future__ import annotations

from ..llm import MODEL_REASONING
from ..tools import MEMORY_TOOLS
from ._shared import build_system
from .base import Agent

_CHECKLIST = """\
- pslist / pstree: unexpected parent-child relationships, processes with deleted binaries,
  names masquerading as system daemons (e.g. an 'apache2' with no httpd lineage).
- malfind: pages with RWX permissions / injected code in a process address space.
- sockstat: active/established connections, especially to external IPs. Cross-reference any
  connection against what the logs show — a connection present in memory but absent from
  logs is a log-tampering indicator, not a contradiction to discard.
Do NOT name a specific malware family (e.g. 'meterpreter') unless a tool string supports it.
"""

ROLE = (
    "Analyze the memory image for injected code, suspicious processes, and live network "
    "connections. Provide the memory image path to each tool."
)


def make_memory_agent() -> Agent:
    return Agent(
        name="memory",
        system=build_system(ROLE, _CHECKLIST),
        tool_names=MEMORY_TOOLS,
        model=MODEL_REASONING,
    )
