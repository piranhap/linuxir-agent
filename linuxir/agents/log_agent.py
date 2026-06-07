"""Log specialist — auth.log, bash_history, syslog correlation."""

from __future__ import annotations

from ..llm import MODEL_REASONING
from ..tools import LOG_TOOLS
from ._shared import build_system
from .base import Agent

_CHECKLIST = """\
- auth.log: SSH brute force (bursts of 'Failed password'), the first 'Accepted password'
  after them (initial access), sudo escalations, new sessions. Note the source IP(s).
- bash_history: attacker commands — downloads (wget/curl), chmod +x, execution from /tmp,
  cron/authorized_keys tampering, archiving + scp/rsync exfiltration, `history -c`.
- Correlate: tie a source IP in auth.log to commands in bash_history to persistence on
  disk. A single attacker IP appearing across artifacts is strong corroboration.
- syslog/other logs: service crashes or exploit traces around the access time.
Cite verbatim log lines. If logs and other evidence disagree, say so — it may be tampering.
"""

ROLE = (
    "Reconstruct the intrusion timeline from logs and shell history. Read auth.log and "
    "the relevant users' .bash_history, then correlate source IPs and commands."
)


def make_log_agent() -> Agent:
    return Agent(
        name="log",
        system=build_system(ROLE, _CHECKLIST),
        tool_names=LOG_TOOLS,
        model=MODEL_REASONING,
    )
