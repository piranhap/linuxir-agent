"""Log specialist — auth.log, bash_history, syslog correlation."""

from __future__ import annotations

from ..llm import MODEL_REASONING
from ..tools import LOG_TOOLS
from ._shared import build_system
from .base import Agent

_CHECKLIST = """\
- logs_parse_auth: SSH brute force (failed-login bursts per source IP), the first Accepted
  login after them (initial access), and sudo/su escalations. Note the source IP(s).
- logs_parse_lastb: failed-login records from btmp (auth.log also covers this).
- logs_parse_syslog: cron/systemd/daemon events; flagged tokens (curl|wget, /tmp, base64).
- logs_build_timeline: merge auth + syslog into one chronological view of the intrusion.
- logs_find_gaps: large time jumps or empty logs — a log-truncation / anti-forensics hint.
- web_parse_access (if a web access log is present): attacker IP by attack ratio, plugin/
  web-shell exploits, and confirmed web-shell command invocations — often the entry point.
- bash_history: attacker commands — downloads (wget/curl), chmod +x, execution from /tmp,
  cron/authorized_keys tampering, archiving + scp/rsync exfiltration, `history -c`.
- Correlate: tie a source IP in auth.log to commands in bash_history to persistence on
  disk. A single attacker IP appearing across artifacts is strong corroboration.
Cite verbatim log lines. If logs and other evidence disagree, say so — it may be tampering.
"""

ROLE = (
    "Reconstruct the intrusion timeline from logs and shell history. Start with "
    "logs_parse_auth and logs_build_timeline, check logs_find_gaps for tampering, then "
    "correlate source IPs and commands against the relevant users' .bash_history."
)


def make_log_agent() -> Agent:
    return Agent(
        name="log",
        system=build_system(ROLE, _CHECKLIST),
        tool_names=LOG_TOOLS,
        model=MODEL_REASONING,
    )
