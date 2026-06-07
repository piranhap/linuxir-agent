"""Disk/persistence specialist — cron, systemd, SSH keys, and filesystem artifacts."""

from __future__ import annotations

from ..llm import MODEL_REASONING
from ..tools import DISK_TOOLS
from ._shared import build_system
from .base import Agent

_CHECKLIST = """\
- cron persistence: /etc/crontab, /etc/cron.d/*, /etc/cron.{hourly,daily,weekly,monthly},
  /var/spool/cron/*. Flag entries invoking curl|wget piped to a shell, /tmp or /dev/shm
  paths, base64, reverse shells (bash -i, /dev/tcp).
- systemd persistence: .service / .timer units with ExecStart pointing at /tmp, /dev/shm,
  or masquerading as a system service.
- SSH persistence: unexpected keys in any authorized_keys (especially /root/.ssh).
- Correlate timestamps and paths across artifacts. Cite the exact lines you rely on.
"""

ROLE = (
    "Find host-based persistence and on-disk attacker artifacts. Run the cron, systemd, "
    "and authorized_keys checks first; then read/inspect anything they surface."
)


def make_disk_agent() -> Agent:
    return Agent(
        name="disk",
        system=build_system(ROLE, _CHECKLIST),
        tool_names=DISK_TOOLS,
        model=MODEL_REASONING,
    )
