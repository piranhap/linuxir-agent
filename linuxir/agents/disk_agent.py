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
- rc/init/profile persistence: rc.local, /etc/init.d, /etc/profile.d, per-user .bashrc/
  .profile run-at-boot/login hooks (persistence_check_rc_files).
- LD_PRELOAD hijacking: /etc/ld.so.preload and LD_PRELOAD in env/profile files
  (persistence_check_ld_preload) — flag any .so under a world-writable path.
- account backdoors: /etc/passwd UID-0 accounts other than root, or unexpected login
  users (persistence_diff_passwd).
- setuid privesc: setuid/setgid shells or interpreters, or setuid files in /tmp, /home,
  /dev/shm (persistence_check_setuid).
- shell history: score every .bash_history for download|sh, /tmp exec, persistence
  writes, exfil (scp/tar), and anti-forensics like `history -c` (persistence_parse_bash_history).
- login records: wtmp/btmp/utmp login timeline (persistence_parse_wtmp).
- Correlate timestamps and paths across artifacts. Cite the exact lines you rely on.
"""

ROLE = (
    "Find host-based persistence and on-disk attacker artifacts. Run the cron, systemd, "
    "authorized_keys, rc-files, ld_preload, passwd, setuid, and bash-history checks "
    "first; then read/inspect anything they surface."
)


def make_disk_agent() -> Agent:
    return Agent(
        name="disk",
        system=build_system(ROLE, _CHECKLIST),
        tool_names=DISK_TOOLS,
        model=MODEL_REASONING,
    )
