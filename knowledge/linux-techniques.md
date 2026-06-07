# Linux IR Technique Checklist

A working checklist of Linux attacker techniques the agents triage for, loosely mapped to
MITRE ATT&CK. Used to seed specialist agent prompts and to keep coverage honest.

## Persistence (TA0003)
- **cron** (T1053.003): `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}`,
  `/var/spool/cron/*`. Red flags: `curl|wget … | bash`, `/tmp` or `/dev/shm` paths, base64,
  reverse shells (`bash -i`, `/dev/tcp/`).
- **systemd** (T1543.002): `.service`/`.timer` units under `/etc/systemd/system`,
  `/lib/systemd/system`. Red flags: `ExecStart` from `/tmp`, `/dev/shm`, or names that
  masquerade as system daemons.
- **SSH authorized_keys** (T1098.004): unexpected keys, especially in `/root/.ssh`.
- **profile.d / shell rc** (T1546.004): `/etc/profile.d/*.sh`, `~/.bashrc`, `~/.bash_profile`
  modifications. *(checklist item added post-testing — was a missed-artifact class.)*
- **.bashrc / .bash_profile** for the *correct* user — resolve the right home directory.

## Initial Access & Execution
- **SSH brute force** (T1110): bursts of `Failed password` in `auth.log`, then the first
  `Accepted password` = initial access. Record the source IP.
- **service exploitation**: crashes / anomalies in service logs around the access time.
- **execution from /tmp** (T1059): downloads then `chmod +x` then run.

## Privilege Escalation
- **sudo** (T1548.003): `sudo … COMMAND=/bin/bash`, session-opened-for-root lines.

## Defense Evasion
- **log tampering** (T1070): `history -c`, truncated/cleared logs, an artifact present in
  memory but absent from logs (treat as a tampering indicator, not a contradiction to drop).
- **timestomping** (T1070.006).

## Credential Access / Collection / Exfiltration
- archive + transfer: `tar czf …` then `scp`/`rsync`/`curl -T` to an external host (TA0010).
- reading `/etc/passwd`, `/etc/shadow`.

## Command & Control
- **C2 beaconing** (T1071): regular inter-arrival times to one external IP (e.g. every 60s).
- reverse shells, `socat`, `nc`.

## Memory artifacts
- injected code (malfind / RWX pages), process masquerade, deleted-binary processes,
  live sockets to external IPs. Do not name a malware family without a supporting string.
