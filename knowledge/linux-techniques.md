# Linux IR Technique Checklist

A working checklist of Linux attacker techniques the agents triage for, loosely mapped to
MITRE ATT&CK. Used to seed specialist agent prompts and to keep coverage honest. 

## Persistence (TA0003)
- **cron & at** (T1053.003): `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}`,
  `/var/spool/cron/*`, and `/var/spool/at/*`. Red flags: `curl|wget … | bash`, `/tmp` or `/dev/shm` paths, base64,
  reverse shells (`bash -i`, `/dev/tcp/`), hidden files (`.script.sh`).
- **systemd** (T1543.002): `.service`/`.timer` units under `/etc/systemd/system`,
  `/lib/systemd/system`, and `~/.config/systemd/user/`. Red flags: `ExecStart` from `/tmp`, `/dev/shm`, or names that
  masquerade as system daemons (e.g., `sshd-worker.service`).
- **SSH authorized_keys** (T1098.004): unexpected keys, especially in `/root/.ssh/authorized_keys` or `~/.ssh/authorized_keys` for service accounts.
- **profile.d / shell rc** (T1546.004): `/etc/profile.d/*.sh`, `~/.bashrc`, `~/.bash_profile`, `~/.zshrc`
  modifications. *(checklist item added post-testing — was a missed-artifact class.)* Ensure resolution of the *correct* home directory for the targeted user.
- **Hijack Execution Flow / LD_PRELOAD** (T1574.006): `/etc/ld.so.preload` or user-level `LD_PRELOAD` environment variables exporting malicious shared objects (`.so`). Common in userland rootkits.
- **rc.local & init.d** (T1037.004): Legacy persistence mechanisms via `/etc/rc.local` or `/etc/init.d/` scripts executing on boot.
- **Web Shells** (T1505.003): `.php`, `.jsp`, or `.py` files dropped in web roots (`/var/www/html`) exhibiting execution logic (`system()`, `exec()`, `eval()`).

## Initial Access & Execution (TA0001 / TA0002)
- **SSH brute force** (T1110): bursts of `Failed password` in `auth.log` / `secure`, then the first
  `Accepted password` = initial access. Record the source IP.
- **service exploitation** (T1190): crashes, segmentation faults, or anomalies in service logs (e.g., Apache, Nginx, Redis) around the access time.
- **execution from /tmp** (T1059): downloads then `chmod +x` then run. Includes executions from `/var/tmp`, `/dev/shm`, and `/run`.
- **Scripting & Interpreters** (T1059.004): Malicious use of built-in interpreters (`python -c`, `perl -e`, `php -r`) to spawn shells or download payloads.

## Privilege Escalation (TA0004)
- **sudo abuse** (T1548.003): `sudo … COMMAND=/bin/bash`, session-opened-for-root lines. Audit `/etc/sudoers` and `/etc/sudoers.d/*` for misconfigurations (`NOPASSWD`).
- **SUID/SGID binaries** (T1548.001): Unexpected binaries with the SUID bit set. Red flags: `find / -perm -4000`, especially custom binaries or copies of `bash`/`cp`/`vim` in temporary directories.
- **Capabilities** (T1548.002): Binaries granted excessive Linux capabilities (`getcap -r /`). Look for `cap_setuid`, `cap_dac_override`.
- **Kernel Exploits** (T1068): Traces of local privilege escalation (LPE) exploits like Dirty COW or Dirty Pipe. Often leaves anomalous entries in `dmesg` or `kern.log`.
- **Cron path hijacking**: Weak file permissions on scripts executed by root cron jobs.

## Defense Evasion (TA0005)
- **log tampering** (T1070): `history -c`, `HISTFILE=/dev/null`, commands prefixed with a space (to avoid history), truncated/cleared logs (`echo "" > /var/log/auth.log`). An artifact present in
  memory but absent from logs should be treated as a tampering indicator, not a contradiction to drop.
- **timestomping** (T1070.006): using `touch -t` or `touch -r` to match the modification times of malware to legitimate system files.
- **Fileless Execution / In-Memory Evasion** (T1620): Use of `memfd_create` to run binaries directly from memory without dropping them to disk.
- **Hidden Files/Directories** (T1564.001): Use of `.` prefix (e.g., `~/.hidden_dir`) or disguised directories (e.g., `...`, `.` + space).
- **Process Masquerading**: Renaming processes via `prctl()` or `exec -a` to look like legitimate threads (e.g., `[kworker/u4:2]`, `/sbin/klogd`).

## Credential Access / Collection / Exfiltration (TA0006 / TA0009 / TA0010)
- **archive + transfer**: `tar czf …` or `zip` then `scp`/`rsync`/`curl -T` to an external host.
- **OS Credential Dumping**: reading `/etc/passwd`, `/etc/shadow`.
- **Cloud/Dev Credential Harvesting** (T1552): Grepping or accessing `~/.aws/credentials`, `~/.kube/config`, `.env` files, or querying the AWS metadata endpoint (`169.254.169.254`).
- **Bash History** (T1552.003): Accessing `~/.bash_history` or `~/.zsh_history` to find plaintext passwords or API keys passed via CLI arguments.
- **Memory Dumping**: Suspicious access to `/dev/mem`, `/proc/kcore`, or use of `gcore`/`gdb` to dump process memory (e.g., SSHD or PAM credential theft).

## Command & Control (TA0011)
- **C2 beaconing** (T1071): regular inter-arrival times to one external IP (e.g., every 60s). Look for TLS connections without associated domain names or hardcoded IPs.
- **Reverse shells**: `socat`, `nc`, `ncat`, `bash -i`, or Python/Perl one-liners.
- **Non-Standard Ports** (T1571): Outbound SSH, HTTP, or DNS traffic over anomalous ports, or unknown protocols running over port 80/443.
- **Proxy usage**: Malicious binaries spinning up SOCKS5 proxies (like Chisel or FRP) to route traffic.

## Memory & Runtime Artifacts
- **Injected code**: `malfind` detections, RWX (Read-Write-Execute) memory pages.
- **Deleted-binary processes**: Running processes where the binary on disk has been deleted (visible via `ls -laR /proc/*/exe | grep "deleted"`).
- **Live sockets**: Established connections to external IPs tied to unknown PIDs or PIDs mimicking system binaries.
- **Rootkits (LKM)**: Loadable Kernel Modules hiding files, processes, or network connections. Detectable via discrepancies between userland tools (`ps`, `netstat`) and kernel space. 
- *Note for Agents:* Do not name a malware family without a supporting string/hash or distinct behavioral signature.

## Heuristic Hunting & Uncategorized Anomalies (Fallback Methodology)

*Agent Instruction: If an observed behavior, artifact, or user query does not map neatly to the known techniques above, fall back to these first-principles anomaly detection strategies to triage the unknown.*

- **Process Lineage Anomalies**: Parent-child relationship violations. Examples: Web servers (`nginx`, `apache2`, `tomcat`) or database daemons spawning `sh`, `bash`, `python`, or `curl`. `sshd` spawning a shell without a corresponding authentication log entry.
- **Unbacked / Orphaned Processes**: Running processes with PPID 1 (`init`/`systemd`) that are not recognized system services, or processes executing from directories that have been deleted.
- **Unmanaged System Files**: Executables or libraries located in `/bin`, `/sbin`, `/usr/bin`, `/usr/lib`, or `/lib` that are *not* tracked by the OS package manager (e.g., `dpkg -S <file>` or `rpm -qf <file>` returns no package).
- **UID/GID Anomalies (Ghost Accounts)**: Files, processes, or cron jobs owned by User IDs (UID) or Group IDs (GID) that do not exist in `/etc/passwd` or `/etc/group` (e.g., owned by UID 1005 when the highest known is 1002). Often indicates deleted rogue accounts or untarred malicious archives.
- **Unattributed Network Sockets**: Active network connections or listening ports where `ss` or `lsof` cannot resolve a PID, or the PID is masked. (Strong indicator of kernel-level rootkits or eBPF backdoors bypassing userland hooks).
- **Resource Exhaustion (Blind Heuristics)**: Unexplained, sustained CPU/RAM spikes by unknown binaries, or continuous outbound network streams from non-network daemons (often indicates cryptomining, localized DoS, or blind data staging/exfiltration).
- **Environment Variable Abuse**: Anomalous global variables set in `/proc/*/environ` across multiple disparate processes, particularly targeting `PATH` hijacking or silent proxy configurations (`http_proxy`, `LD_LIBRARY_PATH`).
- **Timestamp Discrepancies (MACB)**: Files where the `ctime` (inode change time) is vastly different from `mtime` (modification time) in system directories where they should logically match, or creation dates that pre-date the OS installation date.
