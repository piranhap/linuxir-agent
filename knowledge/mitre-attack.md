# MITRE ATT&CK quick reference (Linux IR)

The IR-expert normalizes finding `technique` strings and groups them by tactic for the
polished analysis. Common techniques this platform surfaces:

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Valid Accounts | T1078 |
| Initial Access | Brute Force | T1110 |
| Execution | Command & Scripting Interpreter | T1059 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 |
| Persistence | Create/Modify systemd service | T1543.002 |
| Persistence | SSH authorized_keys | T1098.004 |
| Persistence | Boot/Logon init scripts (rc.local) | T1037 |
| Privilege Escalation | Setuid/Setgid | T1548.001 |
| Privilege Escalation | Sudo and Sudo Caching | T1548.003 |
| Defense Evasion | Hijack Execution Flow: LD_PRELOAD | T1574.006 |
| Defense Evasion | Indicator Removal: Clear/Truncate logs & history | T1070 |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 |
| Collection | Archive Collected Data | T1560 |
| Command & Control | Application Layer Protocol / beaconing | T1071 |
| Command & Control | Proxy: multi-hop (Tor) | T1090.003 |
| Exfiltration | Exfiltration Over C2 / Alternative Protocol | T1041 / T1048 |

Tactic order (for narrative timeline): Initial Access → Execution → Persistence →
Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement →
Collection → C2 → Exfiltration → Impact.
