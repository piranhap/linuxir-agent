# MITRE ATT&CK quick reference (Linux IR)

The IR-expert agent normalizes finding `technique` strings and groups them by tactic for the
polished analysis. This mapping table serves as the agent's translation layer between raw Linux artifacts and standardized MITRE ATT&CK terminology.

Common techniques this platform surfaces:

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application (Web/Service) | T1190 |
| Initial Access | Valid Accounts: Local / Cloud Accounts | T1078 |
| Initial Access | Brute Force: Password Guessing / Spraying | T1110 |
| Execution | Command & Scripting Interpreter: Bash / Python | T1059 |
| Execution | User Execution: Malicious File (/tmp execution) | T1204.002 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 |
| Persistence | Create/Modify System Process: systemd Service | T1543.002 |
| Persistence | Account Manipulation: SSH authorized_keys | T1098.004 |
| Persistence | Boot/Logon Initialization Scripts: rc.local / init.d | T1037.004 |
| Persistence | Event Triggered Execution: .bashrc / .profile | T1546.004 |
| Persistence | Server Software Component: Web Shell | T1505.003 |
| Privilege Escalation | Abuse Elevation Control Mechanism: Sudo | T1548.003 |
| Privilege Escalation | Abuse Elevation Control Mechanism: Setuid/Setgid | T1548.001 |
| Privilege Escalation | Exploitation for Privilege Escalation (Kernel Exploits) | T1068 |
| Defense Evasion | Indicator Removal: Clear/Truncate Logs & History | T1070 |
| Defense Evasion | Indicator Removal: Timestomping | T1070.006 |
| Defense Evasion | Hijack Execution Flow: LD_PRELOAD | T1574.006 |
| Defense Evasion | Masquerading (Renamed processes/binaries) | T1036 |
| Defense Evasion | Hide Artifacts: Hidden Files and Directories | T1564.001 |
| Defense Evasion | Rootkit (LKM / eBPF) | T1014 |
| Defense Evasion | Reflective Code Loading (Fileless / memfd_create) | T1620 |
| Credential Access | OS Credential Dumping: /etc/passwd & /etc/shadow | T1003.008 |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 |
| Credential Access | Unsecured Credentials: Bash History / API Keys | T1552 |
| Discovery | System Information Discovery | T1082 |
| Discovery | Process Discovery | T1057 |
| Discovery | File and Directory Discovery | T1083 |
| Lateral Movement | Remote Services: SSH | T1021.004 |
| Lateral Movement | Lateral Tool Transfer | T1570 |
| Collection | Archive Collected Data (tar/zip) | T1560 |
| Command & Control | Application Layer Protocol / Beaconing | T1071 |
| Command & Control | Proxy: Multi-hop (Tor) | T1090.003 |
| Command & Control | Non-Standard Port | T1571 |
| Command & Control | Ingress Tool Transfer (wget/curl dropping payloads) | T1105 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |
| Impact | Resource Hijacking (Cryptomining) | T1496 |
| Impact | Data Destruction (Wipers / rm -rf) | T1485 |

## Attack Narrative Timeline Strategy

To ensure a logical and readable incident report, the agent must present the findings in chronological order of the attacker lifecycle. Always group and order tactics using the following progression:

**Initial Access** → **Execution** → **Persistence** → **Privilege Escalation** → **Defense Evasion** → **Credential Access** → **Discovery** → **Lateral Movement** → **Collection** → **Command & Control** → **Exfiltration** → **Impact**
