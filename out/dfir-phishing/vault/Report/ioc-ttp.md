# IOC / IOA / TTP

## MITRE ATT&CK techniques

- T1021 (Other)
- T1027 (Other)
- T1041 (Exfiltration)
- T1046 (Other)
- T1071 (Command & Control)
- T1110 (Initial Access)
- T1110.001 (Initial Access)
- T1190 (Other)
- T1204.002 (Other)
- T1218 (Other)
- T1566.001 (Other)

## Indicators of compromise

| indicator | kind | verdict | sources | detail |
|---|---|---|---|---|
| `125.89.169.9` | ip | unknown | local-only | internet-routable; no local match (enable external lookups for more) |
| `127.0.0.1` | ip | benign | rfc | loopback |
| `130.0.0.0` | ip | unknown | local-only | internet-routable; no local match (enable external lookups for more) |
| `172.20.10.3` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `172.20.10.5` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.0` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.1` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.143` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.146` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.128.95` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.43.112` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.57.0` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.57.119` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.69.125` | ip | internal | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `7.2.25.259` | ip | unknown |  | not a valid IP address |
| `flycode.cn` | domain | unknown | local-only | no baseline match; label entropy normal |

## Cross-artifact correlations (IOA)

- Indicator 7.2.25.259 corroborated across 2 agents (disk, log): findings phishing-email-spearphishing-attachment, phishing-email-lure-alice-to-bob.
- Indicator 127.0.0.1 corroborated across 2 agents (disk, log): findings phishing-email-spearphishing-attachment, phishing-email-lure-alice-to-bob.
- Indicator 130.0.0.0 corroborated across 2 agents (log, network): findings tomcat-manager-bruteforce-100.1-to-100.146, tomcat-manager-bruteforce-100-146.
- Indicator 192.168.100.146 corroborated across 2 agents (log, network): findings tomcat-manager-bruteforce-100.1-to-100.146, tomcat-host-100.146-post-exploit-outbound, no-host-logs-pivot-to-network, tomcat-manager-bruteforce-100-146.
- Indicator 192.168.100.1 corroborated across 2 agents (log, network): findings tomcat-manager-bruteforce-100.1-to-100.146, no-host-logs-pivot-to-network, tomcat-manager-bruteforce-100-146.

[[report|← back to report]]
