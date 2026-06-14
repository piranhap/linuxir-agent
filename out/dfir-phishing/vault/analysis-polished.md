# Polished analysis (Linux IR Expert)

## Executive narrative

The intrusion began with a spearphishing email recovered from the mail artifact (alice@flycode.cn → bob@flycode.cn), which used a "强网杯" lure to deliver a weaponized, password-protected AES ZIP whose password (2024qwbs8) was disclosed in the body to defeat automated scanning (T1566.001, T1027); parsing of the archive confirmed it contained a .msc MMC snap-in, a known user-execution/binary-proxy vector (T1204.002, T1218). Because the evidence set comprised only the email and a network capture — with no host filesystem, auth.log, syslog, or .bash_history available — persistence checks were not applicable and the timeline was reconstructed solely from these two sources, a coverage limitation that bounds confidence in the post-execution phases. tshark/Zeek correlation of the pcap revealed an Apache Tomcat Manager HTTP Basic-auth brute force from 192.168.100.1 against 192.168.100.146:6789 (T1110/T1110.001, T1190), indicating an attempt to exploit a public-facing application after or alongside the phishing vector. Following that activity, the same Tomcat host 192.168.100.146 generated outbound traffic to external 125.89.169.9:443 together with internal fan-out, consistent with C2 over an application-layer protocol and network service discovery (T1071, T1046); threat-intel checks classified 125.89.169.9 as internet-routable with no local reputation match, while the internal addresses resolved to RFC1918 hosts consistent with lateral movement rather than external infrastructure. Zeek flow analysis additionally surfaced a large ~22 MB X11 (port 6000) session from 192.168.100.143 to off-subnet host 192.168.57.119, consistent with remote GUI/screen streaming and a plausible exfiltration channel over display forwarding (T1021/T1041). Overall assessment: the available email and packet evidence support a multi-stage intrusion — phishing-delivered malicious file alongside brute-force exploitation of a Tomcat manager, followed by C2 beaconing, internal fan-out, and a sizable X11 transfer — but the absence of any host-side artifacts means privilege escalation, persistence, and definitive exfiltration cannot be confirmed at the endpoint level and are inferred from network behavior only. All conclusions are anchored to the parsed email headers/attachment and the pcap flows examined via tshark and Zeek; no host memory (Volatility) or Plaso/syslog timeline was in scope, and the off-network hosts implicated by the C2 and X11 sessions warrant follow-on collection to close these gaps.

## MITRE ATT&CK coverage

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

## Threat-intel enrichment

| indicator | kind | verdict | sources | detail |
|---|---|---|---|---|
| `125.89.169.9` | ip | **unknown** | local-only | internet-routable; no local match (enable external lookups for more) |
| `127.0.0.1` | ip | **benign** | rfc | loopback |
| `130.0.0.0` | ip | **unknown** | local-only | internet-routable; no local match (enable external lookups for more) |
| `172.20.10.3` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `172.20.10.5` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.0` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.1` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.143` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.146` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.128.95` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.43.112` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.57.0` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.57.119` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.69.125` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `7.2.25.259` | ip | **unknown** |  | not a valid IP address |
| `flycode.cn` | domain | **unknown** | local-only | no baseline match; label entropy normal |

## Confirmed findings reviewed

- [HIGH] No host filesystem in evidence — persistence checks N/A (email + pcap only) _([[analysis-disk]])_
- [MEDIUM] Spearphishing email with malicious attachment (alice@flycode.cn → bob@flycode.cn) _([[analysis-disk]])_
- [HIGH] Password-protected (AES) ZIP attachment, password disclosed in body: 2024qwbs8 _([[analysis-disk]])_
- [MEDIUM] ZIP contains a .msc (MMC snap-in) file — malicious-file execution vector _([[analysis-disk]])_
- [MEDIUM] Phishing email with weaponized attachment: alice@flycode.cn → bob@flycode.cn ("强网杯" lure) _([[analysis-log]])_
- [MEDIUM] Tomcat Manager HTTP Basic-auth brute force: 192.168.100.1 → 192.168.100.146:6789 _([[analysis-log]])_
- [MEDIUM] Post-attack outbound activity from Tomcat host 192.168.100.146 (external 125.89.169.9:443 + internal fan-out) _([[analysis-log]])_
- [MEDIUM] No auth.log / syslog / .bash_history present — timeline reconstructed from email + pcap only _([[analysis-log]])_
- [MEDIUM] Large X11 (port 6000) session from 192.168.100.143 to off-subnet host 192.168.57.119 — ~22 MB remote GUI / screen streaming _([[analysis-network]])_
- [MEDIUM] Apache Tomcat Manager HTTP Basic-auth brute force against 192.168.100.146:6789 _([[analysis-network]])_

[[report|← back to report]]
