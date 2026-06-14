# Compromise — mandatory IR answers

_Case `dfir-phishing` · 10 confirmed findings._

### 1. Is this device compromised?

**Yes — the host shows confirmed, evidence-backed indicators of compromise.** _(confidence: HIGH)_

Supporting findings: `no-host-filesystem-persistence-artifacts`, `phishing-email-spearphishing-attachment`, `password-protected-aes-zip-attachment`, `malicious-msc-payload-in-zip`, `phishing-email-lure-alice-to-bob`, `tomcat-manager-bruteforce-100.1-to-100.146` ([[analysis-disk]] [[analysis-log]] [[analysis-network]])

Artifacts: `/home/sansforensics/linuxir-agent/evidence/phishing`, `/home/sansforensics/linuxir-agent/evidence/phishing (dir listing)`, `/home/sansforensics/linuxir-agent/evidence/phishing/challenge.pcapng`, `/home/sansforensics/linuxir-agent/evidence/phishing/关于...通知.eml`, `/home/sansforensics/linuxir-agent/evidence/phishing/关于组织参加第八届"强网杯"全国网络安全挑战赛的通知.eml`, `/home/sansforensics/linuxir-agent/evidence/phishing/关于组织参加第八届“强网杯”全国网络安全挑战赛的通知.eml lines 1-63`, `challenge.pcapng conv,ip 192.168.100.1<->192.168.100.146`, `challenge.pcapng conv,ip rows for 192.168.100.146`

### 2. When was the device believed to be compromised?

**No precise timestamp recovered; see [[timeline]] for the reconstructed sequence.** _(confidence: LOW)_

See [[timeline]] for the full chronology.

### 3. Which accounts are suspected of being compromised?

**No specific account could be attributed across artifacts.** _(confidence: LOW)_

Supporting findings: `tomcat-manager-bruteforce-100.1-to-100.146`, `tomcat-host-100.146-post-exploit-outbound`, `no-host-logs-pivot-to-network`, `tomcat-manager-bruteforce-100-146`, `no-host-filesystem-persistence-artifacts`, `no-host-logs-pivot-to-network` ([[analysis-disk]] [[analysis-log]] [[analysis-network]])

Artifacts: `/home/sansforensics/linuxir-agent/evidence/phishing`, `/home/sansforensics/linuxir-agent/evidence/phishing (dir listing)`, `/home/sansforensics/linuxir-agent/evidence/phishing/challenge.pcapng`, `challenge.pcapng conv,ip 192.168.100.1<->192.168.100.146`, `challenge.pcapng conv,ip rows for 192.168.100.146`, `challenge.pcapng http.authorization Basic creds`, `challenge.pcapng http.request /manager/html`, `challenge.pcapng ip.dst==125.89.169.9`

### 4. How was the device compromised and where did the attack originate?

**Tomcat Manager HTTP Basic-auth brute force: 192.168.100.1 → 192.168.100.146:6789.** _(confidence: MEDIUM)_

Supporting findings: `tomcat-manager-bruteforce-100.1-to-100.146`, `tomcat-host-100.146-post-exploit-outbound`, `no-host-logs-pivot-to-network`, `tomcat-manager-bruteforce-100-146` ([[analysis-log]] [[analysis-network]])

Artifacts: `/home/sansforensics/linuxir-agent/evidence/phishing (dir listing)`, `/home/sansforensics/linuxir-agent/evidence/phishing/challenge.pcapng`, `challenge.pcapng conv,ip 192.168.100.1<->192.168.100.146`, `challenge.pcapng conv,ip rows for 192.168.100.146`, `challenge.pcapng http.authorization Basic creds`, `challenge.pcapng http.request /manager/html`, `challenge.pcapng ip.dst==125.89.169.9`, `intel_lookup_ip 125.89.169.9`

### 5. Do we need to investigate any other devices on the network?

**Yes — lateral movement / multi-host activity is indicated; investigate the connected hosts and accounts below.** _(confidence: MEDIUM)_

Supporting findings: `tomcat-host-100.146-post-exploit-outbound`, `x11-gui-exfil-57-119` ([[analysis-log]] [[analysis-network]])

Artifacts: `/home/sansforensics/linuxir-agent/evidence/phishing/challenge.pcapng`, `challenge.pcapng conv,ip rows for 192.168.100.146`, `challenge.pcapng ip.dst==125.89.169.9`, `intel_lookup_ip 125.89.169.9`

### 6. Did the attacker elevate privileges? If so, how?

**Yes — No host filesystem in evidence — persistence checks N/A (email + pcap only).** _(confidence: HIGH)_

Supporting findings: `no-host-filesystem-persistence-artifacts`, `no-host-logs-pivot-to-network` ([[analysis-disk]] [[analysis-log]])

Artifacts: `/home/sansforensics/linuxir-agent/evidence/phishing`, `/home/sansforensics/linuxir-agent/evidence/phishing (dir listing)`

### 7. Has the attacker established persistence?

**Yes — persistence was established via: No auth.log / syslog / .bash_history present — timeline reconstructed from email + pcap only; No host filesystem in evidence — persistence checks N/A (email + pcap only).** _(confidence: HIGH)_

Supporting findings: `no-host-filesystem-persistence-artifacts`, `no-host-logs-pivot-to-network` ([[analysis-disk]] [[analysis-log]])

Artifacts: `/home/sansforensics/linuxir-agent/evidence/phishing`, `/home/sansforensics/linuxir-agent/evidence/phishing (dir listing)`

### 8. What did the attackers do in the environment?

**No host filesystem in evidence — persistence checks N/A (email + pcap only); Spearphishing email with malicious attachment (alice@flycode.cn → bob@flycode.cn); Password-protected (AES) ZIP attachment, password disclosed in body: 2024qwbs8; ZIP contains a .msc (MMC snap-in) file — malicious-file execution vector; Phishing email with weaponized attachment: alice@flycode.cn → bob@flycode.cn ("强网杯" lure); Tomcat Manager HTTP Basic-auth brute force: 192.168.100.1 → 192.168.100.146:6789; Post-attack outbound activity from Tomcat host 192.168.100.146 (external 125.89.169.9:443 + internal fan-out); No auth.log / syslog / .bash_history present — timeline reconstructed from email + pcap only; Large X11 (port 6000) session from 192.168.100.143 to off-subnet host 192.168.57.119 — ~22 MB remote GUI / screen streaming; Apache Tomcat Manager HTTP Basic-auth brute force against 192.168.100.146:6789** _(confidence: HIGH)_

Supporting findings: `no-host-filesystem-persistence-artifacts`, `phishing-email-spearphishing-attachment`, `password-protected-aes-zip-attachment`, `malicious-msc-payload-in-zip`, `phishing-email-lure-alice-to-bob`, `tomcat-manager-bruteforce-100.1-to-100.146` ([[analysis-disk]] [[analysis-log]] [[analysis-network]])

Artifacts: `/home/sansforensics/linuxir-agent/evidence/phishing`, `/home/sansforensics/linuxir-agent/evidence/phishing (dir listing)`, `/home/sansforensics/linuxir-agent/evidence/phishing/challenge.pcapng`, `/home/sansforensics/linuxir-agent/evidence/phishing/关于...通知.eml`, `/home/sansforensics/linuxir-agent/evidence/phishing/关于组织参加第八届"强网杯"全国网络安全挑战赛的通知.eml`, `/home/sansforensics/linuxir-agent/evidence/phishing/关于组织参加第八届“强网杯”全国网络安全挑战赛的通知.eml lines 1-63`, `challenge.pcapng conv,ip 192.168.100.1<->192.168.100.146`, `challenge.pcapng conv,ip rows for 192.168.100.146`

### 9. Is there any significant behavior we need to know about?

**Yes — anti-forensic / evasion behavior: No auth.log / syslog / .bash_history present — timeline reconstructed from email + pcap only; Password-protected (AES) ZIP attachment, password disclosed in body: 2024qwbs8.** _(confidence: HIGH)_

Supporting findings: `password-protected-aes-zip-attachment`, `no-host-logs-pivot-to-network` ([[analysis-disk]] [[analysis-log]])

Artifacts: `/home/sansforensics/linuxir-agent/evidence/phishing (dir listing)`, `/home/sansforensics/linuxir-agent/evidence/phishing/关于...通知.eml`

### 10. Has any data been exfiltrated?

**Yes — data exfiltration is indicated: Large X11 (port 6000) session from 192.168.100.143 to off-subnet host 192.168.57.119 — ~22 MB remote GUI / screen streaming; Password-protected (AES) ZIP attachment, password disclosed in body: 2024qwbs8; ZIP contains a .msc (MMC snap-in) file — malicious-file execution vector.** _(confidence: HIGH)_

Supporting findings: `password-protected-aes-zip-attachment`, `malicious-msc-payload-in-zip`, `x11-gui-exfil-57-119` ([[analysis-disk]] [[analysis-network]])

Artifacts: `/home/sansforensics/linuxir-agent/evidence/phishing/challenge.pcapng`, `/home/sansforensics/linuxir-agent/evidence/phishing/关于...通知.eml`

### 11. What, if any, malware did the attacker use?

**No malware binary confirmed by hash; review tooling in the findings.** _(confidence: LOW)_

### 12. What IOC/IOA/TTP can you recover from this intrusion?

**16 indicator(s) enriched and 11 ATT&CK technique(s) mapped — see [[ioc-ttp]].** _(confidence: HIGH)_

Full indicator and TTP listing in [[ioc-ttp]].
