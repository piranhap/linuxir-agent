# Timeline (reconstructed)

_Times scraped from the tool output each finding cites; normalized for ordering within the case. Precise timestamps are in the cited output of each finding._

## Chronological

- _(no timestamped findings)_

## Undated findings

- No host filesystem in evidence — persistence checks N/A (email + pcap only) _([[analysis-disk]])_
- Spearphishing email with malicious attachment (alice@flycode.cn → bob@flycode.cn) _([[analysis-disk]])_
- Password-protected (AES) ZIP attachment, password disclosed in body: 2024qwbs8 _([[analysis-disk]])_
- ZIP contains a .msc (MMC snap-in) file — malicious-file execution vector _([[analysis-disk]])_
- Phishing email with weaponized attachment: alice@flycode.cn → bob@flycode.cn ("强网杯" lure) _([[analysis-log]])_
- Tomcat Manager HTTP Basic-auth brute force: 192.168.100.1 → 192.168.100.146:6789 _([[analysis-log]])_
- Post-attack outbound activity from Tomcat host 192.168.100.146 (external 125.89.169.9:443 + internal fan-out) _([[analysis-log]])_
- No auth.log / syslog / .bash_history present — timeline reconstructed from email + pcap only _([[analysis-log]])_
- Large X11 (port 6000) session from 192.168.100.143 to off-subnet host 192.168.57.119 — ~22 MB remote GUI / screen streaming _([[analysis-network]])_
- Apache Tomcat Manager HTTP Basic-auth brute force against 192.168.100.146:6789 _([[analysis-network]])_

[[report|← back to report]]
