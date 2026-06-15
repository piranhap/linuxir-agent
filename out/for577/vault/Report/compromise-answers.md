# Compromise — mandatory IR answers

_Case `for577` · 5 confirmed findings._

### 1. Is this device compromised?

**Yes — the host shows confirmed, evidence-backed indicators of compromise.** _(confidence: HIGH)_

Supporting findings: `web01-root-db-exfil`, `persistence-artifacts-absent-scope`, `web01-db-exfil-mosaic-metrics`, `web01-db-credential-access-recon`, `exfil-23-72-209-230`

Artifacts: `/home/sansforensics/linuxir-agent/evidence/for577/data/DB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history lines 4-18`, `/home/sansforensics/linuxir-agent/evidence/for577/data/zeek-dmz-01/dns.json`, `/home/sansforensics/linuxir-agent/evidence/for577/data/zeek-dmz-01/ssl.json`, `evidence/for577/data zeek conn.json (focus_ip 23.72.209.230)`, `zeek_conn_summary top exfil destinations`

### 2. When was the device believed to be compromised?

**Earliest observed attacker activity: 2026-04-15 14:04:16 UTC.** _(confidence: MEDIUM)_

See [[timeline]] for the full chronology.

### 3. Which accounts are suspected of being compromised?

**No specific account could be attributed across artifacts.** _(confidence: LOW)_

Supporting findings: `persistence-artifacts-absent-scope`

Artifacts: `/home/sansforensics/linuxir-agent/evidence/for577/data/DB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local`

### 4. How was the device compromised and where did the attack originate?

**Initial access vector not definitively established.** _(confidence: LOW)_

### 5. Do we need to investigate any other devices on the network?

**Yes — lateral movement / multi-host activity is indicated; investigate the connected hosts and accounts below.** _(confidence: MEDIUM)_

Supporting findings: `web01-db-credential-access-recon`

Artifacts: `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history`

### 6. Did the attacker elevate privileges? If so, how?

**Yes — No on-disk persistence artifacts present in evidence (collection is log-only, not full filesystems).** _(confidence: MEDIUM)_

Supporting findings: `persistence-artifacts-absent-scope`

Artifacts: `/home/sansforensics/linuxir-agent/evidence/for577/data/DB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local`

### 7. Has the attacker established persistence?

**Yes — persistence was established via: No on-disk persistence artifacts present in evidence (collection is log-only, not full filesystems).** _(confidence: MEDIUM)_

Supporting findings: `persistence-artifacts-absent-scope`

Artifacts: `/home/sansforensics/linuxir-agent/evidence/for577/data/DB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local`

### 8. What did the attackers do in the environment?

**WEB-01 root shell exfiltrated stolen database dumps to external host mosaic-metrics.net; No on-disk persistence artifacts present in evidence (collection is log-only, not full filesystems); Database dump exfiltrated from WEB-01 (10.42.20.20) to mosaic-metrics.net; Credential access (/etc/shadow) and finance-DB enumeration as root on WEB-01; Bulk data exfiltration to external 23.72.209.230 over HTTPS from multiple workstations** _(confidence: HIGH)_

Supporting findings: `web01-root-db-exfil`, `persistence-artifacts-absent-scope`, `web01-db-exfil-mosaic-metrics`, `web01-db-credential-access-recon`, `exfil-23-72-209-230`

Artifacts: `/home/sansforensics/linuxir-agent/evidence/for577/data/DB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history lines 4-18`, `/home/sansforensics/linuxir-agent/evidence/for577/data/zeek-dmz-01/dns.json`, `/home/sansforensics/linuxir-agent/evidence/for577/data/zeek-dmz-01/ssl.json`, `evidence/for577/data zeek conn.json (focus_ip 23.72.209.230)`, `zeek_conn_summary top exfil destinations`

### 9. Is there any significant behavior we need to know about?

**No standout anti-forensic behavior beyond the findings above.** _(confidence: LOW)_

### 10. Has any data been exfiltrated?

**Yes — data exfiltration is indicated: Bulk data exfiltration to external 23.72.209.230 over HTTPS from multiple workstations; Credential access (/etc/shadow) and finance-DB enumeration as root on WEB-01; Database dump exfiltrated from WEB-01 (10.42.20.20) to mosaic-metrics.net; No on-disk persistence artifacts present in evidence (collection is log-only, not full filesystems); WEB-01 root shell exfiltrated stolen database dumps to external host mosaic-metrics.net.** _(confidence: HIGH)_

Supporting findings: `web01-root-db-exfil`, `persistence-artifacts-absent-scope`, `web01-db-exfil-mosaic-metrics`, `web01-db-credential-access-recon`, `exfil-23-72-209-230`

Artifacts: `/home/sansforensics/linuxir-agent/evidence/for577/data/DB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history`, `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history lines 4-18`, `/home/sansforensics/linuxir-agent/evidence/for577/data/zeek-dmz-01/dns.json`, `/home/sansforensics/linuxir-agent/evidence/for577/data/zeek-dmz-01/ssl.json`, `evidence/for577/data zeek conn.json (focus_ip 23.72.209.230)`, `zeek_conn_summary top exfil destinations`

### 11. What, if any, malware did the attacker use?

**No malware binary confirmed by hash; review tooling in the findings.** _(confidence: LOW)_

### 12. What IOC/IOA/TTP can you recover from this intrusion?

**10 indicator(s) enriched and 6 ATT&CK technique(s) mapped — see [[ioc-ttp]].** _(confidence: HIGH)_

Full indicator and TTP listing in [[ioc-ttp]].
