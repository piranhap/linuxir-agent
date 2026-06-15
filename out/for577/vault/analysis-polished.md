# Polished analysis (Linux IR Expert)

## Executive narrative

Reconstructed primarily from Zeek conn.log and HTTP/SSL log correlations against the syslog-derived timeline, the intrusion centers on WEB-01 (10.42.20.20), where activity executed in a root context indicates the attacker had already obtained privileged access on that host. Auditd/syslog event correlation shows credential access against `/etc/shadow` and enumeration of the finance database as root (T1003, T1213), establishing both credential-harvesting and data-staging objectives on the server. From that root shell, Zeek and tshark flow analysis confirm stolen database dumps were exfiltrated from WEB-01 to the external host `mosaic-metrics.net`, with the outbound transfer mapping to T1041/T1567/T1048 and the underlying data-collection step to T1005. In parallel, tshark volumetric analysis of multiple internal workstations (the RFC1918 10.42.40.x and 10.42.31.x range confirmed by intel as internal hosts) revealed bulk HTTPS data egress to the internet-routable destination 23.72.209.230, indicating coordinated exfiltration beyond the single server. Threat-intel verdicts classify the 10.42.x.x addresses as internal—consistent with lateral movement or insider-adjacent staging rather than external C2—while `mosaic-metrics.net` and 23.72.209.230 remain unresolved under local-only lookups and warrant external enrichment. Critically, no on-disk persistence artifacts (cron, systemd, SSH keys, setuid) were recoverable because the evidence collection is log-only and does not include full filesystems, so persistence can be neither confirmed nor excluded and is flagged as an evidence-coverage limitation rather than a negative finding. Overall assessment: this is a confirmed data-exfiltration incident with high confidence that finance/database content left WEB-01, supported by medium-confidence indications of root-level credential access and multi-host bulk egress; the dominant ATT&CK theme is Exfiltration (T1041, T1048, T1567) layered on credential access and information-repository collection. Recommended next steps are external IOC enrichment on the two unknown destinations and acquisition of full WEB-01 and workstation filesystems to close the persistence and initial-access gaps the current log-only dataset cannot resolve.

## MITRE ATT&CK coverage

- T1003 (Other)
- T1005 (Other)
- T1041 (Exfiltration)
- T1048 (Exfiltration)
- T1213 (Other)
- T1567 (Exfiltration)

## Threat-intel enrichment

| indicator | kind | verdict | sources | detail |
|---|---|---|---|---|
| `10.42.20.20` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.31.15` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.32` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.51` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.71` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.81` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.91` | ip | **internal** | rfc1918 | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `103.27.202.93` | ip | **unknown** | local-only | internet-routable; no local match (enable external lookups for more) |
| `23.72.209.230` | ip | **unknown** | local-only | internet-routable; no local match (enable external lookups for more) |
| `mosaic-metrics.net` | domain | **unknown** | local-only | no baseline match; label entropy normal |

## Confirmed findings reviewed

- [MEDIUM] WEB-01 root shell exfiltrated stolen database dumps to external host mosaic-metrics.net _([[analysis-None]])_
- [MEDIUM] No on-disk persistence artifacts present in evidence (collection is log-only, not full filesystems) _([[analysis-None]])_
- [HIGH] Database dump exfiltrated from WEB-01 (10.42.20.20) to mosaic-metrics.net _([[analysis-None]])_
- [MEDIUM] Credential access (/etc/shadow) and finance-DB enumeration as root on WEB-01 _([[analysis-None]])_
- [MEDIUM] Bulk data exfiltration to external 23.72.209.230 over HTTPS from multiple workstations _([[analysis-None]])_

[[report|← back to report]]
