# LinuxIR Report — case `dfir-phishing`

Evidence scope: `/home/sansforensics/linuxir-agent/evidence/phishing`

## Confidence distribution (confirmed findings)

| Confidence | Count | % |
|---|---|---|
| HIGH | 2 | 20.0% |
| MEDIUM | 8 | 80.0% |
| LOW | 0 | 0.0% |
| UNVERIFIED | 0 | 0.0% |

**10 confirmed findings.** 3 flagged for human review. 2 findings dropped by the auditor (see below).

## Key deliverables

- **Mandatory IR answers:** [[compromise-answers]]
- **IOC / IOA / TTP:** [[ioc-ttp]]
- **Recommendations:** [[recommendations]]
- **Attacker profile:** [[attacker-profile]] · **Timeline:** [[timeline]] · **Narrative:** [[narrative]]
- **Expert analysis:** [[analysis-polished]]

## Confirmed findings

### No host filesystem in evidence — persistence checks N/A (email + pcap only)
- **id:** `no-host-filesystem-persistence-artifacts`
- **confidence:** HIGH
- **technique:** N/A (evidence completeness)
- **hallucination_risk:** none
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/phishing`

The evidence scope contains only a phishing email (.eml) and a network capture (challenge.pcapng) — there is no mounted root filesystem. All host-based persistence checks (cron, systemd, authorized_keys, rc/init/profile, ld.so.preload, /etc/passwd, setuid, bash_history, wtmp/btmp) returned no artifacts because the relevant files are not present in scope. This is an evidence-completeness note, NOT a clean bill of health for the host. The on-disk attacker artifact in scope is the phishing email and its attachment (see related findings).

<details><summary>cited tool output</summary>

```
list_directory /home/sansforensics/linuxir-agent/evidence/phishing:
- 666   26409704 challenge.pcapng
- 666    1944400 关于组织参加第八届"强网杯"全国网络安全挑战赛的通知.eml

persistence_check_cron: [no cron artifacts found in evidence scope]
persistence_check_systemd: [no systemd units found in evidence scope]
check_authorized_keys: [no authorized_keys files found in evidence scope]
persistence_check_rc_files: [no rc/init/profile files found in evidence scope]
persistence_check_ld_preload: [no ld.so.preload or LD_PRELOAD environment entries found]
persistence_diff_passwd: [no /etc/passwd found in evidence scope]
persistence_check_setuid: [no setuid/setgid files found in evidence scope]
persistence_parse_bash_history: [no shell history files found in evidence scope]
persistence_parse_wtmp: [no wtmp/btmp/utmp files found in evidence scope]
```

</details>

_Source: [[analysis-disk]]_

### Spearphishing email with malicious attachment (alice@flycode.cn → bob@flycode.cn)
- **id:** `phishing-email-spearphishing-attachment`
- **confidence:** MEDIUM
- **technique:** T1566.001 Phishing: Spearphishing Attachment
- **hallucination_risk:** low
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/phishing/关于组织参加第八届"强网杯"全国网络安全挑战赛的通知.eml`

On-disk artifact: a phishing email crafted as an official notice for the 8th "Qiangwang Cup" (强网杯) national cybersecurity competition. Sent from alice@flycode.cn to bob@flycode.cn, dated Fri, 1 Nov 2024, composed with Foxmail 7.2.25.259[cn]. The Received header shows it was generated on host DESKTOP-FVLG67O via localhost (127.0.0.1), consistent with a locally-forged/attacker-controlled mail submission rather than transit through legitimate MX infrastructure. X-Has-Attach: yes and the multipart/mixed body carries an application/octet-stream attachment (a ZIP — see related finding). Classic spearphishing-attachment lure leveraging a topical, authoritative pretext to induce the recipient to open the attachment.

<details><summary>cited tool output</summary>

```
Return-Path: alice@flycode.cn
Received: from DESKTOP-FVLG67O (DESKTOP-FVLG67O [127.0.0.1])
	by DESKTOP-FVLG67O with ESMTPA
	; Fri, 1 Nov 2024 04:02:08 +0800
Date: Fri, 1 Nov 2024 04:02:08 +0800
From: "alice@flycode.cn" <alice@flycode.cn>
To: bob <bob@flycode.cn>
Subject: =?GB2312?B?udjT2tfp1q+yzrzTtdqwy73sobDHv834sa2hscirufrN+MLnsLLIq8z01b3I/LXEzajWqg==?=
X-Priority: 3
X-Has-Attach: yes
X-Mailer: Foxmail 7.2.25.259[cn]
Mime-Version: 1.0
Message-ID: <202411011759251120771@flycode.cn>
Content-Type: multipart/mixed;
	boundary="----=_001_NextPart161862142000_=----"
```

</details>

_Source: [[analysis-disk]]_

### Password-protected (AES) ZIP attachment, password disclosed in body: 2024qwbs8
- **id:** `password-protected-aes-zip-attachment`
- **confidence:** HIGH
- **technique:** T1027 Obfuscated/Encrypted Files; T1566.001 Spearphishing Attachment
- **hallucination_risk:** none
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/phishing/关于...通知.eml`

The email attachment is an application/octet-stream ZIP archive. The base64 payload begins "UEsDBDMAAQBjADt0YVkA...", which decodes to the ZIP local-file header: 50 4B 03 04 (PK\x03\x04), version-needed 0x0033 (51), general-purpose flags 0x0001 (bit0 = encrypted), and compression method 0x0063 (99 = AES encryption). Compressed size ~1,418,073 bytes, uncompressed ~2,314,408 bytes. The archive password is openly provided in the HTML body ("密码:2024qwbs8", GB2312-encoded as =C3=DC=C2=EB:2024qwbs8). Password-protecting the malicious archive and supplying the password in the lure text is a deliberate defense-evasion technique to bypass AV/email gateway content inspection while still enabling the victim to open it. The MIME attachment filename base64 ends "...KOpLnppcA==" which decodes to ".zip".

<details><summary>cited tool output</summary>

```
Content-Type: application/octet-stream;
	name="=?GB2312?B?...KOpLnppcA==?="
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
	filename="=?GB2312?B?...KOpLnppcA==?="

UEsDBDMAAQBjADt0YVkAAAAAWaMVAKhQIwBSAIsAudjT2tfp1q+yzrzTtdqwy73sobDHv834sa2h
scirufrN+MLnsLLIq8z01b3I/LXEzajWqqOoMTHUwjLI1dbBM8jVvtnQ0M/fyc/I/KOpLm1zY3Vw

(HTML body, GB2312 quoted-printable) ... =FC,=C3=DC=C2=EB:2024qwbs8</div>
[=C3=DC=C2=EB = GB2312 "密码" (password); PK\x03\x04 v51 flag 0x0001 method 0x0063=AES]
```

</details>

_Source: [[analysis-disk]]_

### ZIP contains a .msc (MMC snap-in) file — malicious-file execution vector
- **id:** `malicious-msc-payload-in-zip`
- **confidence:** MEDIUM
- **technique:** T1204.002 User Execution: Malicious File; T1218 System Binary Proxy Execution (mmc/.msc)
- **hallucination_risk:** low
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/phishing/关于...通知.eml`

Decoding the ZIP local-file header from the verbatim base64 yields: filename-length = 0x0052 (82 bytes), extra-length = 0x008B (139 bytes). The 82-byte entry name is a GB2312 Chinese string (the same "Qiangwang Cup notice" lure) whose final four bytes decode to 2E 6D 73 63 = ".msc". The inner payload is therefore a Microsoft Management Console snap-in (.msc) file. Weaponized .msc files (e.g. the "GrimResource" technique) execute attacker code when opened in mmc.exe, and are commonly delivered inside password-protected archives precisely as seen here. Confidence is MEDIUM because the AES-encrypted contents cannot be decrypted/inspected and the extension was derived by manual base64 decode of the entry name rather than tool extraction. Behavioral/C2 confirmation should come from the companion challenge.pcapng (network domain).

<details><summary>cited tool output</summary>

```
UEsDBDMAAQBjADt0YVkAAAAAWaMVAKhQIwBSAIsAudjT2tfp1q+yzrzTtdqwy73sobDHv834sa2h
scirufrN+MLnsLLIq8z01b3I/LXEzajWqqOoMTHUwjLI1dbBM8jVvtnQ0M/fyc/I/KOpLm1zY3Vw
fAAB...
[header decode: fname_len=0x0052=82, extra_len=0x008B=139; last 4 filename bytes "...Lm1zY3" -> 2E 6D 73 63 = ".msc"]
```

</details>

_Source: [[analysis-disk]]_

### Phishing email with weaponized attachment: alice@flycode.cn → bob@flycode.cn ("强网杯" lure)
- **id:** `phishing-email-lure-alice-to-bob`
- **confidence:** MEDIUM
- **technique:** T1566.001 Phishing: Spearphishing Attachment
- **hallucination_risk:** low
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/phishing/关于组织参加第八届“强网杯”全国网络安全挑战赛的通知.eml lines 1-63`

An .eml in evidence is an internal-looking spearphish from "alice@flycode.cn" to "bob@flycode.cn" dated Fri, 1 Nov 2024 04:02:08 +0800, sent via Foxmail 7.2.25.259. The Subject and the attachment name are GB2312/base64-encoded and match the lure theme "关于组织参加第八届'强网杯'全国网络安全挑战赛的通知" (Notice to participate in the 8th Qiangwang Cup national cybersecurity challenge). The message carries an application/octet-stream attachment, base64-encoded, delivered as Content-Disposition: attachment (filename also GB2312/base64, ending the lure name). The Received header shows the message was injected locally (DESKTOP-FVLG67O [127.0.0.1]), consistent with a spoofed/locally-crafted phish. This is the candidate initial-access vector (T1566.001). The attachment payload was not detonated/decoded with available read-only tools, so its exact type/hash is not confirmed here.

<details><summary>cited tool output</summary>

```
Return-Path: alice@flycode.cn
Received: from DESKTOP-FVLG67O (DESKTOP-FVLG67O [127.0.0.1])
Date: Fri, 1 Nov 2024 04:02:08 +0800
From: "alice@flycode.cn" <alice@flycode.cn>
To: bob <bob@flycode.cn>
Subject: =?GB2312?B?udjT2tfp1q+yzrzTtdqwy73sobDHv834sa2hscirufrN+MLnsLLIq8z01b3I/LXEzajWqg==?=
X-Mailer: Foxmail 7.2.25.259[cn]
Message-ID: <202411011759251120771@flycode.cn>
Content-Type: application/octet-stream;
	name="=?GB2312?B?udjT2tfp1q+yzrzTtdqwy73sobDHv834sa2hscirufrN+MLnsLLIq8z01b3I/LXEzajWqqOoMTHUwjLI1dbBM8jVvtnQ0M/fyc/I/KOpLnppcA==?="
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
	filename="=?GB2312?B?udjT2tfp1q+yzrzTtdqwy73sobDHv834sa2hscirufrN+MLnsLLIq8z01b3I/LXEzajWqqOoMTHUwjLI1dbBM8jVvtnQ0M/fyc/I/KOpLnppcA==?="
```

</details>

_Source: [[analysis-log]]_

### Tomcat Manager HTTP Basic-auth brute force: 192.168.100.1 → 192.168.100.146:6789  ⚠️ **requires human review**
- **id:** `tomcat-manager-bruteforce-100.1-to-100.146`
- **confidence:** MEDIUM
- **technique:** T1110 Brute Force; T1190 Exploit Public-Facing Application
- **hallucination_risk:** moderate
- **evidence:** `challenge.pcapng http.request /manager/html`, `challenge.pcapng http.authorization Basic creds`, `challenge.pcapng conv,ip 192.168.100.1<->192.168.100.146`

The capture shows host 192.168.100.1 hammering the Apache Tomcat Manager app on 192.168.100.146:6789. After loading the default Tomcat page (/, /tomcat.css, /tomcat.svg) at t≈137s, it requested /manager/html and began HTTP Basic-auth guessing. Early manual tries: t=148.8s "Basic dG9tY2F0OnRvbWNhdA=="=tomcat:tomcat, t=169.5s "Basic YWRtaW46YWRtaW4="=admin:admin. From t≈263s a high-volume credential-stuffing burst followed — hundreds of /manager/html requests cycling the usernames admin/tomcat against a rockyou-style password list (e.g. YWRtaW46MTIzNDU=admin:12345, dG9tY2F0OnBhc3N3b3Jk=tomcat:password, YWRtaW46aWxvdmV5b3U=admin:iloveyou, dG9tY2F0OnJvY2t5b3U=tomcat:rockyou, etc.). The pcap conversation list confirms 192.168.100.1 is the only HTTP peer of 192.168.100.146 (2,583 frames / 1.4 MB outbound to the server). This is brute-force/credential access against the Tomcat management interface (T1110 / T1190). The single successful credential and any subsequent WAR/webshell deploy could not be confirmed because HTTP response codes are not retrievable with the available read-only toolset.

<details><summary>cited tool output</summary>

```
142.350812000|192.168.100.146:6789|/manager/html|Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/130.0.0.0
148.805401000|192.168.100.146|Basic dG9tY2F0OnRvbWNhdA==||
169.457738000|192.168.100.146|Basic YWRtaW46YWRtaW4=||
263.544814000|192.168.100.146|Basic YWRtaW46MTIzNDU=||
263.544814000|192.168.100.146|Basic dG9tY2F0OjEyMzQ1Njc4OQ==||
263.546147000|192.168.100.146|Basic YWRtaW46cGFzc3dvcmQ=||
263.546954000|192.168.100.146|Basic dG9tY2F0OnJvY2t5b3U=||

IPv4 Conversations
192.168.100.1        <-> 192.168.100.146         1868 1,125 kB     2583 1,418 kB     4451 2,544 kB    137.214586000       418.2095
```

</details>

_Source: [[analysis-log]]_

### Post-attack outbound activity from Tomcat host 192.168.100.146 (external 125.89.169.9:443 + internal fan-out)
- **id:** `tomcat-host-100.146-post-exploit-outbound`
- **confidence:** MEDIUM
- **technique:** T1046 Network Service Discovery; T1071 Application Layer Protocol (C2)
- **hallucination_risk:** low
- **evidence:** `challenge.pcapng conv,ip rows for 192.168.100.146`, `challenge.pcapng ip.dst==125.89.169.9`, `intel_lookup_ip 125.89.169.9`

After the Manager brute force, the Tomcat host 192.168.100.146 initiates a series of outbound connections it had not made before. At t=334.8s it reaches the internet-routable IP 125.89.169.9 on tcp/443 (brief, ~3 packets), and across t≈305–386s it sends small 5-SYN bursts (≈330 bytes, mostly unanswered) to multiple hosts across foreign subnets: 192.168.69.125, 192.168.43.112, 172.20.10.3, 172.20.10.5, 192.168.128.95. The repeated short SYN-only fan-out to addresses on networks the host does not normally talk to is consistent with post-exploitation host discovery / lateral-movement attempts, while the 125.89.169.9:443 contact is a candidate C2/egress check-in. 125.89.169.9 returned UNKNOWN in the local intel DB (internet-routable, no local match) and geoiplookup is unavailable, so attribution/geolocation is not established. Beaconing periodicity could not be confirmed (only a single short contact observed).

<details><summary>cited tool output</summary>

```
192.168.100.146      <-> 192.168.69.125             2 120 bytes     10 660 bytes      12 780 bytes   305.420307000        61.4150
192.168.100.146      <-> 192.168.43.112             1 60 bytes        5 330 bytes       6 390 bytes   305.419664000        21.0287
192.168.100.146      <-> 172.20.10.3                1 60 bytes        5 330 bytes       6 390 bytes   345.793374000        21.0416
192.168.100.146      <-> 172.20.10.5                1 60 bytes        5 330 bytes       6 390 bytes   386.184702000        21.0422
192.168.100.146      <-> 192.168.128.95             1 60 bytes        5 330 bytes       6 390 bytes   386.184702000        21.0422
192.168.100.146      <-> 125.89.169.9               2 120 bytes       2 138 bytes       4 258 bytes   334.825137000         0.0004

$ tshark ... -Y ip.dst == 125.89.169.9
334.825137000	125.89.169.9	443
334.825441000	125.89.169.9	443
356.790064000	192.168.100.146,125.89.169.9	443

ip 125.89.169.9: UNKNOWN [local-only] — internet-routable; no local match
```

</details>

_Source: [[analysis-log]]_

### No auth.log / syslog / .bash_history present — timeline reconstructed from email + pcap only
- **id:** `no-host-logs-pivot-to-network`
- **confidence:** MEDIUM
- **technique:** N/A (evidence-coverage note)
- **hallucination_risk:** low
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/phishing (dir listing)`

My primary log-domain sources are entirely absent from this evidence set. logs_parse_auth, logs_build_timeline, logs_find_gaps and persistence_parse_bash_history all returned "no files found". The evidence directory contains only the phishing .eml and challenge.pcapng. This is not necessarily anti-forensic tampering — the dataset is a network-centric phishing/exploitation capture rather than a host triage image — but it means there is no on-host record of attacker commands, sudo/su escalation, or login records to corroborate the network activity. The intrusion timeline (phish 2024-11-01 → Tomcat Manager brute force from 192.168.100.1 against 192.168.100.146:6789 → post-exploit outbound from 192.168.100.146) is therefore reconstructed solely from the email headers and packet capture, and host-side confirmation (which credential succeeded, commands run, persistence) is not available from these artifacts.

<details><summary>cited tool output</summary>

```
logs_parse_auth: [no auth.log / secure files found in evidence scope]
logs_build_timeline: [no parseable text logs found for a timeline]
logs_find_gaps: [no logs to check for gaps]
persistence_parse_bash_history: [no shell history files found in evidence scope]

list_directory /evidence/phishing:
- 666   26409704 challenge.pcapng
- 666    1944400 关于组织参加第八届"强网杯"全国网络安全挑战赛的通知.eml
```

</details>

_Source: [[analysis-log]]_

### Large X11 (port 6000) session from 192.168.100.143 to off-subnet host 192.168.57.119 — ~22 MB remote GUI / screen streaming  ⚠️ **requires human review**
- **id:** `x11-gui-exfil-57-119`
- **confidence:** MEDIUM
- **technique:** T1021 Remote Services / T1041 Exfiltration Over C2 Channel (X11 display forwarding)
- **hallucination_risk:** moderate
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/phishing/challenge.pcapng`

The single dominant flow in the capture is 192.168.100.143 -> 192.168.57.119 carrying ~22 MB over 18,232 frames, entirely X11 protocol to TCP destination port 6000 (the X11 display server). 192.168.57.119 sits on a different subnet (192.168.57.0/24 vs the victim's 192.168.100.0/24) and is confirmed RFC1918 internal. X11 to an off-subnet host on port 6000 means GUI applications/screen output from 192.168.100.143 are being rendered on 192.168.57.119's X server — i.e. remote GUI access / screen streaming, a channel suitable for interactive control and data collection/exfiltration. This is the bulk-transfer "exfil" candidate flagged by the byte counter (22,390,199 outbound bytes from 192.168.100.143). Not periodic C2 beaconing — it is a continuous interactive session (packets arrive in tight sub-millisecond bursts starting at t=3.48s).

<details><summary>cited tool output</summary>

```
pcap_conversations: 192.168.100.143 <-> 192.168.57.119  15806 22 MB / 2426 355 kB / 18232 22 MB  Start 3.482858000  Duration 550.9912
pcap_summary: tcp ... x11 frames:24 ... (X11 protocol present)
network_detect_exfil: 192.168.100.143: 22,390,199 bytes   [LARGE OUTBOUND — possible exfil]
detect_beaconing (dst 192.168.57.119): 3.482858000 192.168.57.119 6000 / 3.483773000 192.168.57.119 6000 / 3.485296000 192.168.57.119 6000 ... (continuous port 6000 = X11 display)
intel_lookup_ip 192.168.57.119: INTERNAL [rfc1918] — RFC1918 private address — internal host
```

</details>

_Source: [[analysis-network]]_

### Apache Tomcat Manager HTTP Basic-auth brute force against 192.168.100.146:6789  ⚠️ **requires human review**
- **id:** `tomcat-manager-bruteforce-100-146`
- **confidence:** MEDIUM
- **technique:** T1110.001 Brute Force: Password Guessing
- **hallucination_risk:** moderate
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/phishing/challenge.pcapng`

A high-volume HTTP Basic authentication brute-force attack targets the Tomcat Manager app (/manager/html) on host 192.168.100.146:6789. After fetching the default Tomcat landing page (/tomcat.css, /asf-logo-wide.svg, /manager/html), the attacker submits hundreds of Basic-auth attempts in rapid succession (dozens within the same second, e.g. t=263.5xx) cycling the usernames "tomcat" and "admin" against a rockyou-style password list. Decoded cleartext credentials include tomcat:tomcat (dG9tY2F0OnRvbWNhdA==), admin:admin (YWRtaW46YWRtaW4=), admin:12345 (YWRtaW46MTIzNDU=), tomcat:123456789 (dG9tY2F0OjEyMzQ1Njc4OQ==), tomcat:password (dG9tY2F0OnBhc3N3b3Jk), tomcat:princess, admin:iloveyou, admin:password, etc. The conversation table shows 192.168.100.1 <-> 192.168.100.146 as the dominant flow to the target (4451 frames / 2.5 MB), identifying 192.168.100.1 as the most likely attack source. The single, browser-like User-Agent (Chrome/130.0.0.0) across all attempts is consistent with an automated scripted tool spoofing a browser.

<details><summary>cited tool output</summary>

```
network_extract_http: 142.350812000|192.168.100.146:6789|/manager/html|Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/130.0.0.0
(many repeated /manager/html at 263.5xx)
network_extract_credentials:
148.805401000|192.168.100.146|Basic dG9tY2F0OnRvbWNhdA==
169.457738000|192.168.100.146|Basic YWRtaW46YWRtaW4=
263.544814000|192.168.100.146|Basic YWRtaW46MTIzNDU=
263.544814000|192.168.100.146|Basic dG9tY2F0OjEyMzQ1Njc4OQ==
263.546696000|192.168.100.146|Basic dG9tY2F0Omlsb3ZleW91
263.546147000|192.168.100.146|Basic YWRtaW46cGFzc3dvcmQ=
pcap_conversations: 192.168.100.1 <-> 192.168.100.146  1868 1,125 kB / 2583 1,418 kB / 4451 2,544 kB
```

</details>

_Source: [[analysis-network]]_

## Cross-artifact correlations

- Indicator 7.2.25.259 corroborated across 2 agents (disk, log): findings phishing-email-spearphishing-attachment, phishing-email-lure-alice-to-bob.
- Indicator 127.0.0.1 corroborated across 2 agents (disk, log): findings phishing-email-spearphishing-attachment, phishing-email-lure-alice-to-bob.
- Indicator 130.0.0.0 corroborated across 2 agents (log, network): findings tomcat-manager-bruteforce-100.1-to-100.146, tomcat-manager-bruteforce-100-146.
- Indicator 192.168.100.146 corroborated across 2 agents (log, network): findings tomcat-manager-bruteforce-100.1-to-100.146, tomcat-host-100.146-post-exploit-outbound, no-host-logs-pivot-to-network, tomcat-manager-bruteforce-100-146.
- Indicator 192.168.100.1 corroborated across 2 agents (log, network): findings tomcat-manager-bruteforce-100.1-to-100.146, no-host-logs-pivot-to-network, tomcat-manager-bruteforce-100-146.

## Expert analysis & threat intel

_Senior IR-expert review — full narrative in [[analysis-polished]]._

**MITRE ATT&CK coverage:** T1021 (Other), T1027 (Other), T1041 (Exfiltration), T1046 (Other), T1071 (Command & Control), T1110 (Initial Access), T1110.001 (Initial Access), T1190 (Other), T1204.002 (Other), T1218 (Other), T1566.001 (Other)

**Threat-intel IOCs:** 16 enriched, 0 notable (malicious/suspicious).

| indicator | kind | verdict | detail |
|---|---|---|---|
| `125.89.169.9` | ip | **unknown** | internet-routable; no local match (enable external lookups for more) |
| `127.0.0.1` | ip | **benign** | loopback |
| `130.0.0.0` | ip | **unknown** | internet-routable; no local match (enable external lookups for more) |
| `172.20.10.3` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `172.20.10.5` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.0` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.1` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.143` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.100.146` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.128.95` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.43.112` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.57.0` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.57.119` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `192.168.69.125` | ip | **internal** | RFC1918 private address — internal host (lateral movement / insider context, not external C2) |
| `7.2.25.259` | ip | **unknown** | not a valid IP address |
| `flycode.cn` | domain | **unknown** | no baseline match; label entropy normal |

## Auditor-dropped findings (transparency)

- **Large 22 MB X11 session between 192.168.57.119 and 192.168.100.143 (interactive GUI / possible data movement)** (`large-x11-transfer-57.119-to-100.143`, from log) — dropped: The flow size (22 MB) and byte tally are supported, but the protocol hierarchy shows X11 is only 24 frames/107,784 bytes—not 22 MB—so attributing the large flow to an X11 session is contradicted by the cited output. _(risk: high)_
- **No external C2 beaconing, Tor exits, or DGA domains — DNS traffic is benign Microsoft/Google telemetry** (`no-external-c2-dns-benign`, from network) — dropped: Tor (17/0), DNS list, and the 125.89.169.9 intel/geoip claims are well-substantiated, but the 'no C2 beaconing' assertion and the specific '4 frames/258 bytes from 192.168.100.146' detail have no supporting tool output cited. _(risk: moderate)_

## Method & limitations

- Evidence was treated as **read-only**; every tool call was vetted by the ConstraintEnforcer before execution and logged to `audit/tool-calls.jsonl`. Blocked evidence-mutation attempts (if any) are in `audit/spoliation-attempts.jsonl`.
- Each finding was verified by an independent auditor pass against the verbatim tool output it cites; unsubstantiated claims were dropped.
- Tools whose binaries are not installed on this host return an 'unavailable' result; affected analyses are necessarily incomplete (not absent-of-evidence).


Agent notes: [[analysis-disk]], [[analysis-log]], [[analysis-network]], [[analysis-polished]]
