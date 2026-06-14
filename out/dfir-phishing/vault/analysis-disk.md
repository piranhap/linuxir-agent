# analysis-disk

*Agent turns:* 0

## Findings

_(confirmed)_

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

_(confirmed)_

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

_(confirmed)_

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

_(confirmed)_

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

## Agent summary

## Summary

My domain is host-based persistence and on-disk artifacts. The evidence scope (`/home/.../evidence/phishing`) contains **no mounted root filesystem** — only a phishing email (`.eml`) and a network capture (`challenge.pcapng`) — so every standard persistence check (cron, systemd, authorized_keys, rc/init/profile, ld.so.preload, `/etc/passwd`, setuid, bash_history, wtmp/btmp) returned nothing; that is an evidence-completeness limitation, not a clean host. The single on-disk attacker artifact is the email: a **spearphishing-attachment lure** (T1566.001) forged on host `DESKTOP-FVLG67O` from `alice@flycode.cn` to `bob@flycode.cn` (Foxmail), disguised as an official "Qiangwang Cup" (强网杯) cybersecurity-competition notice. It carries a **password-protected, AES-encrypted ZIP** (PK header `UEsDBDMAAQBj…`, flag `0x0001`, method `0x0063`=AES) whose password (`2024qwbs8`) is openly given in the body — a deliberate AV/gateway evasion technique (T1027). Decoding the ZIP local-file header shows an 82-byte entry name ending in `.msc`, i.e. a malicious **Microsoft Management Console snap-in** (T1204.002 / GrimResource-style `.msc` execution; MEDIUM confidence as the AES contents couldn't be decrypted). Recommend the network agent inspect `challenge.pcapng` for the resulting payload download/C2 to confirm execution behavior.


[[report|← back to report]]
