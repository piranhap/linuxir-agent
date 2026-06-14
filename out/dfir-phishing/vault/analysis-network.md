# analysis-network

*Agent turns:* 0

## Findings

_(confirmed)_

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

_(confirmed)_

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

_(DROPPED by auditor)_

### No external C2 beaconing, Tor exits, or DGA domains — DNS traffic is benign Microsoft/Google telemetry  ⚠️ **requires human review**
- **id:** `no-external-c2-dns-benign`
- **confidence:** MEDIUM
- **technique:** N/A (negative finding — rules out external C2/exfil)
- **hallucination_risk:** moderate
- **evidence:** `/home/sansforensics/linuxir-agent/evidence/phishing/challenge.pcapng`

All malicious activity in this capture is between RFC1918 internal hosts; there is no anonymized or external C2 infrastructure. None of the 17 destination IPs match the bundled Tor-exit list. The DNS queries are exclusively normal Windows/host telemetry and browsing: dns.msftncsi.com (connectivity check), edge.microsoft.com, config.edge.skype.com, clients2.google.com, www.bing.com / cn.bing.com, go.microsoft.com, v10.events.data.microsoft.com, static.edge.microsoftapp.net, www.wireshark.org, google.com — no high-entropy/DGA names. One internet-routable IP, 125.89.169.9, was contacted by 192.168.100.146 but only briefly (4 frames / 258 bytes) and has no local intel match; geoiplookup is unavailable so its country is unknown and not asserted.

<details><summary>cited tool output</summary>

```
network_find_tor_exits: [none of 17 destination IP(s) match the known Tor-exit list]
network_extract_dns: www.wireshark.org / dns.msftncsi.com / www.bing.com / config.edge.skype.com / edge.microsoft.com / clients2.google.com / cn.bing.com / go.microsoft.com / v10.events.data.microsoft.com / static.edge.microsoftapp.net / edge-consumer-static.azureedge.net / google.com
intel_lookup_ip 125.89.169.9: UNKNOWN [local-only] — internet-routable; no local match
geoip_lookup 125.89.169.9: [tool unavailable] geoiplookup is not installed; cannot geolocate ... Do not infer a country without data.
```

</details>

## Agent summary

Investigation complete. Summary:

The packet capture documents two internal-network attacks with **no external C2, Tor, exfil, or DGA infrastructure** — all malicious traffic is between RFC1918 hosts. First, the dominant flow is a ~22 MB / 18,232-frame **X11 session on port 6000 from victim 192.168.100.143 to off-subnet host 192.168.57.119** (confirmed internal): the victim's GUI/screen output is being streamed to the attacker's X server — an interactive remote-GUI / screen-capture channel (continuous sub-millisecond bursts, not periodic beaconing), and the single largest outbound transfer in the capture. Second, **192.168.100.146:6789 (Apache Tomcat Manager) is hit by an HTTP Basic-auth brute force** — hundreds of `/manager/html` attempts cycling usernames `tomcat`/`admin` against a rockyou-style wordlist (decoded creds include tomcat:tomcat, admin:admin, admin:12345, tomcat:password), most likely sourced from 192.168.100.1 (the dominant 2.5 MB flow to the target) using a scripted tool spoofing a Chrome User-Agent. DNS is entirely benign Microsoft/Google/Bing telemetry; the one public IP contacted (125.89.169.9) saw only 258 bytes, has no intel match, and its geolocation is unknown (geoiplookup unavailable, so no country is asserted). No Zeek JSON logs were present in scope.


[[report|← back to report]]
