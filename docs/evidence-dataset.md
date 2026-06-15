# Evidence datasets

What LinuxIR Agent was developed and tested against. See [[accuracy-report]] for results.

---

## 1. Bundled synthetic fixture (`tests/fixtures/evidence/`)

A small, self-contained post-attack Linux tree that exercises every tool offline with **zero
setup or API spend**. It encodes a coherent intrusion plus a deliberate hallucination:

| Artifact | What it plants |
|---|---|
| `etc/cron.d/apache-monitor` | C2 beacon `curl … \| bash` every minute (cron persistence) |
| `root/.ssh/authorized_keys` | Attacker ed25519 key (SSH persistence) |
| `var/log/auth.log` | SSH brute force from `185.220.101.47` → accepted login → sudo |
| `home/victim/.bash_history` | wget→/tmp→chmod+x→run, cron tamper, key add, `tar`+`scp` exfil, `history -c` |
| `etc/systemd/system/dbus-update.service` | `ExecStart` from `/dev/shm` (systemd persistence, LOW-confidence) |
| `etc/passwd` | `support:x:0:0` UID-0 backdoor account |
| `etc/ld.so.preload` | `/tmp/.x/libhook.so` (LD_PRELOAD hijack) |
| `etc/rc.local` | boot-persistence C2 line |
| `var/log/syslog` | cron-driven C2 + a deliberate 161-min coverage gap |

The offline demo also records a **planted "Metasploit meterpreter" finding** with no
supporting evidence, so the auditor pass has a real hallucination to catch and drop.

Run it:

```bash
uv run linuxir analyze --case cases/sample-case.yaml --offline
```

---

## 2. Public CTF — *Master of DFIR — Phishing* (real external dataset)

Used for the real-evidence validation in [[accuracy-report]] §3. This is a **public** DFIR
challenge (the "强网杯 / Qiangwang Cup" *Master of DFIR — Phishing* scenario), not internal
or course-restricted material — so the full run, including its audit logs, ships in the repo
under `out/dfir-phishing/` for inspection. The evidence set is two files:

- `关于组织参加第八届"强网杯"全国网络安全挑战赛的通知.eml` — a spearphishing email with a
  password-protected AES ZIP attachment.
- `challenge.pcapng` — a packet capture of the surrounding network activity.

This is a deliberately **partial** evidence set — email + pcap only, with *no* host
filesystem, auth.log, syslog, or `.bash_history`. That is precisely why it is a useful test:
it forces the persistence tools to come up empty (exercising the self-correction pivots) and
forces the agent to be honest about what it cannot conclude from the endpoint.

**How it was run:** a case pointed `evidence_scope` at `evidence/phishing/` (read-only) and
the full multi-agent pipeline ran end-to-end. `tshark`/`volatility3` were absent on the host,
so the network agent degraded gracefully to the **Zeek** JSON tools (graceful degradation,
not fabrication).

**What the tools surfaced:**

- **Email parsing** — spearphishing lure `alice@flycode.cn → bob@flycode.cn` using a "强网杯"
  theme; password-protected AES ZIP whose password (`2024qwbs8`) was disclosed in the body to
  defeat automated scanning; the archive carried a `.msc` MMC snap-in payload
  (T1566.001 / T1027 / T1204.002 / T1218).
- **Zeek/pcap correlation** — an Apache Tomcat Manager HTTP Basic-auth brute force from
  `192.168.100.1` against `192.168.100.146:6789` (T1110 / T1190), then outbound from
  `192.168.100.146` to external `125.89.169.9:443` with internal fan-out (T1071 / T1046).
- **Threat-intel / GeoIP** — `125.89.169.9` classified internet-routable, RFC1918 hosts
  correctly tagged internal (lateral movement, not external C2).
- **Honest coverage statement** — because no host artifacts were in scope, the agent flagged
  privilege-escalation/persistence/definitive-exfil as *unconfirmed at the endpoint*.

> Integrity: `evidence/phishing/` is treated as read-only and was never written; confirmed by
> the zero evidence-mutation count in [[accuracy-report]] §3 and the spoliation log.

---

## 3. FOR577 *log-experiment* — multi-host Linux logs (real, used with permission)

The largest and most representative dataset: the FOR577 "log-experiment" (Northbridge
Financial) scenario — a real, multi-host Linux enterprise capture. **Used with the explicit
permission of the data's author.** Validation results are in [[accuracy-report]] §3b; the
full run ships at `out/for577/`. ~1.2 GB across 22 sources:

- **20 Linux hosts** (`WEB-01`, `DB-01`, `DNS-01`, `BKP-01`, `MON-01`, and ~15 workstations),
  each with per-user `bash_history` (epoch-timestamped) and an RFC5424 `syslog.log`; `WEB-01`
  additionally carries a 115 MB `web_access.log`.
- **Two Zeek sensors** (`zeek-core-01`, `zeek-dmz-01`) emitting newline-delimited JSON:
  `conn`, `dns`, `http`, `files`, `ssl`, `x509` (the `conn`/`x509` logs are 100–200 MB each).

This is the dataset that exercises the **log** and **network** agents end-to-end. The Zeek
adapter streams the large JSON line-by-line with `max_lines` caps and returns bounded
summaries (top exfil/inbound talkers, file-hash tables), so multi-hundred-MB logs never reach
the model context. Because the collection is **log-only** (no `/etc`, no full filesystem),
the persistence tools come up empty and the agent **self-corrects** — pivoting to the sibling
checks rather than concluding "no persistence." This is the realistic-degradation behavior the
synthetic fixture cannot exercise.

**What the tools surfaced:** a privileged `WEB-01` shell reading `/etc/shadow` and the finance
database, **exfiltration of DB dumps to `mosaic-metrics.net`**, and bulk HTTPS exfiltration to
`23.72.209.230` recovered from the Zeek `conn` summaries — while honestly leaving the initial
vector LOW-confidence (logs alone did not establish it).

Run it (subscription auth shown; `--auth api` uses `ANTHROPIC_API_KEY`):

```bash
uv run linuxir analyze --case cases/for577.yaml --auth subscription
```

> Integrity: `evidence/for577/` is read-only and was never written (0 mutations,
> [[accuracy-report]] §3b). The raw evidence is gitignored; only the run output is committed.
