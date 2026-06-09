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

## 2. SANS *starkskunk5* (real Linux IR dataset)

Used for the real-evidence validation in [[accuracy-report]] §3. The dataset (mounted at
`/cases`, **read-only**) contains:

- `starkskunk5.E01` — 6.2 GB disk image (EnCase format).
- `logs/` — compressed `authentication_logs` (auth.log + `btmp`/`wtmp`), `system_logs`
  (syslog/kern), firewall/database logs, and an extracted `secure` log.
- `triage/starkskunk5_17Mar.zip` — a **CylR triage collection** (a real `/etc`, `/home`,
  `/var/log` tree with cron, ssh keys, shell histories — ideal for the read-only tools).
- `skunkweb/`, `precooked/` (filesystems, timelines), `examples/`, `binaries/`.

**How it was run:** the CylR triage zip was extracted to scratch (`/tmp/skunk-root`,
never modifying `/cases`); a case pointed `evidence_scope` at it; the full subscription
pipeline ran. `last`/`lastb`/`utmpdump` were present (real `btmp`/`wtmp` decoding);
`tshark`/`volatility3` were absent (graceful degradation).

**What the tools surfaced** (host `starkskunk5`, ~Mar 12–17):

- `logs_parse_auth` — sudo run from `PWD=/dev/shm/.hydra` by `bmorse`; `cbarton` reading
  `/home/bmorse/.ssh/*` as root.
- `logs_parse_lastb` — credential-spray burst from internal `10.130.9.15`/`.11`.
- `persistence_parse_bash_history` — `curl https://sh.rustup.rs \| sh`, GPG key generation,
  `SensitiveDocsForNick`, `.covert`.
- Full pipeline reconstruction: insider exfil by `bmorse`, `hydra` staging, `cbarton` root
  recon, anti-forensic history clearing.

> Integrity: `/cases` is treated as read-only evidence and was never written; all extraction
> went to `/tmp` scratch. Confirmed by file-mtime check post-run.
