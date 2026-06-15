# Case `for577` — analyst questions

Direct answers to the four questions posed for this case, drawn from the **auditor-confirmed**
findings of the run (5 of 10 findings confirmed; see [[compromise-answers]], [[ioc-ttp]],
[[narrative]], and the transparency section of [[report]]). Confidence is stated per answer;
where the evidence does not support a claim, that is said plainly rather than inferred.

---

## 1. Attack timeline

**Earliest observed attacker activity: 2026-04-15 14:04:16 UTC.** _(confidence: MEDIUM)_

Reconstructed sequence (full chronology in [[timeline]]):

1. **Credential access & recon on WEB-01** — a root shell read `/etc/shadow` and enumerated
   the finance database. _(HIGH — `web01-db-credential-access-recon`, T1003/T1213, tc `d3ae3e4d`)_
2. **Database dump exfiltrated** from WEB-01 (10.42.20.20) to external `mosaic-metrics.net`.
   _(HIGH — `web01-db-exfil-mosaic-metrics` / `web01-root-db-exfil`, T1041/T1048/T1567)_
3. **Bulk HTTPS exfiltration** to external `23.72.209.230` observed from multiple
   workstations. _(HIGH — `exfil-23-72-209-230`, T1041/T1567)_

Supporting context: authentication analysis showed **no SSH brute force** and **no
log-coverage gaps**. **The initial-access vector could not be established from the logs in
scope** — reported as LOW confidence rather than guessed.

## 2. Attacker IP addresses

| Address | Role | Confidence |
|---|---|---|
| `10.42.20.20` | **WEB-01** — compromised internal host; source of the root shell and DB exfil | HIGH |
| `mosaic-metrics.net` | External exfiltration destination for the DB dump (resolved via Zeek `dns`/`ssl`) | HIGH |
| `23.72.209.230` | External destination of bulk HTTPS exfiltration from multiple workstations | HIGH |
| `10.42.30.35` | Internal host with risky binary transfers — **needs human review** (the "over SMB" characterization was *dropped* by the auditor; cited flows were port 22) | LOW / unverified |

## 3. Attacker file IOCs

- **`/tmp/nb-maint.sh`** — dropped script on WEB-01 (later removed). _(file path IOC)_
- **Staged database-dump archive** (`.gz`) on WEB-01 — exfiltrated, then deleted. The deletion
  (`rm -f`) is verbatim-supported; the "anti-forensic cleanup" *framing* was dropped by the
  auditor as unproven from the cited output, so it is noted here as an observation, not a
  confirmed conclusion.
- **`cms_ro:Winter2026!`** — hardcoded database credential observed in use on WEB-01. _(credential IOC)_
- Network IOCs: **`mosaic-metrics.net`**, **`23.72.209.230`** (see §2).

> Note: no file-**hash** IOCs (from Zeek `files.json`) reached the confirmed set in this run;
> the transferred-file finding was dropped by the auditor for insufficient citation. Hash IOCs
> would require a follow-up pass over `files.json` on the implicated hosts.

## 4. Was the database compromised?

**Yes.** _(confidence: HIGH)_

A root shell on **WEB-01 (10.42.20.20)** read `/etc/shadow`, used hardcoded DB credentials
(`cms_ro:Winter2026!`), **enumerated the finance database, and exfiltrated database dumps** to
the external host `mosaic-metrics.net`. _(`web01-db-credential-access-recon` +
`web01-root-db-exfil` + `web01-db-exfil-mosaic-metrics`; T1003 / T1213 / T1005 / T1041 / T1048 /
T1567.)_

Evidence: `WEB-01.../bash_history/root.bash_history` (lines 4–18), corroborated by Zeek
`zeek-dmz-01/dns.json` and `ssl.json`. Because the collection is **log-only** (no full
filesystem), endpoint-level confirmation of *which rows/tables* left is out of scope and would
require host-image follow-up; the **fact of dump creation and exfiltration is confirmed**.

---

_Every claim above is traceable to a `tool_call_id` in `audit/tool-calls.jsonl` and cites the
verbatim tool output it rests on; unsupported embellishments were dropped by the auditor pass._
