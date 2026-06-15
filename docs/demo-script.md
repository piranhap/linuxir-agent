# LinuxIR Agent — demo video script (≤5 min)

Target: **under 5 minutes**, narrated screencast of **live terminal execution**, showing the
agent **working against real evidence** with **at least one self-correction** (the hackathon
rule requirements). Record with OBS or `asciinema`; terminal font ~18–20pt; you can speed the
live-run segment 1.5–2× in editing.

## Pre-flight (do this before you hit record)
```bash
cd ~/linuxir-agent
set -a; . ./.env; set +a; unset ANTHROPIC_API_KEY   # subscription token, never shown on screen
clear
```
- Make sure the token is **not** echoed anywhere on screen (`.env` is gitignored; don't `cat` it).
- Have these files ready to open: `out/for577/vault/Report/compromise-answers.md`,
  `out/for577/Corrections/self-learning-log.md`, `out/for577/audit/tool-calls.jsonl`.
- Use `cat` to show files on camera (or open them in your editor for nicer rendering).

---

## Shot 0 — Thesis (0:00–0:25)
*Terminal at repo root.*

> "This is **LinuxIR Agent** — autonomous Linux incident response on a SANS SIFT workstation.
> It's multi-agent, built on Claude. The architectural bet is this: **the language model is
> untrusted.** Every bit of evidence protection is enforced in Python at the tool gateway —
> not by asking the model to behave. Let me show you what that buys us."

---

## Shot 1 — The read-only guardrail, live (0:25–1:05)
```bash
uv run python -m linuxir.guardrails.spoliation_test
```
> "First, the trust boundary. This harness fires ten write/delete/modify attempts at the
> evidence — `dd`, `rm`, `chmod`, `truncate`, shell redirects, out-of-scope paths. Every one is
> **blocked in Python before any subprocess runs**, raised as a violation, and logged to a
> spoliation audit trail. Ten of ten. The model has no path to mutate evidence."

---

## Shot 2 — The agent working live on REAL evidence + self-correction (1:05–2:45)
```bash
uv run linuxir analyze --case cases/for577-demo.yaml --auth subscription
```
*(This is real FOR577 Linux lab data — a web server + a database server, bash histories and
syslogs. Speed up 1.5–2× in editing.)*

> "Now a real case — FOR577 lab data: real Linux hosts, `WEB-01` and `DB-01`, with bash
> histories and syslogs. The orchestrator dispatches specialist agents. **Notice each tool call
> states a hypothesis before it runs** — recorded to the audit log before the agent sees the
> result. The persistence checks come back empty, because this is a log-only collection — and
> the agent **self-corrects**: instead of concluding 'no persistence,' it pivots to the sibling
> checks. Then the log agent reconstructs the intrusion straight out of `root`'s bash history."

*Point the cursor at: a `hypothesis` line, and the `[self-correction]` pivot line.*

---

## Shot 3 — Findings + anti-hallucination, on the full 20-host run (2:45–3:45)
```bash
cat out/for577/vault/Report/compromise-answers.md      # or open in your editor
cat out/for577/Corrections/self-learning-log.md
```
> "Here's the executive output from the **full 20-host run**. The verdict: compromised — a root
> shell on WEB-01 read `/etc/shadow` and the finance database, then exfiltrated DB dumps to
> `mosaic-metrics.net`, with bulk exfil to an external IP. Every answer is confidence-rated, and
> where the logs couldn't establish the initial access vector, **it says so — LOW confidence —
> instead of inventing one.**
>
> And the auditor pass: it **dropped five of ten findings.** Look at *why* — it kept the verbatim
> `rm` command but cut the 'anti-forensic cleanup' framing as unproven; it cut 'over SMB' because
> the cited flows were port 22. Embellishment removed, evidence kept."

---

## Shot 4 — Traceability: every claim → a tool call (3:45–4:25)
```bash
# one audited tool call, pretty-printed: hypothesis recorded BEFORE, outcome AFTER
grep '"hypothesis":' out/for577/audit/tool-calls.jsonl | head -1 | python3 -m json.tool
# the real model's blocked attempts on real evidence
cat out/for577/audit/spoliation-attempts.jsonl | head -3
```
> "Everything is traceable. Each finding cites the verbatim tool output and a tool-call ID into
> this append-only log — here's one call with its **hypothesis recorded before execution and the
> outcome after.** And on this real run the model itself tried seven out-of-scope or redirecting
> calls — all refused in Python. This is the audit trail you can hand to a court."

---

## Shot 5 — Close (4:25–4:40)
> "Read-only by construction, every claim traceable, self-correcting, and honest about
> uncertainty. That's LinuxIR Agent."

---

## Fallback (no live token / safest cut)
Replace **Shot 2** with the deterministic offline pipeline (no API, ~30–60s), then treat
FOR577 (Shots 3–4) as the real-evidence proof:
```bash
echo exit | uv run linuxir analyze --case cases/sample-case.yaml --offline
```
> "Same pipeline, running deterministically offline against a planted intrusion — it even plants
> a fake 'meterpreter' finding with no supporting evidence, and the auditor catches and drops it.
> Then, here it is on 1.2 GB of real multi-host Linux evidence…"
