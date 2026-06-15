# LinuxIR Agent — demo video script (≤5 min)

Structure: **repo & concept tour → spoliation guardrail explained → live terminal demo.**

> Rule check: judges want **live terminal execution** showing the agent **working against
> evidence** with a **self-correction** — *not* slides/marketing. The GitHub tour is the framing,
> but keep Part 3 substantial (don't rush it): the agent visibly working + a self-correction is
> the part that must land. Record with OBS/`asciinema`, ~18–20pt font.

---

## Part 1 — What it is & how it works (GitHub repo) — ~1:30

*Screen-share the GitHub repo. Open `README.md`, then `docs/architecture.svg`.*

> "This is **LinuxIR Agent** — autonomous Linux incident response on a SANS SIFT workstation,
> built on Claude. You give it case context and read-only evidence paths; a team of specialist
> agents investigates in parallel — disk, logs, memory, network — then an auditor, an IR expert,
> and a reporter turn raw findings into a cited investigative narrative in an Obsidian vault."

*Open `docs/architecture.svg` (the trust-boundary diagram).*

> "The architectural bet is the whole project: **the language model is untrusted.** Every tool
> call from every agent funnels through one Python chokepoint — the tool gateway. Evidence
> protection lives *there*, in code, not in a prompt the model could ignore."

*Open `linuxir/gateway.py` → `dispatch`, then `linuxir/agents/_shared.py` briefly.*

> "Two honesty mechanisms worth calling out: every tool call records a **hypothesis before it
> runs** — what the agent expects — so surprises surface instead of getting rationalized. And the
> **auditor** judges each finding against the *verbatim tool output it cites* and drops anything
> it can't substantiate. 113 tests, two real-evidence runs documented in `docs/accuracy-report.md`."

---

## Part 2 — The spoliation guardrail: what / how / against what — ~1:15

*Open `linuxir/guardrails/constraints.py` (the `ConstraintEnforcer`).*

> "**Spoliation** is the destruction or alteration of evidence — in forensics it can invalidate a
> whole case. So the number-one rule is: the tool must **never** be able to mutate evidence.
>
> **How it works:** before any subprocess or file read runs, `dispatch` calls
> `ConstraintEnforcer.check`. It does three things — resolves every path with `realpath` and
> rejects anything outside the read-only evidence scope; blocks destructive command patterns —
> `dd`, `rm`, `chmod`, `truncate`, `tee`, shell `>` redirects; and enforces a read-only tool
> allowlist. A violation raises `SpoliationViolation`, the call is refused, and it's written to a
> dedicated `spoliation-attempts.jsonl` log. Because it's Python at the chokepoint, the model
> literally has no path around it."

*Open `linuxir/guardrails/spoliation_test.py`, then `docs/accuracy-report.md` §1 and §3b.*

> "**What it's run against:** two things. One — this 10-attack harness: ten deliberate
> write/delete/modify attempts, and we assert each is blocked, raised, and logged. Ten of ten.
> Two — and this is the real proof — it held against the **live model on real evidence**: in the
> FOR577 run the model itself tried seven out-of-scope or redirecting calls; all seven were
> refused in Python and logged."

---

## Part 3 — Live terminal demo — ~1:45  (don't rush this)

*Switch to a terminal in the repo. ~18–20pt font.*

**(a) The guardrail, live (~30s)**
```bash
uv run python -m linuxir.guardrails.spoliation_test
```
> "Here's that harness running — ten attempts, ten blocked, ten logged."

**(b) The agent working + catching its own hallucination (~45s)**
```bash
echo exit | uv run linuxir analyze --case cases/sample-case.yaml --offline
```
> "Now the full pipeline on a Linux intrusion. The specialist agents investigate, then the
> auditor reviews — and this case plants a fake 'meterpreter' finding with no supporting evidence.
> Watch: the auditor catches it and **drops it** before the report. Five findings confirmed, the
> hallucination cut."

**(c) Real evidence + a self-correction (~30s)**
```bash
cat out/for577/Corrections/self-learning-log.md     # 8 self-correction pivots + auditor drops
cat out/for577/vault/Report/case-questions.md        # the real answers, evidence-cited
```
> "And on 1.2 GB of real multi-host Linux logs: the persistence checks came back empty — a
> log-only collection — so the agent **self-corrected**, pivoting to sibling checks instead of
> concluding 'no persistence.' Its verdict: WEB-01 compromised, database dumps exfiltrated to an
> external host — every claim traceable to a tool call. **Read-only by construction, self-
> correcting, and honest about uncertainty. That's LinuxIR Agent.**"

---

## Pre-flight
```bash
cd ~/linuxir-agent && uv sync
clear            # don't show the token; .env is gitignored
```
All three terminal commands need only the clone (no token, no 1.2 GB evidence) — the FOR577
run output is committed under `out/for577/`.
