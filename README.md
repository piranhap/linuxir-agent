# LinuxIR Agent

A multi-agent Linux DFIR (digital forensics & incident response) triage system for the
SANS **"FIND EVIL!"** challenge. It investigates a mounted evidence tree — finding
persistence, reconstructing the intrusion timeline, and (when the tools are present)
analyzing memory and network captures — and produces a cross-referenced report with
honest, audited confidence levels.

Its defining property is that **evidence-integrity guardrails are architectural, not
prompt-based**. A Python `ConstraintEnforcer` vets every tool call *before any subprocess
or filesystem write runs*. The model never gets the chance to spoliate evidence — the
restriction is code at the dispatch layer, not an instruction the model could ignore,
jailbreak, or hallucinate past.

```
coordinator ──▶ disk / log / memory / network agents      (Opus 4.8, manual tool loop)
                       │ every tool_use
                       ▼
              ToolGateway.dispatch()   ◀── the one chokepoint
                       │
        ConstraintEnforcer → AuditLogger → adapter (real binary or graceful fallback)
                       ▼
              findings ──▶ auditor (Haiku) ──▶ report.py (Obsidian vault + JSONL)
```

## Why a hand-rolled tool loop

The agents use the Anthropic SDK with an explicit `create → tool_use → dispatch →
tool_result` loop (`linuxir/agents/loop.py`) rather than a higher-level tool runner.
That is deliberate: it forces **every** tool call through `ToolGateway.dispatch`
(`linuxir/gateway.py`), where `ConstraintEnforcer.check` (`linuxir/guardrails/constraints.py`)
runs first. There is no code path from a model tool request to a subprocess that bypasses it.

The enforcer blocks a call when any of these hold:
1. the tool **name** denotes mutation (`write_`, `delete_`, `rm_`, `chmod_`, `truncate_`, …);
2. the tool is **not in the read-only registry**;
3. a path argument resolves (via `realpath`, so `..` is neutralized) **outside evidence scope**;
4. the `bash_readonly` escape hatch uses a non-allowlisted binary, a redirect (`>`/`>>`),
   an in-place edit, or a destructive flag;
5. an **output flag** (`--output-file`, `-o`, `of=`) appears on a read-only tool.

## Proof: the spoliation test (the headline claim)

Reproduces the report's ten write/delete/modify attempts and asserts **10/10 blocked,
10/10 raised as exceptions, 10/10 logged** to `audit/spoliation-attempts.jsonl`:

```bash
uv run python -m linuxir.guardrails.spoliation_test
uv run pytest tests/test_spoliation.py -q
```

## Setup

```bash
uv sync --extra dev          # installs anthropic, pydantic, pyyaml, pytest
```

Optional forensic binaries (the system runs without them — adapters fall back gracefully):
`volatility3` (`pip install volatility3`), `tshark`, `sleuthkit`, `geoiplookup`.

## Run

Three auth modes, selected with `--auth` / `--offline`:

| Mode | Flag | Cost | Needs |
|---|---|---|---|
| **Subscription** (default) | `--auth subscription` | **$0 per-token** (uses your Claude Pro/Max plan limits) | `claude` CLI + `CLAUDE_CODE_OAUTH_TOKEN` |
| Offline demo | `--offline` | $0, no network | nothing |
| Billed API | `--auth api` | paid per token | `ANTHROPIC_API_KEY` |

**Offline demo** — full pipeline, scripted client against the bundled evidence fixture
(great for proving the flow with zero setup):

```bash
uv run linuxir analyze --case cases/sample-case.yaml --offline
```

**Subscription ($0) — the hackathon path.** Runs on the **Claude Agent SDK** authenticated
by your Pro/Max subscription, so there is **no API key and no per-token billing** (just your
plan's usage limits). The forensic tools run as an in-process MCP server, built-in
Bash/Read/Write/Edit are disabled, and the `ConstraintEnforcer` still gates every call.

```bash
uv run linuxir analyze --case cases/sample-case.yaml                 # --auth subscription is the default
uv run linuxir analyze --case cases/sample-case.yaml --model opus --effort high
```

**Billed API** — raw Messages API with a hand-rolled gated loop:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
uv run linuxir analyze --case cases/sample-case.yaml --auth api
```

### Setting up the $0 subscription path on a VM (e.g. the SANS DFIR VM in GNOME Boxes)

The Python Agent SDK shells out to the **Claude Code CLI**, so the VM needs it plus a
subscription OAuth token. Browser login can't happen on a headless VM, so mint the token on
your normal machine and copy it over:

```bash
# 1. On a machine WITH a browser (your laptop), logged into Claude Pro/Max:
npm install -g @anthropic-ai/claude-code
claude setup-token          # opens a browser → prints sk-ant-oat01-...  (valid ~1 year)

# 2. On the SANS VM:
npm install -g @anthropic-ai/claude-code          # needs Node 18+
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...    # the token from step 1
unset ANTHROPIC_API_KEY                            # IMPORTANT: it silently overrides the token
uv sync --extra dev                                # or: pip install -e .
uv run linuxir analyze --case cases/sample-case.yaml
```

Notes:
- `ANTHROPIC_API_KEY` takes precedence over the OAuth token and would bill you — the CLI
  unsets it for you when `--auth subscription`, but keep it out of your shell to be safe.
- Subscription auth is licensed for **personal use** — run it yourself for the competition;
  don't ship it as a multi-user service on subscription credentials.
- Point `evidence_scope` in the case file at the mounted SANS evidence (read-only).

Output lands in the case `workspace`:
- `vault/report.md` + `vault/analysis-<agent>.md` — Obsidian-style notes (cross-linked).
- `audit/audit.jsonl` — every tool call (allowed/blocked), finding, and phase event.
- `audit/spoliation-attempts.jsonl` — blocked evidence-mutation attempts.
- `Corrections/self-learning-log.md` — distilled self-corrections (dropped findings, etc.).

## A case file

```yaml
case_id: demo-001
evidence_scope:          # READ-ONLY roots; paths resolve relative to this file
  - ../tests/fixtures/evidence
workspace: ../out/demo-001   # writable: vault, audit, Corrections
```

Memory images (`*.lime`/`*.raw`/…) and pcaps (`*.pcap`/…) found inside the evidence scope
automatically activate the memory and network agents.

## How findings stay honest

- Each finding **must cite the verbatim tool output** it rests on (`source_tool_output`).
- A separate **auditor pass (Haiku)** judges every finding against that cited output, not
  against the agent's prose, and **drops** anything it can't substantiate — caught before
  the final report. (The demo plants a "meterpreter" claim with no supporting evidence to
  show this working.)
- LOW-confidence or elevated-risk findings are flagged `requires_human_review`.
- The report includes a transparency section listing what the auditor dropped and why.

## Layout

```
linuxir/
  guardrails/constraints.py   ConstraintEnforcer + SpoliationViolation  (the safety core)
  guardrails/spoliation_test.py   10-attack harness
  gateway.py                  ToolGateway.dispatch — the chokepoint
  adapters/                   base.run_binary + disk / memory / network / geoip wrappers
  tools.py                    read-only tool schemas → gateway handlers
  agents/                     loop, base, coordinator, auditor, {disk,log,memory,network}_agent
  agentsdk_runtime.py         $0 subscription runtime (Claude Agent SDK + in-process MCP)
  findings.py audit.py report.py corrections.py config.py llm.py demo.py cli.py
knowledge/linux-techniques.md   technique checklist seeding the agents
cases/sample-case.yaml
tests/                        spoliation (13) + adapters (6) + pipeline (7) + subscription (5) = 31 tests
```

The same gateway, enforcer, tools, prompts, auditor, correlation, and reports are shared by
both transports — only how the model is reached differs (raw Messages API loop vs the Agent
SDK driving in-process MCP tools).

## Status & honesty

This repository is the working implementation. The **spoliation guarantee is real and
machine-verified** (run the test). The accuracy figures in the original report (BOTSv3 /
MemLabs recall, false-positive rates) require those evidence datasets to reproduce and are
**not** claimed by this code on its own — point a case file at real evidence with a live
API key to generate measured results.
