# LinuxIR Agent — Devpost submission

> Paste-ready written description for the FIND EVIL! Hackathon submission form.
> Format: What it does · How we built it · Challenges · What we learned · What's next.

## What it does

LinuxIR Agent is a multi-agent Linux incident response platform that closes the gap between AI threat speed and defensive response time. An IR analyst opens a browser, provides plain-language case context and evidence paths, approves an AI-generated investigation plan, then watches as parallel specialized agents systematically investigate disk images, memory captures, log files, and network captures — correlating findings across evidence types, self-correcting on failures, enriching findings with live threat intelligence, and producing a complete investigative narrative in an Obsidian vault.

Every claim in the final report traces to a specific tool call in an append-only audit log. Every tool call records a hypothesis before execution and an outcome after — simultaneously creating an audit trail and a junior analyst training corpus. A human can open the Obsidian vault at any point, read the analysis in plain markdown, add their own notes, and watch new findings appear as the agents continue working.

## How we built it

Custom MCP Server + Multi-Agent framework on SIFT Workstation. The core architectural decision: the LLM layer is explicitly untrusted. Evidence protection is enforced in Python at the MCP gateway layer — not by asking the model to behave. The gateway validates every file path against the evidence scope, blocks every write/delete/modify pattern, and logs every blocked attempt to a spoliation audit log. We then deliberately ran our guardrail bypass test suite and documented every result.

Four typed MCP servers expose SIFT tools as structured functions (persistence, memory, logs, network). The orchestrator dispatches parallel source agents, an auditor re-runs tool calls to verify findings, a Linux IR expert enriches with threat intelligence and requests re-analysis when needed, a persona builder synthesizes the attacker profile and narrative timeline, and a reporter answers 12 mandatory IR questions with direct artifact citations.

The Corrections log is append-only and read back at the start of each iteration — closing the learning loop. A `--max-iterations` cap prevents runaway execution. All inter-agent communications are logged to `agent-messages.jsonl` with timestamps and token usage.

## Challenges

Keeping context windows clean across parallel agents required deliberately partitioning evidence by source — each agent holds only its own source's data, preventing cross-contamination and context degradation. The auditor re-execution approach (re-running the original tool call independently rather than re-reading the analysis) was the key to catching hallucinations reliably. Volatility3 profile auto-detection on diverse Linux kernels required a three-tier fallback strategy.

## What we learned

The hypothesis-before-execution pattern was the most valuable addition we didn't plan for. Requiring the agent to write what it expects to find before running a tool dramatically reduced hallucinated findings — the agent catches its own surprises during outcome comparison.

## What's next

SIEM integration via MCP (pull live Splunk/Elastic data into the investigation). Windows agent support. Multi-examiner collaboration via shared vault sync. Integration with OpenCTI for structured threat intelligence.
