# LinuxIR Agent — Devpost submission

> Paste-ready written description for the FIND EVIL! Hackathon submission form.
> Format: What it does · How we built it · Challenges · What we learned · What's next.

## What it does

LinuxIR Agent is a multi-agent Linux incident response platform that closes the gap between AI threat speed and defensive response time. An IR analyst opens a browser, provides plain-language case context and read-only evidence paths, and launches the investigation; parallel specialized agents then systematically investigate disk images, memory captures, log files, and network captures — correlating findings across evidence types, self-correcting on failures, enriching findings with threat intelligence, and producing a complete investigative narrative in an Obsidian vault.

Every claim in the final report traces to a specific tool call in an append-only audit log. Every tool call records a hypothesis before it runs and the outcome after — creating an audit trail and a readable, hypothesis-driven reasoning record. Because the agents write the analysis to the Obsidian vault as plain markdown while they work, a human can open the vault at any point, read the analysis as it is produced, and add their own notes.

## How we built it

Custom MCP-style tool gateway + Multi-Agent framework on SIFT Workstation. The core architectural decision: the LLM layer is explicitly untrusted. Evidence protection is enforced in Python at a single tool-gateway chokepoint — not by asking the model to behave. Before any subprocess runs, the gateway validates every file path against the evidence scope, blocks every write/delete/modify pattern and off-allowlist binary, and logs every blocked attempt to a spoliation audit log. We then deliberately ran our guardrail-bypass test suite and documented every result.

A single read-only tool gateway exposes SIFT tools as typed, structured functions across four domains (persistence, memory, logs, network); on the subscription-auth path the same tools are served through an in-process MCP server so the chokepoint is preserved end-to-end. The orchestrator dispatches parallel source agents, an auditor judges each finding against the verbatim tool output it cites and drops anything it cannot substantiate, a Linux IR expert enriches with threat intelligence and can request re-analysis, a persona builder synthesizes the attacker profile and narrative timeline, and a reporter answers 12 mandatory IR questions with direct artifact citations.

The Corrections log is append-only and read back at the start of each iteration — closing the learning loop. A `--max-iterations` cap prevents runaway execution. All inter-agent communications are logged to `agent-messages.jsonl` with timestamps, sender, receiver, and message type.

## Challenges

Keeping context windows clean across parallel agents required deliberately partitioning evidence by source — each agent holds only its own source's data, preventing cross-contamination and context degradation. The auditor's grounding approach — judging each claim against the exact tool output it cites, rather than re-reading the agent's prose — was the key to catching hallucinations reliably. Tools whose binaries are absent (Volatility3, tshark) required graceful degradation: a structured "unavailable" result plus a self-correction pivot (e.g. a kernel-banner recovery for Volatility, falling back to Zeek JSON when tshark is missing) instead of fabricated output.

## What we learned

The hypothesis-before-execution pattern was the most valuable addition we didn't plan for. Requiring the agent to write what it expects to find before running a tool — and recording that expectation in the audit log before the result is seen — measurably reduced hallucinated findings: the agent catches its own surprises during outcome comparison, and the auditor backstop drops what survives anyway.

## What's next

SIEM integration via MCP (pull live Splunk/Elastic data into the investigation). Windows agent support. Multi-examiner collaboration via shared vault sync. Integration with OpenCTI for structured threat intelligence.
