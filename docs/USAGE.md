# LinuxIR Agent — Usage & Testing Guide

Welcome to the **LinuxIR Agent**, an autonomous, multi-agent Digital Forensics and Incident Response (DFIR) triage system. This agent employs strict, model-independent guardrails to ensure evidence integrity, making it safe for live host analysis or offline disk/pcap triage.

This guide covers how to set up, use, test, and interact with the agent.

---

## 1. Prerequisites & Installation

The LinuxIR Agent relies on standard Linux DFIR tooling (e.g., `tshark`, `volatility3`). The Python environment is managed using `uv`.

### Core Requirements
1. **Python 3.12+**
2. **`uv` package manager**: `curl -LsSf https://astral.sh/uv/install.sh | sh`
3. **Forensic Tools**: `sudo apt-get install tshark`

### Setup
Clone the repository and install the application with `uv`:
```bash
git clone <repository_url> linuxir-agent
cd linuxir-agent
uv venv
source .venv/bin/activate
uv pip install -e ".[dev,web]"
```

---

## 2. Authentication

The agent can run using either the **Billed Anthropic API** or the **Claude Agent SDK ($0 per-token via your Claude Pro/Max subscription)**.

### Option A: Subscription (Recommended, $0 cost)
You can use your Claude Pro/Max account to run the agent locally without API billing.

1. Install Claude Code: `npm install -g @anthropic-ai/claude-code`
2. Authenticate: `claude setup-token`
3. Export the token:
```bash
export CLAUDE_CODE_OAUTH_TOKEN="sk-ant-oat01-..."
```
*(Make sure `ANTHROPIC_API_KEY` is **not** set, as it will silently override the token).*

### Option B: Billed API
If you prefer to use standard API billing, export your API key:
```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

---

## 3. Running an Investigation

Investigations are driven by **Case YAML** files. A Case file defines the evidence scope (directories containing disk images, raw logs, EML files, PCAPs, or memory dumps).

### Example Case File (`cases/my-case.yaml`)
```yaml
case_id: incident-042
evidence_scope:
  - ../evidence/compromised_server_dump
workspace: ../out/incident-042
```

### Starting the Analysis
Run the `linuxir` CLI, pointing it to your case file. The `--auth` flag dictates your chosen authentication method (`subscription` or `api`).

```bash
uv run linuxir analyze --case cases/my-case.yaml --auth subscription
```

The system will orchestrate the Disk, Log, Memory, and Network specialist agents to analyze the evidence. When complete, an independent **Auditor Agent** will review all findings, dropping any that hallucinate or misrepresent the cited tool output. 

---

## 4. Understanding the Output Vault

The agent outputs a structured Markdown "Obsidian Vault" containing the full investigation results.

```text
out/incident-042/
├── audit/
│   ├── tool-calls.jsonl            # Cryptographically traceable audit log (UUIDs)
│   └── spoliation-attempts.jsonl   # Blocked destructive commands
└── vault/
    ├── report.md                   # Executive summary
    ├── analysis-disk.md            # Raw disk agent findings
    ├── analysis-log.md             # Raw log agent findings
    ├── analysis-network.md         # Raw network agent findings
    ├── analysis-polished.md        # Senior IR narrative
    ├── Persona/
    │   ├── attacker-profile.md
    │   ├── narrative.md
    │   └── timeline.md
    └── Report/
        ├── compromise-answers.md   # The 12 mandatory SANS IR questions
        ├── ioc-ttp.md              # Extracted IOCs & MITRE mappings
        └── recommendations.md      # Hardening/Remediation steps
```

---

## 5. Interactive QA TUI (New Feature)

Once the analysis completes, the CLI will automatically drop you into an **Interactive QA Mode**.

This terminal UI loads the final `report.md` as context. You can dynamically ask the agent questions about the case, and it will respond strictly based on the vetted evidence in the report.

**Example QA Session:**
```text
============================================================
Investigation complete. Entering interactive QA mode.
Type 'exit' or 'quit' to end the session.
============================================================

User > What was the MD5 hash of the payload?
Agent > The MD5 hash of the payload (.msc file) was f436b02020fa59f3f71e0b6dcac6c7d3.

User > Did you find the password for the ZIP?
Agent > Yes, the password for the ZIP attachment was disclosed in the email body as: 2024qwbs8.

User > exit

Exiting QA mode.
```

---

## 6. Testing the Agent

### Running the Test Suite
The repository includes a comprehensive 100+ test suite that exercises the pipeline, the simulated `demo` responder, the spoliation guardrails, and the audit logging mechanisms.

```bash
uv run pytest
```

### Running the Offline Demo
You can test the end-to-end pipeline against bundled fixture evidence without spending any API tokens or needing a network connection by using the `--offline` flag. This uses a scriptable stand-in LLM.

```bash
uv run linuxir analyze --case cases/sample-case.yaml --offline
```

### Testing Against Real-World Scenarios
For live validation, we recommend downloading external CTF datasets (e.g., from [DFIR-LABS](https://github.com/Azr43lKn1ght/DFIR-LABS)) and pointing a case file at the extracted PCAPs or disk images.

*The `cases/phishing-case.yaml` template included in this repository is pre-configured to analyze the "Master of DFIR - Phishing" challenge from DFIR-LABS if the evidence is extracted to the `evidence/phishing/` directory.*
