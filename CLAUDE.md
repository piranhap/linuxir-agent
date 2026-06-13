# LinuxIR Agent — Claude Code Build Instructions
## FIND EVIL! Hackathon · SANS Institute · Deadline June 15, 2026 11:45pm EDT

You are building a multi-agent Linux incident response platform that runs on a SANS SIFT Workstation.
Read this entire file before writing a single line of code. Every section is load-bearing.

---

## Project identity

**Name:** LinuxIR Agent  
**Tagline:** Autonomous Linux IR on SIFT — from evidence paths to structured investigative narrative  
**Architecture pattern:** Custom MCP Server + Multi-Agent Framework (the judges' top-rated approach)  
**Framework:** Claude Code (claude-sonnet-4-20250514) orchestrating sub-agents via async Python  
**License:** MIT (must be at repo root, detectable in About section)

---

## Absolute constraints — never violate these

1. **Read-only enforcement is architectural, not a prompt.** Every write/delete/modify attempt must be rejected at the MCP gateway layer in Python code, not by asking the model to behave. The model is untrusted.
2. **Every finding must have a `tool_call_id`.** If you cannot trace a finding to a specific tool execution entry in `audit/tool-calls.jsonl`, the finding must be flagged as UNVERIFIED and not included in the final report.
3. **Every tool call must record a `hypothesis` before execution** — what the agent expects to find — and an `outcome` after. This goes in `Corrections/reasoning-trace.md` in Obsidian.
4. **`--max-iterations N`** (default 10) must be respected. The orchestrator must gracefully degrade after N iterations without completing, writing a partial report rather than looping forever.
5. **`agent-messages.jsonl`** must record every inter-agent communication with timestamps, sender, receiver, and message type. This is separate from tool-call logs.
6. **The Corrections log must be read at the start of each iteration**, not just written. The agent learns from its own previous attempts.
7. **Evidence scope is enforced in `guardrails/constraints.py`** at the path-validation level. The MCP server must call `validate_path()` before every tool execution. No exceptions.

---

## Repository structure — create exactly this

```
linuxir-agent/
├── CLAUDE.md                          ← this file
├── README.md                          ← setup instructions (see section 12)
├── LICENSE                            ← MIT
├── pyproject.toml                     ← package definition
├── install.sh                         ← one-command installer for SIFT
│
├── app/
│   ├── server.py                      ← FastAPI app, mounts routes
│   ├── routes/
│   │   ├── intake.py                  ← POST /case/new
│   │   ├── plan.py                    ← GET /case/{id}/plan
│   │   ├── approve.py                 ← POST /case/{id}/approve
│   │   └── status.py                  ← GET /case/{id}/status (SSE stream)
│   └── static/
│       └── index.html                 ← single-page GUI
│
├── agents/
│   ├── orchestrator.py                ← master planner + dispatcher
│   ├── source_agent.py                ← generic per-source agent
│   ├── auditor.py                     ← hallucination checker
│   ├── linux_ir_expert.py             ← senior reviewer + threat intel
│   ├── persona_builder.py             ← attacker profile + timeline
│   ├── reporter.py                    ← final report generator
│   └── base.py                        ← shared agent base class
│
├── mcp/
│   ├── gateway.py                     ← aggregates all MCP servers, enforces constraints
│   ├── servers/
│   │   ├── persistence_server.py      ← cron, systemd, SSH, setuid, bash_history
│   │   ├── memory_server.py           ← Volatility3 wrappers
│   │   ├── logs_server.py             ← auth.log, auditd, wtmp, timeline
│   │   └── network_server.py          ← tshark, zeek, pcap analysis
│   └── obsidian_server.py             ← Obsidian Local REST API wrapper
│
├── guardrails/
│   ├── constraints.py                 ← path validation, write denylist, scope enforcement
│   └── spoliation_test.py             ← deliberate bypass test suite (documents in accuracy report)
│
├── models/
│   ├── schemas.py                     ← Pydantic: Finding, AuditEntry, CaseState, AgentMessage
│   └── confidence.py                  ← ConfidenceLevel enum, scoring logic
│
├── knowledge/
│   ├── linux-techniques.md            ← Linux IR checklist (you maintain this)
│   ├── mitre-attack.md                ← ATT&CK TTP reference
│   ├── known-hashes.md                ← malware hash baseline
│   └── threat-intel-sources.md        ← VirusTotal, abuse.ch, MalwareBazaar endpoints
│
├── audit/
│   ├── tool-calls.jsonl               ← append-only: every MCP tool execution
│   ├── agent-messages.jsonl           ← append-only: inter-agent communications
│   └── spoliation-attempts.jsonl      ← append-only: blocked write attempts
│
├── vault/
│   └── template/                      ← copied to vault/cases/{case_id}/ on new case
│       ├── Evidence/
│       │   └── case-state.md
│       ├── Analysis/
│       ├── Persona/
│       ├── Report/
│       └── Corrections/
│           ├── self-learning-log.md
│           ├── reasoning-trace.md
│           └── human-notes.md
│
├── tests/
│   ├── test_constraints.py            ← verify guardrails block writes
│   ├── test_self_correction.py        ← verify 3 recovery sequences
│   ├── test_confidence.py             ← verify scoring logic
│   └── test_audit_trail.py            ← verify every finding is traceable
│
└── docs/
    ├── architecture.svg               ← exported from this session
    ├── accuracy-report.md             ← fill during testing
    ├── evidence-dataset.md            ← what you tested against
    └── devpost-description.md         ← written submission (see section 13)
```

---

## Section 1: Install script (`install.sh`)

```bash
#!/bin/bash
# LinuxIR Agent installer for SIFT Workstation
set -e

echo "[*] Installing LinuxIR Agent..."

# Python 3.10+ required
python3 --version | grep -qE "3\.(10|11|12)" || { echo "Python 3.10+ required"; exit 1; }

# Install dependencies
pip3 install --break-system-packages \
    fastapi uvicorn anthropic python-dotenv \
    pydantic aiofiles httpx asyncio \
    mcp python-multipart sse-starlette

# Check SIFT tools
for tool in vol volatility3 tshark log2timeline plaso fls icat; do
    command -v $tool &>/dev/null && echo "[+] $tool found" || echo "[!] $tool not found — some analysis may be limited"
done

# Check Obsidian Local REST API
curl -s http://localhost:27123/vault/ -H "Authorization: Bearer ${OBSIDIAN_API_KEY:-}" \
    &>/dev/null && echo "[+] Obsidian API reachable" || echo "[!] Obsidian API not reachable — vault features disabled"

# Copy env template
[ -f .env ] || cp .env.template .env
echo "[*] Edit .env and set ANTHROPIC_API_KEY and OBSIDIAN_API_KEY"

echo "[+] Installation complete. Run: python3 -m app.server"
```

---

## Section 2: Environment (`.env.template`)

```
ANTHROPIC_API_KEY=sk-ant-...
OBSIDIAN_API_KEY=your-obsidian-rest-api-key
OBSIDIAN_HOST=http://localhost:27123
VIRUSTOTAL_API_KEY=              # optional, for hash lookups
MAX_ITERATIONS=10
CASE_DIR=./vault/cases
EVIDENCE_SCOPE=                  # set per-case, enforced by guardrails
```

---

## Section 3: Pydantic schemas (`models/schemas.py`)

Define these exactly — everything downstream depends on them:

```python
from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional, List
from datetime import datetime

class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"        # Direct artifact, byte-level traceable
    MEDIUM = "MEDIUM"    # Pattern match + secondary artifact
    LOW = "LOW"          # Single data point or behavioral inference
    UNVERIFIED = "UNVERIFIED"  # Cannot trace to tool call

class SourceType(str, Enum):
    MOUNTED_IMAGE = "mounted_image"
    RAW_DISK = "raw_disk"
    MEMORY_CAPTURE = "memory_capture"
    LOG_FILE = "log_file"
    LOG_DIR = "log_directory"
    PCAP = "pcap"
    UNKNOWN = "unknown"

class Finding(BaseModel):
    finding_id: str              # F-{case}-{seq:04d}
    tool_call_id: str            # links to audit/tool-calls.jsonl
    artifact_path: str           # exact file path or memory offset
    artifact_offset: Optional[int] = None
    source_type: SourceType
    raw_evidence: str            # verbatim tool output excerpt (≤500 chars)
    hypothesis: str              # what agent expected BEFORE running tool
    agent_interpretation: str   # Claude's reasoning
    confidence: ConfidenceLevel
    is_inferred: bool            # True = conclusion, False = direct observation
    hallucination_risk: str      # "none" | "low" | "moderate" | "high"
    mitre_techniques: List[str] = []  # ["T1053.003", ...]
    iocs: List[str] = []         # hashes, IPs, domains
    timestamp_utc: datetime
    auditor_verified: bool = False
    auditor_notes: Optional[str] = None

class ToolCall(BaseModel):
    tool_call_id: str            # tc-{case}-{seq:06d}
    agent_name: str
    tool_name: str
    tool_params: dict
    hypothesis: str              # recorded BEFORE execution
    raw_output_hash: str         # sha256 of full output
    raw_output_excerpt: str      # first 500 chars
    outcome: str                 # recorded AFTER execution
    findings_produced: List[str] = []
    self_correction_applied: bool = False
    correction_reason: Optional[str] = None
    attempts: int = 1
    token_usage: dict            # {"input": N, "output": N}
    duration_ms: int
    timestamp_utc: datetime

class AgentMessage(BaseModel):
    msg_id: str                  # am-{case}-{seq:06d}
    timestamp_utc: datetime
    sender: str                  # agent name
    receiver: str                # agent name or "orchestrator"
    msg_type: str                # "finding_update" | "reanalysis_request" | "intel_match" | "plan_revision"
    payload: dict
    token_usage: Optional[dict] = None

class CaseState(BaseModel):
    case_id: str
    client_name: str
    industry: str
    suspected_breach_date: Optional[str] = None
    context: str
    sources: List[dict]          # [{"path": "...", "type": "...", "status": "..."}]
    phase: str                   # "triage" | "analysis" | "audit" | "expert" | "persona" | "report" | "complete"
    iteration: int = 0
    max_iterations: int = 10
    findings_count: int = 0
    high_confidence_count: int = 0
    created_at: datetime
    updated_at: datetime
```

---

## Section 4: Guardrails (`guardrails/constraints.py`)

This is the trust boundary. It must be called before every MCP tool execution.

```python
import re
import hashlib
from pathlib import Path
from typing import Optional
from models.schemas import ToolCall
import logging

logger = logging.getLogger(__name__)

FORBIDDEN_WRITE_PATTERNS = [
    r"dd\b.*\bof=",
    r">\s*/",
    r"\brm\b\s",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bmkfs\b",
    r"\bshred\b",
    r"\bwipe\b",
    r"\btruncate\b",
    r">\s*\$\{?EVIDENCE",
    r"\bcp\b.*--no-preserve",
]

ALLOWED_TOOL_PREFIXES = {
    "get_", "list_", "parse_", "check_", "read_",
    "search_", "analyze_", "extract_", "find_",
    "vol_", "tshark_", "zeek_", "timeline_"
}

class ScopeViolation(Exception): pass
class WriteViolation(Exception): pass
class ToolDenied(Exception): pass

class ConstraintEnforcer:
    def __init__(self, evidence_scope: Path, case_id: str):
        self.evidence_scope = evidence_scope.resolve()
        self.case_id = case_id
        self._blocked_attempts = 0

    def validate_path(self, path: str) -> Path:
        """Every file access must pass through this. Raises ScopeViolation if outside evidence."""
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(self.evidence_scope):
            self._log_blocked_attempt("scope_violation", path)
            raise ScopeViolation(
                f"Path {path} is outside evidence scope {self.evidence_scope}"
            )
        return resolved

    def validate_command(self, command: str) -> None:
        """Check shell commands for write patterns. Raises WriteViolation if found."""
        for pattern in FORBIDDEN_WRITE_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                self._log_blocked_attempt("write_violation", command[:100])
                raise WriteViolation(
                    f"Destructive command pattern blocked: {pattern}"
                )

    def validate_tool_name(self, tool_name: str) -> None:
        """Only allow read-oriented tools. Raises ToolDenied otherwise."""
        if not any(tool_name.startswith(prefix) for prefix in ALLOWED_TOOL_PREFIXES):
            self._log_blocked_attempt("tool_denied", tool_name)
            raise ToolDenied(f"Tool {tool_name} not in allowed prefix list")

    def _log_blocked_attempt(self, reason: str, detail: str) -> None:
        """Append to spoliation-attempts.jsonl for the accuracy report."""
        import json
        from datetime import datetime, timezone
        entry = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "case_id": self.case_id,
            "reason": reason,
            "detail": detail,
            "blocked": True
        }
        with open(f"audit/spoliation-attempts.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")
        self._blocked_attempts += 1
        logger.warning(f"[GUARDRAIL BLOCKED] {reason}: {detail}")

    @property
    def blocked_count(self) -> int:
        return self._blocked_attempts
```

---

## Section 5: MCP gateway (`mcp/gateway.py`)

The gateway aggregates all MCP servers behind one interface and enforces constraints on every call.

```python
from mcp.server import Server
from mcp.server.stdio import stdio_server
from guardrails.constraints import ConstraintEnforcer, ScopeViolation, WriteViolation, ToolDenied
from mcp.servers.persistence_server import PersistenceServer
from mcp.servers.memory_server import MemoryServer
from mcp.servers.logs_server import LogsServer
from mcp.servers.network_server import NetworkServer
from audit.logger import AuditLogger
import asyncio

class MCPGateway:
    """
    Single point of trust enforcement. All agents go through here.
    The LLM layer cannot bypass this — it is not a prompt instruction.
    """
    def __init__(self, enforcer: ConstraintEnforcer, audit: AuditLogger):
        self.enforcer = enforcer
        self.audit = audit
        self.servers = {
            "persistence": PersistenceServer(enforcer),
            "memory": MemoryServer(enforcer),
            "logs": LogsServer(enforcer),
            "network": NetworkServer(enforcer),
        }

    async def call_tool(self, tool_name: str, params: dict, hypothesis: str, agent_name: str) -> dict:
        """
        Every tool call enters here. Validates, executes, logs.
        Returns structured result or raises with correction hint.
        """
        # 1. Validate tool is allowed
        self.enforcer.validate_tool_name(tool_name)

        # 2. Validate any path params
        for key in ["path", "evidence_path", "log_path", "memory_path", "pcap_path"]:
            if key in params:
                params[key] = str(self.enforcer.validate_path(params[key]))

        # 3. Find server
        server_name = tool_name.split("_")[0]  # e.g. "persistence" from "persistence_check_cron"
        server = self.servers.get(server_name)
        if not server:
            raise ToolDenied(f"No server registered for tool prefix: {server_name}")

        # 4. Execute with timing
        import time, hashlib
        start = time.time()
        result = await server.execute(tool_name, params)
        duration_ms = int((time.time() - start) * 1000)

        # 5. Audit log
        tc = self.audit.record_tool_call(
            tool_name=tool_name,
            params=params,
            hypothesis=hypothesis,
            result=result,
            agent_name=agent_name,
            duration_ms=duration_ms
        )
        result["tool_call_id"] = tc.tool_call_id
        return result
```

---

## Section 6: Self-correction engine (`agents/base.py`)

Every agent inherits from this. The correction logic lives here once, not duplicated.

```python
from typing import Optional, Callable, Any
from models.schemas import ToolCall, ConfidenceLevel
from audit.logger import AuditLogger
import asyncio, logging

logger = logging.getLogger(__name__)

class BaseAgent:
    def __init__(self, gateway, audit: AuditLogger, obsidian, case_id: str):
        self.gateway = gateway
        self.audit = audit
        self.obsidian = obsidian
        self.case_id = case_id
        self.findings = []
        self.correction_log = []

    async def execute_with_correction(
        self,
        tool_name: str,
        params: dict,
        hypothesis: str,
        max_retries: int = 3
    ) -> dict:
        """
        Wraps every tool call. Self-corrects on:
        - Hard errors (wrong path, tool crash) → adapt params and retry
        - Empty results where output expected → flag and continue
        - Contradictions with prior findings → reconcile via Claude
        - Low confidence → flag for human review
        """
        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                result = await self.gateway.call_tool(
                    tool_name, params, hypothesis, self.__class__.__name__
                )

                # Check: empty where we expected output
                if result.get("empty") and result.get("expected_output", True):
                    self._write_correction(
                        tool_name, attempt,
                        f"Empty result — artifact may be absent or path incorrect",
                        "flagged"
                    )
                    result["confidence"] = ConfidenceLevel.LOW
                    result["hallucination_risk"] = "moderate"
                    return result

                # Check: contradicts prior findings
                contradiction = self._check_contradiction(result)
                if contradiction:
                    resolution = await self._reconcile(result, contradiction)
                    self._write_correction(
                        tool_name, attempt,
                        f"Contradiction with {contradiction['finding_id']}: {contradiction['summary']}",
                        "reconciled"
                    )
                    return resolution

                # Check: low confidence
                if result.get("confidence_score", 1.0) < 0.6:
                    result["confidence"] = ConfidenceLevel.LOW
                    result["hallucination_risk"] = "moderate"
                    result["requires_human_review"] = True

                return result

            except Exception as e:
                last_error = e
                adjusted = self._adjust_params(tool_name, params, str(e))
                if adjusted:
                    params = adjusted
                    self._write_correction(
                        tool_name, attempt,
                        f"Error: {str(e)[:200]} → retrying with adjusted params",
                        "retried"
                    )
                    continue
                else:
                    break

        self._write_correction(
            tool_name, max_retries,
            f"Failed after {max_retries} attempts: {str(last_error)[:200]}",
            "failed"
        )
        return {"error": str(last_error), "confidence": ConfidenceLevel.UNVERIFIED, "tool_call_id": None}

    def _adjust_params(self, tool_name: str, params: dict, error: str) -> Optional[dict]:
        """Override in subclasses for tool-specific retry logic."""
        # Generic: try alternate mount points if path not found
        if "No such file" in error and "path" in params:
            alternates = ["/mnt/evidence", "/data/evidence", "/cases/evidence"]
            for alt in alternates:
                candidate = alt + "/" + params["path"].split("/")[-1]
                import os
                if os.path.exists(candidate):
                    return {**params, "path": candidate}
        return None

    def _check_contradiction(self, result: dict) -> Optional[dict]:
        """Check result against growing findings ledger."""
        # Implement per subclass — base returns None (no contradiction detected)
        return None

    async def _reconcile(self, result: dict, contradiction: dict) -> dict:
        """Ask Claude to reason about contradiction."""
        # Call Claude with both the new result and the contradicting finding
        # Return the resolution
        return result  # placeholder — implement with Claude API call

    def _write_correction(self, tool_name: str, attempt: int, reason: str, status: str):
        """Append to Corrections/self-learning-log.md and correction_log."""
        from datetime import datetime, timezone
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool_name,
            "attempt": attempt,
            "reason": reason,
            "status": status,
        }
        self.correction_log.append(entry)
        # Also write to Obsidian
        line = f"\n**{entry['timestamp']}** | `{tool_name}` attempt {attempt}: {reason} → _{status}_\n"
        self.obsidian.append("Corrections/self-learning-log.md", line)

    def read_corrections_from_previous_iteration(self) -> str:
        """Read back prior corrections before starting analysis — closes the learning loop."""
        try:
            return self.obsidian.read("Corrections/self-learning-log.md")
        except Exception:
            return ""
```

---

## Section 7: Source agent tool implementations

### `mcp/servers/persistence_server.py` — implement these tools

```python
# Each tool must:
# 1. Accept validated path from gateway
# 2. Run SIFT/system tool via subprocess (read-only flags only)
# 3. Return structured Pydantic-validated result
# 4. Never write to evidence, never use shell redirection

PERSISTENCE_TOOLS = [
    "persistence_check_cron",        # parse /etc/cron*, /var/spool/cron/crontabs/
    "persistence_check_systemd",     # enumerate /etc/systemd/system/, /lib/systemd/system/
    "persistence_check_ssh_keys",    # find authorized_keys, check for unknown pubkeys
    "persistence_check_setuid",      # find / -perm /6000 -type f (read-only)
    "persistence_parse_bash_history",# extract + score for suspicious commands
    "persistence_parse_wtmp",        # login timeline from wtmp/utmp
    "persistence_check_rc_files",    # /etc/rc.local, /etc/init.d/, profile.d/
    "persistence_check_ld_preload",  # LD_PRELOAD in environment files
    "persistence_diff_passwd",       # compare /etc/passwd to known baseline
]
```

### `mcp/servers/memory_server.py` — Volatility3 wrappers

```python
MEMORY_TOOLS = [
    "memory_vol_pslist",             # linux.pslist — process list
    "memory_vol_malfind",            # linux.malfind — injected code regions
    "memory_vol_netstat",            # linux.netstat — network connections
    "memory_vol_bash",               # linux.bash — recover bash history from memory
    "memory_vol_check_modules",      # linux.check_modules — unsigned/unknown kernel modules
    "memory_vol_lsmod",              # linux.lsmod — loaded modules
    "memory_vol_pstree",             # linux.pstree — process tree (spot orphans)
    "memory_vol_cmdline",            # linux.cmdline — full command lines
]

# Profile auto-detection sequence:
# 1. Try volatility3 auto-detect
# 2. If fails, extract kernel version from memory strings
# 3. Match to known profile list
# 4. If still fails, flag for human and continue with other tools
```

### `mcp/servers/logs_server.py`

```python
LOGS_TOOLS = [
    "logs_parse_auth",               # auth.log: SSH, sudo, su events
    "logs_parse_auditd",             # auditd: execve, file access, privilege events
    "logs_parse_syslog",             # syslog: daemon events, cron execution
    "logs_parse_lastb",              # /var/log/btmp: brute force detection
    "logs_build_timeline",           # log2timeline/plaso: unified event timeline
    "logs_find_gaps",                # detect log truncation / coverage gaps
    "logs_parse_apache",             # access.log, error.log if present
    "logs_correlate_events",         # cross-reference events by timestamp window
]
```

### `mcp/servers/network_server.py` — NEW

```python
NETWORK_TOOLS = [
    "network_tshark_summary",        # tshark -r pcap -q -z io,stat,0
    "network_detect_c2_beaconing",   # regularity analysis on connection intervals
    "network_extract_dns",           # tshark: extract all DNS queries + responses
    "network_detect_exfil",          # large outbound transfers, unusual destinations
    "network_extract_http",          # HTTP requests: user-agents, hosts, URIs
    "network_extract_credentials",   # cleartext auth attempts in pcap
    "network_geoip_ips",             # resolve external IPs to ASN/country
    "network_find_tor_exits",        # match IPs against known Tor exit node list
]

# Implementation note: tshark must be run with -r (read) flag only.
# Never use -i (live capture) — evidence scope is file-based.
# All tshark calls: tshark -r {pcap_path} [filter flags] -T json | head -n 5000
```

---

## Section 8: Obsidian integration (`mcp/obsidian_server.py`)

```python
import httpx
import os

class ObsidianServer:
    def __init__(self):
        self.base = os.getenv("OBSIDIAN_HOST", "http://localhost:27123")
        self.key = os.getenv("OBSIDIAN_API_KEY", "")
        self.headers = {"Authorization": f"Bearer {self.key}", "Content-Type": "text/markdown"}
        self.enabled = bool(self.key)

    def write(self, vault_path: str, content: str) -> bool:
        if not self.enabled:
            return self._write_local_fallback(vault_path, content)
        r = httpx.put(f"{self.base}/vault/{vault_path}", content=content.encode(), headers=self.headers)
        return r.status_code in (200, 204)

    def append(self, vault_path: str, content: str) -> bool:
        existing = self.read(vault_path) or ""
        return self.write(vault_path, existing + content)

    def read(self, vault_path: str) -> str:
        if not self.enabled:
            return self._read_local_fallback(vault_path)
        r = httpx.get(f"{self.base}/vault/{vault_path}", headers=self.headers)
        return r.text if r.status_code == 200 else ""

    def _write_local_fallback(self, vault_path: str, content: str) -> bool:
        """If Obsidian not running, write to vault/cases/{case_id}/ directly."""
        from pathlib import Path
        path = Path(f"vault/cases/{vault_path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return True

    def _read_local_fallback(self, vault_path: str) -> str:
        from pathlib import Path
        path = Path(f"vault/cases/{vault_path}")
        return path.read_text() if path.exists() else ""
```

**Required Obsidian notes to create per case:**

| Path | Written by | When |
|---|---|---|
| `Evidence/case-state.md` | Orchestrator | Case creation, updated each phase |
| `Evidence/due-diligence-{source}.md` | Orchestrator | After triage, before agent approval |
| `Analysis/analysis-{source}.md` | Source agents | After source analysis complete |
| `Analysis/analysis-polished.md` | IR Expert | After threat intel enrichment |
| `Persona/attacker-profile.md` | Persona builder | After expert pass |
| `Persona/timeline.md` | Persona builder | Narrative chronological timeline |
| `Persona/narrative.md` | Persona builder | Story for executive audience |
| `Report/final-report.md` | Reporter | Final output |
| `Report/compromise-answers.md` | Reporter | Answers to 12 mandatory IR questions |
| `Report/ioc-ttp.md` | Reporter | All IOCs and MITRE mappings |
| `Report/recommendations.md` | Reporter | Recovery and hardening steps |
| `Corrections/self-learning-log.md` | All agents | Append-only, human editable |
| `Corrections/reasoning-trace.md` | All agents | hypothesis → outcome per tool call |
| `Corrections/human-notes.md` | Analyst | Human-only, never overwritten by agents |

---

## Section 9: Orchestrator (`agents/orchestrator.py`)

```python
async def run_investigation(case: CaseState, max_iterations: int = 10):
    """
    Main investigation loop. Reads prior corrections before each iteration.
    Dispatches parallel source agents. Coordinates expert pass. Builds report.
    """
    obsidian = ObsidianServer()
    enforcer = ConstraintEnforcer(evidence_scope=Path(case.sources[0]["path"]).parent, case_id=case.case_id)
    gateway = MCPGateway(enforcer, audit_logger)
    
    for iteration in range(1, max_iterations + 1):
        case.iteration = iteration
        
        # READ prior corrections before starting — closes the learning loop
        prior_corrections = obsidian.read("Corrections/self-learning-log.md")
        
        # TRIAGE — detect source types, generate due-diligence plans
        if iteration == 1:
            plans = await generate_due_diligence_plans(case, prior_corrections)
            for source, plan in plans.items():
                obsidian.write(f"Evidence/due-diligence-{source}.md", plan)
            
            # UPDATE GUI — wait for analyst approval before proceeding
            await wait_for_analyst_approval(case.case_id)
        
        # PARALLEL SOURCE ANALYSIS
        agent_queue = asyncio.Queue()
        tasks = [
            run_source_agent(source, case, gateway, agent_queue, obsidian)
            for source in case.sources
        ]
        await asyncio.gather(*tasks)
        
        # LOG all inter-agent messages from queue
        while not agent_queue.empty():
            msg = await agent_queue.get()
            audit_logger.record_agent_message(msg)
        
        # AUDITOR PASS
        auditor = AuditorAgent(gateway, audit_logger, obsidian, case.case_id)
        audit_result = await auditor.verify_all_findings(case.case_id)
        
        # EXPERT PASS
        expert = LinuxIRExpertAgent(gateway, audit_logger, obsidian, case.case_id)
        expert_findings = await expert.enrich(case, audit_result)
        
        # Check if expert wants re-analysis
        if expert_findings.requests_reanalysis and iteration < max_iterations:
            obsidian.append(
                "Corrections/self-learning-log.md",
                f"\n## Iteration {iteration} — expert requests re-analysis\n{expert_findings.reanalysis_reason}\n"
            )
            continue  # loop back with new context
        
        # If we get here, analysis is stable — proceed to output
        break
    
    else:
        # Hit max_iterations — write partial report
        obsidian.append("Corrections/self-learning-log.md",
            f"\n## MAX ITERATIONS REACHED ({max_iterations})\nPartial report generated.\n")
    
    # PERSONA + REPORT
    persona = PersonaBuilderAgent(gateway, audit_logger, obsidian, case.case_id)
    await persona.build(case)
    
    reporter = ReporterAgent(gateway, audit_logger, obsidian, case.case_id)
    await reporter.generate(case)
    
    # Update GUI with completion
    await update_case_state(case.case_id, "complete")
```

---

## Section 10: Reporter agent — mandatory IR questions

The reporter must answer all 12 of these in `Report/compromise-answers.md`:

```python
MANDATORY_IR_QUESTIONS = [
    ("compromised", "Is this device compromised? (Yes/No + confidence level)"),
    ("when_compromised", "When was the device believed to be compromised?"),
    ("compromised_accounts", "Which accounts are suspected of being compromised?"),
    ("how_compromised", "How was the device compromised and where did the attack originate?"),
    ("pivot_needed", "Do we need to investigate any other devices on the network?"),
    ("privilege_escalation", "Did the attacker elevate privileges? If so, how?"),
    ("persistence_established", "Has the attacker established persistence?"),
    ("attacker_actions", "What did the attackers do in the environment?"),
    ("significant_behaviors", "Is there any significant behavior we need to know about?"),
    ("data_exfiltrated", "Has any data been exfiltrated?"),
    ("malware_used", "What, if any, malware did the attacker use?"),
    ("ioc_ioa_ttp", "What IOC/IOA/TTP can you recover from this intrusion?"),
]

# Each answer must:
# - Start with a direct yes/no or concrete statement (no hedging in the opening)
# - Follow with supporting evidence using [[wiki links]] to Analysis/ notes
# - Include confidence level (HIGH/MEDIUM/LOW)
# - List specific artifacts that support the answer
```

---

## Section 11: Analyst training mode

Add this to the GUI as a toggle. When enabled, every tool call in `Corrections/reasoning-trace.md` also writes:

```markdown
## Tool: persistence_check_cron | 2026-06-10 14:23:11 UTC

**Why this tool:** Cron is one of the most common Linux persistence mechanisms.
Attackers frequently add entries to /etc/cron.d/ or /var/spool/cron/crontabs/
to maintain access after a reboot.

**What I expected to find:** Legitimate system cron jobs. I'm looking for any
entries that:
- Reference unusual paths (not /usr/bin, /bin, /usr/sbin)
- Execute scripts from /tmp, /dev/shm, or world-writable directories
- Were created around the suspected breach date (March 2022)
- Have obfuscated commands (base64, wget|sh patterns)

**What I actually found:** 3 system cron entries (normal). 1 suspicious entry
in /var/spool/cron/crontabs/www-data executing /tmp/.s every 5 minutes.

**What this means:** The www-data user (Apache) has a cron job executing a
hidden binary from /tmp — a strong indicator of persistence via web shell
or compromised Apache process. Cross-reference with memory analysis.

**Confidence:** HIGH — direct artifact read, byte-level traceable
**MITRE:** T1053.003 — Scheduled Task/Job: Cron
```

This doubles as a junior analyst training corpus. Toggle via `?training=true` query param.

---

## Section 12: README template

```markdown
# LinuxIR Agent

> Autonomous Linux incident response on SIFT Workstation.
> FIND EVIL! Hackathon submission · Built with Claude Code.

## What it does

LinuxIR Agent is a multi-agent IR platform that ingests Linux evidence
(disk images, memory captures, log files, network captures), autonomously
investigates them in parallel using SIFT Workstation tools via typed MCP
servers, self-corrects on failures, enriches findings with live threat
intelligence, and produces a complete investigative narrative in an Obsidian
vault — with every claim traceable to the specific artifact that produced it.

## Architecture

Multi-agent (Claude Code orchestrator + specialized sub-agents) + Custom MCP
Server with architectural guardrails. The LLM layer is untrusted; all
evidence protection is enforced at the MCP gateway layer in Python.

See docs/architecture.svg for the full component diagram with trust boundaries.

## Quick start

\`\`\`bash
git clone https://github.com/YOU/linuxir-agent
cd linuxir-agent
cp .env.template .env
# Edit .env: set ANTHROPIC_API_KEY and OBSIDIAN_API_KEY
bash install.sh
python3 -m app.server
# Open http://localhost:8080
\`\`\`

## Requirements

- SANS SIFT Workstation (Ubuntu 22.04)
- Python 3.10+
- Obsidian with Local REST API plugin (port 27123)
- ANTHROPIC_API_KEY

## Running against provided evidence

\`\`\`bash
# Download BOTSv3 or use provided starter data
# Mount disk image:
sudo mount -o ro,loop disk.img /mnt/evidence
# Point the GUI at /mnt/evidence and run
\`\`\`

## Self-correction demo

\`\`\`bash
python3 tests/test_self_correction.py
# Demonstrates 3 recovery sequences:
# 1. Volatility3 profile auto-detect failure → recovery
# 2. Empty cron result → fallback to at jobs
# 3. Cross-artifact contradiction → reconciliation
\`\`\`

## Spoliation test

\`\`\`bash
python3 guardrails/spoliation_test.py
# Attempts 10 write/delete operations against evidence scope
# All must be blocked. Results written to docs/accuracy-report.md
\`\`\`

## License

MIT — see LICENSE
```

---

## Section 13: Devpost written description (paste into submission form)

**What it does:**

LinuxIR Agent is a multi-agent Linux incident response platform that closes the gap between AI threat speed and defensive response time. An IR analyst opens a browser, provides plain-language case context and evidence paths, approves an AI-generated investigation plan, then watches as parallel specialized agents systematically investigate disk images, memory captures, log files, and network captures — correlating findings across evidence types, self-correcting on failures, enriching findings with live threat intelligence, and producing a complete investigative narrative in an Obsidian vault.

Every claim in the final report traces to a specific tool call in an append-only audit log. Every tool call records a hypothesis before execution and an outcome after — simultaneously creating an audit trail and a junior analyst training corpus. A human can open the Obsidian vault at any point, read the analysis in plain markdown, add their own notes, and watch new findings appear as the agents continue working.

**How we built it:**

Custom MCP Server + Multi-Agent framework on SIFT Workstation. The core architectural decision: the LLM layer is explicitly untrusted. Evidence protection is enforced in Python at the MCP gateway layer — not by asking the model to behave. The gateway validates every file path against the evidence scope, blocks every write/delete/modify pattern, and logs every blocked attempt to a spoliation audit log. We then deliberately ran our guardrail bypass test suite and documented every result.

Four typed MCP servers expose SIFT tools as structured functions (persistence, memory, logs, network). The orchestrator dispatches parallel source agents, an auditor re-runs tool calls to verify findings, a Linux IR expert enriches with threat intelligence and requests re-analysis when needed, a persona builder synthesizes the attacker profile and narrative timeline, and a reporter answers 12 mandatory IR questions with direct artifact citations.

The Corrections log is append-only and read back at the start of each iteration — closing the learning loop. A `--max-iterations` cap prevents runaway execution. All inter-agent communications are logged to `agent-messages.jsonl` with timestamps and token usage.

**Challenges:**

Keeping context windows clean across parallel agents required deliberately partitioning evidence by source — each agent holds only its own source's data, preventing cross-contamination and context degradation. The auditor re-execution approach (re-running the original tool call independently rather than re-reading the analysis) was the key to catching hallucinations reliably. Volatility3 profile auto-detection on diverse Linux kernels required a three-tier fallback strategy.

**What we learned:**

The hypothesis-before-execution pattern was the most valuable addition we didn't plan for. Requiring the agent to write what it expects to find before running a tool dramatically reduced hallucinated findings — the agent catches its own surprises during outcome comparison.

**What's next:**

SIEM integration via MCP (pull live Splunk/Elastic data into the investigation). Windows agent support. Multi-examiner collaboration via shared vault sync. Integration with OpenCTI for structured threat intelligence.

---

## Section 14: Submission checklist

Before submitting, verify every item:

- [ ] GitHub repo is public with MIT license visible in About section
- [ ] README has `install.sh` one-command setup + evidence testing instructions
- [ ] `audit/tool-calls.jsonl` schema matches `ToolCall` Pydantic model
- [ ] `audit/agent-messages.jsonl` has timestamps for every inter-agent message
- [ ] `guardrails/spoliation_test.py` runs and all 10 tests are blocked
- [ ] `tests/test_self_correction.py` shows all 3 recovery sequences
- [ ] Obsidian vault has all required notes populated from a test run
- [ ] `Report/compromise-answers.md` answers all 12 mandatory IR questions
- [ ] `docs/architecture.svg` shows trust boundaries with zone labels
- [ ] `docs/accuracy-report.md` includes spoliation test results section
- [ ] `docs/evidence-dataset.md` documents what was tested against + findings
- [ ] Demo video is < 5 minutes, shows terminal execution + self-correction + vault
- [ ] Devpost description follows What/How/Challenges/Learned/Next format
- [ ] Architecture diagram uploaded to Devpost separately
- [ ] Agent execution logs (`tool-calls.jsonl` + `agent-messages.jsonl`) linked in submission

---

## Section 15: Day-by-day build order

| Day | Date | What you build | Done when |
|---|---|---|---|
| **1** | Jun 7 | FastAPI server + GUI intake + Obsidian write works | Browser form → note appears in Obsidian |
| **2** | Jun 8 | ConstraintEnforcer + MCPGateway + persistence_server | Cron tool runs, scope violation blocked, logged |
| **3** | Jun 9 | memory_server (Volatility3) + logs_server | pslist + auth.log parsing working |
| **4** | Jun 10 | network_server (tshark) + BaseAgent self-correction | 3 correction sequences working |
| **5** | Jun 11 | Orchestrator loop + parallel dispatch + agent-messages.jsonl | Full triage → parallel run → Obsidian notes |
| **6** | Jun 12 | Auditor + Linux IR Expert + threat intel | Polished analysis + intel matches |
| **7** | Jun 13 | Persona builder + Reporter + all 12 IR answers | Full report in vault |
| **8** | Jun 14 | Spoliation tests + accuracy report + README + docs | All submission artifacts ready |
| **9** | Jun 15 | Record demo video + final submission | Submitted before 11:45pm EDT |

**Day 1 is the gate.** Get the browser form submitting a case and a note appearing in Obsidian. Everything else is additive.

**Day 2 is the differentiator.** The constraint enforcer working + logging blocked attempts is what separates this from every prompt-based submission.
