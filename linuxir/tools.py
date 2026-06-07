"""Tool registry — Anthropic tool schemas bound to gateway-dispatched handlers.

Every tool here is **read-only** with respect to evidence. Each handler receives the
validated input and the shared :class:`ToolContext` (evidence config + findings store +
audit logger). The ConstraintEnforcer has already vetted the call by the time a handler
runs; handlers never reach the filesystem except through the adapters, which only read.

The lone exception is ``record_finding`` — it writes to the *workspace* findings store
(not evidence), which is exactly the evidence/workspace split the enforcer permits.
``bash_readonly`` is the escape hatch: the enforcer restricts it to allowlisted read-only
binaries, and the handler runs it without a shell (``shlex`` + ``run_binary``), so there is
no shell-injection surface.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from .adapters import disk, geoip, memory, network
from .adapters.base import run_binary, summarize
from .findings import Confidence, Finding
from .gateway import ToolContext, ToolSpec

# Tool-name groupings each specialist agent is scoped to.
DISK_TOOLS = [
    "persistence_check_cron",
    "persistence_check_systemd",
    "check_authorized_keys",
    "persistence_parse_bash_history",
    "persistence_check_setuid",
    "persistence_check_rc_files",
    "persistence_check_ld_preload",
    "persistence_diff_passwd",
    "persistence_parse_wtmp",
    "read_evidence_file",
    "list_directory",
    "bash_readonly",
    "disk_partition_table",
    "disk_list_files",
    "disk_cat_inode",
    "record_finding",
]
LOG_TOOLS = ["read_evidence_file", "list_directory", "bash_readonly", "record_finding"]
MEMORY_TOOLS = [
    "memory_pslist",
    "memory_pstree",
    "memory_malfind",
    "memory_netstat",
    "record_finding",
]
NETWORK_TOOLS = [
    "pcap_summary",
    "pcap_conversations",
    "detect_beaconing",
    "geoip_lookup",
    "record_finding",
]


def _roots(ctx: ToolContext) -> list[Path]:
    return list(ctx.case.evidence_scope)


# -- handlers -----------------------------------------------------------------------


def _h_cron(_inp: dict, ctx: ToolContext) -> str:
    return disk.find_cron_persistence(_roots(ctx))


def _h_systemd(_inp: dict, ctx: ToolContext) -> str:
    return disk.find_systemd_persistence(_roots(ctx))


def _h_authkeys(_inp: dict, ctx: ToolContext) -> str:
    return disk.find_authorized_keys(_roots(ctx))


def _h_bash_history(_inp: dict, ctx: ToolContext) -> str:
    return disk.parse_bash_history(_roots(ctx))


def _h_setuid(_inp: dict, ctx: ToolContext) -> str:
    return disk.find_setuid_binaries(_roots(ctx))


def _h_rc_files(_inp: dict, ctx: ToolContext) -> str:
    return disk.find_rc_persistence(_roots(ctx))


def _h_ld_preload(_inp: dict, ctx: ToolContext) -> str:
    return disk.find_ld_preload(_roots(ctx))


def _h_diff_passwd(_inp: dict, ctx: ToolContext) -> str:
    return disk.diff_passwd(_roots(ctx))


def _h_wtmp(_inp: dict, ctx: ToolContext) -> str:
    return disk.parse_wtmp(_roots(ctx))


def _h_read(inp: dict, _ctx: ToolContext) -> str:
    return disk.read_text_file(Path(inp["path"]))


def _h_list(inp: dict, _ctx: ToolContext) -> str:
    return disk.list_dir(Path(inp["path"]))


def _h_bash(inp: dict, _ctx: ToolContext) -> str:
    # Enforcer has validated: allowlisted binary, no redirects, in-scope paths.
    # Run without a shell to avoid any injection surface.
    return summarize(run_binary(shlex.split(inp["command"])))


def _h_disk_mmls(inp: dict, _ctx: ToolContext) -> str:
    return disk.disk_partition_table(inp["image"])


def _h_disk_fls(inp: dict, _ctx: ToolContext) -> str:
    return disk.disk_list_files(inp["image"], inp.get("inode"), inp.get("offset"))


def _h_disk_icat(inp: dict, _ctx: ToolContext) -> str:
    return disk.disk_cat_inode(inp["image"], inp["inode"], inp.get("offset"))


def _h_vol(plugin_fn):
    def handler(inp: dict, _ctx: ToolContext) -> str:
        return plugin_fn(inp["memory_image"], inp.get("extra"))

    return handler


def _h_pcap_summary(inp: dict, _ctx: ToolContext) -> str:
    return network.pcap_summary(inp["pcap"])


def _h_pcap_conv(inp: dict, _ctx: ToolContext) -> str:
    return network.pcap_conversations(inp["pcap"])


def _h_beaconing(inp: dict, _ctx: ToolContext) -> str:
    return network.detect_beaconing(inp["pcap"], inp.get("dest_ip"))


def _h_geoip(inp: dict, _ctx: ToolContext) -> str:
    return geoip.geoip_lookup(inp["ip"])


def _h_record_finding(inp: dict, ctx: ToolContext) -> str:
    finding = Finding(
        id=inp["id"],
        title=inp["title"],
        description=inp["description"],
        technique=inp.get("technique"),
        confidence=Confidence(inp.get("confidence", "UNVERIFIED")),
        evidence_refs=list(inp.get("evidence_refs", [])),
        source_tool_output=inp.get("source_tool_output", ""),
    )
    ctx.findings.append(finding)
    ctx.audit.log_finding(finding=finding.model_dump())
    return f"Recorded finding '{finding.id}' ({finding.confidence}). Total findings: {len(ctx.findings)}."


# -- schemas ------------------------------------------------------------------------

_NO_ARGS = {"type": "object", "properties": {}, "additionalProperties": False}
_PATH = {
    "type": "object",
    "properties": {"path": {"type": "string", "description": "Absolute path inside evidence scope."}},
    "required": ["path"],
    "additionalProperties": False,
}
_CONFIDENCE_ENUM = [c.value for c in Confidence]

_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "description": "Stable slug, e.g. 'cron-persistence-backdoor'."},
        "title": {"type": "string"},
        "description": {"type": "string"},
        "technique": {"type": "string", "description": "MITRE ATT&CK id or technique name."},
        "confidence": {"type": "string", "enum": _CONFIDENCE_ENUM},
        "evidence_refs": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Evidence paths / line refs that support this finding.",
        },
        "source_tool_output": {
            "type": "string",
            "description": "Verbatim tool output the claim rests on. The auditor verifies "
            "the claim against THIS text — include the exact lines you relied on.",
        },
    },
    "required": ["id", "title", "description", "confidence", "source_tool_output"],
    "additionalProperties": False,
}


def build_tools() -> list[ToolSpec]:
    """Construct every read-only tool spec (disk + log + memory + network + record)."""
    return [
        # -- disk / filesystem ---------------------------------------------------
        ToolSpec("persistence_check_cron",
                 "Scan all cron locations (crontab, cron.d, spool) in evidence for "
                 "persistence; suspicious tokens (curl|bash, /tmp, base64) are flagged.",
                 _NO_ARGS, _h_cron),
        ToolSpec("persistence_check_systemd",
                 "Scan systemd unit/timer locations in evidence and list Exec* lines, "
                 "flagging units that launch from /tmp or /dev/shm.",
                 _NO_ARGS, _h_systemd),
        ToolSpec("check_authorized_keys",
                 "List every SSH authorized_keys file under evidence (root + each home).",
                 _NO_ARGS, _h_authkeys),
        ToolSpec("persistence_parse_bash_history",
                 "Read every shell-history file under evidence and score each command for "
                 "attacker behavior (download|sh, /tmp exec, persistence writes, exfil, "
                 "anti-forensics like `history -c`). Flagged lines are annotated with why.",
                 _NO_ARGS, _h_bash_history),
        ToolSpec("persistence_check_setuid",
                 "Walk evidence for setuid/setgid files, flagging setuid shells/interpreters "
                 "and binaries in world-writable locations (/tmp, /dev/shm, /home).",
                 _NO_ARGS, _h_setuid),
        ToolSpec("persistence_check_rc_files",
                 "Scan rc.local, /etc/init.d, /etc/profile.d, and per-user shell rc files "
                 "for run-at-boot / run-at-login persistence; flags suspicious tokens.",
                 _NO_ARGS, _h_rc_files),
        ToolSpec("persistence_check_ld_preload",
                 "Surface /etc/ld.so.preload and any LD_PRELOAD set in environment/profile "
                 "files — a library-injection persistence and hooking technique.",
                 _NO_ARGS, _h_ld_preload),
        ToolSpec("persistence_diff_passwd",
                 "Parse /etc/passwd and flag UID-0 accounts other than root and non-baseline "
                 "accounts with login shells (added backdoor users).",
                 _NO_ARGS, _h_diff_passwd),
        ToolSpec("persistence_parse_wtmp",
                 "Decode wtmp/btmp/utmp login records via `last`/`utmpdump` (graceful "
                 "fallback when the binary or files are absent).",
                 _NO_ARGS, _h_wtmp),
        ToolSpec("read_evidence_file",
                 "Read a text file at an absolute path inside evidence scope.",
                 _PATH, _h_read, path_params=("path",)),
        ToolSpec("list_directory",
                 "List a directory inside evidence scope (mode, size, name).",
                 _PATH, _h_list, path_params=("path",)),
        ToolSpec("bash_readonly",
                 "Run a single read-only shell command (allowlisted binaries only: cat, "
                 "grep, strings, find, awk, sed, stat, sleuthkit, ... ). Redirects and "
                 "destructive tools are rejected by the guardrail. Paths must be in scope.",
                 {"type": "object",
                  "properties": {"command": {"type": "string"}},
                  "required": ["command"], "additionalProperties": False},
                 _h_bash, command_params=("command",)),
        ToolSpec("disk_partition_table",
                 "Run sleuthkit mmls on a raw disk image to list partitions.",
                 {"type": "object", "properties": {"image": {"type": "string"}},
                  "required": ["image"], "additionalProperties": False},
                 _h_disk_mmls, path_params=("image",)),
        ToolSpec("disk_list_files",
                 "Run sleuthkit fls -r on a raw disk image (optionally at an offset/inode).",
                 {"type": "object",
                  "properties": {"image": {"type": "string"}, "offset": {"type": "string"},
                                 "inode": {"type": "string"}},
                  "required": ["image"], "additionalProperties": False},
                 _h_disk_fls, path_params=("image",)),
        ToolSpec("disk_cat_inode",
                 "Run sleuthkit icat to read an inode's content from a raw disk image.",
                 {"type": "object",
                  "properties": {"image": {"type": "string"}, "inode": {"type": "string"},
                                 "offset": {"type": "string"}},
                  "required": ["image", "inode"], "additionalProperties": False},
                 _h_disk_icat, path_params=("image",)),
        # -- memory (volatility3, graceful fallback) -----------------------------
        ToolSpec("memory_pslist", "volatility3 linux.pslist on a memory image.",
                 _mem_schema(), _h_vol(memory.pslist), path_params=("memory_image",),
                 arg_params=("extra",)),
        ToolSpec("memory_pstree", "volatility3 linux.pstree on a memory image.",
                 _mem_schema(), _h_vol(memory.pstree), path_params=("memory_image",),
                 arg_params=("extra",)),
        ToolSpec("memory_malfind", "volatility3 linux.malfind (injected code) on a memory image.",
                 _mem_schema(), _h_vol(memory.malfind), path_params=("memory_image",),
                 arg_params=("extra",)),
        ToolSpec("memory_netstat", "volatility3 linux.sockstat (network sockets) on a memory image.",
                 _mem_schema(), _h_vol(memory.netstat), path_params=("memory_image",),
                 arg_params=("extra",)),
        # -- network (tshark, graceful fallback) ---------------------------------
        ToolSpec("pcap_summary", "tshark protocol hierarchy for a pcap.",
                 _pcap_schema(), _h_pcap_summary, path_params=("pcap",)),
        ToolSpec("pcap_conversations", "tshark IP conversation list for a pcap.",
                 _pcap_schema(), _h_pcap_conv, path_params=("pcap",)),
        ToolSpec("detect_beaconing",
                 "Emit per-packet frame times (optionally filtered to a destination IP) "
                 "so regular C2 beaconing intervals stand out.",
                 {"type": "object",
                  "properties": {"pcap": {"type": "string"}, "dest_ip": {"type": "string"}},
                  "required": ["pcap"], "additionalProperties": False},
                 _h_beaconing, path_params=("pcap",)),
        ToolSpec("geoip_lookup",
                 "Geolocate an IP via the local geoiplookup DB. Returns only what the DB "
                 "says — do NOT infer a country without data.",
                 {"type": "object", "properties": {"ip": {"type": "string"}},
                  "required": ["ip"], "additionalProperties": False},
                 _h_geoip),
        # -- finding capture (workspace write, permitted) ------------------------
        ToolSpec("record_finding",
                 "Record an investigative finding. MUST cite the verbatim tool output in "
                 "source_tool_output — the auditor verifies the claim against it.",
                 _FINDING_SCHEMA, _h_record_finding),
    ]


def _mem_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "memory_image": {"type": "string", "description": "Path to memory image in scope."},
            "extra": {"type": "array", "items": {"type": "string"},
                      "description": "Extra vol args, e.g. ['--os-name','linux']."},
        },
        "required": ["memory_image"],
        "additionalProperties": False,
    }


def _pcap_schema() -> dict:
    return {
        "type": "object",
        "properties": {"pcap": {"type": "string", "description": "Path to pcap in scope."}},
        "required": ["pcap"],
        "additionalProperties": False,
    }
