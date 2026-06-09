"""Offline demo responder — drives the agents through the fixture scenario, zero API spend.

This is a deterministic :class:`~linuxir.llm.FakeClient` responder that scripts realistic
multi-turn behavior for the disk, log, and auditor roles against the bundled evidence
fixture. It is used by ``linuxir analyze --offline`` and by the pipeline test.

It deliberately makes the **log agent record one unsupported finding** ("Metasploit
meterpreter") whose cited evidence does not mention meterpreter — so the auditor pass has
something real to catch and drop, demonstrating the anti-hallucination backstop end-to-end.
Findings cite the *actual* tool output the agent saw (read back from the message history),
so the grounding is genuine, not faked.
"""

from __future__ import annotations

import re
from typing import Any

from .llm import FakeMessage, text, tool_call

_ABS_PATH = re.compile(r"(/[^\s,]+)")


def _turn(messages: list[dict]) -> int:
    """How many assistant turns have already happened (0 on the first call)."""
    return sum(1 for m in messages if m.get("role") == "assistant")


def _evidence_root(messages: list[dict]) -> str:
    task = messages[0]["content"]
    if isinstance(task, list):  # defensive
        task = " ".join(str(c) for c in task)
    m = _ABS_PATH.search(task)
    return m.group(1).rstrip(".") if m else "/mnt/evidence"


def _tool_records(messages: list[dict]) -> list[tuple[str, dict, str]]:
    """Reconstruct (tool_name, input, output) triples from prior turns."""
    id_to_call: dict[str, tuple[str, dict]] = {}
    for m in messages:
        if m.get("role") == "assistant" and isinstance(m.get("content"), list):
            for b in m["content"]:
                if getattr(b, "type", None) == "tool_use":
                    id_to_call[b.id] = (b.name, dict(b.input))
    records: list[tuple[str, dict, str]] = []
    for m in messages:
        if m.get("role") == "user" and isinstance(m.get("content"), list):
            for b in m["content"]:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    name, inp = id_to_call.get(b["tool_use_id"], ("?", {}))
                    records.append((name, inp, str(b.get("content", ""))))
    return records


def _output_containing(records: list[tuple[str, dict, str]], needle: str) -> str:
    for _name, _inp, out in records:
        if needle in out:
            return out
    return ""


def _output_for(records: list[tuple[str, dict, str]], tool: str) -> str:
    for name, _inp, out in records:
        if name == tool:
            return out
    return ""


def demo_responder(kwargs: dict[str, Any]) -> FakeMessage:
    system = kwargs.get("system", "")
    messages = kwargs.get("messages", [])

    # -- IR-expert role (senior review narrative) ---------------------------------
    if "senior Linux incident-response expert" in system:
        return text(
            "Initial access was via SSH using valid credentials from a single attacker IP, "
            "after which the actor escalated to root and established cron persistence and an "
            "unauthorized authorized_keys entry. They staged tooling in world-writable "
            "directories, archived sensitive data, and exfiltrated it off-host before "
            "clearing shell history to frustrate analysis. The activity is a coherent, "
            "single-operator intrusion with persistence and data theft; confidence is high "
            "where on-disk artifacts and logs corroborate the same indicators."
        )

    # -- auditor role -------------------------------------------------------------
    if "finding auditor" in system:
        prompt = messages[-1]["content"]
        low = prompt.lower()
        unsupported = (
            "meterpreter" in low or "metasploit" in low or "moscow" in low
            or "russia" in low or "TOOL OUTPUT CITED:\n```\n\n```" in prompt
        )
        if unsupported:
            return text(
                '{"supported": false, "hallucination_risk": "high", '
                '"suggested_confidence": "UNVERIFIED", '
                '"note": "Cited tool output does not contain the asserted indicator."}'
            )
        return text(
            '{"supported": true, "hallucination_risk": "none", '
            '"suggested_confidence": "HIGH", "note": "Claim matches cited tool output."}'
        )

    root = _evidence_root(messages)
    turn = _turn(messages)
    records = _tool_records(messages)

    # -- disk role ----------------------------------------------------------------
    if "host-based persistence" in system:
        if turn == 0:
            return tool_call(
                ("d1", "persistence_check_cron", {}),
                ("d2", "persistence_check_systemd", {}),
                ("d3", "check_authorized_keys", {}),
            )
        if turn == 1:
            cron = _output_for(records, "persistence_check_cron")
            systemd = _output_for(records, "persistence_check_systemd")
            keys = _output_for(records, "check_authorized_keys")
            return tool_call(
                ("d4", "record_finding", {
                    "id": "cron-persistence-backdoor",
                    "title": "Cron persistence: C2 beacon installed as 'apache-monitor'",
                    "description": "An /etc/cron.d entry runs `curl … | bash` every minute "
                                   "from 185.220.101.47 — a per-minute C2 beacon masquerading "
                                   "as an apache monitor.",
                    "technique": "T1053.003 (Cron)",
                    "confidence": "HIGH",
                    "evidence_refs": [f"{root}/etc/cron.d/apache-monitor"],
                    "source_tool_output": cron,
                }),
                ("d5", "record_finding", {
                    "id": "ssh-authorized-key-backdoor",
                    "title": "Unauthorized SSH key added to /root/.ssh/authorized_keys",
                    "description": "An attacker ed25519 key grants persistent root SSH access.",
                    "technique": "T1098.004 (SSH authorized_keys)",
                    "confidence": "HIGH",
                    "evidence_refs": [f"{root}/root/.ssh/authorized_keys"],
                    "source_tool_output": keys,
                }),
                ("d6", "record_finding", {
                    "id": "systemd-dbus-update-suspect",
                    "title": "systemd unit dbus-update.service launches from /dev/shm",
                    "description": "A .service unit's ExecStart references /dev/shm and /tmp "
                                   "paths. Suspicious, but the referenced binaries are not "
                                   "present in this evidence — weakly supported.",
                    "technique": "T1543.002 (systemd service)",
                    "confidence": "LOW",
                    "evidence_refs": [f"{root}/etc/systemd/system/dbus-update.service"],
                    "source_tool_output": systemd,
                }),
            )
        return text("Disk analysis complete: cron C2 beacon, attacker SSH key, and a "
                    "low-confidence systemd unit recorded.")

    # -- log role -----------------------------------------------------------------
    if "intrusion timeline" in system:
        if turn == 0:
            return tool_call(
                ("l1", "read_evidence_file", {"path": f"{root}/var/log/auth.log"}),
                ("l2", "read_evidence_file", {"path": f"{root}/home/victim/.bash_history"}),
            )
        if turn == 1:
            authlog = _output_containing(records, "Accepted password")
            history = _output_containing(records, "scp ")
            return tool_call(
                ("l3", "record_finding", {
                    "id": "ssh-bruteforce-initial-access",
                    "title": "SSH brute force from 185.220.101.47 then successful login",
                    "description": "Multiple failed SSH passwords from 185.220.101.47 are "
                                   "followed by an Accepted password for 'victim' — initial "
                                   "access, then sudo to root.",
                    "technique": "T1110 (Brute Force) / T1078 (Valid Accounts)",
                    "confidence": "HIGH",
                    "evidence_refs": [f"{root}/var/log/auth.log"],
                    "source_tool_output": authlog,
                }),
                ("l4", "record_finding", {
                    "id": "data-exfiltration-scp",
                    "title": "Data archived and exfiltrated via SCP to 185.220.101.47",
                    "description": "bash_history shows `tar czf /tmp/loot.tgz …` of "
                                   "/etc/passwd, /etc/shadow and Documents, then `scp` of the "
                                   "archive to exfil@185.220.101.47, then `history -c`.",
                    "technique": "T1048 (Exfiltration Over Alternative Protocol)",
                    "confidence": "HIGH",
                    "evidence_refs": [f"{root}/home/victim/.bash_history"],
                    "source_tool_output": history,
                }),
                # Planted hallucination — cited output does NOT mention meterpreter.
                ("l5", "record_finding", {
                    "id": "meterpreter-implant",
                    "title": "Attacker deployed a Metasploit meterpreter implant",
                    "description": "The intrusion used a Metasploit meterpreter payload for "
                                   "C2 (asserted without supporting evidence).",
                    "technique": "T1059",
                    "confidence": "MEDIUM",
                    "evidence_refs": [f"{root}/var/log/auth.log"],
                    "source_tool_output": authlog,
                }),
            )
        return text("Log analysis complete: brute-force initial access and SCP exfiltration "
                    "recorded; a meterpreter claim was made for the auditor to test.")

    # Fallback (unknown role): finish immediately.
    return text("No action.")
