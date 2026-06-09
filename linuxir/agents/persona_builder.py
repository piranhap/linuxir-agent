"""Persona builder — attacker profile, chronological timeline, executive narrative.

Deterministic synthesis over the confirmed findings + IR-expert output. The timeline scrapes
timestamps from the verbatim tool output each finding cites (so the chronology is grounded in
evidence, not invented) and normalizes them to a comparable (month, day, time) key — good for
a single-case sequence; precise times remain in the cited output. The narrative reuses the
expert's LLM-written executive summary where available.
"""

from __future__ import annotations

import datetime as _dt
import re

from ..findings import Finding
from .reporter import _TS, categorize

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_SENTINEL = (99, 99, 99, 99, 99)


def _normalize(syslog: str, epoch: str, iso: str) -> tuple[tuple[int, ...], str]:
    """Return (sort_key, display) for one timestamp match, normalized to (mo,day,h,m,s)."""
    if syslog:
        mo, day, t = syslog.split()[0], syslog.split()[1], syslog.split()[2]
        h, m, s = (int(x) for x in t.split(":"))
        return ((_MONTHS.get(mo, 99), int(day), h, m, s), syslog)
    if epoch:
        try:
            d = _dt.datetime.fromtimestamp(int(epoch), tz=_dt.timezone.utc)
            return ((d.month, d.day, d.hour, d.minute, d.second),
                    f"{d:%Y-%m-%d %H:%M:%S}Z (epoch {epoch})")
        except (ValueError, OSError):
            return (_SENTINEL, f"epoch {epoch}")
    if iso:
        try:
            d = _dt.datetime.fromisoformat(iso.replace("T", " "))
            return ((d.month, d.day, d.hour, d.minute, d.second), iso)
        except ValueError:
            return (_SENTINEL, iso)
    return (_SENTINEL, "")


def _earliest(f: Finding) -> tuple[tuple[int, ...], str] | None:
    keyed = [_normalize(s, e, i) for s, e, i in _TS.findall(f.source_tool_output)]
    keyed = [k for k in keyed if k[0] != _SENTINEL]
    return min(keyed, key=lambda k: k[0]) if keyed else None


def build_timeline(result) -> str:
    out = ["# Timeline (reconstructed)\n",
           "_Times scraped from the tool output each finding cites; normalized for ordering "
           "within the case. Precise timestamps are in the cited output of each finding._\n"]
    dated, undated = [], []
    for f in result.confirmed_findings:
        e = _earliest(f)
        if e:
            dated.append((e, f))
        else:
            undated.append(f)
    dated.sort(key=lambda x: x[0][0])
    out.append("## Chronological\n")
    out += [f"- **{e[1]}** — {f.title} _([[analysis-{f.agent}]])_" for e, f in dated] \
        or ["- _(no timestamped findings)_"]
    if undated:
        out.append("\n## Undated findings\n")
        out += [f"- {f.title} _([[analysis-{f.agent}]])_" for f in undated]
    out.append("\n[[report|← back to report]]\n")
    return "\n".join(out)


def _narrative_from_expert(result) -> str:
    """Pull the executive narrative the IR expert wrote, if present."""
    if not result.expert or not result.expert.polished_markdown:
        return ""
    md = result.expert.polished_markdown
    m = re.search(r"## Executive narrative\s*(.+?)\n##", md, re.DOTALL)
    return m.group(1).strip() if m else ""


def build_narrative(result) -> str:
    out = ["# Narrative\n"]
    expert_narr = _narrative_from_expert(result)
    if expert_narr:
        out.append(expert_narr + "\n")
    else:
        out.append("_(No expert narrative available; see findings and [[timeline]].)_\n")
    out.append("See [[attacker-profile]], [[timeline]], and [[compromise-answers]] for the "
               "structured assessment.\n")
    out.append("\n[[report|← back to report]]\n")
    return "\n".join(out)


def build_attacker_profile(result) -> str:
    cats = categorize(result.confirmed_findings)
    present = [c for c in cats if cats[c]]
    mitre = result.expert.mitre_techniques if result.expert else []
    notable = result.expert.notable_iocs() if result.expert else []

    # Crude sophistication heuristic from breadth of the kill chain.
    depth = sum(bool(cats[c]) for c in
                ("initial_access", "privilege_escalation", "persistence",
                 "exfiltration", "antiforensics", "lateral"))
    level = ("Advanced — full kill chain with evasion" if depth >= 5 else
             "Capable — multi-stage, objective-driven" if depth >= 3 else
             "Limited — narrow activity observed")

    objective = ("Data theft / exfiltration" if cats["exfiltration"] else
                 "Persistent access" if cats["persistence"] else
                 "Access / reconnaissance")

    out = ["# Attacker profile\n",
           f"- **Assessed sophistication:** {level}",
           f"- **Apparent objective:** {objective}",
           f"- **Kill-chain stages observed:** {', '.join(present) or 'none'}",
           f"- **ATT&CK techniques:** {', '.join(mitre) or '—'}",
           f"- **Notable indicators:** "
           + (", ".join(f"`{m.indicator}` ({m.verdict})" for m in notable) if notable else "none"),
           ""]
    if cats["antiforensics"]:
        out.append("- **Tradecraft:** demonstrated anti-forensic / log-tampering behavior — "
                   "treat host logs as partially untrustworthy.")
    if cats["lateral"]:
        out.append("- **Scope:** lateral movement indicated — likely not confined to this host.")
    out.append("\n[[report|← back to report]]\n")
    return "\n".join(out)
