"""Linux IR Expert — senior review + threat-intel enrichment over confirmed findings.

Runs after the auditor. Unlike the specialists (which read evidence), the expert reasons
over the *confirmed* findings: it extracts IOCs, enriches them via the local-first intel
adapter, normalizes MITRE ATT&CK coverage, writes a polished senior-analyst narrative, and
decides whether the investigation warrants another iteration (the ``_needs_reanalysis`` hook
the orchestrator exposes).

Like the auditor, the LLM call is abstracted behind an :data:`~linuxir.agents.auditor.Ask`
so the same logic runs on the raw-API, subscription, and offline paths. The IOC/intel/MITRE
work is deterministic and fully testable without a model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..adapters import intel
from ..audit import JSONLAuditLogger
from ..findings import Finding
from .auditor import Ask

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_URL_HOST = re.compile(r"https?://([a-zA-Z0-9.\-]+)")
_EMAIL_DOMAIN = re.compile(r"[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")

# Minimal technique -> tactic map (see knowledge/mitre-attack.md).
_TACTIC = {
    "T1078": "Initial Access", "T1110": "Initial Access", "T1059": "Execution",
    "T1053": "Persistence", "T1543": "Persistence", "T1098": "Persistence",
    "T1037": "Persistence", "T1548": "Privilege Escalation", "T1574": "Defense Evasion",
    "T1070": "Defense Evasion", "T1552": "Credential Access", "T1560": "Collection",
    "T1071": "Command & Control", "T1090": "Command & Control", "T1041": "Exfiltration",
    "T1048": "Exfiltration", "T1567": "Exfiltration", "T1486": "Impact",
}


@dataclass
class ExpertResult:
    polished_markdown: str = ""
    ioc_matches: list[intel.IntelResult] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    requests_reanalysis: bool = False
    reanalysis_reason: str | None = None

    def notable_iocs(self) -> list[intel.IntelResult]:
        return [m for m in self.ioc_matches if m.verdict in ("malicious", "suspicious")]


def extract_iocs(findings: list[Finding]) -> dict[str, list[str]]:
    """Pull IPs, sha256 hashes, and domains out of the findings' text + evidence."""
    ips, hashes, domains = set(), set(), set()
    for f in findings:
        blob = " ".join([f.title, f.description, f.source_tool_output, *f.evidence_refs])
        ips.update(_IPV4.findall(blob))
        hashes.update(h.lower() for h in _SHA256.findall(blob))
        domains.update(h.lower() for h in _URL_HOST.findall(blob))
        domains.update(d.lower() for d in _EMAIL_DOMAIN.findall(blob))
    # A URL/email host that is an IP literal is already captured as an IP — don't also
    # treat it as a (bogus) domain.
    domains = {d for d in domains if not _IPV4.fullmatch(d)}
    return {"ip": sorted(ips), "hash": sorted(hashes), "domain": sorted(domains)}


def mitre_summary(findings: list[Finding]) -> list[str]:
    """Normalized, tactic-grouped MITRE technique IDs present across the findings."""
    techs: set[str] = set()
    for f in findings:
        if f.technique:
            techs.update(_TECH.findall(f.technique))
    def tactic(t: str) -> str:
        return _TACTIC.get(t.split(".")[0], "Other")
    return [f"{t} ({tactic(t)})" for t in sorted(techs)]


_EXPERT_SYSTEM = """\
You are a senior Linux incident-response expert writing the executive analysis for a case.
You are given the CONFIRMED findings (already verified against evidence by an auditor), the
threat-intel verdicts on their indicators, and the MITRE ATT&CK coverage. Write a tight,
factual narrative (5-10 sentences) of the intrusion: how it began, what the attacker did,
privilege/persistence/exfil, and the overall assessment. Ground every statement in the
findings provided — do NOT introduce new IOCs, malware names, or attribution. No headings,
no bullet list, just the narrative paragraph(s).
"""


def _narrate(ask: Ask, findings: list[Finding], matches: list[intel.IntelResult],
             mitre: list[str]) -> str:
    if not findings:
        return "No confirmed findings; insufficient evidence for an intrusion narrative."
    fl = "\n".join(f"- [{f.confidence}] {f.title} (technique: {f.technique or '—'})"
                   for f in findings)
    il = "\n".join(f"- {m.render()}" for m in matches) or "- (no indicators enriched)"
    prompt = (f"CONFIRMED FINDINGS:\n{fl}\n\nTHREAT-INTEL:\n{il}\n\n"
              f"MITRE ATT&CK: {', '.join(mitre) or '—'}\n\nWrite the narrative.")
    try:
        text = ask(_EXPERT_SYSTEM, prompt).strip()
        return text or "(no narrative produced)"
    except Exception as e:  # narrative is best-effort; enrichment still stands
        return f"(narrative unavailable: {str(e)[:80]})"


def _polished_md(narrative: str, findings: list[Finding], matches: list[intel.IntelResult],
                 mitre: list[str], reanalysis_reason: str | None) -> str:
    lines = ["# Polished analysis (Linux IR Expert)\n", "## Executive narrative\n", narrative, ""]
    lines.append("## MITRE ATT&CK coverage\n")
    lines += [f"- {m}" for m in mitre] or ["- (none mapped)"]
    lines.append("\n## Threat-intel enrichment\n")
    if matches:
        lines.append("| indicator | kind | verdict | sources | detail |")
        lines.append("|---|---|---|---|---|")
        for m in matches:
            lines.append(f"| `{m.indicator}` | {m.kind} | **{m.verdict}** | "
                         f"{', '.join(m.sources)} | {m.detail} |")
    else:
        lines.append("_No indicators extracted from confirmed findings._")
    lines.append("\n## Confirmed findings reviewed\n")
    lines += [f"- [{f.confidence}] {f.title} _([[analysis-{f.agent}]])_" for f in findings] \
        or ["- (none)"]
    if reanalysis_reason:
        lines.append(f"\n## Re-analysis requested\n{reanalysis_reason}")
    lines.append("\n[[report|← back to report]]\n")
    return "\n".join(lines)


def enrich(
    ask: Ask,
    findings: list[Finding],
    *,
    audit: JSONLAuditLogger,
    correlations: list[str] | None = None,
    reanalysis_allowed: bool = True,
) -> ExpertResult:
    """Senior review + intel enrichment over the confirmed findings."""
    correlations = correlations or []
    iocs = extract_iocs(findings)

    matches: list[intel.IntelResult] = []
    for ip in iocs["ip"]:
        matches.append(intel.lookup_ip(ip))
    for h in iocs["hash"]:
        matches.append(intel.lookup_hash(h))
    for d in iocs["domain"]:
        matches.append(intel.lookup_domain(d))
    for m in matches:
        audit.log_event(kind="intel_match", indicator=m.indicator, ioc_kind=m.kind,
                        verdict=m.verdict, sources=m.sources)

    mitre = mitre_summary(findings)
    narrative = _narrate(ask, findings, matches, mitre)

    # Re-analysis decision: findings span multiple agents but nothing correlated them —
    # the cross-artifact link was missed (corroborate on users/paths/keys, not just IPs).
    requests, reason = False, None
    agents = {f.agent for f in findings if f.agent}
    if reanalysis_allowed and len(agents) >= 2 and not correlations:
        requests = True
        reason = (f"Confirmed findings span {len(agents)} agents ({', '.join(sorted(agents))}) "
                  "but no cross-artifact correlation was established. Re-examine for shared "
                  "indicators — usernames, file paths, SSH keys — not only IP addresses.")

    md = _polished_md(narrative, findings, matches, mitre, reason)
    return ExpertResult(polished_markdown=md, ioc_matches=matches, mitre_techniques=mitre,
                        requests_reanalysis=requests, reanalysis_reason=reason)
