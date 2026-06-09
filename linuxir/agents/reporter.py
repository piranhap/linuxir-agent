"""Reporter — the 12 mandatory IR answers, IOC/TTP, and recommendations.

Deterministic synthesis over the *confirmed* (auditor-verified) findings, the IR-expert
enrichment, and the cross-artifact correlations. Because every answer is assembled from
already-verified findings — each carrying the tool output it cites — the report introduces
no new hallucination surface: every claim traces back to an audited finding and the
artifact behind it.

Each compromise answer opens with a direct yes/no/statement, then a confidence level, the
supporting findings as ``[[analysis-<agent>]]`` wiki links, and the specific artifact paths.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import datetime, timezone

from ..findings import Confidence, Finding

# CLAUDE.md Section 10 — the answers the report MUST provide.
MANDATORY_IR_QUESTIONS: list[tuple[str, str]] = [
    ("compromised", "Is this device compromised?"),
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

# Category -> (technique-id prefixes, keyword substrings) used to bucket findings.
_CATEGORIES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "initial_access": (("T1078", "T1110", "T1190", "T1133"),
                       ("initial access", "brute", "accepted password", "accepted publickey",
                        "valid account", "ssh login", "first accepted")),
    "privilege_escalation": (("T1548", "T1068", "T1055"),
                             ("privilege escalation", "sudo", "setuid", "setgid", "escalat",
                              "to root", "gtfobins", "hydra")),
    "persistence": (("T1053", "T1543", "T1098", "T1037", "T1546", "T1574"),
                    ("persistence", "cron", "systemd", "authorized_keys", "rc.local",
                     "ld.so.preload", "ld_preload", "init.d", "backdoor")),
    "exfiltration": (("T1041", "T1048", "T1567", "T1560", "T1052"),
                     ("exfil", "scp", "rsync", "archive", "tar ", "upload", "encrypt",
                      "gpg --encrypt", "loot")),
    "antiforensics": (("T1070", "T1027", "T1551", "T1562"),
                      ("anti-forensic", "antiforensic", "history -c", "shred", "wipe",
                       "tamper", "truncat", "cleared", "chattr", "deleted log")),
    "lateral": (("T1021", "T1080", "T1570"),
                ("lateral", "pivot", "jump host", "moved to", "ssh to ", "scp to ",
                 "another host", "internal host")),
    "credential_access": (("T1552", "T1555", "T1003"),
                          ("private key", "id_rsa", "ssh key", "credential", "password hash",
                           "/etc/shadow", "harvest")),
    "collection": (("T1560", "T1005", "T1119"), ("collect", "staged", "sensitivedocs")),
}

_TS = re.compile(
    r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"     # syslog "Mar 13 08:05:57"
    r"|#(\d{9,11})\b"                                          # bash-history epoch
    r"|\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\b")          # ISO / Zeek

# Usernames named inside a finding's text/output. Each pattern requires enough left-context
# that a bare path component (e.g. the evidence-scope dir) cannot masquerade as an account —
# this is the deterministic complement to correlate_findings' user-links, which only fire
# when the SAME user appears across two agents.
_USER = "([a-z_][a-z0-9._-]{1,31})"
_ACCOUNT_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in (
        rf"(?:invalid user|for user|for invalid user|session opened for user) {_USER}",
        rf"Accepted (?:password|publickey|keyboard-interactive) for {_USER}",
        rf"User '{_USER}'",
        rf"\bUSER={_USER}",
        rf"crontabs/{_USER}",
        rf"bash_history[/-]{_USER}",
        rf"sudo:\s+{_USER}\s*:",
        rf"useradd[^\n]*\b{_USER}\s*$",
    )
]
# Tokens that are never a meaningful "suspected account" even with matching context.
_ACCOUNT_STOPWORDS = {"unknown", "none", "null", "user", "the"}


def _techs(f: Finding) -> set[str]:
    return set(re.findall(r"T\d{4}(?:\.\d{3})?", f.technique or ""))


def categorize(findings: list[Finding]) -> "OrderedDict[str, list[Finding]]":
    cats: OrderedDict[str, list[Finding]] = OrderedDict((k, []) for k in _CATEGORIES)
    for f in findings:
        techs = {t.split(".")[0] for t in _techs(f)}
        blob = f"{f.title} {f.description}".lower()
        for cat, (prefixes, keywords) in _CATEGORIES.items():
            if techs & set(prefixes) or any(k in blob for k in keywords):
                cats[cat].append(f)
    return cats


def _max_conf(findings: list[Finding]) -> Confidence:
    order = [Confidence.UNVERIFIED, Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    best = Confidence.UNVERIFIED
    for f in findings:
        if order.index(f.confidence) > order.index(best):
            best = f.confidence
    return best


def _cite(findings: list[Finding]) -> str:
    agents = sorted({f.agent for f in findings if f.agent})
    links = " ".join(f"[[analysis-{a}]]" for a in agents)
    ids = ", ".join(f"`{f.id}`" for f in findings[:6])
    return (f"Supporting findings: {ids}" + (f" ({links})" if links else "")) if findings else ""


def _artifacts(findings: list[Finding]) -> str:
    refs = sorted({r for f in findings for r in f.evidence_refs})
    return ("Artifacts: " + ", ".join(f"`{r}`" for r in refs[:8])) if refs else ""


def _usernames(result, findings: list[Finding] | None = None) -> list[str]:
    """Suspected accounts: those correlate_findings linked across agents, PLUS any account
    named in a confirmed finding's text/output (auth.log users, crontab owners, USER= in
    sudo/auditd, bash_history/<user>). The correlation-only path missed the latter."""
    users: set[str] = set()
    for c in result.correlations:
        m = re.search(r"User '([^']+)' links", c)
        if m:
            users.add(m.group(1))
    for f in (findings or []):
        blob = f"{f.title}\n{f.description}\n{f.source_tool_output}"
        for pat in _ACCOUNT_PATTERNS:
            for u in pat.findall(blob):
                if u.lower() not in _ACCOUNT_STOPWORDS:
                    users.add(u)
    return sorted(users)


def _earliest_timestamp(findings: list[Finding]) -> str | None:
    """Earliest attacker activity across all confirmed findings, normalized to a real
    instant. syslog ("Mar 13 08:05:57"), bash-history epoch (#...), and ISO/Zeek stamps are
    parsed to comparable datetimes; the minimum is returned in a readable form — never a raw
    epoch integer. syslog has no year, so it borrows the earliest year seen in the dated
    (epoch/ISO) stamps; with no dated anchor it ranks last."""
    raw: list[tuple[str, str, str]] = []
    years: list[int] = []
    for f in findings:
        for syslog, epoch, iso in _TS.findall(f.source_tool_output):
            raw.append((syslog, epoch, iso))
            if epoch:
                years.append(datetime.fromtimestamp(int(epoch), timezone.utc).year)
            elif iso:
                years.append(int(iso[:4]))
    anchor_year = min(years) if years else None

    parsed: list[tuple[datetime, str]] = []
    for syslog, epoch, iso in raw:
        try:
            if epoch:
                dt = datetime.fromtimestamp(int(epoch), timezone.utc).replace(tzinfo=None)
                parsed.append((dt, f"{dt:%Y-%m-%d %H:%M:%S} UTC"))
            elif iso:
                parsed.append((datetime.fromisoformat(iso.replace("T", " ")), iso))
            elif syslog and anchor_year is not None:
                dt = datetime.strptime(f"{anchor_year} {syslog}", "%Y %b %d %H:%M:%S")
                parsed.append((dt, f"{syslog} {anchor_year}"))
            elif syslog:
                parsed.append((datetime.max, syslog))   # no dated anchor — lowest priority
        except (ValueError, OverflowError, OSError):
            continue
    if not parsed:
        return None
    return min(parsed, key=lambda p: p[0])[1]


def _q(n: int, question: str, answer: str, conf: Confidence | str,
       findings: list[Finding] | None = None, extra: str = "") -> str:
    body = [f"### {n}. {question}\n", f"**{answer}** _(confidence: {conf})_\n"]
    if findings:
        body.append(_cite(findings) + "\n")
        arts = _artifacts(findings)
        if arts:
            body.append(arts + "\n")
    if extra:
        body.append(extra + "\n")
    return "\n".join(body)


def build_compromise_answers(result) -> str:
    confirmed = result.confirmed_findings
    cats = categorize(confirmed)
    expert = result.expert
    users = _usernames(result, confirmed)
    out = ["# Compromise — mandatory IR answers\n",
           f"_Case `{result.case.case_id}` · {len(confirmed)} confirmed findings._\n"]
    n = 0

    def add(*a, **k):
        nonlocal n
        n += 1
        out.append(_q(n, *a, **k))

    # 1 compromised
    if confirmed:
        add(MANDATORY_IR_QUESTIONS[0][1],
            "Yes — the host shows confirmed, evidence-backed indicators of compromise.",
            _max_conf(confirmed), confirmed)
    else:
        add(MANDATORY_IR_QUESTIONS[0][1],
            "Inconclusive — no findings survived auditor verification.", Confidence.LOW)

    # 2 when
    ts = _earliest_timestamp(confirmed)
    add(MANDATORY_IR_QUESTIONS[1][1],
        (f"Earliest observed attacker activity: {ts}." if ts
         else "No precise timestamp recovered; see [[timeline]] for the reconstructed sequence."),
        Confidence.MEDIUM if ts else Confidence.LOW,
        extra="See [[timeline]] for the full chronology.")

    # 3 accounts
    add(MANDATORY_IR_QUESTIONS[2][1],
        ("Suspected accounts: " + ", ".join(f"`{u}`" for u in users) + "."
         if users else "No specific account could be attributed across artifacts."),
        Confidence.MEDIUM if users else Confidence.LOW,
        cats["initial_access"] + cats["privilege_escalation"])

    # 4 how / origin
    ia = cats["initial_access"]
    add(MANDATORY_IR_QUESTIONS[3][1],
        (ia[0].title + "." if ia else "Initial access vector not definitively established."),
        _max_conf(ia) if ia else Confidence.LOW, ia)

    # 5 pivot
    lateral = cats["lateral"]
    add(MANDATORY_IR_QUESTIONS[4][1],
        ("Yes — lateral movement / multi-host activity is indicated; investigate the "
         "connected hosts and accounts below." if lateral or len(users) > 1
         else "No clear indication that additional devices were involved."),
        Confidence.MEDIUM if (lateral or len(users) > 1) else Confidence.LOW,
        lateral)

    # 6 privesc
    pe = cats["privilege_escalation"]
    add(MANDATORY_IR_QUESTIONS[5][1],
        ("Yes — " + pe[0].title + "." if pe else "No privilege escalation observed."),
        _max_conf(pe) if pe else Confidence.LOW, pe)

    # 7 persistence
    pr = cats["persistence"]
    add(MANDATORY_IR_QUESTIONS[6][1],
        ("Yes — persistence was established via: "
         + "; ".join(sorted({f.title for f in pr})) + "." if pr
         else "No persistence mechanism confirmed."),
        _max_conf(pr) if pr else Confidence.LOW, pr)

    # 8 actions
    actions = "; ".join(f.title for f in confirmed[:10]) or "No confirmed actions."
    add(MANDATORY_IR_QUESTIONS[7][1], actions, _max_conf(confirmed) if confirmed else Confidence.LOW,
        confirmed[:10])

    # 9 significant behaviors
    af = cats["antiforensics"]
    add(MANDATORY_IR_QUESTIONS[8][1],
        ("Yes — anti-forensic / evasion behavior: "
         + "; ".join(sorted({f.title for f in af})) + "." if af
         else "No standout anti-forensic behavior beyond the findings above."),
        _max_conf(af) if af else Confidence.LOW, af)

    # 10 exfil
    ex = cats["exfiltration"]
    add(MANDATORY_IR_QUESTIONS[9][1],
        ("Yes — data exfiltration is indicated: " + "; ".join(sorted({f.title for f in ex})) + "."
         if ex else "No data exfiltration confirmed."),
        _max_conf(ex) if ex else Confidence.LOW, ex)

    # 11 malware
    mal_iocs = [m for m in (expert.ioc_matches if expert else []) if m.kind == "hash"
                and m.verdict == "malicious"]
    mw = cats["privilege_escalation"]  # hydra etc. surface here; reuse keyword hits
    mw_titles = sorted({f.title for f in confirmed if "malware" in f.title.lower()
                        or "hydra" in f.title.lower() or "implant" in f.title.lower()})
    if mal_iocs:
        ans = "Yes — known-malicious file hashes: " + ", ".join(f"`{m.indicator}`" for m in mal_iocs)
    elif mw_titles:
        ans = "Attacker tooling observed (no confirmed malware binary by hash): " + "; ".join(mw_titles)
    else:
        ans = "No malware binary confirmed by hash; review tooling in the findings."
    add(MANDATORY_IR_QUESTIONS[10][1], ans,
        Confidence.MEDIUM if (mal_iocs or mw_titles) else Confidence.LOW)

    # 12 IOC/IOA/TTP
    nioc = len(expert.ioc_matches) if expert else 0
    nmitre = len(expert.mitre_techniques) if expert else 0
    add(MANDATORY_IR_QUESTIONS[11][1],
        f"{nioc} indicator(s) enriched and {nmitre} ATT&CK technique(s) mapped — see [[ioc-ttp]].",
        Confidence.HIGH if nioc or nmitre else Confidence.LOW,
        extra="Full indicator and TTP listing in [[ioc-ttp]].")

    return "\n".join(out)


def build_ioc_ttp(result) -> str:
    expert = result.expert
    out = ["# IOC / IOA / TTP\n"]
    out.append("## MITRE ATT&CK techniques\n")
    out += [f"- {t}" for t in (expert.mitre_techniques if expert else [])] or ["- (none mapped)"]
    out.append("\n## Indicators of compromise\n")
    matches = expert.ioc_matches if expert else []
    if matches:
        out.append("| indicator | kind | verdict | sources | detail |")
        out.append("|---|---|---|---|---|")
        for m in matches:
            out.append(f"| `{m.indicator}` | {m.kind} | {m.verdict} | "
                       f"{', '.join(m.sources)} | {m.detail} |")
    else:
        out.append("_No indicators extracted from confirmed findings._")
    out.append("\n## Cross-artifact correlations (IOA)\n")
    out += [f"- {c}" for c in result.correlations] or ["- (none)"]
    out.append("\n[[report|← back to report]]\n")
    return "\n".join(out)


_REC_BY_CATEGORY = {
    "initial_access": "Rotate credentials and SSH keys for affected accounts; enforce MFA "
                      "and key-only SSH; review and restrict source IPs allowed to authenticate.",
    "privilege_escalation": "Audit sudoers and setuid/setgid binaries; remove unauthorized "
                            "privilege grants; patch the escalation vector.",
    "persistence": "Remove the persistence artifacts (cron/systemd/authorized_keys/rc/"
                   "ld.so.preload); rebuild from known-good if integrity is in doubt.",
    "exfiltration": "Scope the exfiltrated data, notify per policy/regulation, and block the "
                    "destination infrastructure; preserve evidence for legal hold.",
    "antiforensics": "Treat logs as untrustworthy; pull authoritative copies from the SIEM/"
                     "central log store and reconcile against host artifacts.",
    "lateral": "Investigate the connected hosts and accounts; assume the credential set is "
               "compromised network-wide until proven otherwise.",
    "credential_access": "Rotate every credential and key the attacker could have read; "
                         "invalidate active sessions.",
}


def build_recommendations(result) -> str:
    cats = categorize(result.confirmed_findings)
    out = ["# Recommendations\n", "## Immediate containment & recovery\n"]
    present = [c for c in cats if cats[c]]
    for c in present:
        if c in _REC_BY_CATEGORY:
            out.append(f"- **{c.replace('_', ' ').title()}:** {_REC_BY_CATEGORY[c]}")
    if not any(c in _REC_BY_CATEGORY for c in present):
        out.append("- No category-specific actions; preserve evidence and continue triage.")
    out.append("\n## Hardening (general)\n")
    out += [
        "- Centralize logging off-host (anti-forensics resistance) and monitor for the "
        "recovered IOCs/TTPs.",
        "- Baseline cron, systemd units, authorized_keys, and setuid files; alert on drift.",
        "- Restrict outbound egress and inspect for the C2 / exfil destinations in [[ioc-ttp]].",
        "- Re-image hosts where persistence or root-level compromise is confirmed.",
    ]
    out.append("\n[[report|← back to report]]\n")
    return "\n".join(out)
