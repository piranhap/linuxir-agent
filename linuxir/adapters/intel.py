"""Threat-intel enrichment — local-first, privacy-safe, optional opt-in external lookups.

IOCs extracted from confirmed findings are classified/enriched here. By default this does
**no network egress**: IPs are classified (RFC1918 vs internet-routable) and matched against
a bundled Tor-exit / known-bad list, hashes against a small baseline, domains against a DGA
heuristic. Sending an indicator to a third party (VirusTotal/abuse.ch/AbuseIPDB) discloses
it, so external lookups require BOTH ``LINUXIR_ALLOW_INTEL_NETWORK=1`` and the relevant API
key — never the default for evidence handling.

Each function returns a structured :class:`IntelResult` so callers can both render text and
branch on ``verdict`` (e.g. to decide whether a finding warrants escalation).
"""

from __future__ import annotations

import ipaddress
import math
import os
from dataclasses import dataclass, field

from .network import _KNOWN_TOR_EXIT_PREFIXES

# Bundled baselines — extend from your own intel (see knowledge/*.md).
KNOWN_BAD_IPS: dict[str, str] = {
    # "203.0.113.66": "example C2 (doc-net)",
}
KNOWN_BAD_HASHES: dict[str, str] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        "empty file (placeholder — not malicious)",
}
KNOWN_BAD_DOMAINS: dict[str, str] = {
    # "evil.example": "example C2 domain",
}


@dataclass
class IntelResult:
    indicator: str
    kind: str                      # "ip" | "hash" | "domain"
    verdict: str                   # "malicious" | "suspicious" | "internal" | "benign" | "unknown"
    sources: list[str] = field(default_factory=list)
    detail: str = ""

    def render(self) -> str:
        src = f" [{', '.join(self.sources)}]" if self.sources else ""
        return f"{self.kind} {self.indicator}: {self.verdict.upper()}{src} — {self.detail}"


def _network_enabled() -> bool:
    return os.getenv("LINUXIR_ALLOW_INTEL_NETWORK") == "1"


# -- IP -----------------------------------------------------------------------------

def lookup_ip(ip: str) -> IntelResult:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return IntelResult(ip, "ip", "unknown", detail="not a valid IP address")

    if ip in KNOWN_BAD_IPS:
        return IntelResult(ip, "ip", "malicious", ["known-bad-list"], KNOWN_BAD_IPS[ip])

    if any(ip.startswith(p) for p in _KNOWN_TOR_EXIT_PREFIXES):
        return IntelResult(ip, "ip", "malicious", ["tor-exit-list"],
                           "matches a known Tor exit-node prefix (anonymized infrastructure)")

    if addr.is_loopback:
        return IntelResult(ip, "ip", "benign", ["rfc"], "loopback")
    if addr.is_private:
        return IntelResult(ip, "ip", "internal", ["rfc1918"],
                           "RFC1918 private address — internal host (lateral movement / "
                           "insider context, not external C2)")
    if addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return IntelResult(ip, "ip", "benign", ["rfc"], "special-use address")

    ext = _external_ip(ip)
    if ext:
        return ext
    return IntelResult(ip, "ip", "unknown", ["local-only"],
                       "internet-routable; no local match (enable external lookups for more)")


def _external_ip(ip: str) -> IntelResult | None:
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not (_network_enabled() and key):
        return None
    try:
        import httpx
        r = httpx.get("https://api.abuseipdb.com/api/v2/check",
                      params={"ipAddress": ip, "maxAgeInDays": 90},
                      headers={"Key": key, "Accept": "application/json"}, timeout=6.0)
        score = r.json().get("data", {}).get("abuseConfidenceScore", 0)
        verdict = "malicious" if score >= 50 else "suspicious" if score >= 10 else "benign"
        return IntelResult(ip, "ip", verdict, ["abuseipdb"], f"abuse confidence {score}%")
    except Exception as e:
        return IntelResult(ip, "ip", "unknown", ["abuseipdb-error"], str(e)[:80])


# -- hash ---------------------------------------------------------------------------

def lookup_hash(h: str) -> IntelResult:
    h = h.lower().strip()
    if h in KNOWN_BAD_HASHES:
        label = KNOWN_BAD_HASHES[h]
        verdict = "benign" if "not malicious" in label or "placeholder" in label else "malicious"
        return IntelResult(h, "hash", verdict, ["known-hashes"], label)
    ext = _external_hash(h)
    if ext:
        return ext
    return IntelResult(h, "hash", "unknown", ["local-only"],
                       "no baseline match (enable external lookups for VT/MalwareBazaar)")


def _external_hash(h: str) -> IntelResult | None:
    if not _network_enabled():
        return None
    try:
        import httpx
        r = httpx.post("https://mb-api.abuse.ch/api/v1/",
                       data={"query": "get_info", "hash": h}, timeout=6.0)
        data = r.json()
        if data.get("query_status") == "ok":
            sig = (data.get("data") or [{}])[0].get("signature") or "listed"
            return IntelResult(h, "hash", "malicious", ["malwarebazaar"], f"MalwareBazaar: {sig}")
        return IntelResult(h, "hash", "unknown", ["malwarebazaar"], "not in MalwareBazaar")
    except Exception as e:
        return IntelResult(h, "hash", "unknown", ["malwarebazaar-error"], str(e)[:80])


# -- domain -------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((c := s.count(ch) / len(s)) * math.log2(c) for ch in set(s))


def lookup_domain(domain: str) -> IntelResult:
    domain = domain.lower().strip().rstrip(".")
    if domain in KNOWN_BAD_DOMAINS:
        return IntelResult(domain, "domain", "malicious", ["known-bad-list"], KNOWN_BAD_DOMAINS[domain])
    label = domain.split(".")[0]
    entropy = _shannon_entropy(label)
    if len(label) >= 12 and entropy >= 3.5:
        return IntelResult(domain, "domain", "suspicious", ["dga-heuristic"],
                           f"high-entropy label (len={len(label)}, entropy={entropy:.1f}) — "
                           "possible DGA / algorithmically-generated domain")
    return IntelResult(domain, "domain", "unknown", ["local-only"],
                       "no baseline match; label entropy normal")
