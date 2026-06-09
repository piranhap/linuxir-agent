# Threat-intel sources & enrichment policy

The IR-expert pass enriches IOCs extracted from **confirmed** findings. Enrichment is
**local-first and privacy-safe by default**: indicators are checked against bundled
baselines and computed heuristics with **no network egress**. External lookups (which send
the indicator to a third party) are strictly opt-in.

## Local (default, offline, no egress)
- **IP**: RFC1918 / loopback / link-local classification (internal vs. internet-routable);
  match against the bundled known-Tor-exit prefix list and a small known-bad list.
- **Hash (sha256/sha1/md5)**: match against `known-hashes.md` baseline.
- **Domain**: high-entropy / long-label DGA heuristic; known-bad list.

## External (opt-in only)
Enabled only when BOTH are set: `LINUXIR_ALLOW_INTEL_NETWORK=1` and the relevant API key.
Sending an indicator to these services discloses it to a third party — appropriate for live
IR, but never the default for evidence handling.

| Service | Indicator | Env key | Endpoint |
|---|---|---|---|
| VirusTotal | hash / ip / domain | `VIRUSTOTAL_API_KEY` | `https://www.virustotal.com/api/v3/` |
| abuse.ch MalwareBazaar | sha256 | (none) | `https://mb-api.abuse.ch/api/v1/` |
| AbuseIPDB | ip | `ABUSEIPDB_API_KEY` | `https://api.abuseipdb.com/api/v2/check` |

Every enrichment is logged as an `intel_match` audit event so the provenance of each
verdict is traceable, exactly like tool calls and findings.
