"""Network specialist — pcap protocol stats, conversations, C2 beaconing, GeoIP.

Runs only when the case includes a pcap. GeoIP must report only what the local DB says —
the report flags a DE-read-as-Russia misattribution as a caught hallucination, so the
prompt forbids inferring geography without data.
"""

from __future__ import annotations

from ..llm import MODEL_REASONING
from ..tools import NETWORK_TOOLS
from ._shared import build_system
from .base import Agent

_CHECKLIST = """\
- Protocol summary + conversations: identify external endpoints and high-volume transfers.
- Beaconing: use detect_beaconing and look for near-constant inter-arrival times to one
  external IP (e.g. every ~60s) — the classic C2 signature.
- network_detect_exfil: rank destinations by outbound bytes; large transfers are candidate
  data exfiltration.
- network_extract_dns / network_extract_http: C2 or exfil domains, suspicious URIs, and
  odd User-Agents (tooling fingerprints).
- network_extract_credentials: cleartext HTTP Basic / FTP / telnet secrets in the capture.
- network_find_tor_exits: destinations on known Tor exit nodes (anonymized infrastructure).
- GeoIP: only state a country the local DB returns. If geoiplookup is unavailable or the DB
  is missing, DO NOT guess a country — say it is unknown.
- Zeek JSON logs (if present): zeek_conn_summary for external talkers + exfil (and
  zeek_conn_summary with focus_ip to trace a specific suspect IP's flows / C2 beaconing);
  zeek_file_hashes for transferred-file hash IOCs; zeek_dns for C2/exfil domains; zeek_http
  for tooling/C2 over HTTP. Internal hosts are 10.x — external IPs are the attacker side.
Cite the exact tool output (intervals, byte counts, endpoints) behind each finding.
"""

ROLE = (
    "Analyze the packet capture for C2 beaconing and data exfiltration. Provide the pcap "
    "path to each tool; geolocate external IPs only when the DB supports it."
)


def make_network_agent() -> Agent:
    return Agent(
        name="network",
        system=build_system(ROLE, _CHECKLIST),
        tool_names=NETWORK_TOOLS,
        model=MODEL_REASONING,
    )
