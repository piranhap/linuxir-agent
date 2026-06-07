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
- Protocol summary + conversations: identify external endpoints and high-volume transfers
  (candidate exfiltration).
- Beaconing: use detect_beaconing and look for near-constant inter-arrival times to one
  external IP (e.g. every ~60s) — the classic C2 signature.
- GeoIP: only state a country the local DB returns. If geoiplookup is unavailable or the DB
  is missing, DO NOT guess a country — say it is unknown.
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
