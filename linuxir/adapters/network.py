"""pcap analysis via tshark (graceful fallback when tshark is absent).

Provides a protocol summary, a conversation/endpoint list, and a simple beaconing
heuristic (regular inter-arrival times to a single destination — the classic C2 pattern
the accuracy report calls out). All shell out through :func:`run_binary`.
"""

from __future__ import annotations

from .base import run_binary, summarize


def pcap_summary(pcap: str) -> str:
    """Protocol hierarchy statistics for the capture."""
    return summarize(run_binary(["tshark", "-r", pcap, "-q", "-z", "io,phs"], timeout=300))


def pcap_conversations(pcap: str) -> str:
    """IP conversations (endpoints, packet/byte counts, duration)."""
    return summarize(
        run_binary(["tshark", "-r", pcap, "-q", "-z", "conv,ip"], timeout=300)
    )


def detect_beaconing(pcap: str, dest_ip: str | None = None) -> str:
    """Emit per-packet frame times to a destination so regular beaconing stands out.

    Returns the raw time/dst series; the agent (or a human) judges the regularity. A
    fixed interval (e.g. every 60s) to one external IP is the C2 signature.
    """
    fields = ["-T", "fields", "-e", "frame.time_relative", "-e", "ip.dst", "-e", "tcp.dstport"]
    argv = ["tshark", "-r", pcap, *fields]
    if dest_ip:
        argv += ["-Y", f"ip.dst == {dest_ip}"]
    return summarize(run_binary(argv, timeout=300))
