"""pcap analysis via tshark (graceful fallback when tshark is absent).

Provides a protocol summary, a conversation/endpoint list, and a simple beaconing
heuristic (regular inter-arrival times to a single destination — the classic C2 pattern
the accuracy report calls out). All shell out through :func:`run_binary`.
"""

from __future__ import annotations

from .base import run_binary, summarize

# A small bundled sample of known Tor exit prefixes — enough to demonstrate the check.
# 185.220.101.0/24 is a well-known Tor exit block (the fixture's attacker IP lives here).
# In production this list would be refreshed from the live Tor exit list / threat intel.
_KNOWN_TOR_EXIT_PREFIXES = ("185.220.101.", "185.220.100.", "171.25.193.", "204.13.164.")


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


def extract_dns(pcap: str) -> str:
    """All DNS queries and their answers — surfaces C2/exfil domains and DGA patterns."""
    argv = ["tshark", "-r", pcap, "-Y", "dns", "-T", "fields",
            "-e", "frame.time_relative", "-e", "dns.qry.name", "-e", "dns.a",
            "-E", "separator=|"]
    return summarize(run_binary(argv, timeout=300))


def extract_http(pcap: str) -> str:
    """HTTP requests: host, URI, and User-Agent — odd UAs and hosts flag tooling/C2."""
    argv = ["tshark", "-r", pcap, "-Y", "http.request", "-T", "fields",
            "-e", "frame.time_relative", "-e", "http.host", "-e", "http.request.uri",
            "-e", "http.user_agent", "-E", "separator=|"]
    return summarize(run_binary(argv, timeout=300))


def detect_exfil(pcap: str, top_n: int = 10, flag_bytes: int = 1_000_000) -> str:
    """Sum outbound bytes per destination IP; rank and flag large transfers (exfil)."""
    argv = ["tshark", "-r", pcap, "-T", "fields", "-e", "ip.dst", "-e", "ip.len"]
    res = run_binary(argv, timeout=300)
    if not res.get("available") or res.get("timed_out"):
        return summarize(res)
    totals: dict[str, int] = {}
    for line in (res.get("stdout") or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0]:
            continue
        try:
            totals[parts[0]] = totals.get(parts[0], 0) + int(parts[1] or 0)
        except ValueError:
            continue
    if not totals:
        return "[no IP traffic with lengths found in capture]"
    ranked = sorted(totals.items(), key=lambda kv: -kv[1])[:top_n]
    rows = [f"  {ip}: {nbytes:,} bytes" + ("   [LARGE OUTBOUND — possible exfil]"
                                           if nbytes >= flag_bytes else "")
            for ip, nbytes in ranked]
    return f"[outbound bytes per destination (top {len(ranked)})]\n" + "\n".join(rows)


def extract_credentials(pcap: str) -> str:
    """Cleartext credentials in the capture: HTTP Basic auth, FTP USER/PASS, telnet."""
    disp = ("http.authorization || ftp.request.command == \"USER\" || "
            "ftp.request.command == \"PASS\" || telnet")
    argv = ["tshark", "-r", pcap, "-Y", disp, "-T", "fields",
            "-e", "frame.time_relative", "-e", "ip.dst",
            "-e", "http.authorization", "-e", "ftp.request.command",
            "-e", "ftp.request.arg", "-E", "separator=|"]
    res = run_binary(argv, timeout=300)
    if not res.get("available") or res.get("timed_out"):
        return summarize(res)
    if not (res.get("stdout") or "").strip():
        return "[no cleartext credentials (HTTP Basic / FTP / telnet) observed]"
    return ("[cleartext credential exposure — any output below is a plaintext secret]\n"
            + summarize(res))


def find_tor_exits(pcap: str) -> str:
    """Match the capture's destination IPs against a bundled known-Tor-exit prefix list."""
    argv = ["tshark", "-r", pcap, "-T", "fields", "-e", "ip.dst"]
    res = run_binary(argv, timeout=300)
    if not res.get("available") or res.get("timed_out"):
        return summarize(res)
    dsts = {ip for ip in (res.get("stdout") or "").split() if ip}
    hits = sorted(ip for ip in dsts
                  if any(ip.startswith(p) for p in _KNOWN_TOR_EXIT_PREFIXES))
    if not hits:
        return f"[none of {len(dsts)} destination IP(s) match the known Tor-exit list]"
    return ("[destination IP(s) matching known Tor exit nodes — anonymized infrastructure]\n"
            + "\n".join(f"  {ip}" for ip in hits))
