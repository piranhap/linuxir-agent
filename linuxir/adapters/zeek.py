"""Zeek JSON log analysis (conn / http / dns / files).

Zeek sensors emit newline-delimited JSON (one record per line). This adapter turns that
network telemetry into the IR essentials: external talkers and large/long flows (C2 +
exfiltration), file-transfer hashes (IOCs), DNS queries, and HTTP requests. Logs can be
hundreds of MB, so every reader streams line-by-line and is bounded by ``max_lines``.

``local_orig`` / ``local_resp`` (set by Zeek's local-nets config) tell us which side of a
flow is internal, so we can separate inbound scanning, internal-to-external exfil/C2, and
lateral movement without guessing.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from .discover import discover


def _iter(path: Path, max_lines: int):
    try:
        fh = path.open("r", errors="replace")
    except OSError:
        return
    n = 0
    with fh:
        for line in fh:
            n += 1
            if n > max_lines:
                return
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue


def _ts(v) -> str:
    try:
        return f"{_dt.datetime.fromtimestamp(float(v), tz=_dt.timezone.utc):%Y-%m-%d %H:%M:%S}Z"
    except (ValueError, OSError, TypeError):
        return str(v)


def _logs(roots, name: str) -> list[Path]:
    return discover(roots, (name,))


def conn_summary(roots, focus_ip: str | None = None, max_lines: int = 3_000_000) -> str:
    """External talkers, large/long flows (exfil/C2). With focus_ip: flows involving it."""
    files = _logs(roots, "conn.json")
    if not files:
        return "[no Zeek conn.json found in evidence scope]"

    exfil: dict[str, list[int]] = {}   # external dst -> [bytes_out, count]
    inbound: dict[str, int] = {}       # external src -> conn count
    focus: list[str] = []
    scanned = 0
    for f in files:
        for r in _iter(f, max_lines):
            scanned += 1
            o, d = r.get("id.orig_h"), r.get("id.resp_h")
            ob, rb = r.get("orig_bytes") or 0, r.get("resp_bytes") or 0
            lo, lr = r.get("local_orig"), r.get("local_resp")
            if focus_ip and focus_ip in (o, d) and len(focus) < 60:
                focus.append(f"  {_ts(r.get('ts'))} {o}:{r.get('id.orig_p')} -> "
                             f"{d}:{r.get('id.resp_p')} {r.get('proto')} "
                             f"dur={r.get('duration')} out={ob} in={rb} {r.get('conn_state')}")
            if lo and not lr:                       # internal -> external (exfil/C2)
                agg = exfil.setdefault(d, [0, 0]); agg[0] += int(ob); agg[1] += 1
            elif lr and not lo:                     # external -> internal (inbound)
                inbound[o] = inbound.get(o, 0) + 1

    if focus_ip:
        head = f"[conn flows involving {focus_ip}: {len(focus)} shown of {scanned} records]"
        return head + "\n" + ("\n".join(focus) or "  (none)")

    parts = [f"[Zeek conn: {scanned} flows across {len(files)} sensor(s)]"]
    top_exfil = sorted(exfil.items(), key=lambda kv: -kv[1][0])[:12]
    parts.append("\n== Top internal->external destinations by bytes SENT (exfil candidates) ==")
    parts += [f"  {dst}: {nbytes:,} bytes out over {cnt} flow(s)"
              + ("   [LARGE]" if nbytes >= 1_000_000 else "")
              for dst, (nbytes, cnt) in top_exfil] or ["  (none)"]
    top_in = sorted(inbound.items(), key=lambda kv: -kv[1])[:12]
    parts.append("\n== Top external->internal sources by flow count (inbound) ==")
    parts += [f"  {src}: {cnt} inbound flow(s)" for src, cnt in top_in] or ["  (none)"]
    return "\n".join(parts)


def file_hashes(roots, max_lines: int = 2_000_000, max_hits: int = 200) -> str:
    """Distinct transferred-file hashes (IOCs) with mime/size — md5/sha1/sha256."""
    files = _logs(roots, "files.json")
    if not files:
        return "[no Zeek files.json found in evidence scope]"
    seen: dict[str, dict] = {}
    scanned = 0
    for f in files:
        for r in _iter(f, max_lines):
            scanned += 1
            h = r.get("sha256") or r.get("sha1") or r.get("md5")
            if not h or h in seen:
                continue
            seen[h] = {"sha256": r.get("sha256"), "md5": r.get("md5"),
                       "mime": r.get("mime_type"), "bytes": r.get("seen_bytes"),
                       "ts": _ts(r.get("ts")), "rx": r.get("rx_hosts"), "tx": r.get("tx_hosts")}
            if len(seen) >= max_hits:
                break
    parts = [f"[Zeek files: {len(seen)} distinct file hashes of {scanned} records]"]
    # Surface script/executable/archive mime first — the likely tooling/payload IOCs.
    risky = ("script", "x-sh", "x-executable", "x-elf", "x-dosexec", "octet-stream",
             "zip", "gzip", "x-php", "java", "powershell")
    def is_risky(m): return any(k in (m or "").lower() for k in risky)
    rows = sorted(seen.values(), key=lambda r: (not is_risky(r["mime"]), r["ts"]))
    parts.append("| sha256 | mime | bytes | tx->rx | first seen |")
    parts.append("|---|---|---|---|---|")
    for r in rows[:60]:
        flag = "  ⚠" if is_risky(r["mime"]) else ""
        parts.append(f"| `{(r['sha256'] or r['md5'] or '')[:32]}…`{flag} | {r['mime']} | "
                     f"{r['bytes']} | {r.get('tx')}→{r.get('rx')} | {r['ts']} |")
    return "\n".join(parts)


def dns_summary(roots, max_lines: int = 2_000_000, top: int = 25) -> str:
    """Most-queried domains + a DGA/long-label heuristic flag."""
    files = _logs(roots, "dns.json")
    if not files:
        return "[no Zeek dns.json found in evidence scope]"
    import math
    counts: dict[str, int] = {}
    scanned = 0
    for f in files:
        for r in _iter(f, max_lines):
            scanned += 1
            q = r.get("query")
            if q:
                counts[q] = counts.get(q, 0) + 1

    def entropy(s: str) -> float:
        s = s.split(".")[0]
        return -sum((c := s.count(ch) / len(s)) * math.log2(c) for ch in set(s)) if s else 0.0

    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:top]
    parts = [f"[Zeek dns: {len(counts)} distinct queries of {scanned} records]"]
    for q, n in ranked:
        flag = "   [high-entropy/DGA?]" if len(q.split(".")[0]) >= 12 and entropy(q) >= 3.5 else ""
        parts.append(f"  {n:>6}  {q}{flag}")
    return "\n".join(parts)


def http_summary(roots, max_lines: int = 2_000_000, top: int = 25) -> str:
    """HTTP requests across the network: top hosts/URIs and non-browser User-Agents."""
    files = _logs(roots, "http.json")
    if not files:
        return "[no Zeek http.json found in evidence scope]"
    hosts: dict[str, int] = {}
    uas: dict[str, int] = {}
    posts: list[str] = []
    scanned = 0
    for f in files:
        for r in _iter(f, max_lines):
            scanned += 1
            h = r.get("host") or r.get("id.resp_h")
            if h:
                hosts[h] = hosts.get(h, 0) + 1
            ua = r.get("user_agent") or ""
            if ua:
                uas[ua] = uas.get(ua, 0) + 1
            if r.get("method") == "POST" and len(posts) < 30:
                posts.append(f"  {_ts(r.get('ts'))} {r.get('id.orig_h')} POST "
                             f"{r.get('host')}{r.get('uri')} -> {r.get('status_code')}")
    parts = [f"[Zeek http: {scanned} requests across {len(files)} sensor(s)]"]
    parts.append("\n== Top hosts ==")
    parts += [f"  {n:>6}  {h}" for h, n in sorted(hosts.items(), key=lambda kv: -kv[1])[:top]]
    parts.append("\n== Non-browser User-Agents (top) ==")
    nb = {u: n for u, n in uas.items() if not any(b in u for b in ("Mozilla", "Safari", "Chrome"))}
    parts += [f"  {n:>6}  {u}" for u, n in sorted(nb.items(), key=lambda kv: -kv[1])[:12]] or ["  (none)"]
    return "\n".join(parts)
