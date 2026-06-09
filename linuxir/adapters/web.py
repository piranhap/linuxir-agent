"""Web access-log analysis (Apache/nginx combined format).

Finds web access logs in the evidence (``web_access.log`` / ``access_log`` …, discovered
collection-aware) and surfaces the web-attack story: which client IP fired attack-signature
requests (SQLi / traversal / RCE / known plugin exploits / web-shell access), the first
successful exploit, web-shell candidates (an uploaded ``.php`` hit with a command parameter),
and reverse-shell patterns in request queries. Requests are streamed (these logs can be
hundreds of MB — far past the small-file reader's cap), bounded by ``max_lines``.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote

from .discover import discover

_WEB_GLOBS = ("web_access.log", "access_log", "access.log", "access_log.[0-9]",
              "access.log.[0-9]", "ssl_access.log")

# Combined log: IP - - [time] "METHOD path proto" status size "ref" "ua"
import re
_LINE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<t>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"'
    r'\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"')

# (label, regex over the URL-decoded request path+query)
_SIGNATURES: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("sqli", re.compile(r"union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(|benchmark\(|information_schema", re.I)),
    ("traversal/LFI", re.compile(r"\.\./|/etc/passwd|/proc/self|php://|file://", re.I)),
    ("rce/cmd", re.compile(r";\s*(id|uname|whoami|cat|bash|sh|wget|curl)\b|\bcmd=|\bexec=|/bin/(ba)?sh|nc\s|\|\s*(ba)?sh", re.I)),
    ("reverse-shell", re.compile(r"/dev/tcp/|bash\s+-i|mkfifo|0>&1|\bnc\b.*\b-e\b", re.I)),
    ("plugin-exploit", re.compile(r"revslider|fckeditor|tinymce|timthumb|admin-ajax\.php\?action=", re.I)),
    ("webshell-name", re.compile(r"(?:c99|r57|wso|b374k|weevely)\.ph(p|tml)|/(shell|cmd|backdoor)\.php", re.I)),
    ("upload", re.compile(r"/wp-content/uploads/.*\.ph(p|tml)|/uploads/.*\.ph(p|tml)", re.I)),
)
_SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|gobuster|dirb|wpscan|masscan|hydra|nuclei|"
                         r"feroxbuster|wfuzz|python-requests|go-http-client|curl/", re.I)
# A web-shell command invocation: an uploaded .php hit with a command-ish query param.
_SHELL_CALL = re.compile(r"\.ph(p|tml)\?.*\b(x|c|cmd|exec|q|e|0|shell)=", re.I)


def parse_access(roots: list[Path], max_lines: int = 5_000_000) -> str:
    files = discover(roots, _WEB_GLOBS)
    if not files:
        return "[no web access logs found in evidence scope]"

    by_ip_total: dict[str, int] = {}
    attack_by_ip: dict[str, int] = {}
    hits: list[str] = []           # attack-signature request lines (capped)
    shell_calls: list[str] = []    # web-shell command invocations
    scanners: dict[str, int] = {}
    processed = 0

    for f in files:
        try:
            fh = f.open("r", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                processed += 1
                if processed > max_lines:
                    break
                m = _LINE.match(line)
                if not m:
                    continue
                ip = m["ip"]
                by_ip_total[ip] = by_ip_total.get(ip, 0) + 1
                decoded = unquote(m["path"])
                ua = m["ua"]
                if _SCANNER_UA.search(ua):
                    scanners[ua] = scanners.get(ua, 0) + 1
                labels = [lbl for lbl, rx in _SIGNATURES if rx.search(decoded)]
                if labels:
                    attack_by_ip[ip] = attack_by_ip.get(ip, 0) + 1
                    if len(hits) < 80:
                        hits.append(f"  {m['t']} {ip} {m['method']} \"{decoded}\" "
                                    f"-> {m['status']}  [{', '.join(labels)}]")
                if _SHELL_CALL.search(decoded) and m["status"] == "200":
                    if len(shell_calls) < 40:
                        shell_calls.append(f"  {m['t']} {ip} {m['method']} \"{decoded}\" -> 200")

    parts = [f"[web access analysis: {processed} requests across {len(files)} log(s); "
             f"{sum(attack_by_ip.values())} attack-signature request(s)]",
             "files: " + ", ".join(str(f) for f in files)]

    # Confirmed operators: any IP that successfully invoked a web shell.
    operator_ips = sorted({c.split()[2] for c in shell_calls})
    if operator_ips:
        parts.append("\n== CONFIRMED web-shell operator IP(s) ==")
        parts += [f"  {ip}  (executed commands via an uploaded web shell — HTTP 200)"
                  for ip in operator_ips]

    if attack_by_ip:
        # Rank by attack *ratio* (attacks / total): a low-volume IP that is mostly attacks
        # is the attacker; high-volume app/load-balancer IPs with a few matches are noise.
        ranked = sorted(attack_by_ip.items(),
                        key=lambda kv: -(kv[1] / max(by_ip_total.get(kv[0], 1), 1)))
        parts.append("\n== Suspicious IPs (by attack-signature ratio) ==")
        parts += [f"  {ip}: {n}/{by_ip_total.get(ip, 0)} requests are attacks "
                  f"({100 * n / max(by_ip_total.get(ip, 1), 1):.1f}%)" for ip, n in ranked[:12]]
    parts.append("\n== Web-shell command invocations (uploaded .php?param=, HTTP 200) ==")
    parts += shell_calls or ["  (none detected)"]
    parts.append("\n== Attack-signature requests (sample) ==")
    parts += hits or ["  (none detected)"]
    if scanners:
        top = sorted(scanners.items(), key=lambda kv: -kv[1])[:6]
        parts.append("\n== Scanner / automated User-Agents ==")
        parts += [f"  {n}x  {ua}" for ua, n in top]
    return "\n".join(parts)
