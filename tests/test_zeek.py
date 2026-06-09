"""Zeek-JSON adapter: external talkers/exfil, focus-IP flows, file-hash IOCs, DNS DGA."""

from __future__ import annotations

import json

from linuxir.adapters import zeek

C2 = "103.27.202.92"


def _write_zeek(tmp_path):
    z = tmp_path / "zeek-dmz-01"
    z.mkdir()
    conn = [
        {"ts": 1776197791, "id.orig_h": "10.42.20.20", "id.orig_p": 45191,
         "id.resp_h": C2, "id.resp_p": 443, "proto": "tcp", "duration": 18.9,
         "orig_bytes": 2_500_000, "resp_bytes": 100, "local_orig": True,
         "local_resp": False, "conn_state": "SF"},                         # exfil/C2 out
        {"ts": 1776197000, "id.orig_h": "203.0.113.9", "id.orig_p": 5555,
         "id.resp_h": "10.42.20.20", "id.resp_p": 80, "proto": "tcp",
         "orig_bytes": 200, "resp_bytes": 500, "local_orig": False,
         "local_resp": True, "conn_state": "SF"},                          # inbound
    ]
    (z / "conn.json").write_text("\n".join(json.dumps(r) for r in conn) + "\n")
    files = [{"ts": 1776197800, "fuid": "F1", "tx_hosts": [C2], "rx_hosts": ["10.42.20.20"],
              "mime_type": "application/x-sh", "seen_bytes": 320,
              "md5": "d41d8cd98f00b204e9800998ecf8427e", "sha1": "a", "sha256": "abc123" * 10}]
    (z / "files.json").write_text("\n".join(json.dumps(r) for r in files) + "\n")
    dns = [{"ts": 1776197805, "query": "kq3v9zx1c7mn4b8w.evil.example"},
           {"ts": 1776197806, "query": "www.google.com"}]
    (z / "dns.json").write_text("\n".join(json.dumps(r) for r in dns) + "\n")
    return tmp_path


def test_conn_summary_flags_exfil(tmp_path):
    out = zeek.conn_summary([_write_zeek(tmp_path)])
    assert C2 in out and "LARGE" in out          # 2.5MB sent out to external
    assert "203.0.113.9" in out                  # inbound source listed


def test_conn_focus_ip_lists_flows(tmp_path):
    out = zeek.conn_summary([_write_zeek(tmp_path)], focus_ip=C2)
    assert f"-> {C2}:443" in out and "10.42.20.20" in out


def test_file_hashes_ioc(tmp_path):
    out = zeek.file_hashes([_write_zeek(tmp_path)])
    assert "abcabc" in out.replace(" ", "")[:9999] or "abc123" in out
    assert "x-sh" in out and "⚠" in out          # script mime flagged as risky


def test_dns_dga_flag(tmp_path):
    out = zeek.dns_summary([_write_zeek(tmp_path)])
    assert "kq3v9zx1c7mn4b8w.evil.example" in out and "DGA" in out
    assert "www.google.com" in out


def test_no_zeek(tmp_path):
    assert zeek.conn_summary([tmp_path]).startswith("[no Zeek conn.json")
    assert zeek.file_hashes([tmp_path]).startswith("[no Zeek files.json")
