"""Day-1 web layer: browser intake -> case-state note in the vault.

Asserts the gate: POST /case/new creates a case, classifies its evidence sources,
writes ``Evidence/case-state.md`` to the (local-fallback) vault, and exposes status.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from linuxir.casestore import detect_source_type
from linuxir.web.server import create_app

EVIDENCE = Path(__file__).parent / "fixtures" / "evidence"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CASE_DIR", str(tmp_path))
    monkeypatch.delenv("OBSIDIAN_API_KEY", raising=False)  # force local fallback
    return TestClient(create_app())


def test_healthz(client):
    j = client.get("/healthz").json()
    assert j["ok"] is True
    assert j["obsidian_configured"] is False  # no key -> local fallback


def test_case_new_writes_vault_note(client):
    payload = {
        "client_name": "Acme Corp",
        "industry": "Healthcare",
        "suspected_breach_date": "2022-03",
        "context": "SOC reported suspicious cron and outbound beaconing.",
        "evidence_paths": [str(EVIDENCE), str(EVIDENCE / "var/log/auth.log")],
    }
    r = client.post("/case/new", json=payload)
    assert r.status_code == 200, r.text
    j = r.json()

    assert j["case_id"].startswith("acme-corp-")
    assert j["phase"] == "intake"
    assert j["note"]["transport"] == "local"

    # source-type classification
    types = {s["path"]: s["type"] for s in j["sources"]}
    assert types[str(EVIDENCE)] == "mounted_image"
    assert types[str(EVIDENCE / "var/log/auth.log")] == "log_file"
    assert all(s["exists"] for s in j["sources"])

    # the note actually landed on disk and carries the case context
    note = Path(j["note"]["path"])
    assert note.exists() and note.name == "case-state.md"
    assert note.parent.name == "Evidence"
    body = note.read_text()
    assert "Acme Corp" in body and "read-only" in body.lower()


def test_status_and_404(client):
    j = client.post(
        "/case/new",
        json={"client_name": "Beta", "evidence_paths": [str(EVIDENCE)]},
    ).json()
    cid = j["case_id"]

    s = client.get(f"/case/{cid}/status")
    assert s.status_code == 200
    assert s.json()["case_id"] == cid

    assert cid in client.get("/cases").json()["cases"]
    assert client.get("/case/does-not-exist/status").status_code == 404


def test_intake_requires_evidence(client):
    r = client.post("/case/new", json={"client_name": "NoEvidence", "evidence_paths": []})
    assert r.status_code == 422  # pydantic min_length=1


def test_detect_source_type():
    assert detect_source_type(Path("/x/capture.pcap")) == "pcap"
    assert detect_source_type(Path("/x/mem.lime")) == "memory_capture"
    assert detect_source_type(Path("/x/auth.log")) == "log_file"
