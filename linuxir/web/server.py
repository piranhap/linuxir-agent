"""FastAPI app: the analyst-facing intake GUI and case status API.

Day-1 surface:

* ``GET  /``                 — single-page intake GUI
* ``POST /case/new``         — create a case; writes ``Evidence/case-state.md`` to the vault
* ``GET  /case/{id}/status`` — current :class:`~linuxir.casestore.CaseState` as JSON
* ``GET  /cases``            — list known case ids
* ``GET  /healthz``          — liveness + whether the Obsidian REST API is reachable

The pipeline (gateway/enforcer/agents) is intentionally *not* wired in here yet — Day 1's
gate is "browser form → note appears in Obsidian". Later days add /plan, /approve, and the
SSE run stream that drives the orchestrator.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ..casestore import CaseIntake, CaseStore
from ..obsidian import ObsidianServer

_STATIC = Path(__file__).parent / "static"


def _load_dotenv() -> None:
    """Minimal .env loader (no python-dotenv dependency). Does not override real env vars."""
    env = Path(".env")
    if not env.exists():
        return
    for line in env.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if key and key not in os.environ:
            os.environ[key] = val


def create_app() -> FastAPI:
    _load_dotenv()
    app = FastAPI(title="LinuxIR Agent", version="0.1.0")
    store = CaseStore()
    app.state.store = store

    if _STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        idx = _STATIC / "index.html"
        if not idx.exists():
            return JSONResponse({"error": "GUI not found"}, status_code=500)
        return FileResponse(str(idx))

    @app.get("/healthz")
    def healthz():
        probe = ObsidianServer(case_id="_probe", fallback_root=Path("."))
        return {
            "ok": True,
            "obsidian_configured": probe.enabled,
            "obsidian_reachable": probe.reachable(),
        }

    @app.post("/case/new")
    def case_new(intake: CaseIntake):
        entry = store.create(intake)
        s = entry.state
        return {
            "case_id": s.case_id,
            "phase": s.phase,
            "sources": s.sources,
            "workspace": s.workspace,
            "note": {"transport": s.obsidian_transport, "path": s.note_path},
        }

    @app.get("/case/{case_id}/status")
    def case_status(case_id: str):
        entry = store.get(case_id)
        if not entry:
            raise HTTPException(status_code=404, detail=f"Unknown case '{case_id}'")
        return entry.state.model_dump(mode="json")

    @app.get("/cases")
    def cases():
        return {"cases": store.list_ids()}

    return app


app = create_app()
