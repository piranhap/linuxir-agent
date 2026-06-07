"""Obsidian vault writer — Local REST API primary, local filesystem fallback.

The investigation's human-readable narrative lives in an Obsidian vault so an analyst can
open it, read the analysis in plain markdown, and add their own notes while the agents work.
This module is the single seam through which case notes are written.

Two transports:

* **REST** — the Obsidian *Local REST API* community plugin (default port 27123). Used when
  ``OBSIDIAN_API_KEY`` is set. Notes for a case are namespaced under ``cases/{case_id}/`` in
  the configured Obsidian vault.
* **local** — plain files under the case workspace vault (``CaseConfig.vault_path``). Used
  when the REST API is not configured *or* a REST call fails. This keeps the system fully
  functional with zero Obsidian setup (the hackathon-demo path) and is what the tests assert.

Every write returns a small dict reporting which transport actually persisted the note, so
the GUI can show the analyst whether their live Obsidian vault received it.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)


@dataclass
class WriteResult:
    ok: bool
    transport: str           # "rest" | "local"
    path: str                # vault-relative (rest) or absolute (local)
    detail: str = ""

    def as_dict(self) -> dict:
        return {"ok": self.ok, "transport": self.transport, "path": self.path, "detail": self.detail}


class ObsidianServer:
    """Writes/reads case notes. REST when configured & reachable, else local files."""

    def __init__(
        self,
        case_id: str,
        fallback_root: Path,
        host: str | None = None,
        api_key: str | None = None,
        timeout: float = 4.0,
    ) -> None:
        self.case_id = case_id
        self.fallback_root = Path(fallback_root)
        self.host = (host or os.getenv("OBSIDIAN_HOST", "http://localhost:27123")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.getenv("OBSIDIAN_API_KEY", "")
        self.timeout = timeout
        self.enabled = bool(self.api_key)
        # REST notes are namespaced per case so multiple investigations share one vault.
        self.vault_prefix = f"cases/{case_id}"

    # ---- public API -------------------------------------------------------

    def write(self, rel_path: str, content: str) -> WriteResult:
        """Create/overwrite a note. Tries REST (if enabled), falls back to local on failure."""
        rel_path = rel_path.lstrip("/")
        if self.enabled:
            res = self._rest_put(rel_path, content)
            if res.ok:
                return res
            logger.warning("Obsidian REST write failed (%s); falling back to local file", res.detail)
        return self._local_write(rel_path, content)

    def append(self, rel_path: str, content: str) -> WriteResult:
        existing = self.read(rel_path) or ""
        return self.write(rel_path, existing + content)

    def read(self, rel_path: str) -> str:
        rel_path = rel_path.lstrip("/")
        if self.enabled:
            text = self._rest_get(rel_path)
            if text is not None:
                return text
        return self._local_read(rel_path)

    def reachable(self) -> bool:
        """Best-effort liveness check for the REST API (used by the GUI / status)."""
        if not self.enabled:
            return False
        try:
            r = httpx.get(f"{self.host}/", headers=self._headers, timeout=self.timeout)
            return r.status_code < 500
        except Exception:
            return False

    # ---- REST transport ---------------------------------------------------

    @property
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    def _rest_url(self, rel_path: str) -> str:
        return f"{self.host}/vault/{self.vault_prefix}/{rel_path}"

    def _rest_put(self, rel_path: str, content: str) -> WriteResult:
        try:
            r = httpx.put(
                self._rest_url(rel_path),
                content=content.encode("utf-8"),
                headers={**self._headers, "Content-Type": "text/markdown"},
                timeout=self.timeout,
            )
            if r.status_code in (200, 201, 204):
                return WriteResult(True, "rest", f"{self.vault_prefix}/{rel_path}")
            return WriteResult(False, "rest", rel_path, f"HTTP {r.status_code}")
        except Exception as e:  # network down, plugin off, etc.
            return WriteResult(False, "rest", rel_path, str(e))

    def _rest_get(self, rel_path: str) -> str | None:
        try:
            r = httpx.get(self._rest_url(rel_path), headers=self._headers, timeout=self.timeout)
            return r.text if r.status_code == 200 else None
        except Exception:
            return None

    # ---- local fallback ---------------------------------------------------

    def _local_path(self, rel_path: str) -> Path:
        return self.fallback_root / rel_path

    def _local_write(self, rel_path: str, content: str) -> WriteResult:
        path = self._local_path(rel_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return WriteResult(True, "local", str(path))

    def _local_read(self, rel_path: str) -> str:
        path = self._local_path(rel_path)
        return path.read_text(encoding="utf-8") if path.exists() else ""
