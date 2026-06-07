"""Case configuration: what evidence is in scope and where output goes.

The :class:`CaseConfig` is the single source of truth for the two path domains the
:class:`~linuxir.guardrails.constraints.ConstraintEnforcer` enforces:

* ``evidence_scope`` — directories holding the evidence under analysis. **Read-only.**
  Every tool-call path argument must resolve inside one of these prefixes, and no tool
  may write/delete/modify anything here.
* ``workspace`` (vault + audit dir + corrections) — where the agent writes its notes,
  findings, audit log, and self-learning log. Writable.

Keeping the two domains explicit and separate is what lets the enforcer allow legitimate
report writes while still blocking any mutation of evidence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class CaseConfig:
    """Immutable description of a single investigation."""

    case_id: str
    evidence_scope: tuple[Path, ...]
    workspace: Path

    @property
    def vault_path(self) -> Path:
        """Obsidian-style notes vault (writable)."""
        return self.workspace / "vault"

    @property
    def audit_dir(self) -> Path:
        """Append-only JSONL audit logs (writable)."""
        return self.workspace / "audit"

    @property
    def corrections_dir(self) -> Path:
        """Self-learning / self-correction log (writable)."""
        return self.workspace / "Corrections"

    @property
    def writable_roots(self) -> tuple[Path, ...]:
        """Path prefixes the enforcer permits writes to."""
        return (self.vault_path, self.audit_dir, self.corrections_dir)

    def ensure_workspace(self) -> None:
        """Create the writable workspace directories (never touches evidence)."""
        for d in self.writable_roots:
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_yaml(cls, path: str | os.PathLike[str]) -> "CaseConfig":
        """Load a case from a YAML file.

        Expected shape::

            case_id: demo-001
            evidence_scope:
              - /mnt/evidence
            workspace: ./out/demo-001
        """
        raw = yaml.safe_load(Path(path).read_text())
        base = Path(path).resolve().parent
        scope = tuple(_resolve(base, p) for p in raw["evidence_scope"])
        workspace = _resolve(base, raw["workspace"])
        return cls(case_id=str(raw["case_id"]), evidence_scope=scope, workspace=workspace)


def _resolve(base: Path, p: str) -> Path:
    """Resolve ``p`` against ``base`` if relative, then canonicalize."""
    pp = Path(p)
    if not pp.is_absolute():
        pp = base / pp
    return pp.resolve()
