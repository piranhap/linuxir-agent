"""The ToolGateway — the one chokepoint every tool call passes through.

``dispatch`` is called for *every* tool the model requests, in every agent. Its contract:

    enforce (ConstraintEnforcer)  →  audit-log  →  run handler  →  audit-log result

If the enforcer raises :class:`SpoliationViolation`, the handler never runs: the call is
logged to the spoliation stream and a structured "blocked" string is returned to the model.
This ordering is the architectural guarantee — there is no path from a model tool request
to a subprocess that bypasses ``enforcer.check``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
import uuid

from .audit import JSONLAuditLogger
from .config import CaseConfig
from .findings import Finding
from .guardrails.constraints import ConstraintEnforcer, SpoliationViolation
from .selfcorrect import Correction, recovery_hint

BLOCKED_PREFIX = "BLOCKED by ConstraintEnforcer:"


@dataclass
class ToolContext:
    """Shared state handlers may read/append to (evidence config + findings store)."""

    case: CaseConfig
    audit: JSONLAuditLogger
    findings: list[Finding] = field(default_factory=list)
    corrections: list[Correction] = field(default_factory=list)


# A handler receives the validated tool input and the shared context, returns text.
Handler = Callable[[dict, ToolContext], str]


@dataclass(frozen=True)
class ToolSpec:
    """A registered, read-only tool and the metadata the enforcer needs to vet it."""

    name: str
    description: str
    input_schema: dict
    handler: Handler
    path_params: tuple[str, ...] = ()
    command_params: tuple[str, ...] = ()
    arg_params: tuple[str, ...] = ()

    def anthropic_schema(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


class ToolGateway:
    """Registry + enforced dispatcher for all forensic tools."""

    def __init__(self, case: CaseConfig, audit: JSONLAuditLogger) -> None:
        self.case = case
        self.audit = audit
        self.context = ToolContext(case=case, audit=audit)
        self.enforcer = ConstraintEnforcer(
            evidence_scope=case.evidence_scope,
            writable_roots=case.writable_roots,
        )
        self._tools: dict[str, ToolSpec] = {}

    # -- registration -------------------------------------------------------------

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def register_all(self, specs: list[ToolSpec]) -> None:
        for s in specs:
            self.register(s)

    def schemas_for(self, names: list[str]) -> list[dict]:
        """Anthropic tool schemas for a named subset (an agent's allowed tools)."""
        return [self._tools[n].anthropic_schema() for n in names if n in self._tools]

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools)

    @property
    def specs(self) -> list[ToolSpec]:
        """All registered tool specs (used to build the in-process MCP server)."""
        return list(self._tools.values())

    # -- the chokepoint -----------------------------------------------------------

    def dispatch(self, tool_name: str, tool_input: dict, *, agent: str | None = None) -> str:
        """Validate, log, and (if permitted) execute a single tool call."""
        call_id = str(uuid.uuid4())
        self.context.current_tool_call_id = call_id
        
        spec = self._tools.get(tool_name)
        try:
            self.enforcer.check(
                tool_name,
                tool_input,
                is_registered=spec is not None,
                path_params=spec.path_params if spec else (),
                command_params=spec.command_params if spec else (),
                arg_params=spec.arg_params if spec else (),
            )
        except SpoliationViolation as exc:
            self.audit.log_call(
                tool_call_id=call_id,
                tool=tool_name,
                tool_input=tool_input,
                decision="blocked",
                agent=agent,
                detail=exc.reason,
            )
            self.audit.log_spoliation(
                tool=tool_name, tool_input=tool_input, reason=exc.reason, agent=agent
            )
            return f"{BLOCKED_PREFIX} {exc.reason}"

        # Permitted — run the handler. (spec is non-None here: unregistered tools are
        # rejected by the enforcer above.)
        assert spec is not None
        try:
            result = spec.handler(tool_input, self.context)
        except Exception as exc:  # adapter errors are reported, not fatal
            self.audit.log_call(
                tool_call_id=call_id,
                tool=tool_name,
                tool_input=tool_input,
                decision="error",
                agent=agent,
                detail=repr(exc),
            )
            return f"[tool error] {tool_name}: {exc!r}"

        self.audit.log_call(
            tool_call_id=call_id,
            tool=tool_name, 
            tool_input=tool_input, 
            decision="allowed", 
            agent=agent
        )
        result = result if isinstance(result, str) else str(result)

        # Self-correction: if the result matches a known failure shape, record the
        # remediation and append it so the model is prompted to recover next turn.
        if correction := recovery_hint(tool_name, result):
            self.context.corrections.append(correction)
            self.audit.log_event(
                kind="self_correction", agent=agent, tool=tool_name,
                trigger=correction.trigger,
            )
            result = f"{result}\n\n[self-correction] {correction.hint}"
        return result


def is_blocked(result: str) -> bool:
    """True if a dispatch result is a guardrail block."""
    return result.startswith(BLOCKED_PREFIX)
