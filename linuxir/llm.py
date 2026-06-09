"""LLM client abstraction: the real Anthropic SDK, plus a scriptable offline fake.

The agent loop depends only on a ``client.messages.create(...)`` surface that returns an
object with ``.stop_reason`` and ``.content`` (blocks exposing ``.type`` and, per type,
``.text`` or ``.id``/``.name``/``.input``). Both the real ``anthropic.Anthropic`` client
and :class:`FakeClient` satisfy that, so the entire pipeline — guardrails, agents, auditor,
reporting, audit log — can be exercised in tests and demos with zero API spend.

Models (per the project spec):
    * reasoning / coordinator agents → ``claude-opus-4-8`` (adaptive thinking, high effort)
    * the cheaper auditor pass        → ``claude-haiku-4-5`` (no adaptive thinking/effort)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

MODEL_REASONING = "claude-opus-4-8"
MODEL_AUDITOR = "claude-haiku-4-5"
MODEL_EXPERT = "claude-opus-4-8"  # senior IR-expert review pass


# -- minimal response shapes (mirror the SDK's attribute access) --------------------


@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict
    type: str = "tool_use"


@dataclass
class FakeMessage:
    content: list[Any]
    stop_reason: str  # "end_turn" | "tool_use"


class SupportsCreate(Protocol):
    def create(self, **kwargs: Any) -> Any: ...


class LLMClient(Protocol):
    @property
    def messages(self) -> SupportsCreate: ...


# -- real client --------------------------------------------------------------------


def get_client() -> LLMClient:
    """Return a real Anthropic client (reads ANTHROPIC_API_KEY from the environment).

    Imported lazily so offline tests never require the SDK to authenticate.
    """
    import anthropic

    return anthropic.Anthropic()


# -- offline fake -------------------------------------------------------------------

# A responder decides each turn's reply from the create() kwargs (model, system,
# messages, tools). This lets a test script realistic multi-turn behavior.
Responder = Callable[[dict], FakeMessage]


class _FakeMessages:
    def __init__(self, responder: Responder, calls: list[dict]) -> None:
        self._responder = responder
        self._calls = calls

    def create(self, **kwargs: Any) -> FakeMessage:
        self._calls.append(kwargs)
        return self._responder(kwargs)


@dataclass
class FakeClient:
    """A scriptable stand-in for ``anthropic.Anthropic``.

    Pass a ``responder`` that maps create() kwargs → :class:`FakeMessage`. The recorded
    ``calls`` list lets tests assert on what the agents asked for.
    """

    responder: Responder
    calls: list[dict] = field(default_factory=list)

    @property
    def messages(self) -> _FakeMessages:
        return _FakeMessages(self.responder, self.calls)


# -- helpers for writing responders / scripts ---------------------------------------


def text(s: str) -> FakeMessage:
    return FakeMessage(content=[TextBlock(text=s)], stop_reason="end_turn")


def tool_call(*calls: tuple[str, str, dict]) -> FakeMessage:
    """Build a tool_use turn from ``(id, name, input)`` tuples."""
    blocks = [ToolUseBlock(id=i, name=n, input=inp) for (i, n, inp) in calls]
    return FakeMessage(content=blocks, stop_reason="tool_use")
