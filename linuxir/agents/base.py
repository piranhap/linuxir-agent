"""The ``Agent`` definition — a persona over a scoped subset of read-only tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..gateway import ToolGateway
from ..llm import MODEL_REASONING
from .loop import AgentResult, run_agent


@dataclass
class Agent:
    """A specialist (or coordinator) agent.

    ``tool_names`` scopes which gateway tools this agent may call — a disk agent gets the
    filesystem tools, the network agent gets pcap tools, etc. The gateway still enforces
    read-only behavior regardless, but scoping keeps each agent's context focused.
    """

    name: str
    system: str
    tool_names: list[str]
    model: str = MODEL_REASONING
    thinking: bool = True
    effort: str | None = "high"
    max_turns: int = 12

    def run(self, client: Any, gateway: ToolGateway, task: str) -> AgentResult:
        return run_agent(
            client,
            agent_name=self.name,
            system=self.system,
            tool_names=self.tool_names,
            task=task,
            gateway=gateway,
            model=self.model,
            thinking=self.thinking,
            effort=self.effort,
            max_turns=self.max_turns,
        )
