"""The manual, gated agentic loop shared by every agent.

This is deliberately a hand-rolled ``create → tool_use → dispatch → tool_result`` loop
rather than the SDK's beta tool runner. The reason is the whole point of the project:
**every tool call must pass through ``gateway.dispatch``**, where the ConstraintEnforcer
vets it before anything runs. A higher-level runner that executed tools itself would
bypass that chokepoint.

The loop also extracts findings the agent recorded (via the ``record_finding`` tool, which
appends to the gateway's shared context) and the final natural-language text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..findings import Finding
from ..gateway import ToolGateway


@dataclass
class AgentResult:
    agent: str
    final_text: str
    findings: list[Finding]
    turns: int
    messages: list[dict] = field(default_factory=list)


def run_agent(
    client: Any,
    *,
    agent_name: str,
    system: str,
    tool_names: list[str],
    task: str,
    gateway: ToolGateway,
    model: str,
    thinking: bool = False,
    effort: str | None = None,
    max_turns: int = 12,
    max_tokens: int = 16000,
) -> AgentResult:
    """Run one agent to completion over its allowed tool subset."""
    tools = gateway.schemas_for(tool_names)
    messages: list[dict] = [{"role": "user", "content": task}]

    # Findings recorded during this run are appended to the shared context; snapshot the
    # starting length so we can attribute *this agent's* findings.
    start = len(gateway.context.findings)

    final_text = ""
    turns = 0
    while turns < max_turns:
        turns += 1
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools
        if thinking:
            kwargs["thinking"] = {"type": "adaptive"}
        if effort:
            kwargs["output_config"] = {"effort": effort}

        response = client.messages.create(**kwargs)

        # Preserve the assistant turn verbatim (thinking + tool_use blocks must round-trip).
        messages.append({"role": "assistant", "content": response.content})

        text_parts = [b.text for b in response.content if getattr(b, "type", None) == "text"]
        if text_parts:
            final_text = "\n".join(text_parts)

        if response.stop_reason != "tool_use":
            break

        tool_results = []
        for block in response.content:
            if getattr(block, "type", None) != "tool_use":
                continue
            result = gateway.dispatch(block.name, dict(block.input), agent=agent_name)
            tool_results.append(
                {"type": "tool_result", "tool_use_id": block.id, "content": result}
            )
        messages.append({"role": "user", "content": tool_results})

    findings = gateway.context.findings[start:]
    for f in findings:
        if f.agent is None:
            f.agent = agent_name
    return AgentResult(
        agent=agent_name,
        final_text=final_text,
        findings=findings,
        turns=turns,
        messages=messages,
    )
