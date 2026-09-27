from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from samiir_agent.tools import RunState, ToolGateway


@dataclass
class AgentResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    model: str | None = None
    guardrail_flags: list[str] = field(default_factory=list)


class AgentRuntime(Protocol):
    name: str

    async def run(self, gateway: ToolGateway, state: RunState, history: list[dict[str, str]],
                  message: str, company_name: str) -> AgentResult: ...
