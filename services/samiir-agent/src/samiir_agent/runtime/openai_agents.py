"""OpenAI Agents SDK runtime (Responses API, typed function tools, SDK guardrails).

The SDK drives the model loop; every tool invocation is delegated to ``ToolGateway`` so the
policy engine, schema validation, auditing and persistence apply exactly as in every other
code path. The model never receives credentials, slot tokens, or unfenced retrieved content.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from importlib import resources
from typing import Any

from agents import (
    Agent,
    FunctionTool,
    GuardrailFunctionOutput,
    InputGuardrailTripwireTriggered,
    ModelSettings,
    OutputGuardrailTripwireTriggered,
    RunConfig,
    RunContextWrapper,
    Runner,
    input_guardrail,
    output_guardrail,
    set_default_openai_api,
    set_default_openai_client,
    set_tracing_disabled,
)
from agents.strict_schema import ensure_strict_json_schema
from openai import AsyncOpenAI

from platform_core.observability import instruments
from samiir_agent.guardrails import SAFE_FALLBACK, SECURITY_REDIRECT, assess_input, check_grounding
from samiir_agent.runtime import AgentResult
from samiir_agent.tools import RunState, ToolGateway, ToolSpec


def _load_prompt() -> str:
    return resources.files("samiir_agent").joinpath("prompts/samiir_system.md").read_text()


@input_guardrail(name="security_operations_redirect")
async def _security_guardrail(ctx: RunContextWrapper[RunState], agent: Agent, data: Any
                              ) -> GuardrailFunctionOutput:
    text = data if isinstance(data, str) else str(data[-1].get("content", "")) if data else ""
    assessment = assess_input(text)
    return GuardrailFunctionOutput(output_info={"signals": list(assessment.signals)},
                                   tripwire_triggered=assessment.security_request)


@output_guardrail(name="grounding")
async def _grounding_guardrail(ctx: RunContextWrapper[RunState], agent: Agent, output: str
                               ) -> GuardrailFunctionOutput:
    result = check_grounding(str(output), ctx.context.grounding)
    return GuardrailFunctionOutput(output_info={"violations": list(result.violations)},
                                   tripwire_triggered=not result.ok)


class OpenAIAgentsRuntime:
    name = "openai-agents"

    def __init__(self, api_key: str, model: str, *, max_turns: int = 8,
                 tracing_enabled: bool = False) -> None:
        set_default_openai_client(AsyncOpenAI(api_key=api_key), use_for_tracing=tracing_enabled)
        set_default_openai_api("responses")
        set_tracing_disabled(not tracing_enabled)
        self.model = model
        self.max_turns = max_turns
        self.prompt = _load_prompt()

    def _tool(self, gateway: ToolGateway, spec: ToolSpec) -> FunctionTool:
        schema = ensure_strict_json_schema(spec.args.model_json_schema())

        async def invoke(tool_ctx: Any, args_json: str) -> str:
            return await gateway.invoke(tool_ctx.context, spec.name, args_json)

        return FunctionTool(name=spec.model_name, description=spec.description,
                            params_json_schema=schema, on_invoke_tool=invoke,
                            strict_json_schema=True, timeout_seconds=20)

    async def run(self, gateway: ToolGateway, state: RunState, history: list[dict[str, str]],
                  message: str, company_name: str) -> AgentResult:
        instructions = self.prompt.format(company_name=company_name,
                                          today=datetime.now(UTC).date().isoformat(),
                                          customer_timezone=state.customer_timezone)
        agent = Agent[RunState](
            name="SAMIIR",
            instructions=instructions,
            model=self.model,
            model_settings=ModelSettings(parallel_tool_calls=False, store=False,
                                         metadata={"agent": "SAMIIR"}),
            tools=[self._tool(gateway, spec) for spec in gateway.specs.values()],
            input_guardrails=[_security_guardrail],
            output_guardrails=[_grounding_guardrail],
        )
        items: list[Any] = [{"role": h["role"], "content": h["content"]} for h in history]
        items.append({"role": "user", "content": message})
        started = time.perf_counter()
        flags: list[str] = []
        try:
            result = await Runner.run(
                agent, items, context=state, max_turns=self.max_turns,
                run_config=RunConfig(workflow_name="samiir.chat",
                                     group_id=str(state.conversation_id),
                                     trace_include_sensitive_data=False,
                                     trace_metadata={"tenant": str(state.ctx.tenant_id)}))
            text = str(result.final_output)
            usage = result.context_wrapper.usage
            tokens_in, tokens_out = usage.input_tokens, usage.output_tokens
        except InputGuardrailTripwireTriggered:
            flags.append("security_request_redirected")
            text, tokens_in, tokens_out = SECURITY_REDIRECT, 0, 0
        except OutputGuardrailTripwireTriggered as exc:
            info = exc.guardrail_result.output.output_info or {}
            flags.extend(f"grounding:{v}" for v in info.get("violations", [])[:5])
            instruments().guardrail_trips.add(1, {"agent": "SAMIIR", "guardrail": "grounding"})
            state.escalated = True
            state.escalation_reason = "ungrounded answer blocked"
            text, tokens_in, tokens_out = SAFE_FALLBACK, 0, 0
        latency = (time.perf_counter() - started) * 1000
        instruments().llm_latency.record(latency, {"agent": "SAMIIR", "model": self.model})
        instruments().llm_tokens.add(tokens_in, {"agent": "SAMIIR", "kind": "input"})
        instruments().llm_tokens.add(tokens_out, {"agent": "SAMIIR", "kind": "output"})
        return AgentResult(text=text, input_tokens=tokens_in, output_tokens=tokens_out,
                           model=self.model, guardrail_flags=flags)
