"""Deterministic policy engine.

The language model never decides whether something is permitted. Every HTTP endpoint and
every agent tool invocation calls into this module, which evaluates:

1. tenant binding (cross-tenant → 404, indistinguishable from a missing object),
2. RBAC: principal roles → permissions,
3. caller ceiling: the calling service can only exercise a bounded permission set,
4. step-up: sensitive permissions require an MFA/passkey session,
5. ABAC: ownership rules for customer-scoped resources,
6. agent tool allowlists: a tool must be registered for the agent bound to the executing
   service identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from uuid import UUID

from platform_core.errors import Forbidden, NotFound
from platform_core.security.principal import ActorType, AgentName
from platform_core.security.rbac import MFA_REQUIRED, P, permissions_for
from platform_core.security.service_acl import AGENT_FOR_SERVICE, ceiling_for
from platform_core.security.service_auth import RequestContext


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    requires_approval: bool = False
    risk: RiskLevel = RiskLevel.LOW


@dataclass(frozen=True)
class ToolRule:
    name: str
    agent: AgentName
    any_of: frozenset[P]
    risk: RiskLevel
    requires_approval: bool = False
    description: str = ""


def _rule(name: str, agent: AgentName, perms: set[P], risk: RiskLevel = RiskLevel.LOW,
          requires_approval: bool = False, description: str = "") -> ToolRule:
    return ToolRule(name, agent, frozenset(perms), risk, requires_approval, description)


S, F = AgentName.SAMIIR, AgentName.FATMA

# The complete, static tool registry. A tool that is not listed here cannot run, whatever the
# model outputs. SAMIIR and FATMA share no tool names.
TOOL_REGISTRY: Final[dict[AgentName, dict[str, ToolRule]]] = {
    S: {
        r.name: r
        for r in [
            _rule("knowledge.search", S, {P.SAMIIR_CHAT}, description="approved KB search"),
            _rule("pricing.lookup", S, {P.SAMIIR_CHAT}, description="approved structured prices"),
            _rule("crm.capture_contact", S, {P.CONTACT_SUBMIT}),
            _rule("crm.qualify_lead", S, {P.CONTACT_SUBMIT}),
            _rule("calendar.check_availability", S, {P.APPOINTMENT_REQUEST}),
            _rule("calendar.book_appointment", S, {P.APPOINTMENT_REQUEST}, RiskLevel.MEDIUM),
            _rule("calendar.reschedule_appointment", S, {P.APPOINTMENT_REQUEST},
                  RiskLevel.MEDIUM),
            _rule("calendar.cancel_appointment", S, {P.APPOINTMENT_REQUEST}, RiskLevel.MEDIUM),
            _rule("conversation.escalate_to_human", S, {P.SAMIIR_CHAT}),
        ]
    },
    F: {
        r.name: r
        for r in [
            _rule("security.query_events", F, {P.SECURITY_EVENT_READ, P.INTERNAL_EXECUTE}),
            _rule("incidents.get", F, {P.INCIDENT_READ, P.INTERNAL_EXECUTE}),
            _rule("incidents.list_open", F, {P.INCIDENT_READ, P.INTERNAL_EXECUTE}),
            _rule("findings.list", F, {P.FINDING_READ, P.INTERNAL_EXECUTE}),
            _rule("assets.get", F, {P.ASSET_READ, P.INTERNAL_EXECUTE}),
            _rule("incidents.add_note", F, {P.INCIDENT_TRIAGE, P.INTERNAL_EXECUTE}),
            # Recommending never executes: it records a proposal and, for anything beyond the
            # tenant's pre-approved low-risk list, opens a human approval request.
            _rule("defense.recommend_action", F, {P.INCIDENT_TRIAGE, P.INTERNAL_EXECUTE},
                  RiskLevel.MEDIUM),
            _rule("notifications.notify_security_team", F,
                  {P.INCIDENT_TRIAGE, P.INTERNAL_EXECUTE}),
        ]
    },
}

# Capabilities that must never be exposed to any model as a tool.
FORBIDDEN_TOOL_PREFIXES: Final = (
    "shell", "exec", "scanner.run", "waf.apply", "firewall.", "dns.", "secrets.", "sql.",
    "http.fetch", "file.", "credentials.", "infra.",
)


def _validate_registry() -> None:
    seen: dict[str, AgentName] = {}
    for agent, tools in TOOL_REGISTRY.items():
        for name, rule in tools.items():
            if rule.agent is not agent:
                raise RuntimeError(f"tool {name} registered under wrong agent")
            if name in seen:
                raise RuntimeError(f"tool {name} shared between agents")
            if name.startswith(FORBIDDEN_TOOL_PREFIXES):
                raise RuntimeError(f"forbidden capability registered as tool: {name}")
            seen[name] = agent


_validate_registry()


class PolicyEngine:
    def effective_permissions(self, ctx: RequestContext) -> frozenset[P]:
        return permissions_for(ctx.principal.roles) & ceiling_for(ctx.caller)

    def check(
        self,
        ctx: RequestContext,
        permission: P,
        *,
        tenant_id: UUID | None = None,
        owner_contact_id: UUID | None = None,
    ) -> Decision:
        if tenant_id is not None and tenant_id != ctx.principal.tenant_id:
            return Decision(False, "tenant_mismatch")
        if permission not in self.effective_permissions(ctx):
            return Decision(False, "permission_missing")
        if (
            permission in MFA_REQUIRED
            and ctx.principal.actor_type is ActorType.USER
            and not ctx.principal.mfa
        ):
            return Decision(False, "mfa_required")
        if owner_contact_id is not None and ctx.principal.is_customer:
            if ctx.principal.contact_id != owner_contact_id:
                return Decision(False, "not_owner")
        return Decision(True, "allowed")

    def require(self, ctx: RequestContext, permission: P, **kwargs: UUID | None) -> None:
        decision = self.check(ctx, permission, **kwargs)
        if decision.allowed:
            return
        if decision.reason in {"tenant_mismatch", "not_owner"}:
            raise NotFound()
        raise Forbidden("step-up authentication required"
                        if decision.reason == "mfa_required" else None)

    def require_any(self, ctx: RequestContext, permissions: set[P]) -> None:
        if not any(self.check(ctx, p).allowed for p in permissions):
            raise Forbidden()

    def authorize_tool(self, ctx: RequestContext, executing_service: str, agent: AgentName,
                       tool_name: str) -> Decision:
        bound_agent = AGENT_FOR_SERVICE.get(executing_service)
        if bound_agent is None or bound_agent is not agent:
            return Decision(False, "service_not_bound_to_agent")
        rule = TOOL_REGISTRY[agent].get(tool_name)
        if rule is None:
            return Decision(False, "tool_not_registered_for_agent")
        if agent is AgentName.FATMA and ctx.principal.is_customer:
            return Decision(False, "customers_cannot_invoke_security_tools")
        if not (rule.any_of & self.effective_permissions(ctx)):
            return Decision(False, "principal_lacks_tool_permission")
        return Decision(True, "allowlisted", rule.requires_approval, rule.risk)


__all__ = ["TOOL_REGISTRY", "Decision", "PolicyEngine", "RiskLevel", "ToolRule"]
