from dataclasses import dataclass

from fastapi import HTTPException, status

from app.domain.schemas import AgentName, Principal, Role

ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ANONYMOUS_CUSTOMER: frozenset({"samiir:chat", "appointment:request", "contact:create"}),
    Role.AUTHENTICATED_CUSTOMER: frozenset(
        {"samiir:chat", "appointment:own:manage", "customer:own:read"}
    ),
    Role.SALES_AGENT: frozenset({"crm:manage", "samiir:conversation:read"}),
    Role.SUPPORT_AGENT: frozenset({"samiir:conversation:manage"}),
    Role.SECURITY_ANALYST: frozenset({"security:event:read", "incident:triage", "fatma:analyze"}),
    Role.SECURITY_ENGINEER: frozenset(
        {
            "security:event:read",
            "incident:triage",
            "fatma:analyze",
            "scan:request",
            "finding:review",
            "defense:request",
        }
    ),
    Role.TENANT_ADMIN: frozenset({"tenant:user:manage", "integration:manage", "audit:read"}),
    Role.PLATFORM_ADMIN: frozenset({"platform:operate"}),
    Role.SYSTEM_SERVICE: frozenset({"internal:execute"}),
}
AGENT_TOOL_ALLOWLIST = {
    AgentName.SAMIIR: frozenset(
        {
            "knowledge.search",
            "crm.create_contact",
            "crm.create_opportunity",
            "calendar.availability",
            "calendar.book",
            "notifications.send",
        }
    ),
    AgentName.FATMA: frozenset(
        {
            "security.events.query",
            "incidents.create",
            "findings.update",
            "approvals.request",
            "notifications.security_send",
        }
    ),
}


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:
    def permissions(self, p: Principal) -> frozenset[str]:
        return p.permissions.union(*(ROLE_PERMISSIONS[r] for r in p.roles))

    def require(self, p: Principal, permission: str, tenant_id=None) -> None:
        if tenant_id is not None and p.tenant_id != tenant_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "resource not found")
        if permission not in self.permissions(p):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "permission denied")

    def authorize_tool(self, p: Principal, agent: AgentName, tool: str) -> PolicyDecision:
        if tool not in AGENT_TOOL_ALLOWLIST[agent]:
            return PolicyDecision(False, "tool is not registered for this agent")
        if agent is AgentName.FATMA and not (
            {Role.SECURITY_ANALYST, Role.SECURITY_ENGINEER, Role.SYSTEM_SERVICE} & p.roles
        ):
            return PolicyDecision(False, "security role required")
        return PolicyDecision(True, "allowlisted")
