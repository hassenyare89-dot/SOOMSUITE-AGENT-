"""Static service-to-service trust graph.

Every inbound internal call is authenticated with a short-lived Ed25519 JWT minted by the
calling service. This module decides (1) which callers a service accepts at all and (2) the
*permission ceiling* each caller may exercise on behalf of a principal.

The ceiling is what makes isolation independent of any single component behaving well: even if
the SAMIIR process were fully compromised and forged principal claims with security roles,
FATMA-side services would reject it because ``samiir-agent`` is not an accepted caller, and
SAMIIR-side services cap it at customer-facing permissions.
"""

from __future__ import annotations

from typing import Final

from platform_core.security.principal import AgentName, Role
from platform_core.security.rbac import ROLE_PERMISSIONS, P

GATEWAY_PUBLIC: Final = "api-gateway-public"
GATEWAY_ADMIN: Final = "api-gateway-admin"
SAMIIR_AGENT: Final = "samiir-agent"
FATMA_SOC: Final = "fatma-soc"
CRM: Final = "crm"
SCHEDULING: Final = "scheduling"
NOTIFICATIONS: Final = "notifications"
KNOWLEDGE: Final = "knowledge"
WHATSAPP: Final = "whatsapp"
SECURITY_INGEST: Final = "security-ingest"
SCANNER_CONTROLLER: Final = "scanner-controller"
APPROVALS: Final = "approvals"
AUDIT: Final = "audit"

ALL_SERVICES: Final = frozenset(
    {GATEWAY_PUBLIC, GATEWAY_ADMIN, SAMIIR_AGENT, FATMA_SOC, CRM, SCHEDULING, NOTIFICATIONS,
     KNOWLEDGE, WHATSAPP, SECURITY_INGEST, SCANNER_CONTROLLER, APPROVALS, AUDIT}
)

# Side of the platform each service belongs to. Cross-side edges are listed explicitly below.
SAMIIR_SIDE: Final = frozenset({GATEWAY_PUBLIC, SAMIIR_AGENT, CRM, SCHEDULING, KNOWLEDGE, WHATSAPP})
FATMA_SIDE: Final = frozenset({FATMA_SOC, SECURITY_INGEST, SCANNER_CONTROLLER, APPROVALS})

# receiver -> callers allowed to reach it at all
ACCEPTED_CALLERS: Final[dict[str, frozenset[str]]] = {
    SAMIIR_AGENT: frozenset({GATEWAY_PUBLIC, GATEWAY_ADMIN, WHATSAPP}),
    CRM: frozenset({SAMIIR_AGENT, GATEWAY_ADMIN, SCHEDULING, NOTIFICATIONS}),
    SCHEDULING: frozenset({SAMIIR_AGENT, GATEWAY_ADMIN}),
    KNOWLEDGE: frozenset({SAMIIR_AGENT, GATEWAY_ADMIN}),
    NOTIFICATIONS: frozenset({SAMIIR_AGENT, SCHEDULING, FATMA_SOC, GATEWAY_ADMIN, WHATSAPP}),
    WHATSAPP: frozenset({GATEWAY_PUBLIC, NOTIFICATIONS, GATEWAY_ADMIN, SAMIIR_AGENT}),
    # FATMA side: never reachable from SAMIIR-side services or the public gateway.
    FATMA_SOC: frozenset({GATEWAY_ADMIN, SECURITY_INGEST, SCANNER_CONTROLLER}),
    # The public gateway may only reach the signed-webhook ingestion routes (route-level check).
    SECURITY_INGEST: frozenset({GATEWAY_PUBLIC, GATEWAY_ADMIN, SCANNER_CONTROLLER}),
    SCANNER_CONTROLLER: frozenset({GATEWAY_ADMIN, FATMA_SOC}),
    APPROVALS: frozenset({GATEWAY_ADMIN, FATMA_SOC, SCANNER_CONTROLLER}),
    AUDIT: frozenset(ALL_SERVICES - {AUDIT}),
}

_CUSTOMER: Final = ROLE_PERMISSIONS[Role.ANONYMOUS_CUSTOMER] | ROLE_PERMISSIONS[
    Role.AUTHENTICATED_CUSTOMER
]
_ALL_HUMAN: Final = frozenset(p for p in P if p is not P.INTERNAL_EXECUTE)

# caller -> the maximum set of permissions it may exercise on behalf of any principal
CALLER_PERMISSION_CEILING: Final[dict[str, frozenset[P]]] = {
    GATEWAY_PUBLIC: _CUSTOMER,
    WHATSAPP: _CUSTOMER | {P.INTERNAL_EXECUTE},
    SAMIIR_AGENT: _CUSTOMER | {P.INTERNAL_EXECUTE},
    GATEWAY_ADMIN: _ALL_HUMAN,
    SCHEDULING: _CUSTOMER | {P.INTERNAL_EXECUTE},
    NOTIFICATIONS: frozenset({P.INTERNAL_EXECUTE}),
    FATMA_SOC: frozenset({P.INTERNAL_EXECUTE}),
    SECURITY_INGEST: frozenset({P.INTERNAL_EXECUTE}),
    SCANNER_CONTROLLER: frozenset({P.INTERNAL_EXECUTE}),
    APPROVALS: frozenset({P.INTERNAL_EXECUTE}),
    CRM: frozenset({P.INTERNAL_EXECUTE}),
    KNOWLEDGE: frozenset(),
    AUDIT: frozenset(),
}

AGENT_FOR_SERVICE: Final[dict[str, AgentName]] = {
    SAMIIR_AGENT: AgentName.SAMIIR,
    FATMA_SOC: AgentName.FATMA,
}


def accepted_callers(receiver: str) -> frozenset[str]:
    return ACCEPTED_CALLERS.get(receiver, frozenset())


def ceiling_for(caller: str) -> frozenset[P]:
    return CALLER_PERMISSION_CEILING.get(caller, frozenset())
