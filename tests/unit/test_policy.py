"""Tool authorization, RBAC, caller ceilings, MFA step-up and ABAC."""

from __future__ import annotations

import uuid

import pytest

from platform_core.errors import Forbidden, NotFound
from platform_core.security.policy import TOOL_REGISTRY, PolicyEngine
from platform_core.security.principal import ActorType, AgentName, Principal, Role
from platform_core.security.rbac import P
from platform_core.security.service_auth import RequestContext

T = uuid.uuid4()
policy = PolicyEngine()


def ctx(*roles: Role, caller: str = "api-gateway-admin", mfa: bool = True,
        actor: ActorType = ActorType.USER, contact: uuid.UUID | None = None,
        tenant: uuid.UUID = T) -> RequestContext:
    return RequestContext(caller=caller, receiver="x", request_id="r", principal=Principal(
        subject="u", tenant_id=tenant, actor_type=actor, roles=frozenset(roles), mfa=mfa,
        contact_id=contact))


def test_agents_share_no_tools():
    assert not set(TOOL_REGISTRY[AgentName.SAMIIR]) & set(TOOL_REGISTRY[AgentName.FATMA])


@pytest.mark.parametrize("tool", sorted(TOOL_REGISTRY[AgentName.FATMA]))
def test_samiir_service_can_never_run_fatma_tools(tool):
    c = ctx(Role.SECURITY_ENGINEER, Role.SYSTEM_SERVICE, caller="api-gateway-public")
    assert not policy.authorize_tool(c, "samiir-agent", AgentName.SAMIIR, tool).allowed
    assert not policy.authorize_tool(c, "samiir-agent", AgentName.FATMA, tool).allowed


@pytest.mark.parametrize("tool", sorted(TOOL_REGISTRY[AgentName.SAMIIR]))
def test_fatma_service_cannot_run_samiir_tools(tool):
    c = ctx(Role.SECURITY_ENGINEER)
    assert not policy.authorize_tool(c, "fatma-soc", AgentName.FATMA, tool).allowed


def test_customer_principal_cannot_use_fatma_even_in_fatma_process():
    c = ctx(Role.ANONYMOUS_CUSTOMER, caller="api-gateway-admin", actor=ActorType.CUSTOMER)
    d = policy.authorize_tool(c, "fatma-soc", AgentName.FATMA, "security.query_events")
    assert not d.allowed and d.reason == "customers_cannot_invoke_security_tools"


def test_forged_security_roles_are_capped_by_public_caller_ceiling():
    """Even if a compromised public gateway forged security roles, the ceiling strips them."""
    c = ctx(Role.SECURITY_ENGINEER, Role.TENANT_ADMIN, caller="api-gateway-public")
    assert policy.effective_permissions(c) <= {P.SAMIIR_CHAT, P.CONTACT_SUBMIT,
                                               P.APPOINTMENT_REQUEST, P.APPOINTMENT_OWN_MANAGE,
                                               P.CUSTOMER_OWN_READ}
    with pytest.raises(Forbidden):
        policy.require(c, P.SCAN_REQUEST)


def test_cross_tenant_is_not_found():
    with pytest.raises(NotFound):
        policy.require(ctx(Role.SECURITY_ENGINEER), P.INCIDENT_READ, tenant_id=uuid.uuid4())


def test_sensitive_permissions_need_mfa():
    with pytest.raises(Forbidden):
        policy.require(ctx(Role.SECURITY_ENGINEER, mfa=False), P.SCAN_APPROVE)
    policy.require(ctx(Role.SECURITY_ENGINEER, mfa=False), P.INCIDENT_READ)
    policy.require(ctx(Role.SECURITY_ENGINEER, mfa=True), P.SCAN_APPROVE)


def test_customer_ownership_abac():
    mine = uuid.uuid4()
    c = ctx(Role.AUTHENTICATED_CUSTOMER, caller="api-gateway-public", actor=ActorType.CUSTOMER,
            contact=mine)
    policy.require(c, P.APPOINTMENT_OWN_MANAGE, owner_contact_id=mine)
    with pytest.raises(NotFound):
        policy.require(c, P.APPOINTMENT_OWN_MANAGE, owner_contact_id=uuid.uuid4())


@pytest.mark.parametrize("role,perm,allowed", [
    (Role.ANONYMOUS_CUSTOMER, P.SAMIIR_CHAT, True),
    (Role.ANONYMOUS_CUSTOMER, P.CRM_READ, False),
    (Role.SALES_AGENT, P.CRM_WRITE, True),
    (Role.SALES_AGENT, P.INCIDENT_READ, False),
    (Role.SUPPORT_AGENT, P.CONVERSATION_MANAGE, True),
    (Role.SUPPORT_AGENT, P.CRM_WRITE, False),
    (Role.SECURITY_ANALYST, P.INCIDENT_TRIAGE, True),
    (Role.SECURITY_ANALYST, P.SCAN_REQUEST, False),
    (Role.SECURITY_ENGINEER, P.SCAN_REQUEST, True),
    (Role.SECURITY_ENGINEER, P.TENANT_USER_MANAGE, False),
    (Role.TENANT_ADMIN, P.TENANT_USER_MANAGE, True),
    (Role.TENANT_ADMIN, P.SCAN_REQUEST, False),
    (Role.PLATFORM_ADMIN, P.CRM_READ, False),
])
def test_role_matrix(role, perm, allowed):
    assert policy.check(ctx(role), perm).allowed is allowed
