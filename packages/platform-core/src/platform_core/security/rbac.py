"""Role → permission mapping. This table is the single source of truth for RBAC.

The dashboard's "Roles" page renders it read-only; changing it requires a code review.
"""

from __future__ import annotations

from enum import StrEnum

from platform_core.security.principal import Role


class P(StrEnum):
    # --- customer / SAMIIR surface -------------------------------------------------
    SAMIIR_CHAT = "samiir:chat"
    CONTACT_SUBMIT = "contact:submit"
    APPOINTMENT_REQUEST = "appointment:request"
    APPOINTMENT_OWN_MANAGE = "appointment:own:manage"
    CUSTOMER_OWN_READ = "customer:own:read"
    # --- CRM / support -------------------------------------------------------------
    CRM_READ = "crm:read"
    CRM_WRITE = "crm:write"
    CONVERSATION_READ = "conversation:read"
    CONVERSATION_MANAGE = "conversation:manage"
    APPOINTMENT_READ = "appointment:read"
    APPOINTMENT_MANAGE = "appointment:manage"
    KNOWLEDGE_READ = "knowledge:read"
    KNOWLEDGE_WRITE = "knowledge:write"
    KNOWLEDGE_APPROVE = "knowledge:approve"
    CHANNEL_READ = "channel:read"
    # --- security / FATMA surface --------------------------------------------------
    SECURITY_EVENT_READ = "security:event:read"
    INCIDENT_READ = "incident:read"
    INCIDENT_TRIAGE = "incident:triage"
    INCIDENT_CONFIRM = "incident:confirm"
    ASSET_READ = "asset:read"
    ASSET_MANAGE = "asset:manage"
    FINDING_READ = "finding:read"
    FINDING_REVIEW = "finding:review"
    SCAN_READ = "scan:read"
    SCAN_REQUEST = "scan:request"
    SCAN_APPROVE = "scan:approve"
    MALWARE_READ = "malware:read"
    MALWARE_SUBMIT = "malware:submit"
    DEFENSE_READ = "defense:read"
    DEFENSE_REQUEST = "defense:request"
    DEFENSE_APPROVE = "defense:approve"
    DEFENSE_EXECUTE = "defense:execute"
    FATMA_ASK = "fatma:ask"
    APPROVAL_READ = "approval:read"
    # --- administration ------------------------------------------------------------
    TENANT_USER_MANAGE = "tenant:user:manage"
    TENANT_INTEGRATION_MANAGE = "tenant:integration:manage"
    TENANT_SETTINGS_MANAGE = "tenant:settings:manage"
    AUDIT_READ = "audit:read"
    AGENT_CONFIG_MANAGE = "agent:config:manage"
    APPROVAL_POLICY_MANAGE = "approval:policy:manage"
    PLATFORM_OPERATE = "platform:operate"
    PLATFORM_TENANT_MANAGE = "platform:tenant:manage"
    # --- internal ------------------------------------------------------------------
    INTERNAL_EXECUTE = "internal:execute"


_CRM_READ_SET = {P.CRM_READ, P.CONVERSATION_READ, P.APPOINTMENT_READ, P.KNOWLEDGE_READ,
                 P.CHANNEL_READ}
_SEC_READ_SET = {P.SECURITY_EVENT_READ, P.INCIDENT_READ, P.ASSET_READ, P.FINDING_READ,
                 P.SCAN_READ, P.MALWARE_READ, P.DEFENSE_READ, P.APPROVAL_READ}

ROLE_PERMISSIONS: dict[Role, frozenset[P]] = {
    Role.ANONYMOUS_CUSTOMER: frozenset({P.SAMIIR_CHAT, P.CONTACT_SUBMIT, P.APPOINTMENT_REQUEST}),
    Role.AUTHENTICATED_CUSTOMER: frozenset(
        {P.SAMIIR_CHAT, P.CONTACT_SUBMIT, P.APPOINTMENT_REQUEST, P.APPOINTMENT_OWN_MANAGE,
         P.CUSTOMER_OWN_READ}
    ),
    Role.SALES_AGENT: frozenset(
        _CRM_READ_SET | {P.CRM_WRITE, P.APPOINTMENT_MANAGE, P.CONVERSATION_MANAGE}
    ),
    Role.SUPPORT_AGENT: frozenset(_CRM_READ_SET | {P.CONVERSATION_MANAGE, P.APPOINTMENT_MANAGE}),
    Role.SECURITY_ANALYST: frozenset(
        _SEC_READ_SET | {P.INCIDENT_TRIAGE, P.MALWARE_SUBMIT, P.FATMA_ASK}
    ),
    Role.SECURITY_ENGINEER: frozenset(
        _SEC_READ_SET
        | {P.INCIDENT_TRIAGE, P.INCIDENT_CONFIRM, P.MALWARE_SUBMIT, P.FATMA_ASK, P.ASSET_MANAGE,
           P.FINDING_REVIEW, P.SCAN_REQUEST, P.SCAN_APPROVE, P.DEFENSE_REQUEST,
           P.DEFENSE_APPROVE, P.DEFENSE_EXECUTE}
    ),
    Role.TENANT_ADMIN: frozenset(
        _CRM_READ_SET
        | {P.KNOWLEDGE_WRITE, P.KNOWLEDGE_APPROVE, P.TENANT_USER_MANAGE,
           P.TENANT_INTEGRATION_MANAGE, P.TENANT_SETTINGS_MANAGE, P.AUDIT_READ,
           P.AGENT_CONFIG_MANAGE, P.APPROVAL_POLICY_MANAGE, P.APPROVAL_READ,
           P.DEFENSE_APPROVE, P.ASSET_READ, P.ASSET_MANAGE}
    ),
    Role.PLATFORM_ADMIN: frozenset({P.PLATFORM_OPERATE, P.PLATFORM_TENANT_MANAGE, P.AUDIT_READ}),
    Role.SYSTEM_SERVICE: frozenset({P.INTERNAL_EXECUTE}),
}

# Permissions that require the session to have completed MFA / passkey authentication.
MFA_REQUIRED: frozenset[P] = frozenset(
    {P.INCIDENT_CONFIRM, P.ASSET_MANAGE, P.SCAN_REQUEST, P.SCAN_APPROVE, P.DEFENSE_REQUEST,
     P.DEFENSE_APPROVE, P.DEFENSE_EXECUTE, P.TENANT_USER_MANAGE, P.TENANT_INTEGRATION_MANAGE,
     P.TENANT_SETTINGS_MANAGE, P.AGENT_CONFIG_MANAGE, P.APPROVAL_POLICY_MANAGE,
     P.KNOWLEDGE_APPROVE, P.PLATFORM_OPERATE, P.PLATFORM_TENANT_MANAGE}
)


def permissions_for(roles: frozenset[Role]) -> frozenset[P]:
    out: set[P] = set()
    for role in roles:
        out |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(out)
