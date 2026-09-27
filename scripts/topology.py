"""Single description of the service topology (used by the local runner; mirrored by
docker-compose.yml and the Helm chart). Each service gets only the secrets it needs."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Svc:
    name: str
    factory: str
    port: int
    db_role: str | None
    downstream: dict[str, str] = field(default_factory=dict)  # ENV_VAR -> service name
    secrets: tuple[str, ...] = ()
    extra: dict[str, str] = field(default_factory=dict)


ENC = ("FIELD_ENCRYPTION_KEYRING", "BLIND_INDEX_KEY")

SERVICES: list[Svc] = [
    Svc("api-gateway-public", "api_gateway.main:create_public", 8000, None,
        {"SAMIIR_URL": "samiir-agent", "WHATSAPP_URL": "whatsapp",
         "SECURITY_INGEST_URL": "security-ingest"}, ("CSRF_KEY",)),
    Svc("api-gateway-admin", "api_gateway.main:create_admin", 8001, "svc_gateway_admin",
        {"SAMIIR_URL": "samiir-agent", "CRM_URL": "crm", "SCHEDULING_URL": "scheduling",
         "KNOWLEDGE_URL": "knowledge", "NOTIFICATIONS_URL": "notifications",
         "WHATSAPP_URL": "whatsapp", "FATMA_URL": "fatma-soc",
         "SCANNER_CONTROLLER_URL": "scanner-controller", "SECURITY_INGEST_URL": "security-ingest",
         "APPROVALS_URL": "approvals", "AUDIT_READ_URL": "audit"}, ("CSRF_KEY", *ENC)),
    Svc("samiir-agent", "samiir_agent.main:create", 8101, "svc_samiir",
        {"KNOWLEDGE_URL": "knowledge", "CRM_URL": "crm", "SCHEDULING_URL": "scheduling",
         "NOTIFICATIONS_URL": "notifications", "WHATSAPP_URL": "whatsapp"},
        (*ENC, "SAMIIR_OPENAI_API_KEY")),
    Svc("crm", "crm_service.main:create", 8102, "svc_crm", {}, ENC),
    Svc("scheduling", "scheduling_service.main:create", 8103, "svc_scheduling",
        {"CRM_URL": "crm", "NOTIFICATIONS_URL": "notifications"}, ("SLOT_TOKEN_KEY",)),
    Svc("knowledge", "knowledge_service.main:create", 8104, "svc_knowledge", {}, ()),
    Svc("notifications", "notifications_service.main:create", 8105, "svc_notifications",
        {"CRM_URL": "crm", "WHATSAPP_URL": "whatsapp"}, ENC),
    Svc("whatsapp", "whatsapp_service.main:create", 8106, "svc_whatsapp",
        {"SAMIIR_URL": "samiir-agent", "NOTIFICATIONS_URL": "notifications"},
        ("META_APP_SECRET", "META_VERIFY_TOKEN")),
    Svc("fatma-soc", "fatma_soc.main:create", 8201, "svc_fatma",
        {"APPROVALS_URL": "approvals", "NOTIFICATIONS_URL": "notifications"},
        ("FATMA_OPENAI_API_KEY",)),
    Svc("security-ingest", "security_ingest.main:create", 8202, "svc_security_ingest",
        {"FATMA_URL": "fatma-soc"}, ("QUARANTINE_KEY", "PSEUDONYM_KEY", "INGEST_DEMO_SECRET")),
    Svc("scanner-controller", "scanner_controller.main:create", 8203, "svc_scanner_controller",
        {"APPROVALS_URL": "approvals", "FATMA_URL": "fatma-soc"}, ()),
    Svc("approvals", "approval_service.main:create", 8204, "svc_approvals", {}, ()),
    Svc("audit", "audit_service.main:create", 8205, "svc_audit", {}, ()),
]
