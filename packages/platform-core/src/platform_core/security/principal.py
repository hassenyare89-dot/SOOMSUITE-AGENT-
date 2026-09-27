"""Identities: human principals, customers and services."""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class Role(StrEnum):
    ANONYMOUS_CUSTOMER = "anonymous_customer"
    AUTHENTICATED_CUSTOMER = "authenticated_customer"
    SALES_AGENT = "sales_agent"
    SUPPORT_AGENT = "support_agent"
    SECURITY_ANALYST = "security_analyst"
    SECURITY_ENGINEER = "security_engineer"
    TENANT_ADMIN = "tenant_admin"
    PLATFORM_ADMIN = "platform_admin"
    SYSTEM_SERVICE = "system_service"


class ActorType(StrEnum):
    CUSTOMER = "customer"
    USER = "user"
    AGENT = "agent"
    SERVICE = "service"


class AgentName(StrEnum):
    SAMIIR = "SAMIIR"
    FATMA = "FATMA"


CUSTOMER_ROLES = frozenset({Role.ANONYMOUS_CUSTOMER, Role.AUTHENTICATED_CUSTOMER})
SECURITY_ROLES = frozenset({Role.SECURITY_ANALYST, Role.SECURITY_ENGINEER})


class Principal(BaseModel):
    """The *human or customer* on whose behalf a request runs.

    Principals are created only by the gateways (after authenticating a session) or by
    service ingress points that authenticate a channel (e.g. a Meta-signed WhatsApp webhook).
    Downstream services receive them inside signed service tokens and never from request bodies.
    """

    model_config = ConfigDict(frozen=True)

    subject: str = Field(min_length=1, max_length=256)
    tenant_id: UUID
    actor_type: ActorType
    roles: frozenset[Role]
    session_id: str | None = None
    mfa: bool = False
    # Verified contact reference for authenticated customers (ownership checks, ABAC).
    contact_id: UUID | None = None
    display_name: str | None = None

    @property
    def is_customer(self) -> bool:
        return bool(self.roles & CUSTOMER_ROLES)

    def to_claims(self) -> dict:
        return {
            "sub": self.subject,
            "tid": str(self.tenant_id),
            "typ": self.actor_type.value,
            "roles": sorted(r.value for r in self.roles),
            "sid": self.session_id,
            "mfa": self.mfa,
            "cid": str(self.contact_id) if self.contact_id else None,
            "name": self.display_name,
        }

    @classmethod
    def from_claims(cls, claims: dict) -> Principal:
        return cls(
            subject=claims["sub"],
            tenant_id=UUID(claims["tid"]),
            actor_type=ActorType(claims["typ"]),
            roles=frozenset(Role(r) for r in claims.get("roles", [])),
            session_id=claims.get("sid"),
            mfa=bool(claims.get("mfa", False)),
            contact_id=UUID(claims["cid"]) if claims.get("cid") else None,
            display_name=claims.get("name"),
        )

    @classmethod
    def system(cls, tenant_id: UUID, service: str) -> Principal:
        return cls(
            subject=f"service:{service}",
            tenant_id=tenant_id,
            actor_type=ActorType.SERVICE,
            roles=frozenset({Role.SYSTEM_SERVICE}),
            mfa=True,
        )
