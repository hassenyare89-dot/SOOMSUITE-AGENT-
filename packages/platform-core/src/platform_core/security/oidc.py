"""OIDC access/ID token validation for human users (SSO). Used only by the admin gateway."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient

from platform_core.errors import Unauthenticated

# RFC 8176 authentication method references that indicate MFA or phishing-resistant auth.
MFA_AMR_VALUES = frozenset({"mfa", "hwk", "swk", "otp", "fpt", "face", "pop", "webauthn"})


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    audience: str
    jwks_url: str
    tenant_claim: str = "tenant_id"
    roles_claim: str = "roles"


class OidcVerifier:
    def __init__(self, config: OidcConfig) -> None:
        self.config = config
        self._jwks = PyJWKClient(config.jwks_url, cache_keys=True, lifespan=300)

    async def verify(self, token: str) -> dict[str, Any]:
        try:
            key = await asyncio.to_thread(self._jwks.get_signing_key_from_jwt, token)
            return jwt.decode(
                token,
                key.key,
                algorithms=["RS256", "PS256", "ES256", "EdDSA"],
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except (jwt.PyJWTError, OSError) as exc:
            raise Unauthenticated("invalid identity token") from exc


def has_mfa(claims: dict[str, Any]) -> bool:
    amr = claims.get("amr") or []
    if isinstance(amr, str):
        amr = [amr]
    acr = str(claims.get("acr", ""))
    return bool(MFA_AMR_VALUES & set(amr)) or "mfa" in acr or "phr" in acr
