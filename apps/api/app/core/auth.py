from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends, Header, HTTPException, status
from jwt import PyJWKClient

from app.core.config import Settings, get_settings
from app.domain.schemas import Principal, Role


def principal_from_claims(claims: dict) -> Principal:
    try:
        return Principal(
            subject=claims["sub"],
            tenant_id=UUID(claims["tenant_id"]),
            roles=frozenset(Role(r) for r in claims.get("roles", [])),
            permissions=frozenset(claims.get("permissions", [])),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid identity claims") from exc


async def current_principal(
    authorization: Annotated[str | None, Header()] = None,
    settings: Settings = Depends(get_settings),
) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required")
    token = authorization.removeprefix("Bearer ")
    try:
        key = PyJWKClient(str(settings.jwt_jwks_url)).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256", "ES256"],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid access token") from exc
    return principal_from_claims(claims)


PrincipalDep = Annotated[Principal, Depends(current_principal)]
