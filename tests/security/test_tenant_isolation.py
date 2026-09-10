from uuid import uuid4

import pytest
from app.core.policy import PolicyEngine
from app.domain.schemas import Principal, Role
from fastapi import HTTPException


def test_cross_tenant_is_hidden():
    p = Principal(subject="u", tenant_id=uuid4(), roles=frozenset({Role.SECURITY_ENGINEER}))
    with pytest.raises(HTTPException) as exc:
        PolicyEngine().require(p, "scan:request", uuid4())
    assert exc.value.status_code == 404
