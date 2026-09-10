from uuid import uuid4

from app.core.policy import PolicyEngine
from app.domain.schemas import AgentName, Principal, Role


def principal(role):
    return Principal(subject="u", tenant_id=uuid4(), roles=frozenset({role}))


def test_samiir_cannot_call_fatma_tool():
    d = PolicyEngine().authorize_tool(
        principal(Role.SYSTEM_SERVICE), AgentName.SAMIIR, "security.events.query"
    )
    assert not d.allowed


def test_customer_cannot_access_fatma_even_by_prompt():
    p = principal(Role.ANONYMOUS_CUSTOMER)
    assert not PolicyEngine().authorize_tool(p, AgentName.FATMA, "security.events.query").allowed
