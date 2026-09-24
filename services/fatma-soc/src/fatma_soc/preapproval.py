"""Tenant pre-approved execution path for low-risk actions."""

from __future__ import annotations

import uuid

from fatma_soc.defense import DefenseService, action_payload
from platform_core.app import ServiceRuntime
from platform_core.errors import Forbidden
from platform_core.schemas.enums import (
    LOW_RISK_DEFENSE_ACTIONS,
    DefenseActionStatus,
    DefenseActionType,
    FatmaMode,
)
from platform_core.security.principal import Principal


def _defense(rt: ServiceRuntime) -> DefenseService:
    return rt.extras["defense"]


async def try_preapproved(rt: ServiceRuntime, tenant_id: uuid.UUID, action_id: uuid.UUID,
                          request_id: str) -> None:
    """Auto-execute a low-risk recommendation if (and only if) the approval service grants a
    tenant pre-approval for this exact payload."""
    async with rt.require_db().tenant_session(tenant_id, actor="agent:FATMA") as s:
        action = await _defense(rt).get(s, action_id)
        if action.mode != FatmaMode.PREAPPROVED_LOW_RISK.value or \
                DefenseActionType(action.action_type) not in LOW_RISK_DEFENSE_ACTIONS or \
                action.status != DefenseActionStatus.RECOMMENDED.value:
            return
        payload = action_payload(tenant_id, action)
        system = Principal.system(tenant_id, "fatma-soc")
        try:
            approval = await rt.client("approvals").post(
                "/internal/approvals/preapproved", principal=system, request_id=request_id,
                json={"action_type": payload["action_type"], "payload": payload,
                      "reason": action.rationale, "target_type": "waf_action",
                      "target_id": str(action.id)})
        except Forbidden:
            return
        action.approval_id = uuid.UUID(approval["id"])
        action.status = DefenseActionStatus.APPROVED.value
        await s.flush()
        await rt.client("approvals").post(
            f"/internal/approvals/{action.approval_id}/consume", principal=system,
            request_id=request_id, json={"action_type": payload["action_type"],
                                         "payload": payload})
        await _defense(rt).execute(s, action, "policy:preapproved")
