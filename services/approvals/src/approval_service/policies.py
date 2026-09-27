"""Approval policies per action type (code-reviewed; tenants may only make them stricter)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from platform_core.schemas.enums import LOW_RISK_DEFENSE_ACTIONS, DefenseActionType
from platform_core.security.policy import RiskLevel
from platform_core.security.rbac import P


@dataclass(frozen=True)
class ApprovalPolicy:
    risk: RiskLevel
    approver_permission: P
    ttl: timedelta
    preapprovable: bool = False
    max_preapproved_ttl_seconds: int = 0


POLICIES: dict[str, ApprovalPolicy] = {
    "scan.execute": ApprovalPolicy(RiskLevel.HIGH, P.SCAN_APPROVE, timedelta(hours=24)),
}
for action in DefenseActionType:
    low = action in LOW_RISK_DEFENSE_ACTIONS
    POLICIES[f"defense.{action.value}"] = ApprovalPolicy(
        RiskLevel.MEDIUM if low else RiskLevel.CRITICAL
        if action in {DefenseActionType.DELETE_DATA, DefenseActionType.SHUTDOWN_SERVICE,
                      DefenseActionType.CHANGE_DNS, DefenseActionType.ISOLATE_NETWORK_SEGMENT}
        else RiskLevel.HIGH,
        P.DEFENSE_APPROVE,
        timedelta(hours=1) if low else timedelta(minutes=30),
        preapprovable=low,
        max_preapproved_ttl_seconds=3600 if low else 0,
    )


def policy_for(action_type: str) -> ApprovalPolicy | None:
    return POLICIES.get(action_type)
