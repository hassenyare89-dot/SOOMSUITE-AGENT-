"""Enumerations shared by services, the database schema and the dashboard."""

from enum import StrEnum


class PipelineStage(StrEnum):
    NEW_LEAD = "NEW_LEAD"
    QUALIFIED = "QUALIFIED"
    APPOINTMENT_BOOKED = "APPOINTMENT_BOOKED"
    SECURITY_REVIEW = "SECURITY_REVIEW"
    PROPOSAL = "PROPOSAL"
    NEGOTIATION = "NEGOTIATION"
    WON = "WON"
    LOST = "LOST"


# Allowed forward/backward transitions; WON/LOST are terminal except explicit reopen by humans.
PIPELINE_TRANSITIONS: dict[PipelineStage, frozenset[PipelineStage]] = {
    PipelineStage.NEW_LEAD: frozenset({PipelineStage.QUALIFIED, PipelineStage.APPOINTMENT_BOOKED,
                                       PipelineStage.LOST}),
    PipelineStage.QUALIFIED: frozenset({PipelineStage.APPOINTMENT_BOOKED,
                                        PipelineStage.SECURITY_REVIEW, PipelineStage.PROPOSAL,
                                        PipelineStage.LOST}),
    PipelineStage.APPOINTMENT_BOOKED: frozenset({PipelineStage.QUALIFIED,
                                                 PipelineStage.SECURITY_REVIEW,
                                                 PipelineStage.PROPOSAL, PipelineStage.LOST}),
    PipelineStage.SECURITY_REVIEW: frozenset({PipelineStage.PROPOSAL,
                                              PipelineStage.APPOINTMENT_BOOKED,
                                              PipelineStage.LOST}),
    PipelineStage.PROPOSAL: frozenset({PipelineStage.NEGOTIATION, PipelineStage.WON,
                                       PipelineStage.LOST}),
    PipelineStage.NEGOTIATION: frozenset({PipelineStage.PROPOSAL, PipelineStage.WON,
                                          PipelineStage.LOST}),
    PipelineStage.WON: frozenset(),
    PipelineStage.LOST: frozenset({PipelineStage.NEW_LEAD}),
}


class Channel(StrEnum):
    WEB = "web"
    WHATSAPP = "whatsapp"
    EMAIL = "email"


class ConversationStatus(StrEnum):
    OPEN = "OPEN"
    ESCALATED = "ESCALATED"
    HUMAN_HANDLING = "HUMAN_HANDLING"
    CLOSED = "CLOSED"


class SenderType(StrEnum):
    CUSTOMER = "customer"
    SAMIIR = "samiir"
    HUMAN_AGENT = "human_agent"
    SYSTEM = "system"


class AppointmentStatus(StrEnum):
    BOOKED = "BOOKED"
    CANCELLED = "CANCELLED"
    RESCHEDULED = "RESCHEDULED"
    COMPLETED = "COMPLETED"
    NO_SHOW = "NO_SHOW"
    FAILED = "FAILED"


class KnowledgeStatus(StrEnum):
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    ARCHIVED = "ARCHIVED"


class KnowledgeCategory(StrEnum):
    COMPANY_PROFILE = "company_profile"
    SERVICES = "services"
    PRODUCTS = "products"
    PRICING = "pricing"
    FAQ = "faq"
    ONBOARDING = "onboarding"
    SERVICE_SCOPE = "service_scope"
    INCLUDED = "included"
    EXCLUDED = "excluded"
    DELIVERY_TIMELINE = "delivery_timeline"
    SUPPORT_PROCEDURES = "support_procedures"
    CUSTOMER_SERVICE_POLICIES = "customer_service_policies"
    APPOINTMENT_RULES = "appointment_rules"
    SALES_QUALIFICATION_RULES = "sales_qualification_rules"
    REFUND_ESCALATION_POLICIES = "refund_escalation_policies"
    SECURITY_SERVICES = "security_services"
    LEGAL_APPROVED_MESSAGING = "legal_approved_messaging"


class Visibility(StrEnum):
    PUBLIC = "public"      # usable by the customer-facing agent
    INTERNAL = "internal"  # staff only; never retrieved for customers


class RiskClass(StrEnum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"
    CRITICAL = "CRITICAL"


class IncidentClaim(StrEnum):
    SUSPECTED = "SUSPECTED INCIDENT"
    CONFIRMED = "CONFIRMED INCIDENT"


class IncidentStatus(StrEnum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    REMEDIATED = "REMEDIATED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


INCIDENT_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.NEW: frozenset({IncidentStatus.ACKNOWLEDGED, IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.ACKNOWLEDGED: frozenset({IncidentStatus.INVESTIGATING,
                                            IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.CONTAINED, IncidentStatus.REMEDIATED,
                                             IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.CONTAINED: frozenset({IncidentStatus.REMEDIATED, IncidentStatus.INVESTIGATING}),
    IncidentStatus.REMEDIATED: frozenset({IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING}),
    IncidentStatus.CLOSED: frozenset({IncidentStatus.INVESTIGATING}),
    IncidentStatus.FALSE_POSITIVE: frozenset({IncidentStatus.INVESTIGATING}),
}


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanProfile(StrEnum):
    SAFE_PASSIVE = "safe-passive"
    SAFE_STANDARD = "safe-standard"


class ScanStatus(StrEnum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    REJECTED = "REJECTED"


class FalsePositiveStatus(StrEnum):
    UNREVIEWED = "UNREVIEWED"
    CONFIRMED_TRUE = "CONFIRMED_TRUE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class RemediationStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    VERIFIED = "VERIFIED"
    WONT_FIX = "WONT_FIX"


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTED = "EXECUTED"
    CANCELLED = "CANCELLED"


class DefenseActionType(StrEnum):
    # Low-risk (eligible for tenant pre-approval, always time-bounded)
    CHALLENGE_IP = "challenge_ip"
    RATE_LIMIT_PATH = "rate_limit_path"
    TEMP_BLOCK_IP = "temp_block_ip"
    REVOKE_APP_SESSION = "revoke_app_session"
    # High-risk (always require human approval)
    BLOCK_COUNTRY = "block_country"
    DISABLE_ACCOUNT = "disable_account"
    ROTATE_CREDENTIALS = "rotate_credentials"
    CHANGE_FIREWALL_RULE = "change_firewall_rule"
    SHUTDOWN_SERVICE = "shutdown_service"
    CHANGE_DNS = "change_dns"
    MODIFY_INFRASTRUCTURE = "modify_infrastructure"
    DELETE_DATA = "delete_data"
    ISOLATE_NETWORK_SEGMENT = "isolate_network_segment"


LOW_RISK_DEFENSE_ACTIONS = frozenset({
    DefenseActionType.CHALLENGE_IP, DefenseActionType.RATE_LIMIT_PATH,
    DefenseActionType.TEMP_BLOCK_IP, DefenseActionType.REVOKE_APP_SESSION,
})


class DefenseActionStatus(StrEnum):
    RECOMMENDED = "RECOMMENDED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"
    REVERTED = "REVERTED"
    REJECTED = "REJECTED"
    DISMISSED = "DISMISSED"


class FatmaMode(StrEnum):
    RECOMMEND_ONLY = "recommend_only"
    PREAPPROVED_LOW_RISK = "preapproved_low_risk"


class MalwareVerdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"
    PENDING = "pending"


class QuarantineStatus(StrEnum):
    QUARANTINED = "QUARANTINED"
    RELEASED = "RELEASED"
    DESTROYED = "DESTROYED"


class NotificationStatus(StrEnum):
    SCHEDULED = "SCHEDULED"
    SENDING = "SENDING"
    SENT = "SENT"
    DELIVERED = "DELIVERED"
    READ = "READ"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AssetVerificationStatus(StrEnum):
    UNVERIFIED = "UNVERIFIED"
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"
