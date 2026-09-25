"""Domain errors mapped to safe HTTP responses (no internal detail leaks)."""

from __future__ import annotations


class PlatformError(Exception):
    status_code = 400
    code = "bad_request"
    public_message = "The request could not be processed."

    def __init__(self, message: str | None = None, *, details: dict | None = None) -> None:
        super().__init__(message or self.public_message)
        self.message = message or self.public_message
        self.details = details or {}


class NotFound(PlatformError):
    # Cross-tenant and unauthorized-object lookups also surface as 404 to prevent enumeration.
    status_code = 404
    code = "not_found"
    public_message = "Resource not found."


class Unauthenticated(PlatformError):
    status_code = 401
    code = "unauthenticated"
    public_message = "Authentication required."


class Forbidden(PlatformError):
    status_code = 403
    code = "forbidden"
    public_message = "Permission denied."


class Conflict(PlatformError):
    status_code = 409
    code = "conflict"
    public_message = "The request conflicts with the current state."


class ValidationFailed(PlatformError):
    status_code = 422
    code = "validation_failed"
    public_message = "The request is invalid."


class RateLimited(PlatformError):
    status_code = 429
    code = "rate_limited"
    public_message = "Too many requests."

    def __init__(self, retry_after: int = 60) -> None:
        super().__init__()
        self.retry_after = retry_after


class ApprovalRequired(PlatformError):
    status_code = 202
    code = "approval_required"
    public_message = "Human approval is required before this action can run."

    def __init__(self, approval_id: str) -> None:
        super().__init__(details={"approval_id": approval_id})
        self.approval_id = approval_id


class UpstreamUnavailable(PlatformError):
    status_code = 503
    code = "upstream_unavailable"
    public_message = "A dependent service is temporarily unavailable."


class PayloadTooLarge(PlatformError):
    status_code = 413
    code = "payload_too_large"
    public_message = "Request body too large."
