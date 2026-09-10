import re

SECRET_KEYS = {"authorization", "cookie", "password", "token", "secret", "api_key", "access_token"}


def redact(value):
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if k.lower() in SECRET_KEYS else redact(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"(?i)bearer\s+[a-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
    return value
