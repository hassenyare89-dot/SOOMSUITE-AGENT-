import hashlib
import hmac
import json
from typing import Any


def payload_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def approval_matches(payload: dict[str, Any], approved_hash: str) -> bool:
    return hmac.compare_digest(payload_hash(payload), approved_hash)
