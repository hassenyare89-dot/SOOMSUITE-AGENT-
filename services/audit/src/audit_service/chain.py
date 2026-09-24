"""Hash chain: entry_hash = SHA-256(prev_hash || canonical(entry)). Any modification, deletion
or reordering of rows breaks verification from that point on."""

from __future__ import annotations

from typing import Any

from platform_core.security.crypto import canonical_json, sha256_hex

GENESIS = "0" * 64
CHAINED_FIELDS = ("tenant_id", "seq", "actor_type", "actor_id", "agent_name", "agent_run_id",
                  "service", "tool_name", "action", "target_type", "target_id", "request_id",
                  "source_ip", "result", "risk_level", "approval_id", "metadata_redacted",
                  "created_at")


def entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    material = {k: (str(entry[k]) if entry.get(k) is not None and k not in ("seq",
                                                                           "metadata_redacted")
                    else entry.get(k)) for k in CHAINED_FIELDS}
    return sha256_hex(prev_hash.encode() + canonical_json(material))
