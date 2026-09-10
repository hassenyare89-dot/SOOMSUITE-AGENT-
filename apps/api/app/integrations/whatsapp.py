import hashlib
import hmac

from app.core.config import Settings


def verify_signature(body: bytes, signature: str | None, settings: Settings) -> bool:
    if not signature or not signature.startswith("sha256=") or not settings.meta_app_secret:
        return False
    expected = hmac.new(settings.meta_app_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature.removeprefix("sha256="), expected)


def parse_messages(payload: dict) -> list[dict]:
    out = []
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            for msg in value.get("messages", []):
                if msg.get("type") == "text":
                    out.append(
                        {
                            "message_id": msg["id"],
                            "sender": msg["from"],
                            "text": msg["text"]["body"],
                        }
                    )
    return out
