import hashlib
import hmac

from app.core.config import Settings
from app.integrations.whatsapp import verify_signature


def test_meta_signature():
    s = Settings(meta_app_secret="test-secret")
    body = b"{}"
    sig = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    assert verify_signature(body, sig, s)
    assert not verify_signature(body, sig + "0", s)
