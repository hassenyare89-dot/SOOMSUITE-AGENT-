"""Create a local `.env` with random secrets and per-service Ed25519 identities.

    python scripts/bootstrap_dev.py            # idempotent: fills only missing values
    python scripts/bootstrap_dev.py --rotate-keys

Outputs (git-ignored):
  .env                              secrets for docker compose / local runner
  .secrets/service-keys/<svc>.pem   private key, mounted ONLY into that service
  .secrets/service-keys/trust.json  public trust bundle, mounted into every service
  .secrets/quarantine.key           quarantine AES key (security-ingest + malware worker)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/platform-core/src"))

from platform_core.security.crypto import Keyring  # noqa: E402
from platform_core.security.service_auth import generate_keypair  # noqa: E402

SERVICES = ["api-gateway-public", "api-gateway-admin", "samiir-agent", "fatma-soc", "crm",
            "scheduling", "notifications", "knowledge", "whatsapp", "security-ingest",
            "scanner-controller", "approvals", "audit"]


def b64(n: int = 32) -> str:
    return base64.b64encode(os.urandom(n)).decode()


GENERATORS = {
    "FIELD_ENCRYPTION_KEYRING": lambda: Keyring.generate("k1").to_json(),
    "BLIND_INDEX_KEY": b64, "SLOT_TOKEN_KEY": b64, "CSRF_KEY": b64, "QUARANTINE_KEY": b64,
    "PSEUDONYM_KEY": b64,
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rotate-keys", action="store_true")
    args = parser.parse_args()
    env_path = ROOT / ".env"
    template = (ROOT / ".env.example").read_text().splitlines()
    existing: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                existing[k] = v
    out = []
    for line in template:
        if "=" not in line or line.lstrip().startswith("#"):
            out.append(line)
            continue
        key, default = line.split("=", 1)
        value = existing.get(key, default)
        if not value:
            if key in GENERATORS:
                value = GENERATORS[key]()
            elif "PASSWORD" in key or key in ("META_APP_SECRET", "META_VERIFY_TOKEN",
                                              "INGEST_DEMO_SECRET"):
                value = secrets.token_urlsafe(24)
        if value.startswith("{"):
            value = "'" + value + "'"
        out.append(f"{key}={value}")
    env_path.write_text("\n".join(out) + "\n")
    os.chmod(env_path, 0o600)

    keys = ROOT / ".secrets" / "service-keys"
    keys.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT / ".secrets", 0o700)
    bundle_path = keys / "trust.json"
    bundle = json.loads(bundle_path.read_text())["keys"] if bundle_path.exists() else {}
    for svc in SERVICES:
        pem_path = keys / f"{svc}.pem"
        if args.rotate_keys or not pem_path.exists() or svc not in bundle:
            pem, pub = generate_keypair()
            pem_path.write_bytes(pem)
            os.chmod(pem_path, 0o600)
            bundle[svc] = pub
    bundle_path.write_text(json.dumps({"keys": bundle}, indent=2))
    qk = ROOT / ".secrets" / "quarantine.key"
    quarantine = next(line.split("=", 1)[1] for line in out if line.startswith("QUARANTINE_KEY="))
    qk.write_text(quarantine)
    os.chmod(qk, 0o600)
    print(f"wrote {env_path} and {len(SERVICES)} service identities under {keys}")


if __name__ == "__main__":
    main()
