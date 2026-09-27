"""Seed demo tenants (development only; used by the compose `migrate` job when SEED_DEMO=true)."""

from __future__ import annotations

import asyncio
import base64
import os
import sys

from platform_core.devtools.seed import seed
from platform_core.security.crypto import FieldEncryptor, Keyring


def main() -> int:
    if os.environ.get("SEED_DEMO", "false").lower() != "true":
        print("SEED_DEMO not enabled; skipping")
        return 0
    if os.environ.get("ENVIRONMENT") in ("staging", "production"):
        print("refusing to seed a production-like environment", file=sys.stderr)
        return 2
    enc = FieldEncryptor(Keyring.from_json(os.environ["FIELD_ENCRYPTION_KEYRING"]),
                         base64.b64decode(os.environ["BLIND_INDEX_KEY"]))
    result = asyncio.run(seed(os.environ["ADMIN_DATABASE_URL"], enc))
    print(f"seeded {list(result.tenants)}; acme widget key {result.widget_keys['acme']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
