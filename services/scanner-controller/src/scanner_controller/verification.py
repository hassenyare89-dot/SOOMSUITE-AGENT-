"""Domain-ownership verification (DNS TXT or HTTPS well-known file).

The challenge token is shown once; only its SHA-256 is stored. The HTTP check is SSRF-hardened:
HTTPS only, public addresses only, no redirects, tiny response cap, short timeouts."""

from __future__ import annotations

import secrets

import httpx

from platform_core.security.crypto import sha256_hex
from platform_core.security.ssrf import resolve_public, validate_hostname

TXT_PREFIX = "_samiir-fatma-verify"
WELL_KNOWN = "/.well-known/samiir-fatma-verify.txt"


def new_challenge() -> tuple[str, str]:
    token = "sfv_" + secrets.token_urlsafe(24)
    return token, sha256_hex(token)


def instructions(method: str, host: str, token: str) -> dict[str, str]:
    if method == "dns_txt":
        return {"method": "dns_txt", "record_name": f"{TXT_PREFIX}.{host}",
                "record_type": "TXT", "record_value": f"sf-verify={token}"}
    return {"method": "http_file", "url": f"https://{host}{WELL_KNOWN}", "file_content": token}


async def check_dns(host: str, token_hash: str) -> bool:
    import dns.asyncresolver
    import dns.exception

    validate_hostname(host)
    try:
        answers = await dns.asyncresolver.resolve(f"{TXT_PREFIX}.{host}", "TXT", lifetime=5)
    except (dns.exception.DNSException, OSError):
        return False
    for rdata in answers:
        value = b"".join(rdata.strings).decode(errors="ignore").strip()
        if value.startswith("sf-verify=") and sha256_hex(value.removeprefix("sf-verify=")) \
                == token_hash:
            return True
    return False


async def check_http(host: str, token_hash: str, client: httpx.AsyncClient | None = None) -> bool:
    await resolve_public(host)
    own = client is None
    client = client or httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=3.0),
                                         follow_redirects=False)
    try:
        async with client.stream("GET", f"https://{host}{WELL_KNOWN}") as resp:
            if resp.status_code != 200:
                return False
            body = b""
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > 1024:
                    return False
    except httpx.HTTPError:
        return False
    finally:
        if own:
            await client.aclose()
    return sha256_hex(body.decode(errors="ignore").strip()) == token_hash
