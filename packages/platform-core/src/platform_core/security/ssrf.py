"""SSRF prevention for any server-side outbound request whose target is not a fixed constant."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from platform_core.errors import ValidationFailed

_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "255.255.255.255/32", "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64",
        "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
    )
]
_BLOCKED_HOST_SUFFIXES = (".local", ".localhost", ".internal", ".svc", ".cluster.local", ".lan",
                          ".home", ".corp", ".intranet")


def ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not any(addr in net for net in _BLOCKED_NETWORKS) and addr.is_global


def validate_hostname(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host or len(host) > 253 or host == "localhost" or host.endswith(_BLOCKED_HOST_SUFFIXES):
        raise ValidationFailed("target host is not allowed")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or not all(
            0 < len(lbl) <= 63 and lbl.replace("-", "").isalnum() and not lbl.startswith("-")
            for lbl in labels
        ):
            raise ValidationFailed("invalid hostname") from None
        return host
    if not ip_is_public(host):
        raise ValidationFailed("target address is not public")
    return host


async def resolve_public(host: str, port: int = 443) -> list[str]:
    """Resolve and require every address to be public (defeats DNS pointing at internals)."""
    host = validate_hostname(host)
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationFailed("target does not resolve") from exc
    addrs = sorted({info[4][0] for info in infos})
    if not addrs or not all(ip_is_public(a) for a in addrs):
        raise ValidationFailed("target resolves to a non-public address")
    return addrs


async def validate_outbound_url(url: str, *, allowed_hosts: frozenset[str] | None = None,
                                require_https: bool = True) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ({"https"} if require_https else {"https", "http"}):
        raise ValidationFailed("URL scheme not allowed")
    if parts.username or parts.password:
        raise ValidationFailed("credentials in URL are not allowed")
    host = validate_hostname(parts.hostname or "")
    if allowed_hosts is not None and host not in allowed_hosts:
        raise ValidationFailed("host is not allowlisted")
    await resolve_public(host, parts.port or (443 if parts.scheme == "https" else 80))
    return url
