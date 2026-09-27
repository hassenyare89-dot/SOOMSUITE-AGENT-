"""File-type detection and hashing (pure functions; files are never executed or opened by
external tools here)."""

from __future__ import annotations

import hashlib

MAGIC: list[tuple[bytes, int, str]] = [
    (b"MZ", 0, "application/x-dosexec"),
    (b"\x7fELF", 0, "application/x-executable"),
    (b"\xcf\xfa\xed\xfe", 0, "application/x-mach-binary"),
    (b"%PDF-", 0, "application/pdf"),
    (b"PK\x03\x04", 0, "application/zip"),
    (b"\x1f\x8b", 0, "application/gzip"),
    (b"Rar!\x1a\x07", 0, "application/vnd.rar"),
    (b"7z\xbc\xaf\x27\x1c", 0, "application/x-7z-compressed"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "application/x-ole-storage"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"GIF8", 0, "image/gif"),
    (b"#!", 0, "text/x-script"),
]
EXECUTABLE_MIMES = {"application/x-dosexec", "application/x-executable",
                    "application/x-mach-binary", "text/x-script"}


def detect_mime(data: bytes) -> str:
    for magic, offset, mime in MAGIC:
        if data[offset:offset + len(magic)] == magic:
            return mime
    head = data[:512].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html")) or b"<script" in head:
        return "text/html"
    if head.startswith(b"<?php"):
        return "application/x-php"
    try:
        data[:4096].decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def hashes(data: bytes) -> dict[str, str]:
    # SHA-1/MD5 are for sample identification (threat-intel lookups), never for integrity.
    return {"sha256": hashlib.sha256(data).hexdigest(),
            # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
            "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest()}
