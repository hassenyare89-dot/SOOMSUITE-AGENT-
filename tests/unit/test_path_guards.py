from __future__ import annotations

import pytest

from platform_core.errors import ValidationFailed
from platform_core.http import safe_path
from platform_core.storage import FilesystemObjectStore


@pytest.mark.parametrize("path", ["/internal/chat", "/internal/contacts/0b6c1f0e-8f7a-4c1e-9d2b-1f3e5a7c9b0d",
                                  "/internal/audit/verify", "/internal/approvals/"])
def test_safe_path_accepts_relative_service_paths(path: str) -> None:
    assert safe_path(path) == path


@pytest.mark.parametrize("path", ["//evil.example/x", "http://evil.example/", "internal/chat",
                                  "/internal/../admin", "/internal/./x", "/internal/%2e%2e/x",
                                  "/internal/x?y=1", "/internal/x#f", "/internal//x", "", "/a\\b"])
def test_safe_path_rejects_host_or_prefix_escapes(path: str) -> None:
    with pytest.raises(ValidationFailed):
        safe_path(path)


async def test_object_store_confines_keys_to_root(tmp_path) -> None:  # noqa: ANN001
    store = FilesystemObjectStore(tmp_path / "objects")
    ref = await store.put("raw/tenant/source/2026/09/25/a.json.gz", b"x")
    assert await store.get(ref) == b"x"
    for bad in ["../escape", "/etc/passwd", "raw/../../x", "raw//x", ".hidden/x", "a\\b", ""]:
        with pytest.raises(ValueError):
            await store.put(bad, b"x")
    # A sibling directory sharing the root's name prefix is not "inside" the root.
    (tmp_path / "objects-evil").mkdir()
    with pytest.raises(ValueError):
        store._path("../objects-evil/x")
