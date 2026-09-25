from __future__ import annotations

from fastapi import FastAPI

from crm_service.api import router
from crm_service.config import Settings
from crm_service.service import CrmService
from platform_core.app import ServiceRuntime, build_runtime, create_app
from platform_core.security.crypto import load_field_encryptor


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def startup(rt: ServiceRuntime) -> None:
        if "crm" not in rt.extras:
            enc = await load_field_encryptor(rt.secrets, settings.field_keyring_ref,
                                             settings.blind_index_key_ref,
                                             allow_ephemeral=not settings.is_production_like)
            rt.extras["crm"] = CrmService(enc)

    return create_app(settings=settings, runtime_factory=lambda: build_runtime(settings, {}),
                      routers=[router], on_startup=startup, title="SAMIIR CRM Service")
