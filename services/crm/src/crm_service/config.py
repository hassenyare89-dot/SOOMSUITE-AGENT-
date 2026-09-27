from platform_core.config import BaseServiceSettings, EncryptionSettingsMixin


class Settings(EncryptionSettingsMixin, BaseServiceSettings):
    service_name: str = "crm"
