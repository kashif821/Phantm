from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class PhantmSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path.home() / ".phantm" / ".env",
        env_prefix="PHANTM_",
        extra="ignore",
    )

    debug: bool = False
