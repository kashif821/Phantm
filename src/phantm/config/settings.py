from pathlib import Path
from typing import Any, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_settings.sources import TomlConfigSettingsSource


def _flatten(d: dict[str, Any], parent_key: str = "", depth: int = 0) -> dict[str, Any]:
    if depth > 10:
        raise ValueError("Security Violation: Configuration nesting is too deep (DoS prevention).")
    items: dict[str, Any] = {}
    for k, v in d.items():
        new_key = f"{parent_key}_{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(_flatten(v, new_key, depth + 1))
        else:
            items[new_key] = v
    return items


class FlattenedTomlSource(TomlConfigSettingsSource):
    def _read_file(self, file_path: Path) -> dict[str, Any]:
        data = super()._read_file(file_path)
        return _flatten(data)


class PhantmSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path.home() / ".phantm" / ".env",
        env_prefix="PHANTM_",
        extra="ignore",
    )

    github_token: Optional[str] = None
    virustotal_api_key: Optional[str] = Field(default=None, repr=False)
    abuseipdb_api_key: Optional[str] = Field(default=None, repr=False)
    nvd_api_key: Optional[str] = None
    default_model: str = "gpt-4o"
    cache_virustotal_ttl_hours: int = 24
    cache_abuseipdb_ttl_hours: int = 48
    cache_nvd_ttl_days: int = 7

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        return (
            env_settings,
            dotenv_settings,
            FlattenedTomlSource(
                settings_cls,
                toml_file=Path.home() / ".phantm" / "config.toml",
            ),
        )
