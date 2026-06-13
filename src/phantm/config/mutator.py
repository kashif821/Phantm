import tomlkit
from pathlib import Path
from typing import Any
from phantm.ui.components.feedback import print_error


def _coerce(value: str) -> Any:
    lower = value.lower()
    if lower in ("true", "yes"):
        return True
    if lower in ("false", "no"):
        return False
    if lower in ("none", "null"):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


ALLOWED_KEYS = {
    "default_model",
    "github_token",
    "virustotal_api_key",
    "abuseipdb_api_key",
    "nvd_api_key",
    "cache_virustotal_ttl_hours",
    "cache_abuseipdb_ttl_hours",
    "cache_nvd_ttl_days",
}


def set_config_value(key: str, value: str) -> None:
    config_path = Path.home() / ".phantm" / "config.toml"

    if key not in ALLOWED_KEYS:
        print_error(f"Security Rejection: '{key}' is not a permitted configuration key.")
        raise ValueError("Mass assignment blocked")

    try:
        doc = tomlkit.parse(config_path.read_text())
    except FileNotFoundError:
        doc = tomlkit.document()

    parts = key.split(".")
    container = doc
    for part in parts[:-1]:
        if part not in container:
            container[part] = tomlkit.table()
        elif not isinstance(container.get(part), dict):
            print_error(f"Cannot set '{key}' because '{part}' is already a flat value, not a section.")
            raise ValueError("Data integrity violation")
        container = container[part]

    container[parts[-1]] = _coerce(value)
    config_path.write_text(tomlkit.dumps(doc))
