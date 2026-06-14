"""Test set_config_value: allowlist enforcement, destructive-overwrite prevention."""
from __future__ import annotations

import pytest
import tomlkit
from pathlib import Path


def test_rejects_rogue_keys() -> None:
    from phantm.config.mutator import set_config_value

    with pytest.raises(ValueError, match="Mass assignment blocked"):
        set_config_value("system.malicious_flag", "true")


def test_accepts_allowed_keys(tmp_path: "Path") -> None:
    (tmp_path / ".phantm").mkdir(parents=True, exist_ok=True)
    from phantm.config.mutator import set_config_value

    set_config_value("default_model", "cerebras/llama-3.1-8b")
    config_path = Path.home() / ".phantm" / "config.toml"
    doc = tomlkit.parse(config_path.read_text())
    assert doc.get("default_model") == "cerebras/llama-3.1-8b"


def test_multiple_writes_accumulate(tmp_path: "Path") -> None:
    (tmp_path / ".phantm").mkdir(parents=True, exist_ok=True)
    from phantm.config.mutator import set_config_value

    set_config_value("default_model", "model-a")
    set_config_value("cache_virustotal_ttl_hours", "12")
    config_path = Path.home() / ".phantm" / "config.toml"
    doc = tomlkit.parse(config_path.read_text())
    assert doc["default_model"] == "model-a"
    assert doc["cache_virustotal_ttl_hours"] == 12


def test_coerce_types(tmp_path: "Path") -> None:
    (tmp_path / ".phantm").mkdir(parents=True, exist_ok=True)
    from phantm.config.mutator import set_config_value

    set_config_value("cache_virustotal_ttl_hours", "48")
    set_config_value("cache_abuseipdb_ttl_hours", "96")
    config_path = Path.home() / ".phantm" / "config.toml"
    doc = tomlkit.parse(config_path.read_text())
    assert doc["cache_virustotal_ttl_hours"] == 48
    assert doc["cache_abuseipdb_ttl_hours"] == 96
