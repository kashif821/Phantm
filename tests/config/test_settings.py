"""Test PhantmSettings Pydantic model: env loading, repr masking."""
from __future__ import annotations

import pytest
from phantm.config.settings import PhantmSettings


def test_loads_from_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PHANTM_GITHUB_TOKEN", "ghp_test123")
    monkeypatch.setenv("PHANTM_DEFAULT_MODEL", "cerebras/llama-test")
    settings = PhantmSettings()
    assert settings.github_token == "ghp_test123"
    assert settings.default_model == "cerebras/llama-test"


def test_sensitive_keys_have_repr_false() -> None:
    settings = PhantmSettings()
    rep = repr(settings)
    assert "virustotal_api_key" not in rep or "SecretStr" in rep
    assert "abuseipdb_api_key" not in rep or "SecretStr" in rep


def test_sensitive_keys_masked_in_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PHANTM_VIRUSTOTAL_API_KEY", "vt_secret_key_12345")
    settings = PhantmSettings()
    rep = repr(settings)
    assert "vt_secret_key_12345" not in rep


def test_defaults_are_sane() -> None:
    settings = PhantmSettings()
    assert settings.default_model == "gpt-4o"
    assert settings.cache_virustotal_ttl_hours == 24
    assert settings.cache_abuseipdb_ttl_hours == 48
    assert settings.cache_nvd_ttl_days == 7


def test_extra_env_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PHANTM_SHOULD_NOT_EXIST", "oops")
    settings = PhantmSettings()
    assert not hasattr(settings, "should_not_exist")
