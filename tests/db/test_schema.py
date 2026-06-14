"""Test SQLite DB: schema creation, file permissions, TTL expiry, UUID generation."""
from __future__ import annotations

import json
import os
import stat as stat_module
from datetime import datetime, timedelta
from pathlib import Path

import pytest


def _init_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    db_path = tmp_path / ".phantm" / "phantm.db"
    monkeypatch.setattr("phantm._internal.db.DB_PATH", db_path)
    from phantm._internal.db import init_db

    init_db()
    return db_path


def test_init_db_creates_file_with_strict_permissions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    db_path = _init_db(monkeypatch, tmp_path)
    assert db_path.exists()
    mode = os.stat(db_path).st_mode & 0o777
    assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


def test_create_scan_record_returns_uuid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _init_db(monkeypatch, tmp_path)
    from phantm._internal.db import create_scan_record

    scan_id = create_scan_record("/some/path", 42)
    assert isinstance(scan_id, str)
    assert len(scan_id) == 32
    int(scan_id, 16)


def test_get_intel_cache_ttl_expiry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _init_db(monkeypatch, tmp_path)
    from phantm._internal.db import get_intel_cache, set_intel_cache

    set_intel_cache("test-artifact", "ip", {"data": "fresh"})
    assert get_intel_cache("test-artifact", ttl_hours=1) is not None

    conn = sqlite3.connect(str(tmp_path / ".phantm" / "phantm.db"))
    old_ts = (datetime.now() - timedelta(hours=3)).isoformat()
    conn.execute(
        "UPDATE intel_cache SET timestamp = ? WHERE artifact_id = ?",
        (old_ts, "test-artifact"),
    )
    conn.commit()
    conn.close()

    assert get_intel_cache("test-artifact", ttl_hours=1) is None


def test_set_and_get_intel_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _init_db(monkeypatch, tmp_path)
    from phantm._internal.db import get_intel_cache, set_intel_cache

    payload = {"malicious": True, "score": 85}
    set_intel_cache("artifact:1", "url", payload)
    result = get_intel_cache("artifact:1", ttl_hours=24)
    assert result is not None
    assert result["malicious"] is True
    assert result["score"] == 85


def test_save_and_query_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _init_db(monkeypatch, tmp_path)
    from phantm._internal.db import create_scan_record, save_findings, get_findings_for_scan

    scan_id = create_scan_record("/target", 1)
    findings = [
        {"file_path": "a.py", "line_number": "10", "severity": "HIGH", "vuln_type": "RCE", "description": "bad"},
        {"file_path": "b.py", "line_number": "20", "severity": "LOW", "vuln_type": "INFO", "description": "meh"},
    ]
    save_findings(scan_id, findings)
    rows = get_findings_for_scan(scan_id)
    assert len(rows) == 2
    assert rows[0]["severity"] == "HIGH"


import sqlite3  # noqa: E402 (needed for TTL test above)
