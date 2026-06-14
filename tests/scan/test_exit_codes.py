"""Test run_scan exit codes: 0 (clean), 1 (vulns), 4 (engine crash)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def risky_file(tmp_path: Path) -> Path:
    f = tmp_path / "target.py"
    f.write_text("import os\nos.system('ls')\n")
    return f


def test_exit_code_0_clean(tmp_path: Path) -> None:
    """When Tier 1 returns nothing, exit 0 before touching Tier 2/3."""
    from phantm.scan.engine import run_scan

    f = tmp_path / "clean.py"
    f.write_text("x = 1\n")
    with pytest.raises(SystemExit) as exc:
        run_scan(str(f))
    assert exc.value.code == 0


def test_exit_code_1_vulns_found(risky_file: Path) -> None:
    """When LLM returns vulnerabilities, exit 1."""
    from phantm.scan.engine import run_scan

    with (
        patch("phantm.scan.engine.ask_model") as mock_llm,
        patch("phantm.scan.engine.get_intel_cache", return_value=None),
    ):
        mock_llm.return_value = (
            '[{"severity": "HIGH", "type": "RCE", "description": "bad", "line": 2, "confidence": "high"}]'
        )
        with pytest.raises(SystemExit) as exc:
            run_scan(str(risky_file))
        assert exc.value.code == 1


def test_exit_code_4_unhandled_exception(tmp_path: Path) -> None:
    """When the orchestrator raises an unexpected exception before file loop, exit 4.

    Mock get_scannable_files to raise so the error propagates outside the
    per-file try/except.
    """
    from phantm.scan.engine import run_scan

    f = tmp_path / "target.py"
    f.write_text("x = 1\n")

    with pytest.raises(SystemExit) as exc:
        with patch("phantm.scan.engine.get_scannable_files", side_effect=RuntimeError("boom")):
            run_scan(str(tmp_path))
    assert exc.value.code == 4


def test_exit_code_0_no_risky_patterns(tmp_path: Path) -> None:
    """When Tier 1 finds no risky blocks across all files, exit 0."""
    from phantm.scan.engine import run_scan

    f = tmp_path / "innocent.py"
    f.write_text("from datetime import datetime\nprint('hello')\n")
    with pytest.raises(SystemExit) as exc:
        run_scan(str(f))
    assert exc.value.code == 0


def test_exit_code_1_vulns_with_threat_context(risky_file: Path) -> None:
    """Exit 1 when LLM returns findings even with threat intel context."""
    from phantm.scan.engine import run_scan

    # Mock threat intel to return cached data, and LLM to return findings
    with (
        patch("phantm.scan.engine.get_intel_cache") as mock_cache,
        patch("phantm.scan.engine.ask_model") as mock_llm,
    ):
        mock_cache.return_value = {"abuseConfidenceScore": 95}
        mock_llm.return_value = (
            '[{"severity": "HIGH", "type": "RCE", "description": "shell injection", "line": 2, "confidence": "high"}]'
        )
        with pytest.raises(SystemExit) as exc:
            run_scan(str(risky_file))
        assert exc.value.code == 1
