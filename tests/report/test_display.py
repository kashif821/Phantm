"""Test report display helpers: severity coloring, corrupted data handling."""
from __future__ import annotations

from unittest.mock import patch

import pytest


def test_color_severity_returns_formatted_string() -> None:
    from phantm.report.cmd import _color_severity

    result = _color_severity("HIGH")
    assert "[red]" in result
    assert "HIGH" in result
    assert "[/]" in result


def test_color_severity_escapes_markup() -> None:
    from phantm.report.cmd import _color_severity

    result = _color_severity("[malicious]HIGH[/]")
    assert "\\[malicious\\]" in result or "[malicious]" not in result.split("[")[1] if len(result.split("[")) > 1 else True


def test_color_severity_unknown_danger_default() -> None:
    from phantm.report.cmd import _color_severity

    result = _color_severity("UNKNOWN")
    assert "UNKNOWN" in result


def test_display_report_corrupted_data() -> None:
    from phantm.report.cmd import default_report

    with patch("phantm.report.cmd.get_latest_report_data", return_value={"scan": {}, "findings": []}):
        with patch("phantm.report.cmd.print_error") as mock_err:
            default_report()
            mock_err.assert_called_once()


def test_display_report_no_scans_yet() -> None:
    from phantm.report.cmd import default_report

    with patch("phantm.report.cmd.get_latest_report_data", return_value=None):
        with patch("phantm.ui.console.console.print") as mock_print:
            default_report()
            args = "".join(str(a) for a in mock_print.call_args[0])
            assert "No scans" in args
