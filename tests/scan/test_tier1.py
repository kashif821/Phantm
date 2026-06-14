"""Test Tier 1 AST extraction: risky calls, clean files, SyntaxError fallback."""
from __future__ import annotations

from pathlib import Path

import pytest


RISKY_CODE = """
import os

def deploy():
    os.system("rm -rf /")
"""

CLEAN_CODE = """
def add(a: int, b: int) -> int:
    return a + b
"""

MALFORMED_CODE = """
def broken(
    os.system("ls")
"""


def test_finds_os_system(tmp_path: Path) -> None:
    from phantm.scan.engine import extract_risky_blocks

    f = tmp_path / "risky.py"
    f.write_text(RISKY_CODE)
    blocks = extract_risky_blocks(f)
    assert len(blocks) == 1
    assert blocks[0]["line"] == 5
    assert blocks[0]["enclosing"] == "deploy"
    assert "os.system" in blocks[0]["snippet"]


def test_clean_file_returns_empty(tmp_path: Path) -> None:
    from phantm.scan.engine import extract_risky_blocks

    f = tmp_path / "clean.py"
    f.write_text(CLEAN_CODE)
    blocks = extract_risky_blocks(f)
    assert blocks == []


def test_syntax_error_fallback_uses_regex(tmp_path: Path) -> None:
    from phantm.scan.engine import extract_risky_blocks

    f = tmp_path / "broken.py"
    f.write_text(MALFORMED_CODE)
    blocks = extract_risky_blocks(f)
    assert len(blocks) >= 1
    assert any("os.system" in b["snippet"] for b in blocks)
    assert all(b["enclosing"] == "<fallback>" for b in blocks)


def test_returns_empty_for_nonexistent_file(tmp_path: Path) -> None:
    from phantm.scan.engine import extract_risky_blocks

    blocks = extract_risky_blocks(tmp_path / "nope.py")
    assert blocks == []


def test_enclosing_function_detected(tmp_path: Path) -> None:
    from phantm.scan.engine import extract_risky_blocks

    code = """
class Malware:
    def run(self):
        eval("dangerous")
"""
    f = tmp_path / "cls.py"
    f.write_text(code)
    blocks = extract_risky_blocks(f)
    assert len(blocks) == 1
    assert blocks[0]["enclosing"] == "run"
