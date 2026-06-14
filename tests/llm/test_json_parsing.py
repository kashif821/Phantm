"""Test LLM response JSON parsing: markdown backticks, conversational text."""
from __future__ import annotations

from unittest.mock import patch

import pytest


def _run_llm_for_file(blocks: list[dict], threat_context: str, model: str, rel_path: str) -> list[dict]:
    """Minimal import of the private function from the engine."""
    from phantm.scan.engine import _run_llm_for_file as fn

    return fn(blocks, threat_context, model, rel_path)


SAMPLE_BLOCKS = [
    {
        "file": "/tmp/test.py",
        "line": 5,
        "snippet": "os.system('ls')",
        "enclosing": "run",
        "start_line": 5,
        "end_line": 5,
    }
]


def test_parses_clean_json() -> None:
    with patch("phantm.scan.engine.ask_model") as m:
        m.return_value = (
            '[{"severity": "HIGH", "type": "RCE", "description": "bad", "line": 5, "confidence": "high"}]'
        )
        result = _run_llm_for_file(SAMPLE_BLOCKS, "no intel", "cerebras/model", "test.py")
    assert len(result) == 1
    assert result[0]["severity"] == "HIGH"


def test_strips_markdown_backticks() -> None:
    with patch("phantm.scan.engine.ask_model") as m:
        m.return_value = "```json\n[{\"severity\": \"MEDIUM\", \"type\": \"Info\", \"description\": \"test\", \"line\": 5, \"confidence\": \"low\"}]\n```"
        result = _run_llm_for_file(SAMPLE_BLOCKS, "", "cerebras/model", "test.py")
    assert len(result) == 1
    assert result[0]["severity"] == "MEDIUM"


def test_strips_conversational_prefix() -> None:
    with patch("phantm.scan.engine.ask_model") as m:
        m.return_value = "Here are the findings:\n[{\"severity\": \"LOW\", \"type\": \"Info\", \"description\": \"minor\", \"line\": 5, \"confidence\": \"low\"}]"
        result = _run_llm_for_file(SAMPLE_BLOCKS, "", "cerebras/model", "test.py")
    assert len(result) == 1
    assert result[0]["severity"] == "LOW"


def test_returns_empty_on_invalid_json() -> None:
    with patch("phantm.scan.engine.ask_model") as m:
        m.return_value = "This is not JSON at all"
        result = _run_llm_for_file(SAMPLE_BLOCKS, "", "cerebras/model", "test.py")
    assert result == []


def test_returns_empty_on_llm_error() -> None:
    from phantm._internal.llm import PhantmLLMError

    with patch("phantm.scan.engine.ask_model", side_effect=PhantmLLMError("API down")):
        result = _run_llm_for_file(SAMPLE_BLOCKS, "", "cerebras/model", "test.py")
    assert result == []
