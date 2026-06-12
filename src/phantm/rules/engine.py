import ast
import re
from pathlib import Path
from phantm.rules.models import Finding
from phantm._internal.semgrep import run_semgrep


def _check_hardcoded_keys(source: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r"sk-[a-zA-Z0-9]{32,}", source):
        line_num = source[: match.start()].count("\n") + 1
        findings.append(
            Finding(
                file_path=file_path,
                severity="critical",
                type="exposed_key",
                line=line_num,
                description="Hardcoded OpenAI API key detected in source code.",
                fix="Replace with environment variable or secret manager.",
                confidence="high",
                source="regex",
            )
        )
    return findings


def _ast_extract_ai_calls(source: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        parts: list[str] = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        parts.reverse()

        dotted = ".".join(parts)
        ai_targets = {
            "openai.ChatCompletion.create",
            "litellm.completion",
            "anthropic.Anthropic",
        }
        if dotted in ai_targets:
            findings.append(
                Finding(
                    file_path=file_path,
                    severity="info",
                    type="ai_function_call",
                    line=node.lineno,
                    description=f"AI function call detected: {dotted}",
                    fix=None,
                    confidence="high",
                    source="ast",
                )
            )
    return findings


def run_tier_1_checks(target_path: str) -> list[Finding]:
    path = Path(target_path)
    if not path.is_file():
        return []

    source = path.read_text(encoding="utf-8", errors="replace")
    findings: list[Finding] = []

    findings.extend(_check_hardcoded_keys(source, target_path))
    findings.extend(_ast_extract_ai_calls(source, target_path))
    findings.extend(run_semgrep(target_path))

    return findings
