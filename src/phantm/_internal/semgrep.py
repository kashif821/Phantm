from pathlib import Path
import subprocess
import json
from phantm.rules.models import Finding


_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def run_semgrep(target_path: str) -> list[Finding]:
    try:
        safe_target = str(Path(target_path).resolve())
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "-q", safe_target],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode not in (0, 1):
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for rule_match in data.get("results", []):
        start = rule_match.get("start", {})
        extra = rule_match.get("extra", {})

        findings.append(
            Finding(
                file_path=rule_match.get("path", target_path),
                severity=_SEVERITY_MAP.get(extra.get("severity", "INFO"), "low"),
                type=extra.get("check_id", "unknown"),
                line=start.get("line"),
                description=extra.get("message", "No description"),
                fix=None,
                confidence=extra.get("confidence", "low"),
                source="semgrep",
            )
        )

    return findings
