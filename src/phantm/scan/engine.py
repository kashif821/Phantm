import json
import sys
from pathlib import Path
from phantm._internal.db import record_scan, record_finding
from phantm._internal.llm import ask_model, PhantmLLMError
from phantm.rules.engine import run_tier_1_checks
from phantm.rules.models import Finding
from phantm.ui.components.feedback import print_info, print_error, print_success, print_warning
from phantm.ui.layouts.scan_report import render_scan_summary
from phantm.ui.console import console


def run_scan(path: str) -> None:
    target = Path(path).resolve()

    if not target.exists() or not target.is_file():
        print_error(f"Target does not exist or is not a file: {path}")
        sys.exit(2)

    print_info(f"Starting scan on {target}...")

    findings = list(run_tier_1_checks(str(target)))
    snippet = target.read_text(encoding="utf-8", errors="replace")[:1000]

    system_prompt = (
        "You are a helpful Senior Developer performing a routine code review. "
        "Check this snippet for standard security flaws. "
        "Respond with ONLY a JSON object in this exact format: "
        '{"status": "VULNERABLE" or "SECURE", "reason": "<brief explanation>"}. '
        "Do not include markdown formatting or extra text."
    )

    try:
        response = ask_model(system_prompt=system_prompt, user_prompt=snippet)
    except PhantmLLMError as e:
        print_error(f"LLM request failed: {e}")
        sys.exit(3)

    cleaned = response.strip().strip("`").removeprefix("json").strip()

    has_llm_issue = False
    reason = ""

    try:
        parsed = json.loads(cleaned)
        has_llm_issue = parsed.get("status") == "VULNERABLE"
        reason = parsed.get("reason", "")
    except json.JSONDecodeError:
        print_warning("Failed to parse LLM JSON. Falling back to raw text.")
        has_llm_issue = (
            "vulnerability" in cleaned.lower() or "insecure" in cleaned.lower()
        )
        reason = cleaned

    console.print(reason)

    if has_llm_issue:
        findings.append(
            Finding(
                file_path=str(target),
                severity="medium",
                type="llm_audit",
                line=None,
                description=reason,
                fix="Manual review required",
                confidence="low",
                source="llm",
            )
        )

    findings_count = len(findings)
    exit_code = 1 if findings_count > 0 else 0

    scan_id = record_scan(str(target), exit_code)

    for finding in findings:
        record_finding(
            scan_id=scan_id,
            file_path=finding.file_path,
            severity=finding.severity,
            type=finding.type,
            line=finding.line,
            description=finding.description,
            fix=finding.fix,
            confidence=finding.confidence,
            source=finding.source,
        )

    if findings_count:
        print_warning(f"Potential issues detected in {target.name}")
    else:
        print_success(f"No obvious vulnerabilities found in {target.name}")

    render_scan_summary(str(target), findings_count, exit_code)
    sys.exit(exit_code)
