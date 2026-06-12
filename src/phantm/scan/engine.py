import sys
from pathlib import Path
from phantm._internal.llm import ask_model, PhantmLLMError
from phantm._internal.db import record_scan, record_finding
from phantm.ui.components.feedback import print_info, print_error, print_success, print_warning
from phantm.ui.layouts.scan_report import render_scan_summary
from phantm.ui.console import console


def run_scan(path: str) -> None:
    target = Path(path).resolve()

    if not target.exists() or not target.is_file():
        print_error(f"Target does not exist or is not a file: {path}")
        sys.exit(2)

    print_info(f"Starting scan on {target}...")

    snippet = target.read_text(encoding="utf-8", errors="replace")[:1000]

    system_prompt = (
        "You are an AI security auditor. "
        "Analyze this code snippet for vulnerabilities. Be extremely brief."
    )

    try:
        response = ask_model(system_prompt=system_prompt, user_prompt=snippet)
    except PhantmLLMError as e:
        print_error(f"LLM request failed: {e}")
        sys.exit(3)

    console.print(response)

    has_issue = "vulnerability" in response.lower() or "insecure" in response.lower()
    findings_count = 1 if has_issue else 0
    exit_code = 1 if has_issue else 0

    scan_id = record_scan(str(target), exit_code)

    if findings_count:
        print_warning(f"Potential issues detected in {target.name}")
        record_finding(
            scan_id=scan_id,
            file_path=str(target),
            severity="high",
            type="hallucinated_api",
            line=None,
            description=response,
            fix="Manual review required",
            confidence="low",
            source="llm",
        )
    else:
        print_success(f"No obvious vulnerabilities found in {target.name}")

    render_scan_summary(str(target), findings_count, exit_code)
    sys.exit(exit_code)
