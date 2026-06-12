import sys
from pathlib import Path
from phantm._internal.db import record_scan, record_finding
from phantm.rules.engine import run_tier_1_checks
from phantm.ui.components.feedback import print_info, print_error, print_success, print_warning
from phantm.ui.layouts.scan_report import render_scan_summary


def run_scan(path: str) -> None:
    target = Path(path).resolve()

    if not target.exists() or not target.is_file():
        print_error(f"Target does not exist or is not a file: {path}")
        sys.exit(2)

    print_info(f"Starting scan on {target}...")

    findings = run_tier_1_checks(str(target))
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
