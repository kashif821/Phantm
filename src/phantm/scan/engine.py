import json
import sys
from pathlib import Path
from phantm._internal.llm import ask_model, PhantmLLMError
from phantm.ui.components.feedback import print_info, print_error, print_warning, print_success
from phantm.ui.layouts.scan_report import render_scan_summary
from phantm.ui.console import console


def get_scannable_files(target_dir: Path) -> list[Path]:
    files = []
    for path in target_dir.rglob("*.py"):
        if any(part.startswith(".") for part in path.parts):
            continue
        if any(part in ("venv", "env", "__pycache__", "node_modules") for part in path.parts):
            continue
        if path.stat().st_size < 15:
            continue
        files.append(path)
    return files


def run_scan(path: str) -> None:
    target = Path(path).resolve()

    if not target.exists():
        print_error(f"Target does not exist: {path}")
        sys.exit(2)

    files_to_scan = []
    if target.is_file():
        files_to_scan = [target]
    else:
        print_info(f"Indexing directory: {target.name}/")
        files_to_scan = get_scannable_files(target)

    if not files_to_scan:
        print_warning(f"No scannable code found in {target.name}")
        sys.exit(0)

    print_info(f"Found {len(files_to_scan)} valid file(s). Starting AI audit...")

    system_prompt = (
        "You are an AI security auditor analyzing code snippets. "
        "Respond with ONLY a JSON object in this exact format: "
        '{"status": "VULNERABLE" or "SECURE", "reason": "<brief explanation of the flaw, or why it is safe>"}. '
        "Do not include markdown formatting or extra text."
    )

    findings = []

    for file_path in files_to_scan:
        rel_path = file_path.relative_to(target.parent) if target.is_dir() else file_path.name

        snippet = file_path.read_text(encoding="utf-8", errors="replace")[:1000]

        if not snippet.strip():
            continue

        try:
            response = ask_model(system_prompt=system_prompt, user_prompt=snippet)
        except PhantmLLMError as e:
            print_warning(f"Skipped {rel_path}: {e}")
            continue

        cleaned = response.strip().strip("`").removeprefix("json").strip()
        try:
            parsed = json.loads(cleaned)
            if parsed.get("status") == "VULNERABLE":
                reason = parsed.get("reason", "Unknown vulnerability detected")
                findings.append({"file": str(rel_path), "reason": reason})
        except json.JSONDecodeError:
            if "vulnerability" in cleaned.lower() or "insecure" in cleaned.lower():
                findings.append({"file": str(rel_path), "reason": "Potential issue detected via text fallback."})

    print()
    if findings:
        print_warning(f"Detected {len(findings)} vulnerable file(s):")
        for issue in findings:
            console.print(
                f"  [red]✗[/red] [bold white]{issue['file']}[/bold white]: "
                f"[yellow]{issue['reason']}[/yellow]"
            )
        print()
    else:
        print_success("All scanned files appear secure.")

    findings_count = len(findings)
    exit_code = 1 if findings_count > 0 else 0

    render_scan_summary(str(target), findings_count, exit_code)
    sys.exit(exit_code)
