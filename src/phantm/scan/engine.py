import ast
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from phantm._internal.db import get_intel_cache, set_intel_cache, create_scan_record, save_findings, update_scan_summary
from phantm._internal.intel.abuseipdb import check_ip
from phantm._internal.intel.exceptions import IntelRateLimitError, IntelAuthError
from phantm._internal.intel.virustotal import check_artifact
from phantm._internal.llm import ask_model, PhantmLLMError
from phantm.config.settings import PhantmSettings
from phantm.ui.components.feedback import print_info, print_error, print_warning, print_success
from phantm.ui.layouts.scan_report import render_scan_summary
from phantm.ui.console import console

_MAX_FILE_SIZE = 500 * 1024

_RISKY_CALLS: set[str] = {
    "os.system", "os.popen", "subprocess.run", "subprocess.Popen",
    "subprocess.call", "subprocess.check_output", "eval", "exec",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "openai.ChatCompletion.create", "openai.chat.completions.create",
    "litellm.completion",
}

_RISKY_KEYWORD_RE = re.compile(
    r"(os\.system|os\.popen|subprocess\.\w+|eval\(|exec\(|requests\.|openai\.|litellm\.)"
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s'\"\)]+")


def get_scannable_files(target_dir: Path) -> list[Path]:
    files: list[Path] = []
    for path in target_dir.rglob("*.py"):
        if path.is_symlink():
            continue
        if any(part.startswith(".") for part in path.parts):
            continue
        if any(part in {"venv", "env", "__pycache__", "node_modules"} for part in path.parts):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < 15 or size > _MAX_FILE_SIZE:
            continue
        files.append(path)
    return files


def _resolve_parent(file_path: Path, target: Path) -> Path:
    parent = target if target.is_dir() else target.parent
    return parent


def _enclosing_name(node: ast.AST) -> str:
    for parent in ast.walk(node):
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return parent.name
    return "<module>"


def extract_risky_blocks(file_path: Path) -> list[dict]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    try:
        tree = ast.parse(text)
    except SyntaxError:
        blocks: list[dict] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _RISKY_KEYWORD_RE.search(line):
                snippet = line.strip()[:200]
                blocks.append({
                    "file": str(file_path),
                    "line": lineno,
                    "snippet": snippet,
                    "enclosing": "<fallback>",
                    "start_line": lineno,
                    "end_line": lineno,
                })
        return blocks

    blocks = []
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
        else:
            continue
        full_name = ".".join(reversed(parts))

        if full_name not in _RISKY_CALLS:
            continue

        enclosing = _enclosing_name(node)
        lineno = getattr(node, "lineno", 1)
        end_lineno = getattr(node, "end_lineno", lineno)
        snippet = ast.get_source_segment(text, node)
        if snippet and len(snippet) > 300:
            snippet = snippet[:300] + "..."

        blocks.append({
            "file": str(file_path),
            "line": lineno,
            "snippet": snippet or "",
            "enclosing": enclosing,
            "start_line": lineno,
            "end_line": end_lineno,
        })

    return blocks


def gather_threat_intel(code_blocks: list[dict]) -> str:
    settings = PhantmSettings()
    vt_key = settings.virustotal_api_key
    ab_key = settings.abuseipdb_api_key
    vt_ttl = settings.cache_virustotal_ttl_hours
    ab_ttl = settings.cache_abuseipdb_ttl_hours

    combined_text = "\n".join(b.get("snippet", "") for b in code_blocks)
    ips = set(_IP_RE.findall(combined_text))
    urls = set(_URL_RE.findall(combined_text))

    context_lines: list[str] = []

    for ip in ips:
        cached = get_intel_cache(ip, ab_ttl)
        if cached is not None:
            abuse_score = cached.get("abuseConfidenceScore", "UNKNOWN")
            context_lines.append(f"[Intel: AbuseIPDB] IP {ip} — score {abuse_score}")
            continue
        if not ab_key:
            context_lines.append(f"[Intel: AbuseIPDB] IP {ip} — SKIPPED (no API key)")
            continue
        try:
            result = check_ip(ip, ab_key, ab_ttl)
            score = result.get("abuseConfidenceScore", "UNKNOWN")
            context_lines.append(f"[Intel: AbuseIPDB] IP {ip} — score {score}")
        except IntelRateLimitError:
            context_lines.append(f"[Intel: AbuseIPDB] IP {ip} — RATE_LIMITED")
        except (IntelAuthError, OSError) as e:
            context_lines.append(f"[Intel: AbuseIPDB] IP {ip} — ERROR: {e}")

    for url in urls:
        cached = get_intel_cache(url, vt_ttl)
        if cached is not None:
            malicious = cached.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            context_lines.append(f"[Intel: VirusTotal] URL {url} — {malicious} malicious reports")
            continue
        if not vt_key:
            context_lines.append(f"[Intel: VirusTotal] URL {url} — SKIPPED (no API key)")
            continue
        try:
            result = check_artifact(url, "urls", vt_key, vt_ttl)
            malicious = result.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            context_lines.append(f"[Intel: VirusTotal] URL {url} — {malicious} malicious reports")
        except IntelRateLimitError:
            context_lines.append(f"[Intel: VirusTotal] URL {url} — RATE_LIMITED")
        except (IntelAuthError, OSError) as e:
            context_lines.append(f"[Intel: VirusTotal] URL {url} — ERROR: {e}")

    return "\n".join(context_lines) if context_lines else "No threat intelligence data available."


def _run_llm_for_file(blocks: list[dict], threat_context: str, model: str, rel_path: str) -> list[dict]:
    code_summary = "\n---\n".join(
        f"File: {b['file']} line {b['line']} in {b['enclosing']}:\n{b['snippet']}"
        for b in blocks
    )

    system_prompt = (
        "You are an AI security auditor. Analyze the provided code blocks for vulnerabilities. "
        "Respond with ONLY a JSON array of objects, each with keys: "
        '"severity" ("CRITICAL"/"HIGH"/"MEDIUM"/"LOW"), '
        '"type" (short label), '
        '"description" (explanation), '
        '"line" (integer line number), '
        '"confidence" ("high"/"medium"/"low"), '
        'and "fix" (optional suggested fix string). '
        'If no vulnerabilities exist, return an empty array []. '
        "Do not include markdown formatting or extra text."
    )

    user_prompt = f"Threat Intelligence Context:\n{threat_context}\n\nCode Blocks:\n{code_summary}"

    try:
        raw = ask_model(system_prompt=system_prompt, user_prompt=user_prompt, model=model)
    except (PhantmLLMError, ValueError) as e:
        print_warning(f"LLM error for {rel_path}: {e}")
        return []

    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        print_warning(f"LLM returned unparseable JSON for {rel_path}")
        return []

    if not isinstance(parsed, list):
        parsed = [parsed]

    results: list[dict] = []
    for item in parsed:
        if isinstance(item, dict) and item.get("severity", "").upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            item["file"] = rel_path
            results.append(item)

    return results


def run_scan(path: str) -> None:
    target = Path(path).resolve()

    if not target.exists():
        print_error(f"Target does not exist: {path}")
        sys.exit(2)

    if target.is_symlink():
        print_error("Security Violation: Symlinks are not allowed as scan targets.")
        sys.exit(4)

    files_to_scan: list[Path] = []
    if target.is_file():
        files_to_scan = [target]
    else:
        print_info(f"Indexing directory: {target.name}/")
        files_to_scan = get_scannable_files(target)

    if not files_to_scan:
        print_warning(f"No scannable code found in {target.name}")
        sys.exit(0)

    print_info(f"Found {len(files_to_scan)} valid file(s). Starting 3-tier audit...")

    settings = PhantmSettings()
    model = settings.default_model
    parent = _resolve_parent(target, target)

    all_findings: list[dict] = []
    total_skipped = 0
    tier1_empty_count = 0
    all_llm_failed = False
    llm_success_count = 0

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        fut_map: dict = {}

        for file_path in files_to_scan:
            future = executor.submit(extract_risky_blocks, file_path)
            fut_map[future] = file_path

        blocks_by_file: dict[str, list[dict]] = {}

        for future in as_completed(fut_map):
            file_path = fut_map[future]
            rel_path = str(file_path.relative_to(parent))
            try:
                blocks = future.result()
            except Exception as exc:
                print_warning(f"Tier 1 crash for {rel_path}: {exc}")
                total_skipped += 1
                continue

            if not blocks:
                tier1_empty_count += 1
                continue

            blocks_by_file[rel_path] = blocks

        if tier1_empty_count > 0:
            print_info(f"{tier1_empty_count} file(s) had no risky patterns (Tier 1 early exit).")

        if not blocks_by_file:
            print_success("No risky patterns found across any scanned files.")
            sys.exit(0)

        print_info(f"Tier 1 passed for {len(blocks_by_file)} file(s). Gathering threat intelligence...")

        threat_context = gather_threat_intel(
            [b for blist in blocks_by_file.values() for b in blist]
        )
        print_info("Threat intelligence gathered. Dispatching to LLM...")

        llm_fut_map: dict = {}
        for rel_path, blocks in blocks_by_file.items():
            future = executor.submit(_run_llm_for_file, blocks, threat_context, model, rel_path)
            llm_fut_map[future] = rel_path

        for future in as_completed(llm_fut_map):
            rel_path = llm_fut_map[future]
            try:
                file_findings = future.result()
            except Exception as exc:
                print_warning(f"Tier 3 crash for {rel_path}: {exc}")
                total_skipped += 1
                continue

            if file_findings:
                llm_success_count += 1
                all_findings.extend(file_findings)
            else:
                all_llm_failed = True

    scan_id = create_scan_record(str(target), len(files_to_scan))

    mapped = [
        {
            "file_path": f.get("file", "unknown"),
            "line_number": str(f.get("line", "")),
            "severity": f.get("severity", "LOW"),
            "vuln_type": f.get("type", "unknown"),
            "description": f.get("description", ""),
        }
        for f in all_findings
    ]
    if mapped:
        save_findings(scan_id, mapped)
        update_scan_summary(scan_id, len(mapped))

    print()
    if all_findings:
        print_warning(f"Detected {len(all_findings)} vulnerability(ies):")
        for issue in all_findings:
            console.print(
                f"  [red]✗[/red] [bold white]{issue['file']}[/bold white]:"
                f"[{issue.get('line', '?')}] "
                f"[yellow]{issue.get('type', '?')}[/yellow] — "
                f"{issue.get('description', '')}"
            )
        exit_code = 1
    elif total_skipped > 0 and llm_success_count == 0:
        print_error("All LLM audits failed — network error.")
        exit_code = 3
    else:
        print_success("All scanned files appear secure.")
        exit_code = 0

    render_scan_summary(str(target), len(all_findings), exit_code)
    sys.exit(exit_code)
