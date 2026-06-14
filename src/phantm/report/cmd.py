import typer
from rich.markup import escape
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from phantm.ui.console import console
from phantm.ui.components.feedback import print_error
from phantm.ui.themes import COLOR_DANGER, COLOR_WARNING, COLOR_INFO, COLOR_DIM
from phantm.report.engine import get_latest_report_data

app = typer.Typer()

_SEVERITY_COLORS = {
    "critical": COLOR_DANGER,
    "high": COLOR_DANGER,
    "medium": COLOR_WARNING,
    "low": COLOR_INFO,
    "info": COLOR_INFO,
}


def _color_severity(severity: str) -> str:
    safe_severity = escape(severity)
    color = _SEVERITY_COLORS.get(safe_severity.lower(), COLOR_DIM)
    return f"[{color}]{safe_severity}[/]"


@app.callback(invoke_without_command=True)
def default_report() -> None:
    """Show the most recent scan report."""
    data = get_latest_report_data()

    if data is None:
        console.print(f"[{COLOR_INFO}]No scans have been run yet.[/]")
        return

    scan_info = data.get("scan", {})
    findings = data.get("findings", [])

    if not scan_info:
        print_error("Report data is corrupted or empty.")
        return

    summary = Panel.fit(
        f"[bold]Target:[/] {scan_info.get('target_path', 'N/A')}\n"
        f"[bold]Timestamp:[/] {scan_info.get('timestamp', 'N/A')}\n"
        f"[bold]Total Findings:[/] {scan_info.get('total_findings', 0)}",
        title="Scan Summary",
        border_style=COLOR_INFO,
    )
    console.print(summary)

    if not findings:
        console.print(f"\n[{COLOR_INFO}]No findings to display.[/]")
        return

    table = Table(title="Vulnerability Findings", title_style="bold cyan")
    table.add_column("Line", style=COLOR_DIM, no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Description")

    for f in findings:
        line_str = str(f["line_number"]) if f.get("line_number") else "-"
        table.add_row(
            line_str,
            _color_severity(f["severity"]),
            f["vuln_type"],
            f["description"],
        )

    console.print(table)
