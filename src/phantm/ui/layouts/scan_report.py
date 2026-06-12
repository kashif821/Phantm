from rich.panel import Panel
from rich.table import Table
from phantm.ui.console import console
from phantm.ui.themes import (
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_INFO,
    COLOR_DIM,
)


def render_scan_summary(target: str, findings_count: int, exit_code: int) -> None:
    status_color = COLOR_SUCCESS if exit_code == 0 else COLOR_DANGER

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style=COLOR_DIM, no_wrap=True)
    table.add_column("Value", style=COLOR_INFO)

    table.add_row("Target", target)
    table.add_row("Findings", str(findings_count))
    table.add_row("Exit code", f"[{status_color}]{exit_code}[/]")

    console.print(
        Panel.fit(
            table,
            title="[bold]Scan Summary[/bold]",
            border_style=COLOR_INFO,
        )
    )
