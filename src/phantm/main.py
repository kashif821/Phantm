import typer
from pathlib import Path
import os
from rich import print as rprint
from rich.panel import Panel

app = typer.Typer()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Phantm - Security scanner for LLM-generated code."""
    _ensure_phantm_dir()
    if ctx.invoked_subcommand is None:
        rprint(
            Panel.fit(
                "[bold cyan]Phantm[/bold cyan] - Security Scanner "
                "for LLM-generated Code\n"
                "Use [yellow]phantm --help[/yellow] to see available commands.",
                border_style="cyan",
            )
        )


def _ensure_phantm_dir() -> None:
    config_dir = Path.home() / ".phantm"
    config_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config_dir, 0o700)
    (config_dir / ".env").touch(exist_ok=True)
    (config_dir / "config.toml").write_text("")

    from phantm._internal.db import init_db

    init_db()


from phantm.config.cmd import app as config_app
from phantm.scan.cmd import app as scan_app
from phantm.report.cmd import app as report_app

app.add_typer(config_app, name="config")
app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
