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
    phantm_dir = Path.home() / ".phantm"
    if not phantm_dir.exists():
        phantm_dir.mkdir()
        os.chmod(phantm_dir, 0o700)
        (phantm_dir / ".env").touch()
        (phantm_dir / "config.toml").write_text("")


from phantm.config.cmd import app as config_app
from phantm.scan.cmd import app as scan_app

app.add_typer(config_app, name="config")
app.add_typer(scan_app, name="scan")
