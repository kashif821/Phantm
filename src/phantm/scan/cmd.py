from pathlib import Path
import typer
from phantm.scan.engine import run_scan
from phantm.ui.components.feedback import print_error

app = typer.Typer()


@app.command()
def run(
    path: str = typer.Argument(
        default=".",
        help="File or directory path to scan.",
    ),
) -> None:
    """Run a security scan on the given path."""
    safe_path = Path(path).resolve()

    if not safe_path.exists():
        print_error(f"Invalid target: {safe_path} does not exist.")
        return

    run_scan(str(safe_path))
