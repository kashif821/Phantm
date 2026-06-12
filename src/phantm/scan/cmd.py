import typer
from phantm.scan.engine import run_scan

app = typer.Typer()


@app.command()
def run(
    path: str = typer.Argument(
        default=".",
        help="File or directory path to scan.",
    ),
) -> None:
    """Run a security scan on the given path."""
    run_scan(path)
