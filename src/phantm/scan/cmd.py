import os
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
    raw_path = Path(path)

    if raw_path.is_symlink():
        print_error("Security Violation: Symlinks are not allowed as scan targets.")
        return

    try:
        target_path = raw_path.resolve(strict=True)
    except FileNotFoundError:
        print_error(f"Invalid target: Path does not exist.")
        return
    workspace = Path.cwd().resolve()

    if not target_path.is_relative_to(workspace):
        print_error(f"Security Violation: Target path '{target_path}' escapes the current workspace.")
        return

    if not target_path.exists():
        print_error(f"Invalid target: {target_path} does not exist.")
        return

    run_scan(str(target_path))
