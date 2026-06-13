from rich.markup import escape
from rich.panel import Panel
from phantm.ui.console import console
from phantm.ui.themes import (
    COLOR_DANGER,
    COLOR_WARNING,
    COLOR_SUCCESS,
    COLOR_INFO,
    COLOR_DIM,
)


def print_error(message: str) -> None:
    console.print(f"[{COLOR_DANGER}][ERROR][/] {escape(message)}")


def print_warning(message: str) -> None:
    console.print(f"[{COLOR_WARNING}][WARNING][/] {escape(message)}")


def print_success(message: str) -> None:
    console.print(f"[{COLOR_SUCCESS}][SUCCESS][/] {escape(message)}")


def print_info(message: str) -> None:
    console.print(f"[{COLOR_INFO}][INFO][/] {escape(message)}")


def print_degraded_notice(state: str, message: str, action: str) -> None:
    console.print(
        Panel.fit(
            f"[bold {COLOR_WARNING}]{state}[/]\n\n"
            f"{message}\n\n"
            f"[{COLOR_DIM}]{action}[/]",
            border_style=COLOR_WARNING,
        )
    )
