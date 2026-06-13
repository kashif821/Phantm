import typer
from rich.table import Table
from rich import print as rprint
from typing import Any
from phantm.config.settings import PhantmSettings
from phantm.config.mutator import set_config_value

app = typer.Typer()

_SECRET_KEYS = {"github_token", "virustotal_api_key", "abuseipdb_api_key", "nvd_api_key"}


def _mask(key: str, value: Any | None) -> str:
    if value is None:
        return "[UNSET]"
    s = str(value)
    if key in _SECRET_KEYS:
        if len(s) <= 8:
            return "********"
        return f"{'*' * (len(s) - 4)}{s[-4:]}"
    return s


@app.command()
def show() -> None:
    """Show current configuration."""
    settings = PhantmSettings()

    table = Table(title="Phantm Configuration", title_style="bold cyan")
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="yellow")

    table.add_row("github_token", _mask("github_token", settings.github_token))
    table.add_row("virustotal_api_key", _mask("virustotal_api_key", settings.virustotal_api_key))
    table.add_row("abuseipdb_api_key", _mask("abuseipdb_api_key", settings.abuseipdb_api_key))
    table.add_row("nvd_api_key", _mask("nvd_api_key", settings.nvd_api_key))
    table.add_row("default_model", _mask("default_model", settings.default_model))
    table.add_row("cache_virustotal_ttl_hours", _mask("cache_virustotal_ttl_hours", str(settings.cache_virustotal_ttl_hours)))
    table.add_row("cache_abuseipdb_ttl_hours", _mask("cache_abuseipdb_ttl_hours", str(settings.cache_abuseipdb_ttl_hours)))
    table.add_row("cache_nvd_ttl_days", _mask("cache_nvd_ttl_days", str(settings.cache_nvd_ttl_days)))

    rprint(table)


@app.command()
def set(key: str, value: str) -> None:
    """Set a configuration value.

    Use dotted notation for nested keys, e.g. cache.virustotal_ttl_hours 12
    """
    set_config_value(key, value)
    rprint(f"[green]✓[/green] Set [bold]{key}[/bold] = {value}")
