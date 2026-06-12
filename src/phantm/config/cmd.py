import typer
from rich import print as rprint
from phantm.config.settings import PhantmSettings
from phantm.config.mutator import load_config, save_config

app = typer.Typer()


@app.command()
def show() -> None:
    """Show current configuration."""
    settings = PhantmSettings()
    rprint(f"Debug: {settings.debug}")


@app.command()
def set(key: str, value: str) -> None:
    """Set a configuration value."""
    config = load_config()
    config[key] = value
    save_config(config)
    rprint(f"Set [bold]{key}[/bold] = {value}")
