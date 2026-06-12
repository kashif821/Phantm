import tomlkit
from pathlib import Path


def load_config(path: Path | None = None) -> dict:
    path = path or Path.home() / ".phantm" / "config.toml"
    if not path.exists():
        return {}
    return tomlkit.parse(path.read_text())


def save_config(config: dict, path: Path | None = None) -> None:
    path = path or Path.home() / ".phantm" / "config.toml"
    path.write_text(tomlkit.dumps(config))
