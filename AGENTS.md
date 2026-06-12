# AGENTS.md — Phantm

## Dev commands

```bash
pip install -e .           # editable install (src layout)
phantm --help              # verify CLI works
phantm config show         # read ~/.phantm/.env via Pydantic BaseSettings
phantm config set <k> <v>  # write ~/.phantm/config.toml via tomlkit
phantm scan run [path]     # placeholder scan controller
```

## Architecture

- **src layout**: `src/phantm/` is the installable package. `pyproject.toml` uses hatchling.
- **Entry point**: `phantm=phantm.main:app` — Typer app with `config` and `scan` subcommands.
- **First-run init**: `main.py:_ensure_phantm_dir()` creates `~/.phantm/` (mode 700), `.env`, and `config.toml` on first command invocation.
- **Config read**: `config/settings.py` — Pydantic `BaseSettings` loading from `~/.phantm/.env` with `PHANTM_` prefix, read-only.
- **Config write**: `config/mutator.py` — tomlkit-based R/W of `~/.phantm/config.toml`, write-only.
- **Scan**: `scan/cmd.py` → `scan/engine.py` — controller pattern, engine is a placeholder.

## Package boundaries

| Directory | Purpose |
|-----------|---------|
| `src/phantm/` | Package root |
| `config/` | Config read (settings.py) + write (mutator.py) + CLI (cmd.py) |
| `scan/` | Scan controller + engine |
| `report/` | Report generation (future) |
| `rules/` | Rule definitions (future) |
| `ui/` | Rich console helpers, themes, formatters (future) |
| `_internal/` | Shared infra — db, llm, intel (future) |

## Conventions

- Typer subcommands are registered in `main.py` via `app.add_typer(...)` after the import.
- All imports at module level (no lazy loading).
- `~/.phantm/` directory permissions are always `700` — never change this.
- `.env` in `~/.phantm/` is for env-var config, `config.toml` for persisted settings.
