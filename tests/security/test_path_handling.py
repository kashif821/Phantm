"""Test path-handling security: traversal, symlinks, null bytes."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


# ── Path Traversal (via cmd.py CLI handler) ──────────────────────


def test_path_traversal_rejected_at_cmd_layer() -> None:
    """cmd.py's run() must reject paths that escape the workspace."""
    from phantm.scan.cmd import run

    with patch("phantm.scan.cmd.run_scan") as mock_run:
        run(path="../../../etc/passwd")
        mock_run.assert_not_called()


def test_path_traversal_dot_dot(tmp_path: Path) -> None:
    """Resolved path outside workspace must be blocked."""
    from phantm.scan.cmd import run
    from phantm.scan.engine import run_scan as engine_run

    target = tmp_path / "subdir" / ".." / ".." / "outside"
    target.parent.mkdir(parents=True, exist_ok=True)

    with patch("phantm.scan.cmd.run_scan") as mock_run:
        run(path=str(target))
        mock_run.assert_not_called()


def test_engine_rejects_nonexistent_traversal_path() -> None:
    """Engine's run_scan should exit 2 when traversal target does not exist."""
    from phantm.scan.engine import run_scan

    with pytest.raises(SystemExit) as exc:
        run_scan("/nonexistent/../../no_such_file_xyz")
    assert exc.value.code == 2


# ── Symlink Attacks ──────────────────────────────────────────────


def test_symlink_target_rejected(tmp_path: Path) -> None:
    """Engine run_scan must reject symlink targets with exit 4."""
    from phantm.scan.engine import run_scan

    real = tmp_path / "real.py"
    real.write_text("import os\nos.system('ls')\n")
    link = tmp_path / "evil_link.py"
    link.symlink_to(real)

    with pytest.raises(SystemExit) as exc:
        run_scan(str(link))
    assert exc.value.code == 4


def test_symlink_inside_directory_skipped(tmp_path: Path) -> None:
    """get_scannable_files must skip symlinked files."""
    from phantm.scan.engine import get_scannable_files

    real = tmp_path / "real.py"
    real.write_text("import os\nos.system('ls')\n")
    link = tmp_path / "link.py"
    link.symlink_to(real)
    legit = tmp_path / "legit.py"
    legit.write_text("import sys\nx = 1\nprint(x)\n")

    files = get_scannable_files(tmp_path)
    paths = [str(f.name) for f in files]
    assert "link.py" not in paths
    assert "legit.py" in paths


def test_symlink_rejected_at_cmd_layer(tmp_path: Path) -> None:
    """cmd.py must block symlink targets before engine is invoked."""
    from phantm.scan.cmd import run

    real = tmp_path / "real.py"
    real.write_text("x = 1\n")
    link = tmp_path / "evil_link.py"
    link.symlink_to(real)

    with patch("phantm.scan.cmd.run_scan") as mock_run:
        run(path=str(link))
        mock_run.assert_not_called()


# ── Null Byte Injection ──────────────────────────────────────────


def test_null_byte_in_path_raises_value_error() -> None:
    """Null byte in a path should cause a ValueError from the OS layer."""
    from phantm.scan.engine import run_scan

    with pytest.raises((ValueError, OSError, SystemExit)):
        run_scan("src/benign.py\x00malicious.py")


def test_null_byte_in_cmd_layer_safe() -> None:
    """cmd.py run() must not crash on null byte inputs."""
    from phantm.scan.cmd import run

    try:
        run(path="src/benign.py\x00malicious.py")
    except (ValueError, OSError, SystemExit):
        pass
    except Exception:
        pytest.fail("Null byte input caused an unexpected exception type")


# ── Hidden / Special Paths ───────────────────────────────────────


def test_dotfile_directory_skipped(tmp_path: Path) -> None:
    """get_scannable_files must skip files inside hidden directories."""
    from phantm.scan.engine import get_scannable_files

    hidden = tmp_path / ".hidden"
    hidden.mkdir()
    f = hidden / "malicious.py"
    f.write_text("import os\nos.system('ls')\n")

    files = get_scannable_files(tmp_path)
    assert all(".hidden" not in str(p) for p in files)


def test_venv_directory_skipped(tmp_path: Path) -> None:
    """get_scannable_files must skip virtual-environment directories."""
    from phantm.scan.engine import get_scannable_files

    venv = tmp_path / "venv"
    venv.mkdir()
    f = venv / "pwn.py"
    f.write_text("import os\nos.system('ls')\n")

    files = get_scannable_files(tmp_path)
    assert all("venv" not in str(p) for p in files)
