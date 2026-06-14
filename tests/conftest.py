import pytest


@pytest.fixture(autouse=True)
def _mock_home(tmp_path: "pytest.TempPathFactory", monkeypatch: pytest.MonkeyPatch) -> None:
    """Point all Path.home() references to a temp directory for the entire session."""
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
