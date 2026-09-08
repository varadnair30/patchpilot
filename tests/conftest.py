import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEMO_APP = ROOT / "fixtures" / "patchpilot-demo-app"


@pytest.fixture(autouse=True)
def recorded_mode(monkeypatch):
    """Every test runs in recorded mode with the repo's fixtures; no network, ever."""
    monkeypatch.setenv("PATCHPILOT_MODE", "recorded")
    monkeypatch.setenv("PATCHPILOT_RECORD", "0")
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def demo_app() -> Path:
    assert DEMO_APP.exists(), "fixture repo missing"
    return DEMO_APP


@pytest.fixture
def tmp_repo(tmp_path: Path):
    """Factory for tiny synthetic repos: files is {relative_path: content}."""

    def make(files: dict[str, str]) -> Path:
        for rel, content in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return tmp_path

    return make


def _no_network(*args, **kwargs):
    raise AssertionError("network call attempted in recorded mode")


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    import httpx

    monkeypatch.setattr(httpx.Client, "get", _no_network)
    monkeypatch.setattr(httpx.Client, "post", _no_network)
    os.environ.pop("HTTPS_PROXY", None)
