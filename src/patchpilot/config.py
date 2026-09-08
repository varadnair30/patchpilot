"""Runtime settings. Everything comes from environment variables (or a .env file)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_FIXTURES = PACKAGE_ROOT / "recorded" / "fixtures"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PATCHPILOT_", env_file=".env", extra="ignore")

    # "recorded": replay JSON fixtures, zero network (default for demo, tests, CI).
    # "live": call OSV.dev / FIRST EPSS. With record=True, live responses are written to fixtures.
    mode: Literal["recorded", "live"] = "recorded"
    record: bool = False
    fixtures_dir: Path = DEFAULT_FIXTURES

    osv_base_url: str = "https://api.osv.dev/v1"
    epss_base_url: str = "https://api.first.org/data/v1/epss"
    http_timeout_seconds: float = 20.0

    model_primary: str = "gpt-4o-mini"
    model_judge: str = "gpt-4o"

    # Per-run budget (enforced from step 3 when the LLM is wired in)
    budget_tokens: int = 200_000
    budget_usd: float = 1.00


@lru_cache
def get_settings() -> Settings:
    return Settings()
