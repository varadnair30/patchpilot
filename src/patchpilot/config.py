"""Runtime settings. Everything comes from environment variables (or a .env file)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load .env into the process environment (never overriding a real environment variable). Settings
# below would read the file on their own, but OPENAI_API_KEY, LANGSMITH_* and GITHUB_TOKEN are read
# straight from os.environ — by us and by langchain — so they have to actually land there.
load_dotenv(override=False)

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
    pypi_base_url: str = "https://pypi.org/pypi"
    http_timeout_seconds: float = 20.0

    # Durable state (step 5). DATABASE_URL is deliberately un-prefixed: it is the standard name
    # every host injects. With it unset, checkpoints and the decision ledger live in a local
    # SQLite file, so `patchpilot scan` then `patchpilot queue approve` works with no setup.
    database_url: str | None = Field(default=None, validation_alias="DATABASE_URL")
    checkpoint_db: Path = Path(".patchpilot") / "checkpoints.sqlite"

    model_primary: str = "gpt-4o-mini"
    model_judge: str = "gpt-4o"
    model_embeddings: str = "text-embedding-3-small"

    # Per-run budget (enforced from step 3 when the LLM is wired in)
    budget_tokens: int = 200_000
    budget_usd: float = 1.00


@lru_cache
def get_settings() -> Settings:
    return Settings()
