"""Recorded-response store.

Every external call the tools make goes through `RecordedStore.fetch(namespace, key, live_fn)`:

* recorded mode  -> return fixtures/<namespace>/<key>.json, or raise `MissingFixture`.
* live mode      -> call `live_fn()`; if `record` is on, write the response as a fixture.

Keys are plain strings chosen by the caller (an advisory id, "requests==2.31.0", a CVE id) so the
fixture tree is browsable and diffable in git.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from patchpilot.config import Settings, get_settings

_SAFE = re.compile(r"[^A-Za-z0-9._=+-]")


class MissingFixture(RuntimeError):
    """Raised in recorded mode when no fixture exists for a request."""


def _safe_key(key: str) -> str:
    return _SAFE.sub("_", key)


class RecordedStore:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.root = Path(self.settings.fixtures_dir)

    def path(self, namespace: str, key: str) -> Path:
        return self.root / namespace / f"{_safe_key(key)}.json"

    def has(self, namespace: str, key: str) -> bool:
        return self.path(namespace, key).exists()

    def read(self, namespace: str, key: str) -> Any:
        p = self.path(namespace, key)
        if not p.exists():
            raise MissingFixture(
                f"No recorded fixture for {namespace}/{key}. "
                f"Run once with PATCHPILOT_MODE=live PATCHPILOT_RECORD=1 to create it."
            )
        return json.loads(p.read_text(encoding="utf-8"))

    def write(self, namespace: str, key: str, payload: Any) -> Path:
        p = self.path(namespace, key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return p

    def fetch(self, namespace: str, key: str, live_fn: Callable[[], Any]) -> Any:
        if self.settings.mode == "recorded":
            return self.read(namespace, key)
        payload = live_fn()
        if self.settings.record:
            self.write(namespace, key, payload)
        return payload
