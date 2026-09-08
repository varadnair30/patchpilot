"""LLM access. One place that knows about OpenAI, pricing, and LangSmith.

* `get_chat_model()` returns a ChatOpenAI for the configured model, or None when no key is set
  (the graph then runs "LLM off": deterministic fallbacks, zero cost, still fully testable).
* `usage_cost()` converts usage metadata into a Budget delta using the price table below.
* LangSmith tracing needs no code: setting LANGSMITH_TRACING=true and LANGSMITH_API_KEY in the
  environment makes langchain-core emit traces for every model call and every graph node.
"""

from __future__ import annotations

import os
from typing import Any

from patchpilot.config import get_settings
from patchpilot.graph.state import Budget

# USD per 1M tokens (input, output). Update deliberately; cost gates in CI read Budget, not this.
PRICES: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
}


def llm_enabled() -> bool:
    return (
        bool(os.environ.get("OPENAI_API_KEY")) and os.environ.get("PATCHPILOT_LLM", "on") != "off"
    )


def get_chat_model(model: str | None = None, temperature: float = 0.0) -> Any | None:
    if not llm_enabled():
        return None
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(model=model or get_settings().model_primary, temperature=temperature)


def usage_cost(model: str, usage: dict[str, Any] | None) -> Budget:
    """Budget delta for one call. Unknown models are priced like gpt-4o to stay conservative."""
    if not usage:
        return Budget()
    inp = int(usage.get("input_tokens", 0))
    out = int(usage.get("output_tokens", 0))
    price_in, price_out = PRICES.get(model, PRICES["gpt-4o"])
    return Budget(tokens_used=inp + out, usd_used=(inp * price_in + out * price_out) / 1_000_000)
