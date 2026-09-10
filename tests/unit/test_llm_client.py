"""The LLM is optional, and every path that assumes otherwise is a bug.

PatchPilot's whole design is that decisions are identical with or without a model (ADR-0002). So a
missing key, a missing `[llm]` extra, or `PATCHPILOT_LLM=off` must all leave the tool fully usable —
in particular `patchpilot queue list`, which never touches a model at all.
"""

import builtins

import pytest

from patchpilot.llm.client import (
    MissingLLMExtra,
    get_chat_model,
    get_embeddings_model,
    llm_enabled,
    usage_cost,
)


@pytest.fixture
def llm_on(monkeypatch):
    """Opt back in: conftest turns the LLM off for the whole suite so a real key in .env can
    never make the tests spend money."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
    monkeypatch.setenv("PATCHPILOT_LLM", "on")


@pytest.fixture
def without_langchain_openai(monkeypatch):
    """Simulate an install that never got `pip install -e '.[llm]'`."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("langchain_openai"):
            raise ImportError("No module named 'langchain_openai'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


# ------------------------------------------------------------------ the off switch


def test_no_key_means_no_model():
    assert llm_enabled() is False
    assert get_chat_model() is None
    assert get_embeddings_model() is None


def test_a_key_turns_the_model_on(llm_on):
    assert llm_enabled() is True


def test_the_kill_switch_beats_a_present_key(monkeypatch):
    """`PATCHPILOT_LLM=off` is how the demo runs free and fully deterministic."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("PATCHPILOT_LLM", "off")
    assert llm_enabled() is False
    assert get_chat_model() is None


# ------------------------------------------------------------------ the missing extra


def test_a_missing_extra_is_a_clear_message_not_an_import_traceback(
    llm_on, without_langchain_openai
):
    with pytest.raises(MissingLLMExtra) as excinfo:
        get_chat_model()
    message = str(excinfo.value)
    assert ".[llm]" in message, "it must say how to fix it"
    assert "PATCHPILOT_LLM=off" in message, "and how to proceed without it"


def test_embeddings_report_the_missing_extra_the_same_way(llm_on, without_langchain_openai):
    with pytest.raises(MissingLLMExtra):
        get_embeddings_model()


def test_the_missing_extra_is_silent_when_the_llm_is_off(without_langchain_openai):
    """No key, no import, no error: the deterministic path needs nothing installed."""
    assert get_chat_model() is None
    assert get_embeddings_model() is None


# ------------------------------------------------------------------ import-time side effects


def test_importing_the_graph_module_builds_nothing(llm_on, without_langchain_openai):
    """Regression: `graph = build_graph()` at module scope constructed an OpenAI client on import,
    so a missing extra took down every command — `queue list` included."""
    import patchpilot.graph.build as build

    assert "graph" not in build.__dict__, "the Studio entry point must stay lazy"
    assert build.build_graph(justifier=None, summariser=None) is not None


def test_the_cli_imports_without_a_model(llm_on, without_langchain_openai):
    from patchpilot.cli.main import app

    assert app is not None


# ------------------------------------------------------------------ pricing


def test_no_usage_costs_nothing():
    budget = usage_cost("gpt-4o-mini", None)
    assert budget.tokens_used == 0 and budget.usd_used == 0.0


def test_tokens_are_priced_per_million():
    budget = usage_cost("gpt-4o-mini", {"input_tokens": 1_000_000, "output_tokens": 0})
    assert budget.tokens_used == 1_000_000
    assert budget.usd_used == pytest.approx(0.15)


def test_an_unknown_model_is_priced_conservatively():
    """Better to over-report spend than to slip past the budget gate."""
    unknown = usage_cost("some-new-model", {"input_tokens": 1_000_000, "output_tokens": 0})
    assert unknown.usd_used == pytest.approx(
        usage_cost("gpt-4o", {"input_tokens": 1_000_000}).usd_used
    )
