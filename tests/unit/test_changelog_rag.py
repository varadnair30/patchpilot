"""Fetch, chunk and retrieve release notes for a version range.

Retrieval must be deterministic offline: with no embeddings available the tool falls back to
lexical scoring, and either way it is scored against the symbols the repo actually imports.
"""

import pytest

from patchpilot.recorded.store import MissingFixture, RecordedStore
from patchpilot.tools.changelog_rag import (
    ChangelogInput,
    chunk_release_notes,
    retrieve_changelog,
)


@pytest.fixture
def changelog(monkeypatch, tmp_path):
    monkeypatch.setenv("PATCHPILOT_FIXTURES_DIR", str(tmp_path))
    monkeypatch.setenv("PATCHPILOT_LLM", "off")
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    store = RecordedStore()

    def write(package: str, from_version: str, to_version: str, releases: list[dict]):
        store.write("changelog", f"{package}/{from_version}..{to_version}", {"releases": releases})

    yield write
    get_settings.cache_clear()


NOTES = [
    {
        "version": "2.32.0",
        "notes": (
            "## Breaking changes\n"
            "- `Session.request` no longer accepts the `strict` keyword; it was removed.\n"
            "\n"
            "## Improvements\n"
            "- Faster header parsing.\n"
        ),
    },
    {
        "version": "2.32.4",
        "notes": "## Bugfixes\n- Fix a leak in `Session.close`.\n",
    },
]


# ------------------------------------------------------------------ chunking


def test_chunks_carry_stable_ids_and_their_version():
    chunks = chunk_release_notes(NOTES)
    assert [c.chunk_id for c in chunks][:2] == ["2.32.0#0", "2.32.0#1"]
    assert all(c.version in {"2.32.0", "2.32.4"} for c in chunks)
    assert all(c.text.strip() for c in chunks)


def test_chunking_is_deterministic():
    assert [c.model_dump() for c in chunk_release_notes(NOTES)] == [
        c.model_dump() for c in chunk_release_notes(NOTES)
    ]


def test_headings_stay_attached_to_the_text_under_them():
    chunks = chunk_release_notes(NOTES)
    breaking = next(c for c in chunks if "strict" in c.text)
    assert "Breaking changes" in breaking.text


def test_empty_notes_produce_no_chunks():
    assert chunk_release_notes([{"version": "1.0.0", "notes": "   \n\n"}]) == []


# ------------------------------------------------------------------ retrieval


def test_retrieval_ranks_chunks_that_mention_the_repos_symbols(changelog):
    changelog("requests", "2.31.0", "2.32.4", NOTES)
    out = retrieve_changelog(
        ChangelogInput(
            package="requests",
            from_version="2.31.0",
            to_version="2.32.4",
            symbols=["Session.request"],
            top_k=2,
        )
    )
    assert out.retrieval == "lexical", "no embeddings available with the LLM off"
    assert out.chunks, "the reviewer gets something to read"
    assert "Session.request" in out.chunks[0].text
    assert len(out.chunks) == 2
    assert set(out.chunk_ids) >= {c.chunk_id for c in out.chunks}


def test_every_returned_chunk_id_exists_in_the_corpus(changelog):
    """The citation check downstream is only meaningful if ids are real."""
    changelog("requests", "2.31.0", "2.32.4", NOTES)
    out = retrieve_changelog(
        ChangelogInput(
            package="requests", from_version="2.31.0", to_version="2.32.4", symbols=["close"]
        )
    )
    assert {c.chunk_id for c in out.chunks} <= set(out.chunk_ids)


def test_no_symbols_still_returns_the_breaking_change_chunks(changelog):
    """An advisory that names no symbols still deserves a breaking-change read."""
    changelog("requests", "2.31.0", "2.32.4", NOTES)
    out = retrieve_changelog(
        ChangelogInput(
            package="requests", from_version="2.31.0", to_version="2.32.4", symbols=[], top_k=1
        )
    )
    assert out.chunks and "Breaking" in out.chunks[0].text


def test_top_k_bounds_the_result(changelog):
    changelog("requests", "2.31.0", "2.32.4", NOTES)
    out = retrieve_changelog(
        ChangelogInput(
            package="requests",
            from_version="2.31.0",
            to_version="2.32.4",
            symbols=["Session"],
            top_k=1,
        )
    )
    assert len(out.chunks) == 1


def test_a_package_with_no_recorded_changelog_is_reported_not_fatal(changelog):
    """A missing changelog must degrade the plan's evidence, not halt the branch."""
    out = retrieve_changelog(
        ChangelogInput(package="mystery", from_version="1.0.0", to_version="2.0.0", symbols=["x"])
    )
    assert out.chunks == [] and out.chunk_ids == []
    assert out.available is False
    assert any("no recorded changelog" in n for n in out.notes)


def test_an_empty_changelog_is_marked_unavailable(changelog):
    changelog("pkg", "1.0.0", "2.0.0", [])
    out = retrieve_changelog(
        ChangelogInput(package="pkg", from_version="1.0.0", to_version="2.0.0", symbols=[])
    )
    assert out.available is False and out.chunks == []


# ------------------------------------------------------------------ embeddings path


def test_recorded_embeddings_are_used_when_available(changelog, monkeypatch):
    """With embeddings recorded, retrieval is by cosine similarity rather than word overlap."""
    monkeypatch.setenv("PATCHPILOT_LLM", "on")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-used-offline")
    from patchpilot.config import get_settings

    get_settings.cache_clear()

    changelog("requests", "2.31.0", "2.32.4", NOTES)
    chunks = chunk_release_notes(NOTES)
    store = RecordedStore()
    from patchpilot.tools.changelog_rag import embedding_key, retrieval_query

    # Point the query at the *last* chunk, so a lexical tie-break cannot produce this ordering.
    target = chunks[-1]
    for chunk in chunks:
        vector = [1.0, 0.0] if chunk.chunk_id == target.chunk_id else [0.0, 1.0]
        store.write("embeddings", embedding_key(chunk.text), {"embedding": vector})
    query = retrieval_query("requests", ["Session.close"])
    store.write("embeddings", embedding_key(query), {"embedding": [1.0, 0.0]})

    out = retrieve_changelog(
        ChangelogInput(
            package="requests",
            from_version="2.31.0",
            to_version="2.32.4",
            symbols=["Session.close"],
            top_k=1,
        )
    )
    assert out.retrieval == "embeddings"
    assert out.chunks[0].chunk_id == target.chunk_id


def test_a_missing_embedding_fixture_falls_back_to_lexical(changelog, monkeypatch):
    monkeypatch.setenv("PATCHPILOT_LLM", "on")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-used-offline")
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    changelog("requests", "2.31.0", "2.32.4", NOTES)

    out = retrieve_changelog(
        ChangelogInput(
            package="requests",
            from_version="2.31.0",
            to_version="2.32.4",
            symbols=["Session.request"],
        )
    )
    assert out.retrieval == "lexical"
    assert any("embedding" in n for n in out.notes)
    assert out.chunks


def test_embedding_keys_are_content_addressed():
    from patchpilot.tools.changelog_rag import embedding_key

    assert embedding_key("abc") == embedding_key("abc")
    assert embedding_key("abc") != embedding_key("abd")


def test_recorded_mode_never_reaches_the_network(changelog):
    """conftest makes any httpx call raise; this asserts the recorded path really is offline."""
    changelog("requests", "2.31.0", "2.32.4", NOTES)
    out = retrieve_changelog(
        ChangelogInput(
            package="requests", from_version="2.31.0", to_version="2.32.4", symbols=["Session"]
        )
    )
    assert out.available is True


def test_a_missing_fixture_in_a_strict_namespace_is_still_a_missing_fixture(changelog):
    store = RecordedStore()
    with pytest.raises(MissingFixture):
        store.read("changelog", "nope/1.0.0..2.0.0")
