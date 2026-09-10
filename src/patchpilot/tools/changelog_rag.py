"""Release notes for a version range: fetch, chunk, embed, retrieve.

The point of this tool is not "summarise the changelog". It is to put the *specific* paragraphs
that touch the symbols this repository actually imports in front of a human, with ids, so the
breaking-change summary written afterwards can be checked against them (ADR-0002: the model
summarises retrieved text and cites it; it does not decide anything).

Recorded mode replays:

    changelog/<package>/<from>..<to>.json   {"releases": [{"version": ..., "notes": ...}]}
    embeddings/<sha1-of-text>.json          {"embedding": [...]}

Retrieval degrades rather than fails. With no embeddings — the LLM is off, or a fixture is missing —
it scores lexically against the same query. Both paths are deterministic, and the path taken is
reported in `retrieval` so the reviewer and the eval suite can see which one ran.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from typing import Any

import httpx
from pydantic import BaseModel, Field

from patchpilot.config import get_settings
from patchpilot.graph.state import ChangelogChunk
from patchpilot.guardrails.contracts import contract
from patchpilot.llm.client import llm_enabled
from patchpilot.recorded.store import MissingFixture, RecordedStore

MAX_CHUNK_CHARS = 600
MAX_RELEASE_PAGES = 6
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ChangelogInput(BaseModel):
    package: str
    from_version: str
    to_version: str
    symbols: list[str] = Field(
        default_factory=list, description="Symbols the repo imports or calls; the retrieval query"
    )
    top_k: int = Field(default=5, ge=1, le=25)


class ChangelogOutput(BaseModel):
    package: str
    available: bool = False
    chunks: list[ChangelogChunk] = Field(default_factory=list, description="Top-k, best first")
    chunk_ids: list[str] = Field(
        default_factory=list, description="Every id in the corpus; the citation allowlist"
    )
    retrieval: str = "none"
    notes: list[str] = Field(default_factory=list)


def changelog_key(package: str, from_version: str, to_version: str) -> str:
    return f"{package}/{from_version}..{to_version}"


def embedding_key(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:24]


def retrieval_query(package: str, symbols: list[str]) -> str:
    """The text retrieval is scored against. Exposed so fixtures can be recorded for it."""
    return " ".join([package, *symbols])


# --------------------------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------------------------


#  "Funding" is a github.com URL too, and `github.com/sponsors/<user>` is not a repository.
SOURCE_URL_KEYS = ("source", "repository", "code", "homepage", "home")
_NOT_A_REPO_OWNER = {"sponsors", "orgs", "users", "apps", "features"}


def _source_repo(package: str) -> str | None:
    """PyPI project_urls -> owner/repo on GitHub, when the project declares one."""
    s = get_settings()
    with httpx.Client(timeout=s.http_timeout_seconds) as client:
        r = client.get(f"{s.pypi_base_url}/{package}/json")
        r.raise_for_status()
        project_urls = r.json().get("info", {}).get("project_urls") or {}

    def rank(label: str) -> int:
        lowered = label.lower()
        return next(
            (i for i, key in enumerate(SOURCE_URL_KEYS) if key in lowered), len(SOURCE_URL_KEYS)
        )

    for _label, url in sorted(project_urls.items(), key=lambda kv: rank(kv[0])):
        m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", str(url or ""))
        if m and m.group(1).lower() not in _NOT_A_REPO_OWNER:
            return f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
    return None


def github_headers() -> dict[str, str]:
    """Release notes are public, but anonymous requests are capped at 60/hour. A token — any
    token, no scopes needed — raises that to 5000, which is what re-recording fixtures needs."""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _live_releases(package: str, from_version: str, to_version: str) -> dict[str, Any]:
    """GitHub releases whose tag falls in (from, to]. Read-only, unauthenticated, public API."""
    from packaging.version import InvalidVersion, Version

    repo = _source_repo(package)
    if repo is None:
        return {"releases": []}

    def parse(tag: str):
        try:
            return Version(tag.lstrip("vV"))
        except InvalidVersion:
            return None

    low, high = parse(from_version), parse(to_version)
    if low is None or high is None:
        return {"releases": []}

    s = get_settings()
    out = []
    with httpx.Client(timeout=s.http_timeout_seconds) as client:
        # Releases come back newest first; walk pages until we are safely below the range.
        for page in range(1, MAX_RELEASE_PAGES + 1):
            r = client.get(
                f"https://api.github.com/repos/{repo}/releases",
                params={"per_page": "100", "page": str(page)},
                headers=github_headers(),
            )
            r.raise_for_status()
            payload = r.json()
            if not payload:
                break
            for release in payload:
                version = parse(str(release.get("tag_name") or ""))
                if version is not None and low < version <= high:
                    out.append({"version": str(version), "notes": release.get("body") or ""})
            oldest = min(
                (v for v in (parse(str(rel.get("tag_name") or "")) for rel in payload) if v),
                default=None,
            )
            if oldest is not None and oldest <= low:
                break
    out.sort(key=lambda rel: parse(rel["version"]) or low)
    return {"releases": out}


# --------------------------------------------------------------------------------------------
# Chunk
# --------------------------------------------------------------------------------------------


def chunk_release_notes(releases: list[dict[str, Any]]) -> list[ChangelogChunk]:
    """Split each release's notes on blank lines, keeping a heading with the text beneath it.

    Ids are `<version>#<n>` so a citation is readable on its own and stable across runs.
    """
    chunks: list[ChangelogChunk] = []
    for release in releases:
        version = str(release.get("version") or "")
        blocks: list[str] = []
        heading = ""
        for raw_block in re.split(r"\n\s*\n", str(release.get("notes") or "")):
            block = raw_block.strip()
            if not block:
                continue
            lines = block.splitlines()
            # A lone heading belongs to whatever follows it, not to a chunk of its own.
            if len(lines) == 1 and lines[0].lstrip().startswith("#"):
                heading = lines[0].strip()
                continue
            if lines[0].lstrip().startswith("#") and len(lines) > 1:
                heading, block = lines[0].strip(), "\n".join(lines[1:]).strip()
            text = f"{heading}\n{block}".strip() if heading else block
            for start in range(0, len(text), MAX_CHUNK_CHARS):
                blocks.append(text[start : start + MAX_CHUNK_CHARS])
        for index, text in enumerate(blocks):
            chunks.append(ChangelogChunk(chunk_id=f"{version}#{index}", version=version, text=text))
    return chunks


# --------------------------------------------------------------------------------------------
# Embed and retrieve
# --------------------------------------------------------------------------------------------


def _live_embedding(text: str, model: str) -> dict[str, Any]:
    from patchpilot.llm.client import get_embeddings_model

    client = get_embeddings_model(model)
    if client is None:  # pragma: no cover - only reachable in live mode without a key
        raise MissingFixture("embeddings are off")
    return {"embedding": list(client.embed_query(text))}


def _embed(texts: list[str], store: RecordedStore) -> list[list[float]] | None:
    """Recorded-or-live embeddings. Returns None when any text has no vector available."""
    if not llm_enabled():
        return None
    model = store.settings.model_embeddings
    vectors: list[list[float]] = []
    for text in texts:
        try:
            payload = store.fetch(
                "embeddings", embedding_key(text), lambda t=text: _live_embedding(t, model)
            )
        except MissingFixture:
            return None
        vectors.append([float(x) for x in payload["embedding"]])
    return vectors


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _tokens(text: str) -> list[str]:
    return [t.lower() for t in _WORD.findall(text)]


def _lexical_score(chunk_text: str, symbols: list[str], query_tokens: set[str]) -> float:
    """Exact symbol mentions dominate; shared vocabulary breaks ties; breaking changes win ties."""
    score = 0.0
    for symbol in symbols:
        if symbol and symbol in chunk_text:
            score += 10.0
        else:
            leaf = symbol.rsplit(".", 1)[-1]
            if leaf and re.search(rf"\b{re.escape(leaf)}\b", chunk_text):
                score += 4.0
    chunk_tokens = set(_tokens(chunk_text))
    score += len(query_tokens & chunk_tokens) * 0.5
    lowered = chunk_text.lower()
    breaking_words = ("breaking", "removed", "backward", "incompatible")
    score += sum(1.0 for word in breaking_words if word in lowered)
    score += 0.5 if "deprecat" in lowered else 0.0
    return score


@contract(ChangelogInput, ChangelogOutput)
def retrieve_changelog(inp: ChangelogInput) -> ChangelogOutput:
    store = RecordedStore()
    out = ChangelogOutput(package=inp.package)
    key = changelog_key(inp.package, inp.from_version, inp.to_version)

    try:
        payload = store.fetch(
            "changelog",
            key,
            lambda: _live_releases(inp.package, inp.from_version, inp.to_version),
        )
    except MissingFixture:
        out.notes.append(f"no recorded changelog for {key}")
        return out

    chunks = chunk_release_notes(payload.get("releases") or [])
    out.chunk_ids = [c.chunk_id for c in chunks]
    if not chunks:
        out.notes.append(f"changelog for {key} has no usable text")
        return out
    out.available = True

    query = retrieval_query(inp.package, inp.symbols)
    vectors = _embed([c.text for c in chunks], store)
    query_vector = _embed([query], store) if vectors is not None else None

    if vectors is not None and query_vector is not None:
        out.retrieval = "embeddings"
        ranked = sorted(
            zip(chunks, vectors, strict=True),
            key=lambda pair: -_cosine(query_vector[0], pair[1]),
        )
        out.chunks = [chunk for chunk, _ in ranked[: inp.top_k]]
    else:
        if llm_enabled():
            out.notes.append("no recorded embedding for every chunk; used lexical retrieval")
        out.retrieval = "lexical"
        query_tokens = set(_tokens(query))
        ranked_lex = sorted(
            chunks,
            key=lambda c: (-_lexical_score(c.text, inp.symbols, query_tokens), c.chunk_id),
        )
        out.chunks = ranked_lex[: inp.top_k]
    return out
