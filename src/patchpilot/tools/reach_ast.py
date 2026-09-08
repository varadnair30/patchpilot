"""Static reachability analysis. No LLM, no network.

Answers three questions about one advisory against one repo:

1. Is the vulnerable package imported anywhere?  (import + from-import, aliases resolved)
2. If the advisory names vulnerable symbols, is any of them referenced?  (dotted-name resolution
   through aliases; bare symbols such as a Jinja filter name are searched in code and templates)
3. Is the package a runtime dependency of the app, or only used from tests / declared dev-only?

Confidence encodes what we could and could not see (DESIGN.md §3):
  * not imported at all                       -> 0.90 (dynamic imports are the residual risk)
  * imported, symbols known and searched      -> 0.85
  * imported, advisory names no symbols       -> 0.50 (we only know the package is used)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from packaging.utils import canonicalize_name
from pydantic import BaseModel, Field

from patchpilot.graph.state import CallSite, Reachability
from patchpilot.guardrails.contracts import contract

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    "build",
    "dist",
}
TEST_DIR_NAMES = {"tests", "test", "testing"}
TEMPLATE_SUFFIXES = {".html", ".htm", ".j2", ".jinja", ".jinja2", ".xml"}

# distribution name -> import names, for the common cases where they differ.
# Anything not listed falls back to the canonical name with '-' replaced by '_'.
IMPORT_NAME_OVERRIDES: dict[str, list[str]] = {
    "pyjwt": ["jwt"],
    "pillow": ["PIL"],
    "python-multipart": ["multipart", "python_multipart"],
    "beautifulsoup4": ["bs4"],
    "pyyaml": ["yaml"],
    "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "python-dateutil": ["dateutil"],
    "python-dotenv": ["dotenv"],
    "psycopg2-binary": ["psycopg2"],
    "msgpack-python": ["msgpack"],
    "attrs": ["attr", "attrs"],
    "google-cloud-storage": ["google.cloud.storage"],
}


class ReachabilityInput(BaseModel):
    repo_path: str
    package: str = Field(description="Canonical distribution name")
    vulnerable_symbols: list[str] = Field(default_factory=list)
    declared_dev: bool = False


class ReachabilityOutput(BaseModel):
    reachability: Reachability


def import_names_for(package: str) -> list[str]:
    canon = canonicalize_name(package)
    if canon in IMPORT_NAME_OVERRIDES:
        return IMPORT_NAME_OVERRIDES[canon]
    return [canon.replace("-", "_")]


def _is_test_path(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    parts = {p.lower() for p in rel.parts[:-1]}
    name = rel.name.lower()
    return (
        bool(parts & TEST_DIR_NAMES)
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def _iter_files(root: Path, suffixes: set[str]):
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.suffix in suffixes:
            yield p


class _FileAnalysis(ast.NodeVisitor):
    """Collects import bindings and resolves every Name/Attribute to a dotted path."""

    def __init__(self, roots: list[str]):
        self.roots = roots
        self.aliases: dict[str, str] = {}  # local name -> fully qualified dotted path
        self.import_lines: list[int] = []
        self.references: list[tuple[int, str]] = []  # (line, resolved dotted path)
        self.attr_names: list[tuple[int, str]] = []  # (line, bare attribute/name)

    def _is_ours(self, dotted: str) -> bool:
        head = dotted.split(".")[0]
        return any(head == r.split(".")[0] for r in self.roots)

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            if self._is_ours(a.name):
                self.import_lines.append(node.lineno)
                self.aliases[(a.asname or a.name.split(".")[0])] = (
                    a.name if a.asname else a.name.split(".")[0]
                )
                if not a.asname and "." in a.name:
                    # `import PIL.ImageCms` binds `PIL`; also remember the full path was imported
                    self.references.append((node.lineno, a.name))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        if node.level == 0 and self._is_ours(mod):
            self.import_lines.append(node.lineno)
            for a in node.names:
                if a.name == "*":
                    continue
                self.aliases[a.asname or a.name] = f"{mod}.{a.name}"
                self.references.append((node.lineno, f"{mod}.{a.name}"))
        self.generic_visit(node)

    def _resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.attr_names.append((node.lineno, node.attr))
        resolved = self._resolve(node)
        if resolved:
            self.references.append((node.lineno, resolved))
            return  # don't descend: inner attributes are prefixes of this one
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        resolved = self.aliases.get(node.id)
        if resolved and isinstance(node.ctx, ast.Load):
            self.references.append((node.lineno, resolved))
        self.generic_visit(node)


def _symbol_matches(resolved: str, symbol: str) -> bool:
    """`jwt.decode` matches reference `jwt.decode` or `jwt.decode.something`;
    `starlette.requests.Request.form` matches a reference to `starlette.requests.Request`
    only if followed by `.form`. Prefix in either direction is NOT enough: require the symbol to be
    a dotted-prefix of the reference."""
    return resolved == symbol or resolved.startswith(symbol + ".")


@contract(ReachabilityInput, ReachabilityOutput)
def analyze_reachability(inp: ReachabilityInput) -> ReachabilityOutput:
    root = Path(inp.repo_path)
    package_roots = import_names_for(inp.package)
    dotted_symbols = [s for s in inp.vulnerable_symbols if "." in s]
    bare_symbols = [s for s in inp.vulnerable_symbols if "." not in s]
    # Symbols may be re-exported by another package (fastapi.UploadFile -> starlette), so the
    # analysis also follows the symbols' own top-level names.
    symbol_roots = sorted({s.split(".")[0] for s in dotted_symbols})
    roots = sorted(set(package_roots) | set(symbol_roots))

    import_sites: list[str] = []
    reexport_sites: list[str] = []
    call_sites: list[CallSite] = []
    runtime_import = False
    test_import = False
    notes: list[str] = []

    for py in _iter_files(root, {".py"}):
        try:
            source = py.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py))
        except (SyntaxError, UnicodeDecodeError) as e:
            notes.append(f"skipped {py.relative_to(root)}: {e.__class__.__name__}")
            continue
        fa = _FileAnalysis(roots)
        fa.visit(tree)
        if not fa.import_lines:
            continue
        rel = str(py.relative_to(root))
        is_test = _is_test_path(py, root)
        lines = source.splitlines()
        direct = [
            ln
            for ln in fa.import_lines
            if any(
                re.search(rf"\b{re.escape(r.split('.')[0])}\b", lines[ln - 1])
                for r in package_roots
            )
        ]
        if direct:
            runtime_import |= not is_test
            test_import |= is_test
            import_sites.extend(f"{rel}:{ln}" for ln in direct)
        else:
            reexport_sites.extend(f"{rel}:{ln}" for ln in fa.import_lines)
        seen: set[tuple[str, int, str]] = set()
        for ln, ref in fa.references:
            for sym in dotted_symbols:
                if _symbol_matches(ref, sym) and (rel, ln, sym) not in seen:
                    seen.add((rel, ln, sym))
                    call_sites.append(
                        CallSite(file=rel, line=ln, symbol=sym, snippet=lines[ln - 1].strip()[:160])
                    )
                    if not direct:
                        runtime_import |= not is_test
                        test_import |= is_test
        for ln, attr in fa.attr_names:
            for sym in bare_symbols:
                if attr == sym and (rel, ln, sym) not in seen:
                    seen.add((rel, ln, sym))
                    call_sites.append(
                        CallSite(file=rel, line=ln, symbol=sym, snippet=lines[ln - 1].strip()[:160])
                    )

    # Bare symbols (e.g. a Jinja filter name) may live in templates rather than Python.
    if bare_symbols:
        for tpl in _iter_files(root, TEMPLATE_SUFFIXES):
            try:
                text_lines = tpl.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            rel = str(tpl.relative_to(root))
            for i, line in enumerate(text_lines, start=1):
                for sym in bare_symbols:
                    if re.search(rf"\b{re.escape(sym)}\b", line):
                        call_sites.append(
                            CallSite(file=rel, line=i, symbol=sym, snippet=line.strip()[:160])
                        )

    imported = bool(import_sites)
    via_reexport = bool(call_sites) and not imported
    if via_reexport:
        confidence = 0.85
        symbol_called: bool | None = True
        notes.append(
            f"not imported directly; vulnerable symbol reached via re-export ({reexport_sites[0]})"
        )
    elif not imported:
        confidence = 0.90
        symbol_called = False if inp.vulnerable_symbols else None
        notes.append("package is never imported; residual risk is dynamic import or transitive use")
    elif inp.vulnerable_symbols:
        confidence = 0.85
        symbol_called = bool(call_sites)
    else:
        confidence = 0.50
        symbol_called = None
        notes.append("advisory names no symbols; only import-level evidence is available")

    # Excluded from call sites: references that only appear in tests (still reported as evidence).
    is_runtime = (runtime_import and not inp.declared_dev) or (
        not imported and not via_reexport and not inp.declared_dev
    )
    if inp.declared_dev:
        notes.append("declared as a dev-only dependency")
    if imported and not runtime_import and test_import:
        notes.append("imported from test code only")

    return ReachabilityOutput(
        reachability=Reachability(
            imported=imported,
            import_sites=sorted(import_sites),
            symbol_called=symbol_called,
            call_sites=call_sites,
            is_runtime_dep=is_runtime,
            imported_from_test_only=(imported or via_reexport) and not runtime_import,
            confidence=confidence,
            notes=notes,
        )
    )
