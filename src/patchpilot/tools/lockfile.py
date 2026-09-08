"""Parse a Python project's pinned dependencies.

Supported in v1 (see DESIGN.md §6): requirements*.txt (with -r includes), pyproject.toml
([project.dependencies] and [project.optional-dependencies]), and uv.lock. Only exact pins
(`==`) are resolvable to an advisory lookup; anything else is reported in `unpinned`.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from pydantic import BaseModel, Field

from patchpilot.graph.state import Dependency
from patchpilot.guardrails.contracts import contract

DEV_FILE_HINTS = ("dev", "test", "lint", "docs")
DEV_GROUP_HINTS = ("dev", "test", "tests", "lint", "docs", "typing")


class LockfileInput(BaseModel):
    repo_path: str


class LockfileOutput(BaseModel):
    dependencies: list[Dependency] = Field(default_factory=list)
    unpinned: list[str] = Field(default_factory=list)
    files_read: list[str] = Field(default_factory=list)


def _is_dev_file(name: str) -> bool:
    stem = name.lower()
    return any(h in stem for h in DEV_FILE_HINTS)


def _pin_from_requirement(req: Requirement) -> str | None:
    for spec in req.specifier:
        if spec.operator in ("==", "==="):
            return spec.version
    return None


def _parse_requirements_file(
    path: Path, is_dev: bool, out: LockfileOutput, seen: set[Path]
) -> None:
    if path in seen or not path.exists():
        return
    seen.add(path)
    out.files_read.append(str(path.name))
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            # Included files keep their own scope: `-r requirements.txt` from a dev file is runtime.
            inc = path.parent / line.split(maxsplit=1)[1].strip()
            _parse_requirements_file(inc, _is_dev_file(inc.name), out, seen)
            continue
        if line.startswith("-"):
            continue  # other pip options
        line = re.split(r"\s+--", line)[0]  # strip --hash etc.
        try:
            req = Requirement(line)
        except InvalidRequirement:
            out.unpinned.append(line)
            continue
        pin = _pin_from_requirement(req)
        if pin is None:
            out.unpinned.append(line)
            continue
        out.dependencies.append(
            Dependency(
                name=canonicalize_name(req.name),
                version=pin,
                is_dev=is_dev,
                source_file=path.name,
            )
        )


def _parse_pyproject(path: Path, out: LockfileOutput) -> None:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    out.files_read.append(path.name)

    def add(reqs: list[str], is_dev: bool) -> None:
        for r in reqs:
            try:
                req = Requirement(r)
            except InvalidRequirement:
                out.unpinned.append(r)
                continue
            pin = _pin_from_requirement(req)
            if pin is None:
                out.unpinned.append(r)
                continue
            out.dependencies.append(
                Dependency(
                    name=canonicalize_name(req.name),
                    version=pin,
                    is_dev=is_dev,
                    source_file=path.name,
                )
            )

    add(project.get("dependencies", []), is_dev=False)
    for group, reqs in project.get("optional-dependencies", {}).items():
        add(reqs, is_dev=group.lower() in DEV_GROUP_HINTS)
    for group, reqs in data.get("dependency-groups", {}).items():
        add([r for r in reqs if isinstance(r, str)], is_dev=group.lower() in DEV_GROUP_HINTS)


def _parse_uv_lock(path: Path, out: LockfileOutput) -> None:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out.files_read.append(path.name)
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version or pkg.get("source", {}).get("editable"):
            continue
        out.dependencies.append(
            Dependency(
                name=canonicalize_name(name), version=version, is_dev=False, source_file=path.name
            )
        )


def _dedupe(deps: list[Dependency]) -> list[Dependency]:
    """Same (name, version) from several files -> one entry; runtime wins over dev."""
    best: dict[tuple[str, str], Dependency] = {}
    for d in deps:
        key = (d.name, d.version)
        if key not in best or (best[key].is_dev and not d.is_dev):
            best[key] = d
    return list(best.values())


@contract(LockfileInput, LockfileOutput)
def parse_lockfiles(inp: LockfileInput) -> LockfileOutput:
    root = Path(inp.repo_path)
    out = LockfileOutput()
    seen: set[Path] = set()

    uv_lock = root / "uv.lock"
    if uv_lock.exists():
        _parse_uv_lock(uv_lock, out)
    else:
        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            _parse_pyproject(pyproject, out)
        for req_file in sorted(root.glob("requirements*.txt")):
            _parse_requirements_file(req_file, _is_dev_file(req_file.name), out, seen)
        req_dir = root / "requirements"
        if req_dir.is_dir():
            for req_file in sorted(req_dir.glob("*.txt")):
                _parse_requirements_file(req_file, _is_dev_file(req_file.name), out, seen)

    out.dependencies = _dedupe(out.dependencies)
    return out
