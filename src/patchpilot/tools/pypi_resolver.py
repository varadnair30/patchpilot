"""Resolve the minimal safe version of a package that the repo can actually install.

Two questions, answered from PyPI metadata only (no installing, no solving):

1. What is the smallest published, non-yanked, non-prerelease release at or above the version that
   clears the advisory?
2. Do the repo's *other* pins allow it? `fastapi==0.100.0` requires `starlette<0.28.0`, so bumping
   starlette to 0.40.0 is not a one-line change — and the reviewer has to be told that, not
   discover it from a red test run.

Recorded mode replays two fixture namespaces:

    pypi/project/<package>.json          {"versions": {"2.32.0": {"yanked": false}, ...}}
    pypi/requires/<name>==<version>.json {"requires_dist": ["starlette<0.28.0,>=0.27.0", ...]}

Live mode derives both from `https://pypi.org/pypi/...` and stores exactly those shapes, so the
fixture tree stays small and diffable rather than mirroring PyPI's multi-megabyte release blobs.
"""

from __future__ import annotations

from typing import Any

import httpx
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field

from patchpilot.config import get_settings
from patchpilot.graph.state import BumpKind, Dependency
from patchpilot.guardrails.contracts import contract
from patchpilot.policy.rules import bump_kind
from patchpilot.recorded.store import MissingFixture, RecordedStore


class VersionConstraint(BaseModel):
    """Another installed distribution's opinion about this package's version."""

    requirer: str
    requirer_version: str
    specifier: str

    def describe(self, package: str) -> str:
        return f"{self.requirer} {self.requirer_version} requires {package}{self.specifier}"


class ResolverInput(BaseModel):
    package: str
    installed_version: str
    min_fixed_version: str | None = None
    dependencies: list[Dependency] = Field(
        default_factory=list,
        description="The repo's other pins, used to discover constraints on this package",
    )


class ResolverOutput(BaseModel):
    package: str
    target_version: str | None = None
    bump_kind: BumpKind | None = None
    candidates: list[str] = Field(
        default_factory=list, description="Safe releases considered, ascending"
    )
    constraints: list[VersionConstraint] = Field(default_factory=list)
    conflicts: list[str] = Field(
        default_factory=list, description="Constraints the target version violates"
    )
    reason: str = ""
    notes: list[str] = Field(default_factory=list)


def _live_project(package: str) -> dict[str, Any]:
    """Trim PyPI's project JSON to what the resolver needs: version -> yanked."""
    s = get_settings()
    with httpx.Client(timeout=s.http_timeout_seconds) as client:
        r = client.get(f"{s.pypi_base_url}/{package}/json")
        r.raise_for_status()
        data = r.json()
    versions = {}
    for version, files in (data.get("releases") or {}).items():
        # A release with no files, or whose every file is yanked, cannot be installed.
        yanked = all(f.get("yanked", False) for f in files) if files else True
        versions[version] = {"yanked": yanked}
    return {"name": data.get("info", {}).get("name", package), "versions": versions}


def _live_requires(package: str, version: str) -> dict[str, Any]:
    s = get_settings()
    with httpx.Client(timeout=s.http_timeout_seconds) as client:
        r = client.get(f"{s.pypi_base_url}/{package}/{version}/json")
        r.raise_for_status()
        data = r.json()
    return {"requires_dist": list(data.get("info", {}).get("requires_dist") or [])}


def _version(raw: str) -> Version | None:
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _installable_versions(project: dict[str, Any]) -> list[Version]:
    out = []
    for raw, meta in (project.get("versions") or {}).items():
        if (meta or {}).get("yanked"):
            continue
        parsed = _version(raw)
        if parsed is None or parsed.is_prerelease or parsed.is_devrelease:
            continue
        out.append(parsed)
    return sorted(out)


def _constraints_on(
    package: str, dependencies: list[Dependency], store: RecordedStore
) -> tuple[list[VersionConstraint], list[str]]:
    """What every other installed distribution says about `package`."""
    canon = canonicalize_name(package)
    constraints: list[VersionConstraint] = []
    notes: list[str] = []
    for dep in dependencies:
        if canonicalize_name(dep.name) == canon:
            continue  # a package does not constrain itself
        try:
            meta = store.fetch(
                "pypi/requires",
                f"{dep.name}=={dep.version}",
                lambda d=dep: _live_requires(d.name, d.version),
            )
        except MissingFixture:
            notes.append(f"no recorded metadata for {dep.name}=={dep.version}; constraint unknown")
            continue
        for line in meta.get("requires_dist") or []:
            try:
                req = Requirement(line)
            except InvalidRequirement:
                continue
            if canonicalize_name(req.name) != canon:
                continue
            # `; extra == "..."` only applies when that extra is installed, and none are.
            if req.marker is not None and "extra" in str(req.marker):
                continue
            if not str(req.specifier):
                continue
            constraints.append(
                VersionConstraint(
                    requirer=dep.name, requirer_version=dep.version, specifier=str(req.specifier)
                )
            )
    return constraints, notes


@contract(ResolverInput, ResolverOutput)
def resolve_target_version(inp: ResolverInput) -> ResolverOutput:
    store = RecordedStore()
    out = ResolverOutput(package=inp.package)

    if not inp.min_fixed_version:
        out.reason = "advisory has no fixed version"
        return out

    project = store.fetch("pypi/project", inp.package, lambda: _live_project(inp.package))
    floor = _version(inp.min_fixed_version)
    safe = [v for v in _installable_versions(project) if floor is None or v >= floor]
    out.candidates = [str(v) for v in safe]
    if not safe:
        out.reason = f"no published release at or above {inp.min_fixed_version}"
        return out

    constraints, notes = _constraints_on(inp.package, inp.dependencies, store)
    out.constraints = constraints
    out.notes = notes

    specifiers = [Requirement(f"{inp.package}{c.specifier}").specifier for c in constraints]

    def allowed(version: Version) -> bool:
        return all(version in spec for spec in specifiers)

    # Prefer a target the repo can actually install; fall back to the minimal safe version and
    # report the conflict, because "you also have to bump fastapi" is the reviewer's decision.
    installable = [v for v in safe if allowed(v)]
    target = installable[0] if installable else safe[0]
    out.target_version = str(target)
    out.bump_kind = bump_kind(inp.installed_version, str(target))
    out.conflicts = [
        c.describe(inp.package)
        for c, spec in zip(constraints, specifiers, strict=True)
        if target not in spec
    ]
    out.reason = (
        f"minimal safe version {target}"
        if not out.conflicts
        else f"minimal safe version {target}, blocked by {len(out.conflicts)} repo constraint(s)"
    )
    return out
