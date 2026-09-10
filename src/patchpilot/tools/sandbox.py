"""Does the bump break this repo's tests?

The only honest answer is to run them. The sandbox copies the repo into a container, installs it,
runs the suite unchanged to get a baseline, applies the bump, runs the suite again, and reports
`newly_failing` = after − before. The baseline matters: a repo with three already-red tests must not
have them blamed on the bump. Tests that fail after the bump are rerun once, and any that pass on
the rerun move to `flaky_rerun` instead of blocking the fix.

Nothing here decides anything. It produces evidence; `policy/rules.py` decides what it means.

Recorded mode replays `sandbox/<repo>/<pkg>==<from>..<to>.json`, so the graph, CI and the tests are
Docker-free. An un-recorded bump is reported as `supported=false` — unproven, therefore a human's
problem — rather than reaching for a container behind the caller's back.

Python-only for v1 (rule 8): requirements/pyproject/uv projects with pytest or unittest. Anything
else is `supported=false` and routes to a human.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name
from pydantic import BaseModel, Field

from patchpilot.graph.state import SandboxResult
from patchpilot.guardrails.contracts import contract
from patchpilot.recorded.store import MissingFixture, RecordedStore

DEFAULT_IMAGE = "python:3.12-slim"
PIP_CACHE_VOLUME = "patchpilot-pip-cache"
_PYTEST_FAILURE = re.compile(r"^(?:FAILED|ERROR)\s+(\S+?)(?:\s+-.*)?$", re.MULTILINE)
_UNITTEST_FAILURE = re.compile(r"^(?:FAIL|ERROR):\s+(\w+)\s+\(([\w.]+)\)", re.MULTILINE)
INSTALL_SENTINEL = "__PP_INSTALL_RC"
TEST_SENTINEL = "__PP_TEST_RC"


class SandboxInput(BaseModel):
    repo_path: str
    package: str
    installed_version: str
    target_version: str
    image: str = DEFAULT_IMAGE
    timeout_seconds: int = Field(default=900, ge=30, le=3600)


class SandboxOutput(BaseModel):
    result: SandboxResult
    mode: str = Field(description="recorded | docker | skipped")
    notes: list[str] = Field(default_factory=list)


class ProjectShape(BaseModel):
    supported: bool = False
    reason: str = ""
    install_command: list[str] = Field(default_factory=list)
    test_command: list[str] = Field(default_factory=list)
    test_runner: str = ""


# --------------------------------------------------------------------------------------------
# Detection — pure
# --------------------------------------------------------------------------------------------


def _has_tests(root: Path) -> bool:
    return any(root.glob("tests/test_*.py")) or any(root.glob("test_*.py"))


def _mentions_pytest(root: Path) -> bool:
    for name in ("requirements-dev.txt", "requirements.txt", "pyproject.toml", "setup.cfg"):
        path = root / name
        if path.exists() and "pytest" in path.read_text(encoding="utf-8", errors="ignore"):
            return True
    return False


def detect_project(repo_path: str) -> ProjectShape:
    """How to install and test this repo, or why we cannot (rule 8)."""
    root = Path(repo_path)

    if (root / "uv.lock").exists():
        install = ["uv", "sync", "--frozen"]
    elif (root / "requirements-dev.txt").exists():
        install = ["pip", "install", "-r", "requirements-dev.txt"]
    elif (root / "requirements.txt").exists():
        install = ["pip", "install", "-r", "requirements.txt"]
    elif (root / "pyproject.toml").exists():
        text = (root / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")
        install = ["pip", "install", "-e", ".[dev]" if "dev" in text else "."]
    else:
        return ProjectShape(
            reason="no requirements.txt, pyproject.toml or uv.lock: cannot install the project"
        )

    if not _has_tests(root):
        return ProjectShape(reason="no test files found under tests/ or the repo root")

    if _mentions_pytest(root) or (root / "uv.lock").exists():
        runner, test = "pytest", ["pytest", "-q", "--tb=no", "-p", "no:cacheprovider"]
    else:
        runner, test = "unittest", ["python", "-m", "unittest", "discover", "-v"]

    return ProjectShape(
        supported=True,
        install_command=install,
        test_command=test,
        test_runner=runner,
        reason=f"{' '.join(install)} then {runner}",
    )


# --------------------------------------------------------------------------------------------
# Applying the bump — pure
# --------------------------------------------------------------------------------------------


def _rewrite_pin(text: str, package: str, target_version: str) -> tuple[str, bool]:
    canon = canonicalize_name(package)
    changed = False
    out_lines = []
    for line in text.splitlines(keepends=True):
        # `requests==2.31.0  # http` and `"requests==2.31.0",` must both keep their surroundings.
        def replace(match: re.Match[str]) -> str:
            nonlocal changed
            if canonicalize_name(match.group(1)) != canon:
                return match.group(0)
            changed = True
            return f"{match.group(1)}=={target_version}"

        out_lines.append(re.sub(r"([A-Za-z0-9._-]+)==\s*([A-Za-z0-9._!+-]+)", replace, line))
    return "".join(out_lines), changed


def planned_edits(repo_path: str, package: str, target_version: str) -> dict[str, str]:
    """The bump as {repo-relative path: new content}, touching nothing on disk.

    The sandbox applies these to its throwaway copy; execute_pr commits the same content to a
    branch. Sharing one function is what makes "we tested exactly what we are proposing" true.
    """
    root = Path(repo_path)
    edits: dict[str, str] = {}
    candidates = sorted(root.glob("requirements*.txt")) + sorted(
        (root / "requirements").glob("*.txt")
    )
    if (root / "pyproject.toml").exists():
        candidates.append(root / "pyproject.toml")
    for path in candidates:
        text = path.read_text(encoding="utf-8")
        rewritten, did = _rewrite_pin(text, package, target_version)
        if did:
            edits[path.relative_to(root).as_posix()] = rewritten
    return edits


def apply_bump(repo_path: str, package: str, target_version: str) -> list[str]:
    """Rewrite the package's pin in place. Returns the repo-relative files that changed."""
    root = Path(repo_path)
    edits = planned_edits(repo_path, package, target_version)
    for relative, content in edits.items():
        (root / relative).write_text(content, encoding="utf-8")
    return list(edits)


# --------------------------------------------------------------------------------------------
# Output parsing and the diff — pure
# --------------------------------------------------------------------------------------------


def parse_pytest_failures(output: str) -> list[str]:
    return sorted({m.group(1) for m in _PYTEST_FAILURE.finditer(output)})


def parse_unittest_failures(output: str) -> list[str]:
    return sorted({f"{m.group(2)}.{m.group(1)}" for m in _UNITTEST_FAILURE.finditer(output)})


def diff_failures(before: list[str], after: list[str]) -> list[str]:
    """`newly_failing`: red after the bump and not red before it."""
    return sorted(set(after) - set(before))


# --------------------------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------------------------


def sandbox_key(repo_path: str, package: str, installed_version: str, target_version: str) -> str:
    return f"{Path(repo_path).name}/{package}=={installed_version}..{target_version}"


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        done = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


class RunResult(BaseModel):
    """One container run: what it printed, and whether each phase actually succeeded."""

    output: str = ""
    install_rc: int = -1
    test_rc: int = -1

    @property
    def installed(self) -> bool:
        return self.install_rc == 0

    @property
    def tests_ran(self) -> bool:
        # pytest: 0 = all passed, 1 = tests failed. Anything else (2-5, or 127 for "no such
        # command") means we never got a verdict, which is not the same as a green run.
        return self.test_rc in (0, 1)


def _run_in_container(work: Path, shape: ProjectShape, image: str, timeout: int) -> RunResult:
    """One container per test run: install, then test.

    Each phase's exit code is echoed with a sentinel. Without that, an install that fails outright
    prints no "FAILED" lines and parses as a clean, green run — which would hand `auto_fix` to a
    bump that cannot even be installed.
    """
    # The repository is mounted READ-ONLY and copied to a container-private directory first.
    # A read-write bind mount lets the container's root user litter the host directory with
    # root-owned __pycache__/.pytest_cache/egg-info, which the (non-root) caller then cannot
    # delete — a PermissionError on temp-directory cleanup that only shows up on Linux, because
    # Docker Desktop masks ownership on Windows and macOS.
    script = (
        "cp -a /src /build && cd /build && "
        f"{' '.join(shape.install_command)} ; echo {INSTALL_SENTINEL}=$? ; "
        f"{' '.join(shape.test_command)} ; echo {TEST_SENTINEL}=$?"
    )
    done = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{work}:/src:ro",
            "-v",
            f"{PIP_CACHE_VOLUME}:/root/.cache/pip",
            "-e",
            "PIP_DISABLE_PIP_VERSION_CHECK=1",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            image,
            "sh",
            "-lc",
            script,
        ],
        capture_output=True,
        text=True,
        # Container output is UTF-8. Decoding it with the host's locale (cp1252 on Windows)
        # crashes on the first box-drawing character pip prints.
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    output = (done.stdout or "") + (done.stderr or "")
    return RunResult(
        output=output,
        install_rc=_sentinel(output, INSTALL_SENTINEL),
        test_rc=_sentinel(output, TEST_SENTINEL),
    )


def _sentinel(output: str, name: str) -> int:
    match = re.search(rf"^{name}=(\d+)$", output, re.MULTILINE)
    return int(match.group(1)) if match else -1


def install_failure_reason(run: RunResult) -> str:
    """The one line from pip worth showing a reviewer."""
    for line in run.output.splitlines():
        stripped = line.strip()
        interesting = "conflict" in stripped or "Cannot install" in stripped
        if stripped.startswith("ERROR:") and interesting:
            return stripped[:300]
    for line in run.output.splitlines():
        if line.strip().startswith("ERROR:"):
            return line.strip()[:300]
    return f"install exited {run.install_rc}"


def _failures(run: RunResult, shape: ProjectShape) -> list[str]:
    if shape.test_runner == "pytest":
        return parse_pytest_failures(run.output)
    return parse_unittest_failures(run.output)


@contract(SandboxInput, SandboxOutput)
def run_sandbox(inp: SandboxInput) -> SandboxOutput:
    store = RecordedStore()
    shape = detect_project(inp.repo_path)
    if not shape.supported:
        return SandboxOutput(
            result=SandboxResult(supported=False, reason=shape.reason), mode="skipped"
        )

    key = sandbox_key(inp.repo_path, inp.package, inp.installed_version, inp.target_version)

    if store.settings.mode == "recorded":
        try:
            payload = store.read("sandbox", key)
        except MissingFixture:
            return SandboxOutput(
                result=SandboxResult(
                    supported=False,
                    reason=f"no recorded sandbox run for {key}; the bump is unproven",
                ),
                mode="recorded",
                notes=[f"missing fixture sandbox/{key}"],
            )
        return SandboxOutput(result=SandboxResult.model_validate(payload), mode="recorded")

    if not docker_available():
        return SandboxOutput(
            result=SandboxResult(supported=False, reason="live mode but no Docker engine"),
            mode="skipped",
        )

    notes: list[str] = []
    with tempfile.TemporaryDirectory(
        prefix="patchpilot-sandbox-", ignore_cleanup_errors=True
    ) as tmp:
        # Work on a copy: the sandbox must never modify the repository it was pointed at.
        work = Path(tmp) / Path(inp.repo_path).name
        shutil.copytree(
            inp.repo_path,
            work,
            ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "*.pyc", ".venv", ".pytest_cache", ".patchpilot"
            ),
        )
        try:
            base_run = _run_in_container(work, shape, inp.image, inp.timeout_seconds)
            if not base_run.installed:
                return _unsupported(
                    f"the project does not install before the bump: "
                    f"{install_failure_reason(base_run)}"
                )
            if not base_run.tests_ran:
                return _unsupported(
                    f"the baseline test run produced no verdict (exit {base_run.test_rc})"
                )
            baseline = _failures(base_run, shape)

            changed = apply_bump(str(work), inp.package, inp.target_version)
            if not changed:
                return _unsupported(
                    f"{inp.package} is not pinned in any file the sandbox can rewrite"
                )

            after_run = _run_in_container(work, shape, inp.image, inp.timeout_seconds)
            if not after_run.installed:
                # The bump is not installable at all. That is a harder failure than a red test,
                # and reporting it as "no newly failing tests" would be a lie.
                return _unsupported(
                    f"{inp.package}=={inp.target_version} cannot be installed alongside the "
                    f"repo's other pins: {install_failure_reason(after_run)}",
                    mode="docker",
                    store=store,
                    key=key,
                )
            if not after_run.tests_ran:
                return _unsupported(
                    f"the test run after the bump produced no verdict (exit {after_run.test_rc})",
                    mode="docker",
                    store=store,
                    key=key,
                )
            after = _failures(after_run, shape)
            newly = diff_failures(baseline, after)

            flaky: list[str] = []
            if newly:
                # Rerun once; anything that passes the second time was noise, not the bump.
                rerun_run = _run_in_container(work, shape, inp.image, inp.timeout_seconds)
                if rerun_run.tests_ran:
                    rerun = _failures(rerun_run, shape)
                    flaky = sorted(set(newly) - set(rerun))
                    newly = sorted(set(newly) & set(rerun))
                    if flaky:
                        notes.append(
                            f"{len(flaky)} test(s) passed on rerun and were treated as flaky"
                        )
                else:
                    notes.append("flake rerun produced no verdict; newly failing kept as-is")
        except subprocess.TimeoutExpired:
            return SandboxOutput(
                result=SandboxResult(
                    supported=False, reason=f"test run exceeded {inp.timeout_seconds}s"
                ),
                mode="docker",
            )
        except (OSError, subprocess.SubprocessError) as e:
            return SandboxOutput(
                result=SandboxResult(supported=False, reason=f"docker run failed: {e}"),
                mode="docker",
            )

    result = SandboxResult(
        supported=True,
        reason=shape.reason,
        baseline_failed=baseline,
        after_bump_failed=after,
        newly_failing=newly,
        flaky_rerun=flaky,
    )
    if store.settings.record:
        store.write("sandbox", key, _recordable(result))
    return SandboxOutput(result=result, mode="docker", notes=notes)


def _recordable(result: SandboxResult) -> dict[str, Any]:
    return result.model_dump(mode="json")


def _unsupported(
    reason: str,
    mode: str = "skipped",
    store: RecordedStore | None = None,
    key: str | None = None,
) -> SandboxOutput:
    """Unproven is not the same as clean: the policy reads this as a human's problem.

    An unsupported verdict that a container actually produced is recorded like any other result —
    "this bump cannot be installed" is a finding, and recorded mode has to be able to replay it.
    """
    result = SandboxResult(supported=False, reason=reason)
    if store is not None and key is not None and store.settings.record:
        store.write("sandbox", key, _recordable(result))
    return SandboxOutput(result=result, mode=mode)
