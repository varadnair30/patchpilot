"""The sandbox: detect how to install and test a repo, apply a bump, diff the two test runs.

Docker itself is exercised by exactly one test, which skips when no engine is reachable. Everything
that decides an outcome — project detection, pin rewriting, the failure diff, flake reruns — is
pure and tested here, and recorded mode replays a stored result so the graph stays Docker-free.
"""

import pytest

from patchpilot.recorded.store import RecordedStore
from patchpilot.tools.sandbox import (
    RunResult,
    SandboxInput,
    _sentinel,
    apply_bump,
    detect_project,
    diff_failures,
    docker_available,
    install_failure_reason,
    parse_pytest_failures,
    parse_unittest_failures,
    run_sandbox,
    sandbox_key,
)

REQS = "fastapi==0.100.0\nrequests==2.31.0\n"
DEV_REQS = "-r requirements.txt\npytest==8.3.2\n"


# ------------------------------------------------------------------ project detection


def test_requirements_and_pytest_are_detected(tmp_repo):
    repo = tmp_repo(
        {
            "requirements.txt": REQS,
            "requirements-dev.txt": DEV_REQS,
            "tests/test_app.py": "def test_ok():\n    assert True\n",
        }
    )
    shape = detect_project(str(repo))
    assert shape.supported
    assert "requirements-dev.txt" in " ".join(shape.install_command)
    assert shape.test_runner == "pytest"


def test_a_bare_requirements_file_is_enough(tmp_repo):
    repo = tmp_repo({"requirements.txt": REQS, "tests/test_a.py": "def test_a():\n    assert 1\n"})
    shape = detect_project(str(repo))
    assert shape.supported and "requirements.txt" in " ".join(shape.install_command)


def test_pyproject_is_installed_editable_with_its_dev_extra(tmp_repo):
    repo = tmp_repo(
        {
            "pyproject.toml": '[project]\nname = "x"\nversion = "1"\n'
            '[project.optional-dependencies]\ndev = ["pytest"]\n',
            "tests/test_a.py": "def test_a():\n    assert 1\n",
        }
    )
    shape = detect_project(str(repo))
    assert shape.supported and "[dev]" in " ".join(shape.install_command)


def test_uv_lock_uses_uv_sync(tmp_repo):
    repo = tmp_repo(
        {
            "uv.lock": "version = 1\n",
            "pyproject.toml": '[project]\nname = "x"\nversion = "1"\n',
            "tests/test_a.py": "def test_a():\n    assert 1\n",
        }
    )
    shape = detect_project(str(repo))
    assert shape.supported and shape.install_command[0] == "uv"


def test_unittest_is_detected_when_pytest_is_absent(tmp_repo):
    repo = tmp_repo(
        {
            "requirements.txt": REQS,
            "tests/test_a.py": "import unittest\n\n"
            "class T(unittest.TestCase):\n    def test_a(self):\n        pass\n",
        }
    )
    shape = detect_project(str(repo))
    assert shape.test_runner == "unittest"


def test_a_repo_with_no_tests_is_unsupported(tmp_repo):
    repo = tmp_repo({"requirements.txt": REQS, "app.py": "x = 1\n"})
    shape = detect_project(str(repo))
    assert not shape.supported
    assert "test" in shape.reason.lower()


def test_a_repo_with_no_install_method_is_unsupported(tmp_repo):
    repo = tmp_repo({"tests/test_a.py": "def test_a():\n    assert 1\n"})
    shape = detect_project(str(repo))
    assert not shape.supported
    assert "install" in shape.reason.lower()


# ------------------------------------------------------------------ applying the bump


def test_the_pin_is_rewritten_in_every_requirements_file(tmp_repo):
    repo = tmp_repo({"requirements.txt": REQS, "requirements-dev.txt": DEV_REQS})
    changed = apply_bump(str(repo), "requests", "2.32.4")
    assert changed == ["requirements.txt"]
    assert "requests==2.32.4" in (repo / "requirements.txt").read_text()
    assert "fastapi==0.100.0" in (repo / "requirements.txt").read_text(), "other pins untouched"


def test_the_pin_is_matched_by_canonical_name(tmp_repo):
    repo = tmp_repo({"requirements.txt": "python_multipart==0.0.6\n"})
    assert apply_bump(str(repo), "python-multipart", "0.0.18") == ["requirements.txt"]
    assert "python_multipart==0.0.18" in (repo / "requirements.txt").read_text()


def test_comments_and_layout_survive_the_rewrite(tmp_repo):
    repo = tmp_repo({"requirements.txt": "# pinned on purpose\nrequests==2.31.0  # http\n"})
    apply_bump(str(repo), "requests", "2.32.4")
    text = (repo / "requirements.txt").read_text()
    assert text.startswith("# pinned on purpose\n")
    assert "# http" in text


def test_a_pin_in_pyproject_is_rewritten(tmp_repo):
    repo = tmp_repo(
        {"pyproject.toml": '[project]\nname = "x"\ndependencies = ["requests==2.31.0"]\n'}
    )
    assert apply_bump(str(repo), "requests", "2.32.4") == ["pyproject.toml"]
    assert "requests==2.32.4" in (repo / "pyproject.toml").read_text()


def test_a_package_that_is_not_pinned_anywhere_changes_nothing(tmp_repo):
    repo = tmp_repo({"requirements.txt": REQS})
    assert apply_bump(str(repo), "pillow", "10.3.0") == []
    assert (repo / "requirements.txt").read_text() == REQS


# ------------------------------------------------------------------ the failure diff


def test_newly_failing_is_after_minus_before():
    diff = diff_failures(before=["t::a", "t::b"], after=["t::b", "t::c"])
    assert diff == ["t::c"]


def test_a_test_that_was_already_red_is_not_newly_failing():
    assert diff_failures(before=["t::a"], after=["t::a"]) == []


def test_a_test_that_the_bump_fixed_is_not_reported():
    assert diff_failures(before=["t::a", "t::b"], after=["t::a"]) == []


def test_newly_failing_is_sorted_and_deduplicated():
    assert diff_failures(before=[], after=["t::b", "t::a", "t::b"]) == ["t::a", "t::b"]


# ------------------------------------------------------------------ output parsing


def test_pytest_failures_are_parsed_from_the_short_summary():
    output = (
        "..F.\n"
        "=========================== short test summary info ============================\n"
        "FAILED tests/test_app.py::test_upload_ok - TypeError: unexpected keyword\n"
        "ERROR tests/test_boom.py::test_x - ImportError\n"
        "1 failed, 3 passed in 0.42s\n"
    )
    assert parse_pytest_failures(output) == [
        "tests/test_app.py::test_upload_ok",
        "tests/test_boom.py::test_x",
    ]


def test_a_green_pytest_run_parses_to_no_failures():
    assert parse_pytest_failures("....\n4 passed in 0.10s\n") == []


def test_a_collection_error_is_reported_as_a_failure():
    output = "ERROR tests/test_app.py - ImportError: cannot import name 'x'\n"
    assert parse_pytest_failures(output) == ["tests/test_app.py"]


def test_unittest_failures_are_parsed():
    output = (
        "FAIL: test_upload (tests.test_app.UploadTests)\n"
        "ERROR: test_health (tests.test_app.HealthTests)\n"
        "Ran 3 tests in 0.1s\n"
    )
    assert parse_unittest_failures(output) == [
        "tests.test_app.HealthTests.test_health",
        "tests.test_app.UploadTests.test_upload",
    ]


# ------------------------------------------------------------------ phase exit codes

# A failed install prints no "FAILED" lines, so failure parsing alone reads it as a green run.
# These lock in the distinction between "the suite passed" and "the suite never ran".


def test_exit_codes_are_read_back_from_the_sentinels():
    output = "installing...\n__PP_INSTALL_RC=0\n..\n2 passed\n__PP_TEST_RC=0\n"
    assert _sentinel(output, "__PP_INSTALL_RC") == 0
    assert _sentinel(output, "__PP_TEST_RC") == 0


def test_a_missing_sentinel_reads_as_unknown_not_success():
    assert _sentinel("nothing here", "__PP_INSTALL_RC") == -1
    assert RunResult(output="nothing here").installed is False


@pytest.mark.parametrize(
    ("code", "counts"),
    [(0, True), (1, True), (2, False), (3, False), (4, False), (5, False), (127, False)],
)
def test_only_pass_and_fail_count_as_a_test_verdict(code, counts):
    """pytest 0 = passed, 1 = failed. 5 = nothing collected, 127 = pytest is not installed."""
    assert RunResult(test_rc=code).tests_ran is counts


def test_a_failed_install_is_never_a_clean_run():
    run = RunResult(
        output="ERROR: ResolutionImpossible\n__PP_INSTALL_RC=1\n__PP_TEST_RC=127\n",
        install_rc=1,
        test_rc=127,
    )
    assert not run.installed and not run.tests_ran
    assert parse_pytest_failures(run.output) == [], "and it looks green to failure parsing alone"


def test_the_pip_conflict_line_is_what_the_reviewer_is_shown():
    run = RunResult(
        output=(
            "Collecting starlette==0.40.0\n"
            "ERROR: Cannot install -r /work/requirements.txt (line 2) and starlette==0.40.0 "
            "because these package versions have conflicting dependencies.\n"
            "ERROR: ResolutionImpossible: for help visit https://pip.pypa.io/\n"
        ),
        install_rc=1,
    )
    assert "conflicting dependencies" in install_failure_reason(run)


# ------------------------------------------------------------------ recorded mode


@pytest.fixture
def sandbox_fixtures(monkeypatch, tmp_path):
    monkeypatch.setenv("PATCHPILOT_FIXTURES_DIR", str(tmp_path))
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    yield RecordedStore()
    get_settings.cache_clear()


def test_a_recorded_result_is_replayed_without_docker(sandbox_fixtures, tmp_repo):
    repo = tmp_repo({"requirements.txt": REQS, "tests/test_a.py": "def test_a():\n    assert 1\n"})
    key = sandbox_key(str(repo), "requests", "2.31.0", "2.32.4")
    sandbox_fixtures.write(
        "sandbox",
        key,
        {
            "supported": True,
            "reason": "recorded",
            "baseline_failed": [],
            "after_bump_failed": ["tests/test_a.py::test_a"],
            "newly_failing": ["tests/test_a.py::test_a"],
            "flaky_rerun": [],
        },
    )
    out = run_sandbox(
        SandboxInput(
            repo_path=str(repo),
            package="requests",
            installed_version="2.31.0",
            target_version="2.32.4",
        )
    )
    assert out.mode == "recorded"
    assert out.result.newly_failing == ["tests/test_a.py::test_a"]
    assert out.result.supported is True


def test_a_missing_recording_is_unsupported_not_an_exception(sandbox_fixtures, tmp_repo):
    """Rule 2: recorded mode never reaches out. An un-recorded bump is simply unproven."""
    repo = tmp_repo({"requirements.txt": REQS, "tests/test_a.py": "def test_a():\n    assert 1\n"})
    out = run_sandbox(
        SandboxInput(
            repo_path=str(repo),
            package="requests",
            installed_version="2.31.0",
            target_version="9.9.9",
        )
    )
    assert out.result.supported is False
    assert "no recorded sandbox run" in out.result.reason
    assert out.result.newly_failing == []


def test_the_recorded_key_is_stable_and_browsable(tmp_repo):
    repo = tmp_repo({"requirements.txt": REQS})
    key = sandbox_key(str(repo), "requests", "2.31.0", "2.32.4")
    assert key == f"{repo.name}/requests==2.31.0..2.32.4"
    assert sandbox_key(str(repo), "requests", "2.31.0", "2.32.4") == key


def test_an_unsupported_repo_short_circuits_before_any_run(sandbox_fixtures, tmp_repo):
    repo = tmp_repo({"app.py": "x = 1\n"})
    out = run_sandbox(
        SandboxInput(
            repo_path=str(repo), package="requests", installed_version="1", target_version="2"
        )
    )
    assert out.result.supported is False
    assert out.mode == "skipped"


# ------------------------------------------------------------------ docker (skipped without one)


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="no Docker engine reachable")
def test_docker_really_runs_the_test_suite_twice(tmp_repo, monkeypatch):
    """The only test that starts a container. Proves baseline -> bump -> diff end to end."""
    monkeypatch.setenv("PATCHPILOT_MODE", "live")
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    repo = tmp_repo(
        {
            "requirements.txt": "packaging==24.0\n",
            "requirements-dev.txt": "-r requirements.txt\npytest==8.3.2\n",
            "tests/test_version.py": (
                "import packaging\n\n\n"
                "def test_pinned_version():\n"
                "    assert packaging.__version__ == '24.0'\n"
            ),
        }
    )
    out = run_sandbox(
        SandboxInput(
            repo_path=str(repo),
            package="packaging",
            installed_version="24.0",
            target_version="24.1",
            timeout_seconds=600,
        )
    )
    assert out.mode == "docker", out.result.reason
    assert out.result.supported is True, out.result.reason
    assert out.result.baseline_failed == []
    assert out.result.newly_failing == ["tests/test_version.py::test_pinned_version"]
    assert (repo / "requirements.txt").read_text() == "packaging==24.0\n", "repo left untouched"


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="no Docker engine reachable")
def test_a_bump_pip_refuses_to_install_is_not_reported_as_clean(tmp_repo, monkeypatch):
    """The demo app's starlette case, and the regression that motivated the exit-code sentinels.

    fastapi 0.100.0 requires starlette<0.28.0, so bumping starlette to 0.40.0 makes the install
    impossible. pytest then never runs, the output contains no failures, and a naive reading calls
    it green — which would hand `auto_fix` to a bump that cannot be installed at all.
    """
    monkeypatch.setenv("PATCHPILOT_MODE", "live")
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    repo = tmp_repo(
        {
            "requirements.txt": "fastapi==0.100.0\nstarlette==0.27.0\n",
            "requirements-dev.txt": "-r requirements.txt\npytest==8.3.2\n",
            "tests/test_import.py": (
                "import starlette\n\n\ndef test_imports():\n    assert starlette\n"
            ),
        }
    )
    out = run_sandbox(
        SandboxInput(
            repo_path=str(repo),
            package="starlette",
            installed_version="0.27.0",
            target_version="0.40.0",
            timeout_seconds=1200,
        )
    )
    assert out.result.supported is False, "an uninstallable bump is unproven, not clean"
    assert out.result.newly_failing == []
    assert "cannot be installed" in out.result.reason
    assert "starlette" in out.result.reason


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="no Docker engine reachable")
def test_the_container_cannot_write_into_the_mounted_repository(tmp_repo):
    """The regression that broke CI on Linux.

    With a read-write bind mount the container's root user left root-owned __pycache__ and
    .pytest_cache behind, which the non-root caller could then not delete — a PermissionError
    during temp-directory cleanup. Docker Desktop masks ownership on Windows and macOS, so it only
    ever showed up on a Linux runner. The mount is read-only now, which is checkable anywhere.
    """
    import subprocess

    repo = tmp_repo({"requirements.txt": "packaging==24.0\n"})
    done = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{repo}:/src:ro",
            "python:3.12-slim",
            "sh",
            "-lc",
            "touch /src/should-not-appear && echo WROTE || echo REFUSED",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    assert "REFUSED" in (done.stdout or "") + (done.stderr or "")
    assert not (repo / "should-not-appear").exists()
    assert sorted(p.name for p in repo.iterdir()) == ["requirements.txt"]
