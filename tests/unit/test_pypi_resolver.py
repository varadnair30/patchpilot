"""The minimal safe version, and what the rest of the repo says about it.

Every test writes its own recorded fixtures into a tmp fixtures dir, so these are pure unit tests
of the resolution rules rather than assertions about the demo app's pinned tree.
"""

import pytest

from patchpilot.graph.state import Dependency
from patchpilot.guardrails.contracts import ContractViolation
from patchpilot.recorded.store import MissingFixture, RecordedStore
from patchpilot.tools.pypi_resolver import ResolverInput, resolve_target_version


@pytest.fixture
def pypi(monkeypatch, tmp_path):
    """Write PyPI fixtures the way `patchpilot record` would have."""
    monkeypatch.setenv("PATCHPILOT_FIXTURES_DIR", str(tmp_path))
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    store = RecordedStore()

    def project(package: str, versions, yanked=()):
        store.write(
            "pypi/project",
            package,
            {"name": package, "versions": {v: {"yanked": v in yanked} for v in versions}},
        )

    def requires(package: str, version: str, reqs: list[str]):
        store.write("pypi/requires", f"{package}=={version}", {"requires_dist": reqs})

    project.requires = requires
    yield project
    get_settings.cache_clear()


def dep(name, version, is_dev=False):
    return Dependency(name=name, version=version, is_dev=is_dev, source_file="requirements.txt")


# ------------------------------------------------------------------ minimal safe version


def test_picks_the_smallest_release_at_or_above_the_fixed_version(pypi):
    pypi("requests", ["2.31.0", "2.32.0", "2.32.1", "2.32.4", "3.0.0"])
    out = resolve_target_version(
        ResolverInput(package="requests", installed_version="2.31.0", min_fixed_version="2.32.0")
    )
    assert out.target_version == "2.32.0"
    assert out.bump_kind == "minor"
    assert out.candidates == ["2.32.0", "2.32.1", "2.32.4", "3.0.0"]


def test_a_patch_bump_is_classified_as_patch(pypi):
    pypi("urllib3", ["2.2.1", "2.2.2", "2.3.0"])
    out = resolve_target_version(
        ResolverInput(package="urllib3", installed_version="2.2.1", min_fixed_version="2.2.2")
    )
    assert (out.target_version, out.bump_kind) == ("2.2.2", "patch")


def test_a_yanked_release_is_never_the_target(pypi):
    pypi("pkg", ["1.0.0", "1.0.1", "1.0.2"], yanked=["1.0.1"])
    out = resolve_target_version(
        ResolverInput(package="pkg", installed_version="1.0.0", min_fixed_version="1.0.1")
    )
    assert out.target_version == "1.0.2"
    assert "1.0.1" not in out.candidates


def test_prereleases_are_never_the_target(pypi):
    pypi("pkg", ["1.0.0", "2.0.0rc1", "2.0.0b2", "2.0.0"])
    out = resolve_target_version(
        ResolverInput(package="pkg", installed_version="1.0.0", min_fixed_version="2.0.0rc1")
    )
    assert out.target_version == "2.0.0"
    assert out.candidates == ["2.0.0"]


def test_no_fixed_version_means_no_target(pypi):
    pypi("pkg", ["1.0.0"])
    out = resolve_target_version(
        ResolverInput(package="pkg", installed_version="1.0.0", min_fixed_version=None)
    )
    assert out.target_version is None and out.bump_kind is None
    assert "no fixed version" in out.reason


def test_a_fixed_version_pypi_has_never_published_is_reported(pypi):
    pypi("pkg", ["1.0.0", "1.0.1"])
    out = resolve_target_version(
        ResolverInput(package="pkg", installed_version="1.0.0", min_fixed_version="9.9.9")
    )
    assert out.target_version is None
    assert "no published release" in out.reason


def test_an_unknown_package_raises_a_missing_fixture_in_recorded_mode(pypi):
    with pytest.raises(MissingFixture):
        resolve_target_version(
            ResolverInput(package="ghost", installed_version="1.0", min_fixed_version="1.1")
        )


# ------------------------------------------------------------------ repo constraints


def test_a_constraint_from_another_pin_is_reported_and_respected(pypi):
    """fastapi 0.100.0 pins starlette; the resolver must not pretend the bump is free."""
    pypi("starlette", ["0.27.0", "0.28.0", "0.40.0"])
    pypi.requires("fastapi", "0.100.0", ["starlette<0.28.0,>=0.27.0", "pydantic>=1.7.4"])
    out = resolve_target_version(
        ResolverInput(
            package="starlette",
            installed_version="0.27.0",
            min_fixed_version="0.40.0",
            dependencies=[dep("fastapi", "0.100.0"), dep("starlette", "0.27.0")],
        )
    )
    assert out.target_version == "0.40.0"
    assert [(c.requirer, c.specifier) for c in out.constraints] == [("fastapi", "<0.28.0,>=0.27.0")]
    assert out.conflicts == ["fastapi 0.100.0 requires starlette<0.28.0,>=0.27.0"]


def test_a_satisfied_constraint_produces_no_conflict(pypi):
    pypi("starlette", ["0.27.0", "0.27.1"])
    pypi.requires("fastapi", "0.100.0", ["starlette<0.28.0,>=0.27.0"])
    out = resolve_target_version(
        ResolverInput(
            package="starlette",
            installed_version="0.27.0",
            min_fixed_version="0.27.1",
            dependencies=[dep("fastapi", "0.100.0")],
        )
    )
    assert out.target_version == "0.27.1"
    assert out.constraints and out.conflicts == []


def test_the_smallest_safe_version_that_clears_every_constraint_wins(pypi):
    """Prefer a target the repo can actually install over the numerically smallest one."""
    pypi("pkg", ["1.0.0", "1.1.0", "1.2.0"])
    pypi.requires("other", "1.0.0", ["pkg!=1.1.0"])
    out = resolve_target_version(
        ResolverInput(
            package="pkg",
            installed_version="1.0.0",
            min_fixed_version="1.1.0",
            dependencies=[dep("other", "1.0.0")],
        )
    )
    assert out.target_version == "1.2.0"
    assert out.conflicts == []


def test_extras_only_requirements_are_not_treated_as_constraints(pypi):
    """`; extra == "all"` is only in force when that extra is installed, and it is not."""
    pypi("pkg", ["1.0.0", "2.0.0"])
    pypi.requires("other", "1.0.0", ['pkg<1.5 ; extra == "all"'])
    out = resolve_target_version(
        ResolverInput(
            package="pkg",
            installed_version="1.0.0",
            min_fixed_version="2.0.0",
            dependencies=[dep("other", "1.0.0")],
        )
    )
    assert out.target_version == "2.0.0"
    assert out.constraints == [] and out.conflicts == []


def test_the_package_does_not_constrain_itself(pypi):
    pypi("pkg", ["1.0.0", "2.0.0"])
    pypi.requires("pkg", "1.0.0", ["pkg<1.5"])
    out = resolve_target_version(
        ResolverInput(
            package="pkg",
            installed_version="1.0.0",
            min_fixed_version="2.0.0",
            dependencies=[dep("pkg", "1.0.0")],
        )
    )
    assert out.constraints == [] and out.conflicts == []


def test_a_dependency_with_no_recorded_metadata_is_skipped_not_fatal(pypi):
    """A missing requires_dist fixture must not sink the whole plan."""
    pypi("pkg", ["1.0.0", "2.0.0"])
    out = resolve_target_version(
        ResolverInput(
            package="pkg",
            installed_version="1.0.0",
            min_fixed_version="2.0.0",
            dependencies=[dep("mystery", "3.2.1")],
        )
    )
    assert out.target_version == "2.0.0"
    assert out.constraints == []
    assert any("mystery" in n for n in out.notes)


def test_an_unparseable_requirement_line_is_skipped(pypi):
    pypi("pkg", ["1.0.0", "2.0.0"])
    pypi.requires("other", "1.0.0", ["!!! not a requirement", "pkg>=1.0"])
    out = resolve_target_version(
        ResolverInput(
            package="pkg",
            installed_version="1.0.0",
            min_fixed_version="2.0.0",
            dependencies=[dep("other", "1.0.0")],
        )
    )
    assert out.target_version == "2.0.0"
    assert [c.requirer for c in out.constraints] == ["other"]


# ------------------------------------------------------------------ contract


def test_the_tool_validates_its_input(pypi):
    with pytest.raises(ContractViolation):
        resolve_target_version({"package": "pkg"})  # installed_version missing


# ------------------------------------------------------------------ environment markers


def test_a_marker_that_is_false_in_the_sandbox_is_not_a_constraint(pypi):
    """`; python_version < "3.10"` does not apply on a 3.12 sandbox, so it is not a conflict.

    Treating it as one invents a dependency conflict and sends a clean bump to a human.
    """
    pypi("pkg", ["1.0.0", "2.0.0"])
    pypi.requires("other", "1.0.0", ['pkg<2 ; python_version < "3.10"'])
    out = resolve_target_version(
        ResolverInput(
            package="pkg",
            installed_version="1.0.0",
            min_fixed_version="2.0.0",
            dependencies=[dep("other", "1.0.0")],
        )
    )
    assert out.target_version == "2.0.0"
    assert out.constraints == [] and out.conflicts == []


def test_a_marker_that_is_true_in_the_sandbox_still_constrains(pypi):
    pypi("pkg", ["1.0.0", "2.0.0"])
    pypi.requires("other", "1.0.0", ['pkg<2 ; python_version >= "3.10"'])
    out = resolve_target_version(
        ResolverInput(
            package="pkg",
            installed_version="1.0.0",
            min_fixed_version="2.0.0",
            dependencies=[dep("other", "1.0.0")],
        )
    )
    assert [c.specifier for c in out.constraints] == ["<2"]
    assert out.conflicts == ["other 1.0.0 requires pkg<2"]


def test_a_platform_marker_for_another_os_is_ignored(pypi):
    """The sandbox is Linux; a win32-only requirement is not our constraint."""
    pypi("pkg", ["1.0.0", "2.0.0"])
    pypi.requires("other", "1.0.0", ['pkg<2 ; sys_platform == "win32"'])
    out = resolve_target_version(
        ResolverInput(
            package="pkg",
            installed_version="1.0.0",
            min_fixed_version="2.0.0",
            dependencies=[dep("other", "1.0.0")],
        )
    )
    assert out.conflicts == []


def test_the_marker_environment_matches_the_image_the_sandbox_runs(pypi):
    """If the sandbox image moves to a new Python, marker evaluation has to move with it."""
    from patchpilot.tools.pypi_resolver import SANDBOX_PYTHON_VERSION
    from patchpilot.tools.sandbox import DEFAULT_IMAGE

    assert DEFAULT_IMAGE.startswith(f"python:{SANDBOX_PYTHON_VERSION}"), (
        f"{DEFAULT_IMAGE} and SANDBOX_PYTHON_VERSION={SANDBOX_PYTHON_VERSION} have drifted apart"
    )
