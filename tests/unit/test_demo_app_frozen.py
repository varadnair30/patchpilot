"""The demo app and the fixtures recorded against it must not drift apart.

A sandbox fixture says "installing this tree and running its tests produced exactly this". Recorded
mode never starts a container, so if someone edits the demo app the recordings keep replaying and
the golden set keeps passing — while measuring an application that no longer exists. This test is
what makes that impossible to do by accident.
"""

import json

import pytest

from patchpilot.recorded.freeze import (
    MANIFEST_PATH,
    VENDORED_DEMO_APP,
    DemoAppManifest,
    freeze,
    iter_files,
    load_manifest,
    tree_digest,
    write_manifest,
)


def test_the_vendored_demo_app_still_matches_the_recorded_fixtures():
    manifest = load_manifest()
    assert manifest is not None, (
        "demo_app.json is missing; run scripts/publish_demo_app.py --freeze"
    )

    digest, count = tree_digest(VENDORED_DEMO_APP)
    assert digest == manifest.tree_digest, (
        "fixtures/patchpilot-demo-app has changed since the fixtures were recorded.\n"
        "The recorded OSV/PyPI/changelog/sandbox data now describes a different tree, so every "
        "sandbox result is a claim about an application that no longer exists.\n"
        "Re-record the fixtures against the new tree, re-tag the demo repo, then re-freeze with "
        "`python scripts/publish_demo_app.py --freeze`."
    )
    assert count == manifest.file_count


def test_the_manifest_names_the_published_repository_and_tag():
    manifest = load_manifest()
    assert manifest is not None
    assert manifest.tag, "the fixtures must name the tag they describe"
    assert manifest.repo_url, "the fixtures must name where the demo app is published"


def test_every_sandbox_fixture_belongs_to_the_frozen_app():
    """A sandbox key is `<repo dir>/<pkg>==<from>..<to>`; they must all be the demo app's."""
    from patchpilot.config import get_settings

    sandbox_dir = get_settings().fixtures_dir / "sandbox"
    fixtures = sorted(sandbox_dir.glob("*.json"))
    assert fixtures, "the sandbox fixtures went missing"
    assert all(f.name.startswith("patchpilot-demo-app_") for f in fixtures)


def test_the_pinned_versions_still_match_the_demo_apps_requirements():
    """Each sandbox fixture records a bump from an installed version. That version has to be the
    one the demo app actually pins, or the recording describes a bump nobody is proposing."""
    from patchpilot.config import get_settings

    pins = {}
    for line in (VENDORED_DEMO_APP / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if "==" in line:
            name, _, version = line.partition("==")
            pins[name.strip().lower().replace("_", "-")] = version.strip()

    sandbox_dir = get_settings().fixtures_dir / "sandbox"
    checked = 0
    for fixture in sandbox_dir.glob("*.json"):
        stem = fixture.stem.removeprefix("patchpilot-demo-app_")
        package, _, versions = stem.partition("==")
        installed, _, _target = versions.partition("..")
        pinned = pins.get(package.lower().replace("_", "-"))
        if pinned is None:
            continue  # a dev-only pin, checked by the requirements-dev file instead
        assert pinned == installed, (
            f"sandbox fixture {fixture.name} records a bump from {package}=={installed}, "
            f"but the demo app pins {package}=={pinned}"
        )
        checked += 1
    assert checked >= 5, "expected the runtime pins to be covered by sandbox recordings"


# ==================================================================== the digest itself


def test_the_digest_ignores_line_endings(tmp_path):
    """Git checks the demo app out with CRLF on Windows and LF on Linux; the digest must agree."""
    unix = tmp_path / "unix"
    windows = tmp_path / "windows"
    for root, newline in ((unix, b"\n"), (windows, b"\r\n")):
        (root / "app").mkdir(parents=True)
        (root / "app" / "main.py").write_bytes(b"import widget" + newline + b"x = 1" + newline)
    assert tree_digest(unix)[0] == tree_digest(windows)[0]


def test_the_digest_notices_a_content_change(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "main.py").write_text("import widget\n", encoding="utf-8")
    before, _ = tree_digest(root)
    (root / "main.py").write_text("import widget\nimport other\n", encoding="utf-8")
    assert tree_digest(root)[0] != before


def test_the_digest_notices_a_new_or_renamed_file(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "main.py").write_text("x = 1\n", encoding="utf-8")
    before, _ = tree_digest(root)
    (root / "extra.py").write_text("x = 1\n", encoding="utf-8")
    after, count = tree_digest(root)
    assert after != before and count == 2

    (root / "extra.py").rename(root / "renamed.py")
    assert tree_digest(root)[0] != after, "a rename with identical content must still register"


def test_the_digest_ignores_build_droppings(tmp_path):
    root = tmp_path / "app"
    (root / "__pycache__").mkdir(parents=True)
    (root / "main.py").write_text("x = 1\n", encoding="utf-8")
    before, _ = tree_digest(root)
    (root / "__pycache__" / "main.cpython-312.pyc").write_bytes(b"\x00\x01")
    (root / ".pytest_cache").mkdir()
    (root / ".pytest_cache" / "CACHEDIR.TAG").write_text("x", encoding="utf-8")
    assert tree_digest(root)[0] == before


def test_iter_files_is_deterministic(tmp_path):
    root = tmp_path / "app"
    (root / "b").mkdir(parents=True)
    (root / "a.py").write_text("1", encoding="utf-8")
    (root / "b" / "c.py").write_text("2", encoding="utf-8")
    assert iter_files(root) == iter_files(root)


# ==================================================================== freezing


def test_freezing_records_the_current_tree(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "main.py").write_text("x = 1\n", encoding="utf-8")
    manifest = freeze(root, repo_url="https://github.com/o/r", tag="v1.0.0", commit="a" * 40)
    assert manifest.tree_digest == tree_digest(root)[0]
    assert (manifest.repo_url, manifest.tag, manifest.commit) == (
        "https://github.com/o/r",
        "v1.0.0",
        "a" * 40,
    )


def test_a_manifest_round_trips(tmp_path):
    path = tmp_path / "demo_app.json"
    manifest = DemoAppManifest(tree_digest="abc", file_count=3, tag="v1.0.0")
    write_manifest(manifest, path)
    assert load_manifest(path) == manifest
    assert json.loads(path.read_text(encoding="utf-8"))["tag"] == "v1.0.0"


def test_a_missing_manifest_is_none_not_an_error(tmp_path):
    assert load_manifest(tmp_path / "nope.json") is None


def test_the_shipped_manifest_is_valid_json_and_parses():
    DemoAppManifest.model_validate_json(MANIFEST_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("field", ["tree_digest"])
def test_the_manifest_requires_a_digest(field):
    with pytest.raises(ValueError):
        DemoAppManifest.model_validate({})
