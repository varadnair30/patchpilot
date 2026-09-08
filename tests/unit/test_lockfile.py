from patchpilot.tools.lockfile import LockfileInput, parse_lockfiles


def _by_name(out):
    return {d.name: d for d in out.dependencies}


def test_requirements_include_keeps_runtime_scope(tmp_repo):
    repo = tmp_repo(
        {
            "requirements.txt": "requests==2.31.0\nPyJWT==2.10.0  # comment\n",
            "requirements-dev.txt": "-r requirements.txt\nblack==23.12.1\npytest>=8\n",
        }
    )
    out = parse_lockfiles(LockfileInput(repo_path=str(repo)))
    deps = _by_name(out)
    assert deps["requests"].is_dev is False
    assert deps["pyjwt"].is_dev is False, (
        "names are canonicalised and -r does not inherit dev scope"
    )
    assert deps["black"].is_dev is True
    assert "pytest>=8" in out.unpinned
    assert sorted(out.files_read) == ["requirements-dev.txt", "requirements.txt"]


def test_pyproject_groups(tmp_repo):
    repo = tmp_repo(
        {
            "pyproject.toml": (
                '[project]\nname="x"\ndependencies=["fastapi==0.100.0","httpx>=0.27"]\n'
                '[project.optional-dependencies]\ndev=["pytest==8.3.2"]\nextras=["pillow==10.2.0"]\n'
            )
        }
    )
    out = parse_lockfiles(LockfileInput(repo_path=str(repo)))
    deps = _by_name(out)
    assert deps["fastapi"].is_dev is False
    assert deps["pytest"].is_dev is True
    assert deps["pillow"].is_dev is False, "non-dev optional groups count as runtime"
    assert out.unpinned == ["httpx>=0.27"]


def test_uv_lock_wins_over_requirements(tmp_repo):
    repo = tmp_repo(
        {
            "uv.lock": '[[package]]\nname = "urllib3"\nversion = "2.2.1"\n',
            "requirements.txt": "urllib3==1.26.0\n",
        }
    )
    out = parse_lockfiles(LockfileInput(repo_path=str(repo)))
    assert [(d.name, d.version) for d in out.dependencies] == [("urllib3", "2.2.1")]


def test_demo_app_lockfile(demo_app):
    out = parse_lockfiles(LockfileInput(repo_path=str(demo_app)))
    deps = _by_name(out)
    assert len(out.dependencies) == 13
    assert deps["black"].is_dev and deps["pytest"].is_dev
    assert not deps["starlette"].is_dev
    assert out.unpinned == []
