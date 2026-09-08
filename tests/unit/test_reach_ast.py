from patchpilot.tools.reach_ast import ReachabilityInput, analyze_reachability


def _run(repo, package, symbols=(), declared_dev=False):
    return analyze_reachability(
        ReachabilityInput(
            repo_path=str(repo),
            package=package,
            vulnerable_symbols=list(symbols),
            declared_dev=declared_dev,
        )
    ).reachability


def test_not_imported(tmp_repo):
    repo = tmp_repo({"app.py": "import os\nprint(os.getcwd())\n"})
    r = _run(repo, "requests", ["requests.Session"])
    assert r.imported is False and r.symbol_called is False
    assert r.confidence == 0.90


def test_direct_call_resolves_module_alias(tmp_repo):
    repo = tmp_repo(
        {
            "app.py": "import jwt as j\n\ndef f(t):\n    return j.decode(t, 'k', algorithms=['HS256'])\n"  # noqa: E501
        }
    )
    r = _run(repo, "pyjwt", ["jwt.decode"])
    assert r.imported and r.symbol_called
    assert [(c.file, c.line) for c in r.call_sites] == [("app.py", 4)]
    assert r.confidence == 0.85


def test_from_import_alias(tmp_repo):
    repo = tmp_repo({"app.py": "from jwt import decode as d\n\nx = d('t', 'k')\n"})
    r = _run(repo, "pyjwt", ["jwt.decode"])
    assert r.symbol_called
    assert {c.line for c in r.call_sites} == {1, 3}


def test_imported_but_symbol_not_used(tmp_repo):
    repo = tmp_repo({"app.py": "from PIL import Image\nImage.open('x')\n"})
    r = _run(repo, "pillow", ["PIL.ImageCms"])
    assert r.imported and r.symbol_called is False and r.call_sites == []


def test_symbol_prefix_is_not_a_match(tmp_repo):
    """`requests.Session` must not match `requests.SessionRedirectMixin` or bare `requests`."""
    repo = tmp_repo(
        {"app.py": "import requests\nrequests.get('u')\nrequests.SessionRedirectMixin\n"}
    )
    r = _run(repo, "requests", ["requests.Session"])
    assert r.symbol_called is False


def test_no_symbols_known(tmp_repo):
    repo = tmp_repo({"app.py": "import urllib3\n"})
    r = _run(repo, "urllib3", [])
    assert r.imported and r.symbol_called is None and r.confidence == 0.50


def test_reexport_via_other_package(tmp_repo):
    repo = tmp_repo(
        {"app.py": "from fastapi import UploadFile\n\ndef up(f: UploadFile):\n    return f\n"}
    )
    r = _run(repo, "starlette", ["fastapi.UploadFile", "starlette.requests.Request.form"])
    assert r.imported is False and r.symbol_called is True
    assert r.is_runtime_dep is True
    assert any("re-export" in n for n in r.notes)


def test_test_only_import(tmp_repo):
    repo = tmp_repo(
        {"tests/test_x.py": "import requests\nrequests.Session()\n", "app.py": "x = 1\n"}
    )
    r = _run(repo, "requests", ["requests.Session"])
    assert r.imported and r.symbol_called
    assert r.imported_from_test_only is True and r.is_runtime_dep is False


def test_declared_dev(tmp_repo):
    repo = tmp_repo({"app.py": "x = 1\n"})
    r = _run(repo, "black", ["black.format_str"], declared_dev=True)
    assert r.is_runtime_dep is False


def test_bare_symbol_in_template_only(tmp_repo):
    repo = tmp_repo(
        {
            "app.py": "from jinja2 import Environment\n",
            "templates/a.html": "<div {{ attrs | xmlattr }}></div>\n",
            "README.md": "we do not use xmlattr here\n",
        }
    )
    r = _run(repo, "jinja2", ["xmlattr"])
    assert r.symbol_called is True
    assert [c.file for c in r.call_sites] == ["templates/a.html"], "markdown is not a template"


def test_skips_virtualenv_and_bad_syntax(tmp_repo):
    repo = tmp_repo(
        {
            ".venv/lib/site.py": "import jwt\njwt.decode()\n",
            "broken.py": "def (:\n",
            "app.py": "x = 1\n",
        }
    )
    r = _run(repo, "pyjwt", ["jwt.decode"])
    assert r.imported is False
    assert any("broken.py" in n for n in r.notes)
