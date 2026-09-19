"""The deployment files are code too, and two of their properties are load-bearing.

The queue page renders advisory text copied from the internet (rule 4), so it must never hand that
text to the DOM as markup. And the API image must not carry the credentials or the machinery that
would let it do more than read the queue and record a verdict.

None of this can be caught by running the app locally, which is exactly why it is pinned here.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
QUEUE_PAGE = ROOT / "docs" / "queue" / "index.html"
WORKFLOWS = ROOT / ".github" / "workflows"


# ==================================================================== the queue page


def test_the_queue_page_exists_where_github_pages_serves_it():
    assert QUEUE_PAGE.is_file()


def strip_comments(source: str) -> str:
    """Code only. The page's own comments discuss the patterns this file forbids, and a check
    that cannot tell an explanation from a use would be worse than no check."""
    source = re.sub(r"<!--.*?-->", "", source, flags=re.DOTALL)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"^\s*//.*$", "", source, flags=re.MULTILINE)


def test_untrusted_text_is_never_rendered_as_markup():
    """The page shows advisory and changelog text fetched from the internet. React escapes it as
    a child; dangerouslySetInnerHTML would not."""
    code = strip_comments(QUEUE_PAGE.read_text(encoding="utf-8"))
    assert "dangerouslySetInnerHTML" not in code
    assert "innerHTML" not in code
    assert "document.write" not in code
    assert "eval(" not in code


def test_the_check_above_can_tell_a_use_from_an_explanation():
    """Otherwise the guard passes for the wrong reason and stops meaning anything."""
    assert "dangerouslySetInnerHTML" not in strip_comments("<!-- never dangerouslySetInnerHTML -->")
    assert "dangerouslySetInnerHTML" not in strip_comments("  // avoid dangerouslySetInnerHTML")
    assert "dangerouslySetInnerHTML" in strip_comments("<div dangerouslySetInnerHTML={x} />")


def test_the_page_needs_no_build_step():
    """CLAUDE.md rule 6: no new components. A Node toolchain for a table and two buttons would be
    more machinery than the thing it builds."""
    source = QUEUE_PAGE.read_text(encoding="utf-8")
    assert "react.production.min.js" in source
    assert not (ROOT / "package.json").exists()
    assert not (ROOT / "package-lock.json").exists()


def test_the_page_holds_no_credential():
    source = QUEUE_PAGE.read_text(encoding="utf-8").lower()
    for forbidden in ("api_key", "apikey", "authorization:", "bearer ", "secret", "token:"):
        assert forbidden not in source, forbidden


def test_the_page_only_reaches_the_three_endpoints_it_should():
    source = QUEUE_PAGE.read_text(encoding="utf-8")
    assert "/api/queue" in source
    assert "/verdict" in source
    # Nothing that would start work.
    assert "/api/scan" not in source
    assert "enqueue" not in source


# ==================================================================== workflows


@pytest.mark.parametrize(
    "name", ["ci.yml", "golden-update.yml", "dispatch-resume.yml", "nightly-reset.yml"]
)
def test_every_workflow_is_valid_yaml(name):
    parsed = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    assert parsed["jobs"], name
    # `on:` is parsed by PyYAML as the boolean True — a YAML 1.1 quirk, not a mistake in the file.
    assert parsed.get("on") or parsed.get(True), name


def test_the_worker_workflow_runs_the_documented_command():
    """ADR-0001: Actions is a deployment of the worker, not a different worker."""
    source = (WORKFLOWS / "dispatch-resume.yml").read_text(encoding="utf-8")
    assert "patchpilot worker --once" in source
    assert "repository_dispatch" in source
    assert "schedule" in source, "a verdict must land even if the dispatch never arrives"


def test_the_worker_workflow_will_not_run_from_a_fork():
    for name in ("dispatch-resume.yml", "nightly-reset.yml"):
        source = (WORKFLOWS / name).read_text(encoding="utf-8")
        assert "github.repository ==" in source, name


def test_the_reset_only_ever_closes_patchpilot_branches():
    source = (WORKFLOWS / "nightly-reset.yml").read_text(encoding="utf-8")
    assert "scripts/reset_demo.py --close-prs" in source
    # The filtering lives in the script, where it is unit tested, not in shell in the workflow.
    assert "git push --delete" not in source
    assert "gh pr close" not in source


def test_no_workflow_hardcodes_a_secret():
    for path in WORKFLOWS.glob("*.yml"):
        source = path.read_text(encoding="utf-8")
        for marker in ("ghp_", "github_pat_", "sk-proj-", "lsv2_pt_"):
            assert marker not in source, f"{path.name} contains something shaped like a secret"


# ==================================================================== the API image


def test_the_api_image_installs_only_what_the_api_needs():
    """It must not be able to build a model, drive Docker, or write to a repository."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert '".[api,postgres]"' in dockerfile
    assert "llm" not in dockerfile.split("RUN pip install")[1].split("\n")[0]
    assert "uvicorn patchpilot.api.app:app" in dockerfile


def test_the_api_image_does_not_run_as_root():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER patchpilot" in dockerfile


def test_the_render_blueprint_deploys_only_the_api():
    blueprint = yaml.safe_load((ROOT / "render.yaml").read_text(encoding="utf-8"))
    services = blueprint["services"]
    assert len(services) == 1, "the worker is not deployed here; it needs Docker and a write token"
    service = services[0]
    assert service["healthCheckPath"] == "/health"

    env = {v["key"]: v for v in service["envVars"]}
    assert "OPENAI_API_KEY" not in env, (
        "the API asserts it never builds a model; giving it a key would make that a lie"
    )
    # Real secrets are not values in the blueprint.
    assert env["DATABASE_URL"].get("sync") is False
    assert env["PATCHPILOT_DISPATCH_TOKEN"].get("sync") is False
