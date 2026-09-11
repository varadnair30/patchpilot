"""Run the golden set and write `summary.json`, then decide whether the gate holds.

    python evals/run_evals.py                  # deterministic evaluators only
    python evals/run_evals.py --judge          # adds the gpt-4o faithfulness judge (costs money)
    python evals/run_evals.py --update-baseline

The deterministic evaluators need no key, no network and no Docker, so the blocking half of the
gate runs everywhere — including on a fork's pull request, where secrets are not available. That is
deliberate: `decision_match` is the check that must never be skipped, and a gate that quietly turns
green because a key was missing would be worse than no gate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

# Allow `python evals/run_evals.py` from a clone without installing the package first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from evals.cases import load_cases, prepare_workspace, run_case  # noqa: E402
from evals.evaluators import (  # noqa: E402
    FAITHFULNESS_THRESHOLD,
    CaseReport,
    cost_latency,
    grade,
    make_judge,
)

HERE = Path(__file__).resolve().parent
BASELINE = HERE / "baseline.json"
SUMMARY = HERE / "summary.json"
MAX_SCORE_DROP = 0.02


def summarise(reports: list[CaseReport], graded: bool) -> dict[str, Any]:
    scored = [r.faithfulness for r in reports if r.faithfulness is not None]
    passed = [r for r in reports if r.passed]
    return {
        "total": len(reports),
        "passed": len(passed),
        "score": round(len(passed) / len(reports), 4) if reports else 0.0,
        "decision_flips": [r.case_id for r in reports if r.decision_flipped],
        "errors": [r.case_id for r in reports if r.error],
        "faithfulness": {
            "graded": graded,
            "cases_scored": len(scored),
            "mean": round(sum(scored) / len(scored), 4) if scored else None,
            "below_threshold": [
                r.case_id
                for r in reports
                if r.faithfulness is not None and r.faithfulness < FAITHFULNESS_THRESHOLD
            ],
        },
        "cost_latency": cost_latency(reports),
        "cases": [r.model_dump() for r in reports],
    }


def gate(summary: dict[str, Any], baseline: dict[str, Any] | None) -> list[str]:
    """Every reason this run should block a merge. An empty list is a pass."""
    failures: list[str] = []

    for case_id in summary["decision_flips"]:
        failures.append(f"decision flipped: {case_id}")
    for case_id in summary["errors"]:
        failures.append(f"case errored: {case_id}")

    faith = summary["faithfulness"]
    if faith["graded"]:
        if faith["mean"] is not None and faith["mean"] < FAITHFULNESS_THRESHOLD:
            failures.append(f"evidence_faithfulness {faith['mean']} below {FAITHFULNESS_THRESHOLD}")
        for case_id in faith["below_threshold"]:
            failures.append(f"unfaithful justification: {case_id}")

    if baseline:
        drop = round(baseline.get("score", 0.0) - summary["score"], 4)
        if drop > MAX_SCORE_DROP:
            failures.append(
                f"score dropped {drop} from the baseline {baseline['score']} "
                f"(limit {MAX_SCORE_DROP})"
            )
        cap = baseline.get("cost_latency", {}).get("p95_tokens")
        actual = summary["cost_latency"]["p95_tokens"]
        # Only meaningful once a baseline was recorded with the model on.
        if cap and actual > cap * 1.5:
            failures.append(f"p95 tokens {actual} exceeds 150% of the baseline {cap}")
    return failures


def render(summary: dict[str, Any], failures: list[str]) -> str:
    """The PR comment. Written so a reviewer can act without opening the JSON."""
    faith = summary["faithfulness"]
    lines = [
        "## PatchPilot golden set",
        "",
        f"**{summary['passed']}/{summary['total']}** cases pass (score {summary['score']}).",
        "",
    ]
    if failures:
        lines += ["### The gate is blocking this merge", ""]
        lines += [f"- {reason}" for reason in failures]
        lines.append("")
    else:
        lines += ["The gate passes.", ""]

    if summary["decision_flips"]:
        lines += [
            "### Flipped decisions",
            "",
            "| case | expected | got |",
            "| --- | --- | --- |",
        ]
        by_id = {c["case_id"]: c for c in summary["cases"]}
        for case_id in summary["decision_flips"]:
            check = next(c for c in by_id[case_id]["checks"] if c["name"] == "decision_match")
            lines.append(f"| `{case_id}` | `{check['expected']}` | `{check['actual']}` |")
        lines += [
            "",
            "A flip means a decision a human ratified would now come out differently. If that is "
            "intended, edit the case in `evals/golden/` — which needs two approvals.",
            "",
        ]

    if faith["graded"]:
        lines.append(
            f"Evidence faithfulness: **{faith['mean']}** over {faith['cases_scored']} cases."
        )
    else:
        lines.append(
            "Evidence faithfulness: _not graded_ (no model key available). The deterministic "
            "checks above still ran and still block."
        )
    cost = summary["cost_latency"]
    lines.append(
        f"p95 {cost['p95_tokens']:.0f} tokens / {cost['p95_seconds']}s per case, "
        f"${cost['total_usd']} total."
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--judge", action="store_true", help="run the faithfulness judge (costs)")
    parser.add_argument("--update-baseline", action="store_true", help="pin this run as baseline")
    parser.add_argument("--comment", type=Path, default=None, help="write the PR comment here")
    parser.add_argument(
        "--limit", type=int, default=0, help="run only the first N cases (for a cheap judge check)"
    )
    args = parser.parse_args()

    os.environ.setdefault("PATCHPILOT_MODE", "recorded")
    if not args.judge:
        # Deterministic evaluators do not need a model, and a stray key must not make the run cost
        # money or vary between machines.
        os.environ["PATCHPILOT_LLM"] = "off"

    judge = make_judge() if args.judge else None
    if args.judge and judge is None:
        print("--judge was asked for but no model key is configured", file=sys.stderr)
        return 2

    reports: list[CaseReport] = []
    with tempfile.TemporaryDirectory(prefix="patchpilot-evals-") as tmp:
        workdir = Path(tmp)
        prepare_workspace(workdir)
        cases = load_cases()
        if args.limit:
            cases = cases[: args.limit]
        for case in cases:
            result = run_case(case, workdir)
            report, _ = grade(case, result, judge)
            reports.append(report)
            mark = "ok  " if report.passed else "FAIL"
            print(f"{mark} {case.id}")

    summary = summarise(reports, graded=judge is not None)
    baseline = json.loads(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else None
    failures = gate(summary, baseline)
    summary["gate"] = {"passed": not failures, "failures": failures}

    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    comment = render(summary, failures)
    if args.comment:
        args.comment.write_text(comment + "\n", encoding="utf-8")
    print()
    print(comment)

    if args.limit:
        print("\npartial run: baseline and gate comparisons are not meaningful", file=sys.stderr)
        return 0

    if args.update_baseline:
        BASELINE.write_text(
            json.dumps(
                {
                    "score": summary["score"],
                    "total": summary["total"],
                    "faithfulness": summary["faithfulness"]["mean"],
                    "cost_latency": summary["cost_latency"],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nbaseline updated: {BASELINE}")
        return 0

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
