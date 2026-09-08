"""reachability: first node of the per-advisory subgraph. Static analysis only."""

from __future__ import annotations

from patchpilot.graph.state import AdvisoryBranch
from patchpilot.guardrails.contracts import ContractViolation
from patchpilot.tools.reach_ast import ReachabilityInput, analyze_reachability


def reachability(branch: AdvisoryBranch) -> dict:
    adv = branch["advisory"].model_copy(deep=True)
    try:
        out = analyze_reachability(
            ReachabilityInput(
                repo_path=branch["repo"].path,
                package=adv.package,
                vulnerable_symbols=adv.vulnerable_symbols,
                declared_dev=adv.is_dev,
            )
        )
        adv.reachability = out.reachability
    except ContractViolation as e:
        adv.decision = "halted"
        adv.halt_reason = f"reachability: {e}"
    return {"advisory": adv}
