"""The per-run spend meter, and the two things it does when it runs low.

At 80% of either cap, `policy/rules.py` raises the `budget_near_limit` gate trigger, so remaining
advisories go to a human instead of quietly spending the rest of the run's money on justifications.
At 100%, the branch halts: `decision="halted"`, `halt_reason` set, no further model calls.

The distinction matters. Warning routes work to a human; the hard stop refuses to do work at all.
An agent that can exceed its own budget has no budget.
"""

from __future__ import annotations

from typing import Literal

from patchpilot.graph.state import Budget

BudgetState = Literal["ok", "warn", "exceeded"]

WARN_FRACTION = 0.80
BUDGET_EXHAUSTED_FRACTION = 1.0


class BudgetExceeded(RuntimeError):
    """The run hit its token or dollar cap. No further model calls are permitted."""

    def __init__(self, budget: Budget) -> None:
        self.budget = budget
        super().__init__(
            f"budget cap reached: {budget.tokens_used}/{budget.tokens_cap} tokens, "
            f"${budget.usd_used:.4f}/${budget.usd_cap:.2f}"
        )


def state_of(budget: Budget | None, warn_fraction: float = WARN_FRACTION) -> BudgetState:
    if budget is None:
        return "ok"
    fraction = budget.fraction_used
    if fraction >= 1.0:
        return "exceeded"
    if fraction >= warn_fraction:
        return "warn"
    return "ok"


def is_exhausted(budget: Budget | None) -> bool:
    return state_of(budget) == "exceeded"


def assert_within_cap(budget: Budget | None) -> None:
    """Called before a model call. Raises rather than letting the run overspend."""
    if budget is not None and budget.fraction_used >= 1.0:
        raise BudgetExceeded(budget)


def describe(budget: Budget | None) -> str:
    if budget is None:
        return "budget: not started"
    return (
        f"budget: {budget.tokens_used}/{budget.tokens_cap} tokens, "
        f"${budget.usd_used:.4f}/${budget.usd_cap:.2f} ({budget.fraction_used:.0%})"
    )
