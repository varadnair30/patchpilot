# ADR-0002: The decision is deterministic; the LLM writes the justification only

**Status:** accepted · **Date:** 2026-09-08

## Context

A regression suite over agent decisions is only meaningful if the decision is a function of inputs the suite controls. Free-form agents make the decision inside the model, so every prompt or model change is a potential silent flip, and "decision-match" becomes a coin toss.

## Decision

`risk_policy` computes the decision class (`auto_fix` / `needs_human` / `accept_risk` / `not_applicable`) and the gate triggers from CVSS, EPSS, reachability, dependency scope, and package tier using rules in `policy/rules.py` with thresholds in `policy/thresholds.yaml`. The LLM is invoked afterwards for two bounded tasks: writing a justification that cites evidence ids, and summarising breaking changes from retrieved changelog chunks. Its output is validated against a Pydantic schema and can never raise or lower the decision.

## Consequences

- Decision-match in the golden suite is exact and deterministic; the LLM-dependent evaluators (faithfulness) measure explanation quality, not decision correctness.
- Policy changes are code changes and go through the same CI gate.
- The system is less "agentic" than a free-running ReAct loop, on purpose. The human gate, durable interrupts, and evidence bundles are where the value is.
