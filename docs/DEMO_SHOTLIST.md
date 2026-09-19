# Demo shot list

Target 2:00. Real screen recording throughout — AI only for the title card, the voiceover and
editing. The point of the video is that the thing works, so nothing in it should be a mock-up.

Record at 1920×1080, terminal at a font size that is legible when the video is scaled into a
portfolio card. Run `patchpilot` with `PATCHPILOT_LLM=off` for a free, deterministic take, or with
the key set if you want the model-written justifications on screen — the decisions are identical
either way, which is worth saying in the voiceover.

## Before you record

```powershell
# a clean queue with all five gates open
python scripts/reset_demo.py --close-prs --clear-state
patchpilot scan fixtures\patchpilot-demo-app --thread demo `
  --repo-url https://github.com/varadnair30/patchpilot-demo-app
```

Have these open in tabs: the demo repo's pull requests, the LangSmith project, the queue page, and
a PR on `patchpilot` showing a red golden gate.

| time | screen | what happens |
|---|---|---|
| 0:00–0:10 | title card, then `docs/architecture.svg` | One sentence: dependency advisories are mostly noise, and the expensive part is deciding which ones matter. PatchPilot decides deterministically and asks a human when the policy says so. |
| 0:10–0:28 | terminal | `patchpilot scan fixtures/patchpilot-demo-app`. The table fills in: 11 advisories, the reachability column, then the summary — 3 not_applicable, 2 auto_fix, 5 needs_human, 1 accept_risk. Say that the LLM wrote none of this. |
| 0:28–0:40 | terminal, scrolled | Point at two rows. urllib3 is imported but the vulnerable symbol is never called, so it is dismissed. requests resolves to 2.32.2, not the 2.32.0 the advisory names, because PyPI yanked 2.32.0 and 2.32.1. |
| 0:40–0:52 | LangGraph Studio (or the mermaid graph) | Five branches paused at `human_gate`. Hover one to show the checkpointed state. Say that the process can exit here and the branch survives — this is a durable interrupt, not a blocked thread. |
| 0:52–1:15 | the web queue | Open the pyjwt case. One screen: reachability proof with file:line, the sandbox diff, the changelog citations, the justification with its evidence ids, and the advisory text in a marked block. Say that the decision was made before any of this prose was written. |
| 1:15–1:28 | the web queue → terminal | Type a name, add a note, Approve. Then show `patchpilot worker --once` picking it up. The API recorded a verdict; the worker is what moves the graph. |
| 1:28–1:40 | GitHub, demo repo | The pull request. Scroll the evidence bundle in the body, including the LangSmith trace link. Note the branch protection and that nothing auto-merges — PatchPilot has no merge tool at all. |
| 1:40–1:52 | GitHub Actions on `patchpilot` | A pull request that raises `auto_fix.max_bump` from patch to minor. CI fails: **2 decisions flipped**, both named, with expected and actual. Say that changing a ratified decision needs two approvals. |
| 1:52–2:00 | end card | Links: the repo, the live queue, a trace. |

## The 15-second portfolio GIF

Trim 0:52–1:15 (the evidence bundle and the approve) down to about 15 seconds. That clip is the
whole argument: a human deciding in one screen, with the evidence that decision rests on.

## Things worth saying out loud

- **The model never decides.** It writes the justification and summarises the changelog, both with
  citation checks. Every decision class comes from `policy/rules.py` and YAML thresholds.
- **The gate is durable.** `interrupt()` plus a Postgres checkpointer, so a reviewer can take days.
- **The sandbox actually runs the tests.** Twice, in Docker, before and after the bump — and an
  install that fails is reported as unproven rather than as a clean run.
- **Every ratified decision is a golden case.** 38 of them, and CI blocks on any flip.

## Things not to claim

- It has not run against a large real codebase; the demo target is ten deliberately pinned
  dependencies.
- The golden set is seeded, not accumulated from production use.
- The two-approval rule on golden changes is advisory on a solo repository — the check runs and
  fails visibly, but there is no second reviewer to satisfy it.
