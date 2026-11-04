# Phase 2 — CLI, module execution and lifecycle correctness

**Date:** 2026-11-04
**Repository / branch:** `/lump/apps/.worktrees/consensus-phase2-lifecycle`, `consensus-phase2-lifecycle`
**Base:** `862826852114342808629b0bfa73b681eb806fd4` (Phase 0 documentation commit)
**Pinned source revision:** parent `12206f7608ea1c1d30810b1728c215f938554562`, Consensus 0.4.12
**Result:** **Phase 2 gate NOT PASSED.** CLI parsing and result semantics are sufficiently stable for bounded offline harness work, but the full gate requires demonstrated bounded work and reliable cancellation; a check-count budget is not a request/time/byte budget, SIGTERM is not handled, and output order is completion-dependent. No Phase 1 changes are assumed. No suite files were read or modified in this phase.

## Scope and graph evidence

Read the full `prompt-packs/consensus-osint-phased-prompt-pack.md` and Phase 0 `phase-0-report.md`, `capability-matrix.md`, `network-surface-inventory.md`, and `risk-register.md`. The Phase 0 report was not edited. Worktree was clean at start, on the requested branch and base.

Codebase Memory project `consensus-phase2-lifecycle`, generation `2026-11-04T21:51:41Z`, ready, 4,543 nodes / 14,744 edges. `status --project consensus-phase2-lifecycle --json` reports no partial or skipped parses, 34 ignored files, two unusable Jinja templates, and vendor excluded from parsing. Tier 2 task-directed discovery:

- `search "argument normalization leading global options argparse"`: 11 matches, complete page; found `cli._leading_positional` and `cli.normalise_argv`.
- `search "main argv"`: 11 matches, complete page; found `cli.main` and `normalise_argv`.
- `search "run_all"`: 2 matches, complete page; found `core.runner.run_all`.
- `search "Scanner run"`: 114 matches, first 50 returned, `has_more=true`; broad term was not used as an exhaustive inventory. Qualified trace and exact snippet were used for `cli.Scanner.run`.
- Traces: `cli.main` both directions (155 callees, 1 caller; source snippets used to ground the relevant dispatch paths); `cli.normalise_argv` both directions (6 callees, 2 callers); `cli.Scanner.run` both directions (66 callees, 4 callers); `core.runner.run_all` both directions (13 callees, 2 callers). Relevant caller/callee sets were within the returned trace page; unrelated broad graph results were not treated as proof of absence.
- Exact snippets read: `cli.main`, `cli.normalise_argv`, `cli._leading_positional`, `cli.Scanner.run`, `core.runner.run_all`.
- Coverage checked for relied-on paths: `consensus_osint/cli.py`, `core/runner.py`, `core/scan_budget.py`, `core/reports.py`, `core/models.py`, `core/modules.py`, `core/username_checker.py`, `core/sitesdb.py`, `core/http.py`, `core/scan_control.py`. All report `no_recorded_issue` at the matching generation; this is best-effort metadata, not proof. Source was inspected directly for all cited behavior and gaps. Vendor was excluded and not treated as verified by graph absence.

## Findings

### CLI and issue #13

Upstream issue #13, titled “A leading global option turns any subcommand line into a scan,” was retrieved read-only with:

```sh
curl -fsS https://api.github.com/repos/OSINT-Experts-Society/Consensus-OSINT/issues/13
```

It documents 0.4.11 behavior where `--no-color user ...`, `--no-color email ...`, `--no-color report ...`, or `--no-color version` could prepend `scan` and treat a subcommand word as a username. The pinned 0.4.12 source now walks leading scan options according to argparse option arity (`cli.py:416-472`); if the first positional token is a command/help word, it prints a reorder instruction and raises exit 2 before parsing or dispatch. The exact no-network check below monkeypatched `cmd_scan` to raise if called and confirmed it was not called. The parser rejects this ordering rather than supporting every global flag before a subcommand.

### Headless output and exit semantics

- `consensus scan|user|email|phone` is the subprocess entry point. JSONL mode routes scan printer messages to stderr; scan records go to stdout. Quiet/no-footer/no-animation/no-update-check flags reduce interactive and update behavior. JSONL completion order follows asynchronous check completion, so record order is nondeterministic (`cli.py:1190-1194`, `core/runner.py:38-178`).
- Finding statuses preserve `found`, `not_found`, `unknown`, `blocked`, `rate_limited`, `error`, and `skipped` (`core/models.py:19-37`). Do not turn unknown/blocked/error/skipped or budget-deferred checks into negatives.
- Exit 0 indicates scan completion even when provider outcomes include errors; exit 1 is report-save failure; exit 2 is invalid CLI/input; exit 130 is KeyboardInterrupt. These are command-level outcomes, separate from per-check result statuses (`cli.py:1328-1415,1774-1864`).
- The 30,000 default counts admitted site/module invocations, not HTTP attempts, retries, response bytes, or duration. `ScanBudget.admit` increments once before a site/module call; multiple requests/retries can occur inside it (`core/scan_budget.py:1-52`, `core/runner.py:103-178`, `core/http.py:76-131,240-312`). `--max-checks 0` is unlimited. Default request concurrency is 100, per-host 4; safe methods may be retried once.
- SIGINT is translated to exit 130 and a partial summary path; a stopped scan cancels in-flight async tasks and waits for cleanup. SIGTERM is not registered and therefore does not promise partial output. No process-group termination contract exists for optional browser/child-process paths (`cli.py:1328-1350,1849-1855`; `core/runner.py:103-178`).
- Report save uses a temporary file followed by `os.replace` (`core/reports.py:1432-1456`), giving atomic replacement on the same filesystem in the inspected path. This was source inspection; crash behavior was not tested.
- No stable run ID, durable scheduler, exactly-once replay, or idempotent resumption mechanism was found in the CLI path. Existing saved reports can be re-rendered; repeating a scan issues a new check sequence.
- Loud checks, recursion, search engines, mailcat, browser, FlareSolverr, AI, and browser opening are opt-in flags, but no strict automation mode centrally rejects them. A caller can omit them; that is not an enforceable profile or network-safety guarantee. `--no-update-check` only suppresses the startup check.
- Configuration precedence and credential redaction were inspected at CLI route selection and `redact_options` (`cli.py:477-514`; `core/models.py:370-402`). No secrets were used. This does not verify every vendor error string or optional client.

## Offline fixtures and reproducible checks

Added `tests/fixtures/phase2/fake_provider.json` and `tests/phase2_offline_harness.py`. The harness binds only `127.0.0.1`, exercises production `Http` and `check_site`, checks five fixed outcomes, and asserts request sequence/count. It does not perform external lookups.

Phase-end execution evidence:

| Command | Result |
|---|---|
| `PYTHONPATH=. python3 tests/phase2_offline_harness.py` (initial attempt) | exit 1: fixture URL used `{}` rather than `{username}`; no request reached the fake route, checks were skipped. |
| Same command (second attempt) | exit 1: checker returned `unknown` for generic 200/500 responses; initial expected statuses were too strong. Corrected fixture detection and expected 500 semantics. |
| `PYTHONPATH=. python3 tests/phase2_offline_harness.py` (final) | exit 0; `{"findings": {"fixture-blocked": "blocked", "fixture-error": "unknown", "fixture-found": "found", "fixture-not-found": "not_found", "fixture-rate-limited": "rate_limited"}, "requests": 5}`. |
| `git diff --check` | exit 0. |

The issue #13 command was exactly:

```sh
PYTHONPATH=. python3 -c 'import consensus_osint.cli as c; c.cmd_scan=lambda *a, **k: (_ for _ in ()).throw(AssertionError("scan dispatched"));
try: c.main(["--no-color", "version"])
except SystemExit as e: print(f"observed_exit={e.code}")' 2>&1
```

It exited 0 and printed the reorder instruction plus `observed_exit=2`.

No existing test suite or CI workflow was present in the bounded checkout; no broader suite ran. The initial harness failures are retained here as fixture-development failures, not hidden. No exact-provider subprocess, SIGINT/SIGTERM, atomic-save crash, retry-count, bytes, or packet-capture test was run.

## Changes and commits

Implementation-only commits:

- `475fa0ea70a62eec9d0488c39f2bf34604b04ee4` — deterministic fake-provider fixture and loopback harness.
- `ae4565cf3d82648a4a91f16fc120218624c5cf33` — corrected harness URL interpolation and outcome semantics based on checkpoint failures.

No CLI implementation fix was made: issue #13 is already guarded in the pinned source, and broader lifecycle fixes need bounded design and dedicated controlled tests. Documentation is committed separately from implementation. No changes were made to the suite, Phase 0 report, remotes, or other branch. No external OSINT query, credentials, publication, or merge occurred. The Phase 1 branch was not merged or assumed present.

## Deferred Phase 4 work / limitations

1. Add an enforceable automation profile only after Phase 1 establishes an approved egress contract; ensure recursion, loud checks, AI, challenge solvers, browser, and updates cannot be enabled accidentally.
2. Define request/attempt, byte, and wall-time budgets; `--max-checks` alone does not bound those quantities.
3. Specify and verify SIGINT/SIGTERM behavior, async cleanup, and process-group termination for optional subprocesses.
4. Specify JSONL schema/order and command exit semantics for partial runs, provider errors, and serialization/save failures; add stable downstream ordering or guarantee it explicitly.
5. Exercise output atomicity, idempotent replay/resume expectations, actual retries, duplicate selection, and cancellation in offline controlled tests.

Jev was not called: after the issue text and source were inspected, the relevant decision was deterministic (guarded ordering; lifecycle limits explicitly remain unverified), with no semantic alternative requiring judgment. No authentication or credentials were sought.

## Gate and handoff

**Gate: NOT PASSED for collector automation/adoption.** The CLI guard and deterministic offline checker harness pass their bounded checks. Stable record ordering, total-work bounding, SIGTERM/cancellation guarantees, strict automation enforcement, and Phase 1 route safety remain unproven. Retain the existing suite collectors. Phase 4 owns the lifecycle fixes after controlled constraints and safety gates are available.
