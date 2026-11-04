# Phase 2 headless command contract

Status: proposed automation contract for the pinned Consensus revision `862826852114342808629b0bfa73b681eb806fd4` (0.4.12). It is offline-safe only when provider traffic is replaced by the loopback harness; the general CLI is not certified network-safe.

## Invocation

Use an explicit subcommand first, one authorized identifier per invocation, `--no-update-check`, `--no-footer`, `--no-animation`, `--quiet`, and `--jsonl`. Set `--max-checks N` to a finite value. The current default is 30,000 site/module check invocations, not an HTTP-request, retry, byte, or wall-time cap; each admitted check can make multiple requests. Defaults are concurrency 100 and per-host 4; HTTP retries safe methods once. Keep `--recursive`, `--search-engines`, `--mailcat`, `--allow-loud`, `--browser`, `--flaresolverr`, `--ai`, and `--browse` absent. `--no-update-check` suppresses startup update checks; it does not disable every network-capable feature. The process must run in an externally enforced offline environment for fixture acceptance.

Example command shape (the placeholder is not a real target):

```sh
consensus user AUTHORIZED_FIXTURE --no-update-check --no-footer --no-animation --quiet --jsonl --no-sites --max-checks 1
```

This shape documents flags only; live collector execution is not authorized by Phase 2.

## Output and exit status observed in source

- JSONL is the machine-output mode; terminal/progress output is redirected to stderr by the scan printer. Use `--quiet` and keep stdout exclusively for JSONL records.
- Concurrent checks complete in nondeterministic order, so JSONL record order is not stable even when the selected set is stable. Sort downstream by query/type/site ID/status for deterministic comparison.
- Findings retain `found`, `not_found`, `unknown`, `blocked`, `rate_limited`, `error`, and `skipped`; do not reinterpret missing output or `not_found` after an interrupted/budget-limited run as coverage.
- Exit `0`: command completed, including scans with provider-level error findings.
- Exit `1`: requested report could not be saved.
- Exit `2`: invalid command/options or scan input/output validation error.
- Exit `130`: interrupted scan; partial findings may be retained when `--output` is used. SIGINT is handled as cancellation. SIGTERM uses the platform's default termination; graceful partial output is not established.
- Resume/replay: no durable run identity or exactly-once replay contract exists. Saved reports can be rendered again with `consensus report INPUT -o OUTPUT`; a new scan is a new request sequence.

Sanitized result example:

```json
{"query":"fixture-user","query_type":"username","site":"Fake provider","site_id":"fake-provider","status":"found","source":"sites-db","method":"status_code","http_status":200}
```

## Deterministic offline harness

`tests/phase2_offline_harness.py` serves fixed responses from `tests/fixtures/phase2/fake_provider.json` on `127.0.0.1` only and calls the production `check_site`/`Http` path. It covers found, not-found, blocked, rate-limited, and HTTP 500 (`unknown`, because a server error does not establish absence) and asserts request order/count. It does not exercise transport-error findings, vendored modules, subprocess process groups, real DNS/proxy routing, SIGTERM, or provider accuracy.

Phase-end command: `PYTHONPATH=. python3 tests/phase2_offline_harness.py`. Do not run until the Phase 2 checkpoint. Expected output is `{"findings": {"fixture-blocked": "blocked", "fixture-error": "unknown", "fixture-found": "found", "fixture-not-found": "not_found", "fixture-rate-limited": "rate_limited"}, "requests": 5}`.

## Issue #13

Upstream issue #13 reports a leading global option turning the following subcommand into a username. The pinned source's `normalise_argv` scans leading options using argparse arity and rejects a leading option followed by a command with exit `2` before dispatch (`consensus_osint/cli.py:416-472`). It does not support moving arbitrary global options ahead of subcommands, but prevents the accidental full scan. A side-effect-free invocation check is reserved for the Phase 2 checkpoint.
