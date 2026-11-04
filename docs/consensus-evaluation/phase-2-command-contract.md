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
- Exit `2`: invalid command/options, scan input/output validation error, or filters selecting no checks.
- Exit `130`: interrupted scan. SIGINT follows the existing partial-summary path; during a scan, SIGTERM now temporarily uses the same handler and restores the prior handler on exit. The offline subprocess check confirms the streamed JSONL record survives. Process-group cleanup for optional child processes remains unverified.
- Resume/replay: no durable run identity or exactly-once replay contract exists. Saved reports can be rendered again with `consensus report INPUT -o OUTPUT`; a new scan is a new request sequence.

Sanitized result example:

```json
{"query":"fixture-user","query_type":"username","site":"Fake provider","site_id":"fake-provider","status":"found","source":"sites-db","method":"status_code","http_status":200}
```

## Deterministic offline harness

`tests/phase2_offline_harness.py` serves fixed responses from `tests/fixtures/phase2/fake_provider.json` on `127.0.0.1` only and calls the production `check_site`/`Http` path. It covers found, not-found, blocked, rate-limited, and HTTP 500 (`unknown`, because a server error does not establish absence), plus one retry, response-size rejection, JSONL stdout, and SIGTERM during an in-flight subprocess scan. It counts actual requests received and successful response-body bytes written by the local fixture, excluding headers and socket/protocol bytes. It does not exercise vendored modules, process groups, real DNS/proxy routing, SIGINT in a subprocess, or provider accuracy.

Phase-end command: `PYTHONPATH=. python3 tests/phase2_offline_harness.py`. The expanded harness also runs a CLI subprocess against loopback fixtures, validates its JSONL stdout, sends SIGTERM during a pending local request, measures request arrivals/retries and response-body bytes, and verifies response-size rejection. It does not count HTTP headers or socket/protocol bytes and is not a total egress budget.

Verified output: `{"findings": {"fixture-blocked": "blocked", "fixture-error": "unknown", "fixture-found": "found", "fixture-not-found": "not_found", "fixture-rate-limited": "rate_limited"}, "jsonl_records": 1, "requests": 10, "response_body_bytes": 359, "response_limit": "response exceeds 32 bytes", "retry_attempts": 2, "signal_exit": 130}`.

## Issue #13

Upstream issue #13 reports a leading global option turning the following subcommand into a username. The pinned source's `normalise_argv` scans leading options using argparse arity and rejects a leading option followed by a command with exit `2` before dispatch (`consensus_osint/cli.py:416-472`). It does not support moving arbitrary global options ahead of subcommands, but prevents the accidental full scan. A side-effect-free invocation check confirmed scan dispatch is not reached.
