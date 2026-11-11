# Risk register (updated Phase 1)

**2026-11-05 classification:** R1: **not yet verified** for the full strict path (ambient HTTPX behavior is a confirmed standalone contract violation); R2: **confirmed violation** for unproxied DNS, with email and independent clients disabled by strict CLI policy; R3: **disabled by policy** in strict CLI; R6: **disabled by policy** for strict CLI, otherwise not yet verified. Detailed classifications and controlled evidence are in [Phase 1 report](phase-1-report.md) and [network inventory](network-surface-inventory.md). Older dispositions below preserve the historical investigation context, not a current acceptance claim.

Ratings express current concern and uncertainty, not an observed incident. Harness observations are loopback-only; no public egress was attempted or observed.

| ID | Risk | Rating | Evidence / basis | Phase 0 disposition |
|---|---|---:|---|---|
| R1 | Direct or ambient egress can violate suite route policy | **High / gate blocked** | Standalone shared HTTPX retains ambient environment behavior; `OSINT_REQUIRE_PROXY=1` disables it, rejects missing route, and makes the shared client honor the explicit proxy. Offline tests cover conflicting ambient proxy, unavailable route and SOCKS5h remote DNS. | Bounded shared-client behavior only. No proxyctl health/run-id contract; independent clients remain outside guard. No suite route approved. |
| R2 | DNS and optional clients bypass shared route | **High / gate blocked** | dnspython resolver (`core/emailinfo.py:103-131,148-173`); standalone AI HTTPX (`core/ai.py:83-108`); browser and FlareSolverr (`core/browser.py:77-90`, `core/flaresolverr.py:30,49-56`); many vendored transports. | nftables deny counters and fake-DNS packet capture are verified; actual resolver and independent clients remain untested. Keep them disabled pending Phase 4 coverage. |
| R3 | Automatic update and child process behavior adds unreviewed network/lifecycle path | **High** | Startup update and subprocess paths (`cli.py:1826-1833`, `core/auto_update.py:49-75,97-156`); installer/updater use urllib and subprocess. | Not exercised. Disable and bound in strict automation; verify isolated behavior later. |
| R4 | Capability overlap may be mistaken for verified replacement | **High** | Catalogues, tool counts and task similarity do not establish provider accuracy or identity. Suite has separate input and route selection (`osint-suite/apps/suite/src/suite_planner.py:126-170,353-400`). | No retirement. Phase 3 needs authorized fixtures, canonical keys, outcome statuses and measured errors. |
| R5 | Result semantics may collapse if mapped carelessly | **Medium** | Consensus preserves seven statuses and provenance fields (`consensus_osint/core/models.py:19-28,91-115`); suite has distinct machine outcome handling. | Preserve unknown, blocked, rate-limited, error and skipped; map only after schema comparison. |
| R6 | Vendored provider behavior and code graph gaps hide egress or maintenance issues | **High / gate blocked** | Vendor excluded from index; source search finds provider-specific HTTPX, aiohttp and curl_cffi paths; 34 ignored files and two unusable templates. | No enabled subset certified. Exhaustive provider/transport mapping remains Phase 4 work. |
| R7 | License, attribution or catalogue rights may constrain redistribution | **High** | GPL-3.0-or-later package license and retained notices; unresolved template attribution/source provenance (`THIRD_PARTY_NOTICES.txt:1-17,108-114,167-169,171-182,233-238`). | Preserve notices; obtain explicit legal review before redistribution; no legal conclusion. |
| R8 | Maintenance burden from large merged catalogue and optional dependency surface | **Medium** | Package has core plus modules, PDF, browser and MCP extras (`pyproject.toml:35-65`); data and vendored modules have independent provenance. | Quantified maintenance cost and update drift not measured. |
| R9 | “Check budget” mistaken for request/byte/rate bound | **Medium** | CLI says 30,000 checks, not HTTP requests (`consensus_osint/cli.py:218-219`); budget counts site/module invocations, internal requests/retries continue (`core/scan_budget.py:1-5`). | Enforce request/byte/time budgets separately before adoption. |
| R10 | Test claims or external CI coverage overstated | **Medium** | No test/CI file matched the bounded checkout inventory; no tests were run. | Treat as “not found in inspected names,” not proof of no external CI. Phase-end checks required by prompt pack. |

## Phase 2 updates (2026-11-04)

| ID | Risk | Rating | Phase 2 evidence / disposition |
|---|---|---:|---|
| R9 | Check budget mistaken for request/byte/time bound | **High** | `ScanBudget` admits one site/module invocation per check; retries and additional HTTP requests occur inside the invocation (`consensus_osint/core/scan_budget.py:1-24`, `core/http.py:76-131,240-312`). Use finite `--max-checks` only as a work-count ceiling; Phase 4 must establish request, byte, and wall-time controls before automation. |
| R10 | Test claims or external CI coverage overstated | **Medium** | No pre-existing test suite or CI workflow was found in the bounded checkout. The new local harness passes its focused phase-end checks; this is not broader suite or CI coverage. |
| R11 | Process termination may lose partial work | **Medium** | CLI temporarily routes SIGTERM through its KeyboardInterrupt partial-summary path and restores the prior handler (`consensus_osint/cli.py:1278-1312`); local subprocess fixture confirmed exit 130 and one preserved JSONL record. Process-group cancellation for optional child processes and non-POSIX behavior remain unverified (`core/runner.py:103-178`). |
| R12 | Machine-output order and process exit do not encode all finding outcomes | **Medium** | Concurrent callbacks emit in completion order (`core/runner.py:38-178`); scan-level provider errors remain finding statuses while command exit is normally 0 (`cli.py:1399-1415`). Consumers must parse each record and sort for comparison; Phase 4 should define and verify the wire contract. |
| R13 | Strict automation policy is advisory, not enforced by a mode | **High** | Recursion, loud checks, AI, browser, solver, and search features are exposed as CLI flags; omission is a caller convention. This branch adds no suite mode or route policy. Phase 1 remains a separate blocking gate and may have concurrent work not present in this branch. |

Phase 2 continuation confirms a SIGTERM fix and loopback request/retry/body-byte measurements; see `phase-2-report.md`. The retry fixture made two local GET attempts and the harness counted 359 response-body bytes across 10 received requests. These counts exclude headers and transport bytes and do not establish a global byte/request ceiling. R1-R3 and R6 from Phase 0 remain open; Phase 2 does not establish egress safety.

## Required gate dependencies

- **Phase 1:** R1–R3 and R6 block any enabled suite module until controlled fail-closed routing is demonstrated.
- **Phase 2:** define subprocess CLI, cancellation, work and output contract; include R9.
- **Phase 3:** establish whether any individual collector merits replacement; include R4–R5 and confidence limits.
- **Before redistribution:** resolve R7 with appropriate legal review; preserve all notices.
- **Before retirement:** require accepted comparison, rollback readiness and separate approval.
