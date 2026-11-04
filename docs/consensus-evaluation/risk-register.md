# Risk register (Phase 0)

Ratings express Phase 0 concern and uncertainty, not an observed incident. Static findings below are hypotheses to test; no live egress was observed.

| ID | Risk | Rating | Evidence / basis | Phase 0 disposition |
|---|---|---:|---|---|
| R1 | Direct or ambient egress can violate suite route policy | **High** | Main HTTP client is created without mandatory proxy and does not set `trust_env=False` (`consensus_osint/core/http.py:107-122`); suite requires explicit proxyctl route, no ambient discovery and fail-closed mode (`osint-suite/docs/OSINT_SUITE_RUNTIME_CONTRACT.md:7-23`). | Static concern only; Phase 1 controlled egress gate required. |
| R2 | DNS and optional clients bypass shared route | **High** | dnspython resolver (`core/emailinfo.py:103-131`); standalone AI HTTPX (`core/ai.py:83-108`); browser/solver and vendor clients (`core/browser.py:77-90`, `core/flaresolverr.py:49-56`, vendor excluded from graph). | Static concern; enumerate all routes and prove packet behavior. |
| R3 | Automatic update and child process behavior adds unreviewed network/lifecycle path | **High** | Startup update and background subprocess (`cli.py:1826-1833`, `core/auto_update.py:49-75,97-156`). | Disable in strict automation and verify route/process shutdown in later phases. |
| R4 | Capability overlap may be mistaken for verified replacement | **High** | Catalogues, tool counts and task similarity do not establish provider accuracy or identity. Suite has separate input and route selection (`osint-suite/apps/suite/src/suite_planner.py:126-170,353-400`). | No retirement. Phase 3 needs authorized fixtures, canonical keys, outcome statuses and measured errors. |
| R5 | Result semantics may collapse if mapped carelessly | **Medium** | Consensus preserves seven statuses and provenance fields (`consensus_osint/core/models.py:19-28,91-115`); suite has distinct machine outcome handling. | Preserve unknown, blocked, rate-limited, error and skipped; map only after schema comparison. |
| R6 | Vendored provider behavior and code graph gaps hide egress or maintenance issues | **High** | Vendor excluded from index; direct scan found provider-specific HTTP clients; 34 ignored files and two unusable templates reported. | Representative source inventory only; Phase 1 must inspect selected module set and dependencies directly. |
| R7 | License, attribution or catalogue rights may constrain redistribution | **High** | GPL-3.0-or-later package license and retained notices; unresolved template attribution/source provenance (`THIRD_PARTY_NOTICES.txt:1-17,108-114,167-169,171-182,233-238`). | Preserve notices; obtain explicit legal review before redistribution; no legal conclusion. |
| R8 | Maintenance burden from large merged catalogue and optional dependency surface | **Medium** | Package has core plus modules, PDF, browser and MCP extras (`pyproject.toml:35-65`); data and vendored modules have independent provenance. | Quantified maintenance cost and update drift not measured. |
| R9 | “Check budget” mistaken for request/byte/rate bound | **Medium** | CLI says 30,000 checks, not HTTP requests (`consensus_osint/cli.py:218-219`); budget counts site/module invocations, internal requests/retries continue (`core/scan_budget.py:1-5`). | Enforce request/byte/time budgets separately before adoption. |
| R10 | Test claims or external CI coverage overstated | **Medium** | No test/CI file matched the bounded checkout inventory; no tests were run. | Treat as “not found in inspected names,” not proof of no external CI. Phase-end checks required by prompt pack. |

## Required gate dependencies

- **Phase 1:** R1–R3 and R6 block any enabled suite module until controlled fail-closed routing is demonstrated.
- **Phase 2:** define subprocess CLI, cancellation, work and output contract; include R9.
- **Phase 3:** establish whether any individual collector merits replacement; include R4–R5 and confidence limits.
- **Before redistribution:** resolve R7 with appropriate legal review; preserve all notices.
- **Before retirement:** require accepted comparison, rollback readiness and separate approval.
