# Phase 1 — network egress and fail-closed routing

**Assessment date:** 2026-11-04  
**Base:** `862826852114342808629b0bfa73b681eb806fd4`  
**Branch:** `consensus-phase1-network`  
**Gate: BLOCKED.** No enabled route has packet-level fail-closed evidence. No public identity/provider, credential, or suite was accessed.

## Environment and evidence

- Initial `git status --short --branch`: clean; `HEAD` matched the requested base and branch.
- `codebase-memory-cli status --json --project consensus-phase1-network`: ready at `2026-11-04T21:51:41Z`, 4,543 nodes / 14,747 edges, no partial/skipped files, generation matches. It reports 34 ignored assets and two unusable Jinja templates. Coverage for `consensus_osint/core/http.py` was best-effort with no recorded issue. Structural search returned 88 matches, first page 50 with another page available; no negative/exhaustive claim is based on that graph. Vendor is not fully represented, so source search and direct reads were used for its transport families.
- `unshare -n true`: exit 1, `Operation not permitted`. `nft`, `iptables`, and `tcpdump` were unavailable. A loopback bind in the host namespace succeeded, which provides no isolation.
- Therefore no controlled network test was run. No packets, connections, DNS queries, or attempted direct egress were observed. This is an instrumentation/capability block, not evidence of no egress.

## Path matrix

| Path | Explicit proxy / Tor | Route absent | Redirect / fallback | Finding |
|---|---|---|---|---|
| Shared HTTPX (`core/http.py:76-162,185-312`) | Shared client and HTTP/1.1 fallback receive configured proxy. Tor default is `socks5://127.0.0.1:9050`. | Creates ordinary HTTPX clients without proxy and without `trust_env=False`; HTTPX can use ambient environment proxy settings. | Redirects use same client; safe-method retry and H1 fallback use same configured proxy. curl_cffi gets proxy only when configured. | Static concern; no packet proof. `socks5` does not establish remote DNS. |
| Route selection (`cli.py:477-492`) | `--proxy`, `--tor`, `CONSENSUS_PROXY`, or config. | Returns `(None, False)` absent settings; no mandatory route. | No health check or suite contract enforcement. | Static concern; ambient app config is allowed. |
| DNS (`core/emailinfo.py:103-131,148-173`) | Not routed through shared HTTP client. | System dnspython resolver. | Sync and async lookups for MX/TXT/DMARC. | Direct DNS path in source; packets unobserved. |
| AI (`core/ai.py:83-108`) | Separate HTTPX client does not receive scan proxy. | Client has no explicit proxy and no `trust_env=False`. | Separate configured endpoint. | Static concern; disabled for suite proposal. |
| Browser (`core/browser.py:33-99`) | Playwright proxy only if configured. | Launch omits proxy. | Browser context can make its own network requests. | Static concern; do not enable. |
| FlareSolverr (`core/flaresolverr.py:25-56`) | Client posts to solver endpoint directly; optional scan proxy is a field in solver request. | Endpoint reachable directly; HTTPX `trust_env=False`. | Solver itself fetches target. | Separate route and trust boundary; do not enable. |
| Vendors/adapters | Mixed: user-scanner hook patches selected HTTPX use only; socialscan aiohttp gets per-request proxy in some paths; Numint builds HTTPX transport with context proxy. | Vendor providers include independent HTTPX/aiohttp/curl_cffi and helper transports. | Provider-specific redirects/fallbacks are not uniformly centralized. | Not exhaustively mapped; no provider subset certified. |
| Updates/install/MCP | Separate urllib, package-manager and subprocess routes. | Not governed by scan HTTP client. | Background/update subprocess paths exist. | Not exercised; disable in strict profile and audit separately. |

## Harness and changes

Added `tools/egress-harness/preflight.sh`, which fails closed unless a network namespace can be created. It deliberately does not launch a collector or claim packet assertions. The host returned the expected blocked result; a full local proxy/fake HTTP/DNS harness must be completed and run on a host with namespace and firewall/capture capability.

No implementation fix is isolated safely: strict suite mode does not yet exist, and changing the shared default would alter standalone behavior while leaving DNS, AI, browser, FlareSolverr, vendors, and update paths uncontrolled. No code behavior was changed. The suite was not accessed.

## Phase 4 tasks

1. Define a strict suite invocation/profile requiring an explicit healthy proxyctl route, `OSINT_REQUIRE_PROXY=1`, `OSINT_RUN_ID`, no ambient proxy discovery, and `socks5h` for Tor. Fail before work if absent or unhealthy.
2. Make the approved module subset explicit. Disable DNS enrichment, AI, browser, FlareSolverr, update/install, MCP, and unreviewed vendor transports until each has a route policy.
3. Pass one route policy to all enabled HTTP transports; set `trust_env=False`; prohibit direct fallback, and test redirects, retries, curl_cffi and adapter hooks.
4. Build the namespace harness with a local recording proxy and fake HTTP/DNS endpoints; firewall-deny all other egress; assert proxy request visibility and direct TCP/UDP/DNS denial for explicit route, absent route and unavailable route cases.
5. Exhaustively map the selected vendor subset and dependencies, with source coverage receipts and regression fixtures for each allowed/denied path.

## Verification status and handoff

The implementation checkpoint is complete (harness preflight and documentation only). Verification command `./tools/egress-harness/preflight.sh` returned exit 77 and `BLOCKED: network namespace creation is not permitted; no egress assertions were run`. This is the expected capability gate, not a passing egress test. Phase 1 remains blocked; only an isolated packet-level run can close the gate. Do not treat source inspection, a proxy flag, or an unobserved host namespace as proof of safety.

No Jev decision was required: the gate authority and missing isolation capability determine the outcome without a semantic choice. No authentication/configuration lookup was attempted.
