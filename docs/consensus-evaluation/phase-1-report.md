# Phase 1 — network egress and fail-closed routing

**Assessment date:** 2026-11-04
**Base:** `862826852114342808629b0bfa73b681eb806fd4`
**Branch:** `consensus-phase1-network`
**Gate: BLOCKED.** No enabled route has packet-level fail-closed evidence. No public identity/provider, credential, or suite was accessed.

## Environment and evidence

- Initial `git status --short --branch`: clean; `HEAD` matched the requested base and branch.
- `codebase-memory-cli status --json --project consensus-phase1-network`: ready at `2026-11-04T21:51:41Z`, 4,543 nodes / 14,747 edges, no partial/skipped files, generation matches. It reports 34 ignored assets and two unusable Jinja templates. Coverage for `consensus_osint/core/http.py` was best-effort with no recorded issue. Structural search returned 88 matches, first page 50 with another page available; no negative/exhaustive claim is based on that graph. Vendor is not fully represented, so source search and direct reads were used for its transport families.
- `unshare --user --map-root-user --net ...`: succeeds. `/usr/sbin/nft` and `/usr/bin/tcpdump` are available and work in the namespace; `nft` is outside the default `PATH`, and `iptables` remains unavailable. The harness installs nftables input/output/forward drop policies, accepts loopback only, and verifies a dummy egress sink with only documentation-range routes. Its output drop counter must increase for synthetic TCP and DNS/UDP attempts routed to that dummy; no physical interface or default route exists.
- The first preflight implementation used privileged `unshare --net` and was too restrictive. It was replaced by `tools/egress-harness/run.py`, which creates the unprivileged user+network namespace and performs packet capture itself.

## Path matrix

| Path | Explicit proxy / Tor | Route absent | Redirect / fallback | Finding |
|---|---|---|---|---|
| Shared HTTPX (`core/http.py:76-162,185-312`) | Shared client and HTTP/1.1 fallback receive configured proxy. Tor default is now `socks5h://127.0.0.1:9050`. | Standalone mode still allows direct requests; `OSINT_REQUIRE_PROXY=1` now rejects construction without explicit proxy/Tor. HTTPX clients use `trust_env=False`. | Local packet test confirms explicit HTTP proxy; failed proxy returns error without origin fallback. Tor-route fixture confirms SOCKS5 domain-name request with no local DNS packet. Redirects/retries remain same client. | Bounded shared-client behavior verified; curl_cffi and other clients remain separate. |
| Route selection (`cli.py:477-492`) | `--proxy`, `--tor`, `CONSENSUS_PROXY`, or config. | Returns `(None, False)` absent settings; no mandatory route. | No health check or suite contract enforcement. | Static concern; ambient app config is allowed. |
| Network-status telemetry (`core/network_status.py:21-70`, `core/terminal_ui.py:143-166`) | TUI can check the selected route. | Previously launched a direct public-IP request alongside any proxy check, or system-proxy discovery when selected. | Under `OSINT_REQUIRE_PROXY=1`, now skips the direct/system-proxy probe and checks only the passed explicit proxy; with no explicit route it performs no request. | Strict branch regression fixture passed with mocked request function; no public endpoint contacted. |
| DNS (`core/emailinfo.py:103-131,148-173`) | SOCKS5h is available for shared HTTPX requests. | System dnspython resolver is outside the shared proxy. | Sync and async lookups for MX/TXT/DMARC. Fake DNS packet capture was calibrated, but the resolver itself was not invoked. | Direct DNS path remains unverified and blocks gate. |
| AI (`core/ai.py:83-108`) | Separate HTTPX client does not receive scan proxy. | Client has no explicit proxy and no `trust_env=False`. | Separate configured endpoint. | Static concern; disabled for suite proposal. |
| Browser (`core/browser.py:33-99`) | Playwright proxy only if configured. | Launch omits proxy. | Browser context can make its own network requests. | Static concern; do not enable. |
| FlareSolverr (`core/flaresolverr.py:25-56`) | Client posts to solver endpoint directly; optional scan proxy is a field in solver request. | Endpoint reachable directly; HTTPX `trust_env=False`. | Solver itself fetches target. | Separate route and trust boundary; do not enable. |
| Vendors/adapters | Mixed: user-scanner hook patches selected HTTPX use only; socialscan aiohttp gets per-request proxy in some paths; Numint builds HTTPX transport with context proxy. | Vendor providers include independent HTTPX/aiohttp/curl_cffi and helper transports. | Provider-specific redirects/fallbacks are not uniformly centralized. | Not exhaustively mapped; no provider subset certified. |
| Updates/install/MCP | Separate urllib, package-manager and subprocess routes. | Not governed by scan HTTP client. | Background/update subprocess paths exist. | Not exercised; disable in strict profile and audit separately. |

## Harness and changes

Added `tools/egress-harness/run.py`: it verifies a fresh namespace starts with loopback only and no routes, installs nftables drop policies, creates a dummy sink routed only for `203.0.113.0/24`, and checks denied packet counters. It then captures loopback frames with AF_PACKET while testing Consensus `Http` against local HTTP, proxy, SOCKS5h and fake DNS fixtures. All network fixtures are local; the synthetic routed packets terminate at nftables/dummy and cannot leave the namespace.

Run `./tools/egress-harness/run.py` → exit 0. Observed: nftables counted and dropped 1 test-net TCP packet and 1 test-net DNS/UDP packet; Consensus HTTP request reached the local recording proxy with no fake-origin packet; Tor selection used SOCKS5h and sent `fixture.invalid` to the proxy with no local DNS packet; `OSINT_REQUIRE_PROXY=1` rejected a missing route before socket creation; an unavailable explicit proxy returned an error without origin fallback; strict TUI telemetry skipped direct/system-proxy probes; local TCP/DNS packet-capture calibrations passed. Final run recorded loopback destinations: HTTP proxy port 18081 = 6 packets, SOCKS port 18082 = 16, origin port 18080 = 20 (ambient-proxy regression and deliberate direct calibration only), fake DNS port 15353 = 2. Counts vary slightly with TCP handshakes.

Bounded root-cause fixes: `core/http.py` disables HTTPX ambient environment proxy discovery, changes Tor's default from `socks5` to `socks5h` for remote DNS, and honors `OSINT_REQUIRE_PROXY=1` by refusing to create a shared client without a configured route. `core/network_status.py` skips its direct public-IP/system-proxy probes in strict mode, closing a TUI telemetry bypass through `TerminalUI.refresh_network`. These do not secure independent DNS, AI, browser, FlareSolverr, updater or vendored transports.

The bounded shared-client changes do not establish a full strict suite mode; independent DNS, AI, browser, FlareSolverr, vendor, and update paths remain uncontrolled and must stay disabled for any proposed integration. The suite was not accessed.

## Phase 4 tasks

1. Complete the suite invocation/profile: validate a healthy proxyctl route and `OSINT_RUN_ID`, ensure only explicit selected routes are accepted, and fail before work if absent or unhealthy. Shared `Http` now enforces the `OSINT_REQUIRE_PROXY=1` missing-route check.
2. Make the approved module subset explicit. Disable DNS enrichment, AI, browser, FlareSolverr, update/install, MCP, and unreviewed vendor transports until each has a route policy.
3. Extend the shared route policy to every enabled transport; audit `trust_env`, redirects, retries, curl_cffi, adapters and DNS resolver behavior.
4. Extend the namespace harness cases to those approved transports. The existing harness already demonstrates nftables-denied test-net TCP and DNS/UDP, shared proxy routing, absent/unavailable shared-client routes, and SOCKS5h remote DNS.
5. Exhaustively map the selected vendor subset and dependencies, with source coverage receipts and regression fixtures for each allowed/denied path.

## Verification status and handoff

The implementation checkpoint is complete. `./tools/egress-harness/run.py` → exit 0; `python -m compileall -q tools/egress-harness/run.py consensus_osint/core/http.py` → exit 0; `git diff --check` → exit 0. This controlled suite verifies the shared HTTP client, missing/unavailable route handling, Tor remote DNS, strict TUI telemetry behavior, nftables deny counters, and packet-capture calibration. It does **not** verify the dnspython resolver, AI, vendor transports, browser, FlareSolverr, updates/installers, subprocesses, redirects to off-scope hosts, curl_cffi, or route health. Phase 1 remains blocked until the enabled module set is bounded and every remaining enabled path has equivalent controlled evidence.

No Jev decision was required: the gate authority and remaining unverified transports determine the outcome without a semantic choice. No authentication/configuration lookup was attempted.
