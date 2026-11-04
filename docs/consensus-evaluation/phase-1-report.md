# Phase 1 — network egress and fail-closed routing

**Assessment date:** 2026-11-04
**Base:** `862826852114342808629b0bfa73b681eb806fd4`
**Branch:** `consensus-phase1-network`
**Gate: BLOCKED.** No enabled route has packet-level fail-closed evidence. No public identity/provider, credential, or suite was accessed.

## Environment and evidence

- Initial `git status --short --branch`: clean; `HEAD` matched the requested base and branch.
- `codebase-memory-cli status --json --project consensus-phase1-network`: ready at `2026-11-04T21:51:41Z`, 4,543 nodes / 14,747 edges, no partial/skipped files, generation matches. It reports 34 ignored assets and two unusable Jinja templates. Coverage for `consensus_osint/core/http.py` was best-effort with no recorded issue. Structural search returned 88 matches, first page 50 with another page available; no negative/exhaustive claim is based on that graph. Vendor is not fully represented, so source search and direct reads were used for its transport families.
- `unshare --user --map-root-user --net ...`: succeeds. The isolated namespace exposes only loopback; `ip -4 route show` and `ip -6 route show` are empty. `ip link set lo up` succeeds and an `AF_PACKET/SOCK_RAW` socket binds to `lo`. `nft`, `iptables`, and `tcpdump` remain unavailable. The harness refuses to start if any non-loopback interface or route appears, so it has no public-egress path without relying on firewall rules.
- The first preflight implementation used privileged `unshare --net` and was too restrictive. It was replaced by `tools/egress-harness/run.py`, which creates the unprivileged user+network namespace and performs packet capture itself.

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

Added `tools/egress-harness/run.py`: it verifies loopback-only topology and no routes before opening local fake proxy, HTTP origin, and DNS endpoints; captures Ethernet frames on loopback through AF_PACKET; and tests Consensus's shared `Http` with explicit proxy against `fixture.invalid`. It also performs local direct-TCP and DNS-shaped UDP calibration probes to confirm capture detects both packet classes. All sockets and destinations are loopback; no public provider or identity is addressed.

Run `./tools/egress-harness/run.py` → exit 0. Observed: Consensus HTTP request arrived at the local recording proxy; no packet to fake-origin port during that request; deliberate local direct-TCP and fake-DNS UDP probes were both captured. Final run counters: proxy destination port 18081 = 10 packets, origin port 18080 = 10 packets (the deliberate calibration only), DNS port 15353 = 2 packets. These are local packet counts, not evidence about any external route.

No implementation fix is isolated safely: strict suite mode does not yet exist, and changing the shared default would alter standalone behavior while leaving DNS, AI, browser, FlareSolverr, vendors, and update paths uncontrolled. No code behavior was changed. The suite was not accessed.

## Phase 4 tasks

1. Define a strict suite invocation/profile requiring an explicit healthy proxyctl route, `OSINT_REQUIRE_PROXY=1`, `OSINT_RUN_ID`, no ambient proxy discovery, and `socks5h` for Tor. Fail before work if absent or unhealthy.
2. Make the approved module subset explicit. Disable DNS enrichment, AI, browser, FlareSolverr, update/install, MCP, and unreviewed vendor transports until each has a route policy.
3. Pass one route policy to all enabled HTTP transports; set `trust_env=False`; prohibit direct fallback, and test redirects, retries, curl_cffi and adapter hooks.
4. Build the namespace harness with a local recording proxy and fake HTTP/DNS endpoints; firewall-deny all other egress; assert proxy request visibility and direct TCP/UDP/DNS denial for explicit route, absent route and unavailable route cases.
5. Exhaustively map the selected vendor subset and dependencies, with source coverage receipts and regression fixtures for each allowed/denied path.

## Verification status and handoff

The implementation checkpoint is complete (harness and documentation only). The controlled test verifies the shared HTTP client’s explicit proxy route and packet-capture calibration in a network namespace with no external interfaces or routes. It does **not** verify Consensus DNS resolver routing, absent/unhealthy proxy behavior, AI, vendor transports, browser, FlareSolverr, updates/installers, subprocesses, or route health. No nftables firewall was available; the test instead asserts that the namespace has no non-loopback interface and no IPv4/IPv6 route before starting. Phase 1 remains blocked until all enabled route families have equivalent controlled evidence and a strict enabled-module set is defined.

No Jev decision was required: the gate authority and missing isolation capability determine the outcome without a semantic choice. No authentication/configuration lookup was attempted.
