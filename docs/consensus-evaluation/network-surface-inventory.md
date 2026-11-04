# Network surface inventory (Phase 1 audit)

**Evidence labels:** **Verified** means source contains the path described. **Observed** means the local isolated harness recorded it. **Static concern** means source structure appears incompatible with the suite route contract; it is not evidence of a runtime leak. External/public route behavior remains unverified.

| Surface | Source path / observed behavior | Suite compatibility status |
|---|---|---|
| Main HTTP | `consensus_osint/core/http.py:76-131,152-162,185-200,240-312`: HTTPX AsyncClient; explicit proxy used when set, otherwise default client; HTTP/1.1 fallback, redirects, safe-method retry, optional curl_cffi. | **Observed:** explicit proxy sent fake-host request to loopback recording proxy; no packet to fake-origin port. **Static concern:** no mandatory route or explicit `trust_env=False`; redirects are not constrained to an allowlist. |
| Route inputs | `consensus_osint/cli.py:116-128,477-492,506-514`: `--proxy`, `--tor`, `CONSENSUS_PROXY`, and config are accepted. | Does not by itself enforce proxyctl, route health, `OSINT_REQUIRE_PROXY=1`, `OSINT_RUN_ID`, or `socks5h`; suite requires these (`osint-suite/docs/OSINT_SUITE_RUNTIME_CONTRACT.md:7-23`). |
| Email DNS | `consensus_osint/core/emailinfo.py:103-131,148-173`: dnspython sync and async resolvers perform MX/TXT/DMARC lookups. | **Static concern:** resolver uses system DNS configuration outside the HTTP proxy. Actual packets/destination unobserved. |
| Vendored modules | `consensus_osint/adapters/user_scanner_adapter.py:553-635` patches selected user-scanner HTTPX behavior; `holehe_adapter.py`, `ignorant_adapter.py`, `socialscan_adapter.py`, `numint_adapter.py` load vendored implementations. Direct scan of excluded vendor tree found independent HTTPX/aiohttp clients in provider files (for example `vendor/user_scanner/email_scan/learning/lingq.py`, `vendor/socialscan/platforms.py`). | **Static concern:** broad vendor tree excluded from graph; per-provider client/config/route needs path-by-path audit. Search findings are representative, not exhaustive. |
| Optional AI | `consensus_osint/core/ai.py:83-108`: user-invoked `--ai` creates a separate HTTPX client and posts query/profile data to configured OpenAI-compatible URL. | **Static concern:** does not receive the scan proxy; environment proxy may be consulted by HTTPX. Not suitable for strict mode. |
| DNS and search | `consensus_osint/cli.py:220-221`; `core/emailinfo.py`: optional search engines, mailcat and DNS enrichment. | Separate outbound requests; routing and query disclosure not demonstrated for suite use. |
| Browser / challenge solver | `consensus_osint/cli.py:180-184,517-525`; `core/browser.py:33-90`; `core/flaresolverr.py:25-56`: opt-in Playwright and FlareSolverr. Browser proxy is omitted when unset; FlareSolverr client uses `trust_env=False` and connects directly to its configured endpoint, while passing optional proxy data to the solver. | **Static concern:** browser can have direct egress; solver endpoint is a distinct direct route. Disable both in strict mode. |
| Update checks | `consensus_osint/cli.py:155,1826-1833,1733-1771`; `core/auto_update.py:49-75,97-156`; `core/install_manager.py:145-195`: startup release checks and managed-install background update code. Some noninteractive/proxy/JSON modes disable startup notices, but this does not establish all update paths disabled. | Must disable explicitly in automation; review download host and subprocess/update lifecycle. `--no-update-check` exists. |
| Child processes / browser opening | `core/auto_update.py:66-75`; `core/browser.py:61-90`; `cli.py:169,1327`: updater, Playwright driver and opt-in system browser opening. | Audit subprocess env and process lifetime; none are proof of egress alone. |
| MCP server | `pyproject.toml:55-58`; `cli.py:370-376,1670-1677`: optional MCP extra and server command. | Not needed for collector adoption; leave disabled. Network binding/lifecycle not audited in Phase 0. |

## Excluded and directly inspected scope

Codebase Memory excludes `consensus_osint/vendor/` and reports 34 ignored template assets. `file` inventoried all listed assets; the two unusable templates were searched directly for script/network references. They contain inline scripts and generated external links; no `fetch`/XHR reference was found, and the graph template declares CSP `connect-src 'none'` (`consensus_osint/templates/graph.html.j2:1-16`; `report.html.j2:217-229`). This does not verify rendered output, browser behavior, or the destination of generated links. The vendor tree contains multiple family licenses and numerous independent provider clients; direct searches were used to identify representative call sites, not to certify every provider. No packet capture, namespace/firewall, proxy, DNS, HTTP, browser, or live-provider experiment was run.

## Phase 1 questions

1. Inventory every client/resolver/socket/subprocess across core, adapters, vendored families and provider modules; identify reachable paths from each CLI command.
2. Prove allowed proxy traffic and detect direct TCP/UDP/DNS with local fake endpoints and restricted egress.
3. Test explicit Tor remote DNS, absent/unhealthy route failure, redirects, retries, curl_cffi, user-scanner hooks, browser, FlareSolverr and update routes.
4. Define a narrow approved module set only after each enabled path passes; report exact observations rather than inferring from flags.

## Phase 1 audit findings

The scoped search covered `consensus_osint/core`, `adapters`, and `vendor` for HTTPX, requests, urllib, aiohttp, curl_cffi, DNS resolvers, sockets, subprocesses and browser/solver entrypoints. It is not a complete call graph of every vendored provider. `trust_env` is explicitly disabled in FlareSolverr, but not in the shared HTTP client, standalone AI client, nor every vendor transport. Proxy parsing accepts `socks5` (`core/proxy.py:7-37`); no evidence establishes remote DNS semantics for that scheme. The Tor default is `socks5://127.0.0.1:9050` (`core/http.py:34`), not the suite-required `socks5h`. Explicit `--proxy`/`--tor` paths, absent route, redirects and retries have not been exercised.

No phase-1 route is approved for suite use. Static inspection cannot establish whether a request was emitted or blocked.

`tools/egress-harness/run.py` ran under `unshare --user --map-root-user --net`. It confirmed the proxy observation and packet capture for deliberate loopback TCP and fake-DNS UDP calibration. The namespace had only `lo` and no IPv4/IPv6 routes, checked before fixture startup. Thus the harness had no public egress route. This verifies only the shared HTTP proxy case; the DNS, vendor, AI, browser, solver, updater and other independent clients remain unverified. `nft`, `iptables`, and `tcpdump` are unavailable.
