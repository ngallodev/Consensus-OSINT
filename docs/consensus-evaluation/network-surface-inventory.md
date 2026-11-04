# Network surface inventory (Phase 0 static pass)

**Evidence labels:** **Verified** means the source contains the path described. **Static concern** means source structure appears incompatible with the suite route contract; it is not evidence of a runtime leak. Network behavior was not tested.

| Surface | Source path / observed behavior | Suite compatibility status |
|---|---|---|
| Main HTTP | `consensus_osint/core/http.py:76-131,240-312`: HTTPX AsyncClient; explicit proxy used when set, otherwise default client; redirect support in wrapper; one retry for safe HTTPX methods; optional curl_cffi session uses proxy only when configured. | **Static concern:** no explicit `trust_env=False`; no mandatory route. Verify env proxy behavior, fallback clients and redirects in Phase 1. |
| Route inputs | `consensus_osint/cli.py:116-128,477-492,506-514`: `--proxy`, `--tor`, `CONSENSUS_PROXY`, and config are accepted. | Does not by itself enforce proxyctl, route health, `OSINT_REQUIRE_PROXY=1`, `OSINT_RUN_ID`, or `socks5h`; suite requires these (`osint-suite/docs/OSINT_SUITE_RUNTIME_CONTRACT.md:7-23`). |
| Email DNS | `consensus_osint/core/emailinfo.py:103-131,148-173`: dnspython `Resolver.resolve` performs MX/TXT lookups. | **Static concern:** resolver is not routed through shared HTTP proxy; determine actual DNS destination in controlled environment. |
| Vendored modules | `consensus_osint/adapters/user_scanner_adapter.py:553-635` patches selected user-scanner HTTPX behavior; `holehe_adapter.py`, `ignorant_adapter.py`, `socialscan_adapter.py`, `numint_adapter.py` load vendored implementations. Direct scan of excluded vendor tree found independent HTTPX/aiohttp clients in provider files (for example `vendor/user_scanner/email_scan/learning/lingq.py`, `vendor/socialscan/platforms.py`). | **Static concern:** broad vendor tree excluded from graph; per-provider client/config/route needs path-by-path audit. Search findings are representative, not exhaustive. |
| Optional AI | `consensus_osint/core/ai.py:83-108`: user-invoked `--ai` creates separate HTTPX client and posts query/profile data to configured OpenAI-compatible URL. | **Static concern:** not supplied the scan proxy; outbound destination and data handling need an explicit opt-in and route control. |
| DNS and search | `consensus_osint/cli.py:220-221`; `core/emailinfo.py`: optional search engines, mailcat and DNS enrichment. | Separate outbound requests; routing and query disclosure not demonstrated for suite use. |
| Browser / challenge solver | `consensus_osint/cli.py:180-184,517-525`; `core/browser.py:33-90`; `core/flaresolverr.py:39-56`: opt-in Playwright and FlareSolverr, with configured proxy passed when present. | **Static concern:** browser may launch with no proxy when unset; solver endpoint itself is another network target. Disabled by suite proposal until audited. |
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
