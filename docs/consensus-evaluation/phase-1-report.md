# Phase 1 — network egress and fail-closed routing

**Assessment:** 2026-11-05; fork baseline `12206f7608ea1c1d30810b1728c215f938554562`; Phase 0 branch `d39e073beb3baedfa53cfc5f53d0434d25aa2a65`; implementation checkpoint `221aeb4` (see Git history for full SHA). **Gate: BLOCKED.** No production route, module, or catalogue provider is approved. The controlled fixtures demonstrate limited behavior, not process-wide network isolation or integration acceptance.

## Strict-mode contract

When `OSINT_REQUIRE_PROXY=1`, the CLI allows only noninteractive username catalogue scans with an explicit `--site` matching enabled catalogue IDs and an explicit `--proxy` using an IP-literal host, port, and `http`, `https`, or `socks5h`. Names and domains are accepted in ordinary scans but rejected here: only exact ids preserve the routed scope the operator selected. `--top` and `--fast` still bound the resulting explicit plan. It rejects shorthand Tor, hostnames for the proxy (to avoid local DNS), `socks5`, email/phone/other query types, interactive commands, MCP and updates. It rejects requested AI, browser/open-browser, FlareSolverr, recursion, search discovery, mailcat, and loud checks. It disables module loading, extraction, curl impersonation, breach modules, TUI and update checks (`consensus_osint/cli.py:484-498,511-518,666-672,1198,1291-1300,1834,1878-1889`; `consensus_osint/core/http.py:91-99`). This is a CLI restriction, not a sandbox for arbitrary imports, other entry points, malicious code or other processes.

The operator must obtain and health-check the chosen route from proxyctl, set `OSINT_RUN_ID`, and enforce any required process-level egress boundary externally. This branch does not authenticate a proxy as proxyctl-selected, check its health before starting, or enforce `OSINT_RUN_ID`. An all-network-failure scan exits `3`, but that exit is not attributable to the selected route and does not replace health or identity verification. The fixture checker's URL and proxy are local fakes, not a production provider. The strict dispatcher accepts selected catalogue IDs, but no complete per-rule/provider audit or end-to-end real CLI fixture with a successful selected catalogue request has certified that broader set. Redirect destinations are not restricted to the original host. The optional extras and transports are not accepted merely because disabled in the CLI.

## Strict scan exit status

A strict scan reports command-level outcomes separately from per-check result statuses:

- `0`: the scan completed, including scans whose findings are provider errors or a mix of outcomes.
- `1`: the requested report could not be saved (results are rescued where possible).
- `2`: rejected options, invalid inputs, an empty `--site` selection, a name or domain instead of an exact id, or a missing or invalid `--proxy`.
- `3`: every attempted catalogue check failed at the network layer, including a site-wide deadline (`consensus_osint/cli.py:1461-1464`; `consensus_osint/core/username_checker.py:264-270`). Skipped checks do not count as attempts; one non-network attempted result returns `0`.
- `130`: the scan was interrupted. Streamed findings are kept, and an explicitly requested report is written with every collected result and `interrupted: true` (`consensus_osint/cli.py:1377-1380,1457-1458`).

Exit `3` is a whole-scan signal only: it does not identify the proxy, the route, or the failing hop, and a skipped or budget-deferred check is not evidence that the route worked.

## Evidence and classifications

The updated [network surface inventory](network-surface-inventory.md) records source paths and route modes. Classifications below refer to the stated scope, not other uses of the same library.

| Surface | Classification | Evidence and remaining limit |
|---|---|---|
| Shared HTTPX, explicit loopback proxy, missing/unavailable/interrupted proxy, redirects and retry | **Verified safe** for the specific local fixture only | Namespace harness recorded proxy-only requests, no origin-port packets during these cases, error on refusal/interruption, and two proxied redirect/retry requests. It does not establish whole-process or provider safety. |
| SOCKS5h destination DNS | **Verified safe** for the local fake SOCKS fixture only | Fixture received `fixture.invalid` in SOCKS domain-name form; no UDP/53 packet observed. Actual Tor/proxyctl route and health were not tested. |
| Ambient HTTPX proxies | **Confirmed violation** in standalone mode relative to the suite contract | Local conflicting `HTTP_PROXY` is used in ordinary mode; strict shared HTTPX instead used the explicit proxy with `trust_env=False`. Standalone behavior is intentionally preserved. |
| Email DNS and mailcat SMTP | **Confirmed violation** of proposed strict routing | Local fake DNS recorded the actual dnspython resolver; it is a separate system resolver, not the HTTP proxy (`core/emailinfo.py:103-131,148-173`). Mailcat uses resolver and direct socket (`core/mailcat.py:410-432`). The strict CLI rejects email and mailcat. |
| curl_cffi | **Disabled by policy** | Strict `Http` does not create its impersonation session. A separate curl_cffi 0.13.0 fixture used an explicit local proxy with `trust_env=False`; this is not proof for Consensus's non-strict curl configuration or declared >=0.17 version. |
| Vendored providers | **Disabled by policy** | The local Ignorant Instagram function reached a fake endpoint through a supplied HTTPX client. It is one provider and not evidence for any other vendor client; all code modules are excluded from strict CLI and not loaded during preparation. |
| AI, browser, FlareSolverr, recursion and discovery | **Disabled by policy** | CLI rejects these features; their independent clients and DNS/socket paths were not dynamically certified. |
| Startup updates, installer, shell, MCP, TUI | **Disabled by policy** | CLI rejects non-scan commands and suppresses startup update checks and the TUI for strict scans. The installer and direct Python calls are outside this CLI boundary. |
| proxyctl route authority/health and run ID | **Not yet verified** | Caller selects and checks a route; no identity, health, run ID or route-interruption propagation contract is enforced here. |
| TLS, HTTP CONNECT/HTTPS proxy, IPv6, all redirect targets, every catalogue rule | **Not yet verified** | No HTTPS proxy/TLS fixture, remote Tor service, exhaustive rule-specific call graph, or complete end-to-end selected-ID scan was exercised. |

The pre-existing direct-capable surfaces are static findings except the local ambient-proxy and DNS observations above; no public leak or third-party request is claimed. An independent Luna source audit identified empty/ambiguous selections, DNS/SMTP, independent vendor transports and cross-host redirects as gaps. The implementation now requires exact enabled catalogue IDs and errors on an empty selection; a selected id still does not establish a completed request or a healthy route. The graph excluded vendor; source search found network primitive references in multiple vendor families, so vendor inventory is representative, not exhaustive.

## Controlled verification

After implementation, `./tools/egress-harness/run.py` exited **0** at checkpoint `221aeb4`. It uses `unshare --user --map-root-user --net`, no physical interface or default route, nftables default-drop input/output/forward, a documentation-range dummy sink, local proxy/SOCKS/origin/DNS fixtures and AF_PACKET capture. Calibration counted one denied TCP and one denied UDP packet and detected deliberate local direct TCP and DNS traffic. Observed local destination packet counts in the final run: HTTP proxy 6, SOCKS proxy 14, origin 10 and fake DNS 8; those aggregate counts include explicit calibrations and vary with handshakes. Per-case assertions compare counters before calibration. Missing route, proxy refusal and an interrupted proxy connection returned errors without a direct origin packet. Redirect and retry stayed on the fake proxy. DNS and one vendor function were exercised only with local replacements. No public identity or third-party service was contacted.

`python3 -m compileall -q consensus_osint/cli.py consensus_osint/core/http.py consensus_osint/core/network_status.py tools/egress-harness/run.py` exited **0** for prior checkpoint `b7874a9`; the final harness imported the updated CLI at `221aeb4`. `git diff --check consensus-phase0-evaluation...HEAD` exited **0**. Host: Python 3.13.5, HTTPX 0.28.1, curl_cffi 0.13.0, dnspython 2.8.0, nftables 1.1.3, util-linux 2.41.5. Other package and runtime environments were not validated. Namespace setup failures return 77 or fail the harness; they are not passes.

## Remaining acceptance work

1. Supply a real proxyctl-selected, health-checked route and run ID without introducing a second authority; define startup and interrupted-route failure semantics, including nonzero result propagation.
2. Exercise an end-to-end CLI run against a controlled catalogue fixture with selected IDs under missing, unhealthy and interrupted routes, including DNS, IPv6 and any allowed proxy scheme; prove no direct traffic for every enabled route and relevant redirects.
3. Audit and narrowly approve actual catalogue provider paths and dynamic dependencies, or enforce an external OS-level deny boundary and verify it. Map remaining independent clients and subprocesses before enabling them.
4. Resolve TLS/CONNECT, curl version, CA environment and Tor-specific compatibility; retain email/phone, vendor modules and optional features disabled until separately verified.

No live scans or suite modifications were made. The Phase 0 capability overlap does not justify replacing a collector. Licensing and Phase 2 lifecycle/exit semantics remain separate gates. No Jev decision was required because the acceptance criteria and missing evidence determine the blocked result.
