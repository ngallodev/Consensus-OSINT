# Capability overlap matrix (Phase 0)

**Interpretation:** “Full” means substantial feature-surface overlap only; it does not mean parity, verified identity, equivalent evidence, or replacement readiness. “Partial” means related checks exist with important scope or semantics gaps. “Absent” means no matching capability was identified in this bounded static pass. No live coverage was compared.

| osint-suite integration | Consensus overlap | Phase 0 assessment |
|---|---|---|
| Sherlock | Username profile/site checks via imported site data and rules | **Full overlap; parity untested.** Consensus merges catalogue definitions and supports source filtering; actual current site-level accuracy is unknown (`consensus_osint/data/sites.json`, `consensus_osint/data/sites_wmn.json`, `consensus_osint/core/sitesdb.py`). |
| Maigret | Username checks and profile metadata/pivots | **Full overlap; parity untested.** Matching broad use case, but source selection, metadata, confidence, service coverage and false positives require fixture/live comparison (`consensus_osint/core/recursion.py:1-13`; `consensus_osint/core/modules.py:201-204`). |
| user-scanner | Username and email registration checks | **Full overlap; parity untested.** Vendored adapter and suite tool both support username/email; adapter transport hooks and vendor paths require separate egress audit (`consensus_osint/adapters/user_scanner_adapter.py`; `osint-suite/apps/pipeline/src/osint_tools.py:353-398`). |
| WhatsMyName | Username site catalogue | **Full overlap in catalogue purpose; parity untested.** Imported data is attributed/adapted and distinct from current rule health (`THIRD_PARTY_NOTICES.txt:21-27,43-47`). |
| Holehe | Email account-registration checks | **Full overlap in task intent; parity untested.** Vendored Holehe adapter is present; suite has different subprocess/routing controls (`consensus_osint/adapters/holehe_adapter.py`; suite runtime contract lines 33-43). |
| Ignorant | Phone-linked account registration checks | **Full overlap in task intent; parity untested.** Consensus registers an adapter for vendored Ignorant phone modules, with optional dependencies and its own result mapping; provider coverage, routing and equivalent outcomes remain unverified (`consensus_osint/core/modules.py:125-142`; `consensus_osint/adapters/ignorant_adapter.py:1-12,65-110`; suite `osint_tools.py:401-420`). |
| PhoneInfoga | Phone number enrichment/search templates | **Partial.** Some lookup/dork overlap; carrier/network enrichment and equivalent evidence semantics are not established (`consensus_osint/core/phone.py`; `consensus_osint/data/phone_dorks.yaml`; suite `osint_tools.py:423-428`). |
| h8mail | Email breach/leak-source investigation | **Absent in this bounded pass.** Consensus has email checks and informational enrichment, but no h8mail-equivalent breach corpus/workflow was confirmed; do not infer parity from “email” support. |
| Enola | Username presence checks | **Partial.** The username catalogue overlaps the broad lookup task; equivalent provider set, output evidence and automation contract were not established. |
| Search discovery (DDGS) | Search-engine discovery, dorks, and profile pivots | **Partial.** Consensus has optional search engines/mailcat/dorks; suite DDGS is a separately routed and policy-controlled content search. Not interchangeable (`consensus_osint/cli.py:220-221`; suite runtime contract lines 9-23). |

## Basis and limits

Suite tool names, builders and planner: `osint-suite/apps/pipeline/src/osint_tools.py:1-7,218-245,248-340,347-428` and `osint-suite/apps/suite/src/suite_planner.py:126-170,353-400`. Consensus module families and model: `pyproject.toml:35-65`; `consensus_osint/core/modules.py:183-204`; `consensus_osint/core/models.py:19-28,91-115`. Suite explicitly treats some collectors differently by route and input; its runtime contract is authoritative for that distinction (`osint-suite/docs/OSINT_SUITE_RUNTIME_CONTRACT.md:33-43`).

These are capability categories, not result-quality claims. Counts advertised in README/catalogues are not validated or mapped here. No test, live scan, owned identity comparison, provider-by-provider canonicalization, error-rate analysis, or request measurement was performed. Keep every existing collector selectable until Phase 3 supplies verified comparison and rollback evidence.
