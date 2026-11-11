"""Focused offline checks for strict-mode CLI outcome classification."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from consensus_osint import cli
from consensus_osint.core import username_checker
from consensus_osint.core.models import Finding, ScanSummary, Status
from consensus_osint.core.sitesdb import site_keys


class _Printer:
    terminal_ui = None
    tab_progress = None

    def __init__(self, **kwargs):
        self.stream = kwargs.get("stream") or io.StringIO()
        self.jsonl = kwargs.get("jsonl", False)
        self.quiet = kwargs.get("quiet", False)
        self.terminal_ui = None
        self.tab_progress = _Progress()

    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


class _Progress:
    def start(self):
        pass

    def clear(self):
        pass


class _Sites:
    sites = []


class _Scanner:
    unchecked = []

    def sites_db(self):
        return _Sites()

    @staticmethod
    def _csv(value):
        return [part.strip() for part in value.split(",") if part.strip()] if value else []

    def __init__(self, *_args, **_kwargs):
        self.summary = ScanSummary()
        self.http = None

    async def run(self, _queries):
        self.summary.findings = list(_findings)
        if _interrupt:
            raise KeyboardInterrupt
        return self.summary

    def partial_summary(self):
        self.summary.finished = time.time()
        self.summary.options["interrupted"] = True
        return self.summary

    def solver_stats(self):
        return None

    async def close(self):
        pass


_findings: list[Finding] = []
_interrupt = False


def _finding(status: Status, *, method: str | None = None, error: str = "fixture") -> Finding:
    return Finding(query="fixture", query_type="username", site="Fixture", site_id=status.value,
                   status=status, method=method, error=error)


def _args(**overrides) -> argparse.Namespace:
    values = dict(
        no_footer=True, quiet=True, jsonl=True, format=None, output=None, input=None,
        no_color=True, no_animation=True, all=False, verbose=False, details=False,
        summary_limit=0, live_limit=0, expansion_notices=[], no_verify=False,
        site="fixture", tags=None, fast=True, top=None, source=None, no_sites=False,
        no_modules=True, browse=False, debug=False, ai=False,
        delay=0.0, no_extract=False, per_host=4, search_engines=False, mailcat=False,
        _continuation=None,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


def run_scan(findings: list[Finding], *, interrupt: bool = False, **arg_overrides) -> tuple[int, str]:
    global _findings, _interrupt
    _findings = findings
    _interrupt = interrupt
    stderr = io.StringIO()
    with (patch.dict(os.environ, {"OSINT_REQUIRE_PROXY": "1"}),
          patch.object(cli, "expand_queries", return_value=[("fixture", "username")]),
          patch.object(cli, "Printer", _Printer),
          patch.object(cli, "Scanner", _Scanner),
          patch.object(cli, "SiteDB"),
          patch.object(cli, "_announce_database"),
          patch.object(cli, "all_modules", return_value=[]),
          patch.object(cli, "signal") as mocked_signal,
          contextlib.redirect_stderr(stderr)):
        mocked_signal.signal.side_effect = lambda *_args: None
        code = cli.cmd_scan(_args(**arg_overrides))
    return code, stderr.getvalue()


class StrictScanExitTests(unittest.TestCase):
    def test_all_attempted_network_errors_exit_three_even_with_skipped_check(self):
        code, stderr = run_scan([
            _finding(Status.ERROR, method="network"),
            _finding(Status.SKIPPED),
        ])
        self.assertEqual(code, 3)
        self.assertIn("every attempted catalogue check failed", stderr)

    def test_mixed_network_error_and_successful_check_exit_zero(self):
        code, stderr = run_scan([
            _finding(Status.ERROR, method="network"),
            _finding(Status.NOT_FOUND, method="status code"),
        ])
        self.assertEqual(code, 0)
        self.assertNotIn("every attempted catalogue check failed", stderr)

    def test_all_skipped_checks_do_not_become_network_failure(self):
        code, stderr = run_scan([_finding(Status.SKIPPED)])
        self.assertEqual(code, 0)
        self.assertNotIn("every attempted catalogue check failed", stderr)


class _DeadlineSite:
    """Only the attributes check_site reads on its timeout path."""

    name = "Fixture"
    id = "fixture"
    category = "misc"
    tags: list = []
    nsfw = False

    def profile_url(self, username: str) -> str:
        return f"https://example.invalid/{username}"


async def _never_finishes(*_args, **_kwargs):
    await asyncio.sleep(60)


class StrictSiteDeadlineTests(unittest.TestCase):
    def test_site_deadline_is_classified_separately_and_exits_three(self):
        with (patch.object(username_checker, "_site_deadline", return_value=0.01),
              patch.object(username_checker, "_check_site", new=_never_finishes)):
            finding = asyncio.run(username_checker.check_site(_DeadlineSite(), "fixture", None))
        self.assertEqual(finding.status, Status.ERROR)
        self.assertEqual(finding.method, username_checker.SITE_DEADLINE_METHOD)
        code, stderr = run_scan([finding])
        self.assertEqual(code, 3)
        self.assertIn("every attempted catalogue check failed before a usable response", stderr)
        self.assertIn("not a negative finding", stderr)
        self.assertNotIn("network layer", stderr)

    def test_transport_and_deadline_failures_still_exit_three(self):
        code, stderr = run_scan([
            _finding(Status.ERROR, method="network"),
            _finding(Status.ERROR, method=username_checker.SITE_DEADLINE_METHOD),
        ])
        self.assertEqual(code, 3)
        self.assertIn("does not identify the failing hop", stderr)

    def test_deadline_plus_another_attempt_does_not_exit_three(self):
        code, stderr = run_scan([
            _finding(Status.ERROR, method=username_checker.SITE_DEADLINE_METHOD),
            _finding(Status.NOT_FOUND, method="status code"),
        ])
        self.assertEqual(code, 0)
        self.assertNotIn("every attempted catalogue check failed", stderr)


class _SiteStub:
    def __init__(self, site_id: str, name: str, domain: str, *, disabled: bool = False):
        self.id = site_id
        self.name = name
        self.domain = domain
        self.disabled = disabled
        self.audit_disabled_reason = None

    @property
    def effective_disabled(self) -> bool:
        return self.disabled or bool(self.audit_disabled_reason)


class StrictSiteSelectionTests(unittest.TestCase):
    def test_exact_id_selects_its_entry(self):
        sites = [_SiteStub("twitter-x", "Twitter/X", "twitter.com")]
        self.assertEqual([site.id for site in cli._strict_sites(sites, ["twitter-x"])], ["twitter-x"])

    def test_name_and_domain_are_not_exact_ids(self):
        sites = [_SiteStub("twitter-x", "Twitter/X", "twitter.com")]
        site = sites[0]
        self.assertIn("twitter", site_keys(site))
        for token in ("Twitter", "x.com"):
            with self.subTest(token=token), self.assertRaises(ValueError) as caught:
                cli._strict_sites(sites, [token])
            self.assertIn(f"not an exact enabled catalogue id for this scan: {token.lower()}",
                          str(caught.exception))

    def test_exact_id_does_not_pull_in_domain_siblings(self):
        sites = [
            _SiteStub("github", "GitHub", "github.com"),
            _SiteStub("github-user", "GitHub (User)", "github.com"),
        ]
        self.assertEqual([site.id for site in cli._strict_sites(sites, ["github"])], ["github"])

    def test_disabled_entry_is_rejected(self):
        sites = [_SiteStub("twitter-x", "Twitter/X", "twitter.com", disabled=True)]
        with self.assertRaises(ValueError) as caught:
            cli._strict_sites(sites, ["twitter-x"])
        self.assertIn("disabled: twitter-x", str(caught.exception))

    def test_mixed_exact_id_with_unknown_id_is_rejected(self):
        sites = [_SiteStub("github", "GitHub", "github.com")]
        with self.assertRaises(ValueError) as caught:
            cli._strict_sites(sites, ["github", "nope"])
        self.assertIn("not an exact enabled catalogue id for this scan: nope", str(caught.exception))

    def test_mixed_exact_id_with_domain_is_rejected(self):
        sites = [_SiteStub("github", "GitHub", "github.com")]
        with self.assertRaises(ValueError) as caught:
            cli._strict_sites(sites, ["github", "github.com"])
        self.assertIn("not an exact enabled catalogue id for this scan: github.com", str(caught.exception))

    def test_mixed_exact_id_with_disabled_id_is_rejected(self):
        sites = [_SiteStub("github", "GitHub", "github.com"),
                 _SiteStub("twitter-x", "Twitter/X", "twitter.com", disabled=True)]
        with self.assertRaises(ValueError) as caught:
            cli._strict_sites(sites, ["github", "twitter-x"])
        self.assertIn("disabled: twitter-x", str(caught.exception))


class _ScanStub:
    """Minimal Scanner surface for planning without requests or a catalogue."""

    continuation = None
    ctx = None
    http = None
    concurrency = 1

    def __init__(self, sites, args):
        self._sites = list(sites)
        self.args = args
        self.printer = _Printer()

    def select_sites(self, id_type="username"):
        return list(self._sites)

    def select_modules(self, _kind):
        return []

    def sites_db(self):
        return _Sites()

    def _csv(self, value):
        return [part.strip() for part in value.split(",") if part.strip()] if value else []

    def _finish(self, findings, *_args):
        return findings

    def _collect(self, _finding):
        pass


class StrictSitePlanOrderTests(unittest.TestCase):
    def test_id_filter_runs_before_the_check_limit(self):
        from consensus_osint.core import modules as core_modules
        from consensus_osint.core import runner

        sites = [
            _SiteStub("github", "GitHub", "github.com"),
            _SiteStub("github-user", "GitHub (User)", "github.com"),
        ]
        seen: dict = {}

        def limit_plan(planned, planned_modules, limit, _catalogue, _pairs=()):
            seen["ids"] = [site.id for site in planned]
            return planned[:limit], planned_modules[:limit]

        async def no_checks(*_args, **_kwargs):
            return []

        stub = _ScanStub(sites, _args(site="github-user", top=1))
        with (patch.dict(os.environ, {"OSINT_REQUIRE_PROXY": "1"}),
              patch.object(core_modules, "limit_plan", side_effect=limit_plan),
              patch.object(runner, "run_all", new=no_checks)):
            asyncio.run(cli.Scanner.scan_username(stub, "fixture"))
        self.assertEqual(seen["ids"], ["github-user"])

    def test_mixed_selection_is_rejected_before_any_check_runs(self):
        from consensus_osint.core import runner

        calls = []

        async def no_checks(*_args, **_kwargs):
            calls.append(1)
            return []

        stub = _ScanStub([_SiteStub("github", "GitHub", "github.com")],
                         _args(site="github,nope", top=None))
        with (patch.dict(os.environ, {"OSINT_REQUIRE_PROXY": "1"}),
              patch.object(runner, "run_all", new=no_checks),
              self.assertRaises(ValueError) as caught):
            asyncio.run(cli.Scanner.scan_username(stub, "fixture"))
        self.assertEqual(calls, [])
        self.assertIn("nope", str(caught.exception))


class StrictInterruptedReportTests(unittest.TestCase):
    def test_interrupted_json_report_keeps_partial_non_found_results(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "partial.json"
            code, _ = run_scan(
                [_finding(Status.FOUND, method="status code"),
                 _finding(Status.NOT_FOUND, method="status code")],
                interrupt=True, output=str(output), format="json")
            data = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 130)
        self.assertTrue(data["options"]["interrupted"])
        self.assertEqual({row["status"] for row in data["findings"]}, {"found", "not_found"})


if __name__ == "__main__":
    unittest.main()
