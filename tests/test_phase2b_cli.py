"""Focused offline checks for strict-mode CLI outcome classification."""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import unittest
from unittest.mock import patch

from consensus_osint import cli
from consensus_osint.core.models import Finding, ScanSummary, Status


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
        return self.summary

    def solver_stats(self):
        return None

    async def close(self):
        pass


_findings: list[Finding] = []


def _finding(status: Status, *, method: str | None = None) -> Finding:
    return Finding(query="fixture", query_type="username", site="Fixture", site_id=status.value,
                   status=status, method=method, error="fixture")


def _args() -> argparse.Namespace:
    return argparse.Namespace(
        no_footer=True, quiet=True, jsonl=True, format=None, output=None, input=None,
        no_color=True, no_animation=True, all=False, verbose=False, details=False,
        summary_limit=0, live_limit=0, expansion_notices=[], no_verify=False,
        site="fixture", tags=None, fast=True, top=None, source=None, no_sites=False,
        no_modules=True, browse=False, debug=False, ai=False,
        _continuation=None,
    )


def run_scan(findings: list[Finding]) -> tuple[int, str]:
    global _findings
    _findings = findings
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
        code = cli.cmd_scan(_args())
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


if __name__ == "__main__":
    unittest.main()
