"""Exercise the real username checker against a loopback-only fake provider."""
from __future__ import annotations

import asyncio
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from consensus_osint.core.http import Http
from consensus_osint.core.sitesdb import Site
from consensus_osint.core.username_checker import check_site

FIXTURES = Path(__file__).parent / "fixtures/phase2/fake_provider.json"
EXPECTED = {
    "fixture-found": "found",
    "fixture-not-found": "not_found",
    "fixture-blocked": "blocked",
    "fixture-rate-limited": "rate_limited",
    "fixture-error": "unknown",
}
def child_main(port: int) -> None:
    import consensus_osint.cli as cli

    from consensus_osint.core.sitesdb import SiteDB

    db = SiteDB([
        Site.from_dict({"id": "phase2-fast", "name": "Fast fixture", "url": f"http://127.0.0.1:{port}/profile/fixture-found",
                        "detect": {"type": "message", "found_strings": ["fixture profile"]}}),
        Site.from_dict({"id": "phase2-slow", "name": "Slow fixture", "url": f"http://127.0.0.1:{port}/profile/fixture-slow",
                        "detect": {"type": "message", "found_strings": ["fixture profile"]}}),
    ])
    SiteDB.load = classmethod(lambda cls, *args, **kwargs: db)
    cli.all_modules = lambda: []
    raise SystemExit(cli.main([
        "user", "fixture-user", "--site", "phase2-fast,phase2-slow", "--no-modules", "--jsonl", "--quiet",
        "--no-update-check", "--no-footer", "--no-animation", "--max-checks", "2", "--concurrency", "1",
        "--no-impersonate",
    ]))


def main() -> None:
    routes = json.loads(FIXTURES.read_text(encoding="utf-8"))
    requests: list[str] = []
    attempts: dict[str, int] = {}
    response_body_bytes = 0
    slow_started = threading.Event()
    state_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal response_body_bytes
            with state_lock:
                requests.append(self.path)
                attempts[self.path] = attempts.get(self.path, 0) + 1
                attempt = attempts[self.path]
            if self.path == "/profile/fixture-slow":
                slow_started.set()
                time.sleep(30)
            response = routes.get(self.path)
            if self.path == "/profile/fixture-slow":
                response = {"status": 200, "body": "fixture profile"}
            if self.path == "/profile/fixture-retry" and attempt == 1:
                self.close_connection = True
                self.connection.shutdown(2)
                self.connection.close()
                return
            status, body = (404, "missing fixture") if response is None else (response["status"], response["body"])
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            try:
                written = self.wfile.write(encoded)
            except OSError:
                return
            with state_lock:
                response_body_bytes += written

        def log_message(self, _format, *_args):
            pass

    class LocalServer(ThreadingHTTPServer):
        daemon_threads = True

    server = LocalServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    proxy_names = {name for name in os.environ if name.lower().endswith("_proxy")} | {"CONSENSUS_PROXY"}
    saved_proxy_env = {name: os.environ.pop(name, None) for name in proxy_names}
    try:
        site = Site.from_dict({
            "id": "phase2-fake-provider",
            "name": "Phase 2 fake provider",
            "url": f"http://127.0.0.1:{server.server_port}/profile/{{username}}",
            "detect": {"type": "message", "found_strings": ["fixture profile"],
                       "missing_strings": ["not found"]},
        })

        async def run():
            client = Http(timeout=2, retries=0, impersonate=None, http2=False, user_agent="phase2-fixture")
            try:
                findings = [await check_site(site, query, client, extract=False, retry_impersonate=False)
                            for query in EXPECTED]
            finally:
                await client.aclose()
            import consensus_osint.core.http as http_module

            original_random = http_module.random.random
            http_module.random.random = lambda: 0.0
            retry_client = Http(timeout=2, retries=1, impersonate=None, http2=False,
                                user_agent="phase2-fixture")
            try:
                retry = await retry_client.request("GET", f"http://127.0.0.1:{server.server_port}/profile/fixture-retry")
            finally:
                await retry_client.aclose()
                http_module.random.random = original_random
            assert retry.status == 200, retry

            limited_client = Http(timeout=2, retries=0, impersonate=None, http2=False, max_response_bytes=32,
                                  user_agent="phase2-fixture")
            try:
                oversized = await limited_client.request(
                    "GET", f"http://127.0.0.1:{server.server_port}/profile/fixture-large")
            finally:
                await limited_client.aclose()
            assert oversized.error == "response exceeds 32 bytes", oversized
            return findings, oversized.error

        findings, response_limit_error = asyncio.run(run())
        actual = {finding.query: finding.status.value for finding in findings}
        assert actual == EXPECTED, actual
        assert requests[:5] == [f"/profile/{query}" for query in EXPECTED], requests
        assert attempts["/profile/fixture-retry"] == 2, attempts

        with tempfile.TemporaryDirectory(prefix="consensus-phase2-home-") as isolated_home:
            env = os.environ.copy()
            env["HOME"] = isolated_home
            env["CONSENSUS_HOME"] = isolated_home
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
            env = {key: env[key] for key in ("PATH", "HOME", "CONSENSUS_HOME", "PYTHONPATH") if key in env}
            child = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--child", str(server.server_port)],
                cwd=Path(__file__).resolve().parents[1], env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                ready, _, _ = select.select([child.stdout], [], [], 15)
                assert ready, "CLI emitted no first JSONL result"
                first_line = child.stdout.readline()
                row = json.loads(first_line)
                assert row["status"] == "found" and row["site_id"] == "phase2-fast", row
                assert slow_started.wait(5), "second local check did not start"
                child.send_signal(signal.SIGTERM)
                stdout_tail, stderr = child.communicate(timeout=10)
                records = [json.loads(line) for line in (first_line + stdout_tail).splitlines()]
                assert child.returncode == 130, (child.returncode, stderr)
                assert len(records) == 1 and records[0]["site_id"] == "phase2-fast", records
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate()

        with state_lock:
            request_count = len(requests)
            byte_count = response_body_bytes
        expected_bytes = sum(len(routes[f"/profile/{query}"]["body"].encode("utf-8")) for query in EXPECTED)
        expected_bytes += len(routes["/profile/fixture-retry"]["body"].encode("utf-8"))
        expected_bytes += len(routes["/profile/fixture-large"]["body"].encode("utf-8"))
        expected_bytes += len(routes["/profile/fixture-found"]["body"].encode("utf-8"))
        assert request_count == 10, requests
        assert byte_count == expected_bytes, (byte_count, expected_bytes)
        print(json.dumps({"findings": actual, "requests": request_count, "response_body_bytes": byte_count,
                          "retry_attempts": attempts["/profile/fixture-retry"], "signal_exit": 130,
                          "jsonl_records": 1, "response_limit": response_limit_error}, sort_keys=True))
    finally:
        for name, value in saved_proxy_env.items():
            if value is not None:
                os.environ[name] = value
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        child_main(int(sys.argv[2]))
    else:
        main()
