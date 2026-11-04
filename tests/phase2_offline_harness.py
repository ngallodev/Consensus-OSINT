"""Exercise the real username checker against a loopback-only fake provider."""
from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
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


def main() -> None:
    routes = json.loads(FIXTURES.read_text(encoding="utf-8"))
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            response = routes.get(self.path)
            status, body = (404, "missing fixture") if response is None else (response["status"], response["body"])
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        site = Site.from_dict({
            "id": "phase2-fake-provider",
            "name": "Phase 2 fake provider",
            "url": f"http://127.0.0.1:{server.server_port}/profile/{{username}}",
            "detect": {"type": "message", "found_strings": ["fixture profile"],
                       "missing_strings": ["not found"]},
        })

        async def run():
            client = Http(timeout=2, retries=0, impersonate=None, http2=False)
            try:
                return [await check_site(site, query, client, extract=False, retry_impersonate=False)
                        for query in EXPECTED]
            finally:
                await client.aclose()

        findings = asyncio.run(run())
        actual = {finding.query: finding.status.value for finding in findings}
        assert actual == EXPECTED, actual
        assert requests == [f"/profile/{query}" for query in EXPECTED], requests
        print(json.dumps({"findings": actual, "requests": len(requests)}, sort_keys=True))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
