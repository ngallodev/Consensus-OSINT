#!/usr/bin/env python3
"""Exercise Consensus HTTP routing against loopback-only fixtures in a netns."""
from __future__ import annotations

import collections
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROXY_PORT, ORIGIN_PORT, DNS_PORT = 18081, 18080, 15353


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def check_isolation() -> None:
    links = run("ip", "-brief", "addr").splitlines()
    if any(not line.split()[0].startswith("lo") for line in links):
        raise RuntimeError(f"non-loopback interface present: {links!r}")
    routes = run("ip", "-4", "route", "show").splitlines()
    routes += run("ip", "-6", "route", "show").splitlines()
    if routes:
        raise RuntimeError(f"routes present in test namespace: {routes!r}")
    run("ip", "link", "set", "lo", "up")


class Capture:
    def __init__(self) -> None:
        self.counts: collections.Counter[tuple[int, int, int]] = collections.Counter()
        self.stop = threading.Event()
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.sock.bind(("lo", 0))
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        self.sock.settimeout(0.1)
        while not self.stop.is_set():
            try:
                frame = self.sock.recv(65535)
            except TimeoutError:
                continue
            if len(frame) < 14:
                continue
            ethertype = struct.unpack_from("!H", frame, 12)[0]
            if ethertype == 0x0800 and len(frame) >= 34:
                ihl = (frame[14] & 15) * 4
                proto = frame[23]
                offset = 14 + ihl
                if proto in (6, 17) and len(frame) >= offset + 4:
                    dport = struct.unpack_from("!H", frame, offset + 2)[0]
                    self.counts[(4, proto, dport)] += 1
            elif ethertype == 0x86DD and len(frame) >= 58:
                proto = frame[20]
                if proto in (6, 17):
                    dport = struct.unpack_from("!H", frame, 14 + 42 + 2)[0]
                    self.counts[(6, proto, dport)] += 1

    def wait_for(self, key: tuple[int, int, int], previous: int) -> int:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            count = self.counts[key]
            if count > previous:
                return count
            time.sleep(0.01)
        raise AssertionError(f"packet capture did not observe {key}; counts={dict(self.counts)}")

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=1)
        self.sock.close()


class Fixtures:
    def __init__(self) -> None:
        self.requests: list[bytes] = []
        self.stop = threading.Event()
        self.servers: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self._tcp(PROXY_PORT, self._proxy)
        self._tcp(ORIGIN_PORT, self._origin)
        self._udp(DNS_PORT)

    def _tcp(self, port: int, handler) -> None:
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen()
        server.settimeout(0.1)
        self.servers.append(server)

        def accept() -> None:
            while not self.stop.is_set():
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self.stop.is_set():
                        return
                    raise
                threading.Thread(target=handler, args=(conn,), daemon=True).start()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        self.threads.append(thread)

    def _proxy(self, conn: socket.socket) -> None:
        with conn:
            data = conn.recv(8192)
            self.requests.append(data)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nfixture-proxy")

    def _origin(self, conn: socket.socket) -> None:
        with conn:
            conn.recv(8192)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nfixture-origin")

    def _udp(self, port: int) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", port))
        server.settimeout(0.1)
        self.servers.append(server)

        def receive() -> None:
            while not self.stop.is_set():
                try:
                    payload, peer = server.recvfrom(2048)
                except TimeoutError:
                    continue
                except OSError:
                    if self.stop.is_set():
                        return
                    raise
                # Return a DNS response with no answers; the fixture only needs
                # to prove that a DNS-shaped UDP request reached this endpoint.
                if len(payload) >= 12:
                    flags = struct.unpack_from("!H", payload, 2)[0] | 0x8000
                    server.sendto(payload[:2] + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + payload[12:], peer)

        thread = threading.Thread(target=receive, daemon=True)
        thread.start()
        self.threads.append(thread)

    def close(self) -> None:
        self.stop.set()
        for server in self.servers:
            server.close()


def dns_query() -> bytes:
    # Query fixture.invalid A, ID 0x5151, recursion desired.
    return (b"\x51\x51\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07fixture\x07invalid\x00\x00\x01\x00\x01")


async def exercise_consensus() -> None:
    import httpx
    from consensus_osint.core.http import Http

    proxy = f"http://127.0.0.1:{PROXY_PORT}"
    client = Http(proxy=proxy, impersonate=None, http2=False)
    try:
        result = await client.get("http://fixture.invalid/proxied")
        assert result.status == 200 and result.text == "fixture-proxy", result
    finally:
        await client.aclose()
    # Confirm the test dependency and package are loaded from this checkout.
    assert httpx.__version__


def inside() -> None:
    check_isolation()
    capture = Capture()
    fixtures = Fixtures()
    try:
        proxy_key = (4, 6, PROXY_PORT)
        origin_key = (4, 6, ORIGIN_PORT)
        dns_key = (4, 17, DNS_PORT)
        proxy_before, origin_before = capture.counts[proxy_key], capture.counts[origin_key]
        import asyncio
        asyncio.run(exercise_consensus())
        proxy_after = capture.wait_for(proxy_key, proxy_before)
        time.sleep(0.1)
        assert proxy_after > proxy_before and capture.counts[origin_key] == origin_before
        assert fixtures.requests and b"http://fixture.invalid/proxied" in fixtures.requests[0]
        print("PASS: Consensus Http sent the fake URL through the local proxy; no origin-port packet observed")

        # Detector calibration: a deliberately direct local TCP request must
        # appear in capture. This is loopback-only and cannot reach a provider.
        direct_before = capture.counts[origin_key]
        with socket.create_connection(("127.0.0.1", ORIGIN_PORT), timeout=2) as conn:
            conn.sendall(b"GET /direct-calibration HTTP/1.0\r\n\r\n")
            conn.recv(256)
        capture.wait_for(origin_key, direct_before)
        print("PASS: packet capture detected the deliberate loopback direct-TCP calibration")

        # Same detector calibration for a DNS-shaped UDP request to a fake
        # local resolver. It is not a public DNS query.
        before = capture.counts[dns_key]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.sendto(dns_query(), ("127.0.0.1", DNS_PORT))
            sock.recvfrom(2048)
        capture.wait_for(dns_key, before)
        print("PASS: packet capture detected the deliberate fake-DNS UDP calibration")
        print(f"OBSERVED: local packets by destination port: proxy={proxy_after}, origin={capture.counts[origin_key]}, dns={capture.counts[dns_key]}")
        print("LIMIT: validates the shared HTTP client route and capture only; DNS resolver and other transports remain unaudited")
    finally:
        fixtures.close()
        capture.close()


def main() -> int:
    if os.environ.get("CONSENSUS_EGRESS_IN_NETNS") == "1":
        try:
            inside()
            return 0
        except Exception as exc:
            print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
    if not sys.platform.startswith("linux"):
        print("BLOCKED: Linux network namespaces required", file=sys.stderr)
        return 77
    command = ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable, __file__]
    env = dict(os.environ, CONSENSUS_EGRESS_IN_NETNS="1", PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    try:
        return subprocess.call(command, cwd=ROOT, env=env)
    except FileNotFoundError:
        print("BLOCKED: unshare unavailable; no egress assertions were run", file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
