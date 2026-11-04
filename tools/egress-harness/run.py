#!/usr/bin/env python3
"""Exercise Consensus HTTP routing against loopback-only fixtures in a netns."""
from __future__ import annotations

import collections
import asyncio
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROXY_PORT, ORIGIN_PORT, DNS_PORT, SOCKS_PORT = 18081, 18080, 15353, 18082
NFT = "/usr/sbin/nft"


def run(*args: str, stdin: str | None = None) -> str:
    return subprocess.check_output(args, input=stdin, text=True, stderr=subprocess.STDOUT).strip()


def check_isolation() -> None:
    links = run("ip", "-brief", "addr").splitlines()
    if any(not line.split()[0].startswith("lo") for line in links):
        raise RuntimeError(f"non-loopback interface present: {links!r}")
    routes = run("ip", "-4", "route", "show").splitlines()
    routes += run("ip", "-6", "route", "show").splitlines()
    if routes:
        raise RuntimeError(f"routes present in test namespace: {routes!r}")
    run("ip", "link", "set", "lo", "up")
    if not Path(NFT).is_file():
        raise RuntimeError(f"nftables binary missing at {NFT}")
    run(NFT, "-f", "-", stdin='''
table inet consensus_harness {
 chain output { type filter hook output priority 0; policy drop;
  oifname "lo" accept; oifname != "lo" counter drop;
 }
 chain input { type filter hook input priority 0; policy drop;
  iifname "lo" accept; iifname != "lo" counter drop;
 }
 chain forward { type filter hook forward priority 0; policy drop; }
}
''')
    assert "policy drop" in run(NFT, "list", "table", "inet", "consensus_harness")
    run("ip", "link", "add", "egress-sink", "type", "dummy")
    run("ip", "addr", "add", "198.18.0.1/24", "dev", "egress-sink")
    run("ip", "link", "set", "egress-sink", "up")
    run("ip", "route", "add", "203.0.113.0/24", "dev", "egress-sink")
    assert "dummy" in run("ip", "-d", "link", "show", "egress-sink")
    routes = run("ip", "-4", "route", "show").splitlines()
    assert len(routes) == 2 and all("egress-sink" in route and "default" not in route for route in routes), routes


def nft_drops() -> int:
    listing = run(NFT, "list", "chain", "inet", "consensus_harness", "output")
    match = re.search(r"oifname != \"lo\" counter packets (\d+)", listing)
    if not match:
        raise RuntimeError(f"nftables egress drop counter missing: {listing}")
    return int(match.group(1))


def test_egress_drop() -> None:
    before = nft_drops()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.connect(("203.0.113.7", 80))
        except (TimeoutError, OSError):
            pass
        else:
            raise AssertionError("test-net TCP unexpectedly connected")
    after_tcp = nft_drops()
    assert after_tcp > before, f"nft did not count denied TCP output: {before} -> {after_tcp}"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.sendto(dns_query(), ("203.0.113.53", 53))
        except OSError:
            pass
    after_udp = nft_drops()
    assert after_udp > after_tcp, f"nft did not count denied DNS/UDP output: {after_tcp} -> {after_udp}"
    print(f"PASS: nftables dropped and counted routed test-net TCP and DNS/UDP attempts ({after_tcp - before} TCP packets, {after_udp - after_tcp} UDP packets)")


async def test_strict_network_status() -> None:
    import consensus_osint.core.network_status as status

    calls = []
    original = status.observe_ip
    previous = os.environ.get("OSINT_REQUIRE_PROXY")
    os.environ["OSINT_REQUIRE_PROXY"] = "1"

    async def observe_ip(*, proxy=None, trust_env=False):
        calls.append((proxy, trust_env))
        return "198.51.100.10"

    status.observe_ip = observe_ip
    try:
        result = await status.check_network("http://127.0.0.1:18081", system_proxy=True)
        assert calls == [("http://127.0.0.1:18081", False)], calls
        assert result.public_ip == "not checked" and result.proxy_status == "observed", result
        calls.clear()
        result = await status.check_network(None, system_proxy=True)
        assert not calls and result.proxy_status == "unverified", (calls, result)
    finally:
        status.observe_ip = original
        if previous is None:
            os.environ.pop("OSINT_REQUIRE_PROXY", None)
        else:
            os.environ["OSINT_REQUIRE_PROXY"] = previous


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
        self.socks_domains: list[bytes] = []
        self.stop = threading.Event()
        self.servers: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self._tcp(PROXY_PORT, self._proxy)
        self._tcp(ORIGIN_PORT, self._origin)
        self._tcp(SOCKS_PORT, self._socks)
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
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nfixture-origin")

    def _socks(self, conn: socket.socket) -> None:
        def read_exact(size: int) -> bytes:
            data = bytearray()
            while len(data) < size:
                part = conn.recv(size - len(data))
                if not part:
                    raise ConnectionError("short SOCKS request")
                data.extend(part)
            return bytes(data)

        with conn:
            version, nmethods = read_exact(2)
            read_exact(nmethods)
            if version != 5:
                raise AssertionError(f"unexpected SOCKS version {version}")
            conn.sendall(b"\x05\x00")
            version, command, _, atyp = read_exact(4)
            if atyp == 3:
                host = read_exact(read_exact(1)[0])
            elif atyp == 1:
                host = socket.inet_ntop(socket.AF_INET, read_exact(4)).encode()
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, read_exact(16)).encode()
            else:
                raise AssertionError(f"unexpected SOCKS address type {atyp}")
            read_exact(2)
            self.socks_domains.append(host)
            if (version, command) != (5, 1):
                raise AssertionError("expected SOCKS5 CONNECT")
            conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
            conn.recv(8192)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nfixture-s5h")

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


async def exercise_socks5h() -> None:
    from consensus_osint.core.http import Http
    import consensus_osint.core.http as http_module

    configured = http_module.TOR_PROXY
    assert configured.startswith("socks5h://"), configured
    http_module.TOR_PROXY = f"socks5h://127.0.0.1:{SOCKS_PORT}"
    client = Http(tor=True, impersonate=None, http2=False)
    try:
        result = await client.get("http://fixture.invalid/remote-dns")
        assert result.status == 200 and result.text == "fixture-s5h", result
    finally:
        await client.aclose()
        http_module.TOR_PROXY = configured


def inside() -> None:
    check_isolation()
    test_egress_drop()
    capture = Capture()
    fixtures = Fixtures()
    try:
        proxy_key = (4, 6, PROXY_PORT)
        origin_key = (4, 6, ORIGIN_PORT)
        socks_key = (4, 6, SOCKS_PORT)
        dns_key = (4, 17, DNS_PORT)
        proxy_before, origin_before = capture.counts[proxy_key], capture.counts[origin_key]
        asyncio.run(exercise_consensus())
        proxy_after = capture.wait_for(proxy_key, proxy_before)
        time.sleep(0.1)
        assert proxy_after > proxy_before and capture.counts[origin_key] == origin_before
        assert fixtures.requests and b"http://fixture.invalid/proxied" in fixtures.requests[0]
        print("PASS: Consensus Http sent the fake URL through the local proxy; no origin-port packet observed")

        socks_before = capture.counts[socks_key]
        dns53_before = sum(n for (_, proto, port), n in capture.counts.items() if proto == 17 and port == 53)
        asyncio.run(exercise_socks5h())
        capture.wait_for(socks_key, socks_before)
        time.sleep(0.1)
        dns53_after = sum(n for (_, proto, port), n in capture.counts.items() if proto == 17 and port == 53)
        assert fixtures.socks_domains == [b"fixture.invalid"], fixtures.socks_domains
        assert dns53_after == dns53_before, f"unexpected DNS packets: {dns53_before} -> {dns53_after}"
        print("PASS: socks5h sent the hostname to the local SOCKS proxy without local DNS packets")

        previous = os.environ.get("OSINT_REQUIRE_PROXY")
        os.environ["OSINT_REQUIRE_PROXY"] = "1"
        try:
            from consensus_osint.core.http import Http
            try:
                Http(impersonate=None)
            except ValueError as exc:
                assert "requires an explicit proxy or Tor route" in str(exc)
            else:
                raise AssertionError("strict mode accepted a missing proxy")
        finally:
            if previous is None:
                os.environ.pop("OSINT_REQUIRE_PROXY", None)
            else:
                os.environ["OSINT_REQUIRE_PROXY"] = previous
        print("PASS: OSINT_REQUIRE_PROXY=1 rejects an absent route before network activity")
        asyncio.run(test_strict_network_status())
        print("PASS: strict network-status check skips direct/system-proxy probes")

        failed = Http(proxy="http://127.0.0.1:18083", impersonate=None, http2=False)
        try:
            result = asyncio.run(failed.get("http://fixture.invalid/no-fallback", timeout=1))
            assert result.error, result
        finally:
            asyncio.run(failed.aclose())
        time.sleep(0.1)
        assert capture.counts[origin_key] == origin_before
        print("PASS: unavailable proxy failed closed; no fake-origin fallback packet observed")

        proxy_env = {name: os.environ.get(name) for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy")}
        os.environ.update(HTTP_PROXY=f"http://127.0.0.1:{PROXY_PORT}", NO_PROXY="", no_proxy="")
        os.environ.pop("http_proxy", None)
        os.environ.pop("ALL_PROXY", None)
        os.environ.pop("all_proxy", None)
        before_proxy, before_origin = capture.counts[proxy_key], capture.counts[origin_key]
        client = Http(impersonate=None, http2=False)
        try:
            result = asyncio.run(client.get(f"http://127.0.0.1:{ORIGIN_PORT}/ambient-env", timeout=1))
            assert result.text == "fixture-origin", result
        finally:
            asyncio.run(client.aclose())
            for name, value in proxy_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        time.sleep(0.1)
        assert capture.counts[origin_key] > before_origin
        assert capture.counts[proxy_key] == before_proxy
        print("PASS: HTTPX ignored ambient proxy environment and used the loopback origin directly")

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
        print(f"OBSERVED: local packets by destination port: http-proxy={proxy_after}, socks-proxy={capture.counts[socks_key]}, origin={capture.counts[origin_key]}, fake-dns={capture.counts[dns_key]}")
        print("LIMIT: validates shared Http proxying, socks5h, and missing/unavailable proxy behavior; DNS resolver and other transports remain unaudited")
    finally:
        fixtures.close()
        capture.close()


def main() -> int:
    if os.environ.get("CONSENSUS_EGRESS_IN_NETNS") == "1":
        try:
            inside()
            return 0
        except Exception as exc:
            detail = getattr(exc, "output", b"")
            if isinstance(detail, bytes):
                detail = detail.decode(errors="replace")
            print(f"FAIL: {type(exc).__name__}: {exc}\n{detail}", file=sys.stderr)
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
