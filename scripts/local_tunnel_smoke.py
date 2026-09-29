#!/usr/bin/env python3
"""Exercise the real local Pike stack over QUIC and forced WebSocket fallback.

Checks HTTP forwarding/concurrency, redirects/cookies, upstream WebSocket echo,
TCP server-first/interactive/binary forwarding, both half-close directions,
concurrent TCP clients, port allocation/rejection, management auth, and reconnect.
Only loopback clients, temporary configuration, and the repo's dev TLS keys are used.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import os
import queue
import random
import re
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_BIN = REPO_ROOT / "target" / "debug" / "pike-server"
CLI_BIN = REPO_ROOT / "target" / "debug" / "pike"
TLS_CERT = REPO_ROOT / "config" / "cert.pem"
TLS_KEY = REPO_ROOT / "config" / "key.pem"

SMOKE_API_KEY = "pk_test_smoke_1234"
INTERNAL_TOKEN = "smoke-internal-token"
DOMAIN = "pike.test"
SUBDOMAIN = "smoke"
RELAY_TLS_NAME = "localhost"
SMOKE_SKIP_TLS_VERIFY = True


def log(message: str) -> None:
    print(f"[smoke] {message}", flush=True)


def reserve_free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(sock.getsockname()[1])


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int, bytes, dict[str, str]]:
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (
                response.status,
                response.read(),
                dict(response.headers.items()),
            )
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers.items())


def wait_for_http(
    url: str,
    *,
    expected_status: int,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    interval: float = 0.5,
    process: subprocess.Popen[str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    deadline = time.time() + timeout
    last_result: tuple[int, bytes, dict[str, str]] | None = None
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"process exited early with code {process.returncode}")
        try:
            result = http_get(url, headers=headers, timeout=interval)
            last_result = result
            if result[0] == expected_status:
                return result
        except OSError:
            pass
        time.sleep(interval)

    if last_result is not None:
        raise RuntimeError(
            f"timed out waiting for {url} to return {expected_status}, got {last_result[0]}"
        )
    raise RuntimeError(f"timed out waiting for {url} to become reachable")


def http_post(
    url: str,
    *,
    body: bytes,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int, bytes, dict[str, str]]:
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.request("POST", path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        connection.close()


def get_header(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == target:
            return value
    return None


def encode_ws_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    mask_key = os.urandom(4)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    frame = bytearray()
    frame.append(0x80 | opcode)
    length = len(payload)

    if length < 126:
        frame.append(0x80 | length)
    elif length < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack(">Q", length))

    frame.extend(mask_key)
    frame.extend(masked)
    return bytes(frame)


def read_ws_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 2)
    opcode = header[0] & 0x0F
    masked = (header[1] & 0x80) != 0
    length = header[1] & 0x7F

    if length == 126:
        length = struct.unpack(">H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(sock, 8))[0]

    mask_key = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length)

    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return opcode, payload


def send_server_ws_frame(sock: socket.socket, payload: bytes, opcode: int = 0x1) -> None:
    frame = bytearray()
    frame.append(0x80 | opcode)
    length = len(payload)

    if length < 126:
        frame.append(length)
    elif length < 65536:
        frame.append(126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack(">Q", length))

    frame.extend(payload)
    sock.sendall(frame)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("socket closed while reading frame")
        data.extend(chunk)
    return bytes(data)


class SmokeUpstreamHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass

    def do_GET(self) -> None:  # noqa: N802
        if (
            self.path == "/ws"
            and self.headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in self.headers.get("Connection", "").lower()
        ):
            self.handle_websocket_upgrade()
            return

        if self.path == "/ws-denied":
            self.send_response(403)
            self.send_header("Content-Length", "6")
            self.send_header("X-Rejection", "upstream")
            self.end_headers()
            self.wfile.write(b"denied")
            return
        if self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(32 * 1024 * 1024))
            self.end_headers()
            for _ in range(512):
                self.wfile.write(b"x" * 65536)
            return
        if self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"9\r\ndata: a\n\n\r\n")
            self.wfile.flush()
            time.sleep(3)
            try:
                self.wfile.write(b"9\r\ndata: b\n\n\r\n0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        if self.path == "/demo":
            body = json.dumps(
                {
                    "service": "pike-smoke-upstream",
                    "path": self.path,
                    "method": "GET",
                    "authenticated": True,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = json.dumps(
            {
                "service": "pike-smoke-upstream",
                "path": self.path,
                "method": "GET",
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "33554432")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        if self.path.startswith("/upload/"):
            digest = hashlib.sha256()
            total = 0
            self.server.active_uploads.add(self.path)
            try:
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    while True:
                        line = self.rfile.readline()
                        if not line:
                            return
                        length = int(line.split(b";", 1)[0].strip(), 16)
                        if length == 0:
                            while self.rfile.readline() not in (b"\r\n", b"", b"\n"):
                                pass
                            break
                        remaining = length
                        while remaining:
                            chunk = self.rfile.read(min(remaining, 32768))
                            if not chunk:
                                return
                            digest.update(chunk)
                            total += len(chunk)
                            remaining -= len(chunk)
                            self.server.upload_progress[self.path] = total
                        if self.rfile.read(2) != b"\r\n":
                            return
                else:
                    remaining = int(self.headers.get("Content-Length", "0"))
                    while remaining:
                        chunk = self.rfile.read(min(remaining, 32768))
                        if not chunk:
                            return
                        digest.update(chunk)
                        total += len(chunk)
                        remaining -= len(chunk)
                        self.server.upload_progress[self.path] = total
                body = json.dumps({"bytes": total, "sha256": digest.hexdigest()}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ValueError):
                pass
            finally:
                self.server.active_uploads.discard(self.path)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8", errors="replace")

        if self.path == "/login":
            params = urllib.parse.parse_qs(body)
            if params.get("password") == ["admin123"]:
                self.send_response(302)
                self.send_header("Location", "/demo")
                self.send_header("Set-Cookie", "session=smoke-session; Path=/; HttpOnly")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            response = b"<html><body>Login failed</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            return

        self.send_error(404, "not found")

    def handle_websocket_upgrade(self) -> None:
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            self.send_error(400, "missing websocket key")
            return

        accept_seed = (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
        accept = base64.b64encode(hashlib.sha1(accept_seed).digest()).decode()

        self.send_response_only(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        compressed = "permessage-deflate" in self.headers.get("Sec-WebSocket-Extensions", "")
        if "pike-test" in self.headers.get("Sec-WebSocket-Protocol", ""):
            self.send_header("Sec-WebSocket-Protocol", "pike-test")
        if compressed:
            self.send_header("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
        self.end_headers()
        self.wfile.flush()

        opcode, payload = read_ws_frame(self.connection)
        if opcode != 0x1:
            send_server_ws_frame(self.connection, b"unexpected opcode", opcode=0x8)
            return

        if compressed:
            payload = zlib.decompressobj(wbits=-15).decompress(payload + b"\x00\x00\xff\xff")
            compressor = zlib.compressobj(wbits=-15)
            encoded = compressor.compress(b"echo: " + payload) + compressor.flush(zlib.Z_SYNC_FLUSH)
            encoded = encoded[:-4]
            self.connection.sendall(bytes([0xC1, len(encoded)]) + encoded)
        else:
            send_server_ws_frame(self.connection, b"echo: " + payload)

    def log_message(self, format: str, *args: object) -> None:
        return


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


TCP_GREETING = b"\x00pike-smoke-ready\xff\r\n"
TCP_EOF_ACK = b"\x00upstream-observed-client-FIN\xff"
TCP_HALF_CLOSE_COMMAND = b"pike-smoke-upstream-half-close"
TCP_TUNNEL_DISPLAY = re.compile(r"\bTunnel:?\s+tcp://(\d+)")


class SmokeTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.after_half_close: queue.Queue[bytes] = queue.Queue()
        super().__init__(*args, **kwargs)


class SmokeTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection = self.request
        connection.settimeout(15.0)
        try:
            # Send before receiving even one byte: this needs an empty stream-open.
            connection.sendall(TCP_GREETING)
            while True:
                first = connection.recv(4)
                if not first:
                    # Read EOF must not close the return direction of the tunnel.
                    connection.sendall(TCP_EOF_ACK)
                    connection.shutdown(socket.SHUT_WR)
                    return
                header = first + recv_exact(connection, 4 - len(first))
                size = struct.unpack(">I", header)[0]
                if size > 2 * 1024 * 1024:
                    raise ValueError(f"unexpected TCP smoke frame size {size}")
                payload = recv_exact(connection, size)
                connection.sendall(header + payload)
                if payload == TCP_HALF_CLOSE_COMMAND:
                    connection.shutdown(socket.SHUT_WR)
                    remaining = bytearray()
                    while chunk := connection.recv(16384):
                        remaining.extend(chunk)
                    self.server.after_half_close.put(bytes(remaining))
                    return
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            # Readiness/reconnect probes can race with a relay restart.
            return


def reserve_tcp_pool_port() -> int:
    # macOS may allocate hundreds of consecutive ephemeral ports above 65000.
    # Probe the relay's range directly, below the ephemeral range, using the
    # same wildcard address that the real TCP relay will bind.
    for port in random.sample(range(10000, 49152), 100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            try:
                candidate.bind(("0.0.0.0", port))
                candidate.listen(1)
                return port
            except OSError:
                continue
    raise RuntimeError("could not reserve a TCP port in the relay's allocation range")


def tcp_echo_roundtrip(remote_port: int, index: int, barrier: threading.Barrier | None = None) -> None:
    if barrier is not None:
        barrier.wait(timeout=10.0)
    with socket.create_connection(("127.0.0.1", remote_port), timeout=10.0) as connection:
        if recv_exact(connection, len(TCP_GREETING)) != TCP_GREETING:
            raise RuntimeError("TCP server-first greeting did not arrive intact")
        payloads = [
            b"", b"\x00interactive-" + str(index).encode() + b"\xff\r\n",
            bytes(range(256)) * 1024 + f"connection={index}".encode(),
        ]
        for payload in payloads:
            connection.sendall(struct.pack(">I", len(payload)))
            for offset in range(0, len(payload), 8191):
                connection.sendall(payload[offset:offset + 8191])
            echoed_size = struct.unpack(">I", recv_exact(connection, 4))[0]
            if echoed_size != len(payload) or recv_exact(connection, echoed_size) != payload:
                raise RuntimeError(f"TCP binary echo mismatch on connection {index}")
        # All echoes above must complete while the public client is still writable.
        connection.shutdown(socket.SHUT_WR)
        if recv_exact(connection, len(TCP_EOF_ACK)) != TCP_EOF_ACK:
            raise RuntimeError("client half-close did not reach the upstream")
        if connection.recv(1) != b"":
            raise RuntimeError("upstream EOF did not reach the public TCP client")


def run_tcp_checks(remote_port: int, connections: int, upstream: SmokeTCPServer) -> None:
    tcp_echo_roundtrip(remote_port, 0)
    barrier = threading.Barrier(connections)
    with concurrent.futures.ThreadPoolExecutor(max_workers=connections) as pool:
        futures = [pool.submit(tcp_echo_roundtrip, remote_port, index + 1, barrier) for index in range(connections)]
        for future in futures:
            future.result(timeout=30.0)

    # Independently prove upstream-first FIN preserves the client's write side.
    with socket.create_connection(("127.0.0.1", remote_port), timeout=10.0) as connection:
        if recv_exact(connection, len(TCP_GREETING)) != TCP_GREETING:
            raise RuntimeError("missing server-first greeting for upstream half-close")
        command = struct.pack(">I", len(TCP_HALF_CLOSE_COMMAND)) + TCP_HALF_CLOSE_COMMAND
        connection.sendall(command)
        if recv_exact(connection, len(command)) != command or connection.recv(1) != b"":
            raise RuntimeError("upstream write half-close did not propagate")
        tail = bytes(range(256)) * 256 + b"sent after upstream FIN"
        connection.sendall(tail)
        connection.shutdown(socket.SHUT_WR)
        if upstream.after_half_close.get(timeout=10.0) != tail:
            raise RuntimeError("client data after upstream FIN was truncated or lost")
    log(f"validated TCP server-first, interactive binary echo, both FIN directions, and {connections} concurrent clients")


def start_tcp_client(
    config: Path, local_port: int, remote_port: int | None, env: dict[str, str], log_path: Path,
    max_reconnects: int = 5,
) -> subprocess.Popen[str]:
    command = [str(CLI_BIN), "--config", str(config), "tcp", str(local_port),
               "--max-reconnects", str(max_reconnects)]
    if remote_port is not None:
        command.extend(["--remote-port", str(remote_port)])
    return start_process(command, env=env, log_path=log_path)


def wait_for_tcp_registration(process: subprocess.Popen[str], log_path: Path) -> int:
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"TCP CLI exited before registration (status {process.returncode})")
        if log_path.exists():
            match = TCP_TUNNEL_DISPLAY.search(log_path.read_text(encoding="utf-8", errors="replace"))
            if match:
                port = int(match.group(1))
                if not 10000 <= port <= 65000:
                    raise RuntimeError(f"relay assigned TCP port {port} outside its pool")
                return port
        time.sleep(0.1)
    raise RuntimeError("TCP CLI never confirmed a registered listener")


def run_occupied_port_check(
    config: Path, local_port: int, occupied_port: int, env: dict[str, str], log_path: Path
) -> None:
    process = start_tcp_client(config, local_port, occupied_port, env, log_path, max_reconnects=0)
    try:
        exit_code = process.wait(timeout=20.0)
        output = log_path.read_text(encoding="utf-8", errors="replace")
        if exit_code == 0:
            raise RuntimeError(f"occupied TCP port {occupied_port} reported a successful exit")
        if "TCP tunnel registration confirmed" in output or TCP_TUNNEL_DISPLAY.search(output):
            raise RuntimeError(f"occupied TCP port {occupied_port} was reported as registered")
        if "registration" not in output.lower():
            raise RuntimeError(f"occupied-port check failed before registration: {output}")
        log(f"validated rejection of occupied TCP port {occupied_port}")
    finally:
        stop_process(process, "occupied-port TCP cli")


def wait_for_tcp_reconnect(remote_port: int, process: subprocess.Popen[str]) -> None:
    started = time.monotonic()
    # macOS wildcard binds without address reuse can wait for TCP TIME_WAIT.
    # Measure that delay instead of exhausting the fixture's short retry cap.
    deadline = started + (120.0 if sys.platform == "darwin" else 45.0)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"TCP CLI exited during reconnect (status {process.returncode})")
        try:
            tcp_echo_roundtrip(remote_port, -1)
            log(f"validated TCP reconnect after relay restart with binary echo and FIN in {time.monotonic() - started:.3f}s")
            return
        except (OSError, ConnectionError) as error:
            last_error = error
            time.sleep(0.5)
    raise RuntimeError(f"TCP tunnel did not recover after relay restart: {last_error}")


class ProcessLogger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def dump(self, title: str) -> None:
        if not self.path.exists():
            return
        log(f"{title} log from {self.path}:")
        content = self.path.read_text(encoding="utf-8", errors="replace").strip()
        if content:
            print(content, flush=True)


def start_process(
    command: list[str],
    *,
    env: dict[str, str],
    log_path: Path,
    cwd: Path = REPO_ROOT,
) -> subprocess.Popen[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        return subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
        )


def ensure_binaries() -> None:
    if SERVER_BIN.exists() and CLI_BIN.exists():
        return

    log("building pike-server and pike debug binaries")
    subprocess.run(
        ["cargo", "build", "-p", "pike-server", "-p", "pike"],
        cwd=REPO_ROOT,
        check=True,
    )


def write_server_config(path: Path, relay_port: int, http_port: int, management_port: int) -> None:
    contents = f"""bind_addr = "127.0.0.1:{relay_port}"
http_bind_addr = "127.0.0.1:{http_port}"
management_bind_addr = "127.0.0.1:{management_port}"
internal_token = "{INTERNAL_TOKEN}"
local_api_keys = ["{SMOKE_API_KEY}"]
domain = "{DOMAIN}"

[quic]
idle_timeout_ms = 60000
max_concurrent_streams = 100
congestion_control = "bbr2"
enable_early_data = true
enable_dgram = true
cert_path = "{TLS_CERT.as_posix()}"
key_path = "{TLS_KEY.as_posix()}"
"""
    path.write_text(contents, encoding="utf-8")


def write_client_config(
    path: Path, relay_port: int, inspector_port: int, http_port: int, transport: str
) -> None:
    contents = f"""[auth]
api_key = "{SMOKE_API_KEY}"

[relay]
addr = "127.0.0.1:{relay_port}"
ws_fallback = {"true" if transport == "websocket" else "false"}
ws_url = "ws://127.0.0.1:{http_port}/ws/tunnel"
connect_timeout_ms = 500
quic_timeout_ms = 60000
api_url = "http://127.0.0.1:{http_port}"
tls_server_name = "{RELAY_TLS_NAME}"
insecure_skip_tls_verify = {"true" if SMOKE_SKIP_TLS_VERIFY else "false"}

[tunnel]
subdomain_prefix = ""
bind_addr = "127.0.0.1"

[inspector]
port = {inspector_port}
enabled = false
max_requests = 100

[advanced]
log_level = "info"
zero_rtt = true
heartbeat_interval = 15
"""
    path.write_text(contents, encoding="utf-8")


def run_http_checks(http_port: int, request_count: int) -> None:
    host = f"{SUBDOMAIN}.{DOMAIN}"
    headers = {"Host": host}

    status, body, _ = wait_for_http(
        f"http://127.0.0.1:{http_port}/smoke?attempt=initial",
        expected_status=200,
        headers=headers,
        timeout=30.0,
    )
    if status != 200:
        raise RuntimeError(f"expected tunneled request to succeed, got {status}")

    response = json.loads(body.decode())
    if response.get("service") != "pike-smoke-upstream":
        raise RuntimeError(f"unexpected tunneled response: {response!r}")

    log("validated initial tunneled HTTP request")

    def check_request(index: int) -> None:
        status, body, _ = http_get(
            f"http://127.0.0.1:{http_port}/smoke?attempt={index}",
            headers=headers,
            timeout=5.0,
        )
        if status != 200:
            raise RuntimeError(f"HTTP smoke request {index} failed with status {status}")
        response = json.loads(body.decode())
        if response.get("path") != f"/smoke?attempt={index}":
            raise RuntimeError(f"unexpected response path for request {index}: {response!r}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, request_count)) as pool:
        list(pool.map(check_request, range(request_count)))
    log(f"validated {request_count} tunneled HTTP requests with up to 8 concurrent clients")


def run_login_redirect_check(http_port: int) -> None:
    host = f"{SUBDOMAIN}.{DOMAIN}"
    status, _, headers = http_post(
        f"http://127.0.0.1:{http_port}/login",
        headers={
            "Host": host,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"https://{host}",
        },
        body=b"password=admin123",
        timeout=5.0,
    )

    if status != 302:
        raise RuntimeError(f"expected login POST to return 302, got {status}")
    location = get_header(headers, "Location")
    if location != "/demo":
        raise RuntimeError(f"expected login redirect to /demo, got {location!r}")

    set_cookie = get_header(headers, "Set-Cookie") or ""
    if "session=smoke-session" not in set_cookie:
        raise RuntimeError("expected login response to preserve Set-Cookie header")

    log("validated tunneled login redirect and session cookie preservation")


def run_websocket_check(http_port: int, negotiated: bool = False) -> None:
    host = f"{SUBDOMAIN}.{DOMAIN}"
    key = base64.b64encode(os.urandom(16)).decode()
    extra = "Sec-WebSocket-Protocol: pike-test, other\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover\r\n" if negotiated else ""
    request = (
        f"GET /ws HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"{extra}\r\n"
    ).encode()

    with socket.create_connection(("127.0.0.1", http_port), timeout=5) as sock:
        sock.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                raise RuntimeError("websocket handshake closed unexpectedly")
            response.extend(chunk)

        if b"101 Switching Protocols" not in response:
            raise RuntimeError(f"websocket upgrade failed: {response.decode(errors='replace')}")

        expected_accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        if expected_accept not in response:
            raise RuntimeError("upstream WebSocket accept was not preserved")
        if negotiated and (b"sec-websocket-protocol: pike-test" not in response.lower() or b"permessage-deflate" not in response):
            raise RuntimeError("upstream subprotocol/compression negotiation was lost")
        message = b"hello from smoke"
        if negotiated:
            compressor = zlib.compressobj(wbits=-15)
            encoded = (compressor.compress(message) + compressor.flush(zlib.Z_SYNC_FLUSH))[:-4]
            frame = bytearray(encode_ws_frame(encoded)); frame[0] |= 0x40
            sock.sendall(frame)
        else:
            sock.sendall(encode_ws_frame(message))
        opcode, payload = read_ws_frame(sock)
        if opcode != 0x1:
            raise RuntimeError(f"unexpected websocket opcode: {opcode}")
        if negotiated:
            payload = zlib.decompressobj(wbits=-15).decompress(payload + b"\x00\x00\xff\xff")
        if payload != b"echo: " + message:
            raise RuntimeError(f"unexpected websocket echo payload: {payload!r}")

    log("validated tunneled WebSocket echo" + (" with real subprotocol/compressed frames" if negotiated else ""))


def run_streaming_checks(http_port: int) -> None:
    headers = {"Host": f"{SUBDOMAIN}.{DOMAIN}"}
    status, body, _ = http_get(f"http://127.0.0.1:{http_port}/large", headers=headers, timeout=20)
    if status != 200 or len(body) != 32 * 1024 * 1024 or hashlib.sha256(body).digest() != hashlib.sha256(b"x" * len(body)).digest():
        raise RuntimeError(f"large response failed: {status}, {len(body)} bytes")
    connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
    connection.request("HEAD", "/large", headers=headers)
    response = connection.getresponse()
    if response.status != 200 or response.read() != b"" or response.getheader("Content-Length") != "33554432":
        raise RuntimeError("HEAD framing failed")
    connection.close()
    connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
    start = time.monotonic()
    connection.request("GET", "/events", headers=headers)
    response = connection.getresponse()
    event = response.read(9)
    elapsed = time.monotonic() - start
    if event != b"data: a\n\n" or elapsed >= 2:
        raise RuntimeError(f"SSE was buffered until EOF: {elapsed:.2f}s, {event!r}")
    connection.close()
    headers.update({"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(), "Sec-WebSocket-Version": "13"})
    status, body, returned = http_get(f"http://127.0.0.1:{http_port}/ws-denied", headers=headers)
    if status != 403 or body != b"denied" or get_header(returned, "X-Rejection") != "upstream":
        raise RuntimeError(f"WebSocket rejection was not preserved: {status}, {body!r}")
    run_websocket_check(http_port, negotiated=True)
    log(f"validated 32 MiB download, HEAD, SSE first event in {elapsed:.3f}s, and upstream WS rejection")



def run_upload_checks(http_port: int, upstream, processes, transport: str) -> None:
    limit = 200_000_000
    block = bytes(range(256)) * 256
    headers = {"Host": f"{SUBDOMAIN}.{DOMAIN}"}
    measurements = []
    def resident_kib():
        result = subprocess.check_output(["ps", "-o", "rss=", "-p", ",".join(str(p.pid) for p in processes)], text=True)
        return sum(int(value) for value in result.split())
    for chunked in (False, True):
        for extra in (0, 1):
            total = limit + extra
            label = f"{transport}-{'chunked' if chunked else 'length'}-{total}"
            path = f"/upload/{label}"
            connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=90)
            connection.putrequest("POST", path, skip_host=True)
            connection.putheader("Host", headers["Host"])
            connection.putheader("Content-Type", "application/octet-stream")
            connection.putheader("Transfer-Encoding" if chunked else "Content-Length", "chunked" if chunked else str(total))
            baseline = resident_kib()
            peak = [baseline]
            stop = threading.Event()
            def sample():
                while not stop.wait(0.1):
                    peak[0] = max(peak[0], resident_kib())
            sampler = threading.Thread(target=sample, daemon=True)
            sampler.start()
            start = time.monotonic()
            connection.endheaders()
            digest = hashlib.sha256()
            sent = 0
            streamed_early = False
            try:
                if not (extra and not chunked):
                    while sent < total:
                        chunk = block[:min(len(block), total - sent)]
                        connection.send(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n" if chunked else chunk)
                        digest.update(chunk)
                        sent += len(chunk)
                        if sent == len(block):
                            deadline = time.monotonic() + 5
                            while upstream.upload_progress.get(path, 0) == 0 and time.monotonic() < deadline:
                                time.sleep(0.01)
                            if upstream.upload_progress.get(path, 0) == 0:
                                raise RuntimeError(f"{label}: origin received no bytes until upload completion")
                            streamed_early = True
                            status, _, _ = http_get(f"http://127.0.0.1:{http_port}/parallel", headers=headers, timeout=3)
                            if status != 200:
                                raise RuntimeError("paused upload blocked another request")
                    if chunked:
                        connection.send(b"0\r\n\r\n")
                response = connection.getresponse()
                data = response.read()
                expected = 413 if extra else 200
                if response.status != expected:
                    raise RuntimeError(f"{label}: expected {expected}, received {response.status}: {data[:300]!r}")
                if not extra:
                    result = json.loads(data)
                    if result != {"bytes": total, "sha256": digest.hexdigest()}:
                        raise RuntimeError(f"{label}: upload length or binary SHA-256 mismatch: {result}")
                if extra and not chunked and path in upstream.upload_progress:
                    raise RuntimeError("oversized Content-Length reached origin")
                growth = max(0, peak[0] - baseline) * 1024
                if growth >= 100_000_000:
                    raise RuntimeError(f"{label}: combined relay/client RSS grew by {growth} bytes")
                measurements.append({"case": label, "status": response.status, "bytes_sent": sent,
                    "origin_received_early": streamed_early, "elapsed_seconds": round(time.monotonic() - start, 3),
                    "combined_peak_rss_bytes": peak[0] * 1024, "rss_growth_bytes": growth})
                log(f"validated {label}: status={response.status}, peak RSS growth={growth}, seconds={measurements[-1]['elapsed_seconds']}")
            finally:
                connection.close()
                stop.set()
                sampler.join(timeout=2)
    # Cancellation must release the origin connection, not wait for a body timeout.
    path = f"/upload/{transport}-cancelled"
    connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
    connection.putrequest("POST", path, skip_host=True)
    connection.putheader("Host", headers["Host"])
    connection.putheader("Content-Length", str(limit))
    connection.endheaders()
    connection.send(block)
    deadline = time.monotonic() + 3
    while not upstream.upload_progress.get(path) and time.monotonic() < deadline:
        time.sleep(0.01)
    if not upstream.upload_progress.get(path):
        raise RuntimeError("cancel fixture did not reach origin")
    connection.close()
    deadline = time.monotonic() + 3
    while path in upstream.active_uploads and time.monotonic() < deadline:
        time.sleep(0.01)
    if path in upstream.active_uploads:
        raise RuntimeError("cancelled upload left origin socket open")
    status, _, _ = http_get(f"http://127.0.0.1:{http_port}/after-cancel", headers=headers)
    if status != 200:
        raise RuntimeError("cancellation damaged the tunnel")
    log("validated cancelled upload closes origin and next request succeeds")
    # An overload response must not reopen the rejected stream on late data.
    held = []
    try:
        for index in range(32):
            path = f"/upload/{transport}-held-{index}"
            connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
            held.append(connection)
            connection.putrequest("POST", path, skip_host=True)
            connection.putheader("Host", headers["Host"])
            connection.putheader("Content-Length", str(limit))
            connection.endheaders()
            connection.send(block)
            deadline = time.monotonic() + 3
            while not upstream.upload_progress.get(path) and time.monotonic() < deadline:
                time.sleep(0.01)
            if not upstream.upload_progress.get(path):
                raise RuntimeError(f"origin concurrency fixture {index} did not start")
        status, _, _ = http_get(f"http://127.0.0.1:{http_port}/overloaded", headers=headers)
        if status != 503:
            raise RuntimeError(f"expected concurrency 503, received {status}")
    finally:
        for connection in held:
            connection.close()
    deadline = time.monotonic() + 3
    while upstream.active_uploads and time.monotonic() < deadline:
        time.sleep(0.01)
    if upstream.active_uploads:
        raise RuntimeError("cancelled concurrent origins did not close")
    status, _, _ = http_get(f"http://127.0.0.1:{http_port}/after-overload", headers=headers)
    if status != 200:
        raise RuntimeError("origin overload damaged the shared tunnel")
    log("validated 32 concurrent uploads, isolated 503 rejection, and recovery")
    evidence = REPO_ROOT.parent / "reports" / "feature-delivery-2026-09-20"
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / f"uploads-{transport}.json").write_text(json.dumps(measurements, indent=2) + "\n")

def open_tunnel_websocket(http_port: int) -> tuple[socket.socket, int]:
    connection = socket.create_connection(("127.0.0.1", http_port), timeout=3.0)
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        request = (f"GET /ws/tunnel HTTP/1.1\r\nHost: {DOMAIN}\r\n"
                   f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        connection.sendall(request.encode())
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(recv_exact(connection, 1))
            if len(response) > 16384:
                raise RuntimeError("oversized WebSocket handshake response")
        status = int(response.split(b" ", 2)[1])
        return connection, status
    except Exception:
        connection.close()
        raise


def run_prelogin_websocket_checks(http_port: int) -> None:
    pending: list[socket.socket] = []
    try:
        for _ in range(9):
            connection, status = open_tunnel_websocket(http_port)
            if status == 503:
                connection.close()
                break
            if status != 101:
                connection.close()
                raise RuntimeError(f"unexpected pre-login WebSocket status {status}")
            pending.append(connection)
        else:
            raise RuntimeError("more than 8 unauthenticated WebSockets were accepted")
        if not pending:
            raise RuntimeError("no pre-login WebSockets could be opened")
    finally:
        for connection in pending:
            connection.close()

    # Teardown must release the login capacity, then data-before-login must close.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        connection, status = open_tunnel_websocket(http_port)
        if status == 101:
            break
        connection.close()
        time.sleep(0.1)
    else:
        raise RuntimeError("pre-login WebSocket permits were not released")
    with connection:
        connection.sendall(encode_ws_frame(b"\x01" + bytes(8192), opcode=0x2))
        try:
            opcode, _ = read_ws_frame(connection)
        except ConnectionError:
            pass
        else:
            if opcode != 0x8:
                raise RuntimeError("unauthenticated tunnel data was not rejected")
    log("validated pre-login WebSocket connection cap, permit release, and data rejection")


def run_management_checks(management_port: int, expect_peer_address: bool = False) -> None:
    unauthorized, _, _ = http_get(
        f"http://127.0.0.1:{management_port}/metrics",
        timeout=5.0,
    )
    if unauthorized != 401:
        raise RuntimeError(f"expected unauthorized metrics access to return 401, got {unauthorized}")

    status, body, _ = http_get(
        f"http://127.0.0.1:{management_port}/metrics",
        headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"},
        timeout=5.0,
    )
    if status != 200:
        raise RuntimeError(f"expected authorized metrics access to return 200, got {status}")
    if "pike_active_connections" not in body.decode():
        raise RuntimeError("metrics output did not contain expected Prometheus metric")

    stats_status, stats_body, _ = http_get(
        f"http://127.0.0.1:{management_port}/api/stats",
        headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"},
        timeout=5.0,
    )
    if stats_status != 200:
        raise RuntimeError(f"expected /api/stats to return 200, got {stats_status}")
    stats = json.loads(stats_body.decode())
    if int(stats.get("total_connections", 0)) < 1:
        raise RuntimeError(f"expected at least one active connection in stats, got {stats!r}")

    if expect_peer_address:
        status, body, _ = http_get(
            f"http://127.0.0.1:{management_port}/api/connections",
            headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"},
        )
        connections = json.loads(body).get("connections", []) if status == 200 else []
        active = [connection for connection in connections if connection.get("tunnels")]
        if not active or any(not connection.get("client_addr", "").startswith("127.0.0.1:") for connection in active):
            raise RuntimeError(f"WebSocket peer address was lost: {connections!r}")
    log("validated authenticated management endpoints")


def wait_for_reconnect(http_port: int, cli_process: subprocess.Popen[str]) -> None:
    host = f"{SUBDOMAIN}.{DOMAIN}"
    deadline = time.time() + 45.0
    while time.time() < deadline:
        if cli_process.poll() is not None:
            raise RuntimeError(f"cli exited during reconnect with code {cli_process.returncode}")
        try:
            status, body, _ = http_get(
                f"http://127.0.0.1:{http_port}/smoke?attempt=reconnect",
                headers={"Host": host},
                timeout=2.0,
            )
            if status == 200:
                response = json.loads(body.decode())
                if response.get("service") == "pike-smoke-upstream":
                    log("validated client reconnect after relay restart")
                    return
        except OSError:
            pass
        time.sleep(1.0)

    raise RuntimeError("timed out waiting for tunnel to recover after relay restart")


def stop_process(process: subprocess.Popen[str] | None, name: str) -> None:
    if process is None or process.poll() is not None:
        return

    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        log(f"{name} did not exit after SIGTERM; sending SIGKILL")
        process.kill()
        process.wait(timeout=5)


def start_relay(
    server_config: Path,
    env: dict[str, str],
    log_path: Path,
) -> subprocess.Popen[str]:
    return start_process(
        [str(SERVER_BIN), "--config", str(server_config), "--dev-mode"],
        env=env,
        log_path=log_path,
    )


def run_smoke(request_count: int, tcp_connections: int, transport: str) -> None:
    log(f"starting {transport} transport checks")
    relay_port = reserve_free_port(socket.SOCK_DGRAM)
    http_port = reserve_free_port()
    management_port = reserve_free_port()
    while management_port == http_port:
        management_port = reserve_free_port()
    inspector_port = reserve_free_port()

    # A bound, unread UDP socket deterministically blackholes QUIC handshakes.
    # Therefore successful traffic in this case must use the configured WS endpoint.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unused_udp:
        unused_udp.bind(("127.0.0.1", 0))
        if unused_udp.getsockname()[1] == relay_port:
            relay_port = reserve_free_port(socket.SOCK_DGRAM)
        client_relay_port = int(unused_udp.getsockname()[1]) if transport == "websocket" else relay_port
        with tempfile.TemporaryDirectory(prefix=f"pike-smoke-{transport}-") as tmp_dir:
            temp_root = Path(tmp_dir)
            server_config = temp_root / "server.toml"
            client_config = temp_root / "client.toml"
            server_log_path = temp_root / "pike-server.log"
            cli_log_path = temp_root / "pike-http.log"
            tcp_log_path = temp_root / "pike-tcp.log"
            write_server_config(server_config, relay_port, http_port, management_port)
            write_client_config(client_config, client_relay_port, inspector_port, http_port, transport)

            upstream = ThreadingHTTPServer(("127.0.0.1", 0), SmokeUpstreamHandler)
            upstream.upload_progress = {}
            upstream.active_uploads = set()
            tcp_upstream = SmokeTCPServer(("127.0.0.1", 0), SmokeTCPHandler)
            upstream_port = int(upstream.server_address[1])
            tcp_upstream_port = int(tcp_upstream.server_address[1])
            upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            tcp_thread = threading.Thread(target=tcp_upstream.serve_forever, daemon=True)
            upstream_thread.start()
            tcp_thread.start()
            log(f"upstream HTTP={upstream_port}, TCP={tcp_upstream_port}; relay transport={transport}")
            if SMOKE_SKIP_TLS_VERIFY:
                log("using the repo's self-signed dev certificate for this local-only run")

            env = os.environ.copy()
            env["RUST_LOG"] = os.environ.get("RUST_LOG", "info")
            env["NO_COLOR"] = "1"
            processes: list[tuple[subprocess.Popen[str], str]] = []
            logs = [server_log_path, cli_log_path, tcp_log_path]
            server_process: subprocess.Popen[str] | None = None
            try:
                server_process = start_relay(server_config, env, server_log_path)
                wait_for_http(
                    f"http://127.0.0.1:{http_port}/health", expected_status=200,
                    headers={"Host": DOMAIN}, timeout=30.0, process=server_process,
                )
                log("relay HTTP endpoint is healthy")
                cli_process = start_process(
                    [str(CLI_BIN), "--config", str(client_config), "http", str(upstream_port),
                     "--subdomain", SUBDOMAIN, "--host", "127.0.0.1", "--max-reconnects", "5"],
                    env=env, log_path=cli_log_path,
                )
                processes.append((cli_process, "HTTP cli"))
                run_http_checks(http_port, request_count)
                run_login_redirect_check(http_port)
                run_streaming_checks(http_port)
                run_upload_checks(http_port, upstream, [server_process, cli_process], transport)
                run_websocket_check(http_port)
                if transport == "websocket":
                    run_prelogin_websocket_checks(http_port)
                run_management_checks(management_port, expect_peer_address=transport == "websocket")

                remote_port = reserve_tcp_pool_port()
                tcp_process = start_tcp_client(client_config, tcp_upstream_port, remote_port, env, tcp_log_path,
                                               max_reconnects=10 if sys.platform == "darwin" else 5)
                processes.append((tcp_process, "TCP cli"))
                assigned_port = wait_for_tcp_registration(tcp_process, tcp_log_path)
                if assigned_port != remote_port:
                    raise RuntimeError(f"explicit TCP port changed: requested {remote_port}, got {assigned_port}")
                run_tcp_checks(remote_port, tcp_connections, tcp_upstream)

                # Test pool-assigned ports separately from the explicit-port tunnel.
                auto_log = temp_root / "pike-tcp-auto.log"
                logs.append(auto_log)
                auto_process = start_tcp_client(client_config, tcp_upstream_port, None, env, auto_log)
                processes.append((auto_process, "auto-port TCP cli"))
                auto_port = wait_for_tcp_registration(auto_process, auto_log)
                if auto_port == remote_port:
                    raise RuntimeError("automatic TCP allocation reused the active explicit port")
                tcp_echo_roundtrip(auto_port, 100)
                stop_process(auto_process, "auto-port TCP cli")
                log("validated automatic TCP port allocation with real traffic")

                # Both an OS listener and an existing tunnel must reject an explicit port.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
                    # A loopback-specific listener must block the relay's
                    # wildcard allocation too, including on macOS.
                    occupied.bind(("127.0.0.1", reserve_tcp_pool_port()))
                    occupied.listen(1)
                    for label, port in (("os-listener", int(occupied.getsockname()[1])), ("active-tunnel", remote_port)):
                        failure_log = temp_root / f"pike-tcp-occupied-{label}.log"
                        logs.append(failure_log)
                        run_occupied_port_check(client_config, tcp_upstream_port, port, env, failure_log)
                tcp_echo_roundtrip(remote_port, 101)

                log("restarting relay to validate HTTP and TCP reconnect behavior")
                stop_process(server_process, "relay")
                server_process = start_relay(server_config, env, server_log_path)
                wait_for_http(
                    f"http://127.0.0.1:{http_port}/health", expected_status=200,
                    headers={"Host": DOMAIN}, timeout=30.0, process=server_process,
                )
                wait_for_reconnect(http_port, cli_process)
                wait_for_tcp_reconnect(remote_port, tcp_process)
                run_tcp_checks(remote_port, tcp_connections, tcp_upstream)
                run_login_redirect_check(http_port)
                run_websocket_check(http_port)
            except Exception:
                for path in logs:
                    ProcessLogger(path).dump(path.stem)
                raise
            finally:
                for process, name in reversed(processes):
                    stop_process(process, name)
                stop_process(server_process, "relay")
                upstream.shutdown()
                tcp_upstream.shutdown()
                upstream.server_close()
                tcp_upstream.server_close()
                upstream_thread.join(timeout=5)
                tcp_thread.join(timeout=5)
    log(f"PASS {transport}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--request-count",
        type=int,
        default=20,
        help="number of tunneled HTTP requests to issue during the smoke test",
    )
    parser.add_argument("--transport", choices=("both", "quic", "websocket"), default="both",
                        help="transport to verify (default: both; websocket forces QUIC failure)")
    parser.add_argument("--tcp-connections", type=int, default=8,
                        help="number of simultaneous TCP clients (default: 8)")
    args = parser.parse_args()
    if args.request_count < 1 or args.tcp_connections < 1:
        parser.error("request and connection counts must be positive")
    return args


def main() -> int:
    args = parse_args()
    try:
        ensure_binaries()
        transports = ("quic", "websocket") if args.transport == "both" else (args.transport,)
        for transport in transports:
            run_smoke(args.request_count, args.tcp_connections, transport)
    except subprocess.CalledProcessError as error:
        log(f"command failed with exit code {error.returncode}: {error.cmd}")
        return error.returncode or 1
    except KeyboardInterrupt:
        log("interrupted")
        return 130
    except Exception as error:  # pragma: no cover - exercised by real smoke failures
        log(f"FAILED: {error}")
        return 1

    log("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
