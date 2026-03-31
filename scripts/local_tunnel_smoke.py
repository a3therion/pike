#!/usr/bin/env python3
"""Run a local end-to-end smoke test for the Pike relay stack.

This boots:
- a local upstream HTTP + WebSocket echo server
- a local pike-server relay in dev mode with explicit local API keys
- a local pike HTTP tunnel over QUIC only

It then validates:
- platform health checks
- tunneled HTTP forwarding
- concurrent request handling
- tunneled WebSocket upgrades + echo
- authenticated management endpoints
- client reconnect after relay restart
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
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


def reserve_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
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

    def do_GET(self) -> None:  # noqa: N802
        if (
            self.path == "/ws"
            and self.headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in self.headers.get("Connection", "").lower()
        ):
            self.handle_websocket_upgrade()
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

    def do_POST(self) -> None:  # noqa: N802
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
        self.end_headers()
        self.wfile.flush()

        opcode, payload = read_ws_frame(self.connection)
        if opcode != 0x1:
            send_server_ws_frame(self.connection, b"unexpected opcode", opcode=0x8)
            return

        send_server_ws_frame(self.connection, b"echo: " + payload)

    def log_message(self, format: str, *args: object) -> None:
        return


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


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
    handle = log_path.open("w", encoding="utf-8")
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


def write_client_config(path: Path, relay_port: int, inspector_port: int, http_port: int) -> None:
    contents = f"""[auth]
api_key = "{SMOKE_API_KEY}"

[relay]
addr = "127.0.0.1:{relay_port}"
ws_fallback = false
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

    for index in range(request_count):
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

    log(f"validated {request_count} tunneled HTTP requests")


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


def run_websocket_check(http_port: int) -> None:
    host = f"{SUBDOMAIN}.{DOMAIN}"
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET /ws HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
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

        message = b"hello from smoke"
        sock.sendall(encode_ws_frame(message))
        opcode, payload = read_ws_frame(sock)
        if opcode != 0x1:
            raise RuntimeError(f"unexpected websocket opcode: {opcode}")
        if payload != b"echo: " + message:
            raise RuntimeError(f"unexpected websocket echo payload: {payload!r}")

    log("validated tunneled WebSocket echo")


def run_management_checks(management_port: int) -> None:
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


def run_smoke(request_count: int) -> None:
    ensure_binaries()

    relay_port = reserve_free_port()
    http_port = reserve_free_port()
    management_port = reserve_free_port()
    upstream_port = reserve_free_port()
    inspector_port = reserve_free_port()

    with tempfile.TemporaryDirectory(prefix="pike-smoke-") as tmp_dir:
        temp_root = Path(tmp_dir)
        home_dir = temp_root / "home"
        home_dir.mkdir(parents=True, exist_ok=True)

        server_config = temp_root / "server.toml"
        client_config = temp_root / "client.toml"
        server_log_path = temp_root / "pike-server.log"
        cli_log_path = temp_root / "pike.log"

        write_server_config(server_config, relay_port, http_port, management_port)
        write_client_config(client_config, relay_port, inspector_port, http_port)

        upstream = ThreadingHTTPServer(("127.0.0.1", upstream_port), SmokeUpstreamHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        log(f"upstream server listening on 127.0.0.1:{upstream_port}")
        if SMOKE_SKIP_TLS_VERIFY:
            log("using the repo's self-signed dev certificate; peer verification is disabled for this local-only smoke run")

        env = os.environ.copy()
        env["HOME"] = str(home_dir)
        env["RUST_LOG"] = "info"
        env["NO_COLOR"] = "1"

        server_log = ProcessLogger(server_log_path)
        cli_log = ProcessLogger(cli_log_path)

        server_process: subprocess.Popen[str] | None = None
        cli_process: subprocess.Popen[str] | None = None

        try:
            server_process = start_relay(server_config, env, server_log_path)
            wait_for_http(
                f"http://127.0.0.1:{http_port}/health",
                expected_status=200,
                headers={"Host": DOMAIN},
                timeout=30.0,
                process=server_process,
            )
            log("relay HTTP endpoint is healthy")

            cli_process = start_process(
                [
                    str(CLI_BIN),
                    "--config",
                    str(client_config),
                    "http",
                    str(upstream_port),
                    "--subdomain",
                    SUBDOMAIN,
                    "--host",
                    "127.0.0.1",
                    "--max-reconnects",
                    "5",
                ],
                env=env,
                log_path=cli_log_path,
            )

            run_http_checks(http_port, request_count)
            run_login_redirect_check(http_port)
            run_websocket_check(http_port)
            run_management_checks(management_port)

            log("restarting relay to validate reconnect behavior")
            stop_process(server_process, "relay")
            server_process = start_relay(server_config, env, server_log_path)
            wait_for_http(
                f"http://127.0.0.1:{http_port}/health",
                expected_status=200,
                headers={"Host": DOMAIN},
                timeout=30.0,
                process=server_process,
            )
            wait_for_reconnect(http_port, cli_process)

        except Exception:
            server_log.dump("relay")
            cli_log.dump("cli")
            raise
        finally:
            stop_process(cli_process, "cli")
            stop_process(server_process, "relay")
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--request-count",
        type=int,
        default=20,
        help="number of tunneled HTTP requests to issue during the smoke test",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        run_smoke(args.request_count)
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
