#!/usr/bin/env python3
"""Independent OpenSSL/Python TLS clients against real Pike CLI and relay processes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time

import local_tunnel_smoke as fixture


def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True)


def certificate(root, name, stem, ca, key=None):
    key = key or root / (stem + '.key')
    if not key.exists():
        openssl('genrsa', '-out', key, '2048')
    csr, cert, ext = [root / (stem + suffix) for suffix in ('.csr', '.pem', '.ext')]
    openssl('req', '-new', '-key', key, '-out', csr, '-subj', '/CN=' + name)
    ext.write_text('subjectAltName=DNS:' + name + '\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
    openssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', root / 'ca.key',
            '-CAcreateserial', '-days', '1', '-extfile', ext, '-out', cert)
    return cert, key


class Origin:
    def __init__(self, label, cert=None, key=None):
        self.label, self.stopped = label, threading.Event()
        self.active = set()
        self.lock = threading.Lock()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(64)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.context = None
        if cert:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(cert, key)
            self.context.set_alpn_protocols(['echo/1'])
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.serve, args=(connection,), daemon=True).start()

    def serve(self, connection):
        # Longer than the connector heartbeat budget so a frozen-relay test
        # measures connector cleanup, rather than this fixture's own timeout.
        connection.settimeout(60)
        try:
            if self.context:
                connection = self.context.wrap_socket(connection, server_side=True)
            with self.lock:
                self.active.add(connection)
            connection.sendall(self.label)
            while data := connection.recv(16384):
                connection.sendall(data)
        except (OSError, ssl.SSLError):
            pass
        finally:
            with self.lock:
                self.active.discard(connection)
            connection.close()

    def count(self):
        with self.lock:
            return len(self.active)

    def close(self):
        self.stopped.set()
        self.thread.join(2)
        self.listener.close()
        with self.lock:
            for connection in list(self.active):
                connection.close()


def wait_for(fn, description, seconds=30):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            value = fn()
            if value:
                return value
        except (OSError, AssertionError) as error:
            last = error
        time.sleep(0.1)
    raise AssertionError(description) from last


def receive(sock, length):
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        assert chunk, 'unexpected EOF'
        result.extend(chunk)
    return bytes(result)


def connected(context, port, name):
    sock = socket.create_connection(('127.0.0.1', port), timeout=4)
    try:
        return context.wrap_socket(sock, server_hostname=name)
    except Exception:
        sock.close()
        raise


def exchange(context, port, name, label):
    with connected(context, port, name) as sock:
        assert receive(sock, len(label)) == label
        payload = os.urandom(96 * 1024)
        sock.sendall(payload)
        assert receive(sock, len(payload)) == payload
        return hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest(), sock.selected_alpn_protocol()


def rejected(fn):
    try:
        connection = fn()
    except (OSError, ssl.SSLError):
        return
    connection.close()
    raise AssertionError('TLS connection unexpectedly accepted')


def fragmented(context, port, name):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_hostname=name)
    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
        first = True
        while True:
            done = False
            try:
                client.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                pass
            data = outgoing.read()
            if first:
                # Force ClientHello to arrive in multiple TCP reads.
                for offset in range(0, len(data), 13):
                    sock.sendall(data[offset:offset + 13])
                    time.sleep(0.001)
                first = False
            else:
                sock.sendall(data)
            if done:
                assert client.selected_alpn_protocol() == 'echo/1'
                return
            data = sock.recv(16384)
            assert data
            incoming.write(data)


def run(transport):
    checks, processes, logs, origins = [], [], [], []
    env = dict(os.environ, NO_COLOR='1', RUST_LOG=os.environ.get('RUST_LOG', 'info'))
    with tempfile.TemporaryDirectory(prefix='pike-tls-' + transport + '-') as folder:
        root = Path(folder)
        ca = root / 'ca.pem'
        ca_config = root / 'ca.cnf'
        ca_config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=Pike local TLS fixture CA\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
        openssl('req', '-config', ca_config, '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-keyout', root / 'ca.key', '-out', ca, '-subj', '/CN=Pike local TLS fixture CA')
        pass_cert, pass_key = certificate(root, 'pass.pike.test', 'pass', ca)
        term_cert, term_key = certificate(root, 'term.pike.test', 'term', ca)
        tls_origin, plain_origin = Origin(b'P', pass_cert, pass_key), Origin(b'T')
        origins.extend([tls_origin, plain_origin])
        context = ssl.create_default_context(cafile=ca)
        context.set_alpn_protocols(['echo/1'])
        http_port, tls_port = fixture.reserve_free_port(), fixture.reserve_free_port()
        relay_port, management = fixture.reserve_free_port(socket.SOCK_DGRAM), fixture.reserve_free_port()
        blackhole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blackhole.bind(('127.0.0.1', 0))
        server_config, client_config = root / 'server.toml', root / 'client.toml'
        fixture.write_server_config(server_config, relay_port, http_port, management)
        owner = 'local-' + hashlib.sha256(fixture.SMOKE_API_KEY.encode()).hexdigest()
        server_config.write_text(server_config.read_text().replace(
            'local_api_keys = ["' + fixture.SMOKE_API_KEY + '"]',
            'local_api_keys = ["' + fixture.SMOKE_API_KEY + '", "pk_other_tls_fixture"]') + f'''
[public_tls]
bind_addr = "127.0.0.1:{tls_port}"
[[public_tls.certificates]]
hostname = "term.pike.test"
owner_user_id = "{owner}"
cert_path = "{term_cert}"
key_path = "{term_key}"
''')
        fixture.write_client_config(client_config, blackhole.getsockname()[1] if transport == 'websocket' else relay_port,
                                    fixture.reserve_free_port(), http_port, transport)
        relay_log = root / 'relay.log'
        logs.append(relay_log)
        relay = None

        def launch(name, origin, mode, config=client_config, retries=5):
            path = root / f'{name}-{mode}-{len(processes)}.log'
            process = fixture.start_process([str(fixture.CLI_BIN), '--config', str(config), 'tls', str(origin.port),
                        '--subdomain', name, '--mode', mode, '--max-reconnects', str(retries)], env=env, log_path=path)
            processes.append(process)
            logs.append(path)
            return process, path

        try:
            relay = fixture.start_relay(server_config, env, relay_log)
            fixture.wait_for_http(f'http://127.0.0.1:{http_port}/health', expected_status=200,
                                 headers={'Host': fixture.DOMAIN}, timeout=30, process=relay)
            other = root / 'other.toml'
            other.write_text(client_config.read_text().replace(fixture.SMOKE_API_KEY, 'pk_other_tls_fixture'))
            for mode in ['passthrough', 'terminate']:
                process, path = launch('term', plain_origin, mode, config=other, retries=0)
                process.wait(timeout=20)
                assert 'TLS endpoint:' not in path.read_text(), path.read_text()
                assert 'another account' in path.read_text(), path.read_text()
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('certificate hostname ownership rejects another account in both TLS modes')
            passthrough, pass_log = launch('pass', tls_origin, 'passthrough')
            terminated, _ = launch('term', plain_origin, 'terminate')
            _, wrong_log = launch('wrong', tls_origin, 'passthrough')
            pass_fp, alpn = wait_for(lambda: exchange(context, tls_port, 'pass.pike.test', b'P'), 'passthrough')
            assert alpn == 'echo/1'
            expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pass_cert.read_text())).hexdigest()
            assert pass_fp == expected
            term_fp, _ = wait_for(lambda: exchange(context, tls_port, 'term.pike.test', b'T'), 'termination')
            assert term_fp != pass_fp
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('shared-port SNI routing preserves 96 KiB binary payloads and presents origin/relay certificates correctly')
            with ThreadPoolExecutor(max_workers=12) as pool:
                results = [pool.submit(exchange, context, tls_port, name, label) for name, label in
                           [('pass.pike.test', b'P'), ('term.pike.test', b'T')] * 6]
                for result in results:
                    result.result()
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('12 concurrent TLS clients remain isolated between passthrough and terminated origins')
            fragmented(context, tls_port, 'pass.pike.test')
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('fragmented ClientHello and passthrough ALPN negotiate with an independent TLS origin')
            rejected(lambda: connected(ssl.create_default_context(), tls_port, 'term.pike.test'))
            wait_for(lambda: 'wrong.pike.test' in wrong_log.read_text(), 'wrong-name route registration')
            rejected(lambda: connected(context, tls_port, 'wrong.pike.test'))
            rejected(lambda: connected(context, tls_port, 'unknown.pike.test'))
            no_sni = ssl.create_default_context(cafile=ca)
            no_sni.check_hostname = False
            rejected(lambda: connected(no_sni, tls_port, None))
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('clients reject untrusted CA and wrong certificate name; relay rejects unknown and absent SNI')
            for payload in [b'GET / HTTP/1.1\r\n\r\n', b'\x16']:
                with socket.create_connection(('127.0.0.1', tls_port), timeout=7) as sock:
                    start = time.monotonic()
                    sock.sendall(payload)
                    try:
                        assert sock.recv(1) == b''
                    except ConnectionResetError:
                        pass
                    assert time.monotonic() - start < 6.5
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('plaintext and incomplete TLS handshakes close within the five-second handshake budget')
            rotated, _ = certificate(root, 'term.pike.test', 'rotated', ca, key=term_key)
            os.replace(rotated, term_cert)
            new_fp, _ = exchange(context, tls_port, 'term.pike.test', b'T')
            assert new_fp != term_fp
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('atomically replaced operator certificate takes effect on new handshakes without reconnecting the tunnel')
            held = connected(context, tls_port, 'term.pike.test')
            assert receive(held, 1) == b'T'
            terminated.send_signal(signal.SIGINT)
            terminated.wait(timeout=10)
            try:
                assert held.recv(1) == b''
            except (OSError, ssl.SSLError):
                pass
            held.close()
            wait_for(lambda: plain_origin.count() == 0, 'terminated origin cleanup', 5)
            rejected(lambda: connected(context, tls_port, 'term.pike.test'))
            exchange(context, tls_port, 'pass.pike.test', b'P')
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('graceful unregister closes active TLS streams and removes only its SNI route')
            fixture.stop_process(relay, 'TLS relay reconnect')
            relay = None
            wait_for(lambda: tls_origin.count() == 0, 'passthrough disconnect cleanup', 5)
            relay = fixture.start_relay(server_config, env, relay_log)
            wait_for(lambda: exchange(context, tls_port, 'pass.pike.test', b'P'), 'TLS relay reconnect')
            assert passthrough.poll() is None
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('relay disconnect releases origin sockets and same CLI re-registers its SNI route')
            held = connected(context, tls_port, 'pass.pike.test')
            assert receive(held, 1) == b'P'
            # A stopped process leaves sockets open but cannot acknowledge
            # heartbeats. This reproduces silent loss without a close packet.
            relay.send_signal(signal.SIGSTOP)
            started = time.monotonic()
            wait_for(lambda: tls_origin.count() == 0 and 'heartbeat acknowledgement timed out' in pass_log.read_text(),
                     'silent relay loss origin cleanup', 25)
            silent_loss_ms = round((time.monotonic() - started) * 1000)
            assert 'heartbeat acknowledgement timed out' in pass_log.read_text()
            relay.kill()
            relay.wait(timeout=5)
            held.close()
            relay = fixture.start_relay(server_config, env, relay_log)
            wait_for(lambda: exchange(context, tls_port, 'pass.pike.test', b'P'), 'silent loss reconnect')
            assert passthrough.poll() is None
            print(transport, 'TLS check', len(checks) + 1, flush=True)
            checks.append('silent relay loss expires heartbeat, releases the origin and reconnects the same CLI')
            result = {'transport': transport, 'state': 'passed', 'checks': checks,
                      'silent_loss_cleanup_ms': silent_loss_ms,
                      'scope': 'Local loopback, independent Python/OpenSSL clients and origins; operator certificates, no ACME or deployment proof'}
            print(json.dumps(result), flush=True)
            return result
        except Exception:
            for path in logs:
                if path.exists():
                    print(path.name, path.read_text()[-12000:], flush=True)
            raise
        finally:
            if relay is not None and relay.poll() is None:
                relay.send_signal(signal.SIGCONT)
            for process in processes:
                fixture.stop_process(process, 'TLS CLI')
            fixture.stop_process(relay, 'TLS relay')
            blackhole.close()
            for origin in origins:
                origin.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--transport', choices=['quic', 'websocket', 'both'], default='both')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    results = [run(t) for t in (['quic', 'websocket'] if args.transport == 'both' else [args.transport])]
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + '\n')
