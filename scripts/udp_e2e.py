#!/usr/bin/env python3
"""Real CLI/relay/UDP-origin tests; loopback only, both tunnel transports."""
import argparse
import json
import os
from pathlib import Path
import queue
import re
import socket
import tempfile
import threading
import time

import local_tunnel_smoke as fixture


class Origin:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(0.1)
        self.events = queue.Queue()
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                data, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            self.events.put((data, peer))
            if data != b'HOLD':
                response = str(peer[1]).encode() if data == b'WHO' else data
                self.socket.sendto(response, peer)

    def close(self):
        self.stopped.set()
        self.thread.join(2)
        self.socket.close()


def client(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
    sock.bind(('127.0.0.1', 0))
    sock.connect(('127.0.0.1', port))
    sock.settimeout(2)
    return sock


def exchange(sock, payload):
    assert sock.send(payload) == len(payload)
    return sock.recv(65535)


def registered(process, path):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        assert process.poll() is None, path.read_text()
        match = re.search(r'udp://(\d+)', path.read_text())
        if match:
            return int(match[1])
        time.sleep(0.05)
    raise AssertionError(f'UDP registration timeout: {path.read_text()}')


def expect_silence(sock, duration=0.25):
    sock.settimeout(duration)
    try:
        data = sock.recv(65535)
    except (socket.timeout, ConnectionRefusedError):
        pass
    else:
        raise AssertionError(f'unexpected packet: {data[:100]!r}')
    finally:
        sock.settimeout(2)


def run(transport):
    checks = []
    sockets, processes = [], []
    origin = Origin()
    with client(origin.socket.getsockname()[1]) as probe:
        assert exchange(probe, b'') == b''
    origin.events.get(timeout=2)
    env = dict(os.environ, NO_COLOR='1', RUST_LOG='pike=debug,pike_server=debug,pike_core=debug')
    with tempfile.TemporaryDirectory(prefix=f'pike-udp-{transport}-') as folder:
        root = Path(folder)
        relay_port = fixture.reserve_free_port(socket.SOCK_DGRAM)
        http_port, management_port = fixture.reserve_free_port(), fixture.reserve_free_port()
        blackhole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blackhole.bind(('127.0.0.1', 0))
        sockets.append(blackhole)
        config, client_config = root/'server.toml', root/'client.toml'
        fixture.write_server_config(config, relay_port, http_port, management_port)
        fixture.write_client_config(client_config, blackhole.getsockname()[1] if transport == 'websocket' else relay_port,
                                    fixture.reserve_free_port(), http_port, transport)
        server_log, cli_log = root/'relay.log', root/'cli.log'
        relay = None
        try:
            relay = fixture.start_relay(config, env, server_log)
            fixture.wait_for_http(f'http://127.0.0.1:{http_port}/health', expected_status=200,
                                 headers={'Host': fixture.DOMAIN}, timeout=30, process=relay)
            # Choose within the allocation range; verify UDP rather than TCP ownership.
            port = None
            for candidate in range(24000, 25000):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    try:
                        probe.bind(('0.0.0.0', candidate))
                    except OSError:
                        continue
                    port = candidate
                    break
            assert port
            command = [str(fixture.CLI_BIN), '--config', str(client_config), 'udp', str(origin.socket.getsockname()[1]),
                       '--remote-port', str(port), '--idle-timeout', '3', '--max-reconnects', '5']
            cli = fixture.start_process(command, env=env, log_path=cli_log)
            processes.append(cli)
            assert registered(cli, cli_log) == port
            first = client(port)
            sockets.append(first)
            for payload in (b'', b'\x00\xffbinary\x00', bytes(range(256))*255+b'x'*227):
                assert len(payload) <= 65507
                print(f'{transport}: echo {len(payload)} bytes', flush=True)
                assert exchange(first, payload) == payload
            checks.append('empty, binary and exact 65507-byte packets preserve boundaries and content')
            for sequence in range(64):
                payload = sequence.to_bytes(4, 'big') + bytes([sequence]) * 8188
                assert exchange(first, payload) == payload
            checks.append('64 consecutive 8 KiB datagrams pass beyond the per-stream credit window')

            peers = [first] + [client(port) for _ in range(31)]
            sockets.extend(peers[1:])
            origin_ports = {int(exchange(peer, b'WHO')) for peer in peers}
            assert len(origin_ports) == 32, origin_ports
            for i, peer in enumerate(peers):
                peer.send(f'client-{i}'.encode())
            for i, peer in enumerate(peers):
                assert peer.recv(65535) == f'client-{i}'.encode()
            checks.append('32 concurrent public clients have 32 distinct origin sockets and isolated replies')
            overflow = client(port)
            sockets.append(overflow)
            overflow.send(b'over-cap')
            expect_silence(overflow)
            assert exchange(first, b'still-active') == b'still-active'
            checks.append('33rd client is dropped while existing clients continue')

            while not origin.events.empty():
                origin.events.get_nowait()
            first.send(b'HOLD')
            data, local_peer = origin.events.get(timeout=2)
            assert data == b'HOLD'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as attacker:
                attacker.sendto(b'forged-origin', local_peer)
            expect_silence(first)
            origin.socket.sendto(b'legitimate-origin', local_peer)
            assert first.recv(100) == b'legitimate-origin'
            checks.append('unsolicited datagrams from a different origin socket are rejected')

            time.sleep(3.5)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(local_peer)  # Expiry released the real connector socket.
            assert exchange(overflow, b'capacity-restored') == b'capacity-restored'
            checks.append('idle expiry releases origin sockets and restores peer capacity')

            # A second authenticated CLI cannot steal an active public UDP port.
            conflict_log = root/'conflict.log'
            conflict = fixture.start_process(command[:-1]+['0'], env=env, log_path=conflict_log)
            processes.append(conflict)
            conflict.wait(timeout=20)
            assert 'udp://' not in conflict_log.read_text(), conflict_log.read_text()
            assert exchange(overflow, b'owner-retained') == b'owner-retained'
            checks.append('occupied UDP port fails registration without disrupting its owner')

            old_origin_port = int(exchange(overflow, b'WHO'))
            fixture.stop_process(relay, 'UDP relay for reconnect')
            relay = None
            deadline = time.monotonic() + 15
            while True:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    try:
                        probe.bind(('127.0.0.1', old_origin_port))
                        break
                    except OSError:
                        assert time.monotonic() < deadline, 'origin session leaked after disconnect'
                time.sleep(0.1)
            relay = fixture.start_relay(config, env, server_log)
            deadline = time.monotonic() + 30
            while True:
                try:
                    if exchange(overflow, b'reconnected') == b'reconnected':
                        break
                except (socket.timeout, ConnectionRefusedError):
                    pass
                assert cli.poll() is None, cli_log.read_text()
                assert time.monotonic() < deadline, 'UDP did not reconnect'
                time.sleep(0.2)
            checks.append('relay disconnect releases origin sockets; same CLI reconnects and forwards new packets')
            print(json.dumps({'transport': transport, 'state': 'passed', 'checks': checks}), flush=True)
            return {'transport': transport, 'state': 'passed', 'checks': checks}
        except Exception:
            print('Origin received:', [(len(data), peer) for data, peer in list(origin.events.queue)], flush=True)
            for path in (server_log, cli_log):
                if path.exists():
                    print(path.read_text()[-16000:], flush=True)
            raise
        finally:
            for process in processes:
                fixture.stop_process(process, 'UDP CLI')
            fixture.stop_process(relay, 'UDP relay')
            for sock in sockets:
                sock.close()
            origin.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--transport', choices=['both', 'quic', 'websocket'], default='both')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    rows = [run(transport) for transport in (['quic', 'websocket'] if args.transport == 'both' else [args.transport])]
    if args.output:
        args.output.write_text(json.dumps(rows, indent=2)+'\n')
