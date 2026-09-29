#!/usr/bin/env python3
"""Real PostgreSQL/Redis/OpenSSH clients through both Pike transports.

Uses cached images only, fresh tmpfs databases, loopback origin ports, disposable
SSH keys/config and a command-restricted sshd. Never touches existing services.
"""
import argparse
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import tempfile
import time

import local_tunnel_smoke as fixture


def command(args, data=None, check=True, env=None):
    result = subprocess.run(list(map(str, args)), input=data, capture_output=True,
                            timeout=30, env=env)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr.decode(errors="replace")[-1500:]}')
    return result


def wait_for(fn, description):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        if fn():
            return
        time.sleep(0.2)
    raise AssertionError(description)


class Services:
    def __init__(self, root):
        self.root, self.containers, self.sshd = root, [], None
        self.password = secrets.token_hex(24)

    def container(self, image, port, extra, args):
        name = 'pike-interop-' + secrets.token_hex(6)
        self.containers.append(name)
        command(['docker', 'run', '--pull=never', '--rm', '-d', '--name', name,
                 '-p', f'127.0.0.1::{port}', *extra, image, *args])
        mapping = command(['docker', 'port', name, f'{port}/tcp']).stdout.decode().strip()
        assert mapping.startswith('127.0.0.1:'), mapping
        return name, int(mapping.rsplit(':', 1)[1])

    def start(self):
        self.pg, self.pg_port = self.container('postgres:16.14', 5432,
            ['--tmpfs', '/var/lib/postgresql/data', '-e', f'POSTGRES_PASSWORD={self.password}'], [])
        wait_for(lambda: command(['docker', 'exec', self.pg, 'pg_isready', '-U', 'postgres'], check=False).returncode == 0,
                 'PostgreSQL readiness')
        self.redis, self.redis_port = self.container('redis:7', 6379, ['--tmpfs', '/data'],
            ['redis-server', '--save', '', '--appendonly', 'no', '--requirepass', self.password])
        wait_for(lambda: b'PONG' in command(['docker', 'exec', '-e', f'REDISCLI_AUTH={self.password}', self.redis, 'redis-cli', 'PING'], check=False).stdout,
                 'Redis readiness')
        self.ssh_port = fixture.reserve_free_port()
        for name in ['host', 'client', 'wrong']:
            command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', self.root / name])
        self.sftp_dir = self.root / 'sftp'
        self.sftp_dir.mkdir()
        # The fixture key can run only this fixed command or the SFTP subsystem.
        guard = self.root / 'ssh-command.sh'
        guard.write_text('#!/bin/sh\ncase "$SSH_ORIGINAL_COMMAND" in\n'
                         'pike-fixture) printf "pike-ssh-ok\\n" ;;\n'
                         f'/usr/libexec/sftp-server) exec /usr/libexec/sftp-server -d {shlex.quote(str(self.sftp_dir))} ;;\n'
                         '*) exit 126 ;;\nesac\n')
        guard.chmod(0o700)
        config = self.root / 'sshd.conf'
        config.write_text(f'''Port {self.ssh_port}
ListenAddress 127.0.0.1
HostKey {self.root / 'host'}
PidFile {self.root / 'sshd.pid'}
AuthorizedKeysFile {self.root / 'client.pub'}
AllowUsers {getpass.getuser()}
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitRootLogin no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
UseDNS no
ForceCommand {guard}
Subsystem sftp /usr/libexec/sftp-server
LogLevel ERROR
''')
        self.ssh_log = self.root / 'sshd.log'
        self.sshd = fixture.start_process(['/usr/sbin/sshd', '-D', '-e', '-f', str(config)],
                                         env=dict(os.environ), log_path=self.ssh_log)
        def ssh_ready():
            if self.sshd.poll() is not None:
                raise RuntimeError(self.ssh_log.read_text())
            try:
                with socket.create_connection(('127.0.0.1', self.ssh_port), timeout=1):
                    return True
            except OSError:
                return False
        wait_for(ssh_ready, 'isolated OpenSSH readiness')
        self.versions = {
            'postgres': command(['docker', 'exec', self.pg, 'psql', '--version']).stdout.decode().strip(),
            'redis': command(['docker', 'exec', self.redis, 'redis-server', '--version']).stdout.decode().strip(),
            'ssh': command(['ssh', '-V']).stderr.decode().strip(),
            'container_images': [command(['docker', 'inspect', '--format', '{{.Image}}', name]).stdout.decode().strip()
                                 for name in self.containers],
        }

    def close(self):
        fixture.stop_process(self.sshd, 'isolated sshd')
        for name in self.containers:
            removed = command(['docker', 'rm', '-f', name], check=False)
            if removed.returncode and command(['docker', 'inspect', name], check=False).returncode == 0:
                raise RuntimeError(f'could not remove fixture container {name}')

    def database_checks(self, pg_port, redis_port):
        pg = ['docker', 'exec', '-i', '-e', f'PGPASSWORD={self.password}', self.pg,
              'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-h', 'host.docker.internal',
              '-p', str(pg_port), '-U', 'postgres']
        payload = os.urandom(128 * 1024)
        sql = (b'CREATE TEMP TABLE fixture (data bytea); BEGIN; COPY fixture FROM STDIN;\n'
               + b'\\\\x' + payload.hex().encode() + b'\n\\.\nCOMMIT;\n'
               + b"SELECT encode(data,'hex') FROM fixture; BEGIN; DELETE FROM fixture; ROLLBACK; SELECT count(*) FROM fixture;\n")
        result = command(pg, sql).stdout.splitlines()
        assert result == [payload.hex().encode(), b'1'], 'PostgreSQL binary or transaction mismatch'
        rejected = pg.copy()
        rejected[4] = 'PGPASSWORD=incorrect-fixture-password'
        denied = command(rejected, b'SELECT 1;\n', check=False)
        assert denied.returncode and b'password authentication failed' in denied.stderr
        redis = ['docker', 'exec', '-i', '-e', f'REDISCLI_AUTH={self.password}', self.redis,
                 'redis-cli', '--no-auth-warning', '-h', 'host.docker.internal', '-p', str(redis_port), '--raw']
        assert command([*redis, '-x', 'SET', 'pike-fixture'], payload).stdout.strip() == b'OK'
        assert command([*redis, 'GET', 'pike-fixture']).stdout == payload + b'\n'
        assert command([*redis, 'DEL', 'pike-fixture']).stdout.strip() == b'1'
        bad = redis.copy()
        bad[4] = 'REDISCLI_AUTH=incorrect-fixture-password'
        denied = command([*bad, 'GET', 'pike-fixture'], check=False)
        assert b'WRONGPASS' in denied.stdout + denied.stderr
        return ['PostgreSQL/libpq: 128 KiB binary COPY and result, commit/rollback, wrong-password rejection',
                'Redis/redis-cli: 128 KiB binary SET/GET, deletion and wrong-password rejection']

    def ssh_checks(self, port):
        known = self.root / 'known_hosts'
        key = (self.root / 'host.pub').read_text().split()
        known.write_text(f'[127.0.0.1]:{port} {key[0]} {key[1]}\n')
        opts = ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={known}',
                '-o', 'ConnectTimeout=5', '-i', str(self.root / 'client')]
        destination = getpass.getuser() + '@127.0.0.1'
        ssh = ['ssh', *opts, '-p', str(port), destination]
        assert command([*ssh, 'pike-fixture']).stdout == b'pike-ssh-ok\n'
        assert command([*ssh, 'not-allowed'], check=False).returncode == 126
        wrong = opts.copy()
        wrong[-1] = str(self.root / 'wrong')
        denied = command(['ssh', *wrong, '-p', str(port), destination, 'pike-fixture'], check=False)
        assert denied.returncode == 255 and b'Permission denied' in denied.stderr
        source, downloaded = self.root / 'upload.bin', self.root / 'download.bin'
        payload = os.urandom(512 * 1024)
        source.write_bytes(payload)
        remote = self.sftp_dir / 'roundtrip.bin'
        batch = f'put {source} {remote}\nget {remote} {downloaded}\nrm {remote}\n'.encode()
        command(['sftp', *opts, '-P', str(port), '-b', '-', destination], batch)
        assert downloaded.read_bytes() == payload
        assert not remote.exists()
        return ['OpenSSH: pinned host key, public-key login, command result/status and unauthorized-key rejection',
                'OpenSSH SFTP: 512 KiB binary upload/download with SHA-256 identity and remote cleanup'], hashlib.sha256(payload).hexdigest()


def run(transport, services, root):
    processes, logs = [], []
    env = dict(os.environ, NO_COLOR='1', RUST_LOG='info')
    http_port, relay_port = fixture.reserve_free_port(), fixture.reserve_free_port(socket.SOCK_DGRAM)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blackhole:
        blackhole.bind(('127.0.0.1', 0))
        server, client = root / 'server.toml', root / 'client.toml'
        fixture.write_server_config(server, relay_port, http_port, fixture.reserve_free_port())
        fixture.write_client_config(client, blackhole.getsockname()[1] if transport == 'websocket' else relay_port,
                                    fixture.reserve_free_port(), http_port, transport)
        try:
            relay_log = root / f'{transport}-relay.log'
            relay = fixture.start_relay(server, env, relay_log)
            processes.append(relay); logs.append(relay_log)
            fixture.wait_for_http(f'http://127.0.0.1:{http_port}/health', headers={'Host': fixture.DOMAIN},
                                 expected_status=200, timeout=30, process=relay)
            ports = []
            for name, origin in [('postgres', services.pg_port), ('redis', services.redis_port), ('ssh', services.ssh_port)]:
                path = root / f'{transport}-{name}.log'
                process = fixture.start_tcp_client(client, origin, None, env, path)
                processes.append(process); logs.append(path)
                ports.append(fixture.wait_for_tcp_registration(process, path))
            checks = services.database_checks(*ports[:2])
            ssh, digest = services.ssh_checks(ports[2])
            checks.extend(ssh)
            result = dict(transport=transport, state='passed', checks=checks, sftp_sha256=digest)
            print(json.dumps(result), flush=True)
            return result
        except Exception:
            for path in logs:
                if path.exists():
                    print(path.name, path.read_text()[-3000:], flush=True)
            raise
        finally:
            for process in reversed(processes):
                fixture.stop_process(process, 'application interoperability fixture')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='pike-services-') as directory:
        root = Path(directory)
        services = Services(root)
        try:
            services.start()
            cases = [run(transport, services, root) for transport in ['quic', 'websocket']]
            result = dict(checkedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(), cases=cases, versions=services.versions,
                          scope='Local cached PostgreSQL 16.14/Redis 7 and macOS OpenSSH clients/servers; isolated disposable fixtures, no external network or deployment proof')
            args.output.write_text(json.dumps(result, indent=2) + '\n')
        finally:
            services.close()
