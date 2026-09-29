"""Run installer regression fixtures without modifying host users or services.
Usage: python3 crates/pike-server/tests/deploy_setup.py [--cloud-dir /path/to/pike-cloud]
"""
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser()
parser.add_argument('--cloud-dir', type=Path)
args, remaining = parser.parse_known_args()
if args.cloud_dir:
    args.cloud_dir = args.cloud_dir.resolve()

class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pike-setup-')
        self.base = Path(self.temp.name)
        self.bundle = self.base / 'bundle'
        self.bundle.mkdir()
        self.root = self.base / 'fixture-root'
        self.root.mkdir()
        self.unrelated = self.base / 'unrelated'
        self.unrelated.mkdir()
        for name in ['setup.sh', 'server-vps.toml', 'pike-server.service']:
            shutil.copy2(REPO / 'deploy' / name, self.bundle / name)
        (self.bundle / 'pike-server').write_text('#!/bin/sh\nprintf "fixture relay\\n"\n')
        self.env = {**os.environ, 'PIKE_INSTALL_ROOT': str(self.root)}

    def tearDown(self):
        self.temp.cleanup()

    def install(self):
        result = subprocess.run(['bash', str(self.bundle / 'setup.sh')], cwd=self.unrelated,
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_unrelated_cwd_preserves_config_tokens_and_fixes_tls_modes_on_rerun(self):
        self.install()
        config = self.root / 'etc/pike/server.toml'
        initial = config.read_text()
        self.assertNotIn('CHANGE_ME_SET_A_RANDOM_INTERNAL_TOKEN', initial)
        customized = initial.replace('CHANGE_ME_IF_USING_REMOTE_CONTROL_PLANE', 'existing-server-secret') + '\n# custom deployment value\n'
        config.write_text(customized)
        tls = self.root / 'etc/pike/tls'
        for name in ['key.pem', 'cert.pem']:
            (tls / name).write_text('existing certificate contents')
            (tls / name).chmod(0o600)
        self.install()
        self.assertEqual(config.read_text(), customized)
        self.assertEqual(stat.S_IMODE(tls.stat().st_mode), 0o750)
        for path in [config, tls / 'key.pem', tls / 'cert.pem']:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertTrue((self.root / 'var/lib/pike').is_dir())
        binary = self.root / 'opt/pike/pike-server'
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
        service = (self.root / 'etc/systemd/system/pike-server.service').read_text()
        self.assertIn('User=pike\nGroup=pike', service)
        self.assertIn('StateDirectory=pike', service)

    def test_incomplete_bundle_fails_before_creating_installation(self):
        (self.bundle / 'pike-server').unlink()
        result = subprocess.run(['bash', str(self.bundle / 'setup.sh')], cwd=self.unrelated,
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.root.iterdir()), [])

    @unittest.skipUnless(args.cloud_dir, 'cloud repository not supplied')
    def test_cloud_wrapper_runs_downloaded_bundle_in_its_extraction_directory(self):
        archive = self.base / 'bundle.tar.gz'
        # A legacy installer requires cwd explicitly; the wrapper must support it.
        (self.bundle / 'setup.sh').write_text('#!/bin/sh\nset -eu\ntest -f ./pike-server\ntest -f ./server-vps.toml\ncp ./server-vps.toml "$PIKE_INSTALL_ROOT/cloud-overlay.toml"\n')
        with tarfile.open(archive, 'w:gz') as bundle:
            for item in self.bundle.iterdir():
                bundle.add(item, arcname=item.name)
        stubs = self.base / 'commands'
        stubs.mkdir()
        (stubs / 'uname').write_text('#!/bin/sh\nprintf "x86_64\\n"\n')
        (stubs / 'curl').write_text('#!/bin/sh\nset -eu\nwhile [ "$1" != -o ]; do shift; done\ncp "$PIKE_TEST_ARCHIVE" "$2"\n')
        for item in stubs.iterdir():
            item.chmod(0o755)
        env = {**self.env, 'PATH': str(stubs) + ':' + self.env['PATH'], 'PIKE_TEST_ARCHIVE': str(archive)}
        result = subprocess.run(['sh', str(args.cloud_dir / 'deploy/setup.sh')], cwd=self.unrelated,
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'cloud-overlay.toml').read_bytes(),
                         (args.cloud_dir / 'deploy/server-vps.toml').read_bytes())

if __name__ == '__main__':
    unittest.main(argv=['deploy_setup.py', *remaining])
