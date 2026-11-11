import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).resolve().parents[1] / 'publish-downloads.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


def stage_release(base, version):
    stage = base / ('stage-' + version)
    stage.mkdir()
    files = {}
    for target in publisher.TARGETS:
        ext = 'zip' if target.startswith('windows') else 'tar.gz'
        name = f'croakcode-{version}-{target}.{ext}'
        content = (version + target).encode()
        (stage / name).write_bytes(content)
        files[target] = {'file': name, 'sha256': hashlib.sha256(content).hexdigest(), 'size': len(content)}
    (stage / 'manifest.json').write_text(json.dumps({'product': 'croakcode', 'latest': version, 'minimum': '0.1.0', 'files': files}))
    (stage / 'SHA256SUMS').write_text('checksums')
    (stage / 'ca.crt').write_text('public certificate')
    return stage


CA = "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n"


def with_installers(stage):
    (stage / 'ca.crt').write_text(CA)
    (stage / 'install.sh').write_text("default_gate='__CROAK_GATE__'\n")
    (stage / 'install.ps1').write_text("$DefaultGate = '__CROAK_GATE__'\n")
    (stage / 'croakcode-setup.sh').write_text("gate='__CROAK_GATE__'\n")
    (stage / 'croakcode-setup-windows.cmd').write_text('set "GATE=__CROAK_GATE__"\r\n')
    return stage


class InstallerTest(unittest.TestCase):
    GATE = 'https://gate.example.internal:8443'

    def test_installers_carry_the_gate_address_and_a_page_is_written(self):
        import zipfile
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            downloads = base / 'croak' / 'downloads'
            downloads.parent.mkdir()
            (downloads.parent / '.env').write_text('OTHER=1\nCROAK_PUBLIC_URL=' + self.GATE + '/\n')
            publisher.publish(with_installers(stage_release(base, '0.6.1')), downloads)
            for name in ('install.sh', 'install.ps1', 'croakcode-setup-linux.sh', 'croakcode-setup-windows.cmd'):
                text = (downloads / name).read_text()
                self.assertIn(self.GATE, text, name)
                self.assertNotIn('__CROAK_GATE__', text, name)
            with zipfile.ZipFile(downloads / 'croakcode-setup-macos.zip') as archive:
                info = archive.getinfo('croakcode-setup.command')
                self.assertEqual(info.external_attr >> 16, 0o100755)
                self.assertIn(self.GATE, archive.read(info).decode())
            index = (downloads / 'index.html').read_text()
            self.assertIn('버전 0.6.1', index)
            self.assertIn(self.GATE + '/download/install.sh | bash', index)
            self.assertIn('href="croakcode-setup-windows.cmd"', index)
            self.assertIn(hashlib.sha256(bytes([0, 1, 2])).hexdigest(), index)

    def test_without_a_gate_address_installers_stay_as_they_are(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            downloads = base / 'downloads'
            publisher.publish(with_installers(stage_release(base, '0.6.1')), downloads)
            self.assertIn('__CROAK_GATE__', (downloads / 'install.sh').read_text())
            self.assertFalse((downloads / 'index.html').exists())

    def test_an_explicit_gate_wins_and_a_bad_env_value_is_ignored(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            downloads = base / 'croak' / 'downloads'
            downloads.parent.mkdir()
            (downloads.parent / '.env').write_text('CROAK_PUBLIC_URL=http://plain.example\n')
            self.assertIsNone(publisher.gate_url(downloads))
            publisher.publish(with_installers(stage_release(base, '0.6.1')), downloads, gate=self.GATE)
            self.assertIn(self.GATE, (downloads / 'install.sh').read_text())


class PublishDownloadsTest(unittest.TestCase):
    def test_publish_and_keep_two_previous_versions(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            downloads = base / 'downloads'
            for number in range(1, 5):
                publisher.publish(stage_release(base, f'0.1.{number}'), downloads)
            self.assertEqual(json.loads((downloads / 'manifest.json').read_text())['latest'], '0.1.4')
            self.assertEqual({p.name for p in (downloads / 'versions').iterdir()}, {'0.1.2', '0.1.3', '0.1.4'})
            self.assertFalse(list(downloads.glob('croakcode-0.1.1-*')))
            self.assertEqual(len(list(downloads.glob('croakcode-0.1.2-*'))), 5)
            self.assertEqual((downloads / 'ca.crt').read_text(), 'public certificate')

    def test_bad_hash_does_not_publish(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            downloads = base / 'downloads'
            publisher.publish(stage_release(base, '0.1.1'), downloads)
            stage = stage_release(base, '0.1.2')
            next(stage.glob('croakcode-*')).write_text('damaged')
            with self.assertRaises(ValueError):
                publisher.publish(stage, downloads)
            self.assertEqual(json.loads((downloads / 'manifest.json').read_text())['latest'], '0.1.1')

    def test_unsafe_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            stage = stage_release(base, '0.1.1')
            manifest = json.loads((stage / 'manifest.json').read_text())
            manifest['files']['linux-x64']['file'] = '../secret'
            (stage / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                publisher.publish(stage, base / 'downloads')
            self.assertFalse((base / 'downloads').exists())
