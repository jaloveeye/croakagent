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
