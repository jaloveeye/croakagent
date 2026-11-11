import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import client_version


class ClientVersionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'manifest.json'
        self.path.write_text(json.dumps({'product': 'croakcode', 'latest': '1.2.0', 'minimum': '1.1.0'}))

    def tearDown(self):
        self.temp.cleanup()

    def test_old_missing_invalid_and_dev_versions(self):
        for value in (None, '', 'local', '1.0.9', '1.1.0-dev.abc', '01.1.0', '1.1.0\n'):
            with self.subTest(value=value):
                self.assertEqual(client_version.check(self.path, value)[0], 426)
        for value in ('1.1.0', '1.2.0', '1.2.0-dev.abc', '2.0.0'):
            with self.subTest(value=value):
                self.assertEqual(client_version.check(self.path, value)[0], 200)

    def test_manifest_changes_apply_immediately_and_fail_closed(self):
        self.assertEqual(client_version.check(self.path, '1.1.0')[0], 200)
        self.path.write_text(json.dumps({'product': 'croakcode', 'latest': '1.2.0', 'minimum': '1.2.0'}))
        self.assertEqual(client_version.check(self.path, '1.1.0')[0], 426)
        self.path.write_text('{')
        self.assertEqual(client_version.check(self.path, '1.2.0')[0], 503)
        self.path.unlink()
        self.assertEqual(client_version.check(self.path, '1.2.0')[0], 503)

    def test_invalid_policy_is_unavailable(self):
        for minimum, latest in [('1.2.1', '1.2.0'), ('1.0.0-dev.abc', '1.2.0'), ('1.0.0', 'invalid')]:
            self.path.write_text(json.dumps({'product': 'croakcode', 'minimum': minimum, 'latest': latest}))
            self.assertEqual(client_version.check(self.path, '2.0.0')[0], 503)


if __name__ == '__main__':
    unittest.main()
