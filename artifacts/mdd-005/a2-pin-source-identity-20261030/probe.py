"""Synthetic Windows pin/source identity checks; no A2 qualification."""
import hashlib
from pathlib import Path
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_input_inventory import PinnedInputInventory
from a2_windows_input_pin import InputPinError, WindowsInputPin


class Checks(unittest.TestCase):
    def test_digest_stays_fixed_and_changed_identity_is_rejected(self):
        directory = ROOT / 'artifacts/local' / ('pin-identity-' + uuid.uuid4().hex)
        directory.mkdir(parents=True)
        path = directory / 'sample.dex'
        data = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()
        path.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        source = PinnedInputInventory(path, expected)
        pin = WindowsInputPin(source)
        self.assertEqual(pin.sha256, expected)
        with pin:
            pin.verify_source()
            source.sha256 = '0' * 64
            try:
                self.assertEqual(pin.sha256, expected)
                with self.assertRaises(InputPinError): pin.verify_source()
            finally:
                source.sha256 = expected
        with self.assertRaises(InputPinError): pin.verify_source()


if __name__ == '__main__':
    unittest.main()
