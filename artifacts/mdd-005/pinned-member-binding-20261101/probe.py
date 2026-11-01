"""Real Windows read pin over a synthetic APK; not producer snapshot proof."""
import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_input_inventory import InputInventoryError, PinnedInputInventory
from a2_windows_input_pin import InputPinError, WindowsInputPin


class PinBindingChecks(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'artifacts/local/pinned-member-binding-20261101'
        base.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix='run-', dir=base))
        self.dex = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()
        self.apk = self.directory / 'input.apk'
        with zipfile.ZipFile(self.apk, 'x') as archive:
            archive.writestr('classes.dex', self.dex, compress_type=zipfile.ZIP_STORED)
            archive.writestr('classes2.dex', self.dex, compress_type=zipfile.ZIP_DEFLATED)
        source = PinnedInputInventory(self.apk, hashlib.sha256(self.apk.read_bytes()).hexdigest())
        self.pin = WindowsInputPin(source)

    def test_real_pin_covers_digest_binding_and_denies_new_writer(self):
        with self.pin:
            with self.assertRaises(PermissionError):
                with self.apk.open('r+b'):
                    pass
            members = self.pin.digest_physical_members(chunk_bytes=31)
            self.assertEqual([x.name for x in members], ['classes.dex', 'classes2.dex'])
            self.assertEqual(members[0].sha256, hashlib.sha256(self.dex).hexdigest())
            rows = self.pin.bind_observed_members(self.apk,
                {0:'classes.dex', 2:'classes2.dex#1', 3:'classes2.dex#0'}, max_observed_rows=3)
            self.assertEqual([(x.file_id, x.member.central_ordinal) for x in rows], [(0,0),(2,1),(3,1)])
            with self.assertRaisesRegex(InputInventoryError, 'row budget'):
                self.pin.bind_observed_members(self.apk,
                    {0:'classes.dex', 2:'classes2.dex#1', 3:'classes2.dex#0'}, max_observed_rows=2)
        with self.assertRaises(InputPinError):
            self.pin.digest_physical_members()

    def test_unheld_pin_cannot_return_member_evidence(self):
        with self.assertRaises(InputPinError):
            self.pin.bind_observed_members(self.apk, {0:'classes.dex', 1:'classes2.dex'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
