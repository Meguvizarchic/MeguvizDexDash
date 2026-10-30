"""Synthetic ZIP local-header checks; not DEX, snapshot or A2 qualification."""
import hashlib
import io
from pathlib import Path
import sys
import unittest
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_input_inventory import InputInventoryError, PinnedInputInventory


class Checks(unittest.TestCase):
    def setUp(self):
        self.directory = ROOT / 'artifacts/local' / ('inventory-header-' + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)

    def source(self, data):
        path = self.directory / (uuid.uuid4().hex + '.apk')
        path.write_bytes(data)
        return PinnedInputInventory(path, hashlib.sha256(data).hexdigest())

    @staticmethod
    def archive():
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_STORED) as output:
            output.writestr('classes.dex', b'first')
            output.writestr('classes2.dex', b'second')
        return bytearray(stream.getvalue())

    def test_accepts_matching_headers_and_logical_occurrences(self):
        inventory = self.source(self.archive())
        self.assertEqual(inventory.physical_members, frozenset(('classes.dex', 'classes2.dex')))
        inventory.verify_inventory(inventory.path, {0: 'classes.dex#0', 1: 'classes2.dex'})

    def test_mismatched_local_name_is_rejected(self):
        data = self.archive()
        self.assertEqual(data[30:41], b'classes.dex')
        data[30] = ord('X')  # Central name stays classes.dex.
        with self.assertRaises(InputInventoryError): self.source(data)

    def test_invalid_local_signature_is_rejected(self):
        data = self.archive()
        data[0] = 0
        with self.assertRaises(InputInventoryError): self.source(data)

    def test_header_check_does_not_claim_crc_verification(self):
        data = self.archive()
        data[41] ^= 1  # Keep headers and declared CRC unchanged; corrupt payload.
        inventory = self.source(data)
        self.assertIn('classes.dex', inventory.physical_members)
        with zipfile.ZipFile(inventory.path) as archive:
            with self.assertRaises(zipfile.BadZipFile): archive.read('classes.dex')


if __name__ == '__main__':
    unittest.main()
