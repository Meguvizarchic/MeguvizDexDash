"""Synthetic APK member digest and CRC checks; no snapshot/A2 qualification."""
import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_input_inventory import InputInventoryError, PinnedInputInventory


class PhysicalDigestChecks(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'artifacts/local/physical-digest-probe-20261101'
        base.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix='run-', dir=base))
        self.dex = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()

    def make_archive(self):
        path = self.directory / 'input.apk'
        with zipfile.ZipFile(path, 'x') as archive:
            archive.writestr('assets/meta', b'meta', compress_type=zipfile.ZIP_STORED)
            archive.writestr('classes.dex', self.dex, compress_type=zipfile.ZIP_STORED)
            archive.writestr('classes10.dex', self.dex, compress_type=zipfile.ZIP_DEFLATED)
        return path

    def pin(self, path, **bounds):
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        return PinnedInputInventory(path, sha, **bounds)

    def test_physical_order_duplicate_content_and_full_read(self):
        path = self.make_archive()
        inventory = self.pin(path, max_dex_bytes=2 * len(self.dex))
        records = inventory.digest_physical_members(chunk_bytes=17)
        self.assertEqual([(row.central_ordinal, row.name) for row in records],
                         [(1, 'classes.dex'), (2, 'classes10.dex')])
        for row in records:
            self.assertEqual(row.uncompressed_bytes, len(self.dex))
            self.assertEqual(row.sha256, hashlib.sha256(self.dex).hexdigest())
            self.assertEqual(row.crc32, zipfile.crc32(self.dex))
        self.assertEqual(inventory.physical_members, {'classes.dex', 'classes10.dex'})
        inventory.verify_inventory(path, {0:'classes.dex', 1:'classes10.dex#0'})
        with self.assertRaises(InputInventoryError):
            inventory.verify_inventory(path, {0:'classes.dex'})

    def test_corrupt_member_crc_is_not_full_success(self):
        path = self.make_archive()
        with zipfile.ZipFile(path) as archive:
            item = archive.getinfo('classes.dex')
            data_start = item.header_offset + 30 + len(item.filename.encode('utf-8')) + len(item.extra)
        with path.open('r+b') as stream:
            stream.seek(data_start + 1)
            original = stream.read(1)
            stream.seek(data_start + 1)
            stream.write(bytes([original[0] ^ 1]))
        inventory = self.pin(path)
        with self.assertRaisesRegex(InputInventoryError, 'CRC verification failed'):
            inventory.digest_physical_members(chunk_bytes=31)

    def test_scope_budget_and_source_change(self):
        path = self.make_archive()
        with self.assertRaises(InputInventoryError):
            self.pin(path, max_dex_bytes=2 * len(self.dex) - 1)
        inventory = self.pin(path)
        for size in (0, -1, True, 1024 * 1024 + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                inventory.digest_physical_members(chunk_bytes=size)
        with path.open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaises(InputInventoryError):
            inventory.digest_physical_members()

    def test_raw_dex_is_not_archive_coverage(self):
        path = self.directory / 'raw.dex'
        path.write_bytes(self.dex)
        self.assertIsNone(self.pin(path).digest_physical_members())

    def test_nul_name_does_not_become_a_different_physical_identity(self):
        path = self.directory / 'nul-name.apk'
        name = b'classes.dexXtail'
        with zipfile.ZipFile(path, 'x') as archive:
            archive.writestr(name.decode('ascii'), self.dex, compress_type=zipfile.ZIP_STORED)
        data = path.read_bytes()
        self.assertEqual(data.count(name), 2, 'expected local and central names')
        path.write_bytes(data.replace(name, b'classes.dex\x00tail'))
        inventory = self.pin(path)
        # Python exposes the truncated filename to HostLab inventory; the
        # physical-byte digest must not certify that normalized identity.
        self.assertEqual(inventory.physical_members, {'classes.dex'})
        with self.assertRaisesRegex(InputInventoryError, 'name was normalized'):
            inventory.digest_physical_members()


if __name__ == '__main__':
    unittest.main(verbosity=2)
