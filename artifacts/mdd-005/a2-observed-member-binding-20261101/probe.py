"""Synthetic producer-row/member mapping; not logical DEX qualification."""
import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_input_inventory import InputInventoryError, PinnedInputInventory


class BindingChecks(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'artifacts/local/observed-member-probe-20261101'
        base.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix='run-', dir=base))
        self.dex = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()
        self.apk = self.directory / 'input.apk'
        with zipfile.ZipFile(self.apk, 'x') as archive:
            archive.writestr('assets/meta', b'meta')
            archive.writestr('classes.dex', self.dex, compress_type=zipfile.ZIP_STORED)
            archive.writestr('classes10.dex', self.dex, compress_type=zipfile.ZIP_DEFLATED)
        self.inventory = PinnedInputInventory(self.apk, hashlib.sha256(self.apk.read_bytes()).hexdigest())

    def test_occurrences_and_observed_order_are_preserved(self):
        files = {9:'classes10.dex#1', 4:'classes.dex', 7:'classes10.dex#0'}
        result = self.inventory.bind_observed_members(self.apk, files, chunk_bytes=13)
        self.assertEqual([(x.file_id, x.entry_name, x.member.central_ordinal) for x in result],
                         [(9, 'classes10.dex#1', 2), (4, 'classes.dex', 1), (7, 'classes10.dex#0', 2)])
        self.assertEqual(result[0].member.sha256, result[1].member.sha256)
        self.assertIs(result[0].member, result[2].member)

    def test_mapping_uses_one_copy_of_the_observed_inventory(self):
        files = {0:'classes.dex', 1:'classes10.dex'}
        digest = self.inventory.digest_physical_members

        def mutate_then_read(**kwargs):
            files.clear()
            files[9] = 'classes.dex'
            return digest(**kwargs)

        with patch.object(self.inventory, 'digest_physical_members', mutate_then_read):
            result = self.inventory.bind_observed_members(self.apk, files)
        self.assertEqual([(x.file_id, x.entry_name) for x in result],
                         [(0, 'classes.dex'), (1, 'classes10.dex')])

    def test_wrong_inventory_and_raw_dex_do_not_bind(self):
        with self.assertRaises(InputInventoryError):
            self.inventory.bind_observed_members(self.apk, {0:'classes.dex'})
        raw = self.directory / 'raw.dex'; raw.write_bytes(self.dex)
        guard = PinnedInputInventory(raw, hashlib.sha256(self.dex).hexdigest())
        with self.assertRaisesRegex(InputInventoryError, 'raw DEX'):
            guard.bind_observed_members(raw, {0:'raw.dex'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
