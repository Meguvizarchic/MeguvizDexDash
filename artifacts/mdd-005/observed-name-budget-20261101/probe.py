"""Synthetic observed-name limit checks; not a producer snapshot proof."""
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
from a2_windows_input_pin import InputPinError, WindowsInputPin


class NameBudgetChecks(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'artifacts/local/observed-name-budget-20261101'
        base.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix='run-', dir=base))
        dex = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()
        self.apk = self.directory / 'input.apk'
        with zipfile.ZipFile(self.apk, 'x') as archive:
            archive.writestr('classes.dex', dex, compress_type=zipfile.ZIP_STORED)
            archive.writestr('classes2.dex', dex, compress_type=zipfile.ZIP_DEFLATED)
        self.source = PinnedInputInventory(self.apk, hashlib.sha256(self.apk.read_bytes()).hexdigest())

    def test_exact_name_budget_and_one_byte_short(self):
        files = {1:'classes.dex', 2:'classes2.dex#0'}
        size = sum(len(name.encode('utf-8')) for name in files.values())
        self.assertEqual(len(self.source.bind_observed_members(self.apk, files,
                         max_observed_name_bytes=size)), 2)
        with patch.object(self.source, 'digest_physical_members', side_effect=RuntimeError('unexpected read')):
            with self.assertRaisesRegex(InputInventoryError, 'name byte budget'):
                self.source.bind_observed_members(self.apk, files, max_observed_name_bytes=size - 1)

    def test_large_and_invalid_unicode_fail_before_archive_read(self):
        for name in ('classes.dex#' + '1' * 20000, 'classes.dex#\ud800'):
            with self.subTest(name_kind='surrogate' if '\ud800' in name else 'long'):
                with patch.object(self.source, 'digest_physical_members', side_effect=RuntimeError('unexpected read')):
                    with self.assertRaises(InputInventoryError):
                        self.source.bind_observed_members(self.apk, {0:name}, max_observed_name_bytes=32)
        for invalid in (True, -1, 1.5):
            with self.subTest(limit=invalid), self.assertRaises(ValueError):
                self.source.bind_observed_members(self.apk, {0:'classes.dex'}, max_observed_name_bytes=invalid)

    def test_str_subclass_cannot_forge_length_or_slice(self):
        class CamouflagedName(str):
            def __len__(self):
                return 1

            def __getitem__(self, key):
                return 'x'

        name = CamouflagedName('classes.dex#' + '1' * 20000)
        with patch.object(self.source, 'digest_physical_members', side_effect=RuntimeError('unexpected read')):
            with self.assertRaisesRegex(InputInventoryError, 'invalid logical DEX'):
                self.source.bind_observed_members(self.apk,
                    {0:name, 1:'classes2.dex'}, max_observed_name_bytes=32)

    def test_windows_pin_forwards_the_explicit_name_budget(self):
        pin = WindowsInputPin(self.source)
        with pin:
            with self.assertRaisesRegex(InputInventoryError, 'name byte budget'):
                pin.bind_observed_members(self.apk, {0:'classes.dex', 1:'classes2.dex'},
                                          max_observed_name_bytes=1)
            result = pin.bind_observed_members(self.apk, {0:'classes.dex', 1:'classes2.dex'},
                                                max_observed_name_bytes=100)
            self.assertEqual([row.file_id for row in result], [0, 1])

    def test_old_source_signature_fails_without_calling_it(self):
        class OldSource:
            path = self.source.path
            sha256 = self.source.sha256
            called = False

            def verify_source(self):
                pass  # Synthetic stub; does not authenticate source.

            def bind_observed_members(self, source, files, *, chunk_bytes, max_observed_rows):
                self.called = True
                return ()

        source = OldSource()
        pin = WindowsInputPin(source)
        with pin:
            with self.assertRaisesRegex(InputPinError, 'required name budget'):
                pin.bind_observed_members(self.apk, {0:'classes.dex'})
            self.assertFalse(source.called)

        class BrokenSource(OldSource):
            def bind_observed_members(self, source, files, **kwargs):
                raise TypeError('source internal failure')

        with WindowsInputPin(BrokenSource()) as pin:
            with self.assertRaisesRegex(TypeError, 'source internal failure'):
                pin.bind_observed_members(self.apk, {0:'classes.dex'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
