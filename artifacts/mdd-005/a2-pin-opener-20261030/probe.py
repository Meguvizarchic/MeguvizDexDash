"""Real Windows sharing checks on synthetic local files; no snapshot qualification."""
import hashlib
import asyncio
import os
from pathlib import Path
import sys
import unittest
import uuid
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_input_inventory import PinnedInputInventory
from a2_windows_input_pin import InputPinError, WindowsInputPin
from a2_dataset_open import A1ExclusiveDatasetOpener


class Checks(unittest.TestCase):
    def setUp(self):
        self.directory = ROOT / 'artifacts/local' / ('input-pin-' + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)
        self.path = self.directory / 'sample.dex'
        data = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()
        self.path.write_bytes(data)
        self.source = PinnedInputInventory(self.path, hashlib.sha256(data).hexdigest())

    def test_lock_blocks_new_write_and_rename_but_allows_reads(self):
        renamed = self.directory / 'renamed.dex'
        pin = WindowsInputPin(self.source)
        with pin:
            self.assertEqual(self.path.read_bytes()[:4], b'dex\n')
            with self.assertRaises(PermissionError): self.path.open('r+b')
            with self.assertRaises(PermissionError): os.rename(self.path, renamed)
            pin.verify()
        with self.path.open('r+b') as handle:
            self.assertEqual(handle.read(4), b'dex\n')
        with self.assertRaises(InputPinError): pin.verify()
        with self.assertRaises(InputPinError): pin.__enter__()

    def test_preexisting_writer_prevents_pin(self):
        with self.path.open('r+b'):
            with self.assertRaises(InputPinError):
                with WindowsInputPin(self.source): pass

    def test_failed_identity_check_releases_handle(self):
        class FailedSource:
            path = self.path
            def verify_source(self): raise RuntimeError('synthetic identity failure')
        pin = WindowsInputPin(FailedSource())
        with self.assertRaisesRegex(RuntimeError, 'synthetic identity failure'):
            with pin: pass
        with self.path.open('r+b') as handle:
            self.assertEqual(handle.read(4), b'dex\n')

    def test_failed_close_can_be_retried(self):
        class FailedClose:
            def CloseHandle(self, handle): return 0
        pin = WindowsInputPin(self.source)
        pin.__enter__()
        real = pin._kernel
        pin._kernel = FailedClose()  # Inject failure without closing the real handle.
        try:
            with self.assertRaises(InputPinError): pin.close()
            with self.assertRaises(PermissionError): self.path.open('r+b')
            pin._kernel = real
            pin.close()
            with self.path.open('r+b') as handle:
                self.assertEqual(handle.read(4), b'dex\n')
        finally:
            pin._kernel = real
            pin.close()

    def test_exit_verifies_before_unlock_and_preserves_body_error(self):
        class Source:
            path = self.path
            calls = 0
            def verify_source(self):
                self.calls += 1
                if self.calls == 2:
                    raise RuntimeError('synthetic final verification failure')
        source = Source()
        with self.assertRaisesRegex(RuntimeError, 'synthetic final verification failure'):
            with WindowsInputPin(source): pass
        with self.path.open('r+b') as handle: self.assertEqual(handle.read(4), b'dex\n')
        source = Source()
        with self.assertRaisesRegex(ValueError, 'body failure') as caught:
            with WindowsInputPin(source): raise ValueError('body failure')
        self.assertTrue(any('final verification failure' in note
                            for note in getattr(caught.exception, '__notes__', [])))
        with self.path.open('r+b') as handle: self.assertEqual(handle.read(4), b'dex\n')

    def test_falsey_body_error_remains_first_on_close_failure(self):
        class FalseError(Exception):
            def __bool__(self): return False
        class FailedClose:
            def CloseHandle(self, handle): return 0
        pin = WindowsInputPin(self.source)
        real = pin._kernel
        try:
            with self.assertRaises(FalseError) as caught:
                with pin:
                    pin._kernel = FailedClose()
                    raise FalseError('body')
            self.assertTrue(any('close failed' in note
                                for note in getattr(caught.exception, '__notes__', [])))
        finally:
            pin._kernel = real
            pin.close()

    def test_entry_verification_and_close_failure_remain_recoverable(self):
        class FailedSource:
            path = self.path
            def verify_source(self): raise ValueError('entry failure')
        pin = WindowsInputPin(FailedSource())
        real = pin._kernel
        class FailedClose:
            CreateFileW = real.CreateFileW
            def CloseHandle(self, handle): return 0
        pin._kernel = FailedClose()
        try:
            with self.assertRaisesRegex(ValueError, 'entry failure') as caught:
                with pin: pass
            self.assertTrue(any('close failed' in note
                                for note in getattr(caught.exception, '__notes__', [])))
            with self.assertRaises(PermissionError): self.path.open('r+b')
        finally:
            pin._kernel = real
            pin.close()
        with self.path.open('r+b') as handle: self.assertEqual(handle.read(4), b'dex\n')

    def test_opener_uses_held_pin_and_rejects_unheld_pin(self):
        pin = WindowsInputPin(self.source)
        size = self.path.stat().st_size
        class Client:
            def __init__(self): self.opened = False; self.calls = []
            async def call_tool(self, tool, args):
                self.calls.append(tool)
                opened = {'dataset_id': 'fixture', 'inputs': [str(pin.path)],
                          'has_dex': True, 'input_bytes': size, 'prepare_ms': 1.0}
                if tool == 'open_dataset':
                    self.opened = True
                    data = opened
                else:
                    data = {'datasets': [opened] if self.opened else [],
                            'admitted_requests': 0, 'running_requests': 0,
                            'usage': {'datasets': int(self.opened),
                                      'input_bytes': size if self.opened else 0}}
                return SimpleNamespace(is_error=False, structured_content=data, content=[])
        client = Client()
        with self.assertRaises(InputPinError):
            asyncio.run(A1ExclusiveDatasetOpener(client, pin, remaining_seconds=lambda: 5).open())
        self.assertEqual(client.calls, [])
        with pin:
            result = asyncio.run(A1ExclusiveDatasetOpener(client, pin, remaining_seconds=lambda: 5).open())
            self.assertEqual(result.dataset_id, 'fixture')
            self.assertEqual(client.calls, ['list_datasets', 'open_dataset', 'list_datasets'])
            self.assertIsNone(pin.verify_inventory(self.path, {0: 'classes.dex'}))
            self.source.path = self.directory / 'different.dex'
            try:
                with self.assertRaises(InputPinError): pin.verify_source()
            finally:
                self.source.path = self.path.resolve()
        with self.assertRaises(InputPinError): pin.verify_source()


if __name__ == '__main__':
    unittest.main()
