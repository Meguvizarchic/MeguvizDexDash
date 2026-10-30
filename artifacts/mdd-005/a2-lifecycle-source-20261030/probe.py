"""Synthetic lifecycle source checks; no producer snapshot or A2 qualification."""
import asyncio
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
spec = importlib.util.spec_from_file_location('lifecycle_fixture',
    ROOT / 'artifacts/mdd-005/a2-dataset-lifecycle-20261030/probe2.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
from a2_input_inventory import PinnedInputInventory
from a2_windows_input_pin import InputPinError, WindowsInputPin


class Source(fixture.Source):
    def __init__(self, failure):
        super().__init__()
        self.failure = failure

    def verify_source(self):
        super().verify_source()
        if self.checks == self.failure:
            raise RuntimeError('synthetic source failure')


class Checks(unittest.TestCase):
    def test_source_failure_before_close_aborts_owner(self):
        async def run():
            source = Source(5); client = fixture.Client(source); owner = fixture.Owner()
            life = fixture.make(source, client, owner)
            with self.assertRaisesRegex(RuntimeError, 'synthetic source failure'):
                async with life: pass
            self.assertFalse(life.close_confirmed)
            self.assertFalse(life.source_confirmed)
            self.assertTrue(life.abort_confirmed)
            self.assertNotIn('close_dataset', client.calls)
        asyncio.run(run())

    def test_source_failure_after_close_keeps_close_fact(self):
        async def run():
            source = Source(6); client = fixture.Client(source); owner = fixture.Owner()
            life = fixture.make(source, client, owner)
            with self.assertRaisesRegex(RuntimeError, 'synthetic source failure'):
                async with life: pass
            self.assertTrue(life.close_confirmed)
            self.assertFalse(life.source_confirmed)
            self.assertTrue(life.abort_confirmed)
            self.assertIn('close_dataset', client.calls)
        asyncio.run(run())

    def test_normal_close_confirms_both_observations(self):
        async def run():
            source = Source(0); client = fixture.Client(source); owner = fixture.Owner()
            life = fixture.make(source, client, owner)
            async with life: pass
            self.assertTrue(life.close_confirmed)
            self.assertTrue(life.source_confirmed)
            self.assertFalse(life.abort_confirmed)
        asyncio.run(run())

    def test_deadline_after_source_verification_aborts(self):
        async def run():
            source = Source(0); client = fixture.Client(source); owner = fixture.Owner()
            life = fixture.A1DatasetLifecycle(client, source,
                remaining_seconds=lambda: 0 if source.checks >= 5 else 10,
                abort_owned_transport=owner.abort, abort_seconds=1)
            with self.assertRaises(TimeoutError):
                async with life: pass
            self.assertTrue(life.abort_confirmed)
            self.assertFalse(life.close_confirmed)
            self.assertFalse(life.source_confirmed)
            self.assertNotIn('close_dataset', client.calls)
        asyncio.run(run())

    def test_released_pin_cannot_finish_lifecycle(self):
        directory = ROOT / 'artifacts/local' / ('lifecycle-pin-' + uuid.uuid4().hex)
        directory.mkdir(parents=True)
        path = directory / 'sample.dex'
        data = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()
        path.write_bytes(data)
        source = PinnedInputInventory(path, hashlib.sha256(data).hexdigest())
        pin = WindowsInputPin(source)
        async def run():
            client = fixture.Client(pin); owner = fixture.Owner()
            life = fixture.make(pin, client, owner)
            pin.__enter__()
            try:
                with self.assertRaises(InputPinError):
                    async with life:
                        pin.close()
                self.assertTrue(life.abort_confirmed)
                self.assertFalse(life.source_confirmed)
                self.assertFalse(life.close_confirmed)
                self.assertNotIn('close_dataset', client.calls)
            finally:
                pin.close()
        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
