"""Synthetic rows with a real Windows input pin; not an A2 certificate."""
import asyncio
import hashlib
import sys
import tempfile
import threading
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_hostlab_session import HostlabCompactSession, HostlabSessionError
from a2_input_inventory import PinnedInputInventory
from a2_windows_input_pin import WindowsInputPin


class Adapter:
    def __init__(self, pin):
        self.pin = pin
        self.remaining = 10

    def remaining_seconds(self):
        return self.remaining

    def verify_binding(self):
        self.pin.verify()  # Real input pin, not producer-generation proof.

    async def result(self, sql, **_):
        if 'dex_files' not in sql:
            raise ValueError('unexpected query')
        rows = [{'file_id':'0', 'entry_name':'classes.dex'},
                {'file_id':'2', 'entry_name':'classes2.dex#1'},
                {'file_id':'3', 'entry_name':'classes2.dex#0'}]
        return SimpleNamespace(columns=('file_id','entry_name'), rows=rows, total_rows=len(rows))


class SyncBindingChecks(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'artifacts/local/sync-physical-binding-20261101'
        base.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix='run-', dir=base))
        dex = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()
        self.apk = self.directory / 'input.apk'
        with zipfile.ZipFile(self.apk, 'x') as archive:
            archive.writestr('classes.dex', dex, compress_type=zipfile.ZIP_STORED)
            archive.writestr('classes2.dex', dex, compress_type=zipfile.ZIP_DEFLATED)
        self.source = PinnedInputInventory(self.apk, hashlib.sha256(self.apk.read_bytes()).hexdigest())
        self.pin = WindowsInputPin(self.source)
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        def worker():
            asyncio.set_event_loop(self.loop)
            self.loop.call_soon(ready.set)
            self.loop.run_forever()

        self.thread = threading.Thread(target=worker)
        self.thread.start()
        if not ready.wait(5):
            raise RuntimeError('event loop did not start')
        self.adapter = Adapter(self.pin)
        self.closed = []

    def tearDown(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        if self.thread.is_alive():
            raise RuntimeError('event loop did not stop')
        self.loop.close()

    def session(self, binder):
        async def close():
            self.closed.append(True)
            return True
        return HostlabCompactSession(self.apk, self.adapter, self.loop,
            verify_inventory=self.pin.verify_inventory, close_dataset=close,
            abort_transport=lambda: True, bind_physical_members=binder)

    def test_real_pinned_physical_mapping_keeps_reported_rows(self):
        with self.pin:
            with self.session(self.pin.bind_observed_members) as session:
                self.assertEqual([(item.file_id, item.member.central_ordinal)
                                  for item in session.physical_members], [(0,0), (2,1), (3,1)])
                self.assertFalse(session.opened['qualified'])
        self.assertEqual(self.closed, [True])

    def test_callback_row_mismatch_fails_closed(self):
        with self.pin:
            def wrong(source, files):
                return tuple(reversed(self.pin.bind_observed_members(source, files)))
            session = self.session(wrong)
            with self.assertRaisesRegex(HostlabSessionError, 'binding differs'):
                session.__enter__()
            self.assertIsNone(session.physical_members)
        self.assertEqual(self.closed, [True])

    def test_inconsistent_physical_identity_fails_closed(self):
        with self.pin:
            for kind in ('same_name', 'same_ordinal'):
                with self.subTest(kind=kind):
                    def inconsistent(source, files):
                        rows = list(self.pin.bind_observed_members(source, files))
                        if kind == 'same_name':
                            rows[2] = replace(rows[2], member=replace(rows[2].member, sha256='0' * 64))
                        else:
                            rows[1] = replace(rows[1], member=replace(rows[1].member, central_ordinal=rows[0].member.central_ordinal))
                        return tuple(rows)
                    session = self.session(inconsistent)
                    with self.assertRaisesRegex(HostlabSessionError, 'physical member binding'):
                        session.__enter__()
                    self.assertIsNone(session.physical_members)

    def test_tuple_subclass_cannot_hide_observed_rows(self):
        class HiddenRows(tuple):
            def __iter__(self):
                return iter(())

        with self.pin:
            def hidden(source, files):
                return HiddenRows(self.pin.bind_observed_members(source, files))
            session = self.session(hidden)
            with self.assertRaisesRegex(HostlabSessionError, 'row count differs'):
                session.__enter__()
            self.assertIsNone(session.physical_members)

    def test_opt_out_is_explicitly_not_bound(self):
        with self.pin:
            with self.session(None) as session:
                self.assertIsNone(session.physical_members)
                self.assertFalse(session.opened['qualified'])

    def test_binding_that_exhausts_deadline_is_not_published(self):
        with self.pin:
            def expired(source, files):
                observations = self.pin.bind_observed_members(source, files)
                self.adapter.remaining = 0
                return observations
            session = self.session(expired)
            with self.assertRaises(TimeoutError):
                session.__enter__()
            self.assertIsNone(session.physical_members)


if __name__ == '__main__':
    unittest.main(verbosity=2)
