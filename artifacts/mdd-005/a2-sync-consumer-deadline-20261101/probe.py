"""Synthetic delivery timeout checks; no producer or A2 qualification."""
import asyncio
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
import a2_hostlab_session as hostlab


class Adapter:
    def __init__(self):
        self.remaining = 10

    def verify_binding(self):
        pass

    def remaining_seconds(self):
        return self.remaining

    async def result(self, sql, **_):
        if 'dex_files' in sql:
            return SimpleNamespace(columns=('file_id', 'entry_name'),
                                   rows=[{'file_id': '0', 'entry_name': 'classes.dex'}], total_rows=1)
        if sql == 'zero':
            return SimpleNamespace(columns=('x',), rows=[], total_rows=0)
        return SimpleNamespace(columns=('x',), rows=[{'x': 'a'}, {'x': 'b'}], total_rows=2)


class DeadlineChecks(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        def worker():
            asyncio.set_event_loop(self.loop)
            self.loop.call_soon(ready.set)
            self.loop.run_forever()

        self.thread = threading.Thread(target=worker)
        self.thread.start()
        if not ready.wait(5):
            raise RuntimeError('owner event loop did not start')
        self.adapter = Adapter()

        async def close():
            return True

        self.session = hostlab.HostlabCompactSession(
            ROOT / 'tests/fixtures/generated/structured-035.dex', self.adapter, self.loop,
            verify_inventory=lambda *_: None, close_dataset=close, abort_transport=lambda: True)

    def tearDown(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        if self.thread.is_alive():
            raise RuntimeError('owner event loop did not stop')
        self.loop.close()

    def test_expired_consumer_does_not_acknowledge_or_deliver(self):
        with self.assertRaises(TimeoutError):
            with self.session:
                iterator = self.session.rows('items')
                self.assertEqual(next(iterator), {'x': 'a'})
                self.adapter.remaining = 0
                with self.assertRaises(TimeoutError):
                    next(iterator)
        self.assertEqual([r.row_count for r in self.session.deliveries], [1])

    def test_expired_empty_result_does_not_create_receipt(self):
        real_digest = hostlab._DeliveryDigest

        def expiring_digest(sql, columns):
            digest = real_digest(sql, columns)
            if sql == 'zero':
                self.adapter.remaining = 0
            return digest

        with self.assertRaises(TimeoutError):
            with self.session:
                with patch.object(hostlab, '_DeliveryDigest', expiring_digest):
                    list(self.session.rows('zero'))
        self.assertEqual([r.row_count for r in self.session.deliveries], [1])


if __name__ == '__main__':
    unittest.main(verbosity=2)
