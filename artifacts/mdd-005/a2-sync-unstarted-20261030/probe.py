"""Synthetic synchronous-session checks; no snapshot, audit, or A2 qualification."""
import asyncio
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_hostlab_session import HostlabCompactSession, HostlabSessionError


class Adapter:
    def __init__(self):
        self.calls = []
    def verify_binding(self):
        pass  # Explicitly mocked: no generation proof.
    def remaining_seconds(self):
        return 5
    async def result(self, sql, **kwargs):
        self.calls.append(sql)
        if 'FROM dex_files' in sql:
            return SimpleNamespace(columns=('file_id', 'entry_name'),
                rows=[{'file_id': '0', 'entry_name': 'classes.dex'}], total_rows=1)
        if 'zero' in sql:
            return SimpleNamespace(columns=('x',), rows=[], total_rows=0)
        return SimpleNamespace(columns=('x',), rows=[{'x': 'a'}, {'x': 'b'}], total_rows=2)


class Checks(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        def worker():
            asyncio.set_event_loop(self.loop)
            self.loop.call_soon(self.ready.set)
            self.loop.run_forever()
        self.thread = threading.Thread(target=worker)
        self.thread.start()
        self.assertTrue(self.ready.wait(5))
        self.adapter = Adapter()
        self.close_calls = []
        async def close():
            self.close_calls.append('close')
            return True
        self.session = HostlabCompactSession(ROOT / 'tests/fixtures/generated/structured-035.dex',
            self.adapter, self.loop, verify_inventory=lambda source, files: None,
            close_dataset=close, abort_transport=lambda: True)

    def tearDown(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.assertFalse(self.thread.is_alive())
        self.loop.close()

    def test_unstarted_query_prevents_success(self):
        with self.assertRaises(HostlabSessionError):
            with self.session:
                iterator = self.session.rows('SELECT x ORDER BY x')
        self.assertEqual(len(self.adapter.calls), 1)  # inventory only
        self.assertEqual(len(self.session.deliveries), 1)
        with self.assertRaises(HostlabSessionError):
            next(iterator)
        self.assertEqual(len(self.adapter.calls), 1)
        self.assertEqual(self.close_calls, ['close'])

    def test_unstarted_closed_iterator_still_prevents_success(self):
        with self.assertRaises(HostlabSessionError):
            with self.session:
                iterator = self.session.rows('SELECT x ORDER BY x')
                iterator.close()
        self.assertEqual(len(self.adapter.calls), 1)

    def test_consumed_and_zero_row_queries_complete(self):
        with self.session:
            self.assertEqual(list(self.session.rows('SELECT x ORDER BY x')),
                             [{'x': 'a'}, {'x': 'b'}])
            self.assertEqual(list(self.session.rows('SELECT zero ORDER BY zero')), [])
            self.assertEqual([item.row_count for item in self.session.deliveries], [1, 2, 0])
        self.assertEqual(self.close_calls, ['close'])

    def test_partial_consumption_prevents_success(self):
        with self.assertRaises(HostlabSessionError):
            with self.session:
                iterator = self.session.rows('SELECT x ORDER BY x')
                self.assertEqual(next(iterator), {'x': 'a'})
        iterator.close()
        self.assertEqual(len(self.session.deliveries), 1)


if __name__ == '__main__':
    unittest.main()
