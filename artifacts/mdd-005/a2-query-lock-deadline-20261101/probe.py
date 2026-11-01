"""Synthetic query-lock deadline test, not a producer or A2 qualification."""
import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_compact_adapter import CompactRowsAdapter


class DeadlineChecks(unittest.IsolatedAsyncioTestCase):
    async def test_waiter_times_out_without_releasing_others_lock(self):
        adapter = CompactRowsAdapter(SimpleNamespace(), 'fixture',
            verify_source=lambda: None, verify_snapshot_binding=lambda _: None,
            verify_ordering=lambda *_: None, continuation_reason=lambda _: None, timeout=0.05)
        await adapter._lock.acquire()
        task = asyncio.create_task(adapter.result('SELECT x ORDER BY x'))
        try:
            await asyncio.sleep(0.2)
            self.assertTrue(task.done(), 'waiting query exceeded its deadline without returning')
            with self.assertRaises(TimeoutError):
                await task
            self.assertTrue(adapter._lock.locked(), 'waiting query released another owner lock')
            self.assertEqual(adapter.queries, 0)
            self.assertFalse(adapter._poisoned, 'a request not sent to producer poisoned the session')
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            adapter._lock.release()


if __name__ == '__main__':
    unittest.main(verbosity=2)
