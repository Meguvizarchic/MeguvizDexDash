"""Synthetic final-page deadline checks; no A2 qualification."""
import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_compact_adapter import CompactRowsAdapter, CompactAdapterError


def make(client):
    return CompactRowsAdapter(client, 'fixture', verify_source=lambda: None,
                              verify_snapshot_binding=lambda _: None,
                              verify_ordering=lambda *_: None,
                              continuation_reason=lambda _: None, timeout=20)


class DeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_page_decoding_expiry_is_rejected(self):
        client = SimpleNamespace()
        adapter = make(client)

        class Response:
            is_error = False
            content = []

            @property
            def structured_content(self):
                adapter._deadline = 0
                return {'dataset_id': 'fixture', 'statements': [{'kind': 'query',
                    'statement_index': 0, 'offset': 0, 'truncated': False,
                    'columns': ['x'], 'rows': [['61']], 'total_rows': 1,
                    'next_offset': None}]}

        async def call_tool(*_):
            return Response()

        client.call_tool = call_tool
        with self.assertRaises(TimeoutError):
            await adapter._page('SELECT x', 0, 1, 4096)

    async def test_final_page_expiry_never_returns_complete_rows(self):
        adapter = make(SimpleNamespace())
        calls = []

        async def page(*_):
            calls.append(1)
            if len(calls) == 1:
                return ['x'], [], 0, None
            adapter._deadline = 0
            return ['x'], [['61']], 1, None

        adapter._page = page
        with self.assertRaises(TimeoutError):
            await adapter.result('SELECT x ORDER BY x', page_size=1, max_page_bytes=4096)
        self.assertEqual(adapter.queries, 0)
        with self.assertRaises(CompactAdapterError):
            await adapter.result('SELECT x ORDER BY x', page_size=1, max_page_bytes=4096)


if __name__ == '__main__':
    unittest.main(verbosity=2)
