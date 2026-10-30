"""Synthetic compact-page terminal checks; no A2 qualification."""
import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_compact_adapter import CompactAdapterError, CompactRowsAdapter


class Client:
    def __init__(self, *, fault=None):
        self.calls = 0
        self.fault = fault

    async def call_tool(self, tool, args):
        self.calls += 1
        shape = self.calls == 1
        item = {'kind': 'query', 'statement_index': 0, 'offset': 0,
                'truncated': False, 'columns': ['x'],
                'rows': [] if shape else [['41']], 'total_rows': 0 if shape else 1,
                'next_offset': None}
        status = False
        content = []
        if not shape:
            if self.fault == 'missing_cursor':
                del item['next_offset']
            elif self.fault == 'boolean_index':
                item['statement_index'] = False
            elif self.fault == 'absent_status':
                status = None
            elif self.fault == 'absent_content':
                content = None
        return SimpleNamespace(is_error=status, content=content,
                               structured_content={'dataset_id': 'sample', 'statements': [item]})


def adapter(client):
    # These checks are deliberately synthetic and do not certify a snapshot or order.
    return CompactRowsAdapter(client, 'sample', verify_source=lambda: None,
        verify_snapshot_binding=lambda dataset: None, verify_ordering=lambda a, b: None,
        continuation_reason=lambda sql: None, timeout=10)


class Checks(unittest.TestCase):
    def test_valid_complete_query(self):
        async def run():
            query = adapter(Client())
            result = await query.result('SELECT x FROM t ORDER BY x')
            self.assertEqual(result.rows, [{'x': 'A'}])
            self.assertEqual(result.total_rows, 1)
            self.assertEqual(query.queries, 1)
        asyncio.run(run())

    def test_unknown_terminal_or_index_never_becomes_success(self):
        async def run(fault):
            query = adapter(Client(fault=fault))
            with self.assertRaises(CompactAdapterError):
                await query.result('SELECT x FROM t ORDER BY x')
            self.assertEqual(query.queries, 0)
            with self.assertRaises(CompactAdapterError):
                await query.result('SELECT x FROM t ORDER BY x')
        for fault in ('missing_cursor', 'boolean_index', 'absent_status', 'absent_content'):
            with self.subTest(fault=fault):
                asyncio.run(run(fault))


if __name__ == '__main__':
    unittest.main()
