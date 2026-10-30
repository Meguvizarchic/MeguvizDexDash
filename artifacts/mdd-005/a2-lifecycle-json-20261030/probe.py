"""Synthetic lifecycle agreement checks; not an A2 qualification."""
import asyncio
import json
import sys
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_dataset_close import A1ExclusiveDatasetCloser, DatasetCloseError, _payload
from a2_dataset_open import A1ExclusiveDatasetOpener, DatasetOpenError


def response(structured, text=None):
    return SimpleNamespace(is_error=False, structured_content=structured,
                           content=[] if text is None else [SimpleNamespace(text=text)])


class Checks(unittest.TestCase):
    def test_text_boolean_is_not_integer(self):
        with self.assertRaises(DatasetCloseError):
            _payload(response({'closed': True}, '{"closed":1}'), 'close_dataset')
        with self.assertRaises(DatasetCloseError):
            _payload(response({'nested': [1.0]}, '{"nested":[1]}'), 'open_dataset')

    def test_nested_readback_different_type_is_not_same_receipt(self):
        source = SimpleNamespace(path=(ROOT / 'tests/fixtures/generated/structured-035.dex').resolve(),
                                 verify_source=lambda: None)
        opened = {'dataset_id': 'sample', 'inputs': [str(source.path)], 'has_dex': True,
                  'input_bytes': 536, 'prepare_ms': 1.0, 'extra': {'count': 1}}
        class Client:
            def __init__(self):
                self.count = 0
            async def call_tool(self, name, args):
                if name == 'open_dataset':
                    return response(opened)
                self.count += 1
                dataset = dict(opened, extra={'count': True})
                return response({'datasets': [] if self.count == 1 else [dataset],
                    'admitted_requests': 0, 'running_requests': 0,
                    'usage': {'datasets': 0 if self.count == 1 else 1,
                              'input_bytes': 0 if self.count == 1 else 536}})
        async def run():
            opener = A1ExclusiveDatasetOpener(Client(), source, remaining_seconds=lambda: 10)
            with self.assertRaises(DatasetOpenError):
                await opener.open()
            self.assertTrue(opener.abort_required)
        asyncio.run(run())

    def test_matching_text_and_structured_are_accepted(self):
        value = {'closed': True, 'nested': [None, 4, 1.5, 'ok']}
        self.assertEqual(_payload(response(value, json.dumps(value)), 'close_dataset'), value)

    def test_invalid_structured_json_is_rejected(self):
        cycle = []
        cycle.append(cycle)
        for value in ({'x': float('nan')}, {'x': {1: 'non-text key'}},
                      {'x': (1, 2)}, {'x': cycle}):
            with self.subTest(value=value), self.assertRaises(DatasetCloseError):
                _payload(response(value), 'close_dataset')
        with self.assertRaises(DatasetCloseError):
            _payload(response(None, '{"x":1e400}'), 'close_dataset')
        # The parser's actual depth limit varies by interpreter; explicitly
        # inject its recursion failure to check error translation.
        with patch('a2_dataset_close.json.loads', side_effect=RecursionError('injected')):
            with self.assertRaises(DatasetCloseError):
                _payload(response(None, '{}'), 'close_dataset')

    def test_close_rejects_disagreement_before_idle_readback(self):
        class Client:
            def __init__(self):
                self.calls = []
            async def call_tool(self, name, args):
                self.calls.append(name)
                return response({'closed': True, 'dataset_id': 'sample'},
                                '{"closed":1,"dataset_id":"sample"}')
        async def run():
            client = Client()
            closer = A1ExclusiveDatasetCloser(client, 'sample', remaining_seconds=lambda: 10)
            with self.assertRaises(DatasetCloseError):
                await closer.close()
            self.assertEqual(client.calls, ['close_dataset'])
        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
