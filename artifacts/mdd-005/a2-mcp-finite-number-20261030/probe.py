"""Synthetic MCP JSON frame number checks; no transport qualification."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_mcp_transport import _check_json


class Checks(unittest.TestCase):
    def test_overflowed_json_float_is_rejected(self):
        for raw in (b'{"jsonrpc":"2.0","id":1e400}',
                    b'{"jsonrpc":"2.0","params":{"x":-1e400}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                _check_json(raw)

    def test_finite_and_other_invalid_json(self):
        self.assertEqual(_check_json(b'{"v":1e300}'), '{"v":1e300}')
        for raw in (b'{"v":NaN}', b'{"v":1,"v":2}', b'[]', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                _check_json(raw)


if __name__ == '__main__':
    unittest.main()
