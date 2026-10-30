"""Synthetic v1 framing checks, plus optional Rust-export integration."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from cross_check import output_directory

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from scope_commitment import ExpectedDex, ExpectedInput, verify_scope_preimage


def framed(value):
    return len(value).to_bytes(8, 'little') + value


def fixture():
    snapshot = 'snapshot-synthetic'
    input_id = 'sha256:' + 'a' * 64
    dex_id = 'sha256:' + 'b' * 64
    inputs = (ExpectedInput(2, input_id, 'top-level-classes-v1',
              (ExpectedDex(dex_id, 3, 0), ExpectedDex(dex_id, None, 64))),)
    body = b'mdd-selected-scope-v1' + framed((2).to_bytes(8, 'little'))
    body += framed(input_id.encode()) + framed(b'top-level-classes-v1')
    body += framed(dex_id.encode()) + framed((3).to_bytes(8, 'little')) + framed((0).to_bytes(8, 'little'))
    body += framed(dex_id.encode()) + framed(((1 << 64)-1).to_bytes(8, 'little')) + framed((64).to_bytes(8, 'little'))
    preimage = body + framed(snapshot.encode())
    return preimage, dict(snapshot_id=snapshot, expected_inputs=inputs,
        scope_id='sha256:' + hashlib.sha256(preimage).hexdigest(),
        scope_content_key='sha256:' + hashlib.sha256(body).hexdigest(),
        captured_source_count=3, max_entries=3, max_bytes=4096)


class Checks(unittest.TestCase):
    def test_expected_roster_and_hashes(self):
        data, args = fixture()
        result = verify_scope_preimage(data, **args)
        self.assertEqual((result.input_count, result.dex_count), (1, 2))
        self.assertEqual(result.scope_id, args['scope_id'])

    def test_rejects_tamper_limits_and_other_roster(self):
        data, args = fixture()
        bad = bytearray(data); bad[40] ^= 1
        for changed, values in ((bytes(bad), args), (data[:-1], args), (data + b'x', args),
                                (data, dict(args, max_entries=2)), (data, dict(args, max_bytes=len(data)-1)),
                                (data, dict(args, captured_source_count=2)),
                                (data, dict(args, snapshot_id='another')),
                                (data, dict(args, scope_id='sha256:' + '0'*64)),
                                (data, dict(args, scope_content_key='sha256:' + '0'*64)),
                                (data, dict(args, expected_inputs=(ExpectedInput(2, 'sha256:'+'a'*64,
                                    'top-level-classes-v1', (ExpectedDex('sha256:'+'b'*64, 4, 0),)),)))):
            with self.subTest(values=values), self.assertRaises(ValueError):
                verify_scope_preimage(changed, **values)

    def test_rejects_boolean_and_duplicate_ordinals(self):
        data, args = fixture()
        for roster in ((ExpectedInput(True, 'sha256:'+'a'*64, 'top-level-classes-v1', ()),),
                       (ExpectedInput(0, 'sha256:'+'a'*64, 'top-level-classes-v1', ()),
                        ExpectedInput(0, 'sha256:'+'a'*64, 'top-level-classes-v1', ()))):
            with self.subTest(roster=roster), self.assertRaises(ValueError):
                verify_scope_preimage(data, **dict(args, expected_inputs=roster))

    def test_empty_input_roster_is_not_a_constructible_selected_scope(self):
        snapshot = 'snapshot'
        body = b'mdd-selected-scope-v1'
        data = body + framed(snapshot.encode())
        with self.assertRaises(ValueError):
            verify_scope_preimage(data, snapshot_id=snapshot, expected_inputs=(),
                scope_id='sha256:' + hashlib.sha256(data).hexdigest(),
                scope_content_key='sha256:' + hashlib.sha256(body).hexdigest(),
                captured_source_count=0, max_entries=0, max_bytes=len(data))

    def test_output_directory_rejects_paths(self):
        for label in ('', '.', '..', '../other', 'a/b', r'a\b', r'C:\outside',
                      r'\\server\share', 'é', 'a' * 65):
            with self.subTest(label=label), self.assertRaises(ValueError):
                output_directory(label)
        self.assertEqual(output_directory('run-2').parent, Path(__file__).resolve().parent)


if __name__ == '__main__':
    unittest.main()
