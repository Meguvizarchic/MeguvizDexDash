"""Synthetic v1 framing checks, plus optional Rust-export integration."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import subprocess
import cross_check
from cross_check import output_directory

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from scope_commitment import ExpectedDex, ExpectedInput, verify_scope_preimage
from snapshot_commitment import ExpectedSource, verify_snapshot_manifest
from capture_scope_binding import verify_capture_scope


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
    def test_snapshot_manifest_roster_identity_and_limits(self):
        content = 'sha256:' + 'a' * 64
        entries = (ExpectedSource(content, 12, 'raw-dex'),) * 2
        key_data = json.dumps(['capture-owned-v1', [[content, 'raw-dex']] * 2],
                              separators=(',', ':')).encode()
        key = 'sha256:' + hashlib.sha256(key_data).hexdigest()
        manifest = {'schema_version': 'mdd.snapshot.capture.v1', 'snapshot_id': 's',
                    'snapshot_content_key': key, 'capture_policy': 'owned-captured-bytes-v1',
                    'sources': [{'occurrence_id': f's:source:{i}', 'input_ordinal': str(i),
                        'content_id': content, 'byte_length': '12', 'input_kind': 'raw-dex'}
                        for i in range(2)], 'captured_input_bytes': '24', 'scope': 'test'}
        args = dict(expected_snapshot_id='s', expected_sources=entries,
                    max_sources=2, max_input_bytes=24)
        observation = verify_snapshot_manifest(manifest, **args)
        self.assertEqual((observation.source_count, observation.captured_input_bytes), (2, 24))
        for altered in (dict(args, max_sources=1), dict(args, max_input_bytes=23),
                        dict(args, expected_snapshot_id='other'),
                        dict(args, expected_sources=(entries[0], ExpectedSource(content, 13, 'raw-dex')))):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                verify_snapshot_manifest(manifest, **altered)
        for field, value in (('captured_input_bytes', '024'), ('snapshot_content_key', 'sha256:'+'0'*64)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_snapshot_manifest(dict(manifest, **{field: value}), **args)
        changed = dict(manifest, sources=list(reversed(manifest['sources'])))
        with self.assertRaises(ValueError):
            verify_snapshot_manifest(changed, **args)

    def test_scope_binds_to_the_corresponding_captured_occurrence(self):
        content = 'sha256:' + 'a' * 64
        other = 'sha256:' + 'c' * 64
        dex = ExpectedDex(content, None, 0)
        selected = (ExpectedInput(2, content, 'top-level-classes-v1', (dex,)),)
        body = b'mdd-selected-scope-v1' + framed((2).to_bytes(8, 'little'))
        body += framed(content.encode()) + framed(b'top-level-classes-v1')
        body += framed(content.encode()) + framed(((1 << 64)-1).to_bytes(8, 'little'))
        body += framed((0).to_bytes(8, 'little'))
        data = body + framed(b'snapshot-synthetic')
        scope = {'snapshot_id': 'snapshot-synthetic', 'expected_inputs': selected,
                 'scope_id': 'sha256:' + hashlib.sha256(data).hexdigest(),
                 'scope_content_key': 'sha256:' + hashlib.sha256(body).hexdigest()}
        sources = (ExpectedSource(other, 4, 'apk-zip'),
                   ExpectedSource(other, 4, 'apk-zip'),
                   ExpectedSource(content, 8, 'raw-dex'))
        items = [[s.content_id, s.input_kind] for s in sources]
        key = 'sha256:' + hashlib.sha256(json.dumps(['capture-owned-v1', items],
                     separators=(',', ':')).encode()).hexdigest()
        manifest = {'schema_version': 'mdd.snapshot.capture.v1',
                    'snapshot_id': scope['snapshot_id'], 'snapshot_content_key': key,
                    'capture_policy': 'owned-captured-bytes-v1',
                    'sources': [{'occurrence_id': f"{scope['snapshot_id']}:source:{i}",
                        'input_ordinal': str(i), 'content_id': item.content_id,
                        'byte_length': str(item.byte_length), 'input_kind': item.input_kind}
                        for i, item in enumerate(sources)],
                    'captured_input_bytes': '16', 'scope': 'synthetic'}
        args = dict(expected_snapshot_id=scope['snapshot_id'], expected_sources=sources,
                    expected_inputs=scope['expected_inputs'], scope_id=scope['scope_id'],
                    scope_content_key=scope['scope_content_key'], max_sources=3,
                    max_input_bytes=16, max_scope_entries=3, max_scope_bytes=4096)
        result = verify_capture_scope(manifest, data, **args)
        self.assertFalse(result.all_captured_sources_selected)
        self.assertEqual((result.captured_source_count, result.selected_input_count,
                          result.selected_dex_count), (3, 1, 1))
        mismatched = (ExpectedInput(2, other, 'top-level-classes-v1', scope['expected_inputs'][0].dexes),)
        with self.assertRaisesRegex(ValueError, 'captured source'):
            verify_capture_scope(manifest, data, **dict(args, expected_inputs=mismatched))

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

    def test_export_start_failure_and_timeout_are_recorded(self):
        failures = (OSError('synthetic launch failure'),
                    subprocess.TimeoutExpired(['cargo'], 300, output=b'partial', stderr=b'late'))
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(sys, 'argv', ['cross_check.py', 'synthetic']), \
                 patch.object(cross_check.subprocess, 'run', side_effect=failure), \
                 patch.object(Path, 'mkdir'), patch.object(Path, 'write_bytes') as binary, \
                 patch.object(Path, 'write_text') as record:
                with self.assertRaises(type(failure)):
                    cross_check.main()
                payload = json.loads(record.call_args.args[0])
                self.assertEqual(payload['status'], 'failed')
                self.assertIsNone(payload['exit_code'])
                self.assertIn(type(failure).__name__, payload['error'])
                self.assertEqual(binary.call_count, 2)
                if isinstance(failure, subprocess.TimeoutExpired):
                    self.assertEqual(binary.call_args_list[0].args[0], b'partial')
                    self.assertEqual(binary.call_args_list[1].args[0], b'late')


if __name__ == '__main__':
    unittest.main()
