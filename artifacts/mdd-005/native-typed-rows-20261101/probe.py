"""Native QueryIR wire validation with synthetic rows, not qualification."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('benchmark_runner', ROOT / 'benchmarks/run-existing-baselines.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class TypedRows(unittest.TestCase):
    def fixture(self):
        case = json.loads((ROOT / 'tests/fixtures/query/cases.json').read_text(encoding='utf-8'))
        return copy.deepcopy(case['tables']['left']['rows']), copy.deepcopy(case['tables']['left']['columns'])

    def check(self, rows, schema, **overrides):
        args = dict(expected_snapshot_id='fixture-snapshot', expected_occurrences=('dex-A', 'dex-B'),
                    max_rows=100, max_cells=1000, max_variable_bytes=10000)
        args.update(overrides)
        return runner.verify_native_typed_rows(rows, schema, **args)

    def test_hand_fixture_preserves_null_and_duplicates(self):
        rows, schema = self.fixture()
        result = self.check(rows, schema)
        self.assertEqual(result['validated_rows'], len(rows))
        self.assertEqual(result['validated_cells'], len(rows) * len(schema))
        self.assertIs(result['qualification'], False)

    def test_utf16_null_and_bytes_are_distinct(self):
        schema = [{'id':'s','display_name':'s','data_type':'utf16','nullable':True},
                  {'id':'b','display_name':'b','data_type':'bytes','nullable':True}]
        rows = [[{'type':'utf16','value':[0, 0xd800, 0xdc00, 0xdfff]}, {'type':'bytes','value':''}],
                [{'type':'null'}, {'type':'bytes','value':'AA=='}]]
        self.assertEqual(self.check(rows, schema)['logical_variable_bytes'], 9)
        for bad in ([True], [65536], [-1]):
            broken = copy.deepcopy(rows); broken[0][0]['value'] = bad
            with self.subTest(value=bad), self.assertRaises(ValueError): self.check(broken, schema)
        broken = copy.deepcopy(rows); broken[1][0] = {'type':'null','value':None}
        with self.assertRaises(ValueError): self.check(broken, schema)

    def test_numeric_types_and_boundaries(self):
        schema = [{'id':'b','display_name':'','data_type':'bool','nullable':False},
                  {'id':'i','display_name':'','data_type':'i64','nullable':False},
                  {'id':'u','display_name':'','data_type':'u64','nullable':False}]
        row = [{'type':'bool','value':True}, {'type':'i64','value':'-9223372036854775808'},
               {'type':'u64','value':'18446744073709551615'}]
        self.check([row], schema)
        for col, bad in [(0, 1), (1, '-0'), (1, '9223372036854775808'),
                         (2, '01'), (2, '18446744073709551616')]:
            broken = copy.deepcopy(row); broken[col]['value'] = bad
            with self.subTest(column=col, value=bad), self.assertRaises(ValueError):
                self.check([broken], schema)

    def test_entity_scope_and_base64_fail_closed(self):
        rows, schema = self.fixture()
        for key, bad in [('snapshot_id','other'), ('dex_occurrence_id','other'),
                         ('local_index',True), ('local_index', 1 << 32), ('kind','unknown')]:
            broken = copy.deepcopy(rows); broken[0][2]['value'][key] = bad
            with self.subTest(key=key, value=bad), self.assertRaises(ValueError):
                self.check(broken, schema)
        for bad in ('AB==','AA=A','!!!=', 'A==='):
            broken = copy.deepcopy(rows); broken[0][3]['value'] = bad
            with self.subTest(base64=bad), self.assertRaises(ValueError): self.check(broken, schema)

    def test_limits_type_and_schema(self):
        rows, schema = self.fixture()
        for bounds in ({'max_rows':len(rows)-1}, {'max_cells':len(rows)*len(schema)-1},
                       {'max_variable_bytes':0}, {'max_rows':True}):
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                self.check(rows, schema, **bounds)
        bad = copy.deepcopy(rows); bad[0][0] = {'type':'u64','value':'1'}
        with self.assertRaises(ValueError): self.check(bad, schema)
        bad = copy.deepcopy(schema); bad[1]['id'] = bad[0]['id']
        with self.assertRaises(ValueError): self.check(rows, bad)

    def test_opt_in_comparison_requires_trusted_schema_and_scope(self):
        rows, schema = self.fixture()
        item = runner.ContractTests().fixture()
        item['row_schema'] = [{'ordinal': i, 'id': col['id'], 'display_name': col['display_name'],
                               'type': col['data_type'], 'nullable': col['nullable']}
                              for i, col in enumerate(schema)]
        item['final_dto']['rows'] = rows
        item['result']['response']['emitted_rows'] = str(len(rows))
        item['result']['response']['total_rows'] = str(len(rows))
        item['result']['snapshot_id'] = 'fixture-snapshot'
        identity = dict(runner.ContractTests().expected_identity(), snapshot_id='fixture-snapshot')
        contract = {'schema':schema, 'left_occurrences':('dex-A','dex-B'),
                    'right_occurrences':('dex-A','dex-B'), 'max_rows':100,
                    'max_cells':1000, 'max_variable_bytes':10000}

        def compare(left, right, config):
            return runner.compare_complete_rows(left, right, ['fixture-occurrence'],
                'fixture-request', ['structure'], left_identity=identity, right_identity=identity,
                native_contract=config)

        result = compare(item, copy.deepcopy(item), contract)
        self.assertTrue(result['equal_under_codec'])
        self.assertEqual(result['native_typed_validation']['left']['validated_rows'], len(rows))
        self.assertIs(result['qualification'], False)
        wrong = copy.deepcopy(item); wrong['final_dto']['rows'][0][0]['type'] = 'u64'
        with self.assertRaises(ValueError): compare(item, wrong, contract)
        wrong = copy.deepcopy(item); wrong['row_schema'][0]['type'] = 'u64'
        with self.assertRaises(ValueError): compare(item, wrong, contract)
        scope = dict(contract, right_occurrences=('dex-A',))
        with self.assertRaises(ValueError): compare(item, item, scope)

        # Fail on a zero row budget before canonicalizing or sorting a row.
        limited = dict(contract, max_rows=0)
        original = runner.canonical

        def reject_row_work(value):
            if isinstance(value, list) and value == rows[0]:
                raise RuntimeError('row was canonicalized before native budget')
            if isinstance(value, dict) and 'final_dto' in value:
                raise RuntimeError('result was canonicalized before native budget')
            return original(value)

        with patch.object(runner, 'canonical', reject_row_work):
            with self.assertRaisesRegex(ValueError, 'row/cell budget'):
                compare(item, item, limited)
        failed = copy.deepcopy(item); failed['result']['operation_status'] = 'error'
        with self.assertRaisesRegex(ValueError, 'request failed'):
            compare(failed, item, limited)


if __name__ == '__main__':
    unittest.main(verbosity=2)
