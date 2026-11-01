"""Synthetic materialized-row diagnostics, not workload qualification."""
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('benchmark_runner', ROOT / 'benchmarks/run-existing-baselines.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ComparatorChecks(unittest.TestCase):
    def fixture(self, rows, mode='ordered'):
        item = runner.ContractTests().fixture()
        item['comparison_mode'] = mode
        item['final_dto']['rows'] = rows
        item['result']['response']['total_rows'] = str(len(rows))
        item['result']['response']['emitted_rows'] = str(len(rows))
        return item

    def compare(self, left, right):
        identity = runner.ContractTests().expected_identity()
        return runner.compare_complete_rows(left, right, ['fixture-occurrence'],
            'fixture-request', ['structure'], left_identity=identity, right_identity=identity)

    def test_equal_ordered_and_null_are_not_qualification(self):
        item = self.fixture([['a'], [None], ['a']])
        result = self.compare(item, copy.deepcopy(item))
        self.assertTrue(result['equal_under_codec'])
        self.assertIsNone(result['difference'])
        self.assertIs(result['qualification'], False)

    def test_ordered_difference_finds_cell(self):
        result = self.compare(self.fixture([['a'], ['b']]), self.fixture([['b'], ['a']]))
        self.assertEqual(result['difference'], {'kind': 'cell', 'row_index': 0,
                                                'column_index': 0, 'row_order': 'delivered'})

    def test_bag_preserves_duplicates_and_ignores_order(self):
        left = self.fixture([['a'], ['a'], ['b']], 'bag')
        self.assertTrue(self.compare(left, self.fixture([['b'], ['a'], ['a']], 'bag'))['equal_under_codec'])
        mismatch = self.compare(left, self.fixture([['a'], ['b'], ['b']], 'bag'))
        self.assertEqual(mismatch['difference']['kind'], 'cell')
        self.assertEqual(mismatch['difference']['row_order'], 'canonical_bag')

    def test_count_schema_and_context_are_not_silently_equal(self):
        self.assertEqual(self.compare(self.fixture([['a']]), self.fixture([['a'], ['b']]))['difference']['kind'], 'row_count')
        left = self.fixture([['a']]); right = copy.deepcopy(left)
        right['row_schema'][0]['type'] = 'other'
        self.assertEqual(self.compare(left, right)['difference']['kind'], 'row_schema')
        right = copy.deepcopy(left)
        right['result']['warnings'] = [{'layer': 'structure', 'reason': 'note', 'blocking': False}]
        self.assertEqual(self.compare(left, right)['difference']['kind'], 'result_context')

    def test_incomplete_side_is_rejected_before_comparison(self):
        left = self.fixture([['a']]); right = copy.deepcopy(left)
        right['result']['response']['more_available'] = True
        with self.assertRaises(ValueError):
            self.compare(left, right)

    def test_distinct_operations_cannot_compare_equal(self):
        left = self.fixture([['a']]); right = copy.deepcopy(left)
        right['result']['operation'] = 'inspect'
        identity = runner.ContractTests().expected_identity()
        right_identity = dict(identity, operation='inspect')
        result = runner.compare_complete_rows(left, right, ['fixture-occurrence'],
            'fixture-request', ['structure'], left_identity=identity, right_identity=right_identity)
        self.assertFalse(result['equal_under_codec'])
        self.assertEqual(result['difference'], {'kind': 'operation'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
