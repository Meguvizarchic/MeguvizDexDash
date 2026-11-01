"""Synthetic source-column localization, not provenance qualification."""
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('benchmark_runner', ROOT / 'benchmarks/run-existing-baselines.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SourceChecks(unittest.TestCase):
    def fixture(self, rows, mode='ordered'):
        item = runner.ContractTests().fixture()
        item['comparison_mode'] = mode
        item['row_schema'] = [{'ordinal': 0, 'id': 'occurrence', 'type': 'utf8'},
                              {'ordinal': 1, 'id': 'payload', 'type': 'utf8'}]
        item['final_dto']['rows'] = rows
        item['result']['response']['total_rows'] = str(len(rows))
        item['result']['response']['emitted_rows'] = str(len(rows))
        return item

    def compare(self, left, right, sources=('occurrence',)):
        identity = runner.ContractTests().expected_identity()
        return runner.compare_complete_rows(left, right, ['fixture-occurrence'],
            'fixture-request', ['structure'], left_identity=identity, right_identity=identity,
            source_column_ids=sources)

    def test_cell_identifies_both_sources_and_unique_column(self):
        result = self.compare(self.fixture([['dex-A', 'old']]), self.fixture([['dex-A', 'new']]))
        self.assertEqual(result['difference'], {'kind': 'cell', 'row_index': 0, 'column_index': 1,
            'row_order': 'delivered', 'column_id': 'payload',
            'left_sources': {'occurrence': 'dex-A'}, 'right_sources': {'occurrence': 'dex-A'}})
        self.assertIs(result['qualification'], False)

    def test_bag_order_and_unmatched_row_sources(self):
        left = self.fixture([['dex-B', 'x'], ['dex-A', 'y']], 'bag')
        equal = self.fixture([['dex-A', 'y'], ['dex-B', 'x']], 'bag')
        self.assertTrue(self.compare(left, equal)['equal_under_codec'])
        missing = self.compare(left, self.fixture([['dex-A', 'y']], 'bag'))
        self.assertEqual(missing['difference']['kind'], 'row_count')
        self.assertEqual(missing['difference']['left_sources'], {'occurrence': 'dex-B'})
        self.assertNotIn('right_sources', missing['difference'])

    def test_source_columns_must_be_unique_and_present(self):
        left = self.fixture([['dex-A', 'x']]); right = copy.deepcopy(left)
        for sources in [('missing',), ('occurrence', 'occurrence'), ['occurrence']]:
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                self.compare(left, right, sources)
        for item in (left, right):
            item['row_schema'][1]['id'] = 'occurrence'
        with self.assertRaises(ValueError):
            self.compare(left, right)


if __name__ == '__main__':
    unittest.main(verbosity=2)
