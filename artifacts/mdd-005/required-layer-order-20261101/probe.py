"""Synthetic required-layer comparison; not a benchmark certificate."""
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('benchmark_runner', ROOT / 'benchmarks/run-existing-baselines.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class LayerChecks(unittest.TestCase):
    def fixture(self):
        item = runner.ContractTests().fixture()
        item['result']['coverage']['required_layers'] = ['inventory', 'structure']
        return item

    def compare(self, left, right):
        identity = runner.ContractTests().expected_identity()
        return runner.compare_complete_rows(left, right, ['fixture-occurrence'],
            'fixture-request', ['inventory', 'structure'], left_identity=identity, right_identity=identity)

    def test_layer_order_is_not_a_workload_difference(self):
        left = self.fixture(); right = copy.deepcopy(left)
        right['result']['coverage']['required_layers'].reverse()
        result = self.compare(left, right)
        self.assertTrue(result['equal_under_codec'])
        self.assertNotEqual(result['left_sha256'], result['right_sha256'])
        self.assertEqual(result['comparison_left_sha256'], result['comparison_right_sha256'])
        self.assertIs(result['qualification'], False)

    def test_other_context_difference_is_not_hidden(self):
        left = self.fixture(); right = copy.deepcopy(left)
        right['result']['coverage']['required_layers'].reverse()
        right['result']['warnings'] = [{'layer': 'structure', 'reason': 'note', 'blocking': False}]
        result = self.compare(left, right)
        self.assertFalse(result['equal_under_codec'])
        self.assertEqual(result['difference']['kind'], 'result_context')

    def test_each_digest_is_normalized_before_any_early_difference(self):
        left = self.fixture(); right = copy.deepcopy(left)
        left['result']['coverage']['required_layers'].reverse()
        right['result']['coverage']['required_layers'].reverse()
        left['final_dto']['rows'] = [['left']]
        right['final_dto']['rows'] = [['right']]
        for item in (left, right):
            item['result']['response']['total_rows'] = '1'
            item['result']['response']['emitted_rows'] = '1'
        normalized = copy.deepcopy(left)
        normalized['result']['coverage']['required_layers'].sort()
        expected = runner.consume(normalized, ['fixture-occurrence'], 'fixture-request',
            ['inventory', 'structure'], expected_identity=runner.ContractTests().expected_identity())
        result = self.compare(left, right)
        self.assertEqual(result['difference']['kind'], 'cell')
        self.assertNotEqual(result['left_sha256'], result['comparison_left_sha256'])
        self.assertEqual(result['comparison_left_sha256'], expected['canonical_sha256'])

    def test_missing_or_duplicate_layer_remains_rejected(self):
        left = self.fixture()
        for layers in (['inventory'], ['inventory', 'structure', 'inventory']):
            right = copy.deepcopy(left); right['result']['coverage']['required_layers'] = layers
            with self.subTest(layers=layers), self.assertRaises(ValueError):
                self.compare(left, right)


if __name__ == '__main__':
    unittest.main(verbosity=2)
