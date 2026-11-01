"""Synthetic native identity-roster checks; no input or audit qualification."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('benchmark_runner', ROOT / 'benchmarks/run-existing-baselines.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

EXPECTED = (('dex-A', 'method_reference', 0), ('dex-A', 'method_reference', 1),
            ('dex-B', 'method_reference', 0), ('dex-B', 'method_reference', 1))


class RosterChecks(unittest.TestCase):
    def fixture(self):
        case = json.loads((ROOT / 'tests/fixtures/query/cases.json').read_text(encoding='utf-8'))
        return copy.deepcopy(case['tables']['left']['rows']), copy.deepcopy(case['tables']['left']['columns'])

    def validate(self, rows, schema, roster=EXPECTED, limit=4):
        return runner.verify_native_typed_rows(rows, schema, expected_snapshot_id='fixture-snapshot',
            expected_occurrences=('dex-A', 'dex-B'), max_rows=100, max_cells=1000,
            max_variable_bytes=10000, expected_entities=roster, max_entities=limit)

    def test_membership_distinguishes_occurrence_and_entity_kind(self):
        rows, schema = self.fixture()
        self.assertTrue(self.validate(rows, schema)['entity_membership_checked'])
        for key, value in [('local_index', 2), ('kind', 'method_definition')]:
            bad = copy.deepcopy(rows); bad[0][2]['value'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'absent from trusted roster'):
                self.validate(bad, schema)
        with self.assertRaisesRegex(ValueError, 'absent from trusted roster'):
            self.validate(rows, schema, tuple(x for x in EXPECTED if x != ('dex-B', 'method_reference', 0)))

    def test_roster_shape_and_budget_are_strict(self):
        rows, schema = self.fixture()
        for roster, limit in [(EXPECTED, 3), (set(EXPECTED), 4),
                              ((('other', 'method_reference', 0),), 4),
                              ((('dex-A', 'method_reference', True),), 4),
                              ((('dex-A', 'method_reference', 1), ('dex-A', 'method_reference', True)), 4),
                              ((('dex-A', 'method_reference', 1), ('dex-A', 'method_reference', 1)), 4),
                              (EXPECTED, True)]:
            with self.subTest(roster=roster, limit=limit), self.assertRaises(ValueError):
                self.validate(rows, schema, roster, limit)
        baseline = runner.verify_native_typed_rows(rows, schema, expected_snapshot_id='fixture-snapshot',
            expected_occurrences=('dex-A','dex-B'), max_rows=100, max_cells=1000, max_variable_bytes=10000)
        self.assertFalse(baseline['entity_membership_checked'])
        self.assertIs(baseline['qualification'], False)

    def test_comparison_opt_in_validates_both_rosters(self):
        rows, schema = self.fixture(); item = runner.ContractTests().fixture()
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
                    'max_cells':1000, 'max_variable_bytes':10000,
                    'left_entities':EXPECTED, 'right_entities':EXPECTED, 'max_entities':4}

        def compare(cfg):
            return runner.compare_complete_rows(item, copy.deepcopy(item), ['fixture-occurrence'],
                'fixture-request', ['structure'], left_identity=identity, right_identity=identity,
                native_contract=cfg)

        result = compare(contract)
        self.assertTrue(result['equal_under_codec'])
        self.assertTrue(result['native_typed_validation']['left']['entity_membership_checked'])
        self.assertTrue(result['native_typed_validation']['right']['entity_membership_checked'])
        with self.assertRaises(ValueError): compare(dict(contract, right_entities=()))
        incomplete = dict(contract); del incomplete['left_entities']
        with self.assertRaises(ValueError): compare(incomplete)
        with self.assertRaises(ValueError): compare(dict(contract, left_entities=None))


if __name__ == '__main__':
    unittest.main(verbosity=2)
