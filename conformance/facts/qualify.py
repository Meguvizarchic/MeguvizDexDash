#!/usr/bin/env python3
"""Merge independent executed native-fact gates; compatibility projection admission stays separate.

Historical generator. It pins the source hashes of the frozen 2026-10-28 index component run
(`INDEX`) and the independent matrix `required-columns.json`, and asserts the 69 compatibility
projections that were unassembled then. It is meant to fail with `tested source drift` once
those sources move; ADR-017 keeps the file it wrote as the record of that bounded check, not as
proof of task completion. The current column state is derived from
`crates/mdd-facts/src/indexes/columns.rs` (all 156 assembled) and merged by
`artifacts/mdd-026/merge_evidence_clean.py`; re-issuing a qualification needs a new index run
and a new generator, not an edit of this one.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[2]
INDEX = 'artifacts/mdd-026/indexes/runs/20261028T141315875747Z/result.json'


def read(path):
    return json.loads((ROOT / path).read_text(encoding='utf-8'))


def identity(path):
    data = (ROOT / path).read_bytes()
    return dict(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    index = read(INDEX)
    require(index['passed'] and not index['profiles_admitted'], 'index gate not successful or profile overclaimed')
    for path, expected in index['source_sha256'].items():
        require(identity(path)['sha256'] == expected, 'tested source drift: ' + path)
    matrix_path = 'conformance/facts/required-columns.json'
    matrix = read(matrix_path)
    require(identity(matrix_path)['sha256'] == index['independent_matrix_sha256'], 'matrix differs')
    columns = [column for relation in matrix['relations'] for column in relation['columns']]
    require(matrix['relation_count'] == len(matrix['relations']) == 17
            and matrix['column_count'] == len(columns) == 156, 'required relation/column denominator changed')
    require(all(column['native_fact_availability'] == 'available_in_validated_declared_scope'
                and column['native_atoms'] for column in columns), 'required native atoms missing')
    missing = [dict(relation=relation['name'], column=column['name']) for relation in matrix['relations']
               for column in relation['columns'] if column['production_projection'] == 'unassembled_production_relation']
    require(len(missing) == index['checks']['unassembled_projection_columns'] == 69,
            'unassembled projections must remain explicit')
    readback_path = INDEX.rsplit('/', 1)[0] + '/readback.json'
    back = read(readback_path)
    require(back['passed'] and back['result_sha256'] == identity(INDEX)['sha256']
            and back['deliberately_invalid_oracle_payloads_rejected'] == 6, 'offline readback incomplete')
    diff_path = 'artifacts/mdd-026/facts-differential.json'
    diff = read(diff_path)
    comparisons = diff['complete_relation_comparisons']
    require(diff['native_fact_composition_checks_passed'] and diff['probe_cases'] == 8
            and diff['dex_occurrences'] == 9 and diff['indexed_scalar_target_checks'] == 331
            and len(comparisons) == 43 and all(item['complete_multiset_equal'] for item in comparisons),
            'independent layered fact differential incomplete')
    root_record_path = 'artifacts/mdd-026/root-reviewed-index-tests/record.json'
    root_record = read(root_record_path)
    require(root_record['exit_code'] == 0, 'current-root integration tests failed')
    output = ROOT / 'artifacts/mdd-026/root-reviewed-index-tests/stdout.txt'
    require(hashlib.sha256(output.read_bytes()).hexdigest() == root_record['stdout']['sha256'], 'root test output changed')
    require(re.search(r'test result: ok\. 11 passed; 0 failed; 0 ignored;', output.read_text()), 'root test count/status differs')
    report = dict(schema_version='mdd.hostlab-native-fact-qualification.v1', task='MDD-026',
                  created_utc=datetime.now(timezone.utc).isoformat(),
                  status='passed-native-atoms-index-and-scoped-coverage',
                  native_fact_scope_only=True, product_profile_admitted=False,
                  compatibility_projection_qualification=False, full_G1_admitted=False,
                  required_relations=17, required_columns=156,
                  unassembled_compatibility_projections=missing,
                  validation=dict(native_fact_scenarios=8, independent_dex_occurrences=9,
                                  indexed_scalar_target_checks=331, complete_relation_comparisons=43,
                                  candidate_predicates=index['checks']['predicates'],
                                  residual_candidate_cases=index['checks']['residual_false_positive_candidate_cases'],
                                  component_fact_unit_tests=35, compile_fail_tests=4,
                                  root_current_lock_index_tests=11, readback_negative_controls=6),
                  semantics=['explicit selected scope, source/DEX occurrence and immutable byte leases',
                             'UTF16 code-unit queries and raw MUTF8 remain separate',
                             'NULL, order and multiplicity checked with independent leaf oracles',
                             'input/facts Complete Partial Unknown recomputed; true failure dominates missing/unsupported',
                             'encoded parameter slots differ from proven prototype positions',
                             'code projection, all physical code, all method bodies and source positions differ',
                             'lazy index attempts retain one terminal; original waiters retain original errors',
                             'no runtime dispatch/inheritance inference or lossy UTF8 substitution'],
                  evidence=[identity(path) for path in [INDEX, readback_path, matrix_path, diff_path, root_record_path,
                            'artifacts/mdd-025/raw-evidence-conformance.json',
                            'artifacts/conformance/parser-safety/ci-readback.json']],
                  index_component_lock_sha256=index['lock_sha256'],
                  root_integration_lock=identity('Cargo.lock'),
                  lock_context='Root separately reran the 11 index tests after unrelated approved internal SQL/runtime dependency edges changed; all index sources and independent matrix match the frozen component run.',
                  not_qualified=['69 frozen relation projections remain unavailable, not NULL defaults',
                                 'full HostLab audit, SQL, interface or release profiles',
                                 'private full-facts corpus or formal performance',
                                 'current-index Linux until immutable feature-branch CI readback'],
                  rollback='Scope revert on review branch; retain original handoff and all failures; no default backend/deployment changed.')
    path = ROOT / 'conformance/manifests/hostlab-fact-qualification.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(status=report['status'], relations=17, columns=156,
                          compatibility_projections_missing=len(missing), profiles_admitted=False)))


if __name__ == '__main__':
    main()
