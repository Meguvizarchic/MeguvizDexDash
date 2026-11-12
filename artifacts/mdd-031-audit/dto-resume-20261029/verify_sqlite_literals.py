#!/usr/bin/env python3
"""Append-only SQLite DTO baseline; never resumes a timed-out reference engine."""
import ast
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
OLD = ROOT / 'artifacts/mdd-031-audit/dto-type-observations'
ORIGIN = ROOT / 'artifacts/mdd-031/dto-origin-20261029/observation.json'
CAST = ROOT / 'artifacts/mdd-031-audit/cast-replay/qualification.json'
EXPECTED = {'integers', 'cast', 'arithmetic', 'case', 'comparison', 'cte'}


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode(value):
    if value is None:
        return {'type': 'null', 'value': None}
    if isinstance(value, int):
        return {'type': 'integer', 'value': str(value)}
    if isinstance(value, float):
        return {'type': 'real', 'f64_be_hex': struct.pack('>d', value).hex()}
    if isinstance(value, str):
        return {'type': 'text', 'value': value}
    if isinstance(value, bytes):
        return {'type': 'blob', 'hex': value.hex()}
    raise TypeError('unknown SQLite value')


def storage_class(value):
    """Storage class of a fetched value; the driver maps each class onto one
    Python type, so this needs no extra typeof() SQL probe."""
    if value is None:
        return 'null'
    if isinstance(value, int):
        return 'integer'
    if isinstance(value, float):
        return 'real'
    if isinstance(value, str):
        return 'text'
    if isinstance(value, bytes):
        return 'blob'
    raise TypeError('unknown SQLite value')


def main():
    require(len(sys.argv) == 2, 'usage: verify_sqlite_literals.py OUTPUT.json')
    target = Path(sys.argv[1]).resolve()
    require(target.is_relative_to(Path(__file__).resolve().parent) and not target.exists(),
            'output must be new and inside this evidence directory')
    reference_source = OLD / 'reference.py'
    source = ast.parse(reference_source.read_text(encoding='utf-8'))
    assignments = [n for n in source.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'SINGLE' for t in n.targets)]
    require(len(assignments) == 1, 'reference query list absent or ambiguous')
    queries = [(name, sql) for name, sql in ast.literal_eval(assignments[0].value) if name in EXPECTED]
    require(len(queries) == len(EXPECTED) and {name for name, _ in queries} == EXPECTED,
            'query denominator changed')
    previous = json.loads((OLD / 'sqlite-literals.json').read_text(encoding='utf-8'))
    prev = {row['id']: row for row in previous['records']}
    for name in ('integers', 'cast', 'case'):
        require(prev[name]['status'] == 'error' and 'nothing' in prev[name]['message'],
                'the recorded failed alias differs')
    origin = json.loads(ORIGIN.read_text(encoding='utf-8'))
    cast = json.loads(CAST.read_text(encoding='utf-8'))
    cast_stdout = json.loads(cast['stdout'])
    require(cast['exit_code'] == 0 and cast_stdout['numeric_matches'] == 54
            and cast_stdout['type_matches'] == 24 and cast_stdout['type_mismatches'] == 30
            and cast_stdout['dto_equivalent'] is False, 'cast reference scope differs')
    for engine in ('A0', 'A1'):
        cases = {x['id']: x for x in origin['examples'] if x['engine'] == engine}
        require(cases['empty']['reference_cell'] == {'type': 'uint64', 'value': '0'}
                and cases['string_0']['reference_cell'] == {'type': 'int64', 'value': '0'}
                and cases['empty']['reference_column']['data_type'] == 'sqlite_dynamic'
                and cases['string_0']['reference_column']['data_type'] == 'sqlite_dynamic',
                'reference zero counterexample differs')
        null = cases['null']
        require(null['reference_cell'] == {'type': 'null', 'value': None}
                and null['candidate_cell'] == {'type': 'null'}, 'null envelope differs')
        try:
            null['candidate_cell']['value']
        except KeyError:
            pass
        else:
            raise RuntimeError('missing candidate null value not observed')
    db = sqlite3.connect(':memory:')
    records = []
    try:
        for name, original_sql in queries:
            fixed = original_sql.replace(' AS nothing', ' AS "nothing"')
            require(fixed != original_sql if name in ('integers', 'cast', 'case') else fixed == original_sql,
                    'unexpected query rewrite')
            cursor = db.execute(fixed)
            names = [column[0] for column in cursor.description]
            rows = cursor.fetchall()
            classes = [list(storage_class(v) for v in row) for row in rows]
            records.append({'id': name, 'original_sql': original_sql, 'executed_sql': fixed,
                            'corrected_alias_only': fixed != original_sql, 'columns': names,
                            'rows': [[encode(v) for v in row] for row in rows],
                            'storage_classes': classes})
    finally:
        db.close()
    require(len(records) == 6 and all(record['rows'] for record in records), 'missing SQLite cases')
    report = {'schema_version': 'mdd.dto-sqlite-baseline.v1', 'status': 'sqlite-only-passed',
              'sqlite_version': sqlite3.sqlite_version, 'records': records,
              'source_sha256': {'reference_source': sha(reference_source),
                                'previous_sqlite_observation': sha(OLD / 'sqlite-literals.json'),
                                'dto_origin': sha(ORIGIN), 'cast_replay': sha(CAST),
                                'this_script': sha(Path(__file__))},
              'preserved_reference_timeout_runs': ['run-20261028T175409892480Z', 'run-20261028T175454131286Z'],
              'reference_runs_executed': 0, 'profile_admitted': False, 'dto_equivalent': False,
              'known_reference_differences': {'numeric_equal': 54, 'same_type': 24, 'different_type': 30,
                  'reference_null': {'type': 'null', 'value': None}, 'candidate_null': {'type': 'null'},
                  'consumer_uses_required_value_key': True},
              'limits': ['SQLite storage classes do not determine A0/A1 SDK integer tags',
                         'both timeout runs stopped at open_dataset; no query or final dataset list',
                         'source/column type and expression affinity remain unqualified',
                         'HostLab consumer and transport adapter are not exercised by this probe']}
    with target.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(report, f, ensure_ascii=True, indent=2)
        f.write('\n')
    print(json.dumps({'status': report['status'], 'sqlite_version': sqlite3.sqlite_version,
                      'cases': len(records), 'reference_runs_executed': 0,
                      'different_type': 30, 'dto_equivalent': False}))


if __name__ == '__main__':
    main()
