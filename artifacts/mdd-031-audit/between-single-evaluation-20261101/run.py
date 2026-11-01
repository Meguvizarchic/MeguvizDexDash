"""Capture focused SQL checks and listed source identities, not qualification."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SOURCES = ['Cargo.lock', 'crates/mdd-sql/src/bridge.rs',
           'crates/mdd-sql/src/dialects/ast.rs', 'crates/mdd-sql/src/dialects/functions.rs',
           'crates/mdd-query/src/budget.rs', 'crates/mdd-facts/src/annotations.rs']


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def run(label, test_filter):
    directory = HERE / label
    directory.mkdir(exist_ok=False)
    command = ['cargo', 'test', '--locked', '-p', 'mdd-sql', test_filter, '--', '--nocapture']
    before = hashes()
    completed = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    after = hashes()
    (directory / 'output.txt').write_bytes(completed.stdout)
    (directory / 'record.json').write_text(json.dumps({'command': command, 'exit': completed.returncode,
        'listed_sources_before': before, 'listed_sources_after': after, 'listed_sources_stable': before == after,
        'scope': 'Focused synthetic tests only; not full SQL, A0/A1, HostLab or performance qualification.'},
        indent=2) + '\n', encoding='utf-8')
    print(label, 'exit', completed.returncode, 'sources stable', before == after)
    if completed.returncode or before != after:
        raise RuntimeError(f'{label} failed or sources changed')


if __name__ == '__main__':
    run('green', 'between_length')
    run('not-between-regression', 'not_between')
    run('q15-regression', 'hostlab_q15_descriptor_concat_order_matches_sqlite')
    run('length-regression', 'length_preserves_code_unit_and_legacy_scalar_semantics')
