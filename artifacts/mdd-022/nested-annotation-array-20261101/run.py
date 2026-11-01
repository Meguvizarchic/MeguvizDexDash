"""Run only the nested annotation regression with explicit source identities."""
import hashlib
import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
here = Path(__file__).resolve().parent
paths = [
    'crates/mdd-facts/src/annotations.rs', 'crates/mdd-facts/src/definitions.rs',
    'crates/mdd-facts/src/metadata.rs', 'crates/mdd-dex/src/annotations.rs',
    'crates/mdd-dex/src/definitions.rs', 'tests/fixtures/annotations/generate.py',
    'artifacts/mdd-022/nested-annotation-array-20261101/generate.py',
    'artifacts/mdd-022/nested-annotation-array-20261101/nested.dex',
    'artifacts/mdd-022/nested-annotation-array-20261101/fixture.json', 'Cargo.lock',
]


def hashes():
    return {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths}


cmd = ['cargo', 'test', '--locked', '-p', 'mdd-facts',
       'annotations::tests::nested_annotation_in_array_keeps_tree_and_cross_array_identity',
       '--', '--exact']
before = hashes()
result = subprocess.run(cmd, cwd=root, capture_output=True)
after = hashes()
(here / 'output.txt').write_bytes(result.stdout + result.stderr)
(here / 'record.json').write_text(json.dumps({
    'command': cmd, 'exit': result.returncode,
    'listed_sources_before': before, 'listed_sources_after': after,
    'listed_sources_stable': before == after,
    'scope': 'Synthetic physical arrays only; not ART or complete MDD-022 qualification.',
}, indent=2) + '\n', encoding='utf-8')
if result.returncode != 0 or before != after:
    raise SystemExit(1)
