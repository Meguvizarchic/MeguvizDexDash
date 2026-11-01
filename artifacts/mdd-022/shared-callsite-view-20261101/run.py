"""Run one fact-level synthetic shared-call-site check and record identities."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
FILES = [
    'crates/mdd-facts/src/annotations.rs', 'crates/mdd-facts/src/definitions.rs',
    'crates/mdd-facts/src/metadata.rs', 'crates/mdd-dex/src/annotations.rs',
    'crates/mdd-dex/src/definitions.rs', 'tests/fixtures/annotations/generate.py',
    'artifacts/mdd-022/shared-callsite-view-20261101/generate.py',
    'artifacts/mdd-022/shared-callsite-view-20261101/shared.dex',
    'artifacts/mdd-022/shared-callsite-view-20261101/fixture.json', 'Cargo.lock',
]
def identities():
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in FILES}

before = identities()
cmd = ['cargo', 'test', '--locked', '-p', 'mdd-facts',
       'annotations::tests::shared_call_sites_retain_independent_identity_and_physical_bytes',
       '--', '--exact']
result = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(OUT / 'output.txt').write_bytes(result.stdout)
after = identities()
record = {'command': cmd, 'exit': result.returncode, 'listed_sources_before': before,
          'listed_sources_after': after, 'listed_sources_stable': before == after,
          'scope': 'Synthetic shared call-site array; no runtime bootstrap, ART, full format or performance qualification.'}
(OUT / 'record.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
if result.returncode or before != after:
    raise SystemExit(result.returncode or 1)
