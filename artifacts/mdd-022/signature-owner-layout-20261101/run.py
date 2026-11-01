"""Run one source-identified local Signature owner test."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / sys.argv[1]
OUT.mkdir(parents=True, exist_ok=False)
FILES = [
    'crates/mdd-facts/src/annotations.rs', 'crates/mdd-facts/src/definitions.rs',
    'crates/mdd-facts/src/metadata.rs', 'crates/mdd-dex/src/definitions.rs',
    'crates/mdd-dex/src/annotations.rs', 'Cargo.lock',
    'tests/fixtures/annotations/generate.py',
    'artifacts/mdd-022/signature-owner-layout-20261101/generate.py',
    'artifacts/mdd-022/signature-owner-layout-20261101/mixed-members.dex',
    'artifacts/mdd-022/signature-owner-layout-20261101/fixture.json',
]
COMMAND = ['cargo', 'test', '--locked', '-p', 'mdd-facts',
           'annotations::tests::signature_owner_lookup_keeps_member_kinds_and_rejects_bad_layout',
           '--', '--exact']


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}


before = hashes()
result = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, check=False)
after = hashes()
(OUT / 'output.txt').write_bytes(result.stdout + result.stderr)
(OUT / 'record.json').write_text(json.dumps({
    'command': COMMAND, 'exit': result.returncode,
    'listed_sources_before': before, 'listed_sources_after': after,
    'listed_sources_stable': before == after,
    'scope': 'Synthetic DEX and injected internal state only; not ART or full-format qualification.',
}, indent=2) + '\n', encoding='utf-8')
sys.exit(result.returncode)
