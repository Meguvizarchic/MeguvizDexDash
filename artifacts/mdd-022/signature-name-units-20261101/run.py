"""Record targeted Signature checks; no complete MDD-022 qualification."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
directory = Path(__file__).parent / sys.argv[1]
if directory.exists():
    raise SystemExit('refusing to overwrite an existing run')
directory.mkdir()
paths = [
    'crates/mdd-facts/src/annotations.rs',
    'crates/mdd-facts/src/definitions.rs',
    'crates/mdd-facts/src/metadata.rs',
    'crates/mdd-dex/src/annotations.rs',
    'crates/mdd-dex/src/strings.rs',
    'tests/fixtures/annotations/generate.py',
    'artifacts/mdd-022/signature-name-units-20261101/generate.py',
    'artifacts/mdd-022/signature-name-units-20261101/fixture.json',
    'artifacts/mdd-022/signature-name-units-20261101/valid.dex',
    'artifacts/mdd-022/signature-name-units-20261101/long-name.dex',
    'artifacts/mdd-022/signature-name-units-20261101/surrogate-name.dex',
    'Cargo.lock',
]

def hashes():
    return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}

before = hashes()
command = ['cargo', 'test', '--locked', '-p', 'mdd-facts', *sys.argv[2:]]
result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, check=False)
(directory / 'output.txt').write_bytes(result.stdout)
after = hashes()
(directory / 'record.json').write_text(json.dumps({
    'command': command,
    'exit': result.returncode,
    'listed_sources_before': before,
    'listed_sources_after': after,
    'listed_sources_stable': before == after,
    'scope': 'Synthetic Signature names; no complete format, ART or HostLab qualification.',
}, indent=2) + '\n', encoding='utf-8')
print(result.stdout.decode('utf-8', 'replace'), end='')
if before != after:
    raise SystemExit('listed sources changed during test')
raise SystemExit(result.returncode)
