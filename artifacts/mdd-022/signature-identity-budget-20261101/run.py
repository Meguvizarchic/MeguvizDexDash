"""Record targeted Signature budget check, not full format qualification."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FILES = [
    'Cargo.lock',
    'crates/mdd-facts/src/annotations.rs',
    'crates/mdd-facts/src/definitions.rs',
    'crates/mdd-dex/src/annotations.rs',
    'tests/fixtures/annotations/generated/parameter-shared-signature.dex',
]


def identities():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}


def main():
    label = sys.argv[1]
    if label not in ('red', 'green', 'regression'):
        raise ValueError('unknown run label')
    folder = Path(__file__).parent / label
    folder.mkdir(exist_ok=False)
    name = ('signature_expansion_charges_every_retained_owner_identity'
            if label != 'regression' else 'shared_parameter_signature_keeps_method_and_unknown_encoded_slots_distinct')
    command = ['cargo', 'test', '--locked', '-p', 'mdd-facts', name, '--', '--nocapture']
    before = identities()
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    after = identities()
    (folder / 'output.txt').write_bytes(result.stdout)
    (folder / 'record.json').write_text(json.dumps({
        'command': command, 'exit': result.returncode,
        'listed_sources_before': before, 'listed_sources_after': after,
        'listed_sources_stable': before == after,
        'scope': 'targeted synthetic Signature budget; not full format qualification',
    }, indent=2) + '\n', encoding='utf-8')
    print(result.stdout.decode('utf-8', errors='replace'))
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
