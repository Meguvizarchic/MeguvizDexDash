"""Record selected annotation tests; not format or performance qualification."""
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
    'crates/mdd-facts/src/metadata.rs',
    'crates/mdd-dex/src/annotations.rs',
    'tests/fixtures/annotations/generated/parameter-shared-signature.dex',
    'tests/fixtures/annotations/generated/parameter-shared-empty-set.dex',
    'tests/fixtures/annotations/generated/valid-orphan-annotation.dex',
]
commands = {
    'single': ['cargo', 'test', '--locked', '-p', 'mdd-facts',
               'annotations::tests::signature_physical_search_keeps_shared_empty_and_orphan_items',
               '--', '--exact', '--nocapture'],
    'signature': ['cargo', 'test', '--locked', '-p', 'mdd-facts', 'signature_', '--', '--nocapture'],
}


def identities():
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in FILES}


def main():
    name = sys.argv[1]
    output = Path(__file__).parent / name
    output.mkdir(exist_ok=False)
    before = identities()
    result = subprocess.run(commands[name], cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    after = identities()
    (output / 'output.txt').write_bytes(result.stdout)
    (output / 'record.json').write_text(json.dumps({
        'command': commands[name], 'exit': result.returncode,
        'listed_sources_before': before, 'listed_sources_after': after,
        'listed_sources_stable': before == after,
        'scope': 'Targeted synthetic annotations; no full format, ART, HostLab or performance qualification.'
    }, indent=2) + '\n', encoding='utf-8')
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
