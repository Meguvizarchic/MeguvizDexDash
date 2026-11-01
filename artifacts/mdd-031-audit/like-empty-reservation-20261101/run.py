"""Record focused SQL tests; this is not full profile qualification."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FILES = ['Cargo.lock', 'crates/mdd-sql/src/dialects/functions.rs',
         'crates/mdd-sql/src/runtime_tests.rs', 'crates/mdd-query/src/budget.rs',
         'crates/mdd-session/src/cancellation.rs', 'crates/mdd-facts/src/annotations.rs']


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: run.py <new-label> <test-filter>')
    directory = Path(__file__).parent / sys.argv[1]
    directory.mkdir(exist_ok=False)
    command = ['cargo', 'test', '--locked', '-p', 'mdd-sql', sys.argv[2], '--', '--nocapture']
    before = hashes()
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    after = hashes()
    (directory / 'output.txt').write_bytes(result.stdout)
    record = {'command': command, 'exit': result.returncode, 'listed_sources_before': before,
              'listed_sources_after': after, 'listed_sources_stable': before == after,
              'scope': 'targeted in-process SQL; no HostLab/profile or performance qualification'}
    (directory / 'record.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'exit': result.returncode, 'stable': before == after}))
    raise SystemExit(result.returncode)
