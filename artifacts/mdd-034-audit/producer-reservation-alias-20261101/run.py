"""Record one targeted cargo invocation; no performance qualification."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
FILES = ['Cargo.lock', 'crates/mdd-query/src/budget.rs', 'crates/mdd-query/src/budget/tests.rs',
         'crates/mdd-session/src/lib.rs', 'crates/mdd-session/src/cancellation.rs',
         'crates/mdd-facts/src/annotations.rs', 'crates/mdd-query/src/executor.rs']


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}


def main():
    if len(sys.argv) != 3 or not sys.argv[1].replace('_', '').isalnum():
        raise ValueError('expected new run directory and cargo test filter')
    output = Path(__file__).parent / sys.argv[1]
    output.mkdir(exist_ok=False)
    command = ['cargo', 'test', '--locked', '-p', 'mdd-query', sys.argv[2], '--', '--nocapture']
    before = hashes()
    run = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    after = hashes()
    (output / 'output.txt').write_bytes(run.stdout)
    (output / 'record.json').write_text(json.dumps({'command': command, 'exit': run.returncode,
        'listed_sources_before': before, 'listed_sources_after': after,
        'listed_sources_stable': before == after,
        'scope': 'targeted synthetic queue check; not production IPC or performance qualification'},
        indent=2) + '\n', encoding='utf-8')
    print(run.stdout.decode('utf-8', 'replace'))
    raise SystemExit(run.returncode)


if __name__ == '__main__':
    main()
