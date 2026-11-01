"""Record one targeted queue check; no IPC or exhaustive race qualification."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
name, test = sys.argv[1:3]
package = sys.argv[3] if len(sys.argv) == 4 else 'mdd-query'
output = Path(__file__).parent / name
output.mkdir(exist_ok=False)
paths = ['Cargo.lock', 'crates/mdd-query/src/budget.rs',
         'crates/mdd-query/src/budget/tests.rs', 'crates/mdd-session/src/cancellation.rs',
         'crates/mdd-session/src/lib.rs', 'crates/mdd-facts/src/annotations.rs']

def hashes():
    return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths}

command = ['cargo', 'test', '--locked', '-p', package, test, '--', '--nocapture']
before = hashes()
run = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
after = hashes()
(output / 'output.txt').write_bytes(run.stdout)
(output / 'record.json').write_text(json.dumps({'command': command, 'exit': run.returncode,
    'listed_sources_before': before, 'listed_sources_after': after,
    'listed_sources_stable': before == after,
    'scope': 'controlled query queue scenario; no full concurrency, IPC or performance qualification'},
    indent=2) + '\n', encoding='utf-8')
sys.stdout.buffer.write(run.stdout)
raise SystemExit(run.returncode)
