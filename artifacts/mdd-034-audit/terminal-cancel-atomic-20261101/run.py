"""Record one bounded local Rust test with listed source identities."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
files = ['Cargo.lock', 'crates/mdd-query/src/budget.rs',
         'crates/mdd-query/src/budget/tests.rs', 'crates/mdd-session/src/cancellation.rs',
         'crates/mdd-session/src/lib.rs', 'crates/mdd-facts/src/annotations.rs']
directory = Path(__file__).parent / sys.argv[1]
name = sys.argv[2]
package = sys.argv[3] if len(sys.argv) > 3 else 'mdd-query'
directory.mkdir(exist_ok=False)


def identities():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files}


before = identities()
command = ['cargo', 'test', '--locked', '-p', package, name, '--', '--nocapture']
process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
after = identities()
(directory / 'output.txt').write_text(process.stdout + process.stderr, encoding='utf-8')
(directory / 'record.json').write_text(json.dumps({
    'command': command, 'exit': process.returncode, 'listed_sources_before': before,
    'listed_sources_after': after, 'listed_sources_stable': before == after,
    'scope': 'Targeted in-process queue behavior; no full concurrency, IPC or performance qualification.'
}, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'directory': directory.name, 'exit': process.returncode, 'stable': before == after}))
sys.exit(process.returncode)
