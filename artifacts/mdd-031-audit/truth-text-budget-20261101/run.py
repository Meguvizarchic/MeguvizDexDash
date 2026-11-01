"""Run focused text-truth checks; not HostLab or performance qualification."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FILES = ['Cargo.lock', 'crates/mdd-sql/src/bridge.rs', 'crates/mdd-sql/src/dialects/ast.rs',
         'crates/mdd-sql/src/dialects/functions.rs', 'crates/mdd-sql/src/control.rs',
         'crates/mdd-sql/src/values.rs', 'crates/mdd-sql/src/runtime_tests.rs',
         'crates/mdd-query/src/budget.rs', 'crates/mdd-session/src/cancellation.rs',
         'crates/mdd-facts/src/annotations.rs',
         'tests/fixtures/references/generated/nonscalar-string-035.dex']


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}


if len(sys.argv) != 3:
    raise SystemExit('usage: run.py unique-output-dir test-filter')
out = Path(__file__).parent / sys.argv[1]
out.mkdir(exist_ok=False)
command = ['cargo', 'test', '--locked', '-p', 'mdd-sql', sys.argv[2], '--', '--nocapture']
before = hashes()
process = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
after = hashes()
(out / 'output.txt').write_bytes(process.stdout)
(out / 'record.json').write_text(json.dumps({
    'command': command, 'exit': process.returncode, 'listed_sources_before': before,
    'listed_sources_after': after, 'listed_sources_stable': before == after,
    'scope': 'Synthetic SQL bridge; not full HostLab, performance or profile qualification.'
}, indent=2) + '\n', encoding='utf-8')
print(process.stdout.decode('utf-8', errors='replace'))
raise SystemExit(process.returncode)
