"""Run one targeted SQL check and capture listed source identities."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
name, test = sys.argv[1:]
output = Path(__file__).parent / name
output.mkdir(exist_ok=False)
files = ['Cargo.lock', 'crates/mdd-sql/src/dialects/functions.rs',
         'crates/mdd-sql/src/values.rs', 'crates/mdd-sql/src/bridge.rs',
         'crates/mdd-sql/src/dialects/ast.rs', 'crates/mdd-sql/src/runtime_tests.rs',
         'crates/mdd-query/src/budget.rs', 'crates/mdd-query/src/executor.rs',
         'crates/mdd-query/src/executor/scoped.rs', 'crates/mdd-facts/src/annotations.rs']


def hashes():
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in files}


command = ['cargo', 'test', '--locked', '-p', 'mdd-sql', test, '--', '--nocapture']
before = hashes()
run = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(output / 'output.txt').write_bytes(run.stdout)
after = hashes()
(output / 'record.json').write_text(json.dumps({'command': command, 'exit': run.returncode,
    'listed_sources_before': before, 'listed_sources_after': after,
    'listed_sources_stable': before == after,
    'scope': 'targeted synthetic SQL check, listed sources only; no HostLab or performance qualification'},
    indent=2) + '\n', encoding='utf-8')
print('exit:', run.returncode, 'listed sources stable:', before == after)
print(run.stdout.decode('utf-8', errors='replace')[-4000:])
raise SystemExit(run.returncode)
