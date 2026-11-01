"""Record targeted aggregate bridge tests; never a SQL profile qualification."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3]
files = ['Cargo.lock', 'crates/mdd-sql/src/bridge.rs',
         'crates/mdd-sql/src/dialects/ast.rs', 'crates/mdd-sql/src/values.rs',
         'crates/mdd-query/src/budget.rs', 'crates/mdd-facts/src/annotations.rs']
run, filter_name = sys.argv[1:]
if run not in {'red', 'green', 'regression', 'distinct_regression'}:
    raise ValueError('unexpected run')
digest = lambda: {f: hashlib.sha256((root / f).read_bytes()).hexdigest() for f in files}
command = ['cargo', 'test', '--locked', '-p', 'mdd-sql', filter_name, '--', '--nocapture']
before = digest()
process = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
after = digest()
out = Path(__file__).parent / run
out.mkdir(exist_ok=False)
(out / 'output.txt').write_bytes(process.stdout)
(out / 'record.json').write_text(json.dumps({
    'command': command, 'exit': process.returncode, 'listed_sources_before': before,
    'listed_sources_after': after, 'listed_sources_stable': before == after,
    'scope': 'targeted synthetic SQLite comparison, no HostLab/A0/A1/profile qualification',
}, indent=2) + '\n', encoding='utf-8')
print(process.stdout.decode('utf-8', errors='replace'))
raise SystemExit(process.returncode)
