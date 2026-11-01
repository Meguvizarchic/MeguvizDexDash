"""Run a focused aggregate FILTER test; not a HostLab qualification."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3]
files = ['Cargo.lock', 'crates/mdd-sql/src/bridge.rs',
         'crates/mdd-sql/src/dialects/ast.rs', 'crates/mdd-sql/src/values.rs',
         'crates/mdd-query/src/budget.rs', 'crates/mdd-facts/src/annotations.rs']


def hashes():
    return {f: hashlib.sha256((root / f).read_bytes()).hexdigest() for f in files}


if len(sys.argv) != 2 or sys.argv[1] not in ('red', 'green', 'regression', 'final', 'numeric', 'final_regression'):
    raise SystemExit('expected red, green, regression, final, numeric or final_regression')
name = sys.argv[1]
test = ('aggregate_filter_truth_for_numeric_carriers_and_invalid_filter' if name == 'numeric'
        else 'distinct_aggregate_expressions_and_having_match_sqlite' if name in ('regression', 'final_regression')
        else 'aggregate_filter_truth_matches_sqlite_for_text_carriers')
command = ['cargo', 'test', '--locked', '-p', 'mdd-sql', test, '--', '--nocapture']
before = hashes()
process = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
after = hashes()
out = Path(__file__).parent / name
out.mkdir(exist_ok=False)
(out / 'output.txt').write_bytes(process.stdout)
(out / 'record.json').write_text(json.dumps({
    'command': command, 'exit': process.returncode, 'listed_sources_before': before,
    'listed_sources_after': after, 'listed_sources_stable': before == after,
    'scope': 'Synthetic bridge and SQLite truth comparison; not full HostLab or profile qualification.'
}, indent=2) + '\n', encoding='utf-8')
print(process.stdout.decode('utf-8', errors='replace'))
raise SystemExit(process.returncode)
