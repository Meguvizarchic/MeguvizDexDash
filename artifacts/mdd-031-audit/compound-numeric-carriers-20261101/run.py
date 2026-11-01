"""Record targeted SQL check and listed source hashes; no profile qualification."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
files = ['Cargo.lock', 'crates/mdd-sql/src/bridge.rs', 'crates/mdd-sql/src/dialects/ast.rs',
         'crates/mdd-sql/src/dialects/functions.rs', 'crates/mdd-sql/src/values.rs',
         'crates/mdd-query/src/budget.rs', 'crates/mdd-facts/src/annotations.rs']
output = Path(__file__).parent / sys.argv[1]
output.mkdir(exist_ok=False)
def hashes():
    return {path: hashlib.sha256((ROOT/path).read_bytes()).hexdigest() for path in files}
before = hashes()
command = ['cargo', 'test', '--locked', '-p', 'mdd-sql',
           'compound_numeric_storage_classes_match_sqlite', '--', '--nocapture']
result = subprocess.run(command, cwd=ROOT, capture_output=True, check=False)
after = hashes()
(output/'stdout.txt').write_bytes(result.stdout)
(output/'stderr.txt').write_bytes(result.stderr)
(output/'record.json').write_text(json.dumps({'command': command, 'exit': result.returncode,
    'listed_sources_before':before,'listed_sources_after':after,'stable':before==after,
    'scope':'Synthetic SQLite comparison only; no HostLab or profile qualification.'},indent=2)+'\n',encoding='utf-8')
print('exit',result.returncode,'listed sources stable',before==after)
sys.exit(result.returncode)
