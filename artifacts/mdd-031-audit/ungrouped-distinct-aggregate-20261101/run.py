"""Record a focused SQL test; does not qualify HostLab or a SQL profile."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3]
name = sys.argv[1]
selector = sys.argv[2]
out = Path(__file__).parent / name
out.mkdir(exist_ok=False)
paths = ['Cargo.lock', 'crates/mdd-sql/src/bridge.rs', 'crates/mdd-sql/src/dialects/ast.rs',
         'crates/mdd-sql/src/dialects/functions.rs', 'crates/mdd-query/src/budget.rs',
         'crates/mdd-facts/src/annotations.rs']

def hashes():
    return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths}

command = ['cargo', 'test', '--locked', '-p', 'mdd-sql', selector, '--', '--nocapture']
before = hashes()
result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
after = hashes()
(out / 'output.txt').write_bytes(result.stdout)
record = {'command': command, 'exit': result.returncode, 'listed_sources_before': before,
          'listed_sources_after': after, 'listed_sources_stable': before == after,
          'scope': 'synthetic SQL comparison only; no HostLab, platform or profile qualification'}
(out / 'record.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
print(result.stdout.decode('utf-8', errors='replace'))
sys.exit(result.returncode)
