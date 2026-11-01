"""Record a bounded SQL test and identities; no profile qualification."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3]
name, test = sys.argv[1:]
target = Path(__file__).parent / name
target.mkdir(exist_ok=False)
files = [
    'Cargo.lock',
    'crates/mdd-sql/src/bridge.rs',
    'crates/mdd-sql/src/dialects/ast.rs',
    'crates/mdd-sql/src/values.rs',
    'crates/mdd-query/src/budget.rs',
    'crates/mdd-facts/src/annotations.rs',
]

def hashes():
    return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in files}

command = ['cargo', 'test', '--locked', '-p', 'mdd-sql', test, '--', '--nocapture']
before = hashes()
result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
after = hashes()
(target / 'output.txt').write_bytes(result.stdout)
(target / 'record.json').write_text(json.dumps({
    'command': command, 'exit': result.returncode,
    'listed_sources_before': before, 'listed_sources_after': after,
    'listed_sources_stable': before == after,
    'scope': 'synthetic SQL comparison, listed sources only; no profile, HostLab, or performance qualification',
}, indent=2) + '\n', encoding='utf-8')
sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
