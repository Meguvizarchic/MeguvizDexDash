"""Record scoped-catalog targeted checks; no profile or performance qualification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', sys.argv[1]):
        raise ValueError('provide a short output label')
    label = sys.argv[1]
    destination = BASE / label
    raw = ROOT / 'artifacts' / 'local' / 'scoped-catalog-raw-20261101' / label
    destination.mkdir(exist_ok=False)
    raw.mkdir(parents=True, exist_ok=False)
    files = [
        'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
        'crates/mdd-query/src/executor.rs', 'crates/mdd-query/src/executor/scoped.rs',
        'crates/mdd-query/src/executor/facts.rs', 'crates/mdd-query/src/budget.rs',
        'crates/mdd-facts/src/coverage.rs', 'crates/mdd-facts/src/indexes/scope.rs',
        'crates/mdd-facts/src/indexes/views.rs', 'crates/mdd-facts/src/references.rs',
        'crates/mdd-input/src/snapshot/mod.rs', 'crates/mdd-input/src/archive/mod.rs',
        'crates/mdd-session/src/lib.rs', 'crates/mdd-session/src/cancellation.rs',
        'tests/fixtures/generated/minimal-035.dex',
        'tests/fixtures/generated/multidex-deflated.apk',
        'tests/fixtures/references/generated/poly-custom-038.dex',
    ]
    before = {name: digest(ROOT / name) for name in files}
    record = {'source_before': before, 'runs': [], 'scope':
        'synthetic selected roster and JSON delivery only; listed sources; not independent acquisition, HostLab or profile qualification'}
    filters = ['executor::scoped::tests', 'json_batches_execute_multiple_rows_and_bind_delivery',
               'json_batches_zero_partial_and_limits_never_fake_complete']
    try:
        for index, name in enumerate(filters):
            command = ['cargo', 'test', '-p', 'mdd-query', '--locked', '--offline', '--jobs', '1', name, '--', '--nocapture']
            started = datetime.now(timezone.utc).isoformat()
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=300)
            for suffix, contents in [('stdout', result.stdout), ('stderr', result.stderr)]:
                (raw / f'{index}.{suffix}').write_bytes(contents)
                (destination / f'{index}.{suffix}').write_bytes(contents.replace(str(ROOT).encode(), b'<workspace>'))
            record['runs'].append({'command': command, 'started_utc': started,
                'finished_utc': datetime.now(timezone.utc).isoformat(), 'exit_code': result.returncode,
                'raw_stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
                'raw_stderr_sha256': hashlib.sha256(result.stderr).hexdigest(),
                'redaction': 'workspace path replaced; raw output retained under ignored local evidence'})
            if result.returncode != 0:
                break
    finally:
        record['source_after'] = {name: digest(ROOT / name) for name in files}
        (destination / 'record.json').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'exit_codes': [run['exit_code'] for run in record['runs']]}))
    return int(any(run['exit_code'] != 0 for run in record['runs']))


if __name__ == '__main__':
    raise SystemExit(main())
