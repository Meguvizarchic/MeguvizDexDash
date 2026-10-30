"""Compare Rust's generated commitment with an independently read synthetic ZIP roster.

The snapshot identifier is observed from the Rust result, so this is not an
independent snapshot identity or coverage certificate.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from scope_commitment import ExpectedDex, ExpectedInput, verify_scope_preimage


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def output_directory(label):
    if not isinstance(label, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', label):
        raise ValueError('output directory must be a short lowercase label')
    base = Path(__file__).resolve(strict=True).parent
    destination = base / label
    if destination.parent.resolve(strict=True) != base:
        raise ValueError('output directory is outside evidence directory')
    return destination


def main():
    if len(sys.argv) != 2:
        raise ValueError('provide a new output directory name')
    destination = output_directory(sys.argv[1])
    destination.mkdir(exist_ok=False)
    fixture = ROOT / 'tests/fixtures/generated/multidex-stored.apk'
    files = ['Cargo.lock', 'crates/mdd-facts/examples/scope_commitment_export.rs',
             'crates/mdd-facts/src/indexes/scope.rs', 'crates/mdd-input/src/archive/mod.rs',
             'benchmarks/scope_commitment.py', 'artifacts/mdd-005/scope-verifier-20261030/cross_check.py',
             'tests/fixtures/generated/multidex-stored.apk']
    before = {name: sha(ROOT / name) for name in files}
    command = ['cargo', 'run', '-p', 'mdd-facts', '--example', 'scope_commitment_export',
               '--locked', '--offline', '--jobs', '1', '--',
               fixture.relative_to(ROOT).as_posix(), fixture.relative_to(ROOT).as_posix()]
    started = datetime.now(timezone.utc).isoformat()
    summary = {'command': command, 'started_utc': started,
               'exit_code': None, 'source_before': before,
               'scope': 'two synthetic APK occurrences; Rust snapshot ID observed, not independently authenticated'}
    try:
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired as error:
            (destination / 'rust.stdout').write_bytes(error.stdout or b'')
            (destination / 'rust.stderr').write_bytes(error.stderr or b'')
            raise
        except OSError:
            (destination / 'rust.stdout').write_bytes(b'')
            (destination / 'rust.stderr').write_bytes(b'')
            raise
        (destination / 'rust.stdout').write_bytes(result.stdout)
        (destination / 'rust.stderr').write_bytes(result.stderr)
        summary['exit_code'] = result.returncode
        summary['source_after'] = {name: sha(ROOT / name) for name in files}
        require(result.returncode == 0, 'Rust scope exporter failed')
        require(summary['source_before'] == summary['source_after'], 'listed source changed')
        result_json = json.loads(result.stdout)
        data = bytes.fromhex(result_json['preimage_hex'])
        archive_hash = 'sha256:' + sha(fixture)
        with zipfile.ZipFile(fixture) as archive:
            dexes = tuple(ExpectedDex('sha256:' + hashlib.sha256(archive.read(item)).hexdigest(),
                         ordinal, 0) for ordinal, item in enumerate(archive.infolist())
                         if re.fullmatch(r'classes\d*\.dex', item.filename))
        require(len(dexes) == 2, 'unexpected fixture DEX count')
        roster = tuple(ExpectedInput(index, archive_hash, 'top-level-classes-v1', dexes)
                       for index in range(2))
        args = dict(snapshot_id=result_json['snapshot_id'], expected_inputs=roster,
                    scope_id=result_json['scope_id'], scope_content_key=result_json['scope_content_key'],
                    captured_source_count=2, max_entries=4, max_bytes=65536)
        observation = verify_scope_preimage(data, **args)
        require(observation.input_count == 2 and observation.dex_count == 4, 'wrong verified counts')
        altered = (ExpectedInput(0, 'sha256:' + '0' * 64, 'top-level-classes-v1', dexes), roster[1])
        try:
            verify_scope_preimage(data, **dict(args, expected_inputs=altered))
        except ValueError:
            pass
        else:
            raise RuntimeError('changed trusted input digest was accepted')
        summary.update(status='passed', input_count=2, dex_count=4,
                       preimage_sha256=sha_bytes(data), negative_changed_input='rejected')
    except BaseException as error:
        summary.update(status='failed', error=repr(error))
        raise
    finally:
        if 'source_after' not in summary:
            summary['source_after'] = {name: sha(ROOT / name) for name in files}
        summary['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (destination / 'record.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': summary['status'], 'exit_code': summary['exit_code']}))


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


if __name__ == '__main__':
    main()
