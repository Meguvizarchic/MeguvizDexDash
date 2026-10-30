"""One bounded synthetic check; not A2, HostLab or performance qualification."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import sys
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SOURCE = ROOT / 'benchmarks/a2_input_inventory.py'
REFERENCE = ROOT / 'artifacts/local/hostlab-reference/tools/hostlab'
REFERENCE_SHA = '8f40845d1328cae8a06dd29830c5e636d962da3cc72194e16904f6fb23030a64'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def expect_failure(operation, expected):
    try:
        operation()
    except expected:
        return
    raise RuntimeError('expected failure was not raised')


def main():
    require(sha(REFERENCE / 'analysis_batch.py') == REFERENCE_SHA,
            'fixed HostLab inventory source differs')
    spec = importlib.util.spec_from_file_location('a2_input_inventory', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.path.insert(0, str(REFERENCE))
    import analysis_batch

    directory = ROOT / 'artifacts/local/a2-input-inventory-probe' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    directory.mkdir(parents=True, exist_ok=False)
    archive = directory / 'synthetic.apk'
    with zipfile.ZipFile(archive, 'w') as output:
        output.writestr('classes.dex', b'synthetic one')
        output.writestr('classes2.dex', b'synthetic two')
        output.writestr('assets/ignored.txt', b'ignored')
    source_hash = sha(archive)
    guard = module.PinnedInputInventory(archive, source_hash)
    require(guard.physical_members == analysis_batch.archive_inventory(archive),
            'physical inventory differs from fixed HostLab')
    files = {1: 'classes.dex#0', 2: 'classes.dex#1', 3: 'classes2.dex'}
    analysis_batch.verify_inventory(analysis_batch.archive_inventory(archive), files)
    guard.verify_inventory(archive, files)
    expect_failure(lambda: guard.verify_inventory(archive, {1: 'classes.dex'}), module.InputInventoryError)
    expect_failure(lambda: guard.verify_inventory(archive, {True: 'classes.dex'}), module.InputInventoryError)

    duplicate = directory / 'duplicate.apk'
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(duplicate, 'w') as output:
            output.writestr('classes.dex', b'first')
            output.writestr('classes.dex', b'second')
    expect_failure(lambda: module.PinnedInputInventory(duplicate, sha(duplicate)), module.InputInventoryError)
    expect_failure(lambda: analysis_batch.archive_inventory(duplicate), ValueError)
    expect_failure(lambda: module.PinnedInputInventory(archive, source_hash, max_entries=1), module.InputInventoryError)
    expect_failure(lambda: module.PinnedInputInventory(archive, source_hash, max_dex_bytes=1), module.InputInventoryError)

    raw = directory / 'synthetic.dex'
    raw.write_bytes(b'synthetic raw dex; identity and inventory only')
    raw_guard = module.PinnedInputInventory(raw, sha(raw))
    require(raw_guard.physical_members is None and analysis_batch.archive_inventory(raw) is None,
            'raw dex must not claim archive inventory')
    raw_guard.verify_inventory(raw, {0: 'synthetic.dex'})
    raw.write_bytes(b'changed raw dex; identity and inventory only')
    expect_failure(raw_guard.verify_source, module.InputInventoryError)
    expect_failure(lambda: module.PinnedInputInventory(archive, '0' * 64), module.InputInventoryError)
    require(sha(REFERENCE / 'analysis_batch.py') == REFERENCE_SHA,
            'fixed HostLab inventory source changed')
    report = {'status': 'passed_scoped_synthetic_check', 'source_sha256': sha(SOURCE),
              'reference_sha256': REFERENCE_SHA, 'synthetic_archive_sha256': source_hash,
              'checks': ['fixed_inventory_match', 'logical_suffix_match', 'missing_member',
                         'invalid_file_id', 'duplicate_member', 'entry_budget', 'dex_byte_budget',
                         'raw_dex_archive_not_claimed', 'source_mutated', 'wrong_sha'],
              'scope': 'local synthetic input inventory only; no producer snapshot, A2 or performance qualification'}
    (HERE / 'record.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf8', newline='\n')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
