"""Fixed A1 lifecycle with locked synthetic input; no A2 qualification."""
import hashlib
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_dataset_lifecycle import A1DatasetLifecycle
from a2_input_inventory import PinnedInputInventory
from a2_windows_input_pin import WindowsInputPin

directory = ROOT / 'artifacts/local' / ('lifecycle-source-a1-' + uuid.uuid4().hex)
directory.mkdir(parents=True)
fixture = directory / 'sample.dex'
data = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()
fixture.write_bytes(data)
source = PinnedInputInventory(fixture, hashlib.sha256(data).hexdigest())
pin = WindowsInputPin(source)
reference = ROOT / 'artifacts/mdd-005/a2-compact-terminal-20261030/a1_probe.py'
text = reference.read_text(encoding='utf-8')
old_path = "(ROOT / 'tests/fixtures/generated/structured-035.dex').resolve(strict=True)"
old_open = """            opened = await client.call_tool('open_dataset', {'inputs': [str(fixture)]})
            require(opened.is_error is False and isinstance(opened.structured_content, dict), 'open failed')
            dataset = opened.structured_content.get('dataset_id')
            require(isinstance(dataset, str) and dataset, 'dataset id missing')"""
new_open = """            async def abort_owned():
                await owned.close()
                return owned.tree_empty_verified
            lifecycle_deadline = time.monotonic() + 20
            lifecycle = A1DatasetLifecycle(client, pinned_source,
                remaining_seconds=lambda: lifecycle_deadline - time.monotonic(),
                abort_owned_transport=abort_owned)
            opened = await lifecycle.__aenter__()
            dataset = opened.dataset_id"""
old_close = """            closer = A1ExclusiveDatasetCloser(client, dataset, remaining_seconds=lambda: 10)
            require(await closer.close() is True, 'close not confirmed')"""
new_close = """            await lifecycle.__aexit__(None, None, None)
            require(lifecycle.close_confirmed and lifecycle.source_confirmed, 'close or source unconfirmed')"""
if any(text.count(part) != 1 for part in (old_path, old_open, old_close)):
    raise RuntimeError('fixed A1 probe structure changed')
derived = text.replace(old_path, 'Path(' + repr(str(fixture)) + ').resolve(strict=True)')
derived = derived.replace(old_open, new_open).replace(old_close, new_close)
print('derived_probe_sha256=' + hashlib.sha256(derived.encode('utf-8')).hexdigest(), flush=True)
with pin:
    exec(compile(derived, str(reference), 'exec'), {'__name__': '__main__',
         '__file__': str(reference), 'A1DatasetLifecycle': A1DatasetLifecycle,
         'pinned_source': pin})
    pin.verify_source()
print('actual A1 lifecycle observed close and source; no snapshot or A2 qualification')
