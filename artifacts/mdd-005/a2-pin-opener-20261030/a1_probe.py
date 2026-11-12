"""Exercise the existing opener over a held Windows pin with fixed A1."""
import hashlib
from pathlib import Path
import runpy
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_input_inventory import PinnedInputInventory
from a2_windows_input_pin import WindowsInputPin
from a2_dataset_open import A1ExclusiveDatasetOpener

directory = ROOT / 'artifacts/local' / ('pin-opener-a1-' + uuid.uuid4().hex)
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
new_open = """            opened = await A1ExclusiveDatasetOpener(client, pinned_source, remaining_seconds=lambda: 10).open()
            dataset = opened.dataset_id"""
if text.count(old_path) != 1 or text.count(old_open) != 1:
    raise RuntimeError('fixed A1 probe structure changed')
derived = text.replace(old_path, 'Path(' + repr(str(fixture)) + ').resolve(strict=True)')
derived = derived.replace(old_open, new_open)
print('derived_probe_sha256=' + hashlib.sha256(derived.encode('utf-8')).hexdigest(), flush=True)
with pin:
    # Stage the derived probe as a file and run it as a module instead of
    # compiling source in-process.
    with tempfile.TemporaryDirectory(dir=reference.parent, prefix='derived-') as staging:
        staged = Path(staging) / 'a1_probe_derived.py'
        staged.write_text(derived, encoding='utf-8', newline='\n')
        runpy.run_path(str(staged), run_name='__main__', init_globals={
            'A1ExclusiveDatasetOpener': A1ExclusiveDatasetOpener,
            'pinned_source': pin,
        })
    pin.verify_source()
print('actual A1 opener used held pin; snapshot/order not proven')
