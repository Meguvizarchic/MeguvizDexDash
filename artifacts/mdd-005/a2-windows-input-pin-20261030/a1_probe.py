"""Fixed A1 opens a locked synthetic copy; no producer snapshot qualification."""
import hashlib
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_input_inventory import PinnedInputInventory
from a2_windows_input_pin import WindowsInputPin

directory = ROOT / 'artifacts/local' / ('input-pin-a1-' + uuid.uuid4().hex)
directory.mkdir(parents=True)
fixture = directory / 'sample.dex'
data = (ROOT / 'tests/fixtures/generated/structured-035.dex').read_bytes()
fixture.write_bytes(data)
source = PinnedInputInventory(fixture, hashlib.sha256(data).hexdigest())
reference = ROOT / 'artifacts/mdd-005/a2-compact-terminal-20261030/a1_probe.py'
text = reference.read_text(encoding='utf-8')
old = "(ROOT / 'tests/fixtures/generated/structured-035.dex').resolve(strict=True)"
if text.count(old) != 1:
    raise RuntimeError('fixed A1 probe fixture selector changed')
derived = text.replace(old, 'Path(' + repr(str(fixture)) + ').resolve(strict=True)')
print('derived_probe_sha256=' + hashlib.sha256(derived.encode('utf-8')).hexdigest(), flush=True)
with WindowsInputPin(source) as pin:
    exec(compile(derived, str(reference), 'exec'), {'__name__': '__main__', '__file__': str(reference)})
    pin.verify()
    try:
        fixture.open('r+b')
    except PermissionError:
        pass
    else:
        raise RuntimeError('input was writable while the A1 session pin remained held')
print('pin held across A1 probe; no snapshot or A2 qualification')
