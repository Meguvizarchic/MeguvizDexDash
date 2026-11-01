"""Create a synthetic Signature DEX with all four encoded member kinds."""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('annotation_generator', ROOT / 'tests/fixtures/annotations/generate.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
raw, layout = generator.build()
data = bytearray(raw)
offset = layout['labels']['class_data']
original = bytes([2, 0, 2, 0, 0, 9, 1, 9, 0, 0x89, 2, 0, 1, 0x89, 2, 0])
if data[offset:offset + len(original)] != original:
    raise ValueError('unexpected class_data fixture layout')
# Keep entry bytes and item extent stable, but split into static/instance and
# direct/virtual lists; native virtual methods remain valid with no code.
data[offset:offset + 4] = bytes([1, 1, 1, 1])
data[offset + 7] = 1
data[offset + 13] = 0x81
sealed = generator.seal(data)
directory = Path(__file__).parent
(directory / 'mixed-members.dex').write_bytes(sealed)
(directory / 'fixture.json').write_text(json.dumps({
    'synthetic': True, 'class_data_offset': offset,
    'sha256': hashlib.sha256(sealed).hexdigest(),
    'static_field': 0, 'instance_field': 1,
    'direct_method': 0, 'virtual_method': 1,
}, indent=2) + '\n', encoding='utf-8')
