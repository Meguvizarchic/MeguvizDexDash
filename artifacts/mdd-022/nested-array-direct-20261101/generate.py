"""Synthetic orphan array with one nested array containing NULL."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

root = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('annotation_fixture_generator',
                                              root / 'tests/fixtures/annotations/generate.py')
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
raw, layout = gen.build(['orphan_arrays'])
data = bytearray(raw)
array = layout['labels']['empty_array']
if layout['labels']['nonempty_array'] != array + 1:
    raise ValueError('physical arrays are not adjacent')
# Replace the two adjacent physical arrays with one array of equal byte size:
# [ array [ null ] ]. Keep section and following offsets unchanged.
data[array:array + 4] = bytes([1, 0x1c, 1, 0x1e])
map_off = layout['labels']['map']
count = struct.unpack_from('<I', data, map_off)[0]
found = 0
for index in range(count):
    at = map_off + 4 + index * 12
    kind, _, size, offset = struct.unpack_from('<HHII', data, at)
    if kind == 0x2005:
        if size != 2 or offset != array:
            raise ValueError('unexpected encoded array map')
        struct.pack_into('<I', data, at + 4, 1)
        found += 1
if found != 1:
    raise ValueError('encoded array map not unique')
data = gen.seal(data)
out = Path(__file__).parent
(out / 'nested.dex').write_bytes(data)
(out / 'fixture.json').write_text(json.dumps({'synthetic': True, 'array_offset': array,
    'bytes_hex': '011c011e', 'sha256': hashlib.sha256(data).hexdigest()}, indent=2) + '\n', encoding='utf-8')
