"""Create synthetic Signature name variants without changing section layout."""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('annotation_fixture_generator',
    ROOT / 'tests/fixtures/annotations/generate.py')
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
raw, layout = gen.build()
out = Path(__file__).parent
index = layout['string_indices']['value']
other = layout['string_indices']['v_infinity_float']
item_at = layout['labels']['class_signature']
string_at = layout['string_offsets']['value']
if raw[item_at:item_at + 4] != bytes([2, 1, 1, index]):
    raise ValueError('unexpected signature fixture encoding')
if raw[string_at:string_at + 7] != b'\x05value\x00':
    raise ValueError('unexpected value string encoding')

valid = raw
other_name = bytearray(raw)
other_name[item_at + 3] = other
other_name = gen.seal(other_name)
surrogate = bytearray(raw)
# v + lone high surrogate + e remains between v_infinity_float and w...;
# its encoded byte length remains unchanged and the UTF-16 length is 3.
surrogate[string_at:string_at + 7] = b'\x03v\xed\xa0\x80e\x00'
surrogate = gen.seal(surrogate)
cases = {'valid.dex': valid, 'long-name.dex': other_name, 'surrogate-name.dex': surrogate}
for name, data in cases.items():
    (out / name).write_bytes(data)
(out / 'fixture.json').write_text(json.dumps({
    'synthetic': True,
    'signature_byte_offset': item_at,
    'name_string_index': index,
    'long_name_string_index': other,
    'long_name': 'v_infinity_float',
    'surrogate_name_utf16': [0x76, 0xd800, 0x65],
    'sha256': {name: hashlib.sha256(data).hexdigest() for name, data in cases.items()},
}, indent=2) + '\n', encoding='utf-8')
