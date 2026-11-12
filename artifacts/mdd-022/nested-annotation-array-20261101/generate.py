"""Generate two physical arrays, one nesting annotation -> array -> NULL/bool."""
import hashlib
import importlib.machinery
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[3]
generator = root / 'tests/fixtures/annotations/generate.py'
source = generator.read_text(encoding='utf-8')
replacements = {
    '        data.extend(b"\\0")':
        '        data.extend(bytes([1, 0x04, 0x2a]))',
    '        data.extend(bytes([1,0x17,255 if "orphan_bad_array" in features else sid["hello"]]))':
        '        data.extend(bytes([1, 0x1d, tid["Lfixture/Nested;"], 1, sid["value"], 0x1c, 2, 0x1e, 0x3f]))',
}
for old, new in replacements.items():
    if source.count(old) != 1:
        raise ValueError('fixture generator layout changed')
    source = source.replace(old, new)
# Stage the patched generator as a module file and import it: the derived
# source is executed from disk rather than compiled in-process.
with tempfile.TemporaryDirectory(prefix='nested-annotation-') as staging:
    staged = Path(staging) / 'fixture_generator.py'
    staged.write_text(source, encoding='utf-8', newline='\n')
    loader = importlib.machinery.SourceFileLoader('fixture_generator', str(staged))
    spec = importlib.util.spec_from_loader('fixture_generator', loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules['fixture_generator'] = module
    loader.exec_module(module)
    data, layout = module.build(['orphan_arrays'])
first, second = layout['labels']['empty_array'], layout['labels']['nonempty_array']
type_index, name_index = layout['type_indices']['Lfixture/Nested;'], layout['string_indices']['value']
if type_index >= 128 or name_index >= 128:
    raise ValueError('fixture uleb requires a single byte')
expected = bytes([1, 0x1d, type_index, 1, name_index, 0x1c, 2, 0x1e, 0x3f])
if data[first:first + 3] != b'\x01\x04\x2a' or data[second:second + len(expected)] != expected:
    raise ValueError('unexpected encoded bytes')
out = Path(__file__).parent
(out / 'nested.dex').write_bytes(data)
(out / 'fixture.json').write_text(json.dumps({
    'synthetic': True, 'first_array_offset': first, 'second_array_offset': second,
    'nested_type_index': type_index, 'element_name_index': name_index,
    'first_bytes_hex': '01042a', 'second_bytes_hex': expected.hex(),
    'sha256': hashlib.sha256(data).hexdigest(),
}, indent=2) + '\n', encoding='utf-8')
