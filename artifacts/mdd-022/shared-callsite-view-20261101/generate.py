"""Create a synthetic DEX with two call_site_ids sharing one encoded array."""
import hashlib
import json
import struct
from pathlib import Path

root = Path(__file__).resolve().parents[3]
source = root / 'tests/fixtures/annotations/generate.py'
text = source.read_text(encoding='utf-8')
changes = {
    'map_entries.append((7,1,len(data)))': 'map_entries.append((7,2,len(data)))',
    'data.extend(b"\\0"*4)': 'data.extend(b"\\0"*8)',
    'struct.pack_into("<I",data,labels["call_site_ids"],labels["call_site_array"])':
        'struct.pack_into("<II",data,labels["call_site_ids"],labels["call_site_array"],labels["call_site_array"])',
}
for old, new in changes.items():
    if text.count(old) != 1:
        raise RuntimeError('fixture generator layout changed: ' + old)
    text = text.replace(old, new, 1)
namespace = {'__name__': 'shared_callsite_fixture', '__file__': str(source)}
exec(compile(text, str(source), 'exec'), namespace)
data, layout = namespace['build'](['call_site_array'])
labels = layout['labels']
site_offset, array_offset = labels['call_site_ids'], labels['call_site_array']
if struct.unpack_from('<II', data, site_offset) != (array_offset, array_offset):
    raise RuntimeError('shared call-site pointers differ')
out = Path(__file__).parent
(out / 'shared.dex').write_bytes(data)
(out / 'fixture.json').write_text(json.dumps({
    'synthetic': True, 'call_site_ids_offset': site_offset,
    'array_offset': array_offset, 'call_site_count': 2,
    'sha256': hashlib.sha256(data).hexdigest(),
}, indent=2) + '\n', encoding='utf-8')
