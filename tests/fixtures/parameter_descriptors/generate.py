"""Independent synthetic DEX with a supplementary descriptor argument."""
from pathlib import Path
import hashlib
import importlib.util
import json

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('reference_fixture',
    ROOT / 'tests/fixtures/references/generate.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
fixture.LOOKUP = 'Lfixture/\U0001f600;'
data, _layout = fixture.build('poly-custom-038')
output = HERE / 'unicode-parameters-038.dex'
output.write_bytes(data)
descriptors = [fixture.LOOKUP, fixture.S, fixture.MT]
joined = ','.join(descriptors)
if any(len(value.encode('utf-16-le')) // 2 >= 128 for value in descriptors):
    raise ValueError('fixture expects one-byte ULEB lengths')
raw = b','.join(fixture.mutf(value)[1:-1] for value in descriptors)
units_bytes = joined.encode('utf-16-le')
units = [int.from_bytes(units_bytes[i:i+2], 'little') for i in range(0, len(units_bytes), 2)]
fixture.LOOKUP = 'Lfixture/\ud800;'
invalid_data, _layout = fixture.build('poly-custom-038')
(HERE / 'nonscalar-parameters-038.dex').write_bytes(invalid_data)
expected = {'fixture_sha256': hashlib.sha256(data).hexdigest(),
            'nonscalar_fixture_sha256': hashlib.sha256(invalid_data).hexdigest(),
            'method_name': 'bootstrap', 'raw_mutf8_hex': raw.hex(),
            'utf16_units': units, 'scope': 'independent synthetic writer, not A0 qualification'}
(HERE / 'expected.json').write_text(json.dumps(expected, ensure_ascii=True, indent=2)+'\n', encoding='utf-8')
print(json.dumps({'bytes': len(data), 'sha256': expected['fixture_sha256']}))
