"""Derive a tiny typed-catch fixture from the independent owned-try writer."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
source_path = ROOT / 'tests/fixtures/owned_try/generate.py'
source = source_path.read_text(encoding='utf-8')
old = 'data.extend(bytes([1, 0, 127 if invalid_handler else 2]))'
new = 'data.extend(bytes([1, 1, 0, 2]))'
if source.count(old) != 1:
    raise RuntimeError('fixture writer changed')
namespace = {'__name__': 'typed_fixture_writer', '__file__': str(source_path)}
exec(compile(source.replace(old, new), str(source_path), 'exec'), namespace)
data, layout = namespace['build'](False)
target = HERE / 'typed-catch.dex'
if target.exists() and target.read_bytes() != data:
    raise RuntimeError('refusing to overwrite a different fixture')
target.write_bytes(data)
print('sha256=' + hashlib.sha256(data).hexdigest())
print('layout=' + repr(layout))
print('scope=synthetic typed catch, no full format qualification')
