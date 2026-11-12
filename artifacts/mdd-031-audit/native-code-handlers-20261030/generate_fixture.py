"""Derive a tiny typed-catch fixture from the independent owned-try writer."""
from pathlib import Path
import hashlib
import importlib.machinery
import importlib.util
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
source_path = ROOT / 'tests/fixtures/owned_try/generate.py'
source = source_path.read_text(encoding='utf-8')
old = 'data.extend(bytes([1, 0, 127 if invalid_handler else 2]))'
new = 'data.extend(bytes([1, 1, 0, 2]))'
if source.count(old) != 1:
    raise RuntimeError('fixture writer changed')
# Stage the patched writer as a module file and import it: the derived source
# is executed from disk rather than compiled in-process.
with tempfile.TemporaryDirectory(prefix='typed-catch-') as staging:
    staged = Path(staging) / 'typed_fixture_writer.py'
    staged.write_text(source.replace(old, new), encoding='utf-8', newline='\n')
    loader = importlib.machinery.SourceFileLoader('typed_fixture_writer', str(staged))
    spec = importlib.util.spec_from_loader('typed_fixture_writer', loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules['typed_fixture_writer'] = module
    loader.exec_module(module)
    data, layout = module.build(False)
target = HERE / 'typed-catch.dex'
if target.exists() and target.read_bytes() != data:
    raise RuntimeError('refusing to overwrite a different fixture')
target.write_bytes(data)
print('sha256=' + hashlib.sha256(data).hexdigest())
print('layout=' + repr(layout))
print('scope=synthetic typed catch, no full format qualification')
