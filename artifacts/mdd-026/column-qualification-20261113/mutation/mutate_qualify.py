import subprocess
import sys
from pathlib import Path

TOOL = Path('tools/qualify_columns_from_differential.py')
TEST = ['python', '-I', 'tools/test_qualify_columns_from_differential.py']
MUTANTS = [
    ('raw_fingerprint ignores content', 'ok = ok and entry["informative_cells"] > 0', 'ok = ok'),
    ('pair violations ignored', 'ok = ok and pair["violations"] == 0 and pair["non_empty_rows"] > 0', 'ok = ok'),
    ('storage class not compared', 'ok = (classes <= {expected_class}) and non_null > 0', 'ok = non_null > 0'),
    ('nullability not enforced', 'and (nullable or entry["null_cells"] == 0)', ''),
    ('N/A allowed on repeating key', 'require(entry is not None and entry["repeated_cells"] == 0,', 'require(entry is not None,'),
    ('value repetition not required', 'elif key in VALUE_REPETITION_MULTIPLICITY and entry is not None and entry["repeated_cells"] > 0:',
     'elif key in VALUE_REPETITION_MULTIPLICITY and entry is not None:'),
    ('repetition applies to any column', 'elif key in VALUE_REPETITION_MULTIPLICITY and entry is not None and entry["repeated_cells"] > 0:',
     'elif entry is not None and entry["repeated_cells"] > 0:'),
    ('provenance needs no repeat', 'if len(values) >= 2 and len(set(values)) < len(values):', 'if len(values) >= 1:'),
    ('NULL exhaustion needs no cell', 'require(entry is not None and entry["cells"] - entry["null_cells"] > 0,', 'require(entry is not None,'),
    ('manifest completeness not checked', 'require(seen == equal_keys,', 'require(True,'),
    ('A0 answer not required', 'require(record["a0"].get("ok") is True,', 'require(True,'),
    ('manifest duplicates allowed', 'require(len(equal_keys) == len(equal["records"]),', 'require(True,'),
    ('records outside the manifest count', 'if key not in equal_keys:\n            continue', 'if False:\n            continue'),
]
original = TOOL.read_text(encoding='utf-8')
bad = 0
for name, old, new in MUTANTS:
    if original.count(old) != 1:
        print('SKIPPED', name, original.count(old))
        bad += 1
        continue
    TOOL.write_text(original.replace(old, new, 1), encoding='utf-8', newline='')
    try:
        done = subprocess.run(TEST, capture_output=True, text=True, timeout=120)
    finally:
        TOOL.write_text(original, encoding='utf-8', newline='')
    killed = done.returncode != 0
    print(('KILLED   ' if killed else 'SURVIVED ') + name)
    bad += not killed
done = subprocess.run(TEST, capture_output=True, text=True, timeout=120)
print('restored passes:', done.returncode == 0)
sys.exit(1 if bad or done.returncode else 0)
