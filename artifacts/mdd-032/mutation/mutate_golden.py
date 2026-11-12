"""Mutation checks: each mutation must make the named tests fail; files are restored."""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path('.')
BRIDGE = ROOT / 'crates/mdd-sql/src/bridge.rs'
WINDOW = ROOT / 'crates/mdd-sql/src/window.rs'
TESTS = ROOT / 'crates/mdd-sql/src/provider/hostlab/tests.rs'
GOLDEN = ROOT / 'conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json'

MUTATIONS = [
    ('skip one row too many', BRIDGE, 'if skipped < window.offset() {', 'if skipped <= window.offset() {'),
    ('never flag the next page', BRIDGE, '                        more = true;\n', '                        more = false;\n'),
    ('total ignores skipped rows', BRIDGE, 'skipped + taken + counted_after', 'taken + counted_after'),
    ('window ignores limit', BRIDGE, 'if rows.len() as u64 == window.limit() {', 'if rows.len() as u64 == window.limit() + 1 {'),
    ('null rendered as text', TESTS, 'SqlValue::Null => "N".to_owned(),\n        SqlValue::U64(value) => format!("i:{}"', 'SqlValue::Null => "t:".to_owned(),\n        SqlValue::U64(value) => format!("i:{}"'),
    ('real bit pattern perturbed', TESTS, 'SqlValue::F64(bits) => format!("f:{:016x}", bits.0),', 'SqlValue::F64(bits) => format!("f:{:016x}", bits.0 ^ 1),'),
    ('blob rendered as text', TESTS, 'SqlValue::Bytes(bytes) => format!("b:{}", hex_lower(bytes)),', 'SqlValue::Bytes(bytes) => format!("t:{}", hex_lower(bytes)),'),
    ('items are not split into statements', BRIDGE, 'let statements = crate::window::script_statements(items)?;', 'let statements: Vec<String> = items.iter().map(|item| (*item).to_owned()).collect();'),
    ('batch stops after the first statement', BRIDGE, 'for (index, sql) in statements.iter().enumerate() {', 'for (index, sql) in statements.iter().enumerate().take(1) {'),
]
TEST_ARGS = ['cargo', 'test', '--offline', '--locked', '-p', 'mdd-sql', '--lib', '--',
             'hostlab_variants_match', 'calls_the_reference']


def run():
    done = subprocess.run(TEST_ARGS, capture_output=True, text=True, encoding='utf-8', errors='replace')
    return done.returncode, done.stdout + done.stderr


def main():
    failures = 0
    for name, path, old, new in MUTATIONS:
        original = path.read_text(encoding='utf-8')
        if original.count(old) != 1:
            print(f'SKIPPED (pattern count {original.count(old)}): {name}')
            failures += 1
            continue
        path.write_text(original.replace(old, new, 1), encoding='utf-8', newline='')
        try:
            code, output = run()
        finally:
            path.write_text(original, encoding='utf-8', newline='')
        verdict = 'KILLED' if code != 0 else 'SURVIVED'
        if code == 0:
            failures += 1
        print(f'{verdict}: {name}')
    # golden mutation: flip one cell of the first non-empty statement
    original = GOLDEN.read_text(encoding='utf-8')
    marker = '"rows":[["'
    at = original.index(marker) + len(marker) - 2
    mutated = original[:at] + '"Z' + original[at + 1:]
    GOLDEN.write_text(mutated, encoding='utf-8', newline='')
    try:
        code, _ = run()
    finally:
        GOLDEN.write_text(original, encoding='utf-8', newline='')
    print(('KILLED' if code != 0 else 'SURVIVED') + ': golden cell edited')
    failures += code == 0
    code, output = run()
    print('restored tree passes:', code == 0)
    sys.exit(1 if failures or code != 0 else 0)


if __name__ == '__main__':
    main()
