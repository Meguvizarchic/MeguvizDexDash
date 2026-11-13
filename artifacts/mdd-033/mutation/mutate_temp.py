"""Mutation checks for the TEMP layer, window naming and session wiring."""
import subprocess
import sys
from pathlib import Path

ROOT = Path('.')
TEMP = ROOT / 'crates/mdd-sql/src/temp.rs'
BRIDGE = ROOT / 'crates/mdd-sql/src/bridge.rs'
AST = ROOT / 'crates/mdd-sql/src/dialects/ast.rs'

MUTATIONS = [
    ('cursor spec ignores the TEMP definitions', BRIDGE,
     "Some(temp) => {\n                        format!(\"mdd.sql.source.v1|{}|temp:{temp}\", self.binding.snapshot_id)\n                    }",
     "Some(_temp) => {\n                        format!(\"mdd.sql.source.v1|{}\", self.binding.snapshot_id)\n                    }"),
    ('expansion does not follow dependencies', TEMP,
     "            if bodies.contains_key(word) {\n                self.visit(word, bodies, visiting, done, order)?;\n            }",
     "            let _ = word;"),
    ('drop keeps the stored body', TEMP,
     "bodies.remove(&name);", "let _ = &name;"),
    ('IF NOT EXISTS replaces', TEMP,
     "if if_not_exists && bodies.contains_key(name) {", "if false && bodies.contains_key(name) {"),
    ('volatile definitions accepted', TEMP,
     "if is_volatile(&query_sql) {", "if false && is_volatile(&query_sql) {"),
    ('DROP ignores the kind keyword', TEMP,
     "ObjectType::View => TempKind::View,\n                _ => return Err(unsupported(\"only DROP TABLE and DROP VIEW are supported\")),",
     "ObjectType::View => TempKind::Table,\n                _ => return Err(unsupported(\"only DROP TABLE and DROP VIEW are supported\")),"),
    ('alias after AS counts as a read', TEMP,
     "previous_as = word.quote_style.is_none() && word.keyword == Keyword::AS;",
     "previous_as = false;"),
    ('definition echoes offset zero', TEMP,
     "offset: window.map_or(0, |window| window.offset()),", "offset: 0,"),
    ('own CTE does not hide a definition', TEMP,
     "&& !own_ctes.contains(word))", "&& true)"),
    ('names are case sensitive', TEMP,
     "Ok(value.to_ascii_lowercase())", "Ok(value.clone())"),
    ('IF NOT EXISTS ignored for views', TEMP,
     "if_not_exists: view.if_not_exists,", "if_not_exists: false,"),
    ('unaliased expressions keep SQLite text names', AST,
     "_ if self.dialect != super::SqlDialect::NativeV1 => {\n                                    \"column\".to_owned()\n                                }",
     "_ if false => {\n                                    \"column\".to_owned()\n                                }"),
    ('result names keep their case', BRIDGE,
     "shown.to_ascii_lowercase()", "shown"),
    ('bridge snapshot is not checked against the session', TEMP, 'if pinned.manifest().snapshot_id != provider.snapshot_id {', 'if false {'),
    ('items are not split into statements', TEMP, 'let statements = script_statements(items)?;', 'let statements: Vec<String> = items.iter().map(|item| (*item).to_owned()).collect();'),
    ('failed list rolls back nothing (stops early)', TEMP,
     "for (index, sql) in statements.iter().enumerate() {\n            match self.execute(sql, window) {",
     "for (index, sql) in statements.iter().enumerate().take(1) {\n            match self.execute(sql, window) {"),
]
TEST_ARGS = ['cargo', 'test', '--offline', '--locked', '-p', 'mdd-sql', '--lib', '--',
             'temp_tests', 'hostlab_variants_match', 'window::']


def run():
    done = subprocess.run(TEST_ARGS, capture_output=True, text=True, encoding='utf-8', errors='replace')
    return done.returncode, done.stdout + done.stderr


def main():
    bad = 0
    for name, path, old, new in MUTATIONS:
        original = path.read_text(encoding='utf-8')
        if original.count(old) != 1:
            print(f'SKIPPED (pattern count {original.count(old)}): {name}')
            bad += 1
            continue
        path.write_text(original.replace(old, new, 1), encoding='utf-8', newline='')
        try:
            code, output = run()
        finally:
            path.write_text(original, encoding='utf-8', newline='')
        killed = code != 0
        compile_error = 'error[' in output or 'could not compile' in output
        print(('KILLED  ' if killed else 'SURVIVED') + (' (compile error!)' if compile_error else '') + f': {name}')
        bad += (not killed) or compile_error
    code, _ = run()
    print('restored tree passes:', code == 0)
    sys.exit(1 if bad or code != 0 else 0)


if __name__ == '__main__':
    main()
