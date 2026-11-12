"""Independent SQLite oracle for the MDD-031 acceptance matrix.

This script is deliberately separate from the Rust bridge: it builds the same
synthetic rows, executes the frozen HostLab Q-series shapes and the acceptance
feature cases with Python's stdlib sqlite3, and writes the observed rows as
JSON. It does not import the bridge, its AST adapter, or its UDFs.

Run with the project virtualenv (Python 3.11+, stdlib only):

    .venv/Scripts/python.exe -O artifacts/mdd-031-audit/acceptance-coverage-20261111T070145Z/oracle/oracle_matrix.py

The Rust test `dialect_feature_matrix_matches_sqlite_for_null_cast_like_length_compare_aggregate_order_join_cte`
and `hostlab_q_series_shapes_match_sqlite_per_dialect` compare the bridge
against the bundled rusqlite SQLite (3.53.2). This script is the second,
independent oracle (Python sqlite3). The two oracles must agree on every
shared case; any disagreement is a finding, not something to hide.
"""
import json
import sqlite3
import sys
from pathlib import Path

OUT = Path(__file__).with_name("oracle-results.json")


def build_q_series(conn):
    conn.executescript(
        """
        CREATE TABLE dex_files(file_id INTEGER, string_pool_id INTEGER,
            source_path TEXT, entry_name TEXT, byte_len INTEGER);
        CREATE TABLE strings(string_pool_id INTEGER, string_idx INTEGER, value TEXT);
        CREATE TABLE types(file_id INTEGER, type_idx INTEGER, descriptor TEXT, java_name TEXT);
        CREATE TABLE classes(file_id INTEGER, class_def_idx INTEGER, class_idx INTEGER,
            descriptor TEXT, access_flags INTEGER, superclass_descriptor TEXT,
            interface_count INTEGER, source_file TEXT);
        CREATE TABLE class_interfaces(file_id INTEGER, class_idx INTEGER, ordinal INTEGER,
            interface_type_idx INTEGER, interface_descriptor TEXT);
        CREATE TABLE class_fields(file_id INTEGER, class_idx INTEGER, class_descriptor TEXT,
            field_idx INTEGER, field_name TEXT, field_descriptor TEXT, kind TEXT,
            access_flags INTEGER);
        CREATE TABLE class_methods(file_id INTEGER, class_idx INTEGER, class_descriptor TEXT,
            method_idx INTEGER, method_name TEXT, method_descriptor TEXT, kind TEXT,
            access_flags INTEGER);
        CREATE TABLE methods(file_id INTEGER, method_idx INTEGER, class_idx INTEGER,
            class_descriptor TEXT, proto_idx INTEGER, name TEXT, descriptor TEXT,
            return_descriptor TEXT, param_count INTEGER, param_descriptors TEXT,
            access_flags INTEGER, opcode_count INTEGER, opcode_hex TEXT, method_kind TEXT);
        CREATE TABLE method_strings(method TEXT, method_class TEXT, method_name TEXT,
            value TEXT, file_id INTEGER, class_idx INTEGER, method_idx INTEGER,
            string_idx INTEGER);
        CREATE TABLE code_items(file_id INTEGER, method_idx INTEGER, code_off INTEGER,
            registers_size INTEGER, ins_size INTEGER, outs_size INTEGER, tries_size INTEGER,
            debug_info_off INTEGER, insns_size INTEGER, insns_off INTEGER,
            tries_off INTEGER, handlers_off INTEGER);
        CREATE TABLE method_calls(method TEXT, method_class TEXT, method_name TEXT,
            callee TEXT, callee_class TEXT, callee_name TEXT, file_id INTEGER,
            class_idx INTEGER, method_idx INTEGER, callee_method_idx INTEGER);
        CREATE TABLE method_field_accesses(method TEXT, method_class TEXT, method_name TEXT,
            field TEXT, field_class TEXT, field_name TEXT, field_type TEXT, using_type TEXT,
            file_id INTEGER, class_idx INTEGER, method_idx INTEGER, field_idx INTEGER);
        CREATE TABLE method_used_types(method TEXT, method_class TEXT, method_name TEXT,
            type_descriptor TEXT, type_name TEXT, file_id INTEGER, class_idx INTEGER,
            method_idx INTEGER, type_idx INTEGER);
        """
    )
    conn.executemany(
        "INSERT INTO dex_files VALUES (?,?,?,?,?)",
        [
            (0, 10, "one.apk", "classes.dex", 2048),
            (1, 11, "two.dex", "two.dex", 4096),
            (2, 12, "three.apk", "classes2.dex", 1024),
        ],
    )
    conn.executemany(
        "INSERT INTO strings VALUES (?,?,?)",
        [(10, 0, "hello"), (10, 1, "world")],
    )
    conn.executemany(
        "INSERT INTO types VALUES (?,?,?,?)",
        [(0, 1, "Lfixture/A;", "fixture.A"), (0, 21, "Lfixture/Iface;", "fixture.Iface")],
    )
    conn.executemany(
        "INSERT INTO classes VALUES (?,?,?,?,?,?,?,?)",
        [
            (0, 0, 1, "Lfixture/A;", 1, "Lfixture/Base;", 1, "A.java"),
            (0, 1, 2, "Lfixture/B;", 1, "Lfixture/Base;", 0, "B.java"),
            (0, 2, 3, "Lcom/bapis/Moss;", 1, None, 0, None),
            (1, 0, 1, "Lfixture/A;", 1, "Lfixture/Base;", 0, "A.java"),
        ],
    )
    conn.executemany(
        "INSERT INTO class_interfaces VALUES (?,?,?,?,?)",
        [
            (0, 1, 0, 21, "Lfixture/Iface;"),
            (0, 1, 1, 22, "Ljava/io/Serializable;"),
            (1, 1, 0, 21, "Lfixture/Iface;"),
        ],
    )
    conn.executemany(
        "INSERT INTO class_fields VALUES (?,?,?,?,?,?,?,?)",
        [
            (0, 1, "Lfixture/A;", 7, "fieldOne", "I", "instance", 2),
            (0, 1, "Lfixture/A;", 8, "fieldTwo", "Ljava/lang/String;", "instance", 2),
            (0, 2, "Lfixture/B;", 9, "fieldThree", "J", "static", 9),
            (1, 1, "Lfixture/A;", 7, "fieldOne", "I", "instance", 2),
        ],
    )
    conn.executemany(
        "INSERT INTO class_methods VALUES (?,?,?,?,?,?,?,?)",
        [
            (0, 1, "Lfixture/A;", 11, "alpha", "()V", "direct", 1),
            (0, 1, "Lfixture/A;", 12, "beta", "(I)V", "virtual", 2),
            (0, 2, "Lfixture/Protocol;", 13, "serve", "()V", "direct", 1),
            (0, 3, "Lcom/bapis/Moss;", 14, "serve", "()V", "direct", 1),
            (1, 1, "Lfixture/A;", 11, "alpha", "()V", "direct", 1),
        ],
    )
    conn.executemany(
        "INSERT INTO methods VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            (0, 11, 1, "Lfixture/A;", 31, "alpha", "()V", "Lfixture/Result;", 0, "", 1, None, None, "direct"),
            (0, 12, 1, "Lfixture/A;", 32, "beta", "(I)V", "Lfixture/Result;", 1, "I", 2, None, None, "virtual"),
            (0, 13, 2, "Lfixture/Protocol;", 33, "serve", "()V", "V", 0, "", 1, None, None, "direct"),
            (1, 11, 1, "Lfixture/A;", 31, "alpha", "()V", "Lfixture/Result;", 0, "", 1, None, None, "direct"),
        ],
    )
    conn.executemany(
        "INSERT INTO method_strings VALUES (?,?,?,?,?,?,?,?)",
        [
            ("Lfixture/A;->alpha()V", "Lfixture/A;", "alpha", "ordinary: one", 0, 1, 11, 41),
            ("Lfixture/A;->alpha()V", "Lfixture/A;", "alpha", "pref_option_key", 0, 1, 11, 42),
            ("Lfixture/A;->beta(I)V", "Lfixture/A;", "beta", "ordinary: two", 0, 1, 12, 43),
            ("Lcom/bapis/Moss;->serve()V", "Lcom/bapis/Moss;", "serve", "ordinary: three", 0, 3, 14, 44),
        ],
    )
    conn.executemany(
        "INSERT INTO code_items VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            # method_idx values straddle Q09's BETWEEN 0 AND 8 so the shape has
            # a non-empty oracle result instead of comparing 0 rows to 0 rows.
            (0, 5, 100, 2, 4, 1, 0, 0, 8, 100, None, None),
            (0, 7, 200, 3, 6, 2, 0, 0, 12, 200, None, None),
            (1, 11, 300, 2, 4, 1, 0, 0, 8, 300, None, None),
        ],
    )
    conn.executemany(
        "INSERT INTO method_calls VALUES (?,?,?,?,?,?,?,?,?,?)",
        [
            # One callee matches Q12's equality predicate so the shape has a
            # non-empty oracle result instead of comparing 0 rows to 0 rows.
            ("Lfixture/A;->alpha()V", "Lfixture/A;", "alpha", "Lfixture/A;->f()V", "Lfixture/A;", "f", 0, 1, 11, 51),
            ("Lfixture/A;->alpha()V", "Lfixture/A;", "alpha", "Lfixture/F;->f()V", "Lfixture/F;", "f", 0, 1, 11, 51),
            ("Lfixture/A;->beta(I)V", "Lfixture/A;", "beta", "Lfixture/G;->g()V", "Lfixture/G;", "g", 0, 1, 12, 52),
            ("Lfixture/B;->b()V", "Lfixture/B;", "b", "Lfixture/F;->f()V", "Lfixture/F;", "f", 0, 2, 15, 51),
        ],
    )
    conn.executemany(
        "INSERT INTO method_field_accesses VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            ("Lfixture/A;->alpha()V", "Lfixture/A;", "alpha", "Lfixture/A;->fieldOne",
             "Lfixture/A;", "fieldOne", "I", None, 0, 1, 11, 7),
        ],
    )
    conn.executemany(
        "INSERT INTO method_used_types VALUES (?,?,?,?,?,?,?,?,?)",
        [
            ("Lfixture/A;->alpha()V", "Lfixture/A;", "alpha", "Lfixture/Result;",
             "Result", 0, 1, 11, 61),
        ],
    )


Q_SERIES = [
    ("Q01", "SELECT file_id,entry_name FROM dex_files ORDER BY file_id"),
    ("Q02", "SELECT cf.* FROM class_fields cf WHERE class_descriptor IN ('Lfixture/A;') ORDER BY file_id,class_idx,kind,field_idx"),
    ("Q03", "SELECT ci.interface_descriptor,c.descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE c.descriptor IN ('Lfixture/A;') ORDER BY ci.file_id,ci.class_idx,ci.ordinal"),
    ("Q05", "SELECT DISTINCT m.class_descriptor FROM class_methods c JOIN methods m ON m.file_id=c.file_id AND m.method_idx=c.method_idx WHERE m.return_descriptor='Lfixture/Result;' ORDER BY m.class_descriptor"),
    ("Q07", "SELECT COUNT(*) AS n FROM classes ORDER BY n"),
    ("Q08", "SELECT file_id,class_def_idx,descriptor,superclass_descriptor FROM classes WHERE file_id=0 AND (descriptor LIKE 'Lfixture/%' ESCAPE '\\') ORDER BY file_id,class_def_idx"),
    ("Q09", "SELECT method_idx,insns_off,insns_size FROM code_items WHERE file_id=0 AND method_idx BETWEEN 0 AND 8 ORDER BY method_idx"),
    ("Q11", "SELECT file_id,method_descriptor FROM class_methods WHERE file_id=0 AND (class_descriptor IN ('Lfixture/Protocol;') OR class_descriptor LIKE 'Lcom/bapis/%Moss;') ORDER BY file_id,class_idx,method_idx"),
    ("Q12", "SELECT file_id,method AS descriptor FROM method_calls WHERE callee='Lfixture/A;->f()V' ORDER BY file_id,method_idx"),
]

FEATURES = [
    ("null-aggregate", "SELECT NULL IS NULL, NULL = NULL, COALESCE(NULL, 1), COUNT(value), COUNT(*), SUM(opt) FROM vals"),
    ("null-predicate", "SELECT id, value, opt, opt IS NULL, value IS NOT NULL FROM vals ORDER BY id"),
    ("cast-text-real", "SELECT CAST(NULL AS TEXT), CAST(opt AS TEXT), CAST(opt AS REAL) FROM vals ORDER BY id"),
    ("cast-blob-eq", "SELECT id, CAST(value AS BLOB)=CAST(value AS BLOB) AS same FROM vals ORDER BY id"),
    ("like-escape-prefix", "SELECT id FROM vals WHERE value LIKE 'a%' ESCAPE '\\' ORDER BY id"),
    ("like-escape-underscore", "SELECT id FROM vals WHERE value LIKE 'a\\_c' ESCAPE '\\' ORDER BY id"),
    ("like-escape-dash", "SELECT id FROM vals WHERE value LIKE 'a\\-c' ESCAPE '\\' ORDER BY id"),
    ("like-null-projection", "SELECT id, value LIKE NULL AS v FROM vals ORDER BY id"),
    ("like-null", "SELECT id FROM vals WHERE value LIKE NULL ORDER BY id"),
    ("length", "SELECT id, length(value), length(opt), length('') FROM vals ORDER BY id"),
    ("comparison", "SELECT id, value='alpha', value>'b', value IN ('alpha','beta'), opt>20 FROM vals ORDER BY id"),
    ("between-in", "SELECT id FROM vals WHERE value IN ('alpha','beta') AND opt BETWEEN 20 AND 50 ORDER BY id"),
    ("aggregate-group", "SELECT value, COUNT(*) AS n, SUM(opt) AS s FROM vals GROUP BY value ORDER BY value"),
    ("aggregate-distinct", "SELECT COUNT(DISTINCT value) AS d, MIN(opt) AS lo, MAX(opt) AS hi FROM vals"),
    ("order-asc-mixed", "SELECT id, value, opt FROM vals ORDER BY value ASC, id DESC"),
    ("order-desc-mixed", "SELECT id, value FROM vals ORDER BY value DESC, id ASC"),
    ("join", "SELECT v.id, w.value FROM vals v JOIN vals w ON v.id=w.id WHERE v.id IN (0,2) ORDER BY v.id"),
    ("cte", "WITH t AS (SELECT id, value FROM vals WHERE id>1) SELECT value FROM t ORDER BY id"),
    ("cte-in-subquery", "WITH t AS (SELECT id FROM vals WHERE opt IS NULL) SELECT id, value FROM vals WHERE id IN (SELECT id FROM t) ORDER BY id"),
]

# SQLite oracle values for the NativeV1 text-to-integer CAST divergence. The
# Rust test asserts NativeV1 rejects these as INVALID_INTEGER_CAST while the
# legacy dialects return the SQLite prefix-parse value.
SQLITE_INTEGER_CAST = [
    ("cast-1.9", "SELECT CAST('1.9' AS INTEGER)"),
    ("cast-abc", "SELECT CAST('abc' AS INTEGER)"),
    ("cast-12", "SELECT CAST('12' AS INTEGER)"),
    ("cast-neg-5.9", "SELECT CAST('-5.9' AS INTEGER)"),
    ("cast-1e5", "SELECT CAST('1e5' AS INTEGER)"),
]


def norm(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    return value


def run_cases(conn, cases):
    records = []
    for label, sql in cases:
        try:
            cursor = conn.execute(sql)
            rows = [ [norm(v) for v in row] for row in cursor.fetchall() ]
            records.append({"id": label, "sql": sql, "status": "ok", "rows": rows})
        except Exception as error:  # noqa: BLE001 - record the real oracle error
            records.append({"id": label, "sql": sql, "status": "error", "error": f"{type(error).__name__}: {error}"})
    return records


def main():
    conn = sqlite3.connect(":memory:")
    build_q_series(conn)
    conn.executescript(
        """
        CREATE TABLE vals(id INTEGER, value TEXT, opt INTEGER);
        INSERT INTO vals VALUES (0,'alpha',10);
        INSERT INTO vals VALUES (1,'beta',NULL);
        INSERT INTO vals VALUES (2,'alpha',30);
        INSERT INTO vals VALUES (3,NULL,40);
        INSERT INTO vals VALUES (4,'',50);
        INSERT INTO vals VALUES (5,'a_c',NULL);
        INSERT INTO vals VALUES (6,'a-c',60);
        """
    )
    payload = {
        "schema_version": "mdd.mdd-031.acceptance-oracle.v1",
        "oracle": "python-stdlib-sqlite3",
        "sqlite_version": sqlite3.sqlite_version,
        "python_version": sys.version.split()[0],
        "scope": "synthetic rows and frozen HostLab Q-series shapes; no real APK facts, no profile admission",
        "q_series": run_cases(conn, Q_SERIES),
        "features": run_cases(conn, FEATURES),
        "sqlite_integer_cast": run_cases(conn, SQLITE_INTEGER_CAST),
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"sqlite_version": sqlite3.sqlite_version, "output": str(OUT),
                      "q_cases": len(payload["q_series"]), "feature_cases": len(payload["features"])}))


if __name__ == "__main__":
    main()
