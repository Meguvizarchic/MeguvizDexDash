#!/usr/bin/env python3
"""Record frozen-A0 behaviour for session TEMP statements and windowed paging.

Usage: python -I generate_catalog_golden.py A0_EXE REPO_ROOT OUTPUT_JSON

Every scenario is replayed against a fresh pair of A0 datasets (one per named
session) opened over the same fixture inputs as the HostLab corpus. Each step is
one `query` call, so its statement list, window and result are recorded exactly
as the reference tool answered them; an error is recorded as the failing
statement index only, because the message wording is not a contract.

The engine replays the same steps in crates/mdd-sql provider/hostlab/temp_tests.rs.
Nothing here derives from this project's own engine.
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GOLDEN_MODULE = HERE.parent / "corpus" / "hostlab" / "generate_golden.py"


def load_golden_module():
    spec = importlib.util.spec_from_file_location("hostlab_generate_golden", GOLDEN_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


G = load_golden_module()

T_AB = "CREATE TEMP TABLE t AS SELECT 1 AS id,'a' AS tag UNION ALL SELECT 2,'b'"
PAGE_BEFORE = ("CREATE TEMP TABLE page_base AS SELECT 1 AS id,'before' AS tag "
               "UNION ALL SELECT 2,'before' UNION ALL SELECT 3,'before' UNION ALL SELECT 4,'before'")
PAGE_AFTER = PAGE_BEFORE.replace("'before'", "'after'")
PAGE_SELECT = "SELECT id,tag FROM page_base ORDER BY id"


def step(statements, session="a", limit=50, offset=0, named=None):
    if isinstance(statements, str):
        statements = [statements]
    item = {"session": session, "statements": statements, "limit": limit, "offset": offset}
    if named is not None:
        item["named_temp_queries"] = [{"name": n, "sql": q} for n, q in named]
    return item


SCENARIOS = [
    {"name": "create_query_drop", "steps": [
        step(T_AB), step("SELECT id,tag FROM t ORDER BY id"), step("DROP TABLE t"),
        step("SELECT id,tag FROM t ORDER BY id")]},
    {"name": "if_not_exists_keeps_the_first_body", "steps": [
        step(T_AB), step("CREATE TEMP TABLE IF NOT EXISTS t AS SELECT 9 AS id"),
        step("CREATE TEMP TABLE IF NOT EXISTS t AS SELECT * FROM missing_relation"),
        step("SELECT id,tag FROM t ORDER BY id"),
        step("CREATE TEMP TABLE IF NOT EXISTS fresh AS SELECT * FROM missing_relation"),
        step("CREATE TEMP VIEW IF NOT EXISTS t AS SELECT 5 AS id"),
        step("SELECT id,tag FROM t ORDER BY id")]},
    {"name": "redefinition_replaces", "steps": [
        step(T_AB), step("CREATE TEMP TABLE t AS SELECT 9 AS id"), step("SELECT * FROM t"),
        step("CREATE TEMP VIEW t AS SELECT 7 AS id"), step("SELECT * FROM t"),
        step("DROP TABLE t"), step("DROP VIEW t"), step("SELECT * FROM t")]},
    {"name": "views_and_tables_are_late_bound", "steps": [
        step(T_AB), step("CREATE TEMP VIEW v AS SELECT id*10 AS big FROM t"),
        step("CREATE TEMP TABLE tt AS SELECT id FROM t"),
        step("SELECT big FROM v ORDER BY big"), step("DROP TABLE t"),
        step("SELECT big FROM v ORDER BY big"), step("SELECT id FROM tt"),
        step("CREATE TEMP TABLE t AS SELECT 5 AS id"),
        step("SELECT big FROM v ORDER BY big"), step("SELECT id FROM tt")]},
    {"name": "drop_kind_and_existence", "steps": [
        step(T_AB), step("CREATE TEMP VIEW v AS SELECT id FROM t"),
        step("DROP VIEW t"), step("DROP TABLE v"), step("DROP VIEW IF EXISTS t"),
        step("DROP TABLE IF EXISTS v"), step("DROP TABLE IF EXISTS nothing"),
        step("DROP VIEW IF EXISTS nothing"), step("DROP TABLE nothing"), step("DROP VIEW nothing"),
        step("DROP VIEW v"), step("DROP TABLE t"), step("DROP TABLE t")]},
    {"name": "unknown_dependency_and_cycle", "steps": [
        step("CREATE TEMP VIEW a1 AS SELECT * FROM b1"),
        step("CREATE TEMP VIEW b1 AS SELECT 1 AS x"),
        step("CREATE TEMP VIEW a1 AS SELECT * FROM b1"),
        step("CREATE TEMP VIEW b1 AS SELECT * FROM a1"),
        step("SELECT x FROM a1"),
        step("CREATE TEMP TABLE selfref AS SELECT * FROM selfref"),
        step("CREATE TEMP VIEW c1 AS SELECT * FROM a1"),
        step("CREATE TEMP VIEW a1 AS SELECT * FROM c1"),
        step("SELECT x FROM c1")]},
    {"name": "sessions_do_not_share_definitions", "steps": [
        step(T_AB, "a"), step("SELECT id FROM t", "b"),
        step("CREATE TEMP TABLE t AS SELECT 42 AS id", "b"),
        step("SELECT id FROM t ORDER BY id", "a"), step("SELECT id FROM t", "b"),
        step("DROP TABLE t", "a"), step("SELECT id FROM t", "b"), step("SELECT id FROM t", "a")]},
    {"name": "a_definition_shadows_a_provider_relation", "steps": [
        step("SELECT COUNT(*) AS n FROM strings"),
        step("CREATE TEMP TABLE strings AS SELECT 1 AS x"),
        step("SELECT x FROM strings"), step("SELECT COUNT(*) AS n FROM strings"),
        step("DROP TABLE strings"), step("SELECT COUNT(*) AS n FROM strings")]},
    {"name": "a_failed_list_keeps_earlier_definitions", "steps": [
        step(["CREATE TEMP TABLE x2 AS SELECT 1 AS a", "SELECT * FROM nope"]),
        step("SELECT a FROM x2"),
        step(["CREATE TEMP TABLE x3 AS SELECT 1 AS a", "SELECT a FROM x3", "DROP TABLE x3", "SELECT a FROM x3"]),
        step("SELECT a FROM x3")]},
    {"name": "statements_see_earlier_statements_of_the_same_call", "steps": [
        step(["CREATE TEMP TABLE x1 AS SELECT 1 AS a", "SELECT a FROM x1"]),
        step(["SELECT a FROM x1", "SELECT a FROM x1"], limit=10)]},
    {"name": "scripts_define_and_read_in_one_item", "steps": [
        step(["CREATE TEMP TABLE g8 AS SELECT 1 AS a; SELECT a FROM g8; DROP TABLE g8; SELECT a FROM g8"]),
        step(["SELECT a FROM g8"]),
        step(["CREATE TEMP TABLE s1 AS SELECT 1 AS a;;\n-- comment; kept out\nCREATE TEMP VIEW s2 AS SELECT a+1 AS a FROM s1; SELECT a FROM s2"]),
        step(["DROP VIEW s2; DROP TABLE s1;"]),
        step(["SELECT a FROM s2"]),
        step(["CREATE TEMP TABLE s3 AS SELECT 'open", "SELECT 1"]),
        step(["CREATE TEMP TABLE s4 AS SELECT 1 AS a; /* never closed"]),
        step(["SELECT a FROM s4"])]},
    {"name": "forms_outside_the_subset", "steps": [
        step("CREATE TABLE plain AS SELECT 1 AS x"),
        step("CREATE OR REPLACE TEMP VIEW g5 AS SELECT 1 AS a"),
        step("CREATE TEMP TABLE g2(a int)"),
        step("CREATE TEMP VIEW g4(x) AS SELECT 1"),
        step('CREATE TEMP TABLE "Quoted Name" AS SELECT 1 AS a'),
        step("DROP TEMP TABLE t"),
        step("DROP TABLE a1, b1"),
        step("INSERT INTO t VALUES (1)"),
        step("UPDATE t SET id=1"),
        step("ALTER TABLE t ADD COLUMN z"),
        step("CREATE INDEX i ON t(id)"),
        step("SELECT id FROM t")]},
    {"name": "plain_create_view_is_a_temp_definition", "steps": [
        step("CREATE VIEW nv AS SELECT 1 AS x"), step("SELECT x FROM nv"), step("DROP VIEW nv")]},
    {"name": "names_are_case_insensitive_and_simple", "steps": [
        step("CREATE TEMP TABLE CaseT AS SELECT 1 AS a"), step("SELECT a FROM caset"),
        step("SELECT a FROM CASET"), step("CREATE TEMP TABLE caset AS SELECT 2 AS a"),
        step("SELECT a FROM CaseT"), step("DROP TABLE CASET"), step("SELECT a FROM caset")]},
    {"name": "definition_bodies", "steps": [
        step("CREATE TEMP TABLE b_with AS WITH q AS (SELECT file_id FROM dex_files) "
             "SELECT file_id FROM q ORDER BY file_id DESC LIMIT 2"),
        step("SELECT file_id FROM b_with"),
        step("CREATE TEMP TABLE b_agg AS SELECT descriptor,COUNT(*) AS n FROM types GROUP BY descriptor"),
        step("SELECT descriptor,n FROM b_agg ORDER BY n DESC,descriptor LIMIT 3"),
        step("CREATE TEMP TABLE b_join AS SELECT a.file_id AS fid FROM dex_files a JOIN dex_files b ON a.file_id=b.file_id"),
        step("SELECT fid FROM b_join ORDER BY fid"),
        step("CREATE TEMP TABLE b_sub AS SELECT file_id FROM dex_files WHERE file_id IN (SELECT file_id FROM classes)"),
        step("SELECT file_id FROM b_sub ORDER BY file_id"),
        step("CREATE TEMP TABLE b_empty AS SELECT 1 AS a WHERE 1=0"),
        step("SELECT a FROM b_empty"),
        step("CREATE TEMP TABLE b_fn AS SELECT lower('A') AS lo,hex(entry_name) AS h FROM dex_files"),
        step("SELECT lo,h FROM b_fn ORDER BY h"),
        step("CREATE TEMP TABLE b_case AS SELECT CASE WHEN 1=1 THEN 'y' END AS c"),
        step("SELECT c FROM b_case"),
        step("CREATE TEMP TABLE b_values AS VALUES (1),(2)"),
        step("SELECT * FROM b_values"),
        step("CREATE TEMP TABLE b_order AS SELECT file_id FROM dex_files ORDER BY file_id DESC"),
        step("SELECT file_id FROM b_order"),
        step("CREATE TEMP TABLE b_dupcols AS SELECT file_id,file_id AS file_id FROM dex_files"),
        step("SELECT * FROM b_dupcols ORDER BY 1"),
        step("CREATE TEMP TABLE b_unnamed AS SELECT 1,'a',NULL"),
        step("SELECT * FROM b_unnamed")]},
    {"name": "volatile_bodies", "steps": [
        step("CREATE TEMP TABLE r AS SELECT random() AS r1"),
        step("SELECT r1 FROM r"),
        step("CREATE TEMP TABLE r2 AS SELECT CURRENT_TIMESTAMP AS ts"),
        step("SELECT COUNT(*) AS n FROM r2")]},
    {"name": "a_definition_reads_a_later_definition_of_its_dependency", "steps": [
        step("CREATE TEMP TABLE base AS SELECT 1 AS id"),
        step("CREATE TEMP VIEW mid AS SELECT id+1 AS id FROM base"),
        step("CREATE TEMP VIEW top AS SELECT id+1 AS id FROM mid"),
        step("SELECT id FROM top"),
        step("CREATE TEMP TABLE base AS SELECT 10 AS id"),
        step("SELECT id FROM top"),
        step("DROP TABLE base"),
        step("SELECT id FROM top"),
        step("CREATE TEMP TABLE base AS SELECT 100 AS id"),
        step("SELECT id FROM top")]},
    {"name": "a_query_own_cte_hides_a_definition", "steps": [
        step("CREATE TEMP TABLE t AS SELECT 1 AS id"),
        step("WITH t AS (SELECT 2 AS id) SELECT id FROM t"),
        step("WITH w AS (SELECT 5 AS n) SELECT n+(SELECT id FROM t) AS v FROM w"),
        step("SELECT id FROM t")]},
    {"name": "definitions_echo_the_window_offset", "steps": [
        step("CREATE TEMP TABLE x3 AS SELECT 1 AS a", limit=1, offset=5),
        step("DROP TABLE x3", limit=7, offset=3),
        step(["CREATE TEMP TABLE x4 AS SELECT 1 AS a", "SELECT a FROM x4"], limit=2, offset=0)]},
    {"name": "paging_over_a_definition", "steps": [
        step(PAGE_BEFORE), step(PAGE_SELECT, limit=2, offset=0), step(PAGE_SELECT, limit=2, offset=2),
        step(PAGE_SELECT, limit=2, offset=4), step(PAGE_SELECT, limit=3, offset=3)]},
    {"name": "paging_across_a_redefinition", "steps": [
        step(PAGE_BEFORE), step(PAGE_SELECT, limit=2, offset=0),
        step(PAGE_AFTER), step(PAGE_SELECT, limit=2, offset=2)]},
    {"name": "paging_across_a_row_count_change", "steps": [
        step(PAGE_BEFORE), step(PAGE_SELECT, limit=2, offset=0),
        step("CREATE TEMP TABLE page_base AS SELECT 1 AS id,'x' AS tag UNION ALL SELECT 2,'x'"),
        step(PAGE_SELECT, limit=2, offset=2), step(PAGE_SELECT, limit=2, offset=0)]},
    {"name": "named_temp_queries", "steps": [
        step("SELECT n FROM nq", named=[("nq", "SELECT 1 AS n")]),
        step("SELECT n FROM nq"),
        step("DROP VIEW nq"),
        step("SELECT n FROM nq"),
        step("DROP TABLE nq"),
        step("SELECT n FROM nq"),
        step("SELECT m FROM b", named=[("a", "SELECT 1 AS n"), ("b", "SELECT n+1 AS m FROM a")]),
        step("SELECT m FROM b2", named=[("b2", "SELECT n+1 AS m FROM a2"), ("a2", "SELECT 1 AS n")]),
        step("SELECT n FROM d1", named=[("d1", "SELECT 1 AS n"), ("d1", "SELECT 2 AS n")]),
        step("SELECT n FROM CASEQ", named=[("CaseQ", "SELECT 3 AS n")]),
        step("SELECT n FROM w1", named=[("w1", "WITH q AS (SELECT 4 AS n) SELECT n FROM q")]),
        step("SELECT * FROM nope", named=[("k1", "SELECT 7 AS n")]),
        step("SELECT n FROM k1"),
        step("SELECT COUNT(*) AS c FROM strings", named=[("strings", "SELECT 9 AS c")]),
        step("SELECT COUNT(*) AS c FROM strings"),
        step("DROP TABLE strings"),
        step("SELECT COUNT(*) AS c FROM strings"),
        step("CREATE TEMP VIEW v1 AS SELECT 1 AS n"),
        step("SELECT n FROM v1", named=[("v1", "SELECT 2 AS n")]),
        step("DROP VIEW v1"),
        step("DROP TABLE v1"),
        step("SELECT 1", named=[("e1", "")]),
        step("SELECT 1", named=[("e2", "SELECT 1; SELECT 2")]),
        step("SELECT 1", named=[("e3", "CREATE TEMP VIEW zz AS SELECT 1")]),
        step("SELECT 1", named=[("e4", "DROP TABLE x")]),
        step("SELECT 1", named=[("e5", "SELECT * FROM nope")]),
        step("SELECT 1", named=[("a b", "SELECT 1")]),
        step("SELECT 1", named=[("select", "SELECT 1")]),
        step("SELECT 1", named=[("x%d" % i, "SELECT 1") for i in range(17)]),
        step("SELECT 1", named=[("x%d" % i, "SELECT 1") for i in range(16)]),
        step(["SELECT 1", "   "], named=[("late", "SELECT 8 AS n")]),
        step("SELECT n FROM late"),
        step("SELECT n FROM nq2", named=[("nq2", "SELECT 1 AS n")], limit=1, offset=3)]},
]


def kind_of(statement):
    return statement["kind"]


def record(statement):
    base = G.statement_record(statement)
    base["kind"] = kind_of(statement)
    return base


def run_step(client, datasets, item):
    extra = {"named_temp_queries": item["named_temp_queries"]} if "named_temp_queries" in item else {}
    reply = client.tool("query", dataset_id=datasets[item["session"]], sql=item["statements"],
                        limit=item["limit"], offset=item["offset"], **extra)
    if reply["_is_error"] or "statements" not in reply:
        return G.error_record(reply)
    return {"statements": [record(s) for s in reply["statements"]]}


def main():
    exe, root, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    spec = json.loads((root / "conformance/corpus/hostlab/required-variants.json").read_text(encoding="utf-8"))
    inputs = [str((root / p).resolve()) for p in spec["inputs"]]
    client = G.Mcp(exe)
    scenarios = []
    for scenario in SCENARIOS:
        datasets = {}
        for session in sorted({s["session"] for s in scenario["steps"]}):
            opened = client.tool("open_dataset", inputs=inputs)
            if opened["_is_error"]:
                raise SystemExit("A0 refused the fixture inputs")
            datasets[session] = opened["dataset_id"]
        steps = []
        for item in scenario["steps"]:
            steps.append({**item, "a0": run_step(client, datasets, item)})
        scenarios.append({"name": scenario["name"], "steps": steps})
        # A0 admits four open datasets per server; a scenario never needs more.
        for dataset in datasets.values():
            client.tool("close_dataset", dataset_id=dataset)
    client.close()
    document = {
        "schema_version": "mdd.catalog-and-paging.v1",
        "a0_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
        "inputs": spec["inputs"],
        "scenarios": scenarios,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    steps = sum(len(s["steps"]) for s in scenarios)
    errors = sum(1 for s in scenarios for st in s["steps"] if "error" in st["a0"])
    print(f"scenarios={len(scenarios)} steps={steps} a0_errors={errors}")


if __name__ == "__main__":
    main()
