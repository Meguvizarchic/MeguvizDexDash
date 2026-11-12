#!/usr/bin/env python3
"""Record `analysis_paging.continuation_reason` results for a fixed SQL list.

The frozen reference module is loaded from its pinned copy under
`source-8782f43/`; its result is the oracle for the Rust port
`mdd_sql::window::paging_blocker`. Nothing here derives from the Rust code.

Usage: python generate_paging_cases.py   (writes paging-blocker-cases.json)
"""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "source-8782f43" / "analysis_paging.py"

CASES = [
    # ordered at the outer level
    "SELECT a FROM t ORDER BY a",
    "select a from t order by a desc",
    "SELECT a FROM t\nORDER\tBY a",
    "SELECT a FROM t ORDER /* split */ BY a",
    "SELECT a FROM t ORDER -- split\n BY a",
    "WITH c AS (SELECT a FROM t) SELECT a FROM c ORDER BY a",
    "SELECT a FROM (SELECT a FROM t) ORDER BY a",
    # no outer order
    "SELECT a FROM t",
    "SELECT a FROM (SELECT a FROM t ORDER BY a)",
    "WITH c AS (SELECT a FROM t ORDER BY a) SELECT a FROM c",
    "SELECT 'ORDER BY a' AS x FROM t",
    "SELECT \"ORDER\" , \"BY\" FROM t",
    "SELECT a FROM t -- ORDER BY a",
    "SELECT a FROM t /* ORDER BY a */",
    "SELECT a FROM t ORDER",
    "SELECT a FROM t BY a ORDER",
    "SELECT [ORDER] FROM t",
    "SELECT `order` FROM t",
    # volatile values and functions
    "SELECT random() FROM t ORDER BY 1",
    "SELECT RANDOM ( ) FROM t ORDER BY 1",
    "SELECT randomblob(4) FROM t ORDER BY 1",
    "SELECT uuid() FROM t ORDER BY 1",
    "SELECT now() FROM t ORDER BY 1",
    "SELECT CURRENT_TIMESTAMP FROM t ORDER BY 1",
    "SELECT current_date FROM t ORDER BY 1",
    "SELECT CURRENT_TIME FROM t ORDER BY 1",
    "SELECT \"random\"() FROM t ORDER BY 1",
    "SELECT 'random()' FROM t ORDER BY 1",
    "SELECT random FROM t ORDER BY 1",
    "SELECT a FROM t ORDER BY random()",
    "SELECT a FROM t -- random()\nORDER BY a",
    "SELECT \"CURRENT_TIMESTAMP\" FROM t ORDER BY 1",
    # quoting and lexing edges (the reference regex skips what it cannot match)
    "SELECT 'it''s' FROM t ORDER BY a",
    "SELECT 'unterminated FROM t ORDER BY a",
    "SELECT \"unterminated FROM t ORDER BY a",
    "SELECT a FROM t /* unterminated ORDER BY a",
    "SELECT [unterminated FROM t ORDER BY a",
    "SELECT 'a''' FROM t ORDER BY a",
    "SELECT 'a'' FROM t ORDER BY a",
    "SELECT 'x' 'y' FROM t",
    "SELECT \"a\"\"b\" FROM t ORDER BY a",
    "SELECT `a``b` FROM t ORDER BY a",
    "SELECT 1+2*3 FROM t ORDER BY 1",
    "SELECT a FROM t WHERE (a>1 AND (b<2)) ORDER BY a",
    "SELECT a FROM t WHERE (a>1 ORDER BY a",
    "SELECT a FROM t WHERE a>1) ORDER BY a",
    ") SELECT a FROM t ORDER BY a",
    "",
    "   ",
    "SELECT",
    "ORDER BY",
    "SELECT é FROM t ORDER BY é",
    "SELECT 数据 FROM t ORDER BY 1",
]


def load():
    spec = importlib.util.spec_from_file_location("analysis_paging", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    module = load()
    cases = [{"sql": sql, "reason": module.continuation_reason(sql)} for sql in CASES]
    reasons = sorted({c["reason"] or "none" for c in cases})
    document = {
        "schema_version": "mdd.paging-blocker-cases.v1",
        "oracle": "conformance/corpus/hostlab/source-8782f43/analysis_paging.py::continuation_reason",
        "oracle_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "cases": cases,
    }
    out = HERE / "paging-blocker-cases.json"
    out.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(cases)} cases; reasons seen: {reasons}")


if __name__ == "__main__":
    main()
