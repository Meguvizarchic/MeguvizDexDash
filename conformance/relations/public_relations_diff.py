#!/usr/bin/env python3
"""MDD-070: replay the recorded reference answers of all 56 public relations against the engine under test.

For every probe record in artifacts/mdd-070/a0-probe/ (one rich fixture each, recorded from the reference engine
dexsql 0.1.0) this opens the same fixture with `meguvizdexdash mcp`, pages `SELECT * FROM <relation>` to the end,
and compares the column list and every cell, row by row and in the recorded order. Nothing is compared by count.

A relation is judged per fixture:
  match       column names and all cells equal, in the recorded order, and the column types and nullable flags equal too
  match_cells column names and all cells equal in the recorded order; a column's type or nullable flag differs (noted)
  reordered   column names and cells equal as a multiset but not in the recorded order (declared difference ORDER)
  refused_by_design  the engine refused the relation for a declared reason (NON_SCALAR)
  reference_incomplete  the reference left out rows the DEX holds (REFERENCE_GAPS); every row it did deliver is the engine's too
  differs   anything else (the first difference is kept)
  error     the engine refused or failed (its error text is kept)

The result is written to --out (default artifacts/mdd-070/public-relations-diff.json). The exit code is 0 only when every
relation of every fixture matches; --allow lists relation names whose difference is declared elsewhere (kept in the
record, but they do not fail the run).

Usage: python -I conformance/relations/public_relations_diff.py [--binary PATH] [--relations a,b] [--fixtures x,y]
                                                                [--out FILE] [--allow a,b] [--strict-order] [--quiet]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "conformance" / "mcp"))
from mcp_client import DEFAULT_BINARY, McpClient  # noqa: E402

PROBE_DIR = ROOT / "artifacts" / "mdd-070" / "a0-probe"
MANIFEST = ROOT / "conformance" / "manifests" / "relations.json"
PAGE = 1000
WINDOW = 200_000

# Differences from the reference that are declared and explained (docs and the qualification manifest repeat them):
#   INT_TAG        a cell of a column declared Int64 holds a non-negative value: the reference tags it int64, the engine
#                  derives the tag from the value (uint64 when it is not negative). The value is identical.
#   NON_SCALAR     a plain UTF-8 relation cannot carry a legal non-scalar DEX string; the engine refuses the whole
#                  relation (INCOMPLETE_FACTS) where the reference substitutes text.
#   ORDER          a relation read without ORDER BY has no promised order; the engine keeps its own stable order.
#   LOCAL_PATH     dex_files.source_path is the path the input was opened from; it differs by machine.
#   FLOAT_ULP      a float64 cell that the reference computed from a 64-bit pattern is up to one unit in the last place
#                  away from the exact reading of the pattern (it passes through 17 decimal digits); the engine is exact.
#   STRICT_INPUT   an input the engine refuses to open because its structure is invalid (see DECLARED_OPEN_REFUSALS).
LOCAL_COLUMNS = {("dex_files", "source_path")}
DECLARED_OPEN_REFUSALS = {
    "shared-class-data": "two class definitions share one class_data_item; the engine refuses the DEX (INVALID_INPUT), the reference reads it",
}
NON_SCALAR_MARKERS = ("non_scalar_UTF16", "NON_SCALAR_TEXT_PROJECTION")
# The reference's own paging defect (0.1.0): reading `code_items` of a DEX whose code item no method declares, it counts
# the item but delivers no page, and `next_offset` stays where it was. What it delivered before it stalled is what the
# record holds (nothing, for these); the engine answers `code_items` with the method-bound items only, which here are none.
A0_PAGING_DEFECTS = {
    ("all-debug-opcodes", "code_items"), ("fill-array", "code_items"), ("packed-switch", "code_items"),
    ("sparse-switch", "code_items"), ("try-catch-all", "code_items"), ("shared-class-data", "code_items"),
    # a type list nothing refers to: counted (count(*) is 1), never delivered
    ("parameter-empty-zero-proto", "type_lists"), ("parameter-orphan-empty-no-binding", "type_lists"),
}
# What the reference leaves out although the DEX holds it: the entries of a type list nothing refers to. The engine reads the
# physical section, so it delivers the list and its entries; the rows the reference does deliver must all be among them.
REFERENCE_GAPS = A0_PAGING_DEFECTS | {
    ("parameter-empty-zero-proto", "type_list_entries"), ("parameter-orphan-empty-no-binding", "type_list_entries"),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def page_relation(client: McpClient, dataset_id: str, relation: str) -> dict:
    rows: list = []
    columns = None
    offset = 0
    while True:
        if offset + PAGE > WINDOW:
            raise RuntimeError(f"{relation}: paging passed the {WINDOW} row window")
        response = client.request("tools/call", {"name": "query", "arguments": {
            "dataset_id": dataset_id, "sql": [f"SELECT * FROM {relation}"], "limit": PAGE, "offset": offset}})
        if "error" in response:
            return {"error": "jsonrpc: " + json.dumps(response["error"], ensure_ascii=False), "columns": columns, "rows": rows}
        result = response["result"]
        if result.get("isError"):
            return {"error": result["content"][0]["text"], "columns": columns, "rows": rows}
        statement = result["structuredContent"]["statements"][0]
        if statement.get("kind") != "query":
            return {"error": "unexpected statement " + json.dumps(statement, ensure_ascii=False)[:300], "columns": columns, "rows": rows}
        if columns is None:
            columns = statement["columns"]
        rows.extend(statement["rows"])
        next_offset = statement.get("next_offset")
        if next_offset is None:
            return {"error": None, "columns": columns, "rows": rows}
        if next_offset <= offset:
            return {"error": f"paging stuck at offset {offset}", "columns": columns, "rows": rows}
        offset = next_offset


def cell_text(cell) -> str:
    return json.dumps(cell, ensure_ascii=False, sort_keys=True)


def float_bits(value: float) -> int:
    bits = struct.unpack("<q", struct.pack("<d", value))[0]
    return bits if bits >= 0 else -(bits & 0x7FFF_FFFF_FFFF_FFFF)


def within_one_ulp(a, b) -> bool:
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return False
    if math.isnan(a) or math.isnan(b) or math.isinf(a) or math.isinf(b):
        return False
    return abs(float_bits(float(a)) - float_bits(float(b))) <= 1


def normalized(cell, tag_ints: bool):
    """The cell as (type, value). With `tag_ints` a recorded int64 cell is compared as uint64 when it is not negative
    (declared difference INT_TAG)."""
    kind, value = cell.get("type"), cell.get("value")
    if tag_ints and kind == "int64" and isinstance(value, str) and not value.startswith("-"):
        kind = "uint64"
    return json.dumps({"type": kind, "value": value}, ensure_ascii=False, sort_keys=True)


def compare(relation: str, recorded: dict, got: dict, fixture: str = "") -> dict:
    """Cells decide the verdict. Column metadata is compared too, but a difference in the type or the nullable flag of a
    column that the engine reports for a result is kept as a note, not as a failure of the cells."""
    if got["error"] is not None:
        verdict = "refused_by_design" if any(marker in got["error"] for marker in NON_SCALAR_MARKERS) else "error"
        return {"verdict": verdict, "detail": got["error"][:400], "rows_recorded": len(recorded["rows"]), "rows_engine": len(got["rows"])}
    want_columns = [(c["name"], c["data_type"], c["nullable"]) for c in recorded["columns"]]
    have_columns = [(c["name"], c["data_type"], c["nullable"]) for c in got["columns"]]
    if [c[0] for c in want_columns] != [c[0] for c in have_columns]:
        return {"verdict": "differs", "detail": f"column names recorded {[c[0] for c in want_columns]} engine {[c[0] for c in have_columns]}",
                "rows_recorded": len(recorded["rows"]), "rows_engine": len(got["rows"])}
    skip = {i for i, c in enumerate(want_columns) if (relation, c[0]) in LOCAL_COLUMNS}
    int64_columns = {i for i, c in enumerate(want_columns) if c[1] == "int64"}
    declared = {"int_tag_cells": 0, "local_cells": 0}

    def project(rows: list, recorded_side: bool) -> list:
        out = []
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                if i in skip:
                    cells.append("<local>")
                    declared["local_cells"] += 1 if recorded_side else 0
                    continue
                tag = i in int64_columns
                text = normalized(cell, tag)
                if tag and recorded_side and cell.get("type") == "int64" and normalized(cell, False) != text:
                    declared["int_tag_cells"] += 1
                cells.append(text)
            out.append(cells)
        return out

    want = project(recorded["rows"], True)
    have = project(got["rows"], False)
    float_columns = [i for i, c in enumerate(want_columns) if c[1] == "float64"]
    if float_columns and len(recorded["rows"]) == len(got["rows"]):
        for r_row, g_row, w, h in zip(recorded["rows"], got["rows"], want, have):
            for i in float_columns:
                a, b = r_row[i].get("value"), g_row[i].get("value")
                if w[i] != h[i] and within_one_ulp(a, b):
                    h[i] = w[i]
                    declared["float_ulp_cells"] = declared.get("float_ulp_cells", 0) + 1
    out = {"rows_recorded": len(want), "rows_engine": len(have)}
    notes = [f"{c[0]}: {c[1]}{'?' if c[2] else ''} -> {d[1]}{'?' if d[2] else ''}"
             for c, d in zip(want_columns, have_columns) if c[1:] != d[1:]]
    if notes:
        out["column_metadata_notes"] = notes
    if declared["int_tag_cells"]:
        out["declared_INT_TAG_cells"] = declared["int_tag_cells"]
    if declared.get("float_ulp_cells"):
        out["declared_FLOAT_ULP_cells"] = declared["float_ulp_cells"]
    if want == have:
        out["verdict"] = "match" if not notes else "match_cells"
    elif sorted(want) == sorted(have):
        out["verdict"] = "reordered"
        out["first_difference"] = {"row": first_difference(want, have)["row"]}
    elif (fixture, relation) in REFERENCE_GAPS and not (collections.Counter(map(tuple, want)) - collections.Counter(map(tuple, have))):
        # every row the reference delivered is there; the engine also has the rows the reference could not or did not give
        out["verdict"] = "reference_incomplete"
        out["first_difference"] = {"row": first_difference(sorted(want), sorted(have))["row"]}
    else:
        out["verdict"] = "differs"
        if len(want) != len(have):
            out["detail"] = f"{len(want)} rows recorded, {len(have)} from the engine"
        out["first_difference"] = first_difference(want, have)
    return out


def first_difference(want: list, have: list) -> dict:
    for index, (a, b) in enumerate(zip(want, have)):
        if a != b:
            return {"row": index, "recorded": a, "engine": b}
    longer, which = (want, "recorded") if len(want) > len(have) else (have, "engine")
    shorter = min(len(want), len(have))
    return {"row": shorter, which: longer[shorter]}


def reference_text(directory: Path, first: Path) -> str:
    engine = json.loads(first.read_text(encoding="utf-8"))["engine"]
    try:
        where = directory.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        where = directory.name
    return f"{engine['name']} {engine['version']} ({engine['sha256']}), recorded in {where}/"


def write_record(path: Path, record: dict) -> None:
    """The record as JSON with one line per (fixture, relation) answer, small enough to review as a diff."""
    head = [f"{json.dumps(key)}: {json.dumps(value, ensure_ascii=False)}" for key, value in record.items() if key != "results"]
    fixtures = []
    for fixture, per in record["results"].items():
        if "open_error" in per:
            fixtures.append(f"{json.dumps(fixture)}: {json.dumps(per, ensure_ascii=False)}")
            continue
        rows = ",\n".join(f"  {json.dumps(name)}: {json.dumps(value, ensure_ascii=False)}" for name, value in per.items())
        fixtures.append(f"{json.dumps(fixture)}: {{\n{rows}\n}}")
    text = "{\n" + ",\n".join(head) + ',\n"results": {\n' + ",\n".join(fixtures) + "\n}\n}\n"
    json.loads(text)  # never write what cannot be read back
    path.write_text(text, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--relations", default="")
    parser.add_argument("--fixtures", default="")
    parser.add_argument("--allow", default="")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "mdd-070" / "public-relations-diff.json")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--dialect", default="", help="the SQL dialect the server runs in (dexsql-0.1.0 or dexsql-0.1.1); the server default when empty")
    parser.add_argument("--probe-dir", type=Path, default=PROBE_DIR, help="the recorded answers to replay (a0-probe: dexsql 0.1.0, a1-probe: dexsql 0.1.1)")
    parser.add_argument("--strict-order", action="store_true", help="a relation read in another order than the recorded one fails")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    order = [entry["name"] for entry in manifest["relations"]]
    wanted = [r for r in args.relations.split(",") if r] or order
    unknown = [r for r in wanted if r not in order]
    if unknown:
        raise SystemExit(f"not relations of the frozen manifest: {unknown}")
    only_fixtures = {f for f in args.fixtures.split(",") if f}
    allowed = {r for r in args.allow.split(",") if r}

    probes = []
    for path in sorted(args.probe_dir.glob("*.json")):
        if path.name == "describe-tables.json":
            continue
        if only_fixtures and path.stem not in only_fixtures:
            continue
        probes.append(path)
    if not probes:
        raise SystemExit("no probe record selected")

    client = McpClient(args.binary, ["--dialect", args.dialect] if args.dialect else None)
    results: dict = {}
    try:
        info = client.initialize()
        for path in probes:
            record = json.loads(path.read_text(encoding="utf-8"))
            fixture = ROOT / record["fixture"]
            if sha256(fixture) != record["fixture_sha256"]:
                raise SystemExit(f"{record['fixture']} is not the fixture that was recorded")
            opened = client.call("open_dataset", inputs=[str(fixture)])
            if opened.get("_is_error"):
                declared = DECLARED_OPEN_REFUSALS.get(path.stem)
                results[path.stem] = {"open_error": json.dumps(opened, ensure_ascii=False)[:400], "declared": declared}
                print(f"{path.stem}: open refused" + (" (declared)" if declared else " (NOT DECLARED)"), flush=True)
                continue
            dataset_id = opened["dataset_id"]
            tables = {t["name"] for t in client.call("list_tables")["tables"]}
            per_relation = {}
            for relation in wanted:
                if relation not in tables:
                    per_relation[relation] = {"verdict": "error", "detail": "not listed by list_tables",
                                              "rows_recorded": len(record["relations"][relation]["rows"]), "rows_engine": 0}
                    continue
                per_relation[relation] = compare(relation, record["relations"][relation], page_relation(client, dataset_id, relation), path.stem)
            client.call("close_dataset", dataset_id=dataset_id)
            results[path.stem] = per_relation
            if not args.quiet:
                bad = {r: v["verdict"] for r, v in per_relation.items() if v["verdict"] not in ("match", "match_cells")}
                print(f"{path.stem}: {len(per_relation) - len(bad)}/{len(per_relation)} match" + (f"  {bad}" if bad else ""), flush=True)
    finally:
        client.close()

    undeclared_open = [f for f, r in results.items() if "open_error" in r and not r.get("declared")]
    summary: dict = {}
    for relation in wanted:
        verdicts = [results[f][relation]["verdict"] for f in results if relation in results[f]]
        summary[relation] = {
            "fixtures": len(verdicts),
            "match": verdicts.count("match"), "match_cells": verdicts.count("match_cells"), "reordered": verdicts.count("reordered"),
            "refused_by_design": verdicts.count("refused_by_design"),
            "reference_incomplete": verdicts.count("reference_incomplete"),
            "differs": verdicts.count("differs"), "error": verdicts.count("error"),
            "nonempty_fixtures": sum(1 for f in results if relation in results[f] and results[f][relation]["rows_recorded"] > 0),
        }
    passing = ("match", "match_cells") if args.strict_order else ("match", "match_cells", "reordered")
    # refused_by_design counts as passing only because the refusal itself is the declared behaviour (NON_SCALAR)
    passing = (*passing, "refused_by_design", "reference_incomplete")
    blocking = [r for r in wanted if r not in allowed
                and any(results[f][r]["verdict"] not in passing for f in results if r in results[f])]
    all_match = all(v["fixtures"] == v["match"] + v["match_cells"] for v in summary.values()) and not undeclared_open
    record = {
        "schema_version": "mdd.public-relations-diff.v2",
        "engine_under_test": {"binary_sha256": sha256(args.binary), "server": info.get("serverInfo"), "dialect": args.dialect or "server default"},
        "reference": reference_text(args.probe_dir, probes[0]),
        "relations_compared": wanted, "fixtures_compared": [p.stem for p in probes],
        "declared_open_refusals": DECLARED_OPEN_REFUSALS, "undeclared_open_refusals": undeclared_open,
        "all_match": all_match, "blocking_relations": blocking, "summary": summary, "results": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_record(args.out, record)
    total = sum(v["fixtures"] for v in summary.values())
    print(f"{sum(v['match'] + v['match_cells'] for v in summary.values())} of {total} (relation, fixture) pairs match exactly, "
          f"{sum(v['reordered'] for v in summary.values())} only in another order, {sum(v['refused_by_design'] for v in summary.values())} refused by design, {sum(v['reference_incomplete'] for v in summary.values())} where the reference is incomplete; "
          f"blocking relations: {blocking}; undeclared open refusals: {undeclared_open}; wrote {args.out}")
    return 0 if not blocking and not undeclared_open else 1


if __name__ == "__main__":
    sys.exit(main())
