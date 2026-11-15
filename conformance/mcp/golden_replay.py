#!/usr/bin/env python3
"""Replay the frozen A0 `query` recordings through the MCP server and compare them.

The recording (conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json) was
made by driving the reference engine's own MCP server with `open_dataset` on three
fixtures and then `query` per variant, following `next_offset` for walks. This script
sends the same requests to meguvizdexdash and compares, page by page: the column names,
every cell in the reference's canonical form, `offset`, `next_offset`, `truncated` and
`total_rows`. Refused requests are compared on whether they were refused and, for a
statement the engine rejected, on the statement index.

Usage: python -I conformance/mcp/golden_replay.py [--binary PATH]
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_client import DEFAULT_BINARY, ROOT, McpClient, McpError  # noqa: E402

import json  # noqa: E402

VARIANTS = "conformance/corpus/hostlab/required-variants.json"
GOLDEN = "conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json"
DEFAULT_LIMIT = 200


def canonical(cell: dict) -> str:
    kind, value = cell["type"], cell["value"]
    if kind == "null":
        return "N"
    if kind in ("int64", "uint64"):
        return "i:" + str(int(value))
    if kind == "float64":
        number = float(value)
        return "f:nan" if number != number else "f:" + struct.pack(">d", number).hex()
    if kind == "utf8":
        return "t:" + value.encode("utf-8").hex()
    if kind == "binary":
        return "b:" + value.lower()
    raise ValueError(f"unmodelled cell type {kind!r}")


def record(statement: dict) -> dict:
    return {
        "columns": [column["name"] for column in statement["columns"]],
        "rows": [[canonical(cell) for cell in row] for row in statement["rows"]],
        "offset": statement["offset"],
        "next_offset": statement["next_offset"],
        "truncated": statement["truncated"],
        "total_rows": statement.get("total_rows"),
    }


def page(client: McpClient, dataset: str, statements: list[str], limit: int, offset: int) -> dict:
    try:
        reply = client.call("query", dataset_id=dataset, sql=statements, limit=limit, offset=offset)
    except McpError as error:
        return {"refused": "protocol", "code": error.code}
    if reply["_is_error"]:
        details = reply["error"].get("details", {})
        index = details.get("statement_index")
        return {"refused": "tool", "statement_index": None if index is None else int(index), "error": reply["error"]}
    return {"statements": [record(s) for s in reply["statements"]]}


def first_difference(actual: list, expected: list) -> str | None:
    if len(actual) != len(expected):
        return f"{len(actual)} pages, recorded {len(expected)}"
    for number, (a, e) in enumerate(zip(actual, expected)):
        if "statements" not in a:
            return f"page {number} was refused: {a}"
        if len(a["statements"]) != len(e["statements"]):
            return f"page {number}: {len(a['statements'])} statements, recorded {len(e['statements'])}"
        for index, (sa, se) in enumerate(zip(a["statements"], e["statements"])):
            for key in ("columns", "offset", "next_offset", "truncated", "total_rows"):
                if sa[key] != se[key]:
                    return f"page {number} statement {index} {key}: {sa[key]!r}, recorded {se[key]!r}"
            if sa["rows"] != se["rows"]:
                for row, (ra, re_) in enumerate(zip(sa["rows"], se["rows"])):
                    if ra != re_:
                        return f"page {number} statement {index} row {row}: {ra}, recorded {re_}"
                return f"page {number} statement {index}: {len(sa['rows'])} rows, recorded {len(se['rows'])}"
    return None


def replay(binary: Path) -> dict:
    spec = json.loads((ROOT / VARIANTS).read_text(encoding="utf-8"))
    golden = json.loads((ROOT / GOLDEN).read_text(encoding="utf-8"))
    if golden["inputs"] != spec["inputs"] or len(golden["cases"]) != len(spec["variants"]):
        raise SystemExit("the golden and the variants are out of step")
    client = McpClient(binary)
    client.initialize()
    opened = client.call("open_dataset", inputs=[str((ROOT / p).resolve()) for p in spec["inputs"]])
    if opened["_is_error"]:
        raise SystemExit("the fixtures did not open: " + json.dumps(opened))
    dataset = opened["dataset_id"]
    differences, pages_checked, rows_checked = [], 0, 0
    for variant, case in zip(spec["variants"], golden["cases"]):
        key = f"{variant['family']}/{variant['variant']}"
        limit, offset = variant.get("limit", DEFAULT_LIMIT), variant.get("offset", 0)
        if (case["family"], case["variant"]) != (variant["family"], variant["variant"]):
            raise SystemExit("golden is out of step at " + key)
        pages = []
        cursor = offset
        for _ in range(4000):
            got = page(client, dataset, variant["statements"], limit, cursor)
            pages.append(got)
            if "statements" not in got or not variant.get("walk"):
                break
            cursor = got["statements"][0]["next_offset"]
            if cursor is None:
                break
        difference = first_difference(pages, case["pages"])
        pages_checked += len(pages)
        rows_checked += sum(len(s["rows"]) for p in pages if "statements" in p for s in p["statements"])
        if difference:
            differences.append({"case": key, "difference": difference})
    rejections = []
    for item, recorded in zip(spec["rejections"], golden["rejections"]):
        got = page(client, dataset, item["statements"], item["limit"], item["offset"])
        refused = "statements" not in got
        row = {"name": item["name"], "refused": refused, "recorded_refused": recorded["refused"]}
        if refused and got.get("refused") == "tool":
            row["statement_index"] = got["statement_index"]
        row["recorded_statement_index"] = recorded.get("error", {}).get("statement_index")
        rejections.append(row)
    code = client.close()
    mismatched = [r for r in rejections
                  if r["refused"] != r["recorded_refused"]
                  or (r.get("statement_index") is not None and r["recorded_statement_index"] is not None
                      and r["statement_index"] != r["recorded_statement_index"])]
    return {
        "cases": len(golden["cases"]), "pages": pages_checked, "rows": rows_checked,
        "walks": sum(1 for v in spec["variants"] if v.get("walk")),
        "differences": differences, "rejections": rejections, "rejection_mismatches": mismatched,
        "server_exit_code": code,
        "equal": not differences and not mismatched and code == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = replay(args.binary)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"cases={result['cases']} pages={result['pages']} rows={result['rows']} walks={result['walks']} "
          f"differences={len(result['differences'])} rejection_mismatches={len(result['rejection_mismatches'])} equal={result['equal']}")
    for item in result["differences"][:10]:
        print("DIFF", item)
    for item in result["rejection_mismatches"][:10]:
        print("REJECTION", item)
    return 0 if result["equal"] else 1


if __name__ == "__main__":
    sys.exit(main())
