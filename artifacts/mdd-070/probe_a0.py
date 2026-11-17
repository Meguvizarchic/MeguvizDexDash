#!/usr/bin/env python3
"""MDD-070: probe a reference engine (dexsql) for all 56 public relations.

Usage: python -I artifacts/mdd-070/probe_a0.py [BINARY] [--version 0.1.0] [--out DIR] [--raw DIR]
  dexsql 0.1.0 (A0): the defaults; records go to artifacts/mdd-070/a0-probe/
  dexsql 0.1.1 (A1): --version 0.1.1 --out artifacts/mdd-070/a1-probe --raw artifacts/local/mdd-070-a1

Opens each rich fixture, records list_tables / describe_table schemas and the full
paged rows of every frozen relation. Raw records (with local absolute paths) go to
the ignored artifacts/local/mdd-070/; sanitized records (repo-relative fixture
paths only) go to artifacts/mdd-070/a0-probe/ for committed evidence.

No bare asserts: every invariant violation raises explicitly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "conformance" / "mcp"))
from mcp_client import McpClient  # noqa: E402

# the reference binary is an ignored local input (artifacts/local/dexsql-a0/); pass its path as the first argument
_ARGS = argparse.ArgumentParser(description="probe a reference dexsql for the 56 public relations")
_ARGS.add_argument("binary", nargs="?", type=Path, default=ROOT / "artifacts" / "local" / "dexsql-a0" / "dexsql-windows-amd64.exe")
_ARGS.add_argument("--version", default="0.1.0", help="the version the server must report")
_ARGS.add_argument("--out", type=Path, default=ROOT / "artifacts" / "mdd-070" / "a0-probe")
_ARGS.add_argument("--raw", type=Path, default=ROOT / "artifacts" / "local" / "mdd-070")
_OPTIONS = _ARGS.parse_args()
A0 = _OPTIONS.binary
RAW_DIR = _OPTIONS.raw
OUT_DIR = _OPTIONS.out

FIXTURES = [
    "tests/fixtures/annotations/generated/annotations-038.dex",
    "tests/fixtures/annotations/generated/valid-call-site-array.dex",
    "tests/fixtures/annotations/generated/valid-orphan-arrays.dex",
    "tests/fixtures/annotations/generated/valid-static-empty-array.dex",
    "tests/fixtures/references/generated/handles-039.dex",
    "tests/fixtures/references/generated/poly-custom-038.dex",
    "tests/fixtures/references/generated/classic-035.dex",
    "tests/fixtures/references/generated/nonscalar-string-035.dex",
    "tests/fixtures/instructions/generated/all-debug-opcodes.dex",
    "tests/fixtures/instructions/generated/try-catch-all.dex",
    "tests/fixtures/instructions/generated/packed-switch.dex",
    "tests/fixtures/instructions/generated/sparse-switch.dex",
    "tests/fixtures/instructions/generated/fill-array.dex",
    "tests/fixtures/decode/generated/decode-all.dex",
    "tests/fixtures/definitions/generated/definitions-035.dex",
    "tests/fixtures/definitions/generated/definitions-038.dex",
    "tests/fixtures/definitions/generated/definitions-040.dex",
    "tests/fixtures/definitions/generated/shared-class-data.dex",
    "tests/fixtures/definitions/generated/empty-class-data.dex",
    "tests/fixtures/generated/minimal-035.dex",
    "tests/fixtures/generated/strings-mutf8-035.dex",
    "tests/fixtures/public_relations/generated/debug-methods-035.dex",
    "tests/fixtures/public_relations/generated/hiddenapi-039.dex",
    "tests/fixtures/public_relations/generated/static-values-035.dex",
    "tests/fixtures/public_relations/generated/proto-share-035.dex",
    "tests/fixtures/public_relations/generated/debug-programs-035.dex",
    "tests/fixtures/public_relations/generated/hiddenapi-order-039.dex",
    "tests/fixtures/public_relations/generated/marker-annotation-038.dex",
    "tests/fixtures/public_relations/generated/build-annotation-038.dex",
    "tests/fixtures/public_relations/generated/call-site-extra-args-038.dex",
    "tests/fixtures/public_relations/generated/root-class-035.dex",
    "tests/fixtures/public_relations/generated/static-values-nested-035.dex",
    "tests/fixtures/annotations/generated/parameter-empty-nonzero-proto.dex",
    "tests/fixtures/annotations/generated/parameter-empty-zero-proto.dex",
    "tests/fixtures/annotations/generated/parameter-long-nonzero-proto.dex",
    "tests/fixtures/annotations/generated/parameter-orphan-empty-no-binding.dex",
    "tests/fixtures/annotations/generated/parameter-shared-empty-set.dex",
    "tests/fixtures/annotations/generated/parameter-shared-signature-complete.dex",
    "tests/fixtures/annotations/generated/parameter-shared-signature.dex",
    "tests/fixtures/annotations/generated/valid-orphan-annotation.dex",
    "tests/fixtures/annotations/generated/valid-orphan-empty-directory.dex",
    "tests/fixtures/annotations/generated/valid-orphan-empty-ref-list.dex",
    "tests/fixtures/annotations/generated/valid-orphan-empty-set.dex",
    "tests/fixtures/annotations/generated/valid-orphan-external-directory.dex",
    "tests/fixtures/annotations/generated/valid-orphan-known-directory.dex",
    "tests/fixtures/annotations/generated/valid-shared-empty-directory.dex",
    "tests/fixtures/annotations/generated/valid-shared-empty-set.dex",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def query_relation(client: McpClient, dataset_id: str, relation: str) -> dict:
    """Page SELECT * FROM <relation> to completion; record errors verbatim.

    A0 0.1.0 can report ``truncated=true`` with ``next_offset`` stuck at the
    current offset (observed on unbound code_items); that is recorded honestly
    as ``paging_stuck`` instead of being retried forever or hidden.
    """
    rows: list = []
    columns = None
    offset = 0
    pages = 0
    total_rows = None
    truncated = False
    paging_stuck = False
    while True:
        if offset + 1000 > 100000:
            raise RuntimeError(f"{relation}: paging exceeded the 100000 row window")
        response = client.request("tools/call", {"name": "query", "arguments": {
            "dataset_id": dataset_id, "sql": [f"SELECT * FROM {relation}"],
            "limit": 1000, "offset": offset}})
        if "error" in response:
            raise RuntimeError(f"{relation}: JSON-RPC error {response['error']}")
        result = response["result"]
        if result.get("isError"):
            text = result["content"][0]["text"]
            return {"error": text, "columns": columns, "rows": rows,
                    "row_count": len(rows), "pages": pages,
                    "total_rows": total_rows, "truncated": truncated,
                    "paging_stuck": paging_stuck}
        structured = result["structuredContent"]
        statement = structured["statements"][0]
        if statement.get("kind") != "query":
            raise RuntimeError(f"{relation}: unexpected statement kind {statement}")
        if columns is None:
            columns = statement["columns"]
        elif columns != statement["columns"]:
            raise RuntimeError(f"{relation}: columns changed between pages")
        rows.extend(statement["rows"])
        pages += 1
        total_rows = statement.get("total_rows")
        truncated = bool(statement.get("truncated"))
        next_offset = statement.get("next_offset")
        if next_offset is None:
            break
        if next_offset <= offset:
            paging_stuck = True
            break
        offset = next_offset
    return {"error": None, "columns": columns, "rows": rows,
            "row_count": len(rows), "pages": pages,
            "total_rows": total_rows, "truncated": truncated,
            "paging_stuck": paging_stuck}


def main() -> None:
    manifest = json.loads((ROOT / "conformance" / "manifests" / "relations.json").read_text("utf-8"))
    relations = [entry["name"] for entry in manifest["relations"]]
    if len(relations) != 56:
        raise RuntimeError(f"expected 56 frozen relations, found {len(relations)}")
    if not A0.is_file():
        raise RuntimeError(f"A0 binary missing: {A0}")
    engine_sha = sha256(A0)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    client = McpClient(A0)
    try:
        info = client.initialize()
        server = info.get("serverInfo", {})
        # 0.1.1 reports its build too ("0.1.1+<commit>"); the record keeps the whole string
        if str(server.get("version")).split("+")[0] != _OPTIONS.version:
            raise RuntimeError(f"unexpected reference version: {server}, wanted {_OPTIONS.version}")
        describes = {}
        for relation in relations:
            response = client.request("tools/call", {"name": "describe_table",
                                                     "arguments": {"name": relation}})
            result = response["result"]
            if result.get("isError"):
                describes[relation] = {"error": result["content"][0]["text"]}
            else:
                describes[relation] = result["structuredContent"]
        (OUT_DIR / "describe-tables.json").write_text(
            json.dumps({"engine": {"name": server.get("name"), "version": server.get("version"),
                                   "sha256": engine_sha},
                        "tables": describes}, ensure_ascii=False, indent=1), "utf-8")

        for fixture in FIXTURES:
            path = ROOT / fixture
            if not path.is_file():
                raise RuntimeError(f"fixture missing: {path}")
            opened = client.call("open_dataset", inputs=[str(path)])
            if opened.get("_is_error"):
                raise RuntimeError(f"open_dataset failed for {fixture}: {opened}")
            dataset_id = opened["dataset_id"]
            listed = client.call("list_tables")
            record = {"fixture": fixture, "fixture_sha256": sha256(path),
                      "list_tables": listed["tables"], "relations": {}}
            for relation in relations:
                data = query_relation(client, dataset_id, relation)
                if data["error"] is None and data["row_count"] == 0 and data["total_rows"]:
                    counted = client.call("query", dataset_id=dataset_id,
                                          sql=[f"SELECT count(*) FROM {relation}"], limit=10)
                    data["count_star"] = counted["statements"][0]["rows"]
                record["relations"][relation] = data
            client.call("close_dataset", dataset_id=dataset_id)
            name = Path(fixture).stem + ".json"
            raw = dict(record)
            raw["fixture_absolute"] = str(path)
            raw["engine"] = {"name": server.get("name"), "version": server.get("version"),
                             "sha256": engine_sha, "binary_path": str(A0)}
            (RAW_DIR / name).write_text(json.dumps(raw, ensure_ascii=False, indent=1), "utf-8")
            record["engine"] = {"name": server.get("name"), "version": server.get("version"),
                                "sha256": engine_sha}
            # dex_files.source_path is the input path as given, i.e. a local absolute path: the committed record
            # keeps the repository-relative fixture path instead.
            files = record["relations"]["dex_files"]
            at = [column["name"] for column in files["columns"]].index("source_path")
            for row in files["rows"]:
                row[at]["value"] = record["fixture"]
            (OUT_DIR / name).write_text(json.dumps(record, ensure_ascii=False, indent=1), "utf-8")
            errors = [rel for rel, data in record["relations"].items() if data["error"]]
            stuck = [rel for rel, data in record["relations"].items() if data.get("paging_stuck")]
            total = sum(data["row_count"] for data in record["relations"].values())
            print(f"{fixture}: rows={total} errors={errors} stuck={stuck}", flush=True)
    finally:
        client.close()
    print("probe complete", flush=True)


if __name__ == "__main__":
    main()