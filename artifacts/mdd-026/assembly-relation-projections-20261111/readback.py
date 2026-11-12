#!/usr/bin/env python3
"""Compare the freshly projected native rows with the recorded HostLab A0 dumps.

The native rows come from native-row-dump.txt, produced by a temporary in-crate
test that called the new row APIs on the same fixtures the A0 slices used. The
A0 dumps are the frozen recorded evidence under artifacts/mdd-026; this script
only reads them.
"""
import datetime
import hashlib
import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DUMP = HERE / "native-row-dump.txt"
RERUN = ROOT / "artifacts/mdd-026/current-source-rerun-20261109/20261109T050254404212Z"

NUMERIC = {
    "file_id", "method_idx", "class_idx", "proto_idx", "param_count", "access_flags",
    "opcode_count", "string_pool_id", "string_idx", "type_idx", "class_def_idx",
    "interface_count", "code_off", "registers_size", "ins_size", "outs_size",
    "tries_size", "debug_info_off", "insns_size", "insns_off", "tries_off",
    "handlers_off", "byte_len", "checksum", "file_size", "header_size",
    "endian_tag", "link_size", "link_off", "map_off", "string_count",
    "string_ids_off", "type_count", "type_ids_off", "proto_count", "proto_ids_off",
    "field_count", "field_ids_off", "method_count", "method_ids_off", "class_count",
    "class_defs_off", "data_size", "data_off",
}


def parse_a0(path, numeric):
    rows = []
    header = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if set("".join(cells)) <= set("-"):
            continue
        row = {}
        for name, cell in zip(header, cells):
            if cell == "N":
                row[name] = None
                continue
            text = bytes.fromhex(cell).decode("utf-8")
            row[name] = int(text) if name in numeric else text
        rows.append(row)
    return rows


def load_native():
    native = {}
    for line in DUMP.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^@@(.+)@@(.*)$", line)
        if match:
            native[match.group(1)] = json.loads(match.group(2))
    return native


def compare(label, a0_rows, native_rows, columns, occurrence=None):
    if occurrence is not None:
        a0_rows = [row for row in a0_rows if row.get("file_id") == occurrence]
    limit = min(len(a0_rows), len(native_rows))
    differences = []
    for index in range(limit):
        keys = columns or sorted(set(a0_rows[index]) & set(native_rows[index]))
        for key in keys:
            if a0_rows[index].get(key) != native_rows[index].get(key):
                differences.append(
                    {
                        "row": index,
                        "column": key,
                        "a0": a0_rows[index].get(key),
                        "native": native_rows[index].get(key),
                    }
                )
    return {
        "label": label,
        "a0_rows": len(a0_rows),
        "native_rows": len(native_rows),
        "compared_rows": limit,
        "compared_columns": columns or "intersection",
        "differences": differences,
        "equal": len(a0_rows) == len(native_rows) and not differences,
    }


def main():
    native = load_native()
    checks = [
        compare(
            "methods:definitions-035.dex",
            parse_a0(RERUN / "methods/a0-definitions/stdout.txt", NUMERIC),
            native["methods:definitions"],
            ["file_id", "method_idx", "class_idx", "class_descriptor", "proto_idx",
             "name", "descriptor", "return_descriptor", "param_count",
             "access_flags", "method_kind"],
        ),
        compare(
            "methods:shared-code-035.dex",
            parse_a0(RERUN / "methods/a0-shared/stdout.txt", NUMERIC),
            native["methods:shared"],
            ["file_id", "method_idx", "class_idx", "class_descriptor", "proto_idx",
             "name", "descriptor", "return_descriptor", "param_count",
             "access_flags", "method_kind"],
        ),
        compare(
            "code_items:classic-035.dex",
            parse_a0(RERUN / "code_atoms/a0-classic/stdout.txt", NUMERIC),
            native["code_items:classic"],
            None,
        ),
        compare(
            "code_items:shared-code-035.dex",
            parse_a0(RERUN / "code_atoms/a0-shared/stdout.txt", NUMERIC),
            native["code_items:shared"],
            None,
        ),
        compare(
            "types:type-names-035.dex",
            parse_a0(RERUN / "types_text/a0-types-type-names/stdout.txt", NUMERIC),
            native["types:type-names"],
            None,
        ),
        compare(
            "strings:classic-035.dex",
            parse_a0(RERUN / "cross_dex/a0-join-two-distinct-raw/stdout.txt", NUMERIC),
            native["strings:classic"],
            ["file_id", "string_pool_id", "string_idx", "value"],
            occurrence=0,
        ),
    ]

    # dex_files has only four measured A0 columns; the two catalog ids are the
    # only comparable ones because source_path/entry_name are the documented gap.
    a0_dex = parse_a0(RERUN / "cross_dex/a0-dex-files-two-distinct-raw/stdout.txt",
                     {"file_id", "string_pool_id"})
    native_dex = native["dex_files:classic"][0]
    dex_equal = (
        a0_dex[0]["file_id"] == native_dex["file_id"]
        and a0_dex[0]["string_pool_id"] == native_dex["string_pool_id"]
    )
    checks.append(
        {
            "label": "dex_files:classic-035.dex (catalog ids only)",
            "a0_rows": len(a0_dex),
            "native_rows": len(native["dex_files:classic"]),
            "compared_rows": 1,
            "compared_columns": ["file_id", "string_pool_id"],
            "differences": [],
            "equal": dex_equal,
            "note": "source_path/entry_name are unassembled by design; the A0 slice measures only these four columns",
        }
    )

    report = {
        "schema_version": "mdd.relation-projection-readback.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task": "MDD-026",
        "native_dump": "native-row-dump.txt",
        "native_dump_sha256": hashlib.sha256(DUMP.read_bytes()).hexdigest(),
        "a0_source": "artifacts/mdd-026/current-source-rerun-20261109/20261109T050254404212Z",
        "native_projection_scope": "single-occurrence row APIs with caller-supplied file_id=0/string_pool_id=0",
        "results": checks,
        "all_equal": all(item["equal"] for item in checks),
        "limits": [
            "Small synthetic fixtures only; no private inputs and no HostLab workload.",
            "The A0 dumps were recorded by the frozen verifier before this change; the native rows were produced by the new row APIs on the same fixture bytes.",
            "dex_files and strings A0 slices measure only a subset of the contract columns.",
        ],
    }
    (HERE / "readback.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    for item in checks:
        print(
            f"{item['label']}: a0={item['a0_rows']} native={item['native_rows']} "
            f"compared={item['compared_rows']} diffs={len(item['differences'])} "
            f"{'OK' if item['equal'] else 'MISMATCH'}"
        )
    print("all_equal:", report["all_equal"])


if __name__ == "__main__":
    main()
