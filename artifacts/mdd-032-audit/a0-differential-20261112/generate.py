#!/usr/bin/env python3
"""Record frozen-A0 results for the 17 HostLab relations over every fixture.

Usage: python generate.py A0_EXE REPO_ROOT OUTPUT_JSON

Each cell is wrapped as CASE WHEN c IS NULL THEN 'N' ELSE typeof(c)||':'||hex(c) END
so NULL, the empty string and the literal text 'NULL' stay distinct and no cell
contains the table delimiter. The one binary64 column (annotation_elements.value_f64)
is recorded as its storage class only; its bit-level comparison lives in
crates/mdd-sql/src/provider/hostlab/tests.rs. Nothing here derives from this
project's own engine.
"""
import hashlib
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

RELATIONS = ["dex_files", "strings", "types", "methods", "classes", "class_interfaces",
             "class_fields", "class_methods", "code_items", "annotation_directory_entries",
             "annotation_set_entries", "annotations", "annotation_elements", "method_strings",
             "method_calls", "method_field_accesses", "method_used_types"]
FLOAT_COLUMNS = {("annotation_elements", "value_f64")}


def wrap(relation, column):
    if (relation, column) in FLOAT_COLUMNS:
        return f"CASE WHEN {column} IS NULL THEN 'N' ELSE typeof({column}) END"
    return f"CASE WHEN {column} IS NULL THEN 'N' ELSE typeof({column})||':'||hex({column}) END"


def build_sql(relation, columns):
    select = ",".join(wrap(relation, c) for c in columns)
    order = ",".join(str(i + 1) for i in range(len(columns)))
    return f"SELECT {select} FROM {relation} ORDER BY {order}"


def parse_table(stdout):
    header, rows = None, []
    for line in stdout.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            header = cells
        else:
            rows.append(cells)
    return header, rows


def run(exe, path, sql):
    done = subprocess.run([str(exe), "query", "--input", str(path), "--sql", sql],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=300, check=False)
    if done.returncode != 0:
        return {"ok": False, "error": (done.stderr or done.stdout).strip()[:300]}
    header, rows = parse_table(done.stdout)
    return {"ok": True, "rows": rows} if header is not None else {"ok": False, "error": "no table"}


def main():
    exe, root, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    contract = json.loads((root / "conformance/manifests/relations.json").read_text(encoding="utf-8"))
    columns = {r["name"]: [c["name"] for c in r["columns"]] for r in contract["relations"]}
    inputs = sorted(p for p in (root / "tests/fixtures").rglob("*") if p.suffix in (".dex", ".apk"))
    jobs = []
    for path in inputs:
        for relation in RELATIONS:
            jobs.append((path, relation, build_sql(relation, columns[relation])))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda j: run(exe, j[0], j[2]), jobs))
    records = []
    for (path, relation, sql), result in zip(jobs, results):
        records.append({"input": path.relative_to(root).as_posix(), "relation": relation,
                        "columns": columns[relation], "sql": sql, "a0": result})
    report = {"a0_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
              "relations": RELATIONS, "inputs": len(inputs), "records": records}
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    ok = sum(1 for r in records if r["a0"]["ok"])
    print(f"inputs={len(inputs)} records={len(records)} a0_ok={ok} a0_err={len(records) - ok}")


if __name__ == "__main__":
    main()
