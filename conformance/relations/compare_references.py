#!/usr/bin/env python3
"""MDD-070: do dexsql 0.1.0 and dexsql 0.1.1 answer the 56 relations alike?

Compares the two sets of recorded answers (artifacts/mdd-070/a0-probe/ and a1-probe/, same fixtures, same questions)
cell by cell with the comparison of public_relations_diff.py, plus the table list and every description. The answer is
data: artifacts/mdd-070/reference-versions.json. Nothing is run against a reference here; the records are read.

Usage: python -I conformance/relations/compare_references.py [--check]
  --check   only say whether the committed record was built from the current records (no write)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "conformance" / "mcp"))

import public_relations_diff as D  # noqa: E402

OUT = "artifacts/mdd-070/reference-versions.json"
OLD, NEW = "artifacts/mdd-070/a0-probe", "artifacts/mdd-070/a1-probe"


def records(directory: str) -> dict[str, Path]:
    return {p.stem: p for p in sorted((ROOT / directory).glob("*.json")) if p.name != "describe-tables.json"}


def digest(directory: str) -> str:
    h = hashlib.sha256()
    for path in sorted((ROOT / directory).glob("*.json")):
        h.update(path.name.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def build() -> dict:
    old, new = records(OLD), records(NEW)
    if list(old) != list(new):
        raise SystemExit(f"the two sets cover different fixtures: {sorted(set(old) ^ set(new))}")
    verdicts: dict[str, int] = {}
    different: list[dict] = []
    tables_equal = True
    for stem in old:
        a = json.loads(old[stem].read_text(encoding="utf-8"))
        b = json.loads(new[stem].read_text(encoding="utf-8"))
        if a["fixture_sha256"] != b["fixture_sha256"]:
            raise SystemExit(f"{stem}: the two records are not of the same bytes")
        tables_equal &= a["list_tables"] == b["list_tables"]
        for name, first in a["relations"].items():
            second = b["relations"][name]
            out = D.compare(name, {"columns": first["columns"], "rows": first["rows"]},
                            {"columns": second["columns"], "rows": second["rows"], "error": second["error"]})
            verdicts[out["verdict"]] = verdicts.get(out["verdict"], 0) + 1
            if out["verdict"] != "match" or first["paging_stuck"] != second["paging_stuck"] or first["total_rows"] != second["total_rows"]:
                different.append({"fixture": stem, "relation": name, "verdict": out["verdict"],
                                  "paging_stuck": [first["paging_stuck"], second["paging_stuck"]],
                                  "total_rows": [first["total_rows"], second["total_rows"]]})
    d_old = json.loads((ROOT / OLD / "describe-tables.json").read_text(encoding="utf-8"))
    d_new = json.loads((ROOT / NEW / "describe-tables.json").read_text(encoding="utf-8"))
    described_differently = sorted(n for n in d_old["tables"] if d_old["tables"][n] != d_new["tables"].get(n))
    return {
        "schema_version": "mdd.reference-versions.v1",
        "task": "MDD-070",
        "kind": "development evidence; admits no profile",
        "older": d_old["engine"], "newer": d_new["engine"],
        "fixtures": len(old), "relations": len(a["relations"]), "pairs": sum(verdicts.values()),
        "verdicts": verdicts,
        "pairs_that_differ": different,
        "list_tables_equal": tables_equal,
        "describe_table_equal": not described_differently,
        "described_differently": described_differently,
        "reading": ("identical" if not different and tables_equal and not described_differently else "differs"),
        "limits": ["only the windows-amd64 build of each version was probed", "the fixtures are small synthetic DEX files; the question asked of each relation was SELECT * paged to the end",
                   "equal answers on these fixtures do not show equal answers on others, nor equal SQL behaviour beyond them"],
        "inputs_sha256": {OLD: digest(OLD), NEW: digest(NEW), "conformance/relations/public_relations_diff.py": hashlib.sha256((ROOT / "conformance/relations/public_relations_diff.py").read_bytes()).hexdigest()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        record = json.loads((ROOT / OUT).read_text(encoding="utf-8"))
        current = build()
        stale = [k for k, v in current["inputs_sha256"].items() if record["inputs_sha256"].get(k) != v]
        for path in stale:
            print("STALE:", path)
        print("committed comparison current:", not stale)
        return 1 if stale else 0
    record = build()
    (ROOT / OUT).write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT}: {record['pairs']} pairs, reading: {record['reading']}, verdicts {record['verdicts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
