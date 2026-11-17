"""What is compared in the structural equivalence, and how. Test, generator and evidence support; standard library only.

A *record* is what one run of the frozen Graph and Rules over one input leaves behind (structural_frozen.record_run):
the 27 FEATURE results, the discoveries, the Graph's class records with their fields and methods (types, generics
from Signature annotations, access flags, signatures), the statements the consumer sent in order, the class count,
the DEX inventory, the refusal of the audit if it refused, and the answers to the call-site and protocol statements
(`EVIDENCE`). Two records are equal only if every one of those is equal; `compare` names each place where they are not.

`EVIDENCE` is the part of the chain of evidence that the Graph itself does not read: how often a method calls
another (COUNT(*) per caller and callee), which methods a protocol class defines, which classes a family prefix
selects. The statements have the shapes of the ones HostLab's `native_surface` sends (per DEX, LIKE ... ESCAPE,
GROUP BY, ORDER BY); the classification of families and protocols is HostLab's `surface_workers` (MDD-052) and is not
part of this comparison.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# the statements, per DEX; `{file}` is the file_id
EVIDENCE = (
    {"id": "calls", "shape": "Q10 call-site multiplicity",
     "sql": ("SELECT file_id,method,callee,COUNT(*) AS n FROM method_calls WHERE file_id={file} AND "
             "(callee_class LIKE 'Lsyn/fam/%' ESCAPE '\\' OR callee_class IN ('Lcom/bapis/bilibili/app/FooMoss;') "
             "OR callee_class LIKE 'Lcom/bapis/%Moss;') GROUP BY file_id,method,callee ORDER BY file_id,method,callee")},
    {"id": "protocols", "shape": "Q11 protocol definitions",
     "sql": ("SELECT file_id,method_descriptor FROM class_methods WHERE file_id={file} AND "
             "(class_descriptor IN ('Lcom/bapis/bilibili/app/FooMoss;') OR class_descriptor LIKE 'Lcom/bapis/%Moss;') "
             "ORDER BY file_id,class_idx,method_idx")},
    {"id": "classes", "shape": "Q08 per-DEX class records",
     "sql": ("SELECT file_id,class_def_idx,descriptor,superclass_descriptor FROM classes WHERE file_id={file} AND "
             "(descriptor LIKE 'Lsyn/fam/%' ESCAPE '\\' OR descriptor LIKE 'Lcom/bapis/%' ESCAPE '\\') "
             "ORDER BY file_id,class_def_idx")},
    {"id": "members", "shape": "Q08 per-DEX member surface",
     "sql": ("SELECT file_id,class_descriptor,method_idx,method_name,method_descriptor FROM class_methods WHERE "
             "file_id={file} AND (class_descriptor LIKE 'Lsyn/fam/%' ESCAPE '\\') ORDER BY file_id,class_idx,method_idx")},
)


def normal(value: Any) -> Any:
    """JSON round trip: the form a golden has on disk (integer keys become strings, tuples lists)."""
    return json.loads(json.dumps(value, sort_keys=True))


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def evidence_rows(session: Any) -> "dict[str, list]":
    """Run every EVIDENCE statement for every DEX of the session and keep the rows."""
    out: dict[str, list] = {}
    for item in EVIDENCE:
        rows: list = []
        for file in sorted(session.files):
            rows.extend(session.all(item["sql"].format(file=file)))
        out[item["id"]] = rows
    return out


KEYS = ("files", "unsupported_audit", "features", "discoveries", "class_count", "graph", "statements", "evidence")


def project(record: dict) -> dict:
    """The part of a run record that must be equal across engines, in the form a golden has."""
    return normal({key: record.get(key) for key in KEYS})


def compare(expected: Any, observed: Any, path: str = "", limit: int = 40) -> list:
    """Every place where the two values differ, as {path, expected, observed}; empty only if they are equal.
    A missing key, an extra key, a different length and a different type are differences."""
    found: list = []

    def walk(a: Any, b: Any, where: str) -> None:
        if len(found) >= limit:
            return
        if type(a) is not type(b):
            found.append({"path": where or "/", "expected": a, "observed": b})
        elif isinstance(a, dict):
            for key in sorted(set(a) | set(b), key=str):
                if key not in a:
                    found.append({"path": f"{where}/{key}", "expected": "<absent>", "observed": b[key]})
                elif key not in b:
                    found.append({"path": f"{where}/{key}", "expected": a[key], "observed": "<absent>"})
                else:
                    walk(a[key], b[key], f"{where}/{key}")
        elif isinstance(a, list):
            if len(a) != len(b):
                found.append({"path": where or "/", "expected": f"{len(a)} items", "observed": f"{len(b)} items"})
            for index, (x, y) in enumerate(zip(a, b)):
                walk(x, y, f"{where}[{index}]")
        elif a != b:
            found.append({"path": where or "/", "expected": a, "observed": b})

    walk(expected, observed, path)
    return found


def counts(projected: dict) -> dict:
    """How many items of each kind a record holds, so that a report can say what was compared item by item."""
    graph = projected.get("graph") or {}
    nodes = [node for node in graph.values() if node]
    fields = [f for node in nodes for f in node["fields"]]
    methods = [m for node in nodes for m in node["methods"]]
    evidence = projected.get("evidence") or {}
    calls = evidence.get("calls", [])
    return {
        "features": len(projected.get("features") or {}),
        "discoveries": sum(len(found) for found in (projected.get("discoveries") or {}).values()),
        "class_records": len(nodes),
        "absent_class_names": len(graph) - len(nodes),
        "fields": len(fields),
        "methods": len(methods),
        "generic_members": sum(1 for f in fields if f["generic"]) + sum(
            1 for m in methods if m["result_generic"] or any(m["arg_generics"])),
        "hierarchy_edges": sum((1 if node["super"] else 0) + len(node["interfaces"]) for node in nodes),
        "statements": len(projected.get("statements") or []),
        "call_count_rows": len(calls),
        "repeated_call_rows": sum(1 for row in calls if int(row["n"]) > 1),
        "protocol_definitions": len(evidence.get("protocols", [])),
        "evidence_rows": sum(len(rows) for rows in evidence.values()),
    }
