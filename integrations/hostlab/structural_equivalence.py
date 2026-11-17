"""The structural equivalence run: golden against B0 and B1 on the real engine, and the negative controls that show the
comparison can fail. Shared by test_structural_equivalence.py and make_structural_equivalence.py. Standard library only.

For each synthetic input the golden holds what HostLab's frozen audit code produced over the reference engine. Here the
same frozen code is run over the MeguvizDexDash engine, once through B0 and once through B1, and compared item by item:
the 27 FEATURE results, the discoveries, the Graph's class records with their fields, methods, signatures and generic
types, the hierarchy edges, the statements the consumer sent (in order), the call-count and protocol statements, the
class count, and - through `structural_provider` - the audit's result record and the TSV that HostLab publishes.
"""
from __future__ import annotations

import copy
import json
import struct
import tempfile
from pathlib import Path
from typing import Any

import structural_compare as compare
import structural_frozen as F

GOLDEN = F.ROOT / "conformance/hostlab/structural-goldens.json"
WIRES = ("b0", "b1")


def load_golden(path: Path = GOLDEN) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def audit_subset(record: dict) -> dict:
    return compare.normal({"features": record["features"], "discoveries": record["discoveries"],
                           "class_count": record["class_count"], "apk_sha256": record["apk_sha256"],
                           "complete": record["complete"], "source_sha_reverified": record["source_sha_reverified"],
                           "reference_sha256": record["reference_sha256"], "queries": record["queries"]})


# ---- damage: edits of a golden record, each of which a comparison must notice ------------------------------------------

def damages(record: dict) -> "list[tuple[str, str, dict]]":
    """(name, path the comparison must report, damaged copy) for edits of a record in every part that is compared."""
    out: list = []

    def mutate(name: str, prefix: str, edit) -> None:
        damaged = copy.deepcopy(record)
        edit(damaged)
        out.append((name, prefix, damaged))

    features = record["features"]
    if features:
        first = sorted(features)[0]
        other = "MISSING" if features[first]["status"] != "MISSING" else "FOUND"
        mutate("a feature status", f"/features/{first}/status", lambda r: r["features"][first].__setitem__("status", other))
        mutate("a feature detail, one character", f"/features/{first}/detail",
               lambda r: r["features"][first].__setitem__("detail", r["features"][first]["detail"] + "x"))
        mutate("a feature missing", f"/features/{first}", lambda r: r["features"].pop(first))
        mutate("a feature added", "/features/zz_extra", lambda r: r["features"].__setitem__("zz_extra", {"status": "FOUND", "detail": ""}))
    found = [(name, items) for name, items in sorted(record["discoveries"].items()) if items]
    if found:
        name, items = found[0]
        mutate("a discovery dropped", f"/discoveries/{name}", lambda r: r["discoveries"][name].pop())
        mutate("a discovery changed", f"/discoveries/{name}[0]", lambda r: r["discoveries"][name][0].__setitem__(1, items[0][1] + "x"))
    nodes = [(name, node) for name, node in sorted(record["graph"].items()) if node]
    if nodes:
        name, node = nodes[0]
        mutate("a class access flag", f"/graph/{name}/access", lambda r: r["graph"][name].__setitem__("access", node["access"] + 1))
        mutate("a class superclass", f"/graph/{name}/super", lambda r: r["graph"][name].__setitem__("super", "x.Other"))
        mutate("an interface edge added", f"/graph/{name}/interfaces", lambda r: r["graph"][name]["interfaces"].append("x.Extra"))
        mutate("a class record removed", f"/graph/{name}", lambda r: r["graph"].pop(name))
        mutate("a class turned absent", f"/graph/{name}", lambda r: r["graph"].__setitem__(name, None))
        mutate("an absent name added", "/graph/x.Absent", lambda r: r["graph"].__setitem__("x.Absent", None))
    with_edge = [(n, node) for n, node in nodes if node["interfaces"]]
    if with_edge:
        name, node = with_edge[0]
        mutate("an interface edge dropped", f"/graph/{name}/interfaces", lambda r: r["graph"][name]["interfaces"].pop())
    with_field = [(n, node) for n, node in nodes if node["fields"]]
    if with_field:
        name, node = with_field[0]
        mutate("a field type", f"/graph/{name}/fields[0]/type", lambda r: r["graph"][name]["fields"][0].__setitem__("type", "x.T"))
        mutate("a field removed", f"/graph/{name}/fields", lambda r: r["graph"][name]["fields"].pop())
    with_generic_field = [(n, f) for n, node in nodes for f in node["fields"] if f["generic"]]
    if with_generic_field:
        name = with_generic_field[0][0]
        index = record["graph"][name]["fields"].index(with_generic_field[0][1])
        mutate("a generic argument of a field", f"/graph/{name}/fields[{index}]/generic",
               lambda r: r["graph"][name]["fields"][index].__setitem__("generic", []))
    with_method = [(n, node) for n, node in nodes if node["methods"]]
    if with_method:
        name, node = with_method[0]
        mutate("a method prototype", f"/graph/{name}/methods[0]/proto", lambda r: r["graph"][name]["methods"][0].__setitem__("proto", "()Lx;"))
        mutate("a method result type", f"/graph/{name}/methods[0]/result", lambda r: r["graph"][name]["methods"][0].__setitem__("result", "x.R"))
        mutate("a method access flag", f"/graph/{name}/methods[0]/access", lambda r: r["graph"][name]["methods"][0].__setitem__("access", node["methods"][0]["access"] ^ 8))
        mutate("a method dropped", f"/graph/{name}/methods", lambda r: r["graph"][name]["methods"].pop())
    generic_methods = [(n, i) for n, node in nodes for i, m in enumerate(node["methods"]) if m["result_generic"] or any(m["arg_generics"])]
    if generic_methods:
        name, index = generic_methods[0]
        mutate("a generic argument of a method", f"/graph/{name}/methods[{index}]",
               lambda r: (r["graph"][name]["methods"][index].__setitem__("result_generic", []),
                          r["graph"][name]["methods"][index].__setitem__("arg_generics", [[] for _ in r["graph"][name]["methods"][index]["args"]])))
    statements = record["statements"]
    if len(statements) > 2:
        mutate("a statement changed", "/statements[0]", lambda r: r["statements"].__setitem__(0, statements[0] + " "))
        mutate("two statements swapped", "/statements[0]", lambda r: r["statements"].insert(0, r["statements"].pop(1)))
        mutate("a statement dropped", "/statements", lambda r: r["statements"].pop())
        mutate("a statement added", "/statements", lambda r: r["statements"].append("SELECT 1 ORDER BY 1"))
    if record["class_count"] is not None:
        mutate("the class count", "/class_count", lambda r: r.__setitem__("class_count", record["class_count"] + 1))
    mutate("the DEX inventory", "/files", lambda r: r["files"].__setitem__("0", "renamed.dex"))
    calls = record["evidence"].get("calls", [])
    repeated = [i for i, row in enumerate(calls) if int(row["n"]) > 1]
    if repeated:
        mutate("a repeated call counted once", f"/evidence/calls[{repeated[0]}]/n", lambda r: r["evidence"]["calls"][repeated[0]].__setitem__("n", "1"))
    if record["evidence"].get("protocols"):
        mutate("a protocol definition dropped", "/evidence/protocols", lambda r: r["evidence"]["protocols"].pop())
    if record["evidence"].get("classes"):
        mutate("a family class record", "/evidence/classes[0]/descriptor", lambda r: r["evidence"]["classes"][0].__setitem__("descriptor", "Lx;"))
    if record["unsupported_audit"] is not None:
        mutate("the refusal of the audit", "/unsupported_audit", lambda r: r.__setitem__("unsupported_audit", record["unsupported_audit"] + "."))
    else:
        mutate("a refusal that was not made", "/unsupported_audit", lambda r: r.__setitem__("unsupported_audit", "duplicate class definitions in native structural audit"))
    return out


def detected(expected: dict, damaged: dict, prefix: str) -> "tuple[bool, list]":
    """Does the comparison of `damaged` (as the golden) against `expected` (as observed) report `prefix`?"""
    found = compare.compare(damaged, expected)
    return bool(found) and any(item["path"].startswith(prefix) for item in found), found


# ---- changed rules: the frozen source with one deliberate edit, run for real ------------------------------------------------

RULE_CHANGES = (
    {"name": "a method name removed from the quality rule", "world": "full", "module": "native_rules",
     "edit": (('m.name in {"a", "c", "getDefaultQuality"}', 'm.name in {"c", "getDefaultQuality"}'),), "reported": "/features/player_default_quality"},
    {"name": "the home tabs rule asks for two", "world": "full", "module": "native_rules",
     "edit": (('"FOUND" if len(tabs) == 1 else "MISSING", refs(tabs))', '"FOUND" if len(tabs) == 2 else "MISSING", refs(tabs))'),),
     "reported": "/features/home_tabs"},
    {"name": "the Graph prefetches in batches of 7", "world": "full", "module": "native_graph",
     "edit": (("range(0, len(names), 80)", "range(0, len(names), 7)"),), "reported": "/statements"},
    {"name": "the Graph reads Signature elements one level deeper", "world": "full", "module": "native_graph",
     "edit": (("AND depth=1 AND value_kind='string'", "AND depth=2 AND value_kind='string'"),), "reported": "/graph"},
)


def with_changed_rule(live: "F.Live", change: dict):
    return F.graph_and_rules(live.ns, modified={change["module"]: change["edit"]})


# ---- the run ------------------------------------------------------------------------------------------------------------------

def run_world(live: "F.Live", golden: dict, world: str, wire: str) -> dict:
    """One input over one wire: the record against the golden, the audit result, the TSV, the request counts."""
    entry = golden["worlds"][world]
    path = live.path(world)
    if F.sha256_file(path) != golden["inputs"][entry["input"]]["sha256"]:
        raise AssertionError(f"{world}: the input is not the one the golden was made from")
    sessions: list = []
    base = live.factory(wire)

    def factory(apk):
        session = base(apk)
        sessions.append(session)
        return session

    with live.environ():
        observed = compare.project(F.record_run(factory, live.rules, live.graph, path))
    session = sessions[0]
    differences = compare.compare(entry["record"], observed)
    outcome = live.outcome(path, wire)
    result: dict[str, Any] = {"differences": differences, "outcome": outcome.outcome, "counts": compare.counts(observed),
                              "record_digest": compare.digest(observed),
                              "logical_statements": len(observed["statements"]), "wire_requests": session.transport.statement_count,
                              "queries": session.queries}
    audit = entry["audit"]
    if "raised" in audit:
        result["audit_differences"] = [] if (outcome.outcome == "audit_refused" and
                                             outcome.record["audit_refusal"]["type"] == audit["raised"] and
                                             outcome.record["audit_refusal"]["message"] == audit["message"]) else [
            {"path": "/audit_refusal", "expected": audit, "observed": outcome.record["audit_refusal"] or outcome.outcome}]
        result["tsv_differences"] = []
    else:
        result["audit_differences"] = compare.compare(audit, audit_subset(outcome.record)) if outcome.outcome == "complete" else [
            {"path": "/outcome", "expected": "complete", "observed": outcome.outcome}]
        with tempfile.TemporaryDirectory(prefix="mdd051-tsv-") as directory:
            text = F.frozen_write_tsv(live.ns, live.graph, live.rules, Path(directory) / "out.tsv", outcome.record, path.name)
        digest = compare.digest(text)
        result["tsv_differences"] = [] if F.sha256_bytes(text.encode("utf-8")) == entry["tsv_sha256"] else [
            {"path": "/tsv", "expected": entry["tsv_sha256"], "observed": F.sha256_bytes(text.encode("utf-8"))}]
        result["tsv_digest"] = digest
    result["engine"] = outcome.record["engine"]
    result["coverage"] = outcome.record["coverage"]
    result["dataset"] = outcome.record["dataset"]
    return result


def dex_string_pool(path: Path) -> list:
    """The input's own string pool, read from its bytes by the DEX format (independent of the engine and of the
    adapter's decoder): the rows `SELECT string_idx,value FROM strings ORDER BY string_pool_id,string_idx` must
    return for a single-DEX input. The expected content a declared B1 difference is compared against."""
    data = Path(path).read_bytes()
    if data[:4] != b"dex\n":
        raise AssertionError("the declared-difference input is not a DEX")
    size, off = struct.unpack_from("<II", data, 0x38)  # header: string_ids_size, string_ids_off
    rows = []
    for idx in range(size):
        (start,) = struct.unpack_from("<I", data, off + 4 * idx)
        i, units, shift = start, 0, 0
        while True:  # ULEB128 UTF-16 unit count
            byte = data[i]; i += 1
            units |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        decoded = []
        while data[i] != 0:  # MUTF-8 up to the terminating NUL
            byte = data[i]
            if byte < 0x80:
                decoded.append(byte); i += 1
            elif byte & 0xE0 == 0xC0 and i + 1 < len(data):
                decoded.append(((byte & 0x1F) << 6) | (data[i + 1] & 0x3F)); i += 2
            elif byte & 0xF0 == 0xE0 and i + 2 < len(data):
                decoded.append(((byte & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F)); i += 3
            else:
                raise AssertionError("the input's string pool is not well-formed MUTF-8")
        if len(decoded) != units:
            raise AssertionError("the input's string pool disagrees with its UTF-16 unit count")
        text = b"".join(struct.pack(">H", unit) for unit in decoded).decode("utf-16-be", "surrogatepass")
        rows.append({"string_idx": str(idx), "value": text})
    return rows


def run_probes(live: "F.Live", golden: dict) -> dict:
    out: dict = {}
    for name, probe in sorted(golden["probes"].items()):
        kind, _, target = probe["input"].partition(":")
        path = live.path(target) if kind == "world" else F.ROOT / target
        if F.sha256_file(path) != probe["input_sha256"]:
            raise AssertionError(f"probe {name}: the input is not the one the golden was made from")
        per_wire: dict = {}
        for wire in WIRES:
            with live.environ(), live.factory(wire)(path) as session:
                try:
                    got: dict = {"rows": compare.normal(session.all(probe["sql"]))}
                except Exception as error:  # noqa: BLE001 - an error is an answer here
                    got = {"error": {"type": type(error).__name__, "message": str(error)}}
            per_wire[wire] = got
        entry = {"a0": probe["a0"], "wires": per_wire, "declared_difference": probe.get("b1_declared_difference"),
                 "known_engine_difference": probe.get("known_engine_difference")}
        if entry["declared_difference"]:
            # the declared difference must show the input's own content, not merely any non-empty answer
            if probe["sql"] != "SELECT string_idx,value FROM strings ORDER BY string_pool_id,string_idx":
                raise AssertionError(f"probe {name}: a declared difference needs its own expected content")
            entry["declared_expected"] = dex_string_pool(path)
        out[name] = entry
    return out


def probe_agreement(probe: dict, wire: str) -> bool:
    """B0 must give the reference engine's answer or its refusal (same message); B1 the same, except where a difference
    is declared - and a declared difference must show exactly the expected content, not just a non-empty answer."""
    a0, got = probe["a0"], probe["wires"][wire]
    known = probe.get("known_engine_difference")
    if known:  # a pinned difference of the SQL layer: the wire must show exactly that, so that a fix is noticed as well
        expected = known[wire]
        if "error" in expected:
            return "error" in got and got["error"]["message"] == expected["error"]["message"]
        return got == expected
    if "error" in a0:
        if wire == "b1" and probe["declared_difference"]:
            expected = probe.get("declared_expected")
            return expected is not None and "rows" in got and got["rows"] == expected
        return "error" in got and got["error"]["message"] == a0["error"]["message"]
    return got == a0
