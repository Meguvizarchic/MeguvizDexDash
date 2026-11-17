#!/usr/bin/env python3
"""Freeze the reference engine's answers to the structural audit (MDD-051): `structural-goldens.json`.

For each synthetic input of `structural_worlds.py` this runs HostLab's frozen audit code (conformance/corpus/hostlab/
source-8782f43: `native_cli.CliSession` as the session, `native_graph`, `native_rules` with the synthetic catalog,
`native_audit.run` and `write_tsv`) against the reference engine, dexsql 0.1.0, and records what comes out: the 27
FEATURE results, the discoveries, the Graph's class records, the statements the consumer sent, the answers to the
call-site and protocol statements, the audit's own refusals, and the TSV that HostLab publishes.

The reference binary is not part of the repository (it is the user's download, git-ignored). The golden is therefore
generated on a machine that has it, and everything else replays the golden:

  python -I conformance/hostlab/structural_a0_golden.py --a0 PATH            write the golden (needs the reference binary)
  python -I conformance/hostlab/structural_a0_golden.py --verify-inputs      no binary: the inputs, the catalog and the
                                                                              frozen sources still hash to what the golden says

Every comparison made against the golden is accompanied by negative controls (test_structural_equivalence.py).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "integrations/hostlab"))

import structural_compare as compare  # noqa: E402
import structural_frozen as frozen  # noqa: E402
import structural_worlds as worlds  # noqa: E402

GOLDEN = HERE / "structural-goldens.json"
SCHEMA = "mdd.hostlab-structural-goldens.v1"
REFERENCE_SHA256 = "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"
# what the golden is built from, apart from the inputs: all of it is hashed into the golden
SOURCES = ("conformance/hostlab/structural_dex.py", "conformance/hostlab/structural_worlds.py",
           "conformance/hostlab/structural_a0_golden.py", "integrations/hostlab/structural_frozen.py",
           "integrations/hostlab/structural_compare.py")
FROZEN_USED = ("native_graph", "native_rules", "native_session", "native_cli", "native_audit", "analysis_batch",
               "analysis_plan", "analysis_paging", "install_dexsql")
CATALOG_FILES = ("analysis/audit_catalog.json", "analysis/HostCompatibilityAudit.java")
# worlds whose expected behaviour is the engine's own, not the reference engine's
ENGINE_WORLDS = {"badrefs": {"outcome": "incomplete_coverage", "engine_code": "INCOMPLETE_FACTS",
                             "why": "a method's code item declares fewer incoming words than its prototype needs, so "
                                    "the code/reference/annotation layers cannot be built; the engine opens the "
                                    "dataset with a layer issue and refuses the relations that need those layers"}}


# Single statements run through the session of the reference engine and recorded as rows or as the error it raised.
# `b1` says what the typed wire is expected to return where it is *declared* to differ (W-B1-3), else it must equal `a0`.
PROBES = (
    {"id": "scalar-values", "input": "world:sparse",
     "sql": "SELECT 9223372036854775807 AS a, -9223372036854775807 AS b, NULL AS c, '' AS d, 'N' AS e, '中' AS f, "
            "'it''s' AS g ORDER BY 1"},
    # A difference of the SQL layer, not of this adapter: SQLite and the reference engine read the literal as the integer
    # -2^63, MeguvizDexDash reads it as REAL. B0 passes the engine's text on (CAST(x AS TEXT)); B1 refuses a REAL cell.
    # It is pinned so that a change in either direction is noticed. The audit's statements contain no such literal.
    {"id": "int64-min-literal", "input": "world:sparse", "sql": "SELECT -9223372036854775808 AS b ORDER BY 1",
     "known_engine_difference": {"b0": {"rows": [{"b": "-9.22337203685478e+18"}]},
                                 "b1": {"error": {"type": "EngineProtocolError",
                                                  "message": "a float cell cannot be represented in the audit DTO"}}}},
    {"id": "empty-result", "input": "world:full", "sql": "SELECT class_idx FROM classes WHERE class_idx < 0 ORDER BY class_idx"},
    {"id": "null-column", "input": "world:full",
     "sql": "SELECT descriptor,source_file,interface_count FROM classes WHERE descriptor LIKE 'Lsyn/decoy/%' ORDER BY descriptor"},
    {"id": "supplementary-characters", "input": "repo:tests/fixtures/query/generated/unicode-order-038.dex",
     "sql": "SELECT string_idx,value FROM strings ORDER BY string_pool_id,string_idx",
     "b1_declared_difference": "W-B1-3"},
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def probe_input(spec: str, directory: Path) -> Path:
    kind, _, name = spec.partition(":")
    if kind == "world":
        members, container = worlds.world(name)
        return directory / (name + (".dex" if container == "dex" else ".apk"))
    if kind == "repo":
        return ROOT / name
    raise ValueError(spec)


def run_probes(session_module, directory: Path) -> dict:
    out = {}
    for probe in PROBES:
        path = probe_input(probe["input"], directory)
        entry = dict(probe, input_sha256=frozen.sha256_file(path))
        with session_module.NativeSession(path, timeout=120, threads=2) as session:
            try:
                entry["a0"] = {"rows": compare.normal(session.all(probe["sql"]))}
            except Exception as error:  # noqa: BLE001 - the reference engine's refusal is the golden
                entry["a0"] = {"error": {"type": type(error).__name__, "message": str(error)}}
        out[probe["id"]] = entry
    return out


def provenance() -> dict:
    """The hashes of everything the golden depends on besides the engine answers."""
    manifest = json.loads((frozen.FROZEN / "manifest.json").read_text(encoding="utf-8"))
    recorded = {Path(item["path"]).stem: item["sha256"] for item in manifest["files"] if item.get("path", "").endswith(".py")}
    return {
        "sources": {path: sha256_bytes((ROOT / path).read_bytes()) for path in SOURCES},
        "frozen_hostlab": {name: frozen.sha256_file(frozen.FROZEN / f"{name}.py") for name in FROZEN_USED},
        "frozen_hostlab_manifest": {name: recorded[name] for name in FROZEN_USED},
        "catalog": {path: frozen.sha256_file(frozen.CATALOG_DIR / path) for path in CATALOG_FILES},
    }


def build_inputs(directory: Path) -> dict:
    digests = worlds.write_inputs(directory)
    out = {}
    for name in worlds.WORLDS:
        members, container = worlds.world(name)
        filename = name + (".dex" if container == "dex" else ".apk")
        out[filename] = {"sha256": digests[filename], "bytes": (directory / filename).stat().st_size,
                         "container": container, "dex_members": len(members),
                         "classes": sum(len(m) for m in members), "world": name}
    return out


def tsv_of(oracle, result: dict, name: str, directory: Path) -> str:
    path = directory / (name + ".tsv")
    oracle.write_tsv(path, result, name)
    return path.read_text(encoding="utf-8")


def audit_subset(result: dict) -> dict:
    return compare.normal({"features": result["features"], "discoveries": result["discoveries"],
                           "class_count": result["class_count"], "apk_sha256": result["apk_sha256"],
                           "complete": result["complete"], "source_sha_reverified": result["source_sha_reverified"],
                           "reference_sha256": result["reference_sha256"], "queries": result["queries"]})


def generate(a0_binary: Path) -> dict:
    if frozen.sha256_file(a0_binary) != REFERENCE_SHA256:
        raise SystemExit("the reference binary is not dexsql 0.1.0 (sha256 differs from the pinned one)")
    with tempfile.TemporaryDirectory(prefix="mdd051-golden-") as scratch:
        scratch = Path(scratch)
        inputs = build_inputs(scratch / "inputs")
        oracle = frozen.A0Oracle(a0_binary, scratch / "state")
        records: dict = {}
        for name in worlds.WORLDS:
            if name in ENGINE_WORLDS:
                continue  # not a world on which the reference engine is the judge
            filename = next(f for f, v in inputs.items() if v["world"] == name)
            apk = scratch / "inputs" / filename
            sha = inputs[filename]["sha256"]
            entry: dict = {"input": filename}
            record = frozen.record_run(oracle.session_factory(), oracle.rules, oracle.graph, apk)
            entry["record"] = compare.project(record)
            entry["counts"] = compare.counts(entry["record"])
            try:
                result = oracle.run_audit(apk, sha)
            except oracle.graph.UnsupportedAudit as error:
                entry["audit"] = {"raised": "UnsupportedAudit", "message": str(error)}
                if record["unsupported_audit"] != str(error):
                    raise SystemExit(f"{name}: native_audit.run and the record disagree about the refusal")
            else:
                entry["audit"] = audit_subset(result)
                entry["tsv_sha256"] = sha256_bytes(tsv_of(oracle, result, filename, scratch).encode("utf-8"))
                # queries counts the DEX inventory statement of __enter__ as well as the class count of run()
                same = (entry["audit"]["features"] == entry["record"]["features"]
                        and entry["audit"]["discoveries"] == entry["record"]["discoveries"]
                        and entry["audit"]["class_count"] == entry["record"]["class_count"]
                        and entry["audit"]["queries"] == len(entry["record"]["statements"]) + 1)
                if not same:
                    raise SystemExit(f"{name}: native_audit.run and the record disagree")
            records[name] = entry
        reference = {}
        for name, expectation in ENGINE_WORLDS.items():  # what the reference engine makes of the engine-specific inputs
            filename = next(f for f, v in inputs.items() if v["world"] == name)
            apk = scratch / "inputs" / filename
            try:
                result = oracle.run_audit(apk, inputs[filename]["sha256"])
                reference[name] = {"outcome": "complete", "complete": result["complete"], "class_count": result["class_count"]}
            except Exception as error:  # noqa: BLE001 - recorded, whatever it is
                reference[name] = {"outcome": "raised", "type": type(error).__name__, "message": str(error)[:300]}
        return {
            "schema": SCHEMA, "task": "MDD-051",
            "about": ("The reference engine's (dexsql 0.1.0) answers to HostLab's frozen structural audit over synthetic "
                      "inputs. The catalog is synthetic (the operator's audit_catalog.json is not in this repository); "
                      "no real application was analysed."),
            "oracle": {"reference_engine": {"product": "dexsql", "version": "0.1.0", "sha256": REFERENCE_SHA256,
                                            "binary_in_repository": False},
                       "driver": ("HostLab 8782f43 native_cli.CliSession as native_session.NativeSession, native_graph, "
                                  "native_rules (synthetic catalog), native_audit.run and write_tsv, loaded after their "
                                  "SHA-256 matched the frozen manifest"),
                       "python": platform.python_version(), "platform": sys.platform},
            "provenance": provenance(),
            "expected_features": frozen.emitted_features(),
            "expected_features_derivation": "the FEATURE names passed to self.emit(...) in the frozen native_rules.py, once each, in source order",
            "inputs": inputs,
            "worlds": records,
            "engine_worlds": {name: dict(expectation, reference_engine_observation=reference[name])
                              for name, expectation in ENGINE_WORLDS.items()},
            "probes": run_probes(oracle.session, scratch / "inputs"),
        }


def verify_inputs(golden: dict) -> list:
    """Problems found when the inputs, the catalog and the frozen sources are checked against the golden (no binary)."""
    problems = []
    if golden.get("schema") != SCHEMA:
        problems.append("schema")
    with tempfile.TemporaryDirectory(prefix="mdd051-verify-") as scratch:
        built = build_inputs(Path(scratch))
    for filename, expected in golden["inputs"].items():
        if built.get(filename) != expected:
            problems.append(f"input {filename} is not what the golden was made from")
    if set(built) != set(golden["inputs"]):
        problems.append("the set of inputs differs")
    current = provenance()
    for group, values in current.items():
        if golden["provenance"].get(group) != values:
            problems.append(f"provenance.{group} differs from the golden")
    if current["frozen_hostlab"] != current["frozen_hostlab_manifest"]:
        problems.append("a frozen HostLab source differs from its manifest digest")
    if golden["expected_features"] != frozen.emitted_features():
        problems.append("the FEATURE names emitted by the frozen rules differ from the golden")
    if sorted(probe["id"] for probe in PROBES) != sorted(golden.get("probes", {})):
        problems.append("the probes differ from the golden")
    for name, probe in golden.get("probes", {}).items():
        spec = next((p["input"] for p in PROBES if p["id"] == name), None)
        if spec is None or spec != probe["input"]:
            problems.append(f"probe {name} names another input")
        elif spec.startswith("repo:"):
            if frozen.sha256_file(ROOT / spec[5:]) != probe["input_sha256"]:
                problems.append(f"probe {name}: the input file changed")
        elif built.get(spec[6:] + (".dex" if worlds.world(spec[6:])[1] == "dex" else ".apk"), {}).get("sha256") != probe["input_sha256"]:
            problems.append(f"probe {name}: the input differs from the golden")
        if next((p for p in PROBES if p["id"] == name), {}).get("sql") != probe["sql"]:
            problems.append(f"probe {name}: the statement differs from the golden")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a0", type=Path, help="the reference engine binary (dexsql 0.1.0)")
    parser.add_argument("--out", type=Path, default=GOLDEN)
    parser.add_argument("--verify-inputs", action="store_true")
    args = parser.parse_args(argv)
    if args.verify_inputs:
        problems = verify_inputs(json.loads(args.out.read_text(encoding="utf-8")))
        for problem in problems:
            print("PROBLEM:", problem)
        print("inputs match the golden" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    if not args.a0:
        parser.error("--a0 is required to write the golden")
    golden = generate(args.a0)
    args.out.write_text(json.dumps(golden, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
