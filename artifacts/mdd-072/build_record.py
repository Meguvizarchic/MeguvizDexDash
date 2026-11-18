#!/usr/bin/env python3
"""Write artifacts/mdd-072/twelve-tool-conformance.json from the runs that stand behind it.

What it records: the comparison of the twelve tools' published schemas with the reference's, the replay of every
recorded call of the reference engine against the current build (rerun here), the controls that show the replay can
fail, the unit and process tests of the crates the resource tools live in, and whether a mutation result is committed
and current. Nothing in the record is typed by hand except the residual list.

Usage: python -I artifacts/mdd-072/build_record.py [--check]
  --check   only say whether the committed record's input hashes are the current files' (no run)
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "conformance" / "mcp"))
RECORD = "artifacts/mdd-072/twelve-tool-conformance.json"
REPLAY = "artifacts/mdd-072/resources-replay.json"
TOOLS_LIST = "artifacts/mdd-072/a0-probe/tools-list.json"
CALLS = "artifacts/mdd-072/a0-probe/calls.jsonl"
CONTRACT = "conformance/mcp/resources-full-contract.json"
MUTATION = "artifacts/mdd-072/mutation/results.txt"
BINARY = "target/debug/meguvizdexdash" + (".exe" if sys.platform == "win32" else "")
SOURCES = [
    "crates/mdd-input/src/resources/mod.rs", "crates/mdd-input/src/resources/value.rs",
    "crates/mdd-input/src/resources/framework.rs", "crates/mdd-input/src/resources/xml.rs",
    "crates/mdd-input/src/resources/config.rs", "crates/mdd-input/src/resources/arsc.rs",
    "crates/mdd-input/src/resources/query.rs", "crates/mdd-input/src/resources/tests.rs",
    "crates/mdd-input/src/manifest/mod.rs", "crates/mdd-service/src/resources.rs",
    "crates/mdd-service/src/manifest.rs", "crates/mdd-service/src/dataset.rs",
    "crates/mdd-mcp/src/tools.rs", "crates/mdd-mcp/src/tool_schemas.json",
    "crates/mdd-mcp/src/resource_tools/mod.rs", "crates/mdd-mcp/src/resource_tools/files.rs",
    "crates/mdd-mcp/src/resource_tools/components.rs", "crates/mdd-mcp/src/resource_tools/read.rs",
    "crates/mdd-mcp/src/resource_tools/query.rs",
    "conformance/mcp/resources_replay.py", "conformance/mcp/test_resources_replay.py", CONTRACT, TOOLS_LIST, CALLS,
    "tests/fixtures/resources/generate.py", "tests/fixtures/resources/manifest.json",
    "artifacts/mdd-072/probe/probe_a0.py", "artifacts/mdd-072/mutation/mutate_resources.py",
]


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def run(command: list[str]) -> tuple[int, str]:
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    return done.returncode, done.stdout + "\n" + done.stderr


def mutation_summary() -> dict:
    path = ROOT / MUTATION
    script = "artifacts/mdd-072/mutation/mutate_resources.py"
    if not path.is_file():
        return {"file": MUTATION, "present": False, "current": False, "script": script,
                "status": "not run yet: it runs in .github/workflows/mutation-resources.yml on request; no result is claimed"}
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("sources sha256:")]
    spec = importlib.util.spec_from_file_location("mutate_resources", ROOT / script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {"file": MUTATION, "script": script, "present": True,
            "current": recorded == [module.base.sources_sha256()],
            "mutants": len(module.MUTANTS),
            "killed": sum(1 for line in lines if line.startswith("KILLED")),
            "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
            "errors": sum(1 for line in lines if line.startswith(("ERROR", "TIMEOUT"))),
            "skipped": sum(1 for line in lines if line.startswith("SKIPPED")),
            "restored_tree_passes": any("passes the unit and process tests, the replays and their controls: True" in line for line in lines)}


def schema_comparison() -> dict:
    """The twelve tools' inputSchema, outputSchema and annotations against the reference's recorded tools/list."""
    from mcp_client import McpClient
    reference = json.loads((ROOT / TOOLS_LIST).read_text(encoding="utf-8"))["tools"]
    client = McpClient(ROOT / BINARY)
    client.initialize()
    served = {tool["name"]: tool for tool in client.tools()}
    client.close()
    rows = {}
    for name in sorted(reference):
        ours = served.get(name)
        rows[name] = None if ours is None else {key: ours.get(key) == reference[name].get(key)
                                                  for key in ("inputSchema", "outputSchema", "annotations")}
    return {"reference_tools": len(reference), "served_tools": len(served), "extra_tools_served": sorted(set(served) - set(reference)),
            "missing_tools": sorted(set(reference) - set(served)), "equal": rows,
            "all_equal": not (set(served) ^ set(reference)) and all(r and all(r.values()) for r in rows.values())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        record = json.loads((ROOT / RECORD).read_text(encoding="utf-8"))
        stale = [path for path, digest in record["inputs_sha256"].items() if sha256(path) != digest]
        mutation = mutation_summary()
        if mutation["present"] and not mutation["current"]:
            stale.append(MUTATION)
        for path in stale:
            print("STALE:", path)
        print("committed record current:", not stale)
        return 1 if stale else 0

    schemas = schema_comparison()
    if not schemas["all_equal"]:
        raise SystemExit(f"the twelve tools do not carry the reference's published schemas: {schemas}")
    code, text = run([sys.executable, "-I", "conformance/mcp/resources_replay.py", "--binary", BINARY, "--out", REPLAY])
    if code != 0:
        print(text[-3000:])
        raise SystemExit("the replay of the recorded calls does not pass against the current build")
    code, text = run([sys.executable, "-I", "conformance/mcp/test_resources_replay.py"])
    if code != 0:
        print(text[-2000:])
        raise SystemExit("the controls of the replay fail")
    replay = json.loads((ROOT / REPLAY).read_text(encoding="utf-8"))
    spec = importlib.util.spec_from_file_location("resources_replay", ROOT / "conformance/mcp/resources_replay.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    contract = json.loads((ROOT / CONTRACT).read_text(encoding="utf-8"))
    code, text = run([sys.executable, "-I", "conformance/decode/a0_replay.py", "--binary", BINARY])
    decode_line = next((line for line in reversed(text.splitlines()) if line.startswith("cases:")), "")

    tests = {}
    for label, command in (("mdd-input lib", ["-p", "mdd-input", "--lib"]), ("mdd-service lib", ["-p", "mdd-service", "--lib"]),
                           ("mdd-mcp lib", ["-p", "mdd-mcp", "--lib"]), ("mdd-cli mcp", ["-p", "mdd-cli", "--test", "mcp"])):
        code, text = run(["cargo", "test", "--offline", "--locked", *command])
        passed = sum(int(n) for n in re.findall(r"test result: ok\. (\d+) passed", text))
        failed = sum(int(n) for n in re.findall(r"(\d+) failed", text))
        tests[label] = {"exit_code": code, "passed": passed, "failed": failed}
        if code != 0:
            print(text[-2000:])
            raise SystemExit(f"the tests of {label} fail")

    mutation = mutation_summary()
    calls = sum(replay["counts"].values())
    record = {
        "schema_version": "mdd.twelve-tool-conformance.v1",
        "task": "MDD-072",
        "status": "all twelve tools are registered with the reference's published schemas; get_manifest answers its xml mode and "
                  "get_manifest_components, list_resource_files, read_resource and query_resources answer; every call recorded from "
                  "the reference engine (dexsql 0.1.0) was replayed against this build and compared field by field",
        "kind": "development evidence; admits no profile",
        "reference": json.loads((ROOT / TOOLS_LIST).read_text(encoding="utf-8"))["reference"],
        "schemas": schemas,
        "replay": {
            "file": REPLAY, "script": "conformance/mcp/resources_replay.py", "recorded_calls": CALLS,
            "calls": calls, "match": replay["counts"].get("match", 0), "declared": replay["counts"].get("declared", 0),
            "undeclared_differences": replay["counts"].get("differs", 0), "errors": replay["counts"].get("error", 0),
            "real_application": {
                "what": "the public NewPipe 0.28.6 APK: the manifest as XML, every component, every member, rows of every resource type, "
                        "configurations and filters, 60 layouts and other XML, binary members",
                **replay["newpipe"],
                "recording": "artifacts/local/a0-probe/newpipe.jsonl (ignored: it holds the application's own strings and layouts); "
                             "made by artifacts/mdd-072/probe/probe_newpipe.py against the pinned reference"},
            "declared_classes": {name: {"calls": replay["classes"].get(name, 0), "explanation": module.DECLARED[name]}
                                 for name in sorted(module.DECLARED)},
        },
        "decode_replay_with_the_manifest_xml_records": {"script": "conformance/decode/a0_replay.py", "result": decode_line},
        "contract": {"file": CONTRACT, "declared_classes_named": sorted(module.DECLARED) == sorted(contract["declared_differences"]["classes"])},
        "controls": {"script": "conformance/mcp/test_resources_replay.py", "passed": True},
        "tests": tests,
        "mutation_check": mutation,
        "inputs_sha256": {path: sha256(path) for path in SOURCES},
        "residual": [
            "the recorded answers are those of dexsql 0.1.0, windows-amd64 build only; dexsql 0.1.1 was not probed for the resource tools",
            "the inputs are small synthetic archives built by tests/fixtures/resources/generate.py and the probe scripts, plus the project's earlier fixtures; no real application was compared, and the NewPipe APK was not used for these tools",
            "the reference leaves out text nodes, writes every android attribute under the prefix android, names ids of the framework's resources, and drops control characters; this engine keeps the first, second and fourth exactly and writes framework ids as ids (declared classes XML_TEXT_NODES, NAMESPACES_KEPT, FRAMEWORK_NAMES, CONTROL_CHARS), so a client that compares XML text with the reference's will see these differences",
            "only installLocation, launchMode and protectionLevel are given framework names; every other android attribute is a number, because the binary XML does not carry the attribute's declared type and no framework table is embedded",
            "the reference reads leniently a table with a wrong header type, binary XML with an undeclared namespace and an element with a repeated attribute; this engine refuses them (declared class STRICT_INPUT), so an application that relies on lenient reading is refused by the resource tools",
            "compact resource entries, overlays and staged aliases are not read: a table with a compact entry is refused as unsupported_capability, the others are passed over and counted in skipped_chunks",
            "style spans of pool strings are validated and kept in the parsed table but not shown",
            "the 64 MiB resource cap and the table budgets are enforced by the same code paths as the others and are tested at small sizes only; no 64 MiB member was read here",
            "the row budget of query_resources, list_resource_files and get_manifest_components counts the answer as sent (structured content and its text copy) and reproduces the reference's page sizes at one recorded point; page boundaries under a small max_bytes can differ by a row (declared class ROW_BUDGET)",
            "the mutation check runs in .github/workflows/mutation-resources.yml, not on a developer machine; until its results.txt is committed no mutation result is claimed",
        ],
        "run": {"finished_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
    }
    (ROOT / RECORD).write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {RECORD}; schemas equal {schemas['all_equal']}; replay {record['replay']['match']} match, "
          f"{record['replay']['declared']} declared, {record['replay']['undeclared_differences']} undeclared of {calls}; tests {tests}; "
          f"mutation present={mutation['present']} current={mutation['current']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
