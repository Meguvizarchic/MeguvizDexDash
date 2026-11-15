#!/usr/bin/env python3
"""Run the MDD-042 MCP conformance and write the (partial) record.

Usage: python -I conformance/mcp/run_mcp_conformance.py [--raw-dir DIR] [--no-write] [--check]

Run it with the validation environment's Python. It builds the CLI, runs the Rust tests
of the MCP server and of its process-level behaviour, a clippy pass, compares the
`tools/list` schemas with the reference engine's recorded ones, replays the frozen A0
`query` recordings through the real server and runs that replay's negative controls. Each
acceptance clause of MDD-042 is mapped to checks whose outcomes come from that run.

The record is PARTIAL by construction: `decode` and `get_manifest` are not implemented, so
clauses 1 to 3 are not proven for them, and the reference engine's executable is not
available here to record `decode`, `get_manifest`, `open_dataset` or `close_dataset`
responses. The record says so row by row instead of passing them.

--check runs nothing: it verifies the committed record still matches its inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import golden_replay  # noqa: E402
from mcp_client import DEFAULT_BINARY, McpClient  # noqa: E402

RECORD = "artifacts/mdd-042/mcp-required-conformance.json"
MUTATION = "artifacts/mdd-042/mutation/results.txt"
MANIFEST = "conformance/manifests/tools-and-options.json"
SOURCES = [
    "crates/mdd-mcp/src/tools.rs", "crates/mdd-mcp/src/server.rs", "crates/mdd-mcp/src/protocol.rs",
    "crates/mdd-mcp/src/lib.rs", "crates/mdd-mcp/src/tool_schemas.json", "crates/mdd-cli/tests/mcp.rs",
    "conformance/mcp/mcp_client.py", "conformance/mcp/golden_replay.py", "conformance/mcp/test_golden_replay.py",
    "conformance/mcp/run_mcp_conformance.py", "conformance/corpus/hostlab/required-variants.json",
    "conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json", MANIFEST,
]

RUST = ["cargo", "test", "--offline", "--locked", "-p", "mdd-mcp", "-p", "mdd-service", "-p", "mdd-cli", "--test", "mcp", "--lib"]
UNIT = ["cargo", "test", "--offline", "--locked", "-p", "mdd-mcp", "-p", "mdd-service", "--lib"]
PROCESS = ["cargo", "test", "--offline", "--locked", "-p", "mdd-cli", "--test", "mcp"]
CLIPPY = ["cargo", "clippy", "--offline", "--locked", "-p", "mdd-mcp", "-p", "mdd-service", "-p", "mdd-cli", "--all-targets", "--", "-D", "warnings"]
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli"]

SCHEMAS = "tools/list: the six registered tools carry the reference engine's published schemas"
REPLAY = "A0 replay: every recorded query page equals the reference through the real server"
REFUSALS = "A0 replay: every recorded refusal is refused, at the same statement index"
CONTROLS = "A0 replay: damaged recordings are caught"

ACCEPTANCE = [
    {"acceptance": "the five HostLab tools open_dataset/query/decode/get_manifest/close_dataset answer request by request like the reference, and the three discovery tools carry the real schema",
     "proven": [SCHEMAS, REPLAY, REFUSALS, CONTROLS],
     "not_proven": ["decode: not implemented", "get_manifest: not implemented",
                    "open_dataset and close_dataset responses: the reference's responses were never recorded and its executable is not available, so only their lifecycle behaviour is tested"]},
    {"acceptance": "decode produces the instructions, method context and declarations production uses, never placeholder text or opcodes alone",
     "proven": [], "not_proven": ["decode: not implemented"]},
    {"acceptance": "Smali and Manifest paging keep their own units (UTF-8 byte offsets, line counts, permission rows) and do not mix with DEX byte offsets",
     "proven": [], "not_proven": ["decode and get_manifest: not implemented; the query tool pages in rows, whose window is proven by the replay"]},
    {"acceptance": "tool ownership, quotas, closing, errors and source identity are checked through real MCP JSON-RPC",
     "proven": ["the_session_must_be_initialized_before_tools_and_may_be_initialized_once",
                "only_protocol_messages_reach_stdout_and_bad_lines_do_not_end_the_session",
                "arguments_that_break_the_published_schema_are_protocol_errors",
                "opening_a_dataset_names_its_source_and_roster",
                "an_input_that_cannot_be_opened_is_a_tool_error_naming_the_cause",
                "closing_releases_a_dataset_and_later_requests_that_name_it_are_refused",
                "the_dataset_quota_is_enforced_and_closing_frees_a_slot",
                "datasets_are_isolated_from_each_other",
                "a_query_that_outlives_its_deadline_closes_its_dataset_and_only_that_one",
                "a_result_over_the_byte_budget_is_refused_never_clipped",
                "a_closed_stdin_is_a_clean_end_and_a_closed_stdout_is_exit_four"],
     "not_proven": []},
    {"acceptance": "the M4 capability registers only what passes; get_manifest_components, list_resource_files, read_resource and query_resources are unavailable or unregistered",
     "proven": ["exactly_the_implemented_tools_are_listed_with_their_published_schemas",
                "an_option_the_server_does_not_implement_is_refused_not_ignored"],
     "not_proven": []},
]

CAPABILITIES = [
    {"name": "open_dataset", "provided": True, "scope": "DEX and APK paths with at least one DEX; resource-only archives are refused"},
    {"name": "list_datasets", "provided": True, "scope": "open datasets, quotas and usage in this server's own shape"},
    {"name": "close_dataset", "provided": True, "scope": "idempotent; later requests naming the dataset are refused"},
    {"name": "list_tables", "provided": True, "scope": "the 17 HostLab contract relations, not the reference's 56"},
    {"name": "describe_table", "provided": True, "scope": "columns, types, fact layers; case-insensitive name"},
    {"name": "query", "provided": True, "scope": "up to 16 statements, row windows with exact totals, TEMP and named temporary queries; equal to the frozen A0 recording; timing refused"},
    {"name": "decode", "provided": False, "reason": "not implemented (Smali; MDD-042 remainder and MDD-071)"},
    {"name": "get_manifest", "provided": False, "reason": "not implemented (MDD-042 remainder and MDD-072)"},
    {"name": "get_manifest_components", "provided": False, "reason": "MDD-072"},
    {"name": "list_resource_files", "provided": False, "reason": "MDD-072"},
    {"name": "read_resource", "provided": False, "reason": "MDD-072"},
    {"name": "query_resources", "provided": False, "reason": "MDD-072"},
    {"name": "cancellation_and_progress_notifications", "provided": False, "reason": "requests are served one at a time; a deadline closes the dataset instead"},
    {"name": "resources_prompts_logging", "provided": False, "reason": "not offered"},
]


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def mutation_hash() -> str:
    spec = importlib.util.spec_from_file_location("mutate_mcp", ROOT / "artifacts/mdd-042/mutation/mutate_mcp.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.sources_sha256()


def run(command: list[str], raw: Path, name: str) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    done = subprocess.run(command, cwd=ROOT, capture_output=True, check=False)
    log = done.stdout + b"\n--- stderr ---\n" + done.stderr
    raw.mkdir(parents=True, exist_ok=True)
    (raw / f"{name}.log").write_bytes(log)
    return {"started_utc": started, "exit_code": done.returncode,
            "log_sha256": hashlib.sha256(log).hexdigest(), "text": log.decode("utf-8", "replace")}


def rust_results(text: str) -> dict:
    results: dict[str, list[str]] = {}
    for name, outcome in re.findall(r"^test (\S+) \.\.\. (\w+)", text, re.M):
        results.setdefault(name, []).append(outcome)
    return results


def lookup(results: dict, suffix: str) -> str:
    hits = [outcomes for name, outcomes in results.items() if name == suffix or name.endswith("::" + suffix)]
    if len(hits) != 1:
        return "not_run" if not hits else f"ambiguous({len(hits)})"
    return hits[0][0] if len(hits[0]) == 1 else f"ambiguous({len(hits[0])})"


def schema_differences(binary: Path) -> list[str]:
    manifest = json.loads((ROOT / MANIFEST).read_text(encoding="utf-8"))
    recorded = {t["name"]: t for t in manifest["native_mcp"]["0.1.0"]}
    client = McpClient(binary)
    client.initialize()
    served = client.tools()
    client.close()
    problems = []
    for tool in served:
        reference = recorded.get(tool["name"])
        if reference is None:
            problems.append(f"{tool['name']}: not in the reference's tools/list")
            continue
        for key in ("inputSchema", "outputSchema", "annotations"):
            if tool.get(key) != reference.get(key):
                problems.append(f"{tool['name']}: {key} differs from the reference's")
    return problems or ([] if len(served) == 6 else ["not six tools"])


def mutation_summary() -> dict:
    path = ROOT / MUTATION
    if not path.is_file():
        return {"file": MUTATION, "present": False, "current": False}
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("sources sha256:")]
    return {
        "file": MUTATION, "script": "artifacts/mdd-042/mutation/mutate_mcp.py", "present": True,
        "current": recorded == [mutation_hash()],
        "killed": sum(1 for line in lines if line.startswith("KILLED")),
        "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
        "errors": sum(1 for line in lines if line.startswith("ERROR")),
        "skipped": sum(1 for line in lines if line.startswith("SKIPPED")),
        "restored_tree_passes": any("passes the MCP tests, the A0 replay and its controls: True" in line for line in lines),
    }


def check_committed() -> int:
    record = json.loads((ROOT / RECORD).read_text(encoding="utf-8"))
    stale = [path for path, digest in record["inputs_sha256"].items() if sha256(path) != digest]
    if not mutation_summary()["current"]:
        stale.append(MUTATION)
    for path in stale:
        print("STALE:", path)
    print("committed record current:", not stale)
    return 1 if stale else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-042-runs")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check_committed()
    raw = args.raw_dir

    rust = run(RUST, raw, "mcp-tests")
    clippy = run(CLIPPY, raw, "clippy")
    build = run(BUILD, raw, "build")
    built = build["exit_code"] == 0
    problems = schema_differences(DEFAULT_BINARY) if built else ["the CLI did not build"]
    replay = golden_replay.replay(DEFAULT_BINARY) if built else None
    controls = run([sys.executable, "-I", "conformance/mcp/test_golden_replay.py"], raw, "controls")

    extra = {
        SCHEMAS: "ok" if not problems else "failed",
        REPLAY: "ok" if replay and not replay["differences"] and replay["server_exit_code"] == 0 and replay["pages"] > 0 else "failed",
        REFUSALS: "ok" if replay and not replay["rejection_mismatches"] and replay["rejections"] else "failed",
        CONTROLS: "ok" if controls["exit_code"] == 0 else "failed",
    }
    results = rust_results(rust["text"])
    rows = []
    for item in ACCEPTANCE:
        proofs = [{"check": name, "outcome": extra.get(name) or lookup(results, name)} for name in item["proven"]]
        proven = all(p["outcome"] == "ok" for p in proofs) and bool(proofs)
        rows.append({"acceptance": item["acceptance"], "proofs": proofs, "not_proven": item["not_proven"],
                     "status": "proven" if proven and not item["not_proven"] else "partial" if proven else "not_proven"})
    mutation = mutation_summary()
    totals = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", rust["text"])

    record = {
        "schema_version": "mdd.mcp-required-conformance.v1",
        "task": "MDD-042",
        "status": "partial: the dataset, table and query tools; decode and get_manifest are not implemented",
        "kind": "development evidence; admits no profile",
        "capabilities": CAPABILITIES,
        "acceptance": rows,
        "schemas": {"compared_with": MANIFEST, "differences": problems},
        "a0_replay": replay and {k: replay[k] for k in ("cases", "pages", "rows", "walks", "equal")},
        "a0_replay_rejections": replay and replay["rejections"],
        "tests": {
            "rust": {"exit_code": rust["exit_code"], "passed": sum(int(t[1]) for t in totals), "failed": sum(int(t[2]) for t in totals)},
            "clippy_exit_code": clippy["exit_code"], "build_exit_code": build["exit_code"],
            "controls_exit_code": controls["exit_code"],
            "log_sha256": {"rust": rust["log_sha256"], "clippy": clippy["log_sha256"], "controls": controls["log_sha256"]},
            "raw_logs_kept_at": "artifacts/local/ (ignored; carries developer-machine output)",
        },
        "inputs_sha256": {path: sha256(path) for path in SOURCES},
        "mutation_check": mutation,
        "residual": [
            "decode, get_manifest and the resource tools are not implemented; the clauses about them are not proven",
            "the reference engine's executable is not on this machine, so open_dataset, close_dataset, list_tables, describe_table and list_datasets responses were never compared with it; their shapes are this server's own",
            "only the query tool's responses were compared with the reference, through the recording made from its own MCP server",
            "list_tables names the 17 HostLab contract relations, not the reference's 56",
            "column data_type and nullable are derived from the returned values because the result carries no declared types; an empty column says \"unknown\"",
            "a statement cannot be stopped from outside, so a deadline closes the dataset and the statement ends under the engine's own budgets",
            "requests are served one at a time; there is no cancellation or progress",
            "text with an unpaired surrogate has no UTF-8 form and is refused rather than repaired",
            "archives without a DEX are refused, although the reference supports resource-only archives",
            "one Windows host; the MCP process tests run on Linux only in the repository CI",
        ],
        "run": {"started_utc": rust["started_utc"]},
    }
    if not args.no_write:
        target = ROOT / RECORD
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")

    print(f"rust: exit={rust['exit_code']} passed={record['tests']['rust']['passed']} failed={record['tests']['rust']['failed']}   clippy={clippy['exit_code']}   build={build['exit_code']}")
    print(f"schemas: {problems or 'equal to the reference'}   controls exit={controls['exit_code']}")
    if replay:
        print(f"replay: cases={replay['cases']} pages={replay['pages']} rows={replay['rows']} walks={replay['walks']} equal={replay['equal']}")
    for row in rows:
        print(f"{row['status']:12}{row['acceptance'][:96]}")
    print(f"mutation: killed={mutation.get('killed')} survived={mutation.get('survived')} current={mutation['current']}")
    ok = (rust["exit_code"] == 0 and clippy["exit_code"] == 0 and built and not problems and replay and replay["equal"]
          and controls["exit_code"] == 0 and mutation["current"] and not mutation.get("survived")
          and not mutation.get("errors") and not mutation.get("skipped"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
