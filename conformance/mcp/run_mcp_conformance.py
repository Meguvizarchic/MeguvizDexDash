#!/usr/bin/env python3
"""Run the MDD-042 MCP conformance and write the (partial) record.

Usage: python -I conformance/mcp/run_mcp_conformance.py [--raw-dir DIR] [--no-write] [--check]

Run it with the validation environment's Python. It builds the CLI, runs the Rust tests of
the MCP server, the shared service and the smali renderer and the MCP process tests, a clippy
pass, compares the `tools/list` schemas with the reference engine's recorded ones, and runs
four replays through the real server: the frozen A0 query recordings, the recorded lifecycle
and decode sessions, the decode conformance (independent renderer and hand-written texts) and
the recorded NewPipe manifest summary. It also runs their negative controls. Each acceptance
clause of MDD-042 is mapped to checks whose outcomes come from that run.

The record is PARTIAL by construction: the reference engine's executable is not available, so
only what was recorded can be compared with it, and the record says row by row which requests
that is and which it is not.

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
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "conformance" / "decode"))
import mutation_harness as H  # noqa: E402
import golden_replay  # noqa: E402
import lifecycle_replay  # noqa: E402
import manifest_replay  # noqa: E402
import run_decode_conformance as decode_conformance  # noqa: E402
from mcp_client import DEFAULT_BINARY, McpClient  # noqa: E402

RECORD = "artifacts/mdd-042/mcp-required-conformance.json"
MUTATION = "artifacts/mdd-042/mutation/results.txt"
MANIFEST = "conformance/manifests/tools-and-options.json"
SOURCES = [
    "crates/mdd-mcp/src/tools.rs", "crates/mdd-mcp/src/tools/decode.rs",
    "crates/mdd-mcp/src/tools/manifest.rs", "crates/mdd-mcp/src/tools/sql.rs",
    "crates/mdd-mcp/src/server.rs", "crates/mdd-mcp/src/protocol.rs",
    "crates/mdd-mcp/src/lib.rs", "crates/mdd-mcp/src/tool_schemas.json", "crates/mdd-cli/tests/mcp.rs",
    "crates/mdd-service/src/decode.rs", "crates/mdd-service/src/dataset.rs", "crates/mdd-service/src/manifest.rs",
    "crates/mdd-facts/src/smali_required/mod.rs", "crates/mdd-facts/src/smali_required/render.rs",
    "crates/mdd-facts/src/smali_required/tests.rs",
    "conformance/mcp/mcp_client.py", "conformance/mcp/golden_replay.py", "conformance/mcp/test_golden_replay.py",
    "conformance/mcp/lifecycle_replay.py", "conformance/mcp/manifest_replay.py", "conformance/mcp/test_replays.py",
    "conformance/mcp/tiny_dex.py", "conformance/mcp/run_mcp_conformance.py",
    "conformance/decode/oracle.py", "conformance/decode/run_decode_conformance.py", "conformance/decode/hand-expected.txt",
    "conformance/decode/a0_cases.py", "conformance/decode/a0_replay.py", "conformance/decode/test_a0_replay.py",
    "conformance/decode/generate_a0_golden.py", "conformance/decode/a0-golden.json",
    "tests/fixtures/decode/generate.py", "tests/fixtures/decode/manifest.json",
    "conformance/corpus/hostlab/required-variants.json",
    "conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json", MANIFEST,
    "evidence/compatibility/0.1.0/mcp-records.json", "artifacts/mdd-025/manifest/a0/summary-pages.json",
]

CARGO = ["cargo", "test", "--offline", "--locked"]
RUST = [CARGO + ["-p", "mdd-mcp", "-p", "mdd-service", "--lib"],
        CARGO + ["-p", "mdd-facts", "--lib", "smali_required"],
        CARGO + ["-p", "mdd-cli", "--test", "mcp"]]
CLIPPY = ["cargo", "clippy", "--offline", "--locked", "-p", "mdd-mcp", "-p", "mdd-service", "-p", "mdd-facts", "-p", "mdd-cli",
          "--all-targets", "--", "-D", "warnings"]
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli"]

SCHEMAS = "tools/list: the eight registered tools carry the reference engine's published schemas"
QUERY = "A0 replay: every recorded query page equals the reference through the real server"
REFUSALS = "A0 replay: every recorded refusal is refused, at the same statement index"
LIFECYCLE = "recorded sessions: open, list, close, errors, TEMP, deadline, identity and the recorded decode answers equal the reference's"
DECODE = "decode conformance: the engine's text equals an independent renderer and hand-written texts for every method of the fixtures"
MANIFEST_REPLAY = "recorded NewPipe get_manifest summary: all six pages equal the reference's"
A0_REPLAY = ("the reference binary's own answers (dexsql 0.1.0, sha256 f354ebcf...c448, frozen in conformance/decode/a0-golden.json): every request answers equally "
             "or with a declared difference, and every method of the fixtures decodes to the same instructions")
CONTROLS = "negative controls: damaged recordings, hand texts, renderers and the replay's own comparison are caught"

ACCEPTANCE = [
    {"acceptance": "the five HostLab tools open_dataset/query/decode/get_manifest/close_dataset answer request by request like the reference, and the three discovery tools carry the real schema",
     "proven": [SCHEMAS, QUERY, REFUSALS, LIFECYCLE, MANIFEST_REPLAY, A0_REPLAY, CONTROLS],
     "not_proven": [
         "equivalence is of content and of the fields a client reads, not of every byte: the declared differences (a0_golden_replay.declared_differences) are this server's choices, among them the writing of the smali text, the words of error messages, arguments outside the reference's ranges, and the order in which several mistakes in one request are named; the acceptance asks for answers 'like the reference'; the product owner accepted content and field equivalence with these differences on 2026-11-16 (\"我觉得042可以算是过了\", after saying that exact equality with dexsql is not required)",
         "decode of a class, the context mode and the xml mode of get_manifest are not implemented (MDD-071, MDD-072); the reference's answers to them are frozen in the golden for those tasks",
         "get_manifest: values of float, dimension, fraction, color and null types are refused; the one manifest of the golden carries none",
         "query: integer type tags for negative numbers and booleans, column data_type (sqlite_dynamic in the reference) and optimizer diagnostics are not equal; they are listed as declared differences",
         "server_busy cannot arise (one request at a time); the path-plus-symlink identity case needs a link this account could not make"]},
    {"acceptance": "decode produces the instructions, method context and declarations production uses, never placeholder text or opcodes alone",
     "proven": [DECODE, A0_REPLAY, CONTROLS],
     "not_proven": ["no fixture holds invoke-custom, const-method-handle or const-method-type (call-site and method-handle tables are not built); their operands print as call_site_N / method_handle_N",
                    "debug info and annotations are not shown (the reference points to SQL tables for them); the class selection and the context mode are refused as not implemented (MDD-071)"]},
    {"acceptance": "Smali and Manifest paging keep their own units (UTF-8 byte offsets, line counts, permission rows) and do not mix with DEX byte offsets",
     "proven": [DECODE, MANIFEST_REPLAY, A0_REPLAY, "decode_pages_by_utf8_byte_offset_and_lines_apart",
                "permissions_page_by_rows_and_the_rest_of_the_summary_repeats_unchanged"],
     "not_proven": ["the page boundaries of a smali text follow this server's text, which is written differently from the reference's, so a page is compared with the reference's for its content and its fields, not for where it ends; the manifest xml mode (UTF-8 byte offsets) is not provided (MDD-072)"]},
    {"acceptance": "tool ownership, quotas, closing, errors and source identity are checked through real MCP JSON-RPC",
     "proven": ["the_session_must_be_initialized_before_tools_and_may_be_initialized_once",
                "only_protocol_messages_reach_stdout_and_bad_lines_do_not_end_the_session",
                "arguments_that_break_the_published_schema_are_protocol_errors",
                "opening_a_dataset_answers_in_the_references_shape_and_names_its_source",
                "an_input_that_cannot_be_opened_is_a_tool_error_naming_the_cause",
                "closing_releases_a_dataset_and_later_requests_that_name_it_are_refused",
                "listing_answers_with_the_references_fields_and_no_others_per_dataset",
                "the_dataset_quota_is_enforced_and_closing_frees_a_slot",
                "the_total_input_byte_quota_is_enforced_like_the_dataset_quota",
                "datasets_are_isolated_from_each_other",
                "a_query_that_outlives_its_deadline_closes_its_dataset_and_only_that_one",
                "a_result_over_the_byte_budget_is_refused_never_clipped",
                "a_dataset_decodes_from_its_snapshot_after_the_source_is_gone",
                "the_manifest_tool_says_why_it_cannot_answer",
                "a_closed_stdin_is_a_clean_end_and_a_closed_stdout_is_exit_four"],
     "not_proven": []},
    {"acceptance": "the M4 capability registers only what passes; get_manifest_components, list_resource_files, read_resource and query_resources are unavailable or unregistered",
     "proven": ["exactly_the_implemented_tools_are_listed_with_their_published_schemas",
                "timing_is_reported_when_asked_for_and_absent_otherwise"],
     "not_proven": []},
]

CAPABILITIES = [
    {"name": "open_dataset", "provided": True, "scope": "DEX and APK paths with at least one DEX; resource-only archives are refused; the reference's six fields plus this engine's snapshot identity"},
    {"name": "list_datasets", "provided": True, "scope": "the reference's shape; limits are this server's own configuration"},
    {"name": "close_dataset", "provided": True, "scope": "a dataset that is not open, closed or never opened, is refused as unknown_dataset, as the reference does"},
    {"name": "list_tables", "provided": True, "scope": "the 17 HostLab contract relations, not the reference's 56"},
    {"name": "describe_table", "provided": True, "scope": "columns, types, fact layers; case-insensitive name"},
    {"name": "query", "provided": True, "scope": "up to 16 statements, row windows with exact totals, TEMP and named temporary queries, timing; equal to the frozen A0 recording"},
    {"name": "decode", "provided": True, "scope": "one method by descriptor or by file_id+method_idx; smali and summary modes; class selection and context mode refused as not implemented (MDD-071)"},
    {"name": "get_manifest", "provided": True, "scope": "summary mode with paged permission rows; xml mode refused as not implemented (MDD-072)"},
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


EIGHT = {"open_dataset", "list_datasets", "close_dataset", "decode", "get_manifest", "list_tables", "describe_table", "query"}


def schema_differences(binary: Path) -> list[str]:
    manifest = json.loads((ROOT / MANIFEST).read_text(encoding="utf-8"))
    recorded = {t["name"]: t for t in manifest["native_mcp"]["0.1.0"]}
    client = McpClient(binary)
    client.initialize()
    # MDD-042's eight; the tools MDD-071 and MDD-072 completed are checked by their own records
    served = [tool for tool in client.tools() if tool["name"] in EIGHT]
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
    return problems or ([] if len(served) == 8 else ["not eight tools"])


def mutation_summary() -> dict:
    """The mutation result, if one is committed. It is produced by .github/workflows/mutation-mcp.yml
    (about four minutes there, in four parts; about an hour if one machine runs all of it), not on a developer machine; until its results.txt is committed the
    record says so instead of claiming a result."""
    path = ROOT / MUTATION
    if not path.is_file():
        spec = importlib.util.spec_from_file_location("mutate_mcp", ROOT / "artifacts/mdd-042/mutation/mutate_mcp.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return {"file": MUTATION, "present": False, "current": False,
                "status": "not run yet: it runs in .github/workflows/mutation-mcp.yml on request; no result is claimed",
                "script": "artifacts/mdd-042/mutation/mutate_mcp.py", "mutants": len(module.MUTANTS),
                "earlier_result": "artifacts/mdd-042/mutation/results-before-reference.txt (52 mutants, Actions run 43820360601 on fbbd3b4, all killed, before the reference replay and 5 more mutants); "
                                  "artifacts/mdd-042/mutation/results-first-slice.txt (17 mutants, the first slice, 2e38019)"}
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("sources sha256:")]
    return {
        "file": MUTATION, "script": "artifacts/mdd-042/mutation/mutate_mcp.py", "present": True,
        "current": recorded == [mutation_hash()],
        "killed": sum(1 for line in lines if line.startswith("KILLED")),
        "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
        "errors": sum(1 for line in lines if line.startswith(("ERROR", "TIMEOUT"))),
        "skipped": sum(1 for line in lines if line.startswith("SKIPPED")),
        "restored_tree_passes": any("passes the unit and process tests, the replays and their controls: True" in line for line in lines),
        "public_apk_was_present": any("public APK present for the manifest replay: True" in line for line in lines),
    }


def check_committed(strict_provenance: bool = False) -> int:
    spec = importlib.util.spec_from_file_location("mutate_mcp", ROOT / "artifacts/mdd-042/mutation/mutate_mcp.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    issues = H.check_evidence(RECORD, module.SUITE, MUTATION, "artifacts/mdd-042/mutation/mutate_mcp.py", strict_provenance=strict_provenance)
    record = json.loads((ROOT / RECORD).read_text(encoding="utf-8"))
    if not record.get("a0_query_replay", {}).get("equal"):
        issues.append("A0_QUERY_NOT_EQUAL")
    if record.get("tests", {}).get("rust", {}).get("failed", 1) != 0:
        issues.append("RECORD_TESTS_FAILED")
    for path in issues:
        print("CHECK_FAIL:", path)
    print("committed record current:", not issues)
    return 1 if issues else 0


def brief(result: dict) -> dict:
    return {"checks": [{"name": c["name"], "equal": c["equal"]} for c in result["checks"]],
            "passed": result["passed"], "failed": result["failed"], "not_run": result.get("not_run", 0)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-042-runs")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--strict-provenance", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check_committed(strict_provenance=args.strict_provenance)
    raw = args.raw_dir

    rust_runs = [run(command, raw, f"rust-{i}") for i, command in enumerate(RUST)]
    rust_text = "\n".join(r["text"] for r in rust_runs)
    rust_exit = max(r["exit_code"] for r in rust_runs)
    clippy = run(CLIPPY, raw, "clippy")
    build = run(BUILD, raw, "build")
    built = build["exit_code"] == 0
    problems = schema_differences(DEFAULT_BINARY) if built else ["the CLI did not build"]
    query = golden_replay.replay(DEFAULT_BINARY) if built else None
    lifecycle = lifecycle_replay.run(DEFAULT_BINARY) if built else None
    decode = decode_conformance.run(DEFAULT_BINARY) if built else None
    manifest = manifest_replay.run(DEFAULT_BINARY) if built else None
    a0_report_path = raw / "a0-replay.json"
    a0_run = run([sys.executable, "-I", "conformance/decode/a0_replay.py", "--out", str(a0_report_path)], raw, "a0-replay") if built else None
    a0_report = json.loads(a0_report_path.read_text(encoding="utf-8")) if a0_run and a0_report_path.is_file() else None
    controls = [run([sys.executable, "-I", "conformance/mcp/test_golden_replay.py"], raw, "controls-golden"),
                run([sys.executable, "-I", "conformance/mcp/test_replays.py"], raw, "controls-replays"),
                run([sys.executable, "-I", "conformance/decode/test_a0_replay.py"], raw, "controls-a0-replay")]
    controls_ok = all(c["exit_code"] == 0 for c in controls)
    manifest_ran = bool(manifest) and manifest["not_run"] == 0

    extra = {
        SCHEMAS: "ok" if not problems else "failed",
        QUERY: "ok" if query and not query["differences"] and query["server_exit_code"] == 0 and query["pages"] > 0 else "failed",
        REFUSALS: "ok" if query and not query["rejection_mismatches"] and query["rejections"] else "failed",
        LIFECYCLE: "ok" if lifecycle and lifecycle["equal"] and lifecycle["passed"] > 0 else "failed",
        DECODE: "ok" if decode and decode["equal"] and decode["passed"] > 0 else "failed",
        MANIFEST_REPLAY: ("ok" if manifest and manifest["equal"] and manifest_ran else "not_run" if manifest and manifest["equal"] else "failed"),
        A0_REPLAY: ("ok" if a0_run and a0_run["exit_code"] == 0 and a0_report and a0_report["cases_equal"] == a0_report["cases_run"] > 0
                    and a0_report["methods"]["equal"] == a0_report["methods"]["total"] > 0 else "failed"),
        CONTROLS: "ok" if controls_ok else "failed",
    }
    results = rust_results(rust_text)
    rows = []
    for item in ACCEPTANCE:
        proofs = [{"check": name, "outcome": extra.get(name) or lookup(results, name)} for name in item["proven"]]
        proven = all(p["outcome"] == "ok" for p in proofs) and bool(proofs)
        rows.append({"acceptance": item["acceptance"], "proofs": proofs, "not_proven": item["not_proven"],
                     "status": "proven" if proven and not item["not_proven"] else "partial" if proven else "not_proven"})
    mutation = mutation_summary()
    totals = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", rust_text)

    record = {
        "schema_version": "mdd.mcp-required-conformance.v2",
        "task": "MDD-042",
        "status": "accepted by the product owner on 2026-11-16: content and the fields a client reads equal the reference's (its binary was obtained that day and its answers frozen), with the declared differences; decode of a class, the context mode and the manifest xml mode are MDD-071 and MDD-072",
        "kind": "development evidence; admits no profile",
        "capabilities": CAPABILITIES,
        "acceptance": rows,
        "schemas": {"compared_with": MANIFEST, "differences": problems},
        "a0_query_replay": query and {k: query[k] for k in ("cases", "pages", "rows", "walks", "equal")},
        "a0_query_replay_rejections": query and query["rejections"],
        "recorded_sessions_replay": lifecycle and dict(brief(lifecycle), recording=lifecycle["recording"],
                                                       recorded_messages=lifecycle["recorded_messages"],
                                                       declared_differences=lifecycle["declared_differences"]),
        "decode_conformance": decode and brief(decode),
        "manifest_replay": manifest and dict(brief(manifest), public_apk_present=manifest_ran),
        "a0_golden_replay": a0_report and {
            "reference": a0_report["reference"], "recorded_utc": a0_report["recorded_utc"],
            "cases_run": a0_report["cases_run"], "cases_equal": a0_report["cases_equal"],
            "cases_equal_exactly": a0_report["cases_equal_exactly"],
            "cases_equal_with_a_declared_difference": a0_report["cases_equal_with_a_declared_difference"],
            "cases_not_run": a0_report["cases_not_run"], "methods": {k: a0_report["methods"][k] for k in ("total", "equal")},
            "declared_differences": a0_report["declared_differences"],
        },
        "tests": {
            "rust": {"exit_code": rust_exit, "passed": sum(int(t[1]) for t in totals), "failed": sum(int(t[2]) for t in totals)},
            "clippy_exit_code": clippy["exit_code"], "build_exit_code": build["exit_code"],
            "controls_exit_codes": [c["exit_code"] for c in controls],
            "log_sha256": {"rust": [r["log_sha256"] for r in rust_runs], "clippy": clippy["log_sha256"],
                           "controls": [c["log_sha256"] for c in controls]},
            "raw_logs_kept_at": "artifacts/local/ (ignored; carries developer-machine output)",
        },
        "inputs_sha256": {path: sha256(path) for path in SOURCES},
        "mutation_check": mutation,
        "residual": [
            "the reference's executable is not kept in the repository (a closed-source binary, https://github.com/LSPosed/dexsql-release v0.1.0); conformance/decode/generate_a0_golden.py freezes its answers from a copy whose sha256 it checks, and the replay needs no binary",
            "decode text follows baksmali's writing (pN parameter registers, :cond_N/:goto_N labels, .catch lines beside the code, L on wide literals, escaped apostrophes) where the reference writes vN registers, :label_XXXX, .catch lines at the end, no L and a bare apostrophe; the two texts are compared after both are reduced to the same form, so instructions, operands, literals, targets, switch cases and exception tables are equal, but the byte offsets and line numbers of a page differ",
            "a method whose invoke names a different number of registers than its prototype takes is rendered as written; the reference refuses it (invalid_input at the invoke's offset)",
            "arguments outside the reference's ranges (max_bytes outside 4096..=131072, timeout_ms outside 1..=60000) are served here; wrong types, unknown fields and limits outside their range are JSON-RPC invalid-params errors here and tool results with isError in the reference",
            "get_manifest refuses attribute values of float, dimension, fraction, color, null and unknown types, and attributes in namespaces other than android; the golden's manifest shows neither",
            "get_manifest page size defaults to 200 rows, the reference's limit maximum (equal in the golden)",
            "when a manifest has several <application> or <uses-sdk> elements the summary shows the first; the reference's choice is unrecorded",
            "an activity-alias is counted under its own name in component_counts; the recording has no alias",
            "the NewPipe manifest replay needs a local public APK (ignored input); without it the check is reported as not run, as in CI",
            "list_tables names the 17 HostLab contract relations, not the reference's 56",
            "column data_type and nullable are derived from the returned values; the reference says sqlite_dynamic for TEMP and expression columns",
            "a statement cannot be stopped from outside, so a deadline closes the dataset and the statement ends under the engine's own budgets",
            "requests are served one at a time; there is no cancellation or progress",
            "text with an unpaired surrogate has no UTF-8 form and is refused rather than repaired",
            "archives without a DEX are refused, although the reference supports resource-only archives",
            "decode needs a DEX whose code layer builds: one code item that fails validation withholds every method body of that DEX",
            "one Windows host; the MCP process tests run on Linux only in the repository CI",
        ],
        "run": {"started_utc": rust_runs[0]["started_utc"]},
    }
    if not args.no_write:
        target = ROOT / RECORD
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")

    print(f"rust: exit={rust_exit} passed={record['tests']['rust']['passed']} failed={record['tests']['rust']['failed']}   clippy={clippy['exit_code']}   build={build['exit_code']}")
    print(f"schemas: {problems or 'equal to the reference'}   controls exit={[c['exit_code'] for c in controls]}")
    if query:
        print(f"query replay: cases={query['cases']} pages={query['pages']} rows={query['rows']} walks={query['walks']} equal={query['equal']}")
    if a0_report:
        print(f"a0 replay: cases {a0_report['cases_equal']}/{a0_report['cases_run']} equal ({a0_report['cases_equal_exactly']} exactly), "
              f"{len(a0_report['cases_not_run'])} not run; methods {a0_report['methods']['equal']}/{a0_report['methods']['total']} equal")
    for label, result in (("sessions", lifecycle), ("decode", decode), ("manifest", manifest)):
        if result:
            print(f"{label}: checks={len(result['checks'])} passed={result['passed']} failed={result['failed']} equal={result['equal']}")
            for check in result["checks"]:
                if check["equal"] is False:
                    print("  FAIL", check["name"], "|", str(check.get("detail", ""))[:600])
    for row in rows:
        print(f"{row['status']:12}{row['acceptance'][:96]}")
    print(f"mutation: present={mutation['present']} killed={mutation.get('killed')} survived={mutation.get('survived')} current={mutation['current']}")
    ok = (rust_exit == 0 and clippy["exit_code"] == 0 and built and not problems and query and query["equal"]
          and lifecycle and lifecycle["equal"] and decode and decode["equal"] and manifest and manifest["equal"]
          and extra[A0_REPLAY] == "ok" and controls_ok and (not mutation["present"] or (mutation["current"] and not mutation.get("survived")
                                                           and not mutation.get("errors") and not mutation.get("skipped"))))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
