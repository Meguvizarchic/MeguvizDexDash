#!/usr/bin/env python3
"""Run every suite of MDD-071 and write artifacts/mdd-071/smali-and-paging-conformance.json.

The record says what ran, what it found, which acceptance line each result stands for, what the result does not show, and
whether a mutation result is committed and current. It is written by this script from the runs, not by hand.

Usage: python -I conformance/decode/build_mdd071_record.py [--no-write] [--check]
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

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "conformance" / "mcp"))
import mutation_harness as H  # noqa: E402
import run_decode_full as full  # noqa: E402
from mcp_client import DEFAULT_BINARY  # noqa: E402

RECORD = "artifacts/mdd-071/smali-and-paging-conformance.json"
CONTRACT = "conformance/mcp/decode-full-contract.json"
MUTATION = "artifacts/mdd-071/mutation/results.txt"
RAW = ROOT / "artifacts" / "local" / "mdd-071-runs"

SOURCES = [
    "crates/mdd-facts/src/smali/mod.rs", "crates/mdd-facts/src/smali/context.rs", "crates/mdd-facts/src/smali/value.rs",
    "crates/mdd-facts/src/smali/annotation.rs", "crates/mdd-facts/src/smali/method.rs", "crates/mdd-facts/src/smali/class.rs",
    "crates/mdd-facts/src/smali_required/mod.rs", "crates/mdd-facts/src/smali_required/render.rs", "crates/mdd-facts/src/smali_required/tests.rs",
    "crates/mdd-service/src/decode.rs", "crates/mdd-service/src/dataset.rs",
    "crates/mdd-mcp/src/tools.rs", "crates/mdd-mcp/src/tools/decode.rs",
    "crates/mdd-mcp/src/tools/manifest.rs", "crates/mdd-mcp/src/tools/sql.rs", "crates/mdd-mcp/src/tool_schemas.json",
    "crates/mdd-cli/tests/mcp.rs",
    "conformance/decode/oracle.py", "conformance/decode/oracle_class.py", "conformance/decode/run_decode_full.py", "conformance/decode/test_decode_full.py",
    "conformance/decode/run_decode_conformance.py", "conformance/decode/hand-expected.txt", "conformance/decode/hand-expected-class.txt",
    "conformance/decode/a0_cases.py", "conformance/decode/a0_replay.py", "conformance/decode/test_a0_replay.py",
    "conformance/decode/generate_a0_golden.py", "conformance/decode/a0-golden.json", "conformance/decode/build_decode_contract.py",
    "tests/fixtures/decode/generate.py", "tests/fixtures/decode/generate_class.py", "tests/fixtures/decode/manifest.json",
    "tests/fixtures/decode/class-manifest.json", "tests/fixtures/decode/generated/decode-class.dex",
    "tests/fixtures/annotations/generated/annotations-038.dex", CONTRACT,
]

CARGO = ["cargo", "test", "--offline", "--locked"]
RUST = [CARGO + ["-p", "mdd-mcp", "-p", "mdd-service", "--lib"], CARGO + ["-p", "mdd-facts", "--lib", "smali"],
        CARGO + ["-p", "mdd-cli", "--test", "mcp"]]
FMT = ["cargo", "fmt", "--all", "--", "--check"]
CLIPPY = ["cargo", "clippy", "--offline", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"]
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli"]
PY = [sys.executable, "-I"]

# (what is claimed, where the proof is read: ("full", a part of the name of a check of run_decode_full.py), ("a0",), ("contract",) or ("rust", a test name))
ACCEPTANCE = [
    {"acceptance": "class/method/annotation/debug/try-catch and payload representations have item-by-item golden and links back to the raw facts, not only a list of opcodes",
     "proven": [("the engine's text equals the independent reader's for every method of four fixtures (annotation values of every kind, every debug opcode, try/catch, switch and array payloads, static values)", ("full", "the method texts (all pages) equal the independent reader's")),
                ("the engine's class text equals the independent reader's for every class", ("full", "the class texts equal the independent reader's")),
                ("the hand-written class and method texts equal both", ("full", "hand-written class and method texts")),
                ("access flags, registers, code units, tries and declaration equal the code item's", ("full", "equal the code item's")),
                ("the reference replay compares the class, context and method answers with the reference's own", ("a0",)),
                ("the annotation values of the annotation fixture are written as the format says", ("rust", "every_kind_of_annotation_value_is_written_as_the_format_says")),
                ("a class with annotations, fields, static values and debug info is shown with all of them", ("rust", "a_class_with_annotations_fields_and_debug_info_is_shown_with_all_of_them"))],
     "not_proven": "the reader and the engine are two programs written from one specification; the specification's choices that the reference does not write "
                   "(baksmali-style labels, .param, .local, .line, field and annotation layout) are not shown to be what the reference or any other tool prints"},
    {"acceptance": "UTF-8 byte offset, max_lines, method_offset and context indexes follow their own units and never mix with DEX code units",
     "proven": [("every page number (byte offset, lines, mid-line flags, totals) equals the text's own, for every method of four fixtures", ("full", "every page number")),
                ("pages by max_lines and max_bytes rebuild the text, stay in their budgets and never cut a character", ("full", "pages by max_lines and max_bytes")),
                ("next_offset counts UTF-8 bytes, not characters", ("full", "next_offset counts UTF-8 bytes")),
                ("a class is listed by method_offset: every method once, in method_idx order, and the last page ends", ("full", "is listed in smali mode by method_offset")),
                ("the context lines name the lines of the full text, and a context pages on its own offsets", ("rust", "the_context_names_the_lines_of_the_full_text_and_pages_on_its_own")),
                ("code_units, total_bytes and total_lines are three different numbers of one method", ("full", "three different numbers"))],
     "not_proven": ""},
    {"acceptance": "methods without a body, invalid selectors, resource limits, truncation and continuation states are explicit and the last page terminates correctly",
     "proven": [("a method without a body has null registers, code units and tries, and no registers line", ("full", "a method without a body has null registers")),
                ("every refusal of the contract's table has its kind", ("full", "is refused as")),
                ("a result over the byte budget is refused whole", ("full", "refused whole")),
                ("the class text cut by max_lines says so", ("full", "the class text cut by max_lines says so")),
                ("max_bytes on a class page bounds its text and cut methods continue to the same text", ("full", "bounds its text")),
                ("method_offset equal to the total is an empty last page, one past it a range error", ("full", "method_offset past total_methods"))],
     "not_proven": "a statement cannot be stopped from outside, so a deadline closes the dataset (MDD-042 residual); the class text is one page and is not continued"},
    {"acceptance": "the output agrees with the raw bytes of the same snapshot, and a change of the text format is versioned separately",
     "proven": [("text_format names mdd.smali.v1 / mdd.smali-context.v1, and is null for summary", ("full", "is listed in smali mode by method_offset")),
                ("decode-full-contract.json records the server's answers and is current", ("contract",)),
                ("a dataset decodes from its snapshot after the source is gone", ("rust", "a_dataset_decodes_from_its_snapshot_after_the_source_is_gone"))],
     "not_proven": "a text carries no hash of its own; its identity is the dataset's snapshot and its format id"},
    {"acceptance": "Smali text does not replace the raw code fingerprint; no decompilation or runtime target inference is presented as fact",
     "proven": [("the contract lists what a text is not", ("contract",)),
                ("a debug position that is not a source line is not written as .line, and omitted counts it", ("full", "`omitted` counts what the independent reader leaves out"))],
     "not_proven": "the HostLab method fingerprint is taken in the adapter from the raw bytes (MDD-050); this task does not touch it"},
]


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def run(command: list[str], name: str) -> dict:
    RAW.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    process = subprocess.run(command, cwd=ROOT, capture_output=True)
    text = (process.stdout + process.stderr).decode("utf-8", "replace")
    (RAW / f"{name}.txt").write_text(text, encoding="utf-8", newline="\n")
    return {"name": name, "command": " ".join(command), "exit_code": process.returncode, "started_utc": started, "text": text,
            "log_sha256": hashlib.sha256(text.encode()).hexdigest()}


def rust_totals(texts: list[str]) -> tuple[int, int]:
    found = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", "\n".join(texts))
    return sum(int(p) for _o, p, _f in found), sum(int(f) for _o, _p, f in found)


def mutation_summary() -> dict:
    path = ROOT / MUTATION
    if not path.is_file():
        return {"file": MUTATION, "present": False, "current": False,
                "status": "not run yet: it runs in .github/workflows/mutation-decode.yml on request; no result is claimed",
                "script": "artifacts/mdd-071/mutation/mutate_decode.py"}
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("sources sha256:")]
    spec = importlib.util.spec_from_file_location("mutate_decode", ROOT / "artifacts/mdd-071/mutation/mutate_decode.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {"file": MUTATION, "script": "artifacts/mdd-071/mutation/mutate_decode.py", "present": True,
            "current": recorded == [module.base.sources_sha256()],
            "killed": sum(1 for line in lines if line.startswith("KILLED")),
            "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
            "errors": sum(1 for line in lines if line.startswith(("ERROR", "TIMEOUT"))),
            "skipped": sum(1 for line in lines if line.startswith("SKIPPED"))}


def check_committed(strict_provenance: bool = False) -> int:
    spec = importlib.util.spec_from_file_location("mutate_decode", ROOT / "artifacts/mdd-071/mutation/mutate_decode.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    issues = H.check_evidence(RECORD, module.SUITE, MUTATION, "artifacts/mdd-071/mutation/mutate_decode.py", strict_provenance=strict_provenance)
    record = json.loads((ROOT / RECORD).read_text(encoding="utf-8"))
    if record.get("full_decode_conformance", {}).get("failed", 1) != 0:
        issues.append("FULL_DECODE_FAILED")
    if record.get("tests", {}).get("rust", {}).get("failed", 1) != 0:
        issues.append("RECORD_TESTS_FAILED")
    for path in issues:
        print("CHECK_FAIL:", path)
    print("committed record current:", not issues)
    return 1 if issues else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--strict-provenance", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check_committed(strict_provenance=args.strict_provenance)

    rust = [run(command, f"rust-{i}") for i, command in enumerate(RUST)]
    fmt, clippy, build = run(FMT, "fmt"), run(CLIPPY, "clippy"), run(BUILD, "build")
    built = build["exit_code"] == 0
    fixtures = [run(PY + ["tests/fixtures/decode/generate.py", "--check"], "fixtures-decode"),
                run(PY + ["tests/fixtures/decode/generate_class.py", "--check"], "fixtures-class")]
    a0_path = RAW / "a0-replay.json"
    a0 = run(PY + ["conformance/decode/a0_replay.py", "--out", str(a0_path)], "a0-replay") if built else None
    a0_report = json.loads(a0_path.read_text(encoding="utf-8")) if a0 and a0_path.is_file() else None
    controls = [run(PY + [script], name) for name, script in (("controls-a0", "conformance/decode/test_a0_replay.py"),
                                                                ("controls-full", "conformance/decode/test_decode_full.py"))]
    decode_042 = run(PY + ["conformance/decode/run_decode_conformance.py"], "decode-conformance") if built else None
    result = full.run(DEFAULT_BINARY) if built else None
    contract = run(PY + ["conformance/decode/build_decode_contract.py", "--check"], "contract") if built else None
    mutation = mutation_summary()

    rust_text = "\n".join(r["text"] for r in rust)
    tests_passed, tests_failed = rust_totals([r["text"] for r in rust])
    rust_results = dict(re.findall(r"^test (\S+) \.\.\. (\w+)", rust_text, re.M))
    rows = []
    for item in ACCEPTANCE:
        proofs = []
        for label, how in item["proven"]:
            if how[0] == "full":
                hits = [c["equal"] for c in (result["checks"] if result else []) if how[1] in c["name"]]
                outcome = "ok" if hits and all(hits) else "not_run" if not result else "failed"
            elif how[0] == "a0":
                outcome = "ok" if a0_report and a0_report["cases_equal"] == a0_report["cases_run"] > 0 and a0_report["methods"]["equal"] == a0_report["methods"]["total"] else "failed"
            elif how[0] == "contract":
                outcome = "ok" if contract and contract["exit_code"] == 0 else "failed"
            else:
                found = [v for k, v in rust_results.items() if k == how[1] or k.endswith("::" + how[1])]
                outcome = found[0] if len(found) == 1 else "not_run" if not found else "ambiguous"
            proofs.append({"check": label, "outcome": outcome})
        rows.append({"acceptance": item["acceptance"], "proofs": proofs, "not_proven": item["not_proven"],
                     "status": "proven" if all(p["outcome"] == "ok" for p in proofs) and not item["not_proven"]
                     else "partial" if all(p["outcome"] == "ok" for p in proofs) else "not_proven"})

    record = {
        "schema_version": "mdd.smali-and-paging-conformance.v1",
        "task": "MDD-071",
        "kind": "development evidence; admits no profile",
        "text_formats": {"smali": full.SMALI_FORMAT, "context": full.CONTEXT_FORMAT},
        "contract": CONTRACT,
        "acceptance": rows,
        "full_decode_conformance": result and {"checks": [{"name": c["name"], "equal": c["equal"]} for c in result["checks"]],
                                               "passed": result["passed"], "failed": result["failed"], "counts": result["counts"]},
        "a0_golden_replay": a0_report and {
            "reference": a0_report["reference"], "recorded_utc": a0_report["recorded_utc"], "cases_run": a0_report["cases_run"],
            "cases_equal": a0_report["cases_equal"], "cases_equal_exactly": a0_report["cases_equal_exactly"],
            "cases_equal_with_a_declared_difference": a0_report["cases_equal_with_a_declared_difference"],
            "cases_not_run": a0_report["cases_not_run"], "methods": {k: a0_report["methods"][k] for k in ("total", "equal")},
            "declared_differences": a0_report["declared_differences"]},
        "decode_conformance_042": decode_042 and {"exit_code": decode_042["exit_code"], "summary": decode_042["text"].strip().splitlines()[-1:]},
        "contract_current": contract and contract["exit_code"] == 0,
        "fixtures_current": [f["exit_code"] == 0 for f in fixtures],
        "tests": {
            "rust": {"exit_code": max(r["exit_code"] for r in rust), "passed": tests_passed, "failed": tests_failed},
            "fmt_exit_code": fmt["exit_code"], "clippy_exit_code": clippy["exit_code"], "build_exit_code": build["exit_code"],
            "controls_exit_codes": [c["exit_code"] for c in controls],
            "log_sha256": {"rust": [r["log_sha256"] for r in rust], "clippy": clippy["log_sha256"], "controls": [c["log_sha256"] for c in controls]},
            "raw_logs_kept_at": "artifacts/local/ (ignored; carries developer-machine output)",
        },
        "inputs_sha256": {path: sha256(path) for path in SOURCES},
        "mutation_check": mutation,
        "residual": [
            "the reference writes no annotation, parameter name, debug directive, class header or field line: those parts of mdd.smali.v1 have no reference output to equal; "
            "they are checked against an independent reader of the bytes and hand-written texts, and the reference replay removes them (EXTRA DIRECTIVES) before it compares instructions",
            "the context view keeps the lines the reference's keeps (checked against its answers for all 240 defined methods of the fixtures); its labels are baksmali-named, so its numbers differ and are compared after reduction",
            "max_bytes on a class page is one budget for the text of the page here; the reference counts the serialized answer (twice) and accepts only 4096..131072",
            "the class text is a single page of max_lines lines (the class selector refuses offset): a class with more lines than that shows `truncated` and the rest is in the SQL relations",
            "a parameter's annotations are placed only when the method's slots are as many as its prototype's parameters; otherwise they are counted in omitted",
            "debug events at no instruction start or past the code, and positions that are no source line, are not written and are counted in omitted",
            "a method handle in an annotation value is shown as method_handle_<index>; the float text keeps no NaN payload",
            "the pc-to-pc recognition is the debug layer's (MDD-023): it describes the encoding, not the producer",
            "the XML mode of get_manifest is MDD-072 and is still refused as not_implemented",
            "smali_required (MDD-042) and smali (MDD-071) are two directories on purpose: the first is named by MDD-042's record; merging them re-cuts that record",
            "one Windows host; the mutation check is run on request in .github/workflows/mutation-decode.yml",
        ],
        "run": {"started_utc": rust[0]["started_utc"]},
    }
    if not args.no_write:
        target = ROOT / RECORD
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(record, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

    print(f"rust: exit={record['tests']['rust']['exit_code']} passed={tests_passed} failed={tests_failed}   fmt={fmt['exit_code']} clippy={clippy['exit_code']} build={build['exit_code']}")
    print(f"controls exit={[c['exit_code'] for c in controls]}  fixtures current={record['fixtures_current']}  contract current={record['contract_current']}")
    if a0_report:
        print(f"a0 replay: cases {a0_report['cases_equal']}/{a0_report['cases_run']} equal ({a0_report['cases_equal_exactly']} exactly), "
              f"{len(a0_report['cases_not_run'])} not run; methods {a0_report['methods']['equal']}/{a0_report['methods']['total']} equal")
    if decode_042:
        print("decode conformance (042):", record["decode_conformance_042"]["summary"])
    if result:
        print(f"full decode: checks={len(result['checks'])} passed={result['passed']} failed={result['failed']} counts={result['counts']}")
        for check in result["checks"]:
            if not check["equal"]:
                print("  FAIL", check["name"], "|", check["detail"])
    print(f"mutation: present={mutation['present']} killed={mutation.get('killed')} survived={mutation.get('survived')} current={mutation['current']}")
    ok = (all(r["exit_code"] == 0 for r in rust) and fmt["exit_code"] == 0 and clippy["exit_code"] == 0 and built and a0 and a0["exit_code"] == 0
          and all(c["exit_code"] == 0 for c in controls) and decode_042 and decode_042["exit_code"] == 0 and result and result["equal"]
          and contract and contract["exit_code"] == 0 and all(f["exit_code"] == 0 for f in fixtures)
          and (not mutation["present"] or (mutation["current"] and not mutation.get("survived") and not mutation.get("errors") and not mutation.get("skipped"))))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
