#!/usr/bin/env python3
"""The requests that are put to the reference engine (A0, dexsql 0.1.0) and to this server.

generate_a0_golden.py runs them against the reference and freezes its answers in a0-golden.json;
a0_replay.py runs the same requests against this server and compares. Nothing here is a judgement
about what the reference should do: a request is in the list because we want to know what it does.

A case is {"id", "inputs": [fixture names], "tool", "arguments": {...}}. `arguments` never holds the
dataset id. A case whose arguments depend on the fixture (a method index) names the method by its
descriptor under "resolve": the generator looks the index up in the reference's own `methods` table
and freezes the concrete arguments, so the replay needs no lookup.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "decode" / "generated"
GOLDEN = HERE / "a0-golden.json"

A0_SHA256 = "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"
A0_ORIGIN = "https://github.com/LSPosed/dexsql-release/releases/download/v0.1.0/dexsql-windows-amd64.exe"

DEX = ["decode-all.dex"]
DEX_TWO = ["decode-all.dex", "decode-v035.dex"]
APK = ["manifest-small.apk"]
NO_MANIFEST = ["no-manifest.apk"]

T = "Ldecode/T;"
SWITCH = T + "->switch_packed()V"
TRY = T + "->try_catch()V"
ABSTRACT = T + "->abstract_one(I)I"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def case(id_: str, inputs: list[str], tool: str, arguments: dict, resolve: dict | None = None) -> dict:
    entry = {"id": id_, "inputs": inputs, "tool": tool, "arguments": arguments}
    if resolve:
        entry["resolve"] = resolve
    return entry


def decode_cases() -> list[dict]:
    cases: list[dict] = []
    # validation of the arguments, answered on the same method
    base = {"method": SWITCH}
    for name, extra in [
        ("max_lines-0", {"max_lines": 0}), ("max_lines-1", {"max_lines": 1}), ("max_lines-1000", {"max_lines": 1000}),
        ("max_lines-1001", {"max_lines": 1001}), ("max_lines-negative", {"max_lines": -1}), ("max_lines-string", {"max_lines": "3"}),
        ("max_bytes-0", {"max_bytes": 0}), ("max_bytes-1", {"max_bytes": 1}), ("max_bytes-4095", {"max_bytes": 4095}),
        ("max_bytes-4096", {"max_bytes": 4096}), ("max_bytes-131072", {"max_bytes": 131072}), ("max_bytes-131073", {"max_bytes": 131073}),
        ("timeout_ms-0", {"timeout_ms": 0}), ("timeout_ms-1", {"timeout_ms": 1}), ("timeout_ms-60000", {"timeout_ms": 60000}),
        ("timeout_ms-60001", {"timeout_ms": 60001}), ("timeout_ms-negative", {"timeout_ms": -5}),
        ("offset-negative", {"offset": -1}), ("offset-string", {"offset": "0"}), ("offset-float", {"offset": 1.5}),
        ("unknown-field", {"bogus": 1}), ("null-fields", {"max_lines": None, "max_bytes": None, "timeout_ms": None, "file_id": None}),
        ("method_offset-1", {"method_offset": 1}), ("method_limit-0", {"method_limit": 0}), ("method_limit-51", {"method_limit": 51}),
        ("mode-bad", {"mode": "components"}), ("mode-smali", {"mode": "smali"}), ("mode-summary", {"mode": "summary"}),
        ("mode-context", {"mode": "context"}), ("mode-null", {"mode": None}),
    ]:
        cases.append(case("decode-arg-" + name, DEX, "decode", {**base, **extra}))
    # the selectors
    cases += [
        case("decode-select-none", DEX, "decode", {}),
        case("decode-select-two", DEX, "decode", {"method": SWITCH, "class": T}),
        case("decode-select-method-and-idx", DEX, "decode", {"method": SWITCH, "method_idx": 7, "file_id": 0}),
        case("decode-select-idx-without-file", DEX, "decode", {"method_idx": 7}),
        case("decode-select-file-only", DEX, "decode", {"file_id": 0}),
        case("decode-select-unknown-method", DEX, "decode", {"method": T + "->nope()V"}),
        case("decode-select-not-a-descriptor", DEX, "decode", {"method": "not a descriptor"}),
        case("decode-select-empty-method", DEX, "decode", {"method": ""}),
        case("decode-select-bad-file", DEX, "decode", {"file_id": 9, "method_idx": 7}),
        case("decode-select-bad-idx", DEX, "decode", {"file_id": 0, "method_idx": 99999}),
        case("decode-select-referenced-only", DEX, "decode", {"file_id": 0, "method_idx": 0}),
        case("decode-select-file-id-too-large", DEX, "decode", {"file_id": 4294967296, "method_idx": 7}),
        case("decode-select-class", DEX, "decode", {"class": T}),
        case("decode-select-class-unknown", DEX, "decode", {"class": "Lnope/Nope;"}),
        case("decode-select-class-smali", DEX, "decode", {"class": T, "mode": "smali"}),
        case("decode-select-class-summary", DEX, "decode", {"class": T, "mode": "summary", "method_limit": 3}),
        case("decode-select-class-context", DEX, "decode", {"class": T, "mode": "context", "method_limit": 2}),
        case("decode-select-class-page-2", DEX, "decode", {"class": T, "method_offset": 3, "method_limit": 2}),
        case("decode-select-class-offset-past", DEX, "decode", {"class": T, "method_offset": 9999}),
        case("decode-select-two-files-ambiguous", DEX_TWO, "decode", {"method": "Ldecode/Other;->work()V"}),
    ]
    # the text and its pages, on a method with a switch, one with tries, one without code
    for label, descriptor in (("switch", SWITCH), ("try", TRY), ("abstract", ABSTRACT)):
        cases.append(case(f"decode-text-{label}", DEX, "decode", {"method": descriptor}))
        cases.append(case(f"decode-text-{label}-by-index", DEX, "decode", {"file_id": 0, "method_idx": None},
                          resolve={"descriptor": descriptor, "into": "method_idx"}))
        cases.append(case(f"decode-text-{label}-context", DEX, "decode", {"method": descriptor, "mode": "context"}))
        cases.append(case(f"decode-text-{label}-summary", DEX, "decode", {"method": descriptor, "mode": "summary"}))
    cases += class_cases()
    for offset in (0, 1, 2, 10, 30, 100):
        cases.append(case(f"decode-page-switch-offset-{offset}", DEX, "decode", {"method": SWITCH, "offset": offset, "max_lines": 2}))
    cases += [
        case("decode-page-switch-offset-total", DEX, "decode", {"method": SWITCH, "offset": 329}),
        case("decode-page-switch-offset-total-plus-1", DEX, "decode", {"method": SWITCH, "offset": 330}),
        case("decode-page-switch-offset-huge", DEX, "decode", {"method": SWITCH, "offset": 99999999}),
        case("decode-page-switch-lines-3-offset-after-first", DEX, "decode", {"method": SWITCH, "offset": 36, "max_lines": 3}),
        case("decode-page-switch-bytes-4096", DEX, "decode", {"method": SWITCH, "max_bytes": 4096, "max_lines": 1}),
    ]
    return cases


def class_cases() -> list[dict]:
    """A class selection, its pages of methods and of text (MDD-071). decode-all.dex defines Ldecode/T; with 238 methods;
    decode-v035.dex defines a class of the same name with two. The last method of T (position 237) has a non-ASCII name."""
    cases = []
    for name, arguments, inputs in [
        ("two-files-ambiguous", {"class": T}, DEX_TWO),
        ("two-files-file-id-1", {"class": T, "file_id": 1}, DEX_TWO),
        ("two-files-file-id-0-limit-1", {"class": T, "file_id": 0, "method_limit": 1}, DEX_TWO),
        ("bad-file-id", {"class": T, "file_id": 9}, DEX_TWO),
        ("unknown-class-with-file-id", {"class": "Lnope/N;", "file_id": 0}, DEX_TWO),
        ("referenced-only", {"class": "Ljava/lang/Object;"}, DEX),
        ("referenced-only-other", {"class": "Ldecode/Other;"}, DEX),
        ("not-a-descriptor", {"class": "decode.T"}, DEX),
        ("without-semicolon", {"class": "Ldecode/T"}, DEX),
        ("empty", {"class": ""}, DEX),
        ("method-offset-total", {"class": T, "method_offset": 238}, DEX),
        ("method-offset-total-plus-1", {"class": T, "method_offset": 239}, DEX),
        ("method-offset-last", {"class": T, "method_offset": 237}, DEX),
        ("last-page-limit-50", {"class": T, "method_offset": 236, "method_limit": 50}, DEX),
        ("method-limit-1", {"class": T, "method_limit": 1}, DEX),
        ("method-limit-50", {"class": T, "method_limit": 50}, DEX),
        ("method-limit-0", {"class": T, "method_limit": 0}, DEX),
        ("method-limit-51", {"class": T, "method_limit": 51}, DEX),
        ("offset-nonzero-summary", {"class": T, "offset": 5}, DEX),
        ("offset-nonzero-smali", {"class": T, "mode": "smali", "method_limit": 3, "offset": 10}, DEX),
        ("offset-nonzero-context", {"class": T, "mode": "context", "offset": 10}, DEX),
        ("smali-max_lines-2", {"class": T, "mode": "smali", "method_limit": 2, "max_lines": 2}, DEX),
        ("smali-method-offset-2-limit-2", {"class": T, "mode": "smali", "method_offset": 2, "method_limit": 2, "max_lines": 1}, DEX),
        ("smali-abstract-and-native", {"class": T, "mode": "smali", "method_offset": 2, "method_limit": 1}, DEX),
        ("smali-last-page", {"class": T, "mode": "smali", "method_offset": 230, "method_limit": 50}, DEX),
        ("smali-try-methods", {"class": T, "mode": "smali", "method_offset": 234, "method_limit": 3}, DEX),
        ("context-max_lines-2", {"class": T, "mode": "context", "method_limit": 2, "max_lines": 2}, DEX),
        ("context-last-page", {"class": T, "mode": "context", "method_offset": 230, "method_limit": 50}, DEX),
        ("context-try-methods", {"class": T, "mode": "context", "method_offset": 234, "method_limit": 3}, DEX),
        ("context-switch-methods", {"class": T, "mode": "context", "method_offset": 232, "method_limit": 4}, DEX),
        ("summary-two-files-file-id-1", {"class": T, "file_id": 1, "mode": "summary"}, DEX_TWO),
        ("summary-max_lines-1", {"class": T, "mode": "summary", "max_lines": 1}, DEX),
        ("mode-bad", {"class": T, "mode": "components"}, DEX),
        ("and-method", {"class": T, "method": SWITCH, "mode": "context"}, DEX),
        ("and-method-idx", {"class": T, "method_idx": 7, "file_id": 0}, DEX),
        # a byte budget: the reference counts the serialized answer, this server the text; the answers are not compared
        ("budget-smali-4096", {"class": T, "mode": "smali", "method_offset": 8, "method_limit": 50, "max_bytes": 4096, "max_lines": 1000}, DEX),
        ("budget-summary-4096", {"class": T, "mode": "summary", "method_limit": 50, "max_bytes": 4096}, DEX),
    ]:
        cases.append(case("decode-class-" + name, inputs, "decode", arguments))
    # the context mode of single methods, with the other arguments that act on text
    for name, arguments in [
        ("context-offset-header", {"method": SWITCH, "mode": "context", "offset": 92}),
        ("context-offset-mid-line", {"method": SWITCH, "mode": "context", "offset": 100, "max_lines": 2}),
        ("context-max_lines-2", {"method": SWITCH, "mode": "context", "max_lines": 2}),
        ("context-max_lines-2-next", {"method": SWITCH, "mode": "context", "max_lines": 2, "offset": 163}),
        ("context-offset-total", {"method": SWITCH, "mode": "context", "offset": 329}),
        ("context-offset-past", {"method": SWITCH, "mode": "context", "offset": 330}),
        ("context-max_bytes-4096", {"method": TRY, "mode": "context", "max_bytes": 4096, "max_lines": 3}),
        ("context-by-index", {"file_id": 0, "method_idx": 240, "mode": "context"}),
        ("context-file-id", {"method": SWITCH, "mode": "context", "file_id": 0}),
        ("context-file-id-wrong", {"method": SWITCH, "mode": "context", "file_id": 1}),
        ("summary-by-index", {"file_id": 0, "method_idx": 240, "mode": "summary"}),
        ("summary-referenced-only", {"file_id": 0, "method_idx": 0, "mode": "summary"}),
        ("smali-method-offset-0", {"method": SWITCH, "method_offset": 0}),
        ("smali-method-limit-5", {"method": SWITCH, "method_limit": 5}),
    ]:
        cases.append(case("decode-method-" + name, DEX, "decode", arguments))
    return cases


def manifest_cases() -> list[dict]:
    cases = []
    for name, args in [
        ("default", {}), ("limit-1", {"limit": 1}), ("limit-200", {"limit": 200}), ("limit-0", {"limit": 0}), ("limit-201", {"limit": 201}),
        ("limit-negative", {"limit": -1}), ("limit-string", {"limit": "1"}), ("offset-1", {"offset": 1}), ("offset-3", {"offset": 3}),
        ("offset-4", {"offset": 4}), ("offset-99", {"offset": 99}), ("offset-negative", {"offset": -1}),
        ("limit-2-offset-1", {"limit": 2, "offset": 1}), ("max_bytes-0", {"max_bytes": 0}), ("max_bytes-10", {"max_bytes": 10}),
        ("max_bytes-4095", {"max_bytes": 4095}), ("max_bytes-4096", {"max_bytes": 4096}), ("max_bytes-131072", {"max_bytes": 131072}),
        ("max_bytes-131073", {"max_bytes": 131073}), ("timeout_ms-0", {"timeout_ms": 0}), ("timeout_ms-1", {"timeout_ms": 1}),
        ("timeout_ms-60000", {"timeout_ms": 60000}), ("timeout_ms-60001", {"timeout_ms": 60001}),
        ("input_index-0", {"input_index": 0}), ("input_index-1", {"input_index": 1}), ("input_index-negative", {"input_index": -1}),
        ("input_index-null", {"input_index": None}), ("mode-summary", {"mode": "summary"}), ("mode-xml", {"mode": "xml"}),
        ("mode-bad", {"mode": "components"}), ("mode-null", {"mode": None}), ("unknown-field", {"bogus": True}),
        ("xml-offset-10", {"mode": "xml", "offset": 10, "max_bytes": 4096}), ("xml-offset-huge", {"mode": "xml", "offset": 999999}),
        ("xml-offset-0-bytes-4096", {"mode": "xml", "max_bytes": 4096}), ("xml-limit", {"mode": "xml", "limit": 5}),
    ]:
        cases.append(case("manifest-" + name, APK, "get_manifest", args))
    cases += [
        case("manifest-no-manifest", NO_MANIFEST, "get_manifest", {}),
        case("manifest-no-manifest-xml", NO_MANIFEST, "get_manifest", {"mode": "xml"}),
        case("manifest-dex-only", DEX, "get_manifest", {}),
        case("manifest-dex-only-index-0", DEX, "get_manifest", {"input_index": 0}),
    ]
    return cases


def combination_cases() -> list[dict]:
    """Two things wrong at once: which one does the reference name? These freeze the order of its checks."""
    cases = []
    sw = {"method": SWITCH}
    for name, extra in [
        ("max_bytes-timeout", {"max_bytes": 0, "timeout_ms": 0}), ("timeout-max_bytes", {"timeout_ms": 0, "max_bytes": 0}),
        ("max_bytes-max_lines", {"max_bytes": 0, "max_lines": 0}), ("timeout-max_lines", {"timeout_ms": 0, "max_lines": 0}),
        ("max_lines-no-selector", {"method": None, "max_lines": 0}), ("max_bytes-no-selector", {"method": None, "max_bytes": 0}),
        ("timeout-no-selector", {"method": None, "timeout_ms": 0}),
        ("max_lines-unknown-method", {"method": T + "->nope()V", "max_lines": 0}),
        ("max_bytes-unknown-method", {"method": T + "->nope()V", "max_bytes": 0}),
        ("offset-huge-unknown-method", {"method": T + "->nope()V", "offset": 99999999}),
        ("method_offset-max_lines", {"method_offset": 1, "max_lines": 0}), ("method_limit-max_lines", {"method_limit": 0, "max_lines": 0}),
        ("method_offset-method_limit", {"method_offset": 1, "method_limit": 0}),
        ("method_limit-no-selector", {"method": None, "method_limit": 0}),
        ("method_offset-no-selector", {"method": None, "method_offset": 1}),
        ("summary-offset", {"mode": "summary", "offset": 5}), ("summary-offset-huge", {"mode": "summary", "offset": 999999}),
        ("summary-max_lines-0", {"mode": "summary", "max_lines": 0}), ("summary-max_bytes-0", {"mode": "summary", "max_bytes": 0}),
        ("summary-unknown-method", {"mode": "summary", "method": T + "->nope()V"}),
        ("idx-without-file-max_lines", {"method": None, "method_idx": 7, "max_lines": 0}),
        ("empty-method-max_lines", {"method": "", "max_lines": 0}),
        ("empty-method-offset", {"method": "", "offset": 5}),
        ("summary-offset-max_lines", {"mode": "summary", "offset": 5, "max_lines": 0}),
        ("summary-offset-method_offset", {"mode": "summary", "offset": 5, "method_offset": 1}),
        ("summary-offset-unknown-method", {"mode": "summary", "offset": 5, "method": T + "->nope()V"}),
        ("method_offset-unknown-method", {"method_offset": 1, "method": T + "->nope()V"}),
        ("method_limit-unknown-method", {"method_limit": 0, "method": T + "->nope()V"}),
        ("two-selectors-empty-method", {"method": "", "class": T}),
        ("idx-without-file-two-selectors", {"method_idx": 7, "class": T}),
        ("file_id-bad-with-method", {"file_id": 9}),
        ("file_id-bad-method-idx-valid-by-descriptor", {"file_id": 1, "method": SWITCH}),
        ("abstract-offset-1", {"method": ABSTRACT, "offset": 1}), ("abstract-offset-total", {"method": ABSTRACT, "offset": 53}),
        ("abstract-offset-54", {"method": ABSTRACT, "offset": 54}),
    ]:
        arguments = {**sw, **extra}
        cases.append(case("decode-combo-" + name, DEX, "decode", {k: v for k, v in arguments.items() if v is not None}))
    for name, extra in [
        ("unknown-dataset", {"dataset_id": "dataset-99"}), ("unknown-dataset-max_bytes", {"dataset_id": "dataset-99", "max_bytes": 0}),
        ("unknown-dataset-timeout", {"dataset_id": "dataset-99", "timeout_ms": 0}), ("unknown-dataset-max_lines", {"dataset_id": "dataset-99", "max_lines": 0}),
        ("unknown-dataset-no-selector", {"dataset_id": "dataset-99", "method": None}),
        ("unknown-dataset-unknown-field", {"dataset_id": "dataset-99", "bogus": 1}),
    ]:
        cases.append(case("decode-combo-" + name, DEX, "decode", {k: v for k, v in {**sw, **extra}.items() if v is not None}))
    for name, extra in [
        ("unknown-dataset-max_bytes", {"dataset_id": "dataset-99", "max_bytes": 0}), ("unknown-dataset-limit", {"dataset_id": "dataset-99", "limit": 0}),
        ("unknown-dataset-timeout", {"dataset_id": "dataset-99", "timeout_ms": 0}), ("unknown-dataset-offset", {"dataset_id": "dataset-99", "offset": 5}),
        ("limit-max_bytes", {"limit": 0, "max_bytes": 0}), ("max_bytes-limit", {"max_bytes": 0, "limit": 0}),
        ("limit-timeout", {"limit": 0, "timeout_ms": 0}), ("limit-offset-past", {"limit": 0, "offset": 99}),
        ("offset-past-max_bytes", {"offset": 99, "max_bytes": 0}), ("offset-past-timeout", {"offset": 99, "timeout_ms": 0}),
        ("input_index-limit", {"input_index": 1, "limit": 0}), ("input_index-max_bytes", {"input_index": 1, "max_bytes": 0}),
        ("input_index-offset-past", {"input_index": 1, "offset": 99}), ("xml-limit-0", {"mode": "xml", "limit": 0}),
        ("xml-max_bytes-0", {"mode": "xml", "max_bytes": 0}), ("xml-input_index-1", {"mode": "xml", "input_index": 1}),
        ("xml-offset-past", {"mode": "xml", "offset": 99}), ("xml-timeout-0", {"mode": "xml", "timeout_ms": 0}),
    ]:
        cases.append(case("manifest-combo-" + name, APK, "get_manifest", extra))
    cases.append(case("manifest-combo-unknown-dataset-no-manifest", NO_MANIFEST, "get_manifest", {"dataset_id": "dataset-99"}))
    return cases


def generic_cases() -> list[dict]:
    """The arguments of the other tools; `@name` stands for a fixture's path, no inputs means no dataset is opened first."""
    cases = []
    path = "@decode-all.dex"
    for name, tool, arguments in [
        ("open-missing-inputs", "open_dataset", {}), ("open-inputs-string", "open_dataset", {"inputs": path}),
        ("open-inputs-empty", "open_dataset", {"inputs": []}), ("open-inputs-missing-file", "open_dataset", {"inputs": ["@nope.dex"]}),
        ("open-unknown-field", "open_dataset", {"inputs": [path], "bogus": 1}), ("open-timeout-0", "open_dataset", {"inputs": [path], "timeout_ms": 0}),
        ("open-inputs-number", "open_dataset", {"inputs": [5]}), ("open-inputs-empty-string", "open_dataset", {"inputs": [""]}),
        ("open-timeout-60001", "open_dataset", {"inputs": [path], "timeout_ms": 60001}),
        ("list-unknown-field", "list_datasets", {"bogus": 1}), ("list-tables-unknown-field", "list_tables", {"bogus": 1}),
        ("close-missing-id", "close_dataset", {}), ("close-unknown-id", "close_dataset", {"dataset_id": "dataset-99"}),
        ("close-id-number", "close_dataset", {"dataset_id": 5}), ("close-unknown-field", "close_dataset", {"dataset_id": "dataset-99", "bogus": 1}),
        ("describe-missing-name", "describe_table", {}), ("describe-unknown-table", "describe_table", {"name": "nope"}),
        ("describe-unknown-field", "describe_table", {"name": "methods", "bogus": 1}), ("describe-name-number", "describe_table", {"name": 5}),
        ("describe-with-dataset", "describe_table", {"name": "methods", "dataset_id": "dataset-1"}),
    ]:
        cases.append(case("generic-" + name, [], tool, arguments))
    for name, arguments in [
        ("missing-sql", {}), ("sql-string", {"sql": "SELECT 1"}), ("sql-empty", {"sql": []}), ("sql-17", {"sql": ["SELECT 1"] * 17}),
        ("limit-0", {"sql": ["SELECT 1"], "limit": 0}), ("limit-1001", {"sql": ["SELECT 1"], "limit": 1001}),
        ("offset-limit-over", {"sql": ["SELECT 1"], "offset": 100000, "limit": 1}), ("max_bytes-0", {"sql": ["SELECT 1"], "max_bytes": 0}),
        ("timeout-0", {"sql": ["SELECT 1"], "timeout_ms": 0}), ("unknown-field", {"sql": ["SELECT 1"], "bogus": 1}),
        ("sql-number", {"sql": [1]}), ("limit-negative", {"sql": ["SELECT 1"], "limit": -1}), ("timing-string", {"sql": ["SELECT 1"], "timing": "yes"}),
        ("named-temp-bad", {"sql": ["SELECT 1"], "named_temp_queries": [{"name": "x"}]}),
    ]:
        cases.append(case("generic-query-" + name, DEX, "query", arguments))
    return cases


def all_cases() -> list[dict]:
    return decode_cases() + manifest_cases() + combination_cases() + generic_cases()


def concrete(value):
    """Replace `@name` strings by the fixture's absolute path."""
    if isinstance(value, str) and value.startswith("@"):
        return str(FIXTURES / value[1:])
    if isinstance(value, list):
        return [concrete(item) for item in value]
    if isinstance(value, dict):
        return {key: concrete(item) for key, item in value.items()}
    return value


VOLATILE = {"prepare_ms"}


def normalize(body, dataset: str | None):
    """The answer with the things that differ for no reason removed: the dataset id, the fixtures' directory, timings."""
    text = json.dumps(body, ensure_ascii=False)
    if dataset:
        text = text.replace(json.dumps(dataset)[1:-1], "DS")
    escaped = json.dumps(str(FIXTURES))[1:-1]
    # an error message that quotes the path has it escaped once already: twice in the JSON text
    text = text.replace(json.dumps(escaped)[1:-1], "<fixtures>").replace(escaped, "<fixtures>")

    def drop(node):
        if isinstance(node, dict):
            return {k: drop(v) for k, v in node.items() if k not in VOLATILE}
        if isinstance(node, list):
            return [drop(item) for item in node]
        return node

    return drop(json.loads(text))


def json_dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
