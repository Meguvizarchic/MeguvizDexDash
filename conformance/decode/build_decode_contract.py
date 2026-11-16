#!/usr/bin/env python3
"""Write (or check) conformance/mcp/decode-full-contract.json: the public contract of the complete `decode` tool.

The contract has two parts. The rules (arguments, units, modes, paging, errors, what is not a fact) are written in this
script; they are the contract. The cases are requests put to the real server on the fixtures and the answers it gave,
with the dataset id and the fixture directory replaced; run_decode_full.py checks the same server against independent
readings of the bytes, and --check here fails when the server's answers are no longer the recorded ones, so a change
of the contract is a visible change of this file.

Usage: python -I conformance/decode/build_decode_contract.py [--binary PATH] [--check]
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
import a0_replay  # noqa: E402
import run_decode_full as full  # noqa: E402
from mcp_client import DEFAULT_BINARY, McpClient, McpError  # noqa: E402

OUT = ROOT / "conformance" / "mcp" / "decode-full-contract.json"
T = "Ldecode/T;"
K = "Ldecode/K;"

RULES = {
    "schema_version": "mdd.decode-full-contract.v1",
    "tool": "decode",
    "about": "The public contract of the decode tool as MDD-071 completes it: what a request may say, in which unit each number is, what each "
             "mode shows, how pages end, which refusals exist, and what a text is not. The published input and output schemas are the reference's "
             "(conformance/manifests/tools-and-options.json) and are unchanged; everything this file adds is an additional key of an answer.",
    "text_formats": {
        "smali": {"id": full.SMALI_FORMAT, "specification": "crates/mdd-facts/src/smali/mod.rs",
                  "contains": ["method line and flags", "registers line", "parameter names (.param) with their annotation blocks",
                               "method annotation blocks", "labels, exception table lines and instructions", "payload tables",
                               "debug directives: .prologue .epilogue .line .local .end local .restart local .source",
                               "class text: .class .super .source .implements, class annotations, fields with static values and field annotations"],
        },
        "context": {"id": full.CONTEXT_FORMAT, "specification": "crates/mdd-facts/src/smali/context.rs",
                    "contains": ["a header line", "'line N: ' and the original line for the method line, register line, labels and exception-table lines "
                                 "(class text: class, super, source, implements and field lines)"]},
        "versioning": "A change to what a text says or how it is written changes its id. A change to the facts it is built from does not. "
                      "mdd.smali.v1 is the first id the engine names: the text MDD-042 wrote was its instruction subset.",
        "answer_key": "`text_format` of the answer: the id of the text the mode shows, null for summary.",
    },
    "units": {
        "byte offset": "UTF-8 bytes of ONE rendered text: offset, next_offset, total_bytes, max_bytes (and the class page's text budget)",
        "line number": "lines of ONE rendered text: start_line, end_line, total_lines, max_lines; the `line N:` numbers of a context count lines of the FULL text "
                       "and the context row names that count as source_total_lines",
        "method offset": "methods of ONE class in method_idx order: method_offset, method_limit, next_method_offset, total_methods",
        "code-unit address": "16-bit units of one code item: only in label names (:goto_1f is address 0x1f) and in code_units; never an offset or a line number",
        "rule": "No number of one unit is ever accepted or returned as another. A context's offsets page the context; the full text's offsets page the full text.",
    },
    "selectors": {
        "exactly one of": ["method (exact descriptor)", "method_idx (with file_id)", "class (exact descriptor)"],
        "file_id": "names the DEX file of a method, or of a class when several files define it",
        "ambiguity": "a descriptor defined in several DEX files names none of them: kind `ambiguous`, supply file_id; the first one is never picked",
        "only referred to": "a method or class that the DEX refers to but does not define is `not_found`",
    },
    "arguments": {
        "mode": {"values": ["summary", "smali", "context"], "default": "summary for class, smali for method"},
        "offset": {"unit": "byte offset", "default": 0, "applies_to": "ONE method's text (smali or context); refused with a class selector (kind invalid_argument, "
                   "the text of a class page continues on its method with file_id and method_idx) and with summary"},
        "max_lines": {"unit": "lines", "default": 200, "range": [1, 1000], "outside": "protocol error (-32602)"},
        "max_bytes": {"unit": "bytes", "default": None, "applies_to": "text modes: the UTF-8 bytes of the text of the page (a method page: its text; a class page: ONE budget for "
                      "all its methods' texts). summary mode of a class: the serialized bytes of the rows. 0 or a budget no character fits in is invalid_input.",
                      "difference": "the reference counts the serialized answer and accepts only 4096..131072"},
        "method_offset": {"unit": "method offset", "default": 0, "applies_to": "a class selector; refused for a method (invalid_argument); past total_methods is invalid_range, "
                          "equal to total_methods is an empty last page"},
        "method_limit": {"unit": "methods", "default": 20, "range": [1, 50], "outside": "protocol error (-32602)"},
        "timeout_ms": {"default": "the server's", "range": ">= 1, at most the server's", "on expiry": "deadline_exceeded and the dataset is closed"},
    },
    "answer": {
        "top level": ["dataset_id", "mode", "text_format", "total_methods", "method_offset", "next_method_offset", "methods", "class (class selector only)"],
        "next_method_offset": "null on the last page, else method_offset + the number of methods shown; a method whose text the budget cut counts as shown",
        "method row": {
            "always": ["file_id", "method_idx", "descriptor", "access_flags", "registers", "code_units", "try_count", "next_offset"],
            "summary": "no text keys; registers, code_units and try_count are null for a method without a body (abstract, native), never 0",
            "text modes": ["declaration", "smali", "offset", "next_offset", "start_line", "end_line", "total_lines", "total_bytes", "starts_mid_line", "ends_mid_line"],
            "context only": ["source_total_lines"],
            "omitted": "present only when the text leaves something out: debug_events_not_at_an_instruction, positions_not_source_lines, "
                       "parameter_annotation_slots_unplaced, annotation_layer_missing. What a text leaves out is never silent.",
            "continuation": "next_offset null: the text ends with this page. Otherwise decode the same method (file_id and method_idx) with offset = next_offset.",
        },
        "class object": {
            "always": ["descriptor", "file_id", "class_def_idx", "access_flags", "superclass", "source_file", "interfaces", "static_fields", "instance_fields"],
            "text modes, first page of methods (method_offset 0)": ["declaration", "smali", "end_line", "total_lines", "total_bytes", "truncated"],
            "truncated": "the class text is one page of max_lines lines and is not continued (offset belongs to a method): true says the text has more lines than were shown; "
                         "the fields and annotations are also rows of the SQL relations",
        },
    },
    "errors": [
        {"when": "no selector, two selectors, method_idx without file_id, an empty descriptor, an offset with a class, method_offset with a method, an offset with summary",
         "kind": "invalid_argument", "code": "INVALID_ARGUMENT"},
        {"when": "a method or class that is not defined (or a file_id that is not in the dataset)", "kind": "not_found", "echo": ["file_id", "method_idx"]},
        {"when": "a descriptor defined in several DEX files and no file_id", "kind": "ambiguous", "code": "AMBIGUOUS_ENTITY"},
        {"when": "offset or method_offset past the end, offset inside a character", "kind": "invalid_range"},
        {"when": "max_bytes that no character fits in", "kind": "invalid_input"},
        {"when": "the serialized answer is over the server's max_result_bytes", "kind": "quota_exceeded", "code": "QUOTA_EXCEEDED",
         "details": ["budget", "limit", "observed"], "rule": "refused whole, never clipped"},
        {"when": "the deadline passes", "kind": "timeout", "code": "DEADLINE_EXCEEDED", "dataset_closed": True},
        {"when": "an argument of the wrong type, an unknown argument, max_lines or method_limit out of range", "jsonrpc_error": -32602},
    ],
    "not_facts": [
        "A smali text never replaces the raw code bytes or their fingerprint: the HostLab method fingerprint is taken from the raw instruction bytes, not from this text.",
        "The text is a display of validated facts; it is not a decompilation and states no call target, type or value that the bytes do not.",
        "A float is shown as its shortest reading; a NaN does not keep its payload. The exact bits are the annotation facts.",
        "A method handle is shown as method_handle_<index>; its target is a fact of the method-handle table, not text.",
        "A debug position that is not a source line (a pc-to-pc surrogate, a non-positive line) is not written as .line.",
    ],
    "reference_differences": None,
}

CASES = [
    ("class-default", "decode-all.dex", {"class": T}),
    ("class-page-2", "decode-all.dex", {"class": T, "method_offset": 3, "method_limit": 2}),
    ("class-last-page-summary", "decode-all.dex", {"class": T, "method_offset": 236, "method_limit": 50}),
    ("class-empty-last-page", "decode-all.dex", {"class": T, "method_offset": 238}),
    ("class-smali-lines-cut", "decode-all.dex", {"class": T, "mode": "smali", "method_offset": 10, "method_limit": 3, "max_lines": 4}),
    ("class-smali-byte-budget", "decode-all.dex", {"class": T, "mode": "smali", "method_offset": 8, "method_limit": 50, "max_lines": 1000, "max_bytes": 700}),
    ("class-context-try-and-switch", "decode-all.dex", {"class": T, "mode": "context", "method_offset": 232, "method_limit": 4}),
    ("class-ambiguous", "both", {"class": T}),
    ("class-with-file-id", "both", {"class": T, "file_id": 1, "mode": "summary"}),
    ("class-text-offset-refused", "decode-all.dex", {"class": T, "offset": 5}),
    ("class-method-offset-past", "decode-all.dex", {"class": T, "method_offset": 239}),
    ("class-not-found", "decode-all.dex", {"class": "Lnope/N;"}),
    ("method-smali", "decode-all.dex", {"method": T + "->switch_packed()V"}),
    ("method-smali-second-page", "decode-all.dex", {"method": T + "->switch_packed()V", "max_lines": 5, "offset": 59}),
    ("method-context", "decode-all.dex", {"method": T + "->switch_packed()V", "mode": "context"}),
    ("method-context-second-page", "decode-all.dex", {"method": T + "->try_catch()V", "mode": "context", "max_lines": 3, "offset": 177}),
    ("method-summary", "decode-all.dex", {"method": T + "->try_catch()V", "mode": "summary"}),
    ("method-without-body", "decode-all.dex", {"method": T + "->abstract_one(I)I"}),
    ("method-non-ascii-name-cut-by-bytes", "decode-all.dex", {"method": T + "->é中()V", "max_bytes": 20}),
    ("class-with-annotations-fields-and-statics", "decode-class.dex", {"class": K, "mode": "smali", "max_lines": 1000}),
    ("class-context-view", "decode-class.dex", {"class": K, "mode": "context", "max_lines": 1000, "method_limit": 1}),
    ("interface-with-constant", "decode-class.dex", {"class": "Ldecode/Marker;", "mode": "smali"}),
    ("method-with-debug-info", "decode-class.dex", {"method": K + "->f(IJLjava/lang/String;)V"}),
    ("method-with-r8-debug-info", "decode-class.dex", {"method": K + "->r8()V"}),
    ("method-with-annotations", "decode-class.dex", {"method": K + "->g(I)V"}),
    ("annotation-values-of-every-kind", "annotations-038.dex", {"class": "Lfixture/A;", "mode": "smali", "max_lines": 1000, "method_limit": 1}),
]


def normalized(body, dataset: str) -> object:
    text = json.dumps(body, ensure_ascii=False).replace(json.dumps(dataset)[1:-1], "DS")
    return json.loads(text)


def collect(binary: Path) -> dict:
    client = McpClient(binary)
    client.initialize()
    datasets: dict[str, str] = {}
    try:
        for name, path in full.FIXTURES.items():
            datasets[name] = client.call("open_dataset", inputs=[str(path)])["dataset_id"]
        datasets["both"] = client.call("open_dataset", inputs=[str(full.FIXTURES["decode-all.dex"]), str(full.FIXTURES["decode-v035.dex"])])["dataset_id"]
        cases = []
        for case_id, fixture, request in CASES:
            dataset = datasets[fixture]
            try:
                answer = client.call("decode", dataset_id=dataset, **request)
                result = {"is_error": answer.pop("_is_error"), "reply": normalized(answer, dataset)}
            except McpError as error:
                result = {"jsonrpc_error": error.error}
            cases.append({"id": case_id, "fixture": fixture, "request": request, **result})
    finally:
        client.close()
    return {"cases": cases}


def contract(binary: Path) -> dict:
    rules = json.loads(json.dumps(RULES))
    rules["reference_differences"] = [{"class": name, "why": why} for name, why in a0_replay.DECLARED]
    rules["fixtures_sha256"] = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(full.FIXTURES.items())}
    rules["hand_written_texts"] = {"file": "conformance/decode/hand-expected-class.txt", "entries": len(full.read_hand())}
    rules["checked_by"] = ["conformance/decode/run_decode_full.py", "conformance/decode/a0_replay.py", "crates/mdd-cli/tests/mcp.rs"]
    rules.update(collect(binary))
    return rules


def render(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args()
    text = render(contract(options.binary))
    if options.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        print("decode-full-contract.json is current" if current == text else "decode-full-contract.json is stale: run build_decode_contract.py")
        return 0 if current == text else 1
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(CASES)} cases, {len(text)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
