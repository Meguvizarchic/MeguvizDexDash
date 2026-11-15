#!/usr/bin/env python3
"""Replay the recorded reference sessions of the dataset lifecycle through the MCP server.

evidence/compatibility/0.1.0/mcp-records.json holds 195 JSON-RPC messages from the
reference engine (A0, dexsql 0.1.0): open_dataset, list_datasets, close_dataset, query on
TEMP definitions, the same dataset closed by a deadline, the identity of repeated inputs.
The 500-byte DEX files it used are not kept, so tiny_dex.py writes files with the content
the recording shows (class Ldemo/A; with foo()V, and a second DEX for the identity cases).

Each check names the recorded message it follows. A check compares what the recording
fixes (keys, kinds, messages, rows, counts) and masks what it cannot (dataset ids, paths,
timings, limits that are a server's own configuration). The declared differences are
listed in DECLARED_DIFFERENCES and are not hidden inside the masks.

Usage: python -I conformance/mcp/lifecycle_replay.py [--binary PATH] [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tiny_dex  # noqa: E402
from mcp_client import DEFAULT_BINARY, ROOT, McpClient  # noqa: E402

RECORDS = "evidence/compatibility/0.1.0/mcp-records.json"

# Fields this server adds to open_dataset beside the reference's six.
OPEN_EXTRAS = {"snapshot_id", "scope_id", "profile", "sql_dialect", "dex_count", "snapshot_manifest", "diagnostics"}

DECLARED_DIFFERENCES = [
    "The reference's `diagnostics` of a query carries sql_static_optimizer_rewrite notes; this server's is empty.",
    "The reference's column data_type is `sqlite_dynamic` for TEMP tables and expressions; this server derives uint64/int64/utf8 from the values.",
    "A dataset whose source file changed: the reference refuses decode (source_changed) and still answers SQL; this server reads one immutable snapshot for both and answers both.",
    "The reference's server_busy (a second request while one runs) cannot arise: this server answers one request at a time.",
    "A recursive CTE is the reference's way to run long; this server's SQL does not offer it, so the deadline is exercised with a cross join.",
    "Dataset identifiers are opaque here (dataset-<hex>); the reference counts dataset-1, dataset-2.",
    "limits values (max_datasets, max_output_bytes, timeout_ms, ...) are each server's own configuration; only their names are compared.",
]


class Report:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def add(self, name: str, recorded: list[int], equal: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "recorded_messages": recorded, "equal": bool(equal), "detail": detail})

    def not_run(self, name: str, recorded: list[int], reason: str) -> None:
        self.checks.append({"name": name, "recorded_messages": recorded, "equal": None, "not_run": reason})


def load_records() -> list[dict]:
    return json.loads((ROOT / RECORDS).read_text(encoding="utf-8"))


def recorded(records: list[dict], index: int) -> dict:
    message = records[index]["message"]
    return message["result"]["structuredContent"]


def type_shape(value):
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if value is None:
        return "null"
    if isinstance(value, list):
        return [type_shape(value[0])] if value else []
    return {key: type_shape(item) for key, item in sorted(value.items())}


def keys_of(value) -> list[str]:
    return sorted(value) if isinstance(value, dict) else []


def without_extras(opened: dict) -> dict:
    return {k: v for k, v in opened.items() if k not in OPEN_EXTRAS and k != "_is_error"}


def replace_id(value, ours: str, theirs: str = "dataset-1"):
    return json.loads(json.dumps(value).replace(json.dumps(ours)[1:-1], json.dumps(theirs)[1:-1]))


def tool_error(reply: dict) -> dict:
    return {k: v for k, v in reply.items() if k != "_is_error"}


without_flag = tool_error


def statement_view(statement: dict) -> dict:
    """What a recorded statement fixes. data_type and the optimizer notes are declared differences."""
    return {
        "kind": statement["kind"], "sql": statement["sql"], "statement_index": statement["statement_index"],
        "columns": [column["name"] for column in statement["columns"]], "rows": statement["rows"],
        "total_rows": statement["total_rows"], "truncated": statement["truncated"],
        "offset": statement["offset"], "next_offset": statement["next_offset"],
    }


def make_files(directory: Path) -> dict[str, Path]:
    files = {}
    for name, data in {
        "resident_cold.dex": tiny_dex.foo_a(), "pagination.dex": tiny_dex.foo_a(), "timeout.dex": tiny_dex.foo_a(),
        "quota_a.dex": tiny_dex.foo_a(), "quota_b.dex": tiny_dex.foo_a(),
        "identity_a.dex": tiny_dex.foo_a(), "identity_a_copy.dex": tiny_dex.foo_a(), "identity_b.dex": tiny_dex.bar_b(),
    }.items():
        path = directory / name
        path.write_bytes(data)
        files[name] = path
    return files


def check_open_and_close(report: Report, records: list[dict], binary: Path, files: dict[str, Path]) -> None:
    client = McpClient(binary)
    client.initialize()
    path = files["resident_cold.dex"]
    opened = client.call("open_dataset", inputs=[str(path)])
    id_ = opened["dataset_id"]
    reference = recorded(records, 6)
    ours = without_extras(opened)
    report.add("open_dataset answers with the reference's six fields", [6], keys_of(ours) == keys_of(reference),
               f"{keys_of(ours)} vs {keys_of(reference)}")
    report.add("open_dataset field types equal the recording's", [6], type_shape(ours) == type_shape(reference),
               f"{type_shape(ours)} vs {type_shape(reference)}")
    report.add("open_dataset values the recording fixes: has_dex, archive_inputs, the inputs echoed, the byte count",
               [6], ours["has_dex"] is True and ours["archive_inputs"] == reference["archive_inputs"] == []
               and ours["inputs"] == [str(path)] and ours["input_bytes"] == path.stat().st_size)
    report.add("open_dataset adds exactly the declared identity fields", [6],
               set(opened) - set(ours) - {"_is_error"} == OPEN_EXTRAS)
    closed = client.call("close_dataset", dataset_id=id_)
    expected = recorded(records, 14)
    report.add("close_dataset answers {closed, dataset_id} exactly", [14],
               tool_error(closed) == replace_id(expected, "dataset-1", id_), json.dumps(tool_error(closed)))
    client.close()


def check_quota_and_errors(report: Report, records: list[dict], binary: Path, files: dict[str, Path]) -> None:
    client = McpClient(binary, ["--max-datasets", "1"])
    client.initialize()
    a, b = files["quota_a.dex"], files["quota_b.dex"]
    first = client.call("open_dataset", inputs=[str(a)])
    first_id = first["dataset_id"]
    over = client.call("open_dataset", inputs=[str(b)])
    reference = recorded(records, 153)["error"]
    report.add("a dataset over the quota is refused with the reference's kind and message", [153],
               over["_is_error"] and over["error"]["kind"] == reference["kind"] and over["error"]["message"] == reference["message"],
               json.dumps(over["error"])[:200])
    listed = client.call("list_datasets")
    reference = recorded(records, 155)
    report.add("list_datasets has the reference's keys at every level", [155],
               sorted(k for k in listed if k != "_is_error") == keys_of(reference)
               and keys_of(listed["limits"]) == keys_of(reference["limits"])
               and keys_of(listed["usage"]) == keys_of(reference["usage"])
               and keys_of(listed["datasets"][0]) == keys_of(reference["datasets"][0]),
               f"{sorted(listed)}")
    report.add("list_datasets counts what is open, as the reference does", [155],
               listed["usage"] == {"datasets": 1, "input_bytes": a.stat().st_size}
               and listed["admitted_requests"] == 0 and listed["running_requests"] == 0
               and [d["dataset_id"] for d in listed["datasets"]] == [first_id]
               and listed["datasets"][0] == without_extras(first),
               json.dumps(listed["usage"]))
    closed = client.call("close_dataset", dataset_id=first_id)
    report.add("closing the first dataset", [157],
               tool_error(closed) == replace_id(recorded(records, 157), "dataset-1", first_id))
    not_open = client.call("query", dataset_id=first_id, sql=["SELECT 1"])
    expected = replace_id(recorded(records, 159), "dataset-1", first_id)
    report.add("a query on the closed handle is refused as unknown_dataset, in the reference's words", [159],
               not_open["_is_error"] and not_open["error"]["kind"] == expected["error"]["kind"]
               and not_open["error"]["message"] == expected["error"]["message"], json.dumps(not_open["error"])[:200])
    again = client.call("close_dataset", dataset_id=first_id)
    expected = replace_id(recorded(records, 161), "dataset-1", first_id)
    report.add("closing twice is refused as unknown_dataset, in the reference's words", [161],
               again["_is_error"] and again["error"]["kind"] == expected["error"]["kind"]
               and again["error"]["message"] == expected["error"]["message"], json.dumps(again["error"])[:200])
    reopened = client.call("open_dataset", inputs=[str(b)])
    report.add("a slot freed by closing can be opened again", [162, 163], not reopened["_is_error"]
               and keys_of(without_extras(reopened)) == keys_of(recorded(records, 163)))
    report.add("the second dataset closes", [165], not client.call("close_dataset", dataset_id=reopened["dataset_id"])["_is_error"])
    client.close()


TEMP_STEPS = [
    # (request index, sql list, limit, offset)
    (54, ["CREATE TEMP TABLE page_base AS SELECT 1 AS id,'before' AS tag UNION ALL SELECT 2,'before' UNION ALL SELECT 3,'before' UNION ALL SELECT 4,'before'"], None, None),
    (56, ["SELECT id,tag FROM page_base ORDER BY id"], 2, 0),
    (58, ["CREATE TEMP TABLE page_base AS SELECT 11 AS id,'after' AS tag UNION ALL SELECT 12,'after' UNION ALL SELECT 13,'after' UNION ALL SELECT 14,'after'"], None, None),
    (60, ["SELECT id,tag FROM page_base ORDER BY id"], 2, 2),
    (62, ["CREATE TEMP TABLE base AS SELECT 1 AS x", "CREATE TEMP TABLE derived AS SELECT x FROM base"], None, None),
    (64, ["SELECT x FROM derived"], None, None),
    (66, ["DROP TABLE base"], None, None),
    (68, ["SELECT x FROM derived"], None, None),
    (70, ["CREATE TEMP TABLE base AS SELECT 7 AS x"], None, None),
    (72, ["SELECT x FROM derived"], None, None),
    (74, ["DROP TABLE derived"], None, None),
    (76, ["SELECT x FROM derived"], None, None),
]


def check_temp_definitions(report: Report, records: list[dict], binary: Path, files: dict[str, Path]) -> None:
    client = McpClient(binary)
    client.initialize()
    opened = client.call("open_dataset", inputs=[str(files["pagination.dex"])])
    id_ = opened["dataset_id"]
    for request_index, sql, limit, offset in TEMP_STEPS:
        arguments = {"dataset_id": id_, "sql": sql}
        if limit is not None:
            arguments["limit"] = limit
            arguments["offset"] = offset
        reply = client.call("query", **arguments)
        expected = recorded(records, request_index + 1)
        label = f"TEMP step {request_index}: {sql[0][:48]}"
        if "error" in expected:
            good = (reply["_is_error"] and reply["error"]["kind"] == expected["error"]["kind"]
                    and reply["error"]["statement_index"] == expected["error"]["statement_index"])
            same_words = reply["error"]["message"] == expected["error"]["message"]
            report.add(label + " (refused: kind and statement index)", [request_index + 1], good,
                       "" if good else json.dumps(reply.get("error"))[:240])
            report.add(label + " (refused: the message, word for word)", [request_index + 1], good and same_words,
                       reply["error"]["message"] + " | " + expected["error"]["message"])
        else:
            ours = [statement_view(s) for s in reply["statements"]] if not reply["_is_error"] else reply
            theirs = [statement_view(s) for s in expected["statements"]]
            report.add(label + " (statements, cell types included)", [request_index + 1], ours == theirs,
                       "" if ours == theirs else f"{json.dumps(ours)[:300]} | {json.dumps(theirs)[:300]}")
    client.close()


def check_timeout(report: Report, records: list[dict], binary: Path, files: dict[str, Path]) -> None:
    client = McpClient(binary)
    client.initialize()
    opened = client.call("open_dataset", inputs=[str(files["timeout.dex"])])
    id_ = opened["dataset_id"]
    late = client.call("query", dataset_id=id_, timeout_ms=1,
                       sql=["SELECT a.type_idx FROM types a, types b, types c, types d, types e, types f"])
    expected = recorded(records, 176)
    error = late.get("error", {})
    report.add("a deadline closes the dataset and says so, in the reference's shape", [176],
               late["_is_error"] and late.get("dataset_id") == id_ and error.get("kind") == "timeout"
               and error.get("dataset_closed") is True and error.get("message") == expected["error"]["message"],
               json.dumps(late)[:300])
    listed = client.call("list_datasets")
    report.add("the dataset is gone from list_datasets after its deadline", [178],
               listed["datasets"] == [] and listed["usage"] == {"datasets": 0, "input_bytes": 0})
    report.not_run("a second request while one runs is refused as server_busy", [174, 175],
                   "requests are answered one at a time here; there is no second request to refuse")
    client.close()


def identity_expectation(records: list[dict], first: int, ours: dict[str, str], recorded_paths: dict[str, str]) -> list:
    rows = recorded(records, first)["statements"][0]["rows"]
    out = []
    for row in rows:
        path = row[1]["value"]
        out.append([row[0], {"type": "utf8", "value": ours[recorded_paths[path]]}, row[2]])
    return out


def check_identity(report: Report, records: list[dict], binary: Path, files: dict[str, Path], directory: Path) -> None:
    base = "/workspace/scratch/acc0e5058f47/research/desktop_v2/runs/baseline_010_final/"
    recorded_paths = {base + n: n for n in ("identity_a.dex", "identity_b.dex", "identity_a_copy.dex", "identity_a_link.dex")}
    link = directory / "identity_a_link.dex"
    linked = True
    try:
        link.symlink_to(files["identity_a.dex"])
    except (OSError, NotImplementedError):
        linked = False
    names = {n: str(p) for n, p in files.items()}
    if linked:
        names["identity_a_link.dex"] = str(link)
    scenarios = [
        ("a_then_b", ["identity_a.dex", "identity_b.dex"], 86),
        ("b_then_a", ["identity_b.dex", "identity_a.dex"], 98),
        ("same_path_twice", ["identity_a.dex", "identity_a.dex"], 110),
        ("same_content_two_paths", ["identity_a.dex", "identity_a_copy.dex"], 122),
        ("path_plus_symlink", ["identity_a.dex", "identity_a_link.dex"], 134),
    ]
    identities = "SELECT d.file_id,d.source_path,c.descriptor FROM dex_files d JOIN classes c ON d.file_id=c.file_id ORDER BY d.file_id,c.descriptor"
    counts = "SELECT count(*),count(DISTINCT descriptor),count(method_kind) FROM methods"
    for name, order, open_response in scenarios:
        if name == "path_plus_symlink" and not linked:
            report.not_run(name, [open_response], "this account cannot create a symbolic link here")
            continue
        client = McpClient(binary)
        client.initialize()
        opened = client.call("open_dataset", inputs=[names[n] for n in order])
        id_ = opened["dataset_id"]
        reference = recorded(records, open_response)
        report.add(f"{name}: open_dataset counts both inputs' bytes and echoes both paths", [open_response],
                   opened["inputs"] == [names[n] for n in order] and keys_of(without_extras(opened)) == keys_of(reference)
                   and opened["input_bytes"] == sum(Path(names[n]).stat().st_size for n in order))
        got = client.call("query", dataset_id=id_, sql=[identities, counts])
        expected_rows = identity_expectation(records, open_response + 2, names, recorded_paths)
        report.add(f"{name}: each input keeps its own file_id, in the order given", [open_response + 2],
                   [statement["rows"] for statement in got["statements"][:1]] == [expected_rows],
                   json.dumps(got["statements"][0]["rows"])[:300])
        theirs = recorded(records, open_response + 4)["statements"][0]["rows"]
        report.add(f"{name}: methods count(*), count(DISTINCT descriptor), count(method_kind), cell types included",
                   [open_response + 4], got["statements"][1]["rows"] == theirs,
                   f"{got['statements'][1]['rows']} vs {theirs}")
        by_descriptor = client.call("decode", dataset_id=id_, method="Ldemo/A;->foo()V")
        expected = replace_id(recorded(records, open_response + 6), reference["dataset_id"], id_)
        if "error" in expected:
            ours = {"dataset_id": by_descriptor.get("dataset_id"), "error": {
                key: by_descriptor["error"].get(key) for key in expected["error"]}}
            report.add(f"{name}: decode by descriptor is refused as ambiguous, naming the DEX files, in the reference's shape",
                       [open_response + 6], by_descriptor["_is_error"] and ours == expected, json.dumps(ours)[:300])
        else:
            report.add(f"{name}: decode by descriptor answers exactly as the reference did (file_id, text, byte and line counts)",
                       [open_response + 6], without_flag(by_descriptor) == expected,
                       json.dumps(without_flag(by_descriptor))[:200])
        file_id = recorded(records, open_response + 8)["methods"][0]["file_id"]
        by_key = client.call("decode", dataset_id=id_, file_id=file_id, method_idx=0)
        expected = replace_id(recorded(records, open_response + 8), reference["dataset_id"], id_)
        report.add(f"{name}: decode by file_id and method_idx answers exactly as the reference did",
                   [open_response + 8], without_flag(by_key) == expected, json.dumps(without_flag(by_key))[:200])
        client.close()


def check_resident_source(report: Report, records: list[dict], binary: Path, files: dict[str, Path]) -> None:
    """rec 38-46: a dataset whose source file is deleted still answers; rec 10-12: one whose file changed."""
    path = files["resident_cold.dex"]
    original = path.read_bytes()
    client = McpClient(binary)
    client.initialize()
    opened = client.call("open_dataset", inputs=[str(path)])
    id_ = opened["dataset_id"]
    rows = client.call("query", dataset_id=id_, sql=["SELECT value,count(*) FROM method_strings GROUP BY value ORDER BY value"])
    theirs = recorded(records, 8)["statements"][0]["rows"]
    report.add("method_strings: the one string 'needle' is used twice, cell types included", [8],
               rows["statements"][0]["rows"] == theirs, json.dumps(rows["statements"][0]["rows"]))
    # same size, still a valid DEX: change the literal's text, then repair the checksum and signature
    changed = bytearray(original)
    at = bytes(changed).index(b"needle")
    changed[at:at + 6] = b"noodle"
    import hashlib, struct, zlib
    changed[12:32] = hashlib.sha1(bytes(changed[32:])).digest()
    struct.pack_into("<I", changed, 8, zlib.adler32(bytes(changed[12:])) & 0xFFFFFFFF)
    path.write_bytes(bytes(changed))
    after = client.call("decode", dataset_id=id_, method="Ldemo/A;->foo()V")
    still = (not after["_is_error"]) and '"needle"' in after["methods"][0]["smali"] and '"noodle"' not in after["methods"][0]["smali"]
    report.add("DECLARED DIFFERENCE: after the source file changed, decode still answers from the snapshot "
               "(the reference refuses decode with source_changed and keeps answering SQL)", [12], still,
               json.dumps(after)[:200])
    sql_after = client.call("query", dataset_id=id_, sql=["SELECT value,count(*) FROM method_strings GROUP BY value ORDER BY value"])
    report.add("after the source file changed, SQL and decode read the same snapshot", [9, 12],
               sql_after["statements"][0]["rows"] == theirs and still)
    path.unlink()
    gone = client.call("decode", dataset_id=id_, method="Ldemo/A;->foo()V")
    expected = replace_id(recorded(records, 44), "dataset-5", id_)
    report.add("decode after the source file was deleted answers exactly as the reference did", [44],
               without_flag(gone) == expected, json.dumps(without_flag(gone))[:200])
    client.close()
    path.write_bytes(original)


def run(binary: Path) -> dict:
    records = load_records()
    report = Report()
    directory = Path(tempfile.mkdtemp(prefix="mdd-lifecycle-"))
    try:
        files = make_files(directory)
        check_open_and_close(report, records, binary, files)
        check_quota_and_errors(report, records, binary, files)
        check_temp_definitions(report, records, binary, files)
        check_timeout(report, records, binary, files)
        check_resident_source(report, records, binary, files)
        check_identity(report, records, binary, files, directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    failed = [c for c in report.checks if c["equal"] is False]
    return {
        "recording": RECORDS, "recorded_messages": len(records),
        "checks": report.checks,
        "passed": sum(1 for c in report.checks if c["equal"] is True),
        "failed": len(failed), "not_run": sum(1 for c in report.checks if c["equal"] is None),
        "declared_differences": DECLARED_DIFFERENCES,
        "equal": not failed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = run(args.binary)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"checks={len(result['checks'])} passed={result['passed']} failed={result['failed']} "
          f"not_run={result['not_run']} equal={result['equal']}")
    for check in result["checks"]:
        if check["equal"] is False:
            print("FAIL", check["name"], check["recorded_messages"], check.get("detail", "")[:400])
        elif check["equal"] is None:
            print("NOT RUN", check["name"], check.get("not_run", ""))
    return 0 if result["equal"] else 1


if __name__ == "__main__":
    sys.exit(main())
