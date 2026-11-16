#!/usr/bin/env python3
"""Put the requests HostLab sends (hostlab-required-tools.json) to the server and check the answers.

For every call: the tool is registered, every argument is in its published input schema, the answer is
not an error, and every field HostLab reads is there. A decode continuation is followed to its end and
the joined pages must equal the single page. The two errors HostLab branches on are checked too.

Usage: python -I conformance/mcp/check_hostlab_required_tools.py [--binary PATH] [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from mcp_client import DEFAULT_BINARY, McpClient, McpError  # noqa: E402

MANIFEST = HERE / "hostlab-required-tools.json"


def fetch(value, path: str):
    """The value at a path such as `statements[0].rows[][].value`; `[]` means every element. Missing -> KeyError."""
    nodes = [value]
    for part in re.findall(r"[^.\[\]]+|\[\d*\]", path):
        step = []
        for node in nodes:
            if part == "[]":
                if not isinstance(node, list):
                    raise KeyError(path)
                step.extend(node)
            elif part.startswith("["):
                step.append(node[int(part[1:-1])])
            else:
                if not isinstance(node, dict) or part not in node:
                    raise KeyError(path)
                step.append(node[part])
        nodes = step
    return nodes


def run(binary: Path, manifest_path: Path = MANIFEST) -> list[dict]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    paths = {name: str(ROOT / relative) for name, relative in manifest["fixtures"].items()}
    results: list[dict] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        results.append({"name": name, "ok": bool(ok), "detail": detail if not ok else ""})

    client = McpClient(binary)
    client.initialize()
    tools = {tool["name"]: tool for tool in client.tools()}
    record("every tool HostLab calls is registered", all(call["tool"] in tools for call in manifest["calls"]),
           str(sorted({c["tool"] for c in manifest["calls"]} - set(tools))))
    record("the tools HostLab does not need and the server lacks are not listed",
           not (set(manifest["discovery"]["not_registered"]) & set(tools)), str(set(manifest["discovery"]["not_registered"]) & set(tools)))

    datasets: dict[str, str] = {}
    for call in manifest["calls"]:
        if call["tool"] not in tools:
            record(f"{call['id']}: the tool {call['tool']} is registered", False, "not in tools/list")
            continue
        schema = tools[call["tool"]]["inputSchema"]
        arguments = json.loads(json.dumps(call["arguments"]))
        if "inputs" in arguments:
            arguments["inputs"] = [paths[item[1:]] if isinstance(item, str) and item.startswith("@") else item for item in arguments["inputs"]]
        known = set(schema.get("properties", {}))
        unknown = sorted(set(arguments) - known)
        needs_dataset = "dataset_id" in schema.get("properties", {})
        if needs_dataset:
            fixture = call["fixture"]
            if fixture not in datasets:
                opened = client.call("open_dataset", inputs=[paths[fixture]])
                datasets[fixture] = opened["dataset_id"]
            arguments["dataset_id"] = datasets[fixture]
        missing = sorted(set(schema.get("required", [])) - set(arguments))
        record(f"{call['id']}: every argument is in the published schema and every required one is given", not unknown and not missing,
               f"unknown {unknown} missing {missing}")
        if call["tool"] == "close_dataset":
            arguments = {"dataset_id": datasets[call["fixture"]]}
        try:
            reply = client.call(call["tool"], **arguments)
        except McpError as error:
            record(f"{call['id']}: answered, not refused", False, f"a protocol error: {error}")
            continue
        record(f"{call['id']}: answered, not refused", not reply["_is_error"], json.dumps(reply)[:300])
        if reply["_is_error"]:
            continue
        for path in call["reads"]:
            try:
                fetch(reply, path)
                record(f"{call['id']}: the answer has `{path}`", True)
            except (KeyError, IndexError):
                record(f"{call['id']}: the answer has `{path}`", False, json.dumps(reply)[:300])
        if "expect_columns" in call:
            columns = [c["name"] for c in reply["statements"][0]["columns"]]
            record(f"{call['id']}: the columns are {call['expect_columns']}", columns == call["expect_columns"], str(columns))
        if call.get("follow_next_offset"):
            joined, page, offset = "", reply, call["arguments"].get("offset", 0)
            for _ in range(1000):
                method = page["methods"][0]
                joined += method["smali"]
                cursor = method["next_offset"]
                if cursor is None:
                    break
                if cursor <= offset:
                    record(f"{call['id']}: the continuation makes progress", False, f"{cursor} <= {offset}")
                    break
                offset = cursor
                page = client.call("decode", **{**arguments, "offset": offset})
                if page["_is_error"]:
                    record(f"{call['id']}: a page of the continuation is answered", False, json.dumps(page)[:300])
                    break
            whole = client.call("decode", **{**arguments, "offset": 0, "max_lines": 1000})["methods"][0]["smali"]
            record(f"{call['id']}: the pages joined equal the one page, and the walk ends with null", joined == whole and whole.endswith("\n"),
                   f"{len(joined)} vs {len(whole)} bytes")

    dataset = client.call("open_dataset", inputs=[paths["dex"]])["dataset_id"]  # the first one was closed by the `close` call
    refused = client.call("query", dataset_id=dataset, sql=["SELECT * FROM no_such_table"])
    record("a rejected statement says error.kind invalid_query and does not close the dataset",
           refused["_is_error"] and refused["error"]["kind"] == "invalid_query" and not refused["error"].get("dataset_closed"),
           json.dumps(refused)[:300])
    still = client.call("query", dataset_id=dataset, sql=["SELECT 1"])
    record("the dataset still answers after a rejected statement", not still["_is_error"], json.dumps(still)[:200])
    closed = client.call("close_dataset", dataset_id=datasets["apk"])
    record("closing the second dataset answers closed", closed.get("closed") is True, json.dumps(closed)[:200])
    gone = client.call("decode", dataset_id=datasets["apk"], method="Ldecode/T;->switch_packed()V")
    record("a closed dataset is refused as unknown_dataset", gone["_is_error"] and gone["error"]["kind"] == "unknown_dataset", json.dumps(gone)[:200])
    client.close()
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--out", type=Path)
    options = parser.parse_args()
    results = run(options.binary)
    failed = [r for r in results if not r["ok"]]
    for r in failed:
        print("FAIL", r["name"], "|", r["detail"])
    print(f"hostlab required tools: {len(results) - len(failed)}/{len(results)} checks passed")
    if options.out:
        options.out.write_text(json.dumps({"checks": results}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
