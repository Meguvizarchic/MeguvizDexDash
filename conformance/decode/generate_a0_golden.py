#!/usr/bin/env python3
"""Freeze the reference engine's answers to the requests in a0_cases.py.

The reference (dexsql 0.1.0, https://github.com/LSPosed/dexsql-release, release v0.1.0) is a
closed-source binary. It is not kept in this repository; this script takes its path, refuses a
file whose sha256 is not the one the project pins (f354ebcf...c448), starts it as its own MCP
server, and writes what it answered to conformance/decode/a0-golden.json. The replay
(a0_replay.py) needs no binary: it compares this server with the frozen answers.

Usage: python -I conformance/decode/generate_a0_golden.py --a0 PATH_TO_dexsql-windows-amd64.exe
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "conformance" / "mcp"))
import a0_cases  # noqa: E402
from mcp_client import McpClient  # noqa: E402

METHODS_QUERY = "SELECT file_id, method_idx, descriptor FROM methods ORDER BY file_id, method_idx"


def cell(value):
    return value["value"] if isinstance(value, dict) and "value" in value else value


def ask(client: McpClient, dataset: str | None, tool: str, arguments: dict) -> dict:
    """The answer, JSON-RPC error or tool result, with the dataset id replaced by DS."""
    sent = a0_cases.concrete(arguments)
    if dataset is not None:
        sent = {"dataset_id": dataset, **sent}
    response = client.request("tools/call", {"name": tool, "arguments": sent})
    if "error" in response:
        return {"jsonrpc_error": a0_cases.normalize(response["error"], dataset)}
    result = response["result"]
    structured = result.get("structuredContent")
    if structured is None:
        body = {"raw_text": result["content"][0]["text"]}
        if set(result) - {"content", "isError"}:
            raise RuntimeError("an unexpected result shape: " + json.dumps(result)[:200])
    else:
        if json.loads(result["content"][0]["text"]) != structured:
            raise RuntimeError("the text content and the structured content differ")
        body = a0_cases.normalize(structured, dataset)
    return {"is_error": bool(result.get("isError")), "reply": body}


def open_session(binary: Path, inputs: list[str]) -> tuple[McpClient, str | None]:
    client = McpClient(binary)
    client.initialize()
    if not inputs:
        return client, None
    opened = client.call("open_dataset", inputs=[str(a0_cases.FIXTURES / name) for name in inputs])
    if opened["_is_error"]:
        raise RuntimeError(f"the reference refused {inputs}: {json.dumps(opened)[:300]}")
    return client, opened["dataset_id"]


def resolve_index(client: McpClient, dataset: str, descriptor: str) -> int:
    sql = f"SELECT method_idx FROM methods WHERE descriptor = '{descriptor}' ORDER BY file_id LIMIT 1"
    reply = client.call("query", dataset_id=dataset, sql=[sql])
    rows = reply["statements"][0]["rows"]
    if not rows:
        raise RuntimeError(f"the reference has no method {descriptor}")
    return int(cell(rows[0][0]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--a0", required=True, type=Path)
    parser.add_argument("--out", type=Path, default=a0_cases.GOLDEN)
    options = parser.parse_args()
    binary = options.a0.resolve()
    digest = a0_cases.sha256(binary)
    if digest != a0_cases.A0_SHA256:
        print(f"refused: {binary} has sha256 {digest}, not the pinned {a0_cases.A0_SHA256}", file=sys.stderr)
        return 2

    cases = []
    for template in a0_cases.all_cases():
        client, dataset = open_session(binary, template["inputs"])
        try:
            arguments = dict(template["arguments"])
            if "resolve" in template:
                arguments[template["resolve"]["into"]] = resolve_index(client, dataset, template["resolve"]["descriptor"])
            answer = ask(client, dataset, template["tool"], arguments)
        finally:
            client.close()
        cases.append({"id": template["id"], "inputs": template["inputs"], "tool": template["tool"],
                      "arguments": arguments, **answer})

    methods = []
    for inputs in (["decode-all.dex", "decode-v035.dex"], ["decode-bad-invoke.dex"]):
        client, dataset = open_session(binary, inputs)
        try:
            listing = client.call("query", dataset_id=dataset, limit=1000, sql=[METHODS_QUERY])
            for row in listing["statements"][0]["rows"]:
                file_id, method_idx, descriptor = int(cell(row[0])), int(cell(row[1])), cell(row[2])
                answer = ask(client, dataset, "decode", {"file_id": file_id, "method_idx": method_idx, "max_lines": 1000})
                context = ask(client, dataset, "decode", {"file_id": file_id, "method_idx": method_idx, "mode": "context", "max_lines": 1000})
                methods.append({"inputs": inputs, "file_id": file_id, "method_idx": method_idx, "descriptor": descriptor, **answer, "context": context})
        finally:
            client.close()

    golden = {
        "schema": 1,
        "reference": {"name": "dexsql", "version": "0.1.0", "sha256": digest, "origin": a0_cases.A0_ORIGIN,
                      "platform": "windows_amd64"},
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fixtures_sha256": {name: a0_cases.sha256(a0_cases.FIXTURES / name) for name in sorted(
            {n for c in cases for n in c["inputs"]} | {"decode-bad-invoke.dex", "decode-v035.dex"})},
        "cases": cases,
        "methods": methods,
    }
    options.out.write_text(a0_cases.json_dump(golden), encoding="utf-8", newline="\n")
    errors = sum(1 for c in cases if c.get("is_error"))
    print(f"wrote {options.out}: {len(cases)} cases ({errors} tool errors), {len(methods)} methods")
    return 0


if __name__ == "__main__":
    sys.exit(main())
