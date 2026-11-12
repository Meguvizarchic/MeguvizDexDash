#!/usr/bin/env python3
"""Record frozen-A0 results for every variant in required-variants.json.

Usage: python -I generate_golden.py A0_EXE REPO_ROOT OUTPUT_JSON

The A0 backend (dexsql 0.1.0) is driven through its own `mcp` stdio server, so
the result windows (offset / next_offset / truncated / total_rows) are the
reference engine's own, not a reconstruction. Cells are recorded in one canonical
form that does not depend on JSON number handling:

    N                 SQL NULL
    i:<decimal>       any integer storage class (int64 / uint64)
    f:<16 hex>        IEEE-754 binary64 bit pattern, big-endian
    f:nan             any NaN: A0's MCP JSON cannot carry a NaN payload, so payload
                      bits are compared elsewhere (the CLI readback test)
    t:<hex>           UTF-8 text, as hex of its bytes
    b:<hex>           blob

Nothing here derives from this project's own engine.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

DEFAULT_LIMIT = 1000
MAX_PAGES = 4000


class Mcp:
    def __init__(self, exe):
        self.proc = subprocess.Popen([str(exe), "mcp"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.next_id = 0
        self.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "mdd-golden", "version": "1"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode())
        self.proc.stdin.flush()

    def call(self, method, params):
        self.next_id += 1
        self._send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("A0 MCP backend closed the pipe")
            message = json.loads(line)
            if message.get("id") == self.next_id:
                return message

    def tool(self, name, **arguments):
        reply = self.call("tools/call", {"name": name, "arguments": arguments})
        if "error" in reply:
            return {"_protocol_error": reply["error"], "_is_error": True}
        result = reply["result"]
        text = result["content"][0]["text"]
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = {"text": text}
        parsed["_is_error"] = bool(result.get("isError", False))
        return parsed

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def canonical(cell):
    kind, value = cell["type"], cell["value"]
    if kind == "null":
        return "N"
    if kind in ("int64", "uint64"):
        return "i:" + str(int(value))
    if kind == "float64":
        number = float(value)
        return "f:nan" if number != number else "f:" + struct.pack(">d", number).hex()
    if kind == "utf8":
        return "t:" + value.encode("utf-8").hex()
    if kind == "binary":
        return "b:" + value.lower()
    raise ValueError(f"unmodelled A0 cell type {kind!r}")


def statement_record(statement):
    return {
        "columns": [column["name"] for column in statement["columns"]],
        "rows": [[canonical(cell) for cell in row] for row in statement["rows"]],
        "offset": statement["offset"],
        "next_offset": statement["next_offset"],
        "truncated": statement["truncated"],
        "total_rows": statement.get("total_rows"),
    }


def error_record(reply):
    error = reply.get("error") or reply.get("_protocol_error") or {}
    return {"error": {"kind": error.get("kind", "protocol"),
                      "statement_index": error.get("statement_index")}}


def run_window(client, dataset, statements, limit, offset):
    reply = client.tool("query", dataset_id=dataset, sql=statements, limit=limit, offset=offset)
    if reply["_is_error"] or "statements" not in reply:
        return error_record(reply)
    return {"statements": [statement_record(s) for s in reply["statements"]]}


def main():
    exe, root, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    spec = json.loads((root / "conformance/corpus/hostlab/required-variants.json").read_text(encoding="utf-8"))
    client = Mcp(exe)
    opened = client.tool("open_dataset", inputs=[str((root / p).resolve()) for p in spec["inputs"]])
    if opened["_is_error"]:
        raise SystemExit("A0 refused the fixture inputs")
    dataset = opened["dataset_id"]
    cases = []
    for variant in spec["variants"]:
        limit, offset = variant.get("limit", DEFAULT_LIMIT), variant.get("offset", 0)
        pages = []
        if variant.get("walk"):
            assert len(variant["statements"]) == 1, "walk follows one statement"
            cursor = offset
            for _ in range(MAX_PAGES):
                page = run_window(client, dataset, variant["statements"], limit, cursor)
                pages.append(page)
                if "statements" not in page:
                    break
                cursor = page["statements"][0]["next_offset"]
                if cursor is None:
                    break
            else:
                raise SystemExit(f"{variant['variant']}: walk did not finish")
        else:
            pages.append(run_window(client, dataset, variant["statements"], limit, offset))
        cases.append({"family": variant["family"], "variant": variant["variant"],
                      "statements": variant["statements"], "limit": limit, "offset": offset, "walk": bool(variant.get("walk")),
                      "pages": pages})
    rejections = []
    for item in spec["rejections"]:
        reply = client.tool("query", dataset_id=dataset, sql=item["statements"],
                            limit=item["limit"], offset=item["offset"])
        refused = reply["_is_error"] or "statements" not in reply
        rejections.append({"name": item["name"], "statements": item["statements"],
                           "limit": item["limit"], "offset": item["offset"], "refused": refused,
                           **(error_record(reply) if refused else {})})
    client.close()
    document = {
        "schema_version": "mdd.hostlab-a0-golden.v1",
        "a0_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
        "inputs": spec["inputs"],
        "cases": cases,
        "rejections": rejections,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n",
                   encoding="utf-8", newline="\n")
    failed = [c["variant"] for c in cases if any("statements" not in p for p in c["pages"])]
    print(f"cases={len(cases)} pages={sum(len(c['pages']) for c in cases)} "
          f"rejections={len(rejections)} refused={sum(r['refused'] for r in rejections)} "
          f"cases_with_a0_error={failed}")


if __name__ == "__main__":
    main()
