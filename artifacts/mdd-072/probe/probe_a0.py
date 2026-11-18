"""Live probe of the pinned A0 reference (dexsql 0.1.0) for MDD-072 resource tools.

Read-only oracle use: the binary is started as an MCP server, never modified.
Usage: python probe_a0.py <fixture-dir> <out.json>
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# The pinned reference binary is a local input: its path comes from the environment.
A0 = Path(os.environ.get("MDD_REFERENCE_DEXSQL_010", "dexsql-0.1.0-not-set"))
PINNED = "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"
# When set, every input a probe opens is copied to <dir>/<probe script name>/<basename>, so the
# replay can open exactly what the reference was asked about.
SAVE = os.environ.get("MDD072_SAVE_FIXTURES")
# When set, every call is also appended to this JSON-lines file as one replayable record.
CALL_LOG = os.environ.get("MDD072_CALL_LOG")
LOGGED = {"open_dataset", "get_manifest", "get_manifest_components", "list_resource_files",
          "read_resource", "query_resources", "list_tables", "query"}
PROBE = Path(sys.argv[0]).stem


class Client:
    def __init__(self, binary):
        self.p = subprocess.Popen([str(binary), "mcp"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.n = 0
        self.datasets = {}
        self.log = []

    def request(self, method, params=None):
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            msg["params"] = params
        self.p.stdin.write(json.dumps(msg).encode() + b"\n")
        self.p.stdin.flush()
        raw = self.p.stdout.readline()
        if not raw:
            raise RuntimeError("closed: " + self.p.stderr.read().decode("utf-8", "replace"))
        return json.loads(raw)

    def initialize(self):
        r = self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "clientInfo": {"name": "probe", "version": "1"}})
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode() + b"\n")
        self.p.stdin.flush()
        return r["result"]

    def call(self, tool, arguments):
        if tool == "open_dataset" and SAVE:
            target = Path(SAVE) / PROBE
            target.mkdir(parents=True, exist_ok=True)
            for source in arguments["inputs"]:
                shutil.copyfile(source, target / Path(source).name)
        r = self.request("tools/call", {"name": tool, "arguments": arguments})
        if "error" in r:
            return {"jsonrpc_error": r["error"]}
        res = r["result"]
        out = {"is_error": bool(res.get("isError"))}
        inputs = [Path(i).name for i in arguments.get("inputs", [])]
        if res.get("structuredContent") is not None:
            out["reply"] = res["structuredContent"]
            if tool == "open_dataset" and "inputs" in out["reply"]:
                # a path on this machine is not part of the record
                self.datasets[out["reply"]["dataset_id"]] = inputs
                out["reply"]["inputs"] = inputs
        else:
            out["raw_text"] = res["content"][0]["text"]
        if tool in LOGGED:
            given = {k: v for k, v in arguments.items() if k != "dataset_id"}
            if tool == "open_dataset":
                # a path on this machine is not part of the record: the inputs are named by file name
                given["inputs"] = inputs
            self.log.append({"probe": PROBE, "tool": tool, "arguments": given,
                             "inputs": inputs or self.datasets.get(arguments.get("dataset_id"), []),
                             "is_error": out["is_error"], "reply": out.get("reply", out.get("raw_text"))})
        return out

    def close(self):
        if CALL_LOG:
            with open(CALL_LOG, "a", encoding="utf-8", newline="\n") as handle:
                for record in self.log:
                    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        try:
            self.p.stdin.close()
        except OSError:
            pass
        self.p.wait(timeout=30)


def main():
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    fixtures = Path(sys.argv[1])
    out = {}
    c = Client(A0)
    init = c.initialize()
    out["initialize"] = init
    out["tools"] = [t["name"] for t in c.request("tools/list")["result"]["tools"]]
    opened = c.call("open_dataset", {"inputs": [str(fixtures / "manifest-small.apk")]})
    out["open_manifest_small"] = opened
    ds = opened["reply"]["dataset_id"]
    for tool, args in [
        ("get_manifest", {"mode": "xml"}),
        ("get_manifest_components", {}),
        ("get_manifest_components", {"kind": "activity"}),
        ("get_manifest_components", {"only_exported": True}),
        ("list_resource_files", {}),
        ("read_resource", {"name": "AndroidManifest.xml"}),
        ("read_resource", {"name": "AndroidManifest.xml", "format": "hex"}),
        ("read_resource", {"name": "classes.dex"}),
        ("read_resource", {"name": "nope.txt"}),
        ("query_resources", {}),
        ("query_resources", {"resource_type": "string"}),
    ]:
        out[tool + " " + json.dumps(args)] = c.call(tool, {"dataset_id": ds, **args})
    c.close()
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", sys.argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())