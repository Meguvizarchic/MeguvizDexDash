"""Record the pinned reference engine's tools/list (all twelve tools, schemas and annotations) and
its initialize answer, for the twelve-tool qualification record of MDD-072.

Usage: python probe_tools_list.py <out.json>
The reference binary is a local input: its path is in MDD_REFERENCE_DEXSQL_010.
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from probe_a0 import A0, PINNED, Client  # noqa: E402


def main():
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    client = Client(A0)
    initialized = client.initialize()
    tools = client.request("tools/list")["result"]["tools"]
    client.close()
    record = {
        "reference": {"name": "dexsql", "version": "0.1.0", "sha256": PINNED},
        "server_info": initialized["serverInfo"],
        "tools": {tool["name"]: tool for tool in tools},
    }
    Path(sys.argv[1]).write_text(json.dumps(record, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                                 encoding="utf-8", newline="\n")
    print("tools:", sorted(record["tools"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
