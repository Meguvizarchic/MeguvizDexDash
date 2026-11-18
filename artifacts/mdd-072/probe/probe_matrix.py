"""Probe the pinned A0 reference across the MDD-072 resource fixtures.

Read-only oracle use. Writes one JSON object per fixture session with every answer.
Usage: python probe_matrix.py <fixture-dir> <out.json>
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_a0 import A0, PINNED, Client


def session(fixture_dir, name, calls):
    c = Client(A0)
    c.initialize()
    out = {}
    opened = c.call("open_dataset", {"inputs": [str(fixture_dir / name)]})
    out["open"] = opened
    if opened.get("is_error") or "jsonrpc_error" in opened:
        c.close()
        return out
    ds = opened["reply"]["dataset_id"]
    for i, (tool, args) in enumerate(calls):
        out[f"{i:02d} {tool} {json.dumps(args, ensure_ascii=False)}"] = c.call(tool, {"dataset_id": ds, **args})
    c.close()
    return out


def main():
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    fd = Path(sys.argv[1])
    out = {}

    small = [
        ("list_resource_files", {}),
        ("list_resource_files", {"prefix": "res/"}),
        ("list_resource_files", {"prefix": "assets/"}),
        ("list_resource_files", {"limit": 2}),
        ("list_resource_files", {"limit": 2, "offset": 2}),
        ("list_resource_files", {"limit": 2, "offset": 6}),
        ("list_resource_files", {"offset": 99}),
        ("list_resource_files", {"limit": 0}),
        ("read_resource", {"name": "assets/hello.txt"}),
        ("read_resource", {"name": "assets/hello.txt", "format": "hex"}),
        ("read_resource", {"name": "assets/blob.bin"}),
        ("read_resource", {"name": "assets/blob.bin", "max_bytes": 4096}),
        ("read_resource", {"name": "assets/blob.bin", "offset": 100, "max_bytes": 4096}),
        ("read_resource", {"name": "assets/blob.bin", "offset": 256}),
        ("read_resource", {"name": "assets/blob.bin", "offset": 257}),
        ("read_resource", {"name": "assets/blob.bin", "offset": 1, "max_bytes": 4096}),
        ("read_resource", {"name": "res/layout/main.xml"}),
        ("read_resource", {"name": "res/layout/main.xml", "format": "hex", "max_bytes": 4096}),
        ("read_resource", {"name": "resources.arsc"}),
        ("read_resource", {"name": "res/raw/data.bin", "offset": 200, "max_bytes": 4096}),
        ("read_resource", {"name": "AndroidManifest.xml", "offset": 100, "max_bytes": 4096}),
        ("read_resource", {"name": "AndroidManifest.xml", "offset": 690}),
        ("read_resource", {"name": "AndroidManifest.xml", "offset": 691}),
        ("read_resource", {"name": "missing"}),
        ("read_resource", {"name": ""}),
        ("read_resource", {"name": "assets/hello.txt", "max_bytes": 0}),
        ("read_resource", {"name": "assets/hello.txt", "max_bytes": 10}),
        ("query_resources", {}),
        ("query_resources", {"resource_type": "string"}),
        ("query_resources", {"name": "string/app_name"}),
        ("query_resources", {"name": "example.test:string/app_name"}),
        ("query_resources", {"resource_id": 0x7F010000}),
        ("query_resources", {"resource_id": 0x7F010001}),
        ("query_resources", {"contains": "app"}),
        ("query_resources", {"configuration": ""}),
        ("query_resources", {"configuration": "en"}),
        ("query_resources", {"configuration": "zh-rCN"}),
        ("query_resources", {"name": "string/app_name", "configuration": "zh-rCN"}),
        ("query_resources", {"resource_type": "style"}),
        ("query_resources", {"resource_type": "array"}),
        ("query_resources", {"resource_type": "plurals"}),
        ("query_resources", {"resource_type": "color"}),
        ("query_resources", {"resource_type": "dimen"}),
        ("query_resources", {"configuration": "night"}),
        ("query_resources", {"configuration": "land"}),
        ("query_resources", {"configuration": "nope"}),
        ("query_resources", {"name": "string/missing"}),
        ("query_resources", {"resource_id": 0x7F990000}),
        ("query_resources", {"resource_type": "string", "limit": 1}),
        ("query_resources", {"resource_type": "string", "limit": 1, "offset": 1}),
        ("query_resources", {"limit": 0}),
        ("query_resources", {"offset": 9999}),
        ("get_manifest_components", {}),
        ("get_manifest_components", {"limit": 2}),
        ("get_manifest_components", {"limit": 2, "offset": 2}),
        ("get_manifest_components", {"offset": 99}),
        ("get_manifest_components", {"kind": "provider"}),
        ("get_manifest_components", {"kind": "bogus"}),
    ]
    out["resources-small.apk"] = session(fd, "resources-small.apk", small)
    out["resources-only.apk"] = session(fd, "resources-only.apk", [
        ("get_manifest", {}),
        ("get_manifest", {"mode": "xml"}),
        ("list_resource_files", {}),
        ("query_resources", {"resource_type": "string"}),
        ("read_resource", {"name": "assets/hello.txt"}),
        ("list_tables", {}),
        ("query", {"sql": ["SELECT file_id FROM dex_files"]}),
    ])
    out["resources-no-arsc.apk"] = session(fd, "resources-no-arsc.apk", [
        ("query_resources", {}),
        ("list_resource_files", {}),
        ("read_resource", {"name": "assets/hello.txt"}),
    ])
    out["resources-corrupt.apk"] = session(fd, "resources-corrupt.apk", [
        ("query_resources", {}),
        ("read_resource", {"name": "resources.arsc"}),
        ("read_resource", {"name": "resources.arsc", "format": "hex"}),
        ("list_resource_files", {}),
    ])
    out["resources-bad-magic.apk"] = session(fd, "resources-bad-magic.apk", [
        ("query_resources", {}),
        ("read_resource", {"name": "resources.arsc"}),
    ])
    out["resources-bad-crc.apk"] = session(fd, "resources-bad-crc.apk", [
        ("read_resource", {"name": "assets/hello.txt"}),
        ("list_resource_files", {}),
        ("query_resources", {"resource_type": "string"}),
    ])
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", sys.argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())