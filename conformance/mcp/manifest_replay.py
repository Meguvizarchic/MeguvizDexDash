#!/usr/bin/env python3
"""Replay the reference engine's recorded get_manifest summary of a public APK.

artifacts/mdd-025/manifest/a0 holds what the reference engine (A0, dexsql 0.1.0) answered
for NewPipe 0.28.6: open_dataset, six get_manifest summary pages of two permission rows
each, and close_dataset. This opens the same APK (an ignored local input, identified by its
SHA-256) in meguvizdexdash and compares every page, key for key and value for value, with
the dataset identifier masked. Without the APK the checks are reported as not run.

Usage: python -I conformance/mcp/manifest_replay.py [--binary PATH] [--out FILE]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_client import DEFAULT_BINARY, ROOT, McpClient  # noqa: E402

RECORD = ROOT / "artifacts" / "mdd-025" / "manifest" / "a0"
APK = ROOT / "artifacts" / "local" / "inputs" / "NewPipe_v0.28.6.apk"
APK_SHA256 = "e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58"
OPEN_KEYS = ["archive_inputs", "dataset_id", "has_dex", "input_bytes", "inputs", "prepare_ms"]


def load_record() -> tuple[list, dict, dict]:
    """The recorded summary pages, open and close answers."""
    read = lambda name: json.loads((RECORD / name).read_text(encoding="utf-8"))
    return read("summary-pages.json"), read("open.json"), read("close.json")


def run(binary: Path) -> dict:
    checks: list[dict] = []

    def add(name, equal, detail="", messages=""):
        checks.append({"name": name, "recorded": messages, "equal": equal, "detail": detail if equal is False else ""})

    if not APK.exists():
        add("the public APK is present", None, messages="open.json, summary-pages.json, close.json")
        checks[-1]["not_run"] = "artifacts/local/inputs/NewPipe_v0.28.6.apk is an ignored local input and is not here"
        return {"checks": checks, "passed": 0, "failed": 0, "not_run": 1, "equal": True}
    digest = hashlib.sha256(APK.read_bytes()).hexdigest()
    if digest != APK_SHA256:
        add("the public APK is the recorded input", False, f"sha256 {digest}")
        return {"checks": checks, "passed": 0, "failed": 1, "not_run": 0, "equal": False}
    pages, recorded_open, recorded_close = load_record()
    client = McpClient(binary)
    client.initialize()
    opened = client.call("open_dataset", inputs=[str(APK)])
    dataset = opened["dataset_id"]
    add("open_dataset on the APK answers the recorded fields: archive_inputs [0], has_dex, the byte count",
        all(opened[k] == recorded_open[k] for k in ("archive_inputs", "has_dex", "input_bytes"))
        and opened["inputs"] == [str(APK)] and set(OPEN_KEYS) <= set(opened), json.dumps({k: opened.get(k) for k in OPEN_KEYS}),
        "open.json")
    got, cursor = [], 0
    while True:
        reply = client.call("get_manifest", dataset_id=dataset, mode="summary", limit=2, offset=cursor)
        reply.pop("_is_error")
        got.append(reply)
        if reply["next_offset"] is None:
            break
        cursor = reply["next_offset"]
    add("the same number of permission pages", len(got) == len(pages), f"{len(got)} pages, recorded {len(pages)}", "summary-pages.json")
    for number, (ours, theirs) in enumerate(zip(got, pages)):
        masked = dict(ours, dataset_id=theirs["dataset_id"])
        different = sorted(k for k in set(masked) | set(theirs) if masked.get(k) != theirs.get(k))
        add(f"page {number}: every field equals the recording ({len(theirs['permissions'])} permission rows)",
            not different, f"differ: {different}", "summary-pages.json")
    default = client.call("get_manifest", dataset_id=dataset)
    whole = [row for page in pages for row in page["permissions"]]
    add("without limit, all 12 rows come in one page and no page is cut", default["permissions"] == whole
        and default["next_offset"] is None and default["truncated"] is False and default["total_rows"] == len(whole),
        json.dumps(default)[:200], "summary-pages.json")
    closed = client.call("close_dataset", dataset_id=dataset)
    closed.pop("_is_error")
    add("close_dataset answers the recorded {closed, dataset_id}", closed == dict(recorded_close, dataset_id=dataset),
        json.dumps(closed), "close.json")
    code = client.close()
    add("the server exits cleanly", code == 0, str(code))
    failed = [c for c in checks if c["equal"] is False]
    return {"checks": checks, "passed": sum(1 for c in checks if c["equal"] is True), "failed": len(failed),
            "not_run": 0, "equal": not failed, "apk_sha256": APK_SHA256}


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
            print("FAIL", check["name"], check["detail"][:400])
        elif check["equal"] is None:
            print("NOT RUN", check["name"], check.get("not_run", ""))
    return 0 if result["equal"] else 1


if __name__ == "__main__":
    sys.exit(main())
