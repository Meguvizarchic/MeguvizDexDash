"""Ask the pinned reference engine (dexsql 0.1.0) the resource questions about a real application, the public NewPipe
0.28.6 APK, and write every call and answer as replay records. The records are an ignored local file
(artifacts/local/a0-probe/newpipe.jsonl): they hold a few MB of the application's own strings and layouts.

The APK is an ignored local input (artifacts/local/inputs/NewPipe_v0.28.6.apk, SHA-256 in EXPECTED); the records name
it by file name only, so the replay can run where the APK is present and reports "not run" where it is not.

Usage: python probe_newpipe.py <apk> artifacts/local/a0-probe/newpipe.jsonl
The reference binary is a local input: its path is in MDD_REFERENCE_DEXSQL_010.
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import probe_a0  # noqa: E402
from probe_a0 import A0, PINNED, Client  # noqa: E402

EXPECTED = "e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58"
TYPES = ["string", "layout", "drawable", "color", "dimen", "bool", "integer", "id", "style", "array", "plurals",
         "attr", "xml", "menu", "mipmap", "raw", "anim", "animator", "font", "fraction", "interpolator", "navigation"]


def main():
    apk = Path(sys.argv[1])
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    if hashlib.sha256(apk.read_bytes()).hexdigest() != EXPECTED:
        print("refused: not the recorded NewPipe APK", file=sys.stderr)
        return 2
    out = Path(sys.argv[2])
    out.parent.mkdir(parents=True, exist_ok=True)
    probe_a0.CALL_LOG = str(out)
    probe_a0.PROBE = "probe_newpipe"
    out.write_text("", encoding="utf-8")
    c = Client(A0)
    c.initialize()
    opened = c.call("open_dataset", {"inputs": [str(apk)]})
    dataset = opened["reply"]["dataset_id"]

    def ask(tool, **arguments):
        return c.call(tool, {"dataset_id": dataset, **arguments})

    def pages(tool, key, limit=200, max_pages=None, **arguments):
        offset, count = 0, 0
        while True:
            answer = ask(tool, offset=offset, limit=limit, **arguments)
            count += 1
            reply = answer.get("reply", {})
            if answer["is_error"] or reply.get("next_offset") is None or (max_pages and count >= max_pages):
                return reply
            offset = reply["next_offset"]

    # the manifest as XML, whole, and the components
    offset = 0
    while True:
        answer = ask("get_manifest", mode="xml", offset=offset)
        nxt = answer["reply"]["page"]["next_offset"]
        if nxt is None:
            break
        offset = nxt
    pages("get_manifest_components", "components")
    pages("get_manifest_components", "components", only_exported=True)
    for kind in ("activity", "service", "receiver", "provider"):
        pages("get_manifest_components", "components", kind=kind)
    # every member
    listing = pages("list_resource_files", "files")
    pages("list_resource_files", "files", prefix="res/layout")
    pages("list_resource_files", "files", prefix="assets/")
    # the resource table: a few pages of everything, then each type, and the filters
    ask("query_resources", limit=200)
    for kind in TYPES:
        pages("query_resources", "values", max_pages=4, resource_type=kind)
    pages("query_resources", "values", max_pages=2, configuration="")
    for configuration in ("en", "de", "fr", "night", "land", "v21", "hdpi", "xxhdpi", "ldrtl", "sw600dp", "zh-rCN", "pt-rBR"):
        pages("query_resources", "values", max_pages=2, configuration=configuration)
    for needle in ("app_name", "title", "settings", "ic_"):
        pages("query_resources", "values", max_pages=2, contains=needle)
    ask("query_resources", name="string/app_name", limit=200)
    ask("query_resources", name="org.schabi.newpipe:string/app_name", limit=200)
    ask("query_resources", resource_type="style", limit=50, offset=0, max_bytes=131072)
    # members: text, binary XML, binary
    names = [f["name"] for f in listing.get("files", [])] if listing else []
    xml_names = [n for n in names if n.startswith("res/") and n.endswith(".xml")]
    for name in xml_names[:60]:
        ask("read_resource", name=name)
    for name in [n for n in names if n.endswith((".png", ".ttf", ".dex", ".arsc", ".version", ".properties", ".json"))][:25]:
        ask("read_resource", name=name, max_bytes=4096)
    ask("read_resource", name="resources.arsc", max_bytes=4096)
    ask("read_resource", name="AndroidManifest.xml")
    c.close()
    print("wrote", out, sum(1 for _ in out.open(encoding="utf-8")), "records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
