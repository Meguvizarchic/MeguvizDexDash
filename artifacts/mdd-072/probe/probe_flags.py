"""Pin how the reference engine names the bits of android:foregroundServiceType (a flag attribute of the
platform), by asking about single bits, combinations and unnamed bits in one synthetic manifest.

Usage: python probe_flags.py <out.json>
"""
import hashlib
import io
import json
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "resources"))
from probe_a0 import A0, PINNED, Client  # noqa: E402
import generate as g  # noqa: E402

A = g.ANDROID
ATTRIBUTE = "foregroundServiceType"
VALUES = [0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
          0x10000, 0x40000000, 0x80000000, 3, 0x42, 0x7, 0xFFFFFFFF, 0x3FFF]


def manifest(values):
    strings = ["android", A, "manifest", "package", "example.flags", "permission", "name", "p.perm", ATTRIBUTE, ""]
    sid = {s: i for i, s in enumerate(strings)}
    elements = [("start", "manifest", [(None, "package", 3, sid["example.flags"], "example.flags")], 1)]
    for v in values:
        elements.append(("start", "permission", [(A, "name", 3, sid["p.perm"], "p.perm"), (A, ATTRIBUTE, 0x11, v, None)], 1))
        elements.append(("end", "permission"))
    elements.append(("end", "manifest"))
    return g.axml(elements, strings, [("android", A)])


def main():
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        info = zipfile.ZipInfo("AndroidManifest.xml", (1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        z.writestr(info, manifest(VALUES))
        z.writestr("classes.dex", g.tiny_dex())
    path = Path(tempfile.mkdtemp(prefix="mdd072-flags-")) / "flags.apk"
    path.write_bytes(buf.getvalue())
    client = Client(A0)
    client.initialize()
    opened = client.call("open_dataset", {"inputs": [str(path)]})
    reply = client.call("get_manifest", {"dataset_id": opened["reply"]["dataset_id"], "limit": 200})["reply"]
    client.close()
    named = {hex(v): row["attributes"].get(f"android:{ATTRIBUTE}") for v, row in zip(VALUES, reply["permissions"])}
    Path(sys.argv[1]).write_text(json.dumps(named, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    for k, v in named.items():
        print(k, "->", v)
    return 0


if __name__ == "__main__":
    sys.exit(main())
