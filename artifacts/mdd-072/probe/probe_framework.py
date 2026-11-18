"""Sweep the pinned A0 framework resource-name table (public android.R) and the
64 MiB resource cap. Offline oracle extraction; results become a static table.

Usage: python probe_framework.py <out.json>
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
from probe_a0 import A0, PINNED, Client
import generate as g

A = g.ANDROID
TYPES = {1: "attr", 2: "id", 3: "style", 4: "string", 5: "dimen", 6: "color",
         7: "array", 8: "drawable", 9: "layout", 10: "anim", 11: "animator",
         12: "interpolator", 13: "mipmap", 14: "integer", 15: "bool",
         16: "fraction", 17: "plurals", 18: "font"}
SPAN = 0x1000


def apk_bytes(manifest, extra=()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        info = zipfile.ZipInfo("AndroidManifest.xml", (1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        z.writestr(info, manifest)
        for name, data in extra:
            z.writestr(name, data)
        z.writestr("classes.dex", g.tiny_dex())
    return buf.getvalue()


def sweep_manifest(type_id, start, count):
    names = [f"f{i:03x}" for i in range(start, start + count)]
    strings = ["android", A, "manifest", "package", "example.sweep", "application"] + names
    sid = {s: i for i, s in enumerate(strings)}
    attrs = [(A, n, 1, 0x01000000 | (type_id << 16) | i, None)
             for i, n in zip(range(start, start + count), names)]
    elements = [
        ("start", "manifest", [(None, "package", 3, sid["example.sweep"], "example.sweep")], 1),
        ("start", "application", attrs, 1),
        ("end", "application"),
        ("end", "manifest"),
    ]
    return g.axml(elements, strings, [("android", A)])


def main():
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    out = {"pinned_sha256": PINNED, "span": SPAN, "types": TYPES}
    tmp = Path(tempfile.mkdtemp(prefix="mdd072-fw-"))
    c = Client(A0)
    c.initialize()
    table = {}
    for tid, tname in TYPES.items():
        resolved = {}
        for start in range(0, SPAN, 1024):
            p = tmp / f"sweep-{tname}-{start}.apk"
            p.write_bytes(apk_bytes(sweep_manifest(tid, start, 1024)))
            opened = c.call("open_dataset", {"inputs": [str(p)]})
            if opened.get("is_error"):
                out[f"error-{tname}-{start}"] = opened
                continue
            ds = opened["reply"]["dataset_id"]
            summ = c.call("get_manifest", {"dataset_id": ds, "limit": 1})
            c.call("close_dataset", {"dataset_id": ds})
            if "reply" not in summ or "application" not in summ.get("reply", {}):
                out.setdefault("output-cap-error", summ)
                continue
            app = summ["reply"]["application"]
            for i in range(start, start + 1024):
                v = app.get(f"android:f{i:03x}")
                if v is not None and v.startswith(f"@android:{tname}/"):
                    resolved[i] = v[len(f"@android:{tname}/"):]
        table[tname] = resolved
        print(tname, "resolved", len(resolved), "max", hex(max(resolved)) if resolved else None)
    out["table"] = table

    # Attr-type sweep extension 0x500..0x600 (type 2 rendering).
    ids = list(range(0x500, 0x600))
    names = [f"a{i:03x}" for i in ids]
    strings = ["android", A, "manifest", "package", "example.sweep", "application"] + names
    sid = {s: i for i, s in enumerate(strings)}
    attrs = [(A, n, 2, 0x01010000 | i, None) for n, i in zip(names, ids)]
    elements = [
        ("start", "manifest", [(None, "package", 3, sid["example.sweep"], "example.sweep")], 1),
        ("start", "application", attrs, 1),
        ("end", "application"),
        ("end", "manifest"),
    ]
    p = tmp / "sweep-attr-ext.apk"
    p.write_bytes(apk_bytes(g.axml(elements, strings, [("android", A)])))
    opened = c.call("open_dataset", {"inputs": [str(p)]})
    ds = opened["reply"]["dataset_id"]
    summ = c.call("get_manifest", {"dataset_id": ds, "limit": 1})
    c.call("close_dataset", {"dataset_id": ds})
    app = summ["reply"]["application"]
    ext = {}
    for i in ids:
        v = app.get(f"android:a{i:03x}")
        if v is not None and v.startswith("android:attr/"):
            ext[i] = v[len("android:attr/"):]
    out["attr_ext"] = ext
    print("attr_ext resolved", len(ext))

    # Components offset==total empty page.
    rich = (ROOT / "artifacts" / "mdd-072" / "probe")
    p = tmp / "small.apk"
    p.write_bytes((ROOT / "tests" / "fixtures" / "resources" / "generated" / "resources-small.apk").read_bytes())
    opened = c.call("open_dataset", {"inputs": [str(p)]})
    ds = opened["reply"]["dataset_id"]
    out["components-offset-total"] = c.call("get_manifest_components", {"dataset_id": ds, "offset": 5})
    out["manifest-offset-total"] = c.call("get_manifest", {"dataset_id": ds, "offset": 3})
    c.call("close_dataset", {"dataset_id": ds})

    # 64 MiB + 1 resource cap.
    big = b"\xff" * (64 * 1024 * 1024 + 1)
    p = tmp / "cap.apk"
    p.write_bytes(apk_bytes(sweep_manifest(1, 0, 16), [("assets/big.bin", big)]))
    opened = c.call("open_dataset", {"inputs": [str(p)]})
    sess = {"open": opened}
    if not opened.get("is_error"):
        ds = opened["reply"]["dataset_id"]
        sess["list"] = c.call("list_resource_files", {"dataset_id": ds, "prefix": "assets/"})
        sess["read"] = c.call("read_resource", {"dataset_id": ds, "name": "assets/big.bin"})
        sess["read_paged"] = c.call("read_resource", {"dataset_id": ds, "name": "assets/big.bin", "max_bytes": 4096})
        sess["read_hex"] = c.call("read_resource", {"dataset_id": ds, "name": "assets/big.bin", "format": "hex"})
        c.call("close_dataset", {"dataset_id": ds})
    out["cap"] = sess
    c.close()
    Path(sys.argv[1]).write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    print("wrote", sys.argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())