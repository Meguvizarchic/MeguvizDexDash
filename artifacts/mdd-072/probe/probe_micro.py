"""Final micro-probes: protectionLevel edges, arsc-backed name resolution,
summary paging, offset==total pages, xmlns presence, list_datasets limits.

Usage: python probe_micro.py <resources-fixture-dir> <out.json>
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


def apk_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            z.writestr(info, data)
        z.writestr("classes.dex", g.tiny_dex())
    return buf.getvalue()


def manifest(levels, app_attrs=(), with_android=True):
    strings = ["android", A, "manifest", "package", "example.micro", "application",
               "uses-sdk", "minSdkVersion", "targetSdkVersion", "permission", "name",
               "p.perm", "protectionLevel", "label", "icon", ""]
    for ns, n, dt, d, r in app_attrs:
        for s in (n, r):
            if s is not None and s not in strings:
                strings.append(s)
    sid = {s: i for i, s in enumerate(strings)}
    elements = [
        ("start", "manifest", [(None, "package", 3, sid["example.micro"], "example.micro")], 1),
        ("start", "uses-sdk", [(A, "minSdkVersion", 0x10, 21, None),
                               (A, "targetSdkVersion", 0x10, 35, None)], 1),
        ("end", "uses-sdk"),
    ]
    for dt, d in levels:
        elements.append(("start", "permission",
                         [(A, "name", 3, sid["p.perm"], "p.perm"),
                          (A, "protectionLevel", dt, d, None)], 1))
        elements.append(("end", "permission"))
    elements.append(("start", "application",
                     [(ns, n, dt, sid[r] if dt == 3 and r is not None else d, r)
                      for ns, n, dt, d, r in app_attrs], 1))
    elements.append(("end", "application"))
    elements.append(("end", "manifest"))
    ns = [("android", A)] if with_android else []
    return g.axml(elements, strings, ns)


def main():
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    out = {}
    tmp = Path(tempfile.mkdtemp(prefix="mdd072-micro-"))
    c = Client(A0)
    c.initialize()

    def session(label, data, calls, close=True):
        p = tmp / f"{label}.apk"
        p.write_bytes(data)
        opened = c.call("open_dataset", {"inputs": [str(p)]})
        sess = {"open": opened}
        ds = None
        if not opened.get("is_error") and "reply" in opened:
            ds = opened["reply"]["dataset_id"]
            for i, (tool, args) in enumerate(calls):
                sess[f"{i:02d} {tool} {json.dumps(args, ensure_ascii=False)}"] = c.call(
                    tool, {"dataset_id": ds, **args})
            if close:
                c.call("close_dataset", {"dataset_id": ds})
        out[label] = sess
        return ds

    levels = [(0x10, v) for v in [0x10000, 0x20000, 0x10010, 0x20010, 5, 6, 7, 8, 9, 0xA, 0xE, 0xF]]
    session("pl-edges", apk_bytes([("AndroidManifest.xml", manifest(levels))]), [
        ("get_manifest", {"limit": 200}),
    ])

    # arsc-backed resolution in summary + query attribute naming.
    arsc = g.small_arsc()
    app_attrs = [(A, "label", 1, 0x7F010000, None), (A, "icon", 1, 0x7F020000, None),
                 (A, "theme", 2, 0x7F010000, None), (A, "theme2", 2, 0x7F010001, None)]
    session("resolved", apk_bytes([("AndroidManifest.xml", manifest([(0x10, 2)], app_attrs)),
                                   ("resources.arsc", arsc)]), [
        ("get_manifest", {}),
        ("get_manifest", {"mode": "xml"}),
        ("query_resources", {"resource_type": "string"}),
    ])

    # Summary paging and offset==total edges across tools.
    ds = session("paging-edges", apk_bytes([
        ("AndroidManifest.xml", manifest([(0x10, 0), (0x10, 1), (0x10, 2)])),
        ("resources.arsc", g.small_arsc()),
        ("assets/hello.txt", b"hello\n"),
    ]), [
        ("get_manifest", {"limit": 1}),
        ("get_manifest", {"limit": 1, "offset": 1}),
        ("get_manifest", {"limit": 1, "offset": 3}),
        ("get_manifest", {"offset": 99}),
        ("get_manifest", {"mode": "xml", "offset": 690}),
        ("get_manifest_components", {"offset": 5}),
        ("list_resource_files", {"offset": 4}),
        ("query_resources", {"offset": 19}),
        ("read_resource", {"name": "assets/hello.txt", "offset": 6}),
        ("list_datasets", {}),
    ], close=False)
    if ds:
        out["paging-edges"]["limits_after"] = c.call("list_datasets", {})
        c.call("close_dataset", {"dataset_id": ds})

    # No android namespace at all: xmlns presence.
    session("no-ns", apk_bytes([("AndroidManifest.xml",
                                manifest([(0x10, 2)], [(None, "label", 3, 0, "plain")],
                                         with_android=False))]), [
        ("get_manifest", {}),
        ("get_manifest", {"mode": "xml"}),
    ])

    # Styled/unpaired AXML through read_resource generic path.
    styled = (ROOT / "tests" / "fixtures" / "manifest" / "generated" / "styled-utf8.axml").read_bytes()
    unpaired = (ROOT / "tests" / "fixtures" / "manifest" / "generated" / "unpaired-value-utf16.axml").read_bytes()
    session("styled-read", apk_bytes([("res/layout/styled.xml", styled),
                                      ("res/layout/unpaired.xml", unpaired)]), [
        ("read_resource", {"name": "res/layout/styled.xml"}),
        ("read_resource", {"name": "res/layout/unpaired.xml"}),
    ])
    c.close()
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", sys.argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())