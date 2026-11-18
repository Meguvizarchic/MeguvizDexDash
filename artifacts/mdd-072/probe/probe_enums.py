"""Pin A0 enum/flag rendering, pagination budget, control-char normalization,
query value-type names and row-budget truncation.

Usage: python probe_enums.py <resources-fixture-dir> <out.json>
"""
import hashlib
import io
import json
import struct
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
N = g.N


def apk_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            z.writestr(info, data)
        z.writestr("classes.dex", g.tiny_dex())
    return buf.getvalue()


def build_manifest(permission_levels, launch_modes, install_locations, extra_app=()):
    """permission_levels: list of (data_type, data, raw). One permission element each."""
    strings = ["android", A, "manifest", "package", "example.enum", "application",
               "uses-sdk", "minSdkVersion", "targetSdkVersion", "permission", "name",
               "p.perm", "protectionLevel", "activity", "launchMode", "installLocation",
               "a", ""]
    for dt, d, raw in permission_levels:
        if raw is not None and raw not in strings:
            strings.append(raw)
    for ns, n, dt, d, r in extra_app:
        for s in (n, r):
            if s is not None and s not in strings:
                strings.append(s)
    sid = {s: i for i, s in enumerate(strings)}
    elements = [
        ("start", "manifest", [(None, "package", 3, sid["example.enum"], "example.enum"),
                               (A, "installLocation", 0x10, install_locations[0], None)], 1),
        ("start", "uses-sdk", [(A, "minSdkVersion", 0x10, 21, None),
                               (A, "targetSdkVersion", 0x10, 35, None)], 1),
        ("end", "uses-sdk"),
    ]
    for i, (dt, d, raw) in enumerate(permission_levels):
        data = sid[raw] if dt == 3 and raw is not None else d
        elements.append(("start", "permission",
                         [(A, "name", 3, sid["p.perm"], "p.perm"),
                          (A, "protectionLevel", dt, data, raw)], 1))
        elements.append(("end", "permission"))
    elements.append(("start", "application",
                     [(ns, n, dt, sid[r] if dt == 3 and r is not None else d, r)
                      for ns, n, dt, d, r in extra_app], 1))
    for i, mode in enumerate(launch_modes):
        elements.append(("start", "activity",
                         [(A, "name", 3, sid["a"], "a"), (A, "launchMode", 0x10, mode, None)], 1))
        elements.append(("end", "activity"))
    elements.append(("end", "application"))
    elements.append(("end", "manifest"))
    return g.axml(elements, strings, [("android", A)])


def typed_arsc():
    """One entry per value type, plus a bag with a reference item and escapes."""
    values = ["Hello", "a&b<c>\"d'e", "x"]
    f32 = lambda x: struct.unpack("<I", struct.pack("<f", x))[0]
    entries = [
        g.simple_entry(0, 3, 0),          # string
        g.simple_entry(1, 1, 0x7F010000),  # reference to self type entry 0
        g.simple_entry(2, 2, 0x01010000),  # attribute framework
        g.simple_entry(3, 4, f32(1.5)),    # float
        g.simple_entry(4, 5, (8 << 8) | 1),  # dimension
        g.simple_entry(5, 6, (50 << 8) | 0),  # fraction
        g.simple_entry(6, 0x10, 123),      # dec
        g.simple_entry(7, 0x11, 0xABCD),   # hex
        g.simple_entry(8, 0x12, 1),        # bool
        g.simple_entry(9, 0x1C, 0xFF336699),
        g.simple_entry(10, 0x1D, 0x336699),
        g.simple_entry(11, 0x1E, 0xF369),
        g.simple_entry(12, 0x1F, 0x369),
        g.simple_entry(13, 0, 0),          # null
        g.simple_entry(14, 7, 0x02010001),  # dynamic ref
        g.simple_entry(15, 8, 0x02010002),  # dynamic attr
        g.simple_entry(16, 99, 0xDEADBEEF),  # unknown
        g.simple_entry(17, 3, 1),          # string with escapes
    ]
    bag = g.bag_entry(18, 0x7F010000, [(0x01010000, 1, 0x7F010001), (0x7F010002, 3, 2)])
    types = [{"id": 1, "specs": [2] * 19, "configs": [(g.config(), entries + [bag])]}]
    keys = [f"k{i}" for i in range(19)]
    return g.build_arsc("example.typed", 0x7F, values, ["string"], keys, types)


def main():
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    out = {}
    tmp = Path(tempfile.mkdtemp(prefix="mdd072-enums-"))
    c = Client(A0)
    c.initialize()

    def session(label, data, calls):
        p = tmp / f"{label}.apk"
        p.write_bytes(data)
        opened = c.call("open_dataset", {"inputs": [str(p)]})
        sess = {"open": opened}
        if not opened.get("is_error") and "reply" in opened:
            ds = opened["reply"]["dataset_id"]
            for i, (tool, args) in enumerate(calls):
                sess[f"{i:02d} {tool} {json.dumps(args, ensure_ascii=False)}"] = c.call(
                    tool, {"dataset_id": ds, **args})
            c.call("close_dataset", {"dataset_id": ds})
        out[label] = sess

    # Protection levels: ints across the flag space + string-typed with distinct data.
    levels = [(0x10, v, None) for v in
              [0, 1, 2, 3, 4, 0x10, 0x11, 0x12, 0x13, 0x20, 0x40, 0x80, 0x100, 0x200,
               0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x200000, 0x400000,
               0x800000, 0x1000000, 0x2000000, 0x4000000, 0x8000000, 0x10000000,
               0x20000000, 0x80000000, 0xFFFFFFFF, 0x12, 0x23, 0x102, 0x2002]]
    levels += [(3, 0, "signature"), (3, 0, "dangerous"), (3, 0, "normal"),
               (3, 0, "signature|privileged"), (3, 0, "bogus")]
    modes = [0, 1, 2, 3, 4, 5, 99]
    session("enums", apk_bytes([("AndroidManifest.xml",
                                 build_manifest(levels, modes, [0]))]), [
        ("get_manifest", {"limit": 200}),
        ("get_manifest_components", {"limit": 200}),
    ])
    session("install-location", apk_bytes([("AndroidManifest.xml",
                                            build_manifest([(0x10, 2, None)], [0], [2]))]), [
        ("get_manifest", {}),
    ])

    # Budget confirmation + control chars + dimension/fraction unit edges.
    big_text = "".join(f"line {i:04d}\n" for i in range(600)).encode()
    ctrl = "a\rb\vc\fd\x01e\x7f"
    app_attrs = [
        (A, "u6", 5, (12 << 8) | 6, None),
        (A, "u7", 5, (12 << 8) | 7, None),
        (A, "fu2", 6, (50 << 8) | 2, None),
        (A, "fu3", 6, (50 << 8) | 3, None),
        (A, "attr_dyn", 2, 0x02010001, None),
        (A, "attr_fw_unknown", 2, 0x0101FFFF, None),
        (A, "dynref_fw", 7, 0x01010000, None),
        (A, "dynattr_fw", 8, 0x01010000, None),
        (A, "ref_fw_unknown", 1, 0x0104FFFF, None),
        (None, "ctrl", 3, 0, ctrl),
    ]
    session("edges", apk_bytes([
        ("AndroidManifest.xml", build_manifest([(0x10, 2, None)], [0], [0], app_attrs)),
        ("assets/big.txt", big_text),
    ]), [
        ("get_manifest", {}),
        ("read_resource", {"name": "assets/big.txt", "max_bytes": 8192}),
        ("read_resource", {"name": "assets/big.txt", "max_bytes": 131072}),
        ("read_resource", {"name": "assets/big.txt", "max_bytes": 4097}),
        ("read_resource", {"name": "assets/big.txt", "format": "hex", "max_bytes": 8192}),
    ])

    # Query value types, contains semantics, row budgets.
    session("typed-table", apk_bytes([("resources.arsc", typed_arsc())]), [
        ("query_resources", {"limit": 200}),
        ("query_resources", {"contains": "Hello"}),
        ("query_resources", {"contains": "k1"}),
        ("query_resources", {"contains": "example.typed"}),
        ("query_resources", {"resource_id": 0x7F010012}),
        ("query_resources", {"max_bytes": 4096, "limit": 200}),
        ("query_resources", {"max_bytes": 4096, "limit": 200, "offset": 10}),
        ("list_resource_files", {"max_bytes": 4096}),
        ("get_manifest_components", {"max_bytes": 4096}),
    ])

    # Bad AXML via read_resource (generic path) and prefix case.
    bad = (ROOT / "tests" / "fixtures" / "manifest" / "generated" / "truncated-7.axml").read_bytes()
    session("bad-axml", apk_bytes([("res/layout/bad.xml", bad)]), [
        ("read_resource", {"name": "res/layout/bad.xml"}),
        ("read_resource", {"name": "res/layout/bad.xml", "format": "hex"}),
        ("list_resource_files", {"prefix": "RES/"}),
        ("list_resource_files", {"prefix": "res"}),
    ])
    c.close()
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", sys.argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())