"""Pin A0 typed-value rendering rules and framework attr-name resolution scope.

One synthetic manifest carries a sweep of attribute-reference IDs plus typed
corner cases; a second session pins string escaping and float formatting.
Usage: python probe_typed.py <out.json>
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


def apk_bytes(manifest):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        info = zipfile.ZipInfo("AndroidManifest.xml", (1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        z.writestr(info, manifest)
        z.writestr("classes.dex", g.tiny_dex())
    return buf.getvalue()


def manifest_with_app_attrs(attrs, extra_elements=()):
    """attrs: list of (name, ns, data_type, data, raw). Root manifest + application."""
    strings = ["android", A, "manifest", "package", "example.typed", "application"]
    for name, ns, dt, d, raw in attrs:
        for s in (name, raw):
            if s is not None and s not in strings:
                strings.append(s)
    for s in ("uses-sdk", "minSdkVersion", "targetSdkVersion"):
        if s not in strings:
            strings.append(s)
    sid = {s: i for i, s in enumerate(strings)}
    elements = [
        ("start", "manifest", [(None, "package", 3, sid["example.typed"], "example.typed")], 1),
        ("start", "uses-sdk", [(A, "minSdkVersion", 0x10, 21, None),
                               (A, "targetSdkVersion", 0x10, 35, None)], 1),
        ("end", "uses-sdk"),
        ("start", "application",
         [(ns, name, dt, sid[raw] if dt == 3 and raw is not None else d, raw)
          for name, ns, dt, d, raw in attrs], 1),
        *extra_elements,
        ("end", "application"),
        ("end", "manifest"),
    ]
    return g.axml(elements, strings, [("android", A)])


def main():
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    out = {}
    tmp = Path(tempfile.mkdtemp(prefix="mdd072-typed-"))
    c = Client(A0)
    c.initialize()

    # Sweep framework attribute IDs 0x01010000..0x010104ff plus edges.
    ids = list(range(0x01010000, 0x01010500)) + [0x01010500, 0x01010600, 0x0101FFFF,
                                                0x010100FF, 0x7F010000, 0x01000000, 0x01020000]
    attrs = [(f"a{i:04x}", A, 2, rid, None) for i, rid in enumerate(ids)]
    # Framework references of several types.
    for i, rid in enumerate([0x01030000, 0x01030001, 0x01040000, 0x01060000, 0x01020000,
                             0x01050000, 0x01070000, 0x01080000, 0x01090000, 0x010A0000,
                             0x010B0000, 0x010C0000, 0x010D0000, 0x010E0000]):
        attrs.append((f"r{i:02d}", A, 1, rid, None))
    data = manifest_with_app_attrs(attrs)
    p = tmp / "attr-sweep.apk"
    p.write_bytes(apk_bytes(data))
    opened = c.call("open_dataset", {"inputs": [str(p)]})
    sess = {"open": opened}
    if not opened.get("is_error"):
        ds = opened["reply"]["dataset_id"]
        sess["summary"] = c.call("get_manifest", {"dataset_id": ds})
        sess["xml"] = c.call("get_manifest", {"dataset_id": ds, "mode": "xml", "max_bytes": 131072})
        c.call("close_dataset", {"dataset_id": ds})
    out["attr-sweep"] = sess

    # Typed corner cases: floats, dimensions (radix/units), fractions, colors, escaping.
    def f32bits(x):
        return struct.unpack("<I", struct.pack("<f", x))[0]

    corner = [
        ("f_one_point_five", A, 4, f32bits(1.5), None),
        ("f_neg", A, 4, f32bits(-2.25), None),
        ("f_zero", A, 4, 0, None),
        ("f_inf", A, 4, 0x7F800000, None),
        ("f_neg_inf", A, 4, 0xFF800000, None),
        ("f_small", A, 4, f32bits(0.1), None),
        ("f_big", A, 4, f32bits(12345678.0), None),
        ("d_px", A, 5, (12 << 8) | 0, None),
        ("d_dp", A, 5, (12 << 8) | 1, None),
        ("d_sp", A, 5, (12 << 8) | 2, None),
        ("d_pt", A, 5, (12 << 8) | 3, None),
        ("d_in", A, 5, (12 << 8) | 4, None),
        ("d_mm", A, 5, (12 << 8) | 5, None),
        ("d_radix1", A, 5, (12 << 8) | (1 << 4) | 1, None),
        ("d_radix2", A, 5, (12 << 8) | (2 << 4) | 1, None),
        ("d_radix3", A, 5, (12 << 8) | (3 << 4) | 1, None),
        ("d_frac", A, 5, (3 << 6) | (1 << 4) | 1, None),  # mantissa 0x300 -> 0.75dp?
        ("fr_u0r0", A, 6, (50 << 8) | 0, None),
        ("fr_u1r0", A, 6, (50 << 8) | 1, None),
        ("fr_u0r1", A, 6, (50 << 8) | (1 << 4) | 0, None),
        ("fr_u0r2", A, 6, (50 << 8) | (2 << 4) | 0, None),
        ("fr_u0r3", A, 6, (50 << 8) | (3 << 4) | 0, None),
        ("fr_u1r2", A, 6, (50 << 8) | (2 << 4) | 1, None),
        ("c_argb8", A, 0x1C, 0xFF336699, None),
        ("c_rgb8", A, 0x1D, 0x336699, None),
        ("c_argb4", A, 0x1E, 0xF369, None),
        ("c_rgb4", A, 0x1F, 0x369, None),
        ("i_dec", A, 0x10, 123, None),
        ("i_hex", A, 0x11, 0xABCD, None),
        ("i_neg", A, 0x10, 0xFFFFFFFF, None),
        ("b_zero", A, 0x12, 0, None),
        ("b_one", A, 0x12, 1, None),
        ("b_two", A, 0x12, 2, None),
        ("s_escape", None, 3, None, 'a"b&c<d>e\'f'),
        ("s_unicode", None, 3, None, "héllo 世界 🎉"),
        ("s_empty", None, 3, None, ""),
        ("s_newline", None, 3, None, "line1\nline2\ttab"),
        ("ref_app", A, 1, 0x7F010000, None),
        ("null_0", A, 0, 0, None),
        ("null_1", A, 0, 1, None),
        ("dyn_ref", A, 7, 0x02010001, None),
        ("dyn_attr", A, 8, 0x02010002, None),
        ("unknown_99", A, 99, 0xDEADBEEF, None),
    ]
    # String-typed attributes are bound to pool indices inside manifest_with_app_attrs.
    data = manifest_with_app_attrs(corner)
    p = tmp / "corner.apk"
    p.write_bytes(apk_bytes(data))
    opened = c.call("open_dataset", {"inputs": [str(p)]})
    sess = {"open": opened}
    if not opened.get("is_error"):
        ds = opened["reply"]["dataset_id"]
        sess["summary"] = c.call("get_manifest", {"dataset_id": ds})
        sess["xml"] = c.call("get_manifest", {"dataset_id": ds, "mode": "xml", "max_bytes": 131072})
        c.call("close_dataset", {"dataset_id": ds})
    out["corner"] = sess
    c.close()
    Path(sys.argv[1]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", sys.argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())