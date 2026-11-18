"""Synthetic resource fixtures for MDD-072: resources.arsc, AXML layouts, config
variants, text/binary entries and damaged negative cases.

Everything here is written from the public Android resource-table and binary-XML
layouts by hand; no Android SDK, no third-party parser and no real APK is used.
The fixtures are small, deterministic (fixed timestamps, stored or deflated with a
fixed level) and labelled synthetic: they are layout vectors, not installable apps.

Run: python tests/fixtures/resources/generate.py [--check]
"""
from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "generated"
ROOT = HERE.parents[2]
ANDROID = "http://schemas.android.com/apk/res/android"
N = 0xFFFFFFFF
P = lambda *x: struct.pack("<" + "I" * len(x), *x)
H = lambda *x: struct.pack("<" + "H" * len(x), *x)


def chunk(kind: int, header: bytes, payload: bytes, header_size: int | None = None) -> bytes:
    hs = len(header) + 8 if header_size is None else header_size
    return H(kind, hs) + P(hs + len(payload)) + header + payload


def len8(n: int) -> bytes:
    return bytes([n]) if n < 128 else bytes([0x80 | (n >> 8), n & 255])


def string_pool(values: list[str], utf8: bool = True) -> bytes:
    """A ResStringPool / AXML string pool of plain strings (no styles)."""
    data, offsets = bytearray(), []
    for value in values:
        offsets.append(len(data))
        units = value.encode("utf-16-le", "surrogatepass")
        if utf8:
            raw = value.encode("utf-8")
            data += len8(len(units) // 2) + len8(len(raw)) + raw + b"\0"
        else:
            size = len(units) // 2
            data += (H(size) if size < 0x8000 else H(0x8000 | (size >> 16), size & 65535)) + units + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    begin = 28 + 4 * len(offsets)
    return chunk(1, P(len(values), 0, 0x100 if utf8 else 0, begin, 0), P(*offsets) + data)


# ---- resources.arsc -------------------------------------------------------------

def config(language: bytes = b"\0\0", country: bytes = b"\0\0", orientation: int = 0,
           density: int = 0, sdk: int = 0, size: int = 56) -> bytes:
    """ResTable_config: only the fields the fixtures vary; the rest stay zero."""
    body = bytearray(size)
    struct.pack_into("<I", body, 0, size)
    body[8:10] = language
    body[10:12] = country
    body[12] = orientation
    struct.pack_into("<H", body, 14, density)
    struct.pack_into("<H", body, 24, sdk)
    return bytes(body)


def value(data_type: int, data: int) -> bytes:
    return H(8) + bytes([0, data_type]) + P(data)


def build_arsc(package: str, package_id: int, value_strings: list[str],
               type_names: list[str], key_names: list[str],
               types: list[dict]) -> bytes:
    """types: [{id, specs: [flags...], configs: [(config_bytes, [entry_or_None...])]}]
    entry: (key_index, flags, value_bytes) with value_bytes a Res_value or a map entry body.
    """
    type_pool = string_pool(type_names)
    key_pool = string_pool(key_names)
    header_size = 288
    type_strings_at = header_size
    key_strings_at = type_strings_at + len(type_pool)
    body = bytearray()
    body += P(package_id)
    body += package.encode("utf-16-le")[:256].ljust(256, b"\0")
    body += P(type_strings_at, len(type_names), key_strings_at, len(key_names), 0)
    body += type_pool + key_pool
    for t in types:
        entry_count = len(t["specs"])
        body += chunk(0x0202, bytes([t["id"], 0]) + H(0) + P(entry_count),
                      b"".join(P(f) for f in t["specs"]))
        for cfg, entries in t["configs"]:
            offsets, data = [], bytearray()
            base = 20 + len(cfg) + 4 * entry_count
            for e in entries:
                if e is None:
                    offsets.append(N)
                else:
                    # Entry offsets are relative to entriesStart, not the chunk start.
                    offsets.append(len(data))
                    key_index, flags, payload = e
                    # a map entry's header holds the parent and the count: 16 bytes, not 8
                    data += H(16 if flags & 1 else 8) + H(flags) + P(key_index) + payload
            header = bytes([t["id"], 0]) + H(0) + P(entry_count, base) + cfg
            body += chunk(0x0201, header, b"".join(P(o) for o in offsets) + bytes(data),
                          header_size=20 + len(cfg))
    pkg = H(0x0200, header_size) + P(8 + len(body)) + bytes(body)
    value_pool = string_pool(value_strings)
    return H(2, 12) + P(12 + len(value_pool) + len(pkg)) + P(1) + value_pool + pkg


def simple_entry(key: int, data_type: int, data: int, public: bool = True) -> tuple:
    return (key, 2 if public else 0, value(data_type, data))


def bag_entry(key: int, parent: int, items: list[tuple[int, int, int]], public: bool = True) -> tuple:
    payload = P(parent) + P(len(items)) + b"".join(P(name) + value(dt, d) for name, dt, d in items)
    return (key, (2 if public else 0) | 1, payload)


# ---- AXML (generic, not only manifests) ------------------------------------------

def axml(elements: list[tuple], strings: list[str], namespaces: list[tuple[str, str]],
         resource_map: list[int] | None = None, utf8: bool = True) -> bytes:
    """elements: a flat list of ("start", name, attrs, line) / ("end", name) / ("text", value)
    where attrs = [(ns_uri_or_None, name, data_type, data, raw_string_or_None)].
    Namespace start/end chunks are emitted around the root from `namespaces`.
    """
    sid = {s: i for i, s in enumerate(strings)}
    records = []
    # Node chunks carry headerSize=16 (ResXMLTree_node only); the ns/name/attrExt
    # fields belong to the payload, matching AAPT and the reference decoder.
    for prefix, uri in namespaces:
        records.append(chunk(0x100, P(1, N), P(sid[prefix], sid[uri]), header_size=16))
    for item in elements:
        if item[0] == "start":
            _, name, attrs, line = item
            raw = b"".join(
                P(sid[ns] if ns else N, sid[n], sid[r] if r is not None else N)
                + H(8) + bytes([0, dt]) + P(d)
                for ns, n, dt, d, r in attrs)
            records.append(chunk(0x102, P(line, N),
                                 P(N, sid[name]) + H(20, 20, len(attrs), 0, 0, 0) + raw,
                                 header_size=16))
        elif item[0] == "end":
            records.append(chunk(0x103, P(1, N), P(N, sid[item[1]]), header_size=16))
        else:
            records.append(chunk(0x104, P(1, N),
                                 P(sid[item[1]]) + H(8) + bytes([0, 3]) + P(sid[item[1]]),
                                 header_size=16))
    for prefix, uri in reversed(namespaces):
        records.append(chunk(0x101, P(1, N), P(sid[prefix], sid[uri]), header_size=16))
    pool = string_pool(strings, utf8)
    rmap = chunk(0x180, b"", P(*(resource_map or [0] * len(strings))))
    data = pool + rmap + b"".join(records)
    return H(3, 8) + P(len(data) + 8) + data


def layout_axml() -> bytes:
    """A small layout: LinearLayout with a TextView child, android + app namespaces,
    a typed dimension, a reference, a boolean and a text child."""
    strings = ["android", ANDROID, "app", "http://schemas.android.com/apk/res-auto",
               "LinearLayout", "orientation", "layout_width", "layout_height", "TextView",
               "text", "textSize", "textColor", "enabled", "hello", "vertical",
               "match_parent", "wrap_content", "@7f010000", "16sp", "#ff336699", "true", ""]
    sid = {s: i for i, s in enumerate(strings)}
    elements = [
        ("start", "LinearLayout", [
            (ANDROID, "orientation", 0x10, sid["vertical"], "vertical"),
            (ANDROID, "layout_width", 0x10, sid["match_parent"], "match_parent"),
            (ANDROID, "layout_height", 0x10, sid["match_parent"], "match_parent"),
        ], 1),
        ("start", "TextView", [
            (ANDROID, "text", 1, 0x7F010000, None),
            (ANDROID, "textSize", 5, (16 << 8) | 2, "16sp"),
            (ANDROID, "textColor", 0x1C, 0xFF336699, "#ff336699"),
            (ANDROID, "enabled", 0x12, N, "true"),
            ("http://schemas.android.com/apk/res-auto", "text", 3, sid["hello"], "hello"),
        ], 2),
        ("text", "hello"),
        ("end", "TextView"),
        ("end", "LinearLayout"),
    ]
    # string-valued attributes must point at pool strings; fix the enum ones to string type
    fixed = []
    for item in elements:
        if item[0] == "start":
            attrs = []
            for ns, n, dt, d, r in item[2]:
                if r is not None and dt in (0x10,):
                    attrs.append((ns, n, 3, d, r))
                else:
                    attrs.append((ns, n, dt, d, r))
            fixed.append(("start", item[1], attrs, item[3]))
        else:
            fixed.append(item)
    rmap = [0] * len(strings)
    rmap[sid["text"]] = 0x7F010000
    return axml(fixed, strings, [("android", ANDROID), ("app", "http://schemas.android.com/apk/res-auto")], rmap)


# ---- the resource table of the fixtures ------------------------------------------

def small_arsc() -> bytes:
    """string/app_name (default, en, zh-rCN), string/greeting (default, en),
    layout/main (default), id/title (default), color/accent (default, night),
    dimen/margin (default, land), bool/flag (default), integer/count (default),
    style/AppTheme (bag, default + en), array/planets (bag, default),
    plurals/items (bag, default)."""
    value_strings = ["Hello", "你好", "Bonjour", "World", " planets ", "Mercury", "Venus",
                     "one", "other", "%d item", "%d items", "AppTheme", "colorAccent"]
    vs = {s: i for i, s in enumerate(value_strings)}
    type_names = ["string", "layout", "id", "color", "dimen", "bool", "integer", "style", "array", "plurals"]
    key_names = ["app_name", "greeting", "main", "title", "accent", "margin", "flag", "count",
                 "AppTheme", "planets", "items"]
    ks = {s: i for i, s in enumerate(key_names)}
    default = config()
    en = config(language=b"en")
    zh = config(language=b"zh", country=b"CN")
    land = config(orientation=2)
    night = config(size=56)
    night = bytearray(night); night[29] = 0x20; night = bytes(night)  # uiMode night = 0x20
    v21 = config(sdk=21)

    def s(i):  # string value
        return value(3, i)

    types = [
        {"id": 1, "specs": [0, 0], "configs": [
            (default, [simple_entry(ks["app_name"], 3, vs["Hello"]), simple_entry(ks["greeting"], 3, vs["World"])]),
            (en, [simple_entry(ks["app_name"], 3, vs["Bonjour"]), simple_entry(ks["greeting"], 3, vs["World"])]),
            (zh, [simple_entry(ks["app_name"], 3, vs["你好"]), None]),
        ]},
        {"id": 2, "specs": [0], "configs": [
            (default, [simple_entry(ks["main"], 3, vs["Hello"])]),  # layout: string path placeholder
        ]},
        {"id": 3, "specs": [0], "configs": [
            (default, [simple_entry(ks["title"], 0x10, 0)]),
        ]},
        {"id": 4, "specs": [0], "configs": [
            (default, [simple_entry(ks["accent"], 0x1C, 0xFF336699)]),
            (night, [simple_entry(ks["accent"], 0x1C, 0xFF112233)]),
        ]},
        {"id": 5, "specs": [0], "configs": [
            (default, [simple_entry(ks["margin"], 5, (8 << 8) | 1)]),   # 8dp
            (land, [simple_entry(ks["margin"], 5, (16 << 8) | 1)]),     # 16dp
        ]},
        {"id": 6, "specs": [0], "configs": [
            (default, [simple_entry(ks["flag"], 0x12, N)]),
        ]},
        {"id": 7, "specs": [0], "configs": [
            (default, [simple_entry(ks["count"], 0x10, 42)]),
        ]},
        {"id": 8, "specs": [0], "configs": [
            (default, [bag_entry(ks["AppTheme"], 0x01030000, [
                (0x01010000, 1, 0x7F040000),  # android:colorAccent -> @7f040000 (attr name id)
            ])]),
            (en, [bag_entry(ks["AppTheme"], 0x01030000, [
                (0x01010000, 3, vs["AppTheme"]),
            ])]),
        ]},
        {"id": 9, "specs": [0], "configs": [
            (default, [bag_entry(ks["planets"], 0, [
                (0x01000000, 3, vs["Mercury"]),
                (0x01000001, 3, vs["Venus"]),
            ])]),
        ]},
        {"id": 10, "specs": [0], "configs": [
            (default, [bag_entry(ks["items"], 0, [
                (0x01000004, 3, vs["%d item"]),   # one
                (0x01000005, 3, vs["%d items"]),  # other
            ])]),
        ]},
    ]
    # layout/main should be a string path "res/layout/main.xml"
    value_strings.append("res/layout/main.xml")
    vs["res/layout/main.xml"] = len(value_strings) - 1
    types[1]["configs"][0][1][0] = simple_entry(ks["main"], 3, vs["res/layout/main.xml"])
    return build_arsc("example.test", 0x7F, value_strings, type_names, key_names, types)


def apk(members: dict[str, bytes], deflate: set[str] = frozenset()) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED if name in deflate else zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, data)
    return buffer.getvalue()


def apk_with_repeated_name(members: list[tuple[str, bytes]]) -> bytes:
    """A stored archive that may name a member twice, which a dict cannot: the central directory lists both."""
    import warnings

    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns about the repeated name; that is the point
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            for name, data in members:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.external_attr = 0o644 << 16
                info.create_system = 3
                archive.writestr(info, data)
    return buffer.getvalue()


def tiny_dex() -> bytes:
    """Reuse the decode fixture's small DEX so the APKs have a real DEX member."""
    return (ROOT / "tests/fixtures/decode/generated/decode-v035.dex").read_bytes()


def manifest_bytes() -> bytes:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "manifest_fixture", ROOT / "tests/fixtures/manifest/generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data, _ = module.encode(typed=False)
    return data


def build_all() -> dict[str, bytes]:
    dex = tiny_dex()
    manifest = manifest_bytes()
    arsc = small_arsc()
    layout = layout_axml()
    text = "hello 世界\nline two\n".encode("utf-8")
    blob = bytes(range(256))
    base = {
        "AndroidManifest.xml": manifest,
        "classes.dex": dex,
        "resources.arsc": arsc,
        "res/layout/main.xml": layout,
        "res/raw/data.bin": blob,
        "assets/hello.txt": text,
        "assets/blob.bin": blob,
    }
    files = {
        "resources-small.apk": apk(base, deflate={"assets/hello.txt", "res/raw/data.bin"}),
        "resources-only.apk": apk({k: v for k, v in base.items() if k != "classes.dex"}),
        "resources-no-arsc.apk": apk({"AndroidManifest.xml": manifest, "classes.dex": dex,
                                      "assets/hello.txt": text}),
    }
    # two members of one name: neither is chosen for the reader
    files["resources-duplicate.apk"] = apk_with_repeated_name(
        [("classes.dex", dex), ("assets/dup.txt", b"one\n"), ("assets/dup.txt", b"two\n")])
    # damaged arsc: truncated, and bad magic
    files["resources-corrupt.apk"] = apk({**base, "resources.arsc": arsc[: len(arsc) // 2]})
    bad_magic = bytearray(arsc); bad_magic[0] = 9
    files["resources-bad-magic.apk"] = apk({**base, "resources.arsc": bytes(bad_magic)})
    # a CRC-damaged text entry: flip a byte of the stored data after writing
    good = apk(base)
    damaged = bytearray(good)
    at = good.find(b"hello ")
    damaged[at] ^= 0xFF
    files["resources-bad-crc.apk"] = bytes(damaged)
    return files


def main(argv: list[str]) -> int:
    files = build_all()
    OUT.mkdir(exist_ok=True)
    manifest = {
        "schema_version": "mdd.resources-fixtures.v1",
        "generator": "tests/fixtures/resources/generate.py",
        "note": "synthetic layout fixtures, not installable APKs; resources.arsc and AXML are assembled here by hand",
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                  for name, data in sorted(files.items())},
    }
    if "--check" in argv:
        recorded = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
        same = recorded == manifest and all((OUT / n).read_bytes() == d for n, d in files.items())
        print("fixtures reproduce byte for byte:", same)
        return 0 if same else 1
    for name, data in files.items():
        (OUT / name).write_bytes(data)
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n",
                                        encoding="utf-8", newline="\n")
    print({n: len(d) for n, d in files.items()})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))