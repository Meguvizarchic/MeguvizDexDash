"""Extended A0 oracle probes for MDD-072: typed XML rendering, rich components,
pagination units, directory entries, combined qualifiers, session errors.

Read-only oracle use; synthetic inputs only. Writes answers to out.json.
Usage: python probe_extra.py <resources-fixture-dir> <manifest-fixture-dir> <out.json>
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


def apk_bytes(entries, dex=True):
    """entries: list of (name, bytes, is_dir). Stored ZIP, fixed timestamp."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data, is_dir in entries:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            if is_dir:
                info.external_attr = 0o40755 << 16
                z.writestr(info, b"")
            else:
                z.writestr(info, data)
        if dex:
            z.writestr("classes.dex", g.tiny_dex())
    return buf.getvalue()


def rich_manifest(target_sdk):
    A = g.ANDROID
    strings = ["android", A, "manifest", "package", "example.rich", "versionCode", "versionName",
               "9.0", "uses-sdk", "minSdkVersion", "targetSdkVersion", "uses-permission", "name",
               "android.permission.INTERNET", "uses-permission-sdk-23", "android.permission.CAMERA",
               "permission", "example.rich.PERMISSION", "protectionLevel", "signature",
               "application", "label", "Rich", "icon", "debuggable", "allowBackup",
               "activity", ".Home", "exported", "launchMode", "intent-filter", "action",
               "android.intent.action.MAIN", "category", "android.intent.category.LAUNCHER",
               "meta-data", "meta.key", "meta.value", "value", "android.intent.action.VIEW",
               "android.intent.category.DEFAULT", "data", "scheme", "https", "host", "example.com",
               ".Other", "activity-alias", ".AliasHome", "targetActivity", "service", ".Disabled",
               "enabled", "receiver", ".Boot", "android.intent.action.BOOT_COMPLETED",
               "provider", ".Prov", "authorities", "example.rich.provider", "grantUriPermissions",
               "true", "false", ""]
    sid = {s: i for i, s in enumerate(strings)}

    def at(name, dt, d, raw=None, ns=A):
        return (ns, name, dt, d, raw)

    def st(name, attrs, line=1):
        return ("start", name, attrs, line)

    elements = [
        st("manifest", [(None, "package", 3, sid["example.rich"], "example.rich"),
                        at("versionCode", 0x10, 9), at("versionName", 3, sid["9.0"], "9.0")]),
        st("uses-sdk", [at("minSdkVersion", 0x10, 21), at("targetSdkVersion", 0x10, target_sdk)]),
        ("end", "uses-sdk"),
        st("uses-permission", [at("name", 3, sid["android.permission.INTERNET"], "android.permission.INTERNET")]),
        ("end", "uses-permission"),
        st("uses-permission-sdk-23", [at("name", 3, sid["android.permission.CAMERA"], "android.permission.CAMERA")]),
        ("end", "uses-permission-sdk-23"),
        st("permission", [at("name", 3, sid["example.rich.PERMISSION"], "example.rich.PERMISSION"),
                          at("protectionLevel", 3, sid["signature"], "signature")]),
        ("end", "permission"),
        st("application", [at("label", 3, sid["Rich"], "Rich"), at("icon", 1, 0x7F020000),
                           at("debuggable", 0x12, N_TRUE := 0xFFFFFFFF, "true"),
                           at("allowBackup", 0x12, 0, "false")]),
        st("activity", [at("name", 3, sid[".Home"], ".Home"), at("exported", 0x12, N_TRUE, "true"),
                        at("launchMode", 0x10, 2)]),
        st("intent-filter", []),
        st("action", [at("name", 3, sid["android.intent.action.MAIN"], "android.intent.action.MAIN")]),
        ("end", "action"),
        st("category", [at("name", 3, sid["android.intent.category.LAUNCHER"], "android.intent.category.LAUNCHER")]),
        ("end", "category"),
        ("end", "intent-filter"),
        st("meta-data", [at("name", 3, sid["meta.key"], "meta.key"),
                         at("value", 3, sid["meta.value"], "meta.value")]),
        ("end", "meta-data"),
        ("end", "activity"),
        st("activity", [at("name", 3, sid[".Other"], ".Other")]),
        st("intent-filter", []),
        st("action", [at("name", 3, sid["android.intent.action.VIEW"], "android.intent.action.VIEW")]),
        ("end", "action"),
        st("category", [at("name", 3, sid["android.intent.category.DEFAULT"], "android.intent.category.DEFAULT")]),
        ("end", "category"),
        st("data", [at("scheme", 3, sid["https"], "https"), at("host", 3, sid["example.com"], "example.com")]),
        ("end", "data"),
        ("end", "intent-filter"),
        ("end", "activity"),
        st("activity-alias", [at("name", 3, sid[".AliasHome"], ".AliasHome"),
                              at("targetActivity", 3, sid[".Home"], ".Home"),
                              at("exported", 0x12, 0, "false")]),
        ("end", "activity-alias"),
        st("service", [at("name", 3, sid[".Disabled"], ".Disabled"), at("enabled", 0x12, 0, "false"),
                       at("exported", 0x12, N_TRUE, "true"),
                       at("permission", 3, sid["example.rich.PERMISSION"], "example.rich.PERMISSION")]),
        ("end", "service"),
        st("receiver", [at("name", 3, sid[".Boot"], ".Boot")]),
        st("intent-filter", []),
        st("action", [at("name", 3, sid["android.intent.action.BOOT_COMPLETED"], "android.intent.action.BOOT_COMPLETED")]),
        ("end", "action"),
        ("end", "intent-filter"),
        ("end", "receiver"),
        st("provider", [at("name", 3, sid[".Prov"], ".Prov"),
                        at("authorities", 3, sid["example.rich.provider"], "example.rich.provider"),
                        at("exported", 0x12, 0, "false"), at("grantUriPermissions", 0x12, N_TRUE, "true")]),
        ("end", "provider"),
        ("end", "application"),
        ("end", "manifest"),
    ]
    return g.axml(elements, strings, [("android", A)])


def qualifier_arsc():
    """One string type with combined-qualifier configs to pin qualifier spelling/order."""
    values = ["Default", "English", "EnglishLand", "Hdpi", "V21", "ZhPort"]
    types = [{"id": 1, "specs": [2], "configs": [
        (g.config(), [g.simple_entry(0, 3, 0)]),
        (g.config(language=b"en"), [g.simple_entry(0, 3, 1)]),
        (g.config(language=b"en", orientation=2), [g.simple_entry(0, 3, 2)]),
        (g.config(density=240), [g.simple_entry(0, 3, 3)]),
        (g.config(sdk=21), [g.simple_entry(0, 3, 4)]),
        (g.config(language=b"zh", country=b"CN", orientation=1), [g.simple_entry(0, 3, 5)]),
    ]}]
    return g.build_arsc("example.qual", 0x7F, values, ["string"], ["label"], types)


def run_session(c, tmp, label, data, calls, out):
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


def main():
    if hashlib.sha256(A0.read_bytes()).hexdigest() != PINNED:
        print("refused: binary hash mismatch", file=sys.stderr)
        return 2
    rfd, mfd = Path(sys.argv[1]), Path(sys.argv[2])
    out = {}
    tmp = Path(tempfile.mkdtemp(prefix="mdd072-extra-"))
    c = Client(A0)
    c.initialize()

    # A. Manifest fixture vectors wrapped as APKs: summary + xml rendering.
    for name in ["utf8", "utf16", "all-typed-values", "long-utf8", "unpaired-value-utf16",
                 "styled-utf8", "aliased-pool", "shadowed-uri", "ambiguous-prefix",
                 "duplicate-attribute"]:
        axml = (mfd / "generated" / f"{name}.axml").read_bytes()
        run_session(c, tmp, f"manifest-{name}", apk_bytes([("AndroidManifest.xml", axml, False)]), [
            ("get_manifest", {}),
            ("get_manifest", {"mode": "xml"}),
            ("get_manifest", {"mode": "xml", "max_bytes": 4096}),
        ], out)

    # B. Rich manifests: components semantics.
    for label, sdk in [("rich", 35), ("rich-old", 16)]:
        run_session(c, tmp, label, apk_bytes([("AndroidManifest.xml", rich_manifest(sdk), False)]), [
            ("get_manifest", {}),
            ("get_manifest", {"mode": "xml"}),
            ("get_manifest_components", {}),
            ("get_manifest_components", {"only_exported": True}),
            ("get_manifest_components", {"kind": "activity"}),
            ("get_manifest_components", {"kind": "activity-alias"}),
            ("get_manifest_components", {"kind": "service"}),
            ("get_manifest_components", {"limit": 2, "offset": 2}),
            ("get_manifest_components", {"only_exported": True, "kind": "provider"}),
        ], out)

    # C. Pagination units, directories, empty files.
    big_text = "".join(f"line {i:04d}\n" for i in range(600)).encode()  # 6000 bytes
    big_bin = bytes(range(256)) * 24  # 6144 bytes
    multi = ("a" * 4094 + "世界" + "b" * 100 + "\n").encode()  # multibyte across 4096 boundary
    entries = [("assets/big.txt", big_text, False), ("assets/big.bin", big_bin, False),
               ("assets/multi.txt", multi, False), ("assets/empty.txt", b"", False),
               ("res/", b"", True), ("res/raw/", b"", True), ("res/raw/x.bin", b"\x01\x02", False)]
    run_session(c, tmp, "paging", apk_bytes(entries), [
        ("list_resource_files", {}),
        ("read_resource", {"name": "assets/big.txt"}),
        ("read_resource", {"name": "assets/big.txt", "max_bytes": 4096}),
        ("read_resource", {"name": "assets/big.txt", "offset": 4090, "max_bytes": 4096}),
        ("read_resource", {"name": "assets/big.txt", "offset": 6000}),
        ("read_resource", {"name": "assets/big.bin"}),
        ("read_resource", {"name": "assets/big.bin", "max_bytes": 4096}),
        ("read_resource", {"name": "assets/big.bin", "offset": 2048, "max_bytes": 4096}),
        ("read_resource", {"name": "assets/big.bin", "offset": 6144}),
        ("read_resource", {"name": "assets/multi.txt", "max_bytes": 4096}),
        ("read_resource", {"name": "assets/multi.txt", "offset": 4095}),
        ("read_resource", {"name": "assets/multi.txt", "offset": 4096}),
        ("read_resource", {"name": "assets/empty.txt"}),
        ("read_resource", {"name": "assets/empty.txt", "format": "hex"}),
        ("read_resource", {"name": "res/"}),
        ("read_resource", {"name": "res/raw/x.bin"}),
        ("read_resource", {"name": "assets/big.txt", "format": "hex", "max_bytes": 4096}),
        ("read_resource", {"name": "assets/big.txt", "timeout_ms": 0}),
        ("read_resource", {"name": "assets/big.txt", "input_index": 3}),
    ], out)

    # D. Qualifier spelling and selector edges.
    run_session(c, tmp, "qualifiers", apk_bytes([("resources.arsc", qualifier_arsc(), False)]), [
        ("query_resources", {}),
        ("query_resources", {"configuration": "en-land"}),
        ("query_resources", {"configuration": "hdpi"}),
        ("query_resources", {"configuration": "v21"}),
        ("query_resources", {"configuration": "zh-rCN-port"}),
        ("query_resources", {"configuration": "land"}),
        ("query_resources", {"name": "label"}),
        ("query_resources", {"name": "string/"}),
        ("query_resources", {"name": "bogus:string/label"}),
        ("query_resources", {"resource_type": "bogus"}),
        ("query_resources", {"resource_id": 0}),
        ("query_resources", {"contains": "LABEL"}),
        ("query_resources", {"contains": "label"}),
        ("query_resources", {"max_bytes": 4096}),
        ("query_resources", {"timeout_ms": 0}),
        ("query_resources", {"resource_id": 4294967296}),
    ], out)

    # E. Session-level errors and multi-input selection.
    p_small = rfd / "resources-small.apk"
    opened = c.call("open_dataset", {"inputs": [str(p_small)]})
    ds = opened["reply"]["dataset_id"]
    out["session-errors"] = {
        "unknown_dataset": c.call("read_resource", {"dataset_id": "dataset-999", "name": "assets/hello.txt"}),
        "manifest_input_index_1": c.call("get_manifest", {"dataset_id": ds, "input_index": 1}),
        "read_input_index_1": c.call("read_resource", {"dataset_id": ds, "name": "assets/hello.txt", "input_index": 1}),
        "query_input_index_1": c.call("query_resources", {"dataset_id": ds, "input_index": 1}),
        "list_input_index_1": c.call("list_resource_files", {"dataset_id": ds, "input_index": 1}),
        "components_input_index_1": c.call("get_manifest_components", {"dataset_id": ds, "input_index": 1}),
        "manifest_timeout_0": c.call("get_manifest", {"dataset_id": ds, "timeout_ms": 0}),
        "manifest_mode_bogus": c.call("get_manifest", {"dataset_id": ds, "mode": "bogus"}),
        "read_format_bogus": c.call("read_resource", {"dataset_id": ds, "name": "assets/hello.txt", "format": "bogus"}),
        "components_max_bytes_0": c.call("get_manifest_components", {"dataset_id": ds, "max_bytes": 0}),
        "list_max_bytes_0": c.call("list_resource_files", {"dataset_id": ds, "max_bytes": 0}),
        "query_max_bytes_0": c.call("query_resources", {"dataset_id": ds, "max_bytes": 0}),
        "manifest_xml_limit_0": c.call("get_manifest", {"dataset_id": ds, "mode": "xml", "limit": 0}),
    }
    closed = c.call("close_dataset", {"dataset_id": ds})
    out["session-errors"]["close"] = closed
    out["session-errors"]["read_after_close"] = c.call("read_resource", {"dataset_id": ds, "name": "assets/hello.txt"})
    out["session-errors"]["query_after_close"] = c.call("query_resources", {"dataset_id": ds})

    # No-manifest APK.
    run_session(c, tmp, "no-manifest", apk_bytes([("assets/hello.txt", b"hi\n", False)]), [
        ("get_manifest", {}),
        ("get_manifest", {"mode": "xml"}),
        ("get_manifest_components", {}),
    ], out)

    # Multi-input: second archive carries the resources.
    p_a = tmp / "multi-a.apk"
    p_a.write_bytes(apk_bytes([("assets/a.txt", b"alpha\n", False)]))
    p_b = tmp / "multi-b.apk"
    p_b.write_bytes((rfd / "resources-small.apk").read_bytes())
    opened = c.call("open_dataset", {"inputs": [str(p_a), str(p_b)]})
    sess = {"open": opened}
    if not opened.get("is_error") and "reply" in opened:
        ds2 = opened["reply"]["dataset_id"]
        for i, (tool, args) in enumerate([
            ("list_resource_files", {}),
            ("list_resource_files", {"input_index": 1}),
            ("read_resource", {"name": "assets/hello.txt"}),
            ("read_resource", {"name": "assets/hello.txt", "input_index": 1}),
            ("read_resource", {"name": "assets/a.txt"}),
            ("query_resources", {"resource_type": "string"}),
            ("query_resources", {"resource_type": "string", "input_index": 1}),
            ("get_manifest", {"mode": "xml"}),
            ("get_manifest", {"mode": "xml", "input_index": 1}),
            ("get_manifest_components", {"input_index": 1}),
        ]):
            sess[f"{i:02d} {tool} {json.dumps(args, ensure_ascii=False)}"] = c.call(
                tool, {"dataset_id": ds2, **args})
    out["multi-input"] = sess
    c.close()
    Path(sys.argv[3]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", sys.argv[3])
    return 0


if __name__ == "__main__":
    sys.exit(main())