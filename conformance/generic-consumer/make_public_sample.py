#!/usr/bin/env python3
"""Deterministic generator and verifier for MDD-065 public multi-DEX sample APK.

Standard library + sibling conformance/mcp/tiny_dex.py only; never imports the engine under test.
Builds a self-contained public APK (`org.publicdemo.auditapp`) containing:
- AndroidManifest.xml (binary AXML) with exported and non-exported components;
- 5 DEX members where `classes4.dex` is byte-identical to `classes3.dex` (physical deduplication
  vs logical occurrence multiplicity: 5 occurrences, 4 unique content SHA-256 digests);
- Cross-DEX invoke edges (`classes.dex` -> `classes3.dex`/`classes4.dex` -> `classes5.dex`);
- Multiple calls to the same callee inside one caller (call-site multiplicity 2 vs 1 distinct edge);
- MUTF-8 string containing embedded NUL (`"audit\\u0000tag"`).

Usage:
    python -I conformance/generic-consumer/make_public_sample.py
    python -I conformance/generic-consumer/make_public_sample.py --check
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
ROOT = HERE.parents[1]
FIXTURES_DIR = HERE / "fixtures"
APK_PATH = FIXTURES_DIR / "public-app-audit.apk"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"

sys.path.insert(0, str(ROOT / "conformance" / "mcp"))
import tiny_dex  # noqa: E402

ANDROID_NS = "http://schemas.android.com/apk/res/android"
NO_INDEX = 0xFFFFFFFF


def _u16(*vals: int) -> bytes:
    return struct.pack("<" + "H" * len(vals), *vals)


def _u32(*vals: int) -> bytes:
    return struct.pack("<" + "I" * len(vals), *vals)


def _chunk(kind: int, header: bytes, payload: bytes) -> bytes:
    return _u16(kind, len(header) + 8) + _u32(len(header) + len(payload) + 8) + header + payload


def _len8(value: int) -> bytes:
    return bytes([value]) if value < 128 else bytes([0x80 | (value >> 8), value & 0xFF])


def _string_pool(values: list[str]) -> bytes:
    data = bytearray()
    offsets: list[int] = []
    for text in values:
        offsets.append(len(data))
        units = text.encode("utf-16-le", "surrogatepass")
        raw = text.encode("utf-8")
        data += _len8(len(units) // 2) + _len8(len(raw)) + raw + b"\0"
    data += b"\0" * (-len(data) % 4)
    begin = 28 + 4 * len(offsets)
    header = _u32(len(values), 0, 0x100, begin, 0)
    return _chunk(1, header, _u32(*offsets) + bytes(data))


def _build_manifest_axml() -> bytes:
    strings = [
        "android",
        ANDROID_NS,
        "manifest",
        "package",
        "versionCode",
        "versionName",
        "uses-sdk",
        "minSdkVersion",
        "targetSdkVersion",
        "uses-permission",
        "name",
        "application",
        "label",
        "activity",
        "service",
        "receiver",
        "exported",
        "org.publicdemo.auditapp",
        "1.0",
        "android.permission.INTERNET",
        "PublicDemoAudit",
        "org.publicdemo.auditapp.MainActivity",
        ".SyncService",
        "org.publicdemo.auditapp.InternalWorker",
    ]
    sid = {value: idx for idx, value in enumerate(strings)}
    records: list[bytes] = []

    def node(kind: int, payload: bytes, line: int = 1) -> bytes:
        return _chunk(kind, _u32(line, NO_INDEX), payload)

    def attr_str(ns: str | None, name: str, val: str) -> bytes:
        return (
            _u32(sid[ns] if ns else NO_INDEX, sid[name], sid[val])
            + _u16(8)
            + bytes([0, 3])
            + _u32(sid[val])
        )

    def attr_typed(ns: str | None, name: str, data_type: int, data_word: int) -> bytes:
        return (
            _u32(sid[ns] if ns else NO_INDEX, sid[name], NO_INDEX)
            + _u16(8)
            + bytes([0, data_type])
            + _u32(data_word)
        )

    def start(tag: str, attrs: list[bytes], line: int = 1) -> None:
        records.append(
            node(
                0x102,
                _u32(NO_INDEX, sid[tag]) + _u16(20, 20, len(attrs), 0, 0, 0) + b"".join(attrs),
                line=line,
            )
        )

    def end(tag: str, line: int = 1) -> None:
        records.append(node(0x103, _u32(NO_INDEX, sid[tag]), line=line))

    records.append(node(0x100, _u32(sid["android"], sid[ANDROID_NS])))
    start(
        "manifest",
        [
            attr_str(None, "package", "org.publicdemo.auditapp"),
            attr_typed(ANDROID_NS, "versionCode", 0x10, 1),
            attr_str(ANDROID_NS, "versionName", "1.0"),
        ],
    )
    start(
        "uses-sdk",
        [
            attr_typed(ANDROID_NS, "minSdkVersion", 0x10, 24),
            attr_typed(ANDROID_NS, "targetSdkVersion", 0x10, 34),
        ],
    )
    end("uses-sdk")
    start("uses-permission", [attr_str(ANDROID_NS, "name", "android.permission.INTERNET")])
    end("uses-permission")
    start("application", [attr_str(ANDROID_NS, "label", "PublicDemoAudit")])
    start(
        "activity",
        [
            attr_str(ANDROID_NS, "name", "org.publicdemo.auditapp.MainActivity"),
            attr_typed(ANDROID_NS, "exported", 0x12, NO_INDEX),
        ],
    )
    end("activity")
    start(
        "service",
        [
            attr_str(ANDROID_NS, "name", ".SyncService"),
            attr_typed(ANDROID_NS, "exported", 0x12, NO_INDEX),
        ],
    )
    end("service")
    start(
        "receiver",
        [
            attr_str(ANDROID_NS, "name", "org.publicdemo.auditapp.InternalWorker"),
            attr_typed(ANDROID_NS, "exported", 0x12, 0),
        ],
    )
    end("receiver")
    end("application")
    end("manifest")
    records.append(node(0x101, _u32(sid["android"], sid[ANDROID_NS])))

    resources = [0] * len(strings)
    for name, res_id in (
        ("label", 0x01010001),
        ("name", 0x01010003),
        ("exported", 0x01010010),
        ("minSdkVersion", 0x0101020C),
        ("versionCode", 0x0101021B),
        ("versionName", 0x0101021C),
        ("targetSdkVersion", 0x01010270),
    ):
        resources[sid[name]] = res_id

    payload = _string_pool(strings) + _chunk(0x180, b"", _u32(*resources)) + b"".join(records)
    return _u16(3, 8) + _u32(len(payload) + 8) + payload


def _method(name: str, *ops: tuple) -> dict:
    return {"name": name, "access": 0x9, "registers": 1, "outs": 0, "code": list(ops)}


def build_sample_apk() -> tuple[bytes, dict]:
    """Return deterministic APK bytes and ground-truth member summary."""
    dex1 = tiny_dex.build(
        "Lorg/publicdemo/auditapp/MainActivity;",
        [
            _method(
                "onCreate",
                ("const-string", 0, "https://api.example.org/v1/ping"),
                ("const-string", 0, "audit\u0000tag"),
                ("invoke-static", "Lorg/publicdemo/net/Transport;", "connect"),
                ("invoke-static", "Lorg/publicdemo/net/Transport;", "connect"),
                ("return-void",),
            ),
            _method("helper", ("return-void",)),
        ],
    )
    dex2 = tiny_dex.build(
        "Lorg/publicdemo/auditapp/SyncService;",
        [
            _method(
                "runSync",
                ("const-string", 0, "sync-start"),
                ("invoke-static", "Lorg/publicdemo/net/Transport;", "connect"),
                ("return-void",),
            )
        ],
    )
    dex3 = tiny_dex.build(
        "Lorg/publicdemo/net/Transport;",
        [
            _method(
                "connect",
                ("const-string", 0, "TLSv1.3"),
                ("invoke-static", "Lorg/publicdemo/crypto/Digest;", "verify"),
                ("return-void",),
            )
        ],
    )
    # Intentionally duplicate classes3.dex into classes4.dex to verify occurrence multiplicity.
    dex4 = bytes(dex3)
    dex5 = tiny_dex.build(
        "Lorg/publicdemo/crypto/Digest;",
        [
            _method(
                "verify",
                ("const-string", 0, "SHA-256"),
                ("return-void",),
            )
        ],
    )
    manifest_axml = _build_manifest_axml()
    members = [
        ("AndroidManifest.xml", manifest_axml),
        ("classes.dex", dex1),
        ("classes2.dex", dex2),
        ("classes3.dex", dex3),
        ("classes4.dex", dex4),
        ("classes5.dex", dex5),
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, raw in members:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            info.create_system = 3
            zf.writestr(info, raw)
    apk_bytes = buf.getvalue()
    manifest = {
        "schema": "mdd.generic-consumer-fixture-manifest.v1",
        "apk": "public-app-audit.apk",
        "apk_bytes": len(apk_bytes),
        "apk_sha256": hashlib.sha256(apk_bytes).hexdigest(),
        "dex_members": [
            {
                "entry_name": name,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            for name, raw in members
            if name.endswith(".dex")
        ],
        "unique_dex_digests": len({hashlib.sha256(raw).hexdigest() for name, raw in members if name.endswith(".dex")}),
    }
    return apk_bytes, manifest


def main(argv: list[str] | None = None) -> int:
    check_only = "--check" in (argv if argv is not None else sys.argv[1:])
    apk_bytes, manifest = build_sample_apk()
    manifest_text = json.dumps(manifest, indent=2) + "\n"
    if check_only:
        if not APK_PATH.is_file() or APK_PATH.read_bytes() != apk_bytes:
            print(f"fixture mismatch: {APK_PATH}", file=sys.stderr)
            return 1
        if not MANIFEST_PATH.is_file() or MANIFEST_PATH.read_text(encoding="utf-8") != manifest_text:
            print(f"manifest mismatch: {MANIFEST_PATH}", file=sys.stderr)
            return 1
        print("generic-consumer sample fixture matches generator")
        return 0
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    APK_PATH.write_bytes(apk_bytes)
    MANIFEST_PATH.write_text(manifest_text, encoding="utf-8", newline="\n")
    print(f"wrote {APK_PATH.name} ({len(apk_bytes)} bytes) and {MANIFEST_PATH.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
