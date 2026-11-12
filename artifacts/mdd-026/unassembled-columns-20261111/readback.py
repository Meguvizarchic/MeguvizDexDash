#!/usr/bin/env python3
"""Independent readback for the five formerly unassembled MDD-026 columns.

The native values are produced by the temporary probe `probe_rows.rs` (it calls
the production row APIs on the same fixtures). This script never imports the
Rust parser: it recomputes every expected value from the raw fixture bytes, the
recorded A0 dumps and the archive directory, and compares them with the probe
output.

Scope: tiny development fixtures. This is not a profile admission and does not
prove task completion.
"""
import hashlib
import json
import pathlib
import struct
import sys
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PROBE = HERE / "native-rows.json"
A0_METHODS = ROOT / "artifacts/mdd-026/method-atom-audit/20261028T165707192974Z"
A0_DEX_FILES = (
    ROOT
    / "artifacts/mdd-026/column-audit-v10/_probe-verify_cross_dex_identity"
    / "20261109T045613053519Z/result.json"
)

FIXTURES = {
    "classic": (
        "tests/fixtures/references/generated/classic-035.dex",
        "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8",
    ),
    "shared": (
        "tests/fixtures/references/generated/shared-code-035.dex",
        "22eb2d4020f172334a99f5c75538af5f2b3e80673adb11803b368cc68aaec0ab",
    ),
    "definitions": (
        "tests/fixtures/definitions/generated/definitions-035.dex",
        "4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc",
    ),
    "dynamic": (
        "tests/fixtures/references/generated/poly-custom-038.dex",
        "25bc5a03641d31d87212a9a292d798e64c563e2666d03f579e7fc894ac8ee425",
    ),
}

FAILURES = []


def require(condition, message):
    if not condition:
        FAILURES.append(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def u32(raw, at):
    return struct.unpack_from("<I", raw, at)[0]


def uleb128(raw, at):
    result = 0
    shift = 0
    while True:
        byte = raw[at]
        at += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return result, at
        shift += 7


def mutf8(raw, at):
    """Decode one MUTF-8 string_data payload into (text, end_offset)."""
    _, at = uleb128(raw, at)
    units = []
    while raw[at] != 0:
        lead = raw[at]
        if lead < 0x80:
            units.append(lead)
            at += 1
        elif lead & 0xE0 == 0xC0:
            units.append(((lead & 0x1F) << 6) | (raw[at + 1] & 0x3F))
            at += 2
        else:
            unit = ((lead & 0x0F) << 12) | ((raw[at + 1] & 0x3F) << 6) | (raw[at + 2] & 0x3F)
            units.append(unit)
            at += 3
    return "".join(chr(u) if not 0xD800 <= u <= 0xDFFF else "\ufffd" for u in units), at + 1


def dex_strings(raw):
    count = u32(raw, 56)
    off = u32(raw, 60)
    return [mutf8(raw, u32(raw, off + 4 * i))[0] for i in range(count)]


def dex_type_descriptors(raw):
    count = u32(raw, 64)
    off = u32(raw, 68)
    strings = dex_strings(raw)
    return [strings[u32(raw, off + 4 * i)] for i in range(count)]


def method_param_vectors(raw):
    """Recompute each method_id's ordered parameter descriptor vector."""
    proto_count = u32(raw, 72)
    proto_off = u32(raw, 76)
    methods_count = u32(raw, 88)
    methods_off = u32(raw, 92)
    descriptors = dex_type_descriptors(raw)
    # Locate the TYPE_LIST section through the physical map, never by guessing.
    map_off = u32(raw, 52)
    map_size = u32(raw, map_off)
    has_type_list = False
    for i in range(map_size):
        at = map_off + 4 + i * 12
        if struct.unpack_from("<H", raw, at)[0] == 0x1001:
            has_type_list = True
    result = []
    for index in range(methods_count):
        at = methods_off + index * 8
        proto_idx = struct.unpack_from("<H", raw, at + 2)[0]
        require(proto_idx < proto_count, f"method {index} proto index out of range")
        parameters_off = u32(raw, proto_off + proto_idx * 12 + 8)
        if parameters_off == 0:
            result.append([])
            continue
        # A non-zero parameter list must live in the declared TYPE_LIST section.
        require(has_type_list, f"method {index} has parameters but no TYPE_LIST section")
        count = u32(raw, parameters_off)
        entries = [struct.unpack_from("<H", raw, parameters_off + 4 + 2 * i)[0] for i in range(count)]
        result.append([descriptors[entry] for entry in entries])
    return result


def a0_rows(path, columns):
    rows = []
    header = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if set("".join(cells)) <= set("-"):
            continue
        row = {}
        for name, cell in zip(header, cells):
            row[name] = None if cell == "N" else bytes.fromhex(cell).decode("utf-8")
        rows.append(row)
    require(header == columns, f"A0 header mismatch in {path}")
    return rows


def main():
    require(PROBE.is_file(), "native-rows.json is missing; run the probe first")
    if not PROBE.is_file():
        return 1
    native = json.loads(PROBE.read_text(encoding="utf-8"))
    require(native["task_complete_proven"] is False, "probe must not claim completion")
    require(native["profile_admitted"] is False, "probe must not claim a profile")

    # --- 1. dex_files.source_path / entry_name ------------------------------
    recorded = json.loads(A0_DEX_FILES.read_text(encoding="utf-8"))
    dex_cases = {entry["case"]: entry["a0_dex_rows"] for entry in recorded["cases"]}
    for label, expected_rows in native["dex_files"].items():
        recorded_rows = dex_cases[label]
        require(len(expected_rows) == len(recorded_rows), f"{label}: row count")
        for ordinal, (actual, expected) in enumerate(zip(expected_rows, recorded_rows)):
            for column in ("file_id", "string_pool_id"):
                require(
                    int(actual[column]) == int(expected[column]),
                    f"{label} row {ordinal} {column}: {actual[column]} != {expected[column]}",
                )
            for column in ("source_path", "entry_name"):
                require(
                    actual[column] == expected[column],
                    f"{label} row {ordinal} {column}: {actual[column]!r} != {expected[column]!r}",
                )
            require(
                actual["entry_name"] == pathlib.PurePath(actual["entry_name"]).name
                or "/" in actual["entry_name"],
                f"{label} row {ordinal} entry_name is not a member/leaf name",
            )

    # The APK case is additionally re-derived from the archive directory itself.
    apk = ROOT / (
        "artifacts/mdd-026/column-audit-v10/_probe-verify_cross_dex_identity"
        "/20261109T045613053519Z/synthetic-same-content.apk"
    )
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
    apk_rows = native["dex_files"]["same-content-multidex-apk"]
    require(
        [row["entry_name"] for row in apk_rows] == names,
        "APK entry names must follow the central directory order",
    )
    require(
        {row["source_path"] for row in apk_rows} == {str(apk)},
        "every APK member must carry the one captured source path",
    )

    # Raw DEX: the source path is the fixture path and entry_name its file name.
    for label, fixture in (("duplicate-raw-input", "classic"), ("two-distinct-raw", "classic")):
        path = ROOT / FIXTURES[fixture][0]
        require(
            native["dex_files"][label][0]["source_path"] == str(path),
            f"{label}: raw DEX source_path is not the captured path",
        )
        require(
            native["dex_files"][label][0]["entry_name"] == path.name,
            f"{label}: raw DEX entry_name is not the captured file name",
        )

    # --- 2/3. methods.param_descriptors and the two opcode columns -----------
    for case, fixture, expected_rows in (
        ("definitions", "definitions", 13),
        ("shared", "shared", 5),
        ("dynamic", "dynamic", 6),
    ):
        raw = (ROOT / FIXTURES[fixture][0]).read_bytes()
        require(digest(ROOT / FIXTURES[fixture][0]) == FIXTURES[fixture][1], f"{fixture} bytes changed")
        vectors = method_param_vectors(raw)
        expected = a0_rows(
            A0_METHODS / f"a0-{case}" / "stdout.txt",
            [
                "file_id",
                "method_idx",
                "class_idx",
                "class_descriptor",
                "proto_idx",
                "name",
                "descriptor",
                "return_descriptor",
                "param_count",
                "param_descriptors",
                "access_flags",
                "opcode_count",
                "opcode_hex",
                "method_kind",
            ],
        )
        require(len(expected) == expected_rows, f"{case}: A0 row count changed")
        actual = native["methods"][case]
        require(len(actual) == len(expected), f"{case}: native row count differs from A0")
        for expected_row, actual_row in zip(expected, actual):
            index = int(expected_row["method_idx"])
            # param_descriptors: independent comma join of the byte-derived vector.
            independent = ",".join(vectors[index])
            require(
                independent == expected_row["param_descriptors"],
                f"{case} method {index}: byte-derived vector differs from A0",
            )
            require(
                actual_row["param_descriptors"] == independent,
                f"{case} method {index}: native param_descriptors {actual_row['param_descriptors']!r} "
                f"!= byte-derived {independent!r}",
            )
            require(
                int(actual_row["param_count"]) == len(vectors[index]),
                f"{case} method {index}: param_count",
            )
            # opcode columns are exactly the recorded A0 values. A0 stores every
            # non-NULL cell as UTF-8 text, so the numeric column is parsed.
            expected_count = (
                None
                if expected_row["opcode_count"] is None
                else int(expected_row["opcode_count"])
            )
            require(
                actual_row["opcode_count"] == expected_count,
                f"{case} method {index} opcode_count: {actual_row['opcode_count']!r} != "
                f"{expected_count!r}",
            )
            require(
                actual_row["opcode_hex"] == expected_row["opcode_hex"],
                f"{case} method {index} opcode_hex: {actual_row['opcode_hex']!r} != "
                f"{expected_row['opcode_hex']!r}",
            )
            # NULL only when there is no definition body at all.
            if expected_row["access_flags"] is None:
                require(
                    actual_row["opcode_count"] is None and actual_row["opcode_hex"] is None,
                    f"{case} method {index}: reference-only row must be NULL",
                )
            else:
                require(
                    actual_row["opcode_count"] is not None
                    and actual_row["opcode_hex"] is not None,
                    f"{case} method {index}: defined row must not be NULL",
                )
                require(
                    int(actual_row["opcode_count"]) * 3 - (1 if int(actual_row["opcode_count"]) else 0)
                    == len(actual_row["opcode_hex"]),
                    f"{case} method {index}: opcode_hex length disagrees with the count",
                )

    summary = {
        "status": "passed" if not FAILURES else "failed",
        "failures": FAILURES,
        "checks": {
            "dex_file_rows_compared": sum(len(rows) for rows in native["dex_files"].values()),
            "methods_rows_compared": sum(len(rows) for rows in native["methods"].values()),
        },
        "probe_sha256": digest(PROBE),
        "readback_source_sha256": digest(pathlib.Path(__file__).resolve()),
        "task_complete_proven": False,
        "profile_admitted": False,
        "scope": "tiny development fixtures; not a profile admission",
    }
    (HERE / "readback.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
