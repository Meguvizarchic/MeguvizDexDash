#!/usr/bin/env python3
"""Negative exploration for classes.file_id multiplicity.

The only way to exercise an exact duplicate row that keeps the per-occurrence
key column ``classes.file_id`` is to have two class definitions in one DEX whose
remaining class columns are identical.  This script builds such a fixture and
records the native probe terminal, showing that the engine rejects the input
with DUPLICATE_CLASS_DEFINITION.  The fixture is an exploration artifact, not a
relation fixture, and is not used by any verdict.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EVIDENCE = HERE / "slices" / "explore-duplicate-class"
PROBE = HERE / "probe_relations.exe"


def encoded(units):
    value = bytearray([len(units)])
    for unit in units:
        if 0 < unit < 128:
            value.append(unit)
        elif unit < 2048:
            value.extend([0xc0 | (unit >> 6), 0x80 | (unit & 63)])
        else:
            value.extend([0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 63), 0x80 | (unit & 63)])
    return bytes(value) + b"\0"


def build_two_classes():
    texts = [[], list(b"Lfixture/Empty;"), list(b"Ljava/lang/Object;")]
    string_off = 112
    type_off = string_off + len(texts) * 4
    class_off = type_off + 2 * 4
    data_off = class_off + 32 * 2
    data = bytearray(data_off)
    entries = [(0, 1, 0), (1, len(texts), string_off), (2, 2, type_off),
               (6, 2, class_off), (0x2002, len(texts), data_off)]
    for index, units in enumerate(texts):
        struct.pack_into("<I", data, string_off + index * 4, len(data))
        data.extend(encoded(units))
    struct.pack_into("<II", data, type_off, 1, 2)
    for k in range(2):
        struct.pack_into("<8I", data, class_off + 32 * k, 0, 1, 1, 0, 0xFFFFFFFF, 0, 0, 0)
    data.extend(b"\0" * (-len(data) % 4))
    map_off = len(data)
    entries.append((0x1000, 1, map_off))
    data.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    struct.pack_into("<20I", data, 32, len(data), 112, 0x12345678, 0, 0, map_off,
                     len(texts), string_off, 2, type_off, 0, 0, 0, 0, 0, 0, 2, class_off,
                     len(data) - data_off, data_off)
    data[:8] = b"dex\n035\0"
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    fixture = EVIDENCE / "two-classes.dex"
    fixture.write_bytes(build_two_classes())
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    proc = subprocess.run([str(PROBE), str(fixture), str(fixture)], cwd=str(ROOT),
                          capture_output=True, timeout=120)
    (EVIDENCE / "stdout.txt").write_bytes(proc.stdout)
    (EVIDENCE / "stderr.txt").write_bytes(proc.stderr)
    record = {
        "argv": [str(PROBE), str(fixture), str(fixture)],
        "started_utc": started,
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "exit_code": proc.returncode,
        "stdout_sha256": hashlib.sha256(proc.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(proc.stderr).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "purpose": "negative exploration: duplicate class definitions are rejected",
    }
    (EVIDENCE / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"exit_code": proc.returncode,
                      "stderr": proc.stderr.decode("utf-8", "replace")[:300],
                      "fixture_sha256": record["fixture_sha256"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
