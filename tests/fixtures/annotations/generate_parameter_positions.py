#!/usr/bin/env python3
"""Generate isolated synthetic parameter-list fixtures without touching old ones.

The small corpus models encoded physical layouts, not Android installability.
`--write` creates only missing named files; `--check` compares existing bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
OUT = HERE / "generated"
CASES = (
    ("parameter-empty-nonzero-proto.dex", ("parameter_slots_empty",), 2, (), 2, "unknown"),
    ("parameter-long-nonzero-proto.dex", ("parameter_slots_long",), 2, ("set", 0, "set"), 2, "unknown"),
    ("parameter-empty-zero-proto.dex", ("parameter_slots_empty", "parameter_zero_proto"), 0, (), 2, "complete"),
    ("parameter-orphan-empty-no-binding.dex", ("parameter_slots_empty", "parameter_zero_proto", "parameter_no_binding"), 0, (), 0, "not_applicable"),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def generate():
    spec = importlib.util.spec_from_file_location("mdd_annotation_fixture_generator", HERE / "generate.py")
    require(spec is not None and spec.loader is not None, "fixture generator unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = []
    for name, features, prototype_count, requested_slots, binding_count, coverage in CASES:
        data, layout = module.build(features)
        labels = layout["labels"]
        list_offset = labels["parameter_ref_list"]
        count = struct.unpack_from("<I", data, list_offset)[0]
        slots = struct.unpack_from("<" + "I" * count, data, list_offset + 4)
        expected_slots = tuple(labels["parameter_set"] if x == "set" else x for x in requested_slots)
        require(count == len(requested_slots) and slots == expected_slots, "encoded slot bytes differ")
        require(struct.unpack_from("<I", data, labels["directory"] + 12)[0] == binding_count,
                "directory binding count differs")
        proto_offset = struct.unpack_from("<I", data, 76)[0]
        parameter_offset = struct.unpack_from("<I", data, proto_offset + 8)[0]
        actual_prototype_count = 0 if parameter_offset == 0 else struct.unpack_from("<I", data, parameter_offset)[0]
        require(actual_prototype_count == prototype_count, "prototype parameter count differs")
        result.append((name, data, {"file": name, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "parameter_list_offset": list_offset,
            "encoded_slots": list(slots), "prototype_parameter_count": prototype_count,
            "parameter_binding_count": binding_count, "expected_position_coverage": coverage}))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate()
    manifest = (json.dumps({"schema_version": "mdd.parameter-position-fixtures.v1",
        "scope": "Synthetic encoded annotation layouts; no Android runtime qualification.",
        "fixtures": [item[2] for item in result]}, indent=2) + "\n").encode()
    targets = [(OUT / name, data) for name, data, _ in result]
    targets.append((HERE / "parameter-position-fixtures.json", manifest))
    if args.write:
        require(all(not path.exists() for path, _ in targets), "target exists; refusing to overwrite")
        for path, data in targets:
            with path.open("xb") as out:
                out.write(data)
    else:
        for path, expected in targets:
            require(path.is_file() and path.read_bytes() == expected, "fixture bytes differ: " + path.name)
    print(json.dumps({"status": "passed", "mode": "write" if args.write else "check",
                      "fixture_count": len(result)}))


if __name__ == "__main__":
    main()
