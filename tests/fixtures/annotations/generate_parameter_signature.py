#!/usr/bin/env python3
"""Create a small shared parameter-Signature fixture without overwriting files.

This is an encoded DEX fixture, not an Android runtime or profile assertion.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
DEX = HERE / 'generated' / 'parameter-shared-signature.dex'
MANIFEST = HERE / 'parameter-shared-signature.json'
COMPLETE_DEX = HERE / 'generated' / 'parameter-shared-signature-complete.dex'
COMPLETE_MANIFEST = HERE / 'parameter-shared-signature-complete.json'
FRAGMENTS = ['(', 'Ljava/util/List<', 'Ljava/lang/String;', '>;I)',
             'Ljava/util/List<', 'Ljava/lang/String;', '>;']


def require(value, message):
    if not value:
        raise ValueError(message)


def read_uleb(data, offset):
    value = 0
    for i in range(5):
        byte = data[offset + i]
        value |= (byte & 0x7f) << (7 * i)
        if not byte & 0x80:
            return value, offset + i + 1
    raise ValueError('invalid fixture ULEB')


def generated(variant):
    spec = importlib.util.spec_from_file_location('mdd_fixture_generator', HERE / 'generate.py')
    require(spec is not None and spec.loader is not None, 'generator unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    features = ['parameter_shared_signature']
    if variant == 'unknown':
        features.append('parameter_slots_long')
    data, info = module.build(features)
    labels = info['labels']
    string_count, string_offset = struct.unpack_from('<II', data, 56)

    def string(index):
        require(index < string_count, 'string index outside fixture')
        offset = struct.unpack_from('<I', data, string_offset + index * 4)[0]
        length, offset = read_uleb(data, offset)
        end = data.index(b'\0', offset)
        raw = data[offset:end]
        require(len(raw) == length, 'fixture string is not expected ASCII')
        return raw.decode('ascii')

    item = labels['method_signature']
    position = item + 1  # visibility
    _, position = read_uleb(data, position)  # annotation type index
    element_count, position = read_uleb(data, position)
    name_index, position = read_uleb(data, position)
    require(element_count == 1 and string(name_index) == 'value', 'Signature element differs')
    require(data[position] == 0x1c, 'Signature is not an encoded array')
    count, position = read_uleb(data, position + 1)
    pieces = []
    for _ in range(count):
        require(data[position] == 0x17, 'Signature element is not a one-byte string index')
        pieces.append(string(data[position + 1]))
        position += 2
    require(pieces == FRAGMENTS, 'encoded Signature fragment order differs')
    set_offset = labels['parameter_set']
    require(struct.unpack_from('<II', data, set_offset) == (1, item), 'parameter set item differs')
    require(struct.unpack_from('<II', data, labels['method_set']) == (1, item),
            'method set does not share the physical item')
    list_offset = labels['parameter_ref_list']
    expected_slots = (set_offset, 0, set_offset) if variant == 'unknown' else (set_offset, 0)
    require(struct.unpack_from('<I' + 'I' * len(expected_slots), data, list_offset)
            == (len(expected_slots), *expected_slots),
            'parameter slot list differs')
    directory = labels['directory']
    _, fields, methods, parameters = struct.unpack_from('<4I', data, directory)
    position = directory + 16 + (fields + methods) * 8
    bindings = [struct.unpack_from('<2I', data, position + 8 * i) for i in range(parameters)]
    require(bindings == [(0, list_offset), (1, list_offset)], 'method list bindings differ')
    proto_offset = struct.unpack_from('<I', data, 76)[0]
    parameter_offset = struct.unpack_from('<I', data, proto_offset + 8)[0]
    require(struct.unpack_from('<I', data, parameter_offset)[0] == 2, 'prototype count differs')
    dex_path = DEX if variant == 'unknown' else COMPLETE_DEX
    manifest = {'schema_version': 'mdd.parameter-signature-fixture.v1',
                'scope': 'Synthetic encoded layout; no ART or profile qualification.',
                'file': dex_path.name, 'sha256': hashlib.sha256(data).hexdigest(),
                'bytes': len(data), 'signature_offset': item, 'parameter_set_offset': set_offset,
                'parameter_list_offset': list_offset,
                'slots': [item if item != 0 else None for item in expected_slots],
                'methods': [0, 1], 'prototype_parameter_count': 2,
                'prototype_position_coverage': variant, 'fragments': pieces}
    return data, (json.dumps(manifest, indent=2) + '\n').encode('utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--write', action='store_true')
    group.add_argument('--check', action='store_true')
    parser.add_argument('--variant', choices=('unknown', 'complete'), default='unknown')
    args = parser.parse_args()
    data, manifest = generated(args.variant)
    targets = ((DEX, data), (MANIFEST, manifest)) if args.variant == 'unknown' else (
        (COMPLETE_DEX, data), (COMPLETE_MANIFEST, manifest))
    if args.write:
        require(all(not path.exists() for path, _ in targets), 'target exists; refusing overwrite')
        for path, content in targets:
            with path.open('xb') as stream:
                stream.write(content)
    else:
        for path, expected in targets:
            require(path.is_file() and path.read_bytes() == expected,
                    'fixture bytes differ: ' + path.name)
    print(json.dumps({'status': 'passed', 'mode': 'write' if args.write else 'check'}))


if __name__ == '__main__':
    main()
