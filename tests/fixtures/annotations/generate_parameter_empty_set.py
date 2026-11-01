#!/usr/bin/env python3
"""Build one synthetic shared physical empty set fixture without overwriting inputs.

The physical map and LE values are inspected with struct independently of the
production parser. This is not an ART or full DEX qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
DEX = HERE / 'generated' / 'parameter-shared-empty-set.dex'
MANIFEST = HERE / 'parameter-shared-empty-set.json'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def generated():
    spec = importlib.util.spec_from_file_location('mdd_fixture_generator', HERE / 'generate.py')
    require(spec is not None and spec.loader is not None, 'generator unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data, info = module.build(['parameter_empty_set_shared'])
    labels = info['labels']
    list_offset = labels['parameter_ref_list']
    count, first, zero, last = struct.unpack_from('<4I', data, list_offset)
    empty_offset = labels['parameter_empty_set']
    orphan_offset = labels['parameter_orphan_empty_set']
    require((count, first, zero, last) == (3, empty_offset, 0, empty_offset),
            'shared empty set or zero slot differs')
    require(empty_offset != orphan_offset, 'orphan and referenced set share identity')
    require(struct.unpack_from('<I', data, empty_offset)[0] == 0
            and struct.unpack_from('<I', data, orphan_offset)[0] == 0,
            'physical set is not empty')
    map_offset = struct.unpack_from('<I', data, 52)[0]
    map_count = struct.unpack_from('<I', data, map_offset)[0]
    entries = [struct.unpack_from('<HHII', data, map_offset + 4 + 12*i)
               for i in range(map_count)]
    set_entries = [entry for entry in entries if entry[0] == 0x1003]
    require(len(set_entries) == 1, 'missing physical set map')
    _, _, set_count, position = set_entries[0]
    starts = []
    for _ in range(set_count):
        require(position % 4 == 0, 'unaligned set')
        starts.append(position)
        items = struct.unpack_from('<I', data, position)[0]
        position += 4 + items * 4
    require(empty_offset in starts and orphan_offset in starts,
            'empty offsets are not physical set starts')
    directory = labels['directory']
    class_offset, fields, methods, parameters = struct.unpack_from('<4I', data, directory)
    require(parameters == 2, 'unexpected encoded method binding count')
    entry_offset = directory + 16 + (fields + methods) * 8
    bindings = [struct.unpack_from('<2I', data, entry_offset + 8*i) for i in range(parameters)]
    require(bindings == [(0, list_offset), (1, list_offset)], 'shared list bindings differ')
    refs = {class_offset}
    refs.update(struct.unpack_from('<2I', data, directory + 16 + 8*i)[1]
                for i in range(fields + methods))
    refs.update((first, last))
    require(orphan_offset not in refs, 'orphan set unexpectedly referenced')
    manifest = {'schema_version': 'mdd.parameter-empty-set-fixture.v1',
                'scope': 'Synthetic physical layout; no runtime or full-format qualification.',
                'file': DEX.name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                'set_map_count': set_count, 'set_starts': starts, 'empty_set_offset': empty_offset,
                'orphan_set_offset': orphan_offset, 'parameter_list_offset': list_offset,
                'slot_offsets': [first, zero, last], 'method_bindings': [0, 1],
                'prototype_parameter_count': 2, 'expected_position_coverage': 'unknown'}
    return data, (json.dumps(manifest, indent=2) + '\n').encode('utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--write', action='store_true')
    group.add_argument('--check', action='store_true')
    args = parser.parse_args()
    data, manifest = generated()
    targets = ((DEX, data), (MANIFEST, manifest))
    if args.write:
        require(all(not path.exists() for path, _ in targets), 'target exists; refusing overwrite')
        for path, content in targets:
            with path.open('xb') as stream:
                stream.write(content)
    else:
        for path, expected in targets:
            require(path.is_file() and path.read_bytes() == expected, 'fixture bytes differ: ' + path.name)
    print(json.dumps({'status': 'passed', 'mode': 'write' if args.write else 'check'}))


if __name__ == '__main__':
    main()
