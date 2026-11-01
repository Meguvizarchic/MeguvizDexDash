#!/usr/bin/env python3
"""Deterministic annotated DEX writer, independent of production annotation readers."""
from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "generated"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uleb(value):
    result = bytearray()
    while True:
        octet = value & 127
        value >>= 7
        result.append(octet | (128 if value else 0))
        if not value:
            return bytes(result)


def seal(data):
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def build(features=None):
    features = set(features or [])
    field_fragments = ["Ljava/util/List<", "Ljava/lang/String;", ">;"]
    method_fragments = ["(", "Ljava/util/List<", "Ljava/lang/String;", ">;I)", "Ljava/util/List<", "Ljava/lang/String;", ">;"]
    class_fragments = ["<T:", "Ljava/lang/Object;", ">Ljava/lang/Object;"]
    names = ["a_byte", "b_short", "c_char", "d_int", "e_long", "f_float", "g_double", "h_string", "i_type", "j_field", "k_method", "l_enum", "m_method_type", "n_method_handle", "o_array", "p_annotation", "q_null", "r_boolean_false", "s_boolean_true", "t_nan_float", "u_nan_double", "v_infinity_float", "w_infinity_double", "x_negative_zero"]
    descriptors = ["I", "Ldalvik/annotation/Signature;", "Lfixture/A;", "Lfixture/Enum;", "Lfixture/Nested;", "Lfixture/Values;", "Ljava/lang/Object;", "Ljava/lang/String;", "Ljava/util/List;"]
    if "shared_empty_directory" in features:
        descriptors.append("Lfixture/B;")
    call_site = bool(features & {"call_site_array","call_site_short"})
    if call_site:
        descriptors.extend(["Lfixture/Bootstrap;","Ljava/lang/invoke/CallSite;","Ljava/lang/invoke/MethodHandles$Lookup;","Ljava/lang/invoke/MethodType;"])
    strings = sorted(set(descriptors + names + field_fragments + method_fragments + class_fragments + ["LLI", "E", "f", "f2", "m", "m2", "value", "hello", "a", "z"] + (["LLLL","bootstrap"] if call_site else []) + (["L"] if "parameter_zero_proto" in features else [])))
    sid = {value: index for index, value in enumerate(strings)}
    tid = {value: index for index, value in enumerate(sorted(descriptors, key=sid.__getitem__))}
    string_off = 112
    type_off = string_off + len(strings) * 4
    proto_off = type_off + len(descriptors) * 4
    proto_count = 2 if call_site else 1
    method_count = 3 if call_site else 2
    field_off = proto_off + 12 * proto_count
    method_off = field_off + 24
    class_off = method_off + 8 * method_count
    class_count = 2 if "shared_empty_directory" in features else 1
    data_off = class_off + 32 * class_count
    data = bytearray(data_off)
    map_entries = [(0, 1, 0), (1, len(strings), string_off), (2, len(descriptors), type_off), (3, proto_count, proto_off), (4, 3, field_off), (5, method_count, method_off), (6, class_count, class_off)]
    labels = {"class_defs":class_off}

    def align():
        data.extend(b"\0" * (-len(data) % 4))

    align()
    if call_site:
        labels["call_site_ids"] = len(data)
        map_entries.append((7,1,len(data)))
        data.extend(b"\0"*4)
    labels["method_handles"] = len(data)
    map_entries.append((8, 1, len(data)))
    data.extend(struct.pack("<4H", 4, 0, 2 if call_site else 0, 0))
    map_entries.append((0x2002, len(strings), len(data)))
    string_offsets = {}
    for index, value in enumerate(strings):
        encoded = value.encode("ascii")
        string_offsets[value] = len(data)
        struct.pack_into("<I", data, string_off + index * 4, len(data))
        data.extend(uleb(len(value)) + encoded + b"\0")
    for descriptor, index in tid.items():
        struct.pack_into("<I", data, type_off + index * 4, sid[descriptor])
    align()
    labels["parameters"] = len(data)
    map_entries.append((0x1001, 2 if call_site else 1, len(data)))
    data.extend(struct.pack("<I2H", 2, tid["Ljava/util/List;"], tid["I"]))
    method_proto_index = 1 if call_site else 0
    if "parameter_zero_proto" in features:
        require(not call_site, "zero-prototype fixture does not support call sites")
        # The existing type_list remains a valid unreferenced physical item.
        struct.pack_into("<III", data, proto_off+method_proto_index*12, sid["L"], tid["Ljava/util/List;"], 0)
    else:
        struct.pack_into("<III", data, proto_off+method_proto_index*12, sid["LLI"], tid["Ljava/util/List;"], labels["parameters"])
    if call_site:
        labels["bootstrap_parameters"] = len(data)
        data.extend(struct.pack("<I3H",3,tid["Ljava/lang/invoke/MethodHandles$Lookup;"],tid["Ljava/lang/String;"],tid["Ljava/lang/invoke/MethodType;"]))
        struct.pack_into("<III",data,proto_off,sid["LLLL"],tid["Ljava/lang/invoke/CallSite;"],labels["bootstrap_parameters"])
    fields = [(tid["Lfixture/A;"], tid["Ljava/util/List;"], sid["f"]), (tid["Lfixture/A;"], tid["Ljava/util/List;"], sid["f2"]), (tid["Lfixture/Enum;"], tid["Lfixture/Enum;"], sid["E"])]
    for index, entry in enumerate(fields):
        struct.pack_into("<HHI", data, field_off + index * 8, *entry)
    for index, name in enumerate(["m", "m2"]):
        struct.pack_into("<HHI", data, method_off + index * 8, tid["Lfixture/A;"], method_proto_index, sid[name])
    if call_site:
        struct.pack_into("<HHI",data,method_off+16,tid["Lfixture/Bootstrap;"],0,sid["bootstrap"])
    labels["class_data"] = len(data)
    map_entries.append((0x2000, 1, len(data)))
    data.extend(b"\x02\0\x02\0" + b"\0\x09\x01\x09" + b"\0\x89\x02\0\x01\x89\x02\0")
    if "orphan_arrays" in features or "orphan_bad_array" in features:
        map_entries.append((0x2005,2,len(data)))
        labels["empty_array"] = len(data)
        data.extend(b"\0")
        labels["nonempty_array"] = len(data)
        data.extend(bytes([1,0x17,255 if "orphan_bad_array" in features else sid["hello"]]))
    if call_site:
        labels["call_site_array"] = len(data)
        map_entries.append((0x2005,1,len(data)))
        data.extend(bytes([2,0x16,0,0x17,sid["m"]]) if "call_site_short" in features else bytes([3,0x16,0,0x17,sid["m"],0x15,method_proto_index]))
        struct.pack_into("<I",data,labels["call_site_ids"],labels["call_site_array"])

    def reference(kind, index):
        require(0 <= index <= 255, "small fixture reference width exceeded")
        return bytes([kind, index])

    def encoded_annotation(type_index, elements):
        ordered = sorted(elements, key=lambda item: sid[item[0]])
        return uleb(type_index) + uleb(len(ordered)) + b"".join(uleb(sid[name]) + value for name, value in ordered)

    def signature(parts):
        array = b"\x1c" + uleb(len(parts)) + b"".join(reference(0x17, sid[part]) for part in parts)
        return b"\x02" + encoded_annotation(tid["Ldalvik/annotation/Signature;"], [("value", array)])

    value_elements = [
        ("a_byte", b"\x00\x80"), ("b_short", b"\x22\x00\x80"), ("c_char", b"\x23\xff\xff"),
        ("d_int", b"\x64\0\0\0\x80"), ("e_long", b"\xe6\0\0\0\0\0\0\0\x80"),
        ("f_float", b"\x30\x80\x3f"), ("g_double", b"\x31\xf0\x3f"), ("h_string", reference(0x17, sid["hello"])),
        ("i_type", reference(0x18, tid["Ljava/lang/String;"])), ("j_field", reference(0x19, 0)), ("k_method", reference(0x1a, 0)),
        ("l_enum", reference(0x1b, 2)), ("m_method_type", reference(0x15, 0)), ("n_method_handle", reference(0x16, 0)),
        ("o_array", b"\x1c\x03" + reference(0x17, sid["z"]) + reference(0x17, sid["a"]) + reference(0x17, sid["z"])),
        ("p_annotation", b"\x1d" + encoded_annotation(tid["Lfixture/Nested;"], [("value", b"\x04\x07")])),
        ("q_null", b"\x1e"), ("r_boolean_false", b"\x1f"), ("s_boolean_true", b"\x3f"),
        ("t_nan_float", b"\x70\x34\x12\xc0\x7f"), ("u_nan_double", b"\xf1\x34\x12\0\0\0\0\xf8\x7f"),
        ("v_infinity_float", b"\x30\x80\x7f"), ("w_infinity_double", b"\x31\xf0\x7f"), ("x_negative_zero", b"\x10\x80")]
    value_body = bytearray(b"\x01" + uleb(tid["Lfixture/Values;"]) + uleb(len(value_elements)))
    relative_value_offsets = {}
    for name, value in sorted(value_elements, key=lambda item: sid[item[0]]):
        value_body.extend(uleb(sid[name]))
        relative_value_offsets[name] = len(value_body)
        value_body.extend(value)
    annotation_values = [("class_signature", signature(class_fragments)), ("values", bytes(value_body)),
                         ("field_signature", signature(field_fragments)), ("method_signature", signature(method_fragments))]
    if "orphan_annotation" in features or "orphan_bad_annotation" in features:
        annotation_values.append(("orphan_annotation",bytes([3 if "orphan_bad_annotation" in features else 0])+uleb(tid["Lfixture/Values;"])+b"\0"))
    map_entries.append((0x2004, len(annotation_values), len(data)))
    for name, value in annotation_values:
        labels[name] = len(data)
        data.extend(value)
    align()
    set_values = [("class_set", [labels["class_signature"], labels["values"]]), ("field_set", [labels["field_signature"]]),
                  ("method_set", [labels["method_signature"]]), ("parameter_set", [labels["values"]])]
    if "parameter_empty_set_shared" in features:
        set_values.extend([("parameter_empty_set", []), ("parameter_orphan_empty_set", [])])
    if features & {"orphan_set","shared_empty_set","orphan_bad_set"}:
        set_values.append(("orphan_set",[labels["class_signature"]+1] if "orphan_bad_set" in features else []))
    map_entries.append((0x1003, len(set_values), len(data)))
    for name, offsets in set_values:
        labels[name] = len(data)
        data.extend(struct.pack("<I" + "I" * len(offsets), len(offsets), *offsets))
    labels["parameter_ref_list"] = len(data)
    map_entries.append((0x1002, 2 if features & {"orphan_ref","orphan_bad_ref"} else 1, len(data)))
    require(len(features & {"parameter_slots_empty", "parameter_slots_long", "parameter_empty_set_shared"}) <= 1,
            "parameter list modes are mutually exclusive")
    if "parameter_slots_empty" in features:
        parameter_slots = []
    elif "parameter_slots_long" in features:
        parameter_slots = [labels["parameter_set"], 0, labels["parameter_set"]]
    elif "parameter_empty_set_shared" in features:
        parameter_slots = [labels["parameter_empty_set"], 0, labels["parameter_empty_set"]]
    else:
        parameter_slots = [labels["parameter_set"], 0]
    data.extend(struct.pack("<I" + "I" * len(parameter_slots), len(parameter_slots), *parameter_slots))
    if features & {"orphan_ref","orphan_bad_ref"}:
        labels["orphan_ref"] = len(data)
        data.extend(struct.pack("<II",1,labels["field_set"]+4) if "orphan_bad_ref" in features else struct.pack("<I",0))
    labels["directory"] = len(data)
    extra_directory = bool(features & {"orphan_directory","orphan_known_directory","orphan_external_directory","orphan_bad_directory","shared_empty_directory"})
    map_entries.append((0x2006, 2 if extra_directory else 1, len(data)))
    parameter_bindings = [] if "parameter_no_binding" in features else [(0, labels["parameter_ref_list"]), (1, labels["parameter_ref_list"])]
    data.extend(struct.pack("<4I", labels["class_set"], 2, 1, len(parameter_bindings)))
    field_set = labels["orphan_set"] if "shared_empty_set" in features else labels["field_set"]
    for index, offset in [(0, field_set), (1, field_set), (0, labels["method_set"])] + parameter_bindings:
        data.extend(struct.pack("<II", index, offset))
    if extra_directory:
        labels["orphan_directory"] = len(data)
        if "orphan_bad_directory" in features:
            data.extend(struct.pack("<8I",0,2,0,0,0,field_set,2,field_set))
        elif features & {"orphan_known_directory","orphan_external_directory"}:
            data.extend(struct.pack("<6I",0,1,0,0,2 if "orphan_external_directory" in features else 0,field_set))
        else:
            data.extend(b"\0"*16)
    class_directory = labels["orphan_directory"] if "shared_empty_directory" in features else labels["directory"]
    struct.pack_into("<8I", data, class_off, tid["Lfixture/A;"], 1, tid["Ljava/lang/Object;"], 0, 0xffffffff,
                     class_directory, labels["class_data"], 0)
    if class_count == 2:
        struct.pack_into("<8I",data,class_off+32,tid["Lfixture/B;"],1,tid["Ljava/lang/Object;"],0,0xffffffff,class_directory,0,0)
    labels["map"] = len(data)
    map_entries.append((0x1000, 1, len(data)))
    data.extend(struct.pack("<I", len(map_entries)))
    for kind, count, offset in map_entries:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    data[:8] = b"dex\n038\0"
    struct.pack_into("<20I", data, 32, len(data), 112, 0x12345678, 0, 0, labels["map"],
                     len(strings), string_off, len(descriptors), type_off, proto_count, proto_off, 3, field_off, method_count, method_off, class_count, class_off, len(data) - data_off, data_off)
    return seal(data), {"labels": labels, "strings": strings, "string_indices": sid, "type_indices": tid, "string_offsets": string_offsets,
        "value_offsets": {name: labels["values"] + offset for name, offset in relative_value_offsets.items()},
        "field_fragments": field_fragments, "method_fragments": method_fragments, "class_fragments": class_fragments,
        "class_idx": tid["Lfixture/A;"], "field_indices": [0,1], "method_indices": [0,1], "external_enum_field_idx": 2}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data, layout = build()
    files = []

    def emit(name, value, expected, reason=None):
        (OUT / name).write_bytes(value)
        files.append({"path": "tests/fixtures/annotations/generated/" + name, "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest(), "expected": expected, "reason": reason})

    emit("annotations-038.dex", data, "valid_structural_annotation_fixture")
    mutants = [
        ("bad-visibility.dex", layout["labels"]["values"], 3, 1, "invalid_visibility"),
        ("bad-annotation-type.dex", layout["labels"]["values"] + 1, 0x7f, 1, "annotation_type_out_of_range"),
        ("bad-class-owner.dex", layout["labels"]["directory"] + 16, 2, 4, "field_owner_mismatch"),
        ("bad-parameter-count.dex", layout["labels"]["parameter_ref_list"], 3, 4, "parameter_ref_bounds"),
        ("bad-parameter-arity.dex", layout["labels"]["parameter_ref_list"], 1, 4, "parameter_count_mismatch"),
        ("bad-value-tag.dex", layout["value_offsets"]["q_null"], 1, 1, "unknown_value_tag"),
        ("bad-value-width.dex", layout["value_offsets"]["a_byte"], 0x20, 1, "invalid_value_arg"),
        ("bad-boolean-arg.dex", layout["value_offsets"]["r_boolean_false"], 0x5f, 1, "invalid_value_arg"),
        ("bad-string-index.dex", layout["value_offsets"]["h_string"] + 1, 255, 1, "value_index_out_of_range"),
        ("bad-element-order.dex", layout["value_offsets"]["b_short"] - 1, layout["string_indices"]["a_byte"], 1, "annotation_element_order"),
        ("bad-field-entry-order.dex", layout["labels"]["directory"] + 24, 0, 4, "directory_entry_order")]
    for name, offset, value, width, reason in mutants:
        changed = bytearray(data)
        changed[offset:offset+width] = value.to_bytes(width, "little")
        emit(name, seal(changed), "valid_parameter_prefix_adjudicated" if name == "bad-parameter-arity.dex" else "invalid_annotation_fixture",None if name == "bad-parameter-arity.dex" else reason)
    physical_cases = [
        ("valid-orphan-annotation.dex",["orphan_annotation"],True,None),
        ("bad-orphan-annotation.dex",["orphan_bad_annotation"],False,"invalid_visibility"),
        ("valid-orphan-arrays.dex",["orphan_arrays"],True,None),
        ("bad-orphan-array.dex",["orphan_bad_array"],False,"value_index_out_of_range"),
        ("valid-orphan-empty-set.dex",["orphan_set"],True,None),
        ("valid-shared-empty-set.dex",["shared_empty_set"],True,None),
        ("bad-orphan-set-interior.dex",["orphan_bad_set"],False,"annotation_target_offset"),
        ("valid-orphan-empty-ref-list.dex",["orphan_ref"],True,None),
        ("bad-orphan-ref-interior.dex",["orphan_bad_ref"],False,"parameter_set_offset"),
        ("valid-orphan-empty-directory.dex",["orphan_directory"],True,None),
        ("valid-orphan-known-directory.dex",["orphan_known_directory"],True,None),
        ("valid-orphan-external-directory.dex",["orphan_external_directory"],True,None),
        ("bad-orphan-directory-owner.dex",["orphan_bad_directory"],False,"directory_owner_mismatch"),
        ("valid-shared-empty-directory.dex",["shared_empty_directory"],True,None),
    ]
    for name,features,valid,reason in physical_cases:
        value,case_layout=build(features)
        emit(name,value,"valid_physical_item_fixture" if valid else "invalid_annotation_fixture",reason)
    interiors = [
        ("bad-directory-interior.dex",layout["labels"]["class_defs"]+20,layout["labels"]["directory"]+4,"directory_not_item_start"),
        ("bad-set-interior.dex",layout["labels"]["directory"]+20,layout["labels"]["field_set"]+4,"owner_set_offset"),
        ("bad-annotation-interior.dex",layout["labels"]["field_set"]+4,layout["labels"]["field_signature"]+1,"annotation_target_offset"),
        ("bad-ref-list-interior.dex",layout["labels"]["directory"]+44,layout["labels"]["parameter_ref_list"]+4,"parameter_list_offset"),
        ("bad-ref-set-interior.dex",layout["labels"]["parameter_ref_list"]+4,layout["labels"]["parameter_set"]+4,"parameter_set_offset"),
    ]
    for name,offset,value,reason in interiors:
        changed=bytearray(data);struct.pack_into("<I",changed,offset,value)
        emit(name,seal(changed),"invalid_annotation_fixture",reason)
    array_data,array_layout=build(["orphan_arrays"])
    changed=bytearray(array_data);struct.pack_into("<I",changed,array_layout["labels"]["class_defs"]+28,array_layout["labels"]["nonempty_array"]+1)
    emit("bad-static-array-interior.dex",seal(changed),"invalid_annotation_fixture","static_array_not_item_start")
    changed=bytearray(array_data);struct.pack_into("<I",changed,array_layout["labels"]["class_defs"]+28,array_layout["labels"]["empty_array"])
    emit("valid-static-empty-array.dex",seal(changed),"valid_physical_item_fixture")
    call_data,call_layout=build(["call_site_array"])
    emit("valid-call-site-array.dex",call_data,"valid_physical_item_fixture")
    changed=bytearray(call_data);struct.pack_into("<I",changed,call_layout["labels"]["call_site_ids"],call_layout["labels"]["call_site_array"]+1)
    emit("bad-call-site-array-interior.dex",seal(changed),"invalid_annotation_fixture","call_site_array_not_item_start")
    short_data,_=build(["call_site_short"])
    emit("bad-call-site-arity.dex",short_data,"invalid_annotation_fixture","call_site_arity")
    for name,relative,value,width,reason in [
        ("bad-call-site-handle-kind.dex",1,0x17,1,"call_site_prefix"),
        ("bad-call-site-name-kind.dex",3,0x0018,2,"call_site_prefix"),
        ("bad-call-site-type-kind.dex",5,0x17,1,"call_site_prefix"),
        ("bad-call-site-handle-index.dex",2,255,1,"value_index_out_of_range"),
        ("bad-call-site-name-index.dex",4,255,1,"value_index_out_of_range"),
        ("bad-call-site-type-index.dex",6,255,1,"value_index_out_of_range"),
    ]:
        changed=bytearray(call_data);offset=call_layout["labels"]["call_site_array"]+relative;changed[offset:offset+width]=value.to_bytes(width,"little")
        emit(name,seal(changed),"invalid_annotation_fixture",reason)
    (HERE / "layout.json").write_text(json.dumps(layout, indent=2) + "\n", encoding="utf-8")
    components = [
        {"id":"standalone-null","hex":"1e","expected_kind":"null"},
        {"id":"null-invalid-arg","hex":"3e","reason":"invalid_value_arg"},
        {"id":"float-invalid-width","hex":"90","reason":"invalid_value_arg"},
        {"id":"truncated-long","hex":"e60102","reason":"truncated"},
        {"id":"deep-array","hex":(b"\x1c\x01"*32+b"\x1e").hex(),"max_depth":8,"reason":"depth_budget"},
        {"id":"node-budget","hex":"1c031e1e1e","max_nodes":2,"reason":"node_budget"},
        {"id":"array-count-budget","hex":"1c7f1e","max_nodes":64,"reason":"node_budget"},
        {"id":"array-count-uleb-overflow","hex":"1cffffffff10","reason":"uleb_overflow"}]
    components.extend([
        {"id":"method-type-before-038","hex":"1500","version":"035","reason":"encoded_value_version"},
        {"id":"method-handle-before-038","hex":"1600","version":"035","reason":"encoded_value_version"}])
    component_path = HERE / "component-vectors.json"
    component_path.write_text(json.dumps({"schema_version":"mdd.annotation-component-vectors.v1","scope":"standalone encoded_value bytes in a known metadata context, not a full DEX", "vectors":components},indent=2)+"\n",encoding="utf-8")
    manifest = {"schema_version": "mdd.annotation-fixtures.v1", "generator": "tests/fixtures/annotations/generate.py",
        "format": "038 little endian", "files": files, "source_reference": "https://source.android.com/docs/core/runtime/dex-format",
        "claim": "Synthetic structurally controlled static-analysis fixture; external annotation types/enum symbol unresolved; no installability or complete ART verifier qualification.",
        "sha1_signature_and_adler32": "recomputed for every fixture and mutant", "generated_implementation_ancestors": "Python struct/hashlib/zlib only; no production parser",
        "component_vectors":{"path":"tests/fixtures/annotations/component-vectors.json","sha256":hashlib.sha256(component_path.read_bytes()).hexdigest(),"count":len(components)}}
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(files)} annotation fixtures")


if __name__ == "__main__":
    main()
