#!/usr/bin/env python3
"""Mutation check for MDD-070: the 39 public relations beyond the seventeen contract names must stay what the recorded
answers of the reference engine say, and a layer that is not built must still refuse.

It uses the machinery of artifacts/mdd-042/mutation/mutate_mcp.py (one source file edited in place per mutant, the
suites run, the original bytes written back in a finally block, commands with time limits, parts, assembly) with this
task's mutants and suites. A mutant is killed when the unit tests of mdd-facts and mdd-sql, the MCP process tests or a
replay fails; the replays include the comparison with the recorded reference answers
(conformance/relations/public_relations_diff.py) against the mutated build.

Usage: the same as mutate_mcp.py
  mutate_public_relations.py                     every mutant, then the clean-tree check
  mutate_public_relations.py --part K/N          the mutants whose position is K-1 modulo N
  mutate_public_relations.py --clean-only        only the clean-tree check and the hash
  mutate_public_relations.py --assemble FILE...  merge the parts and the clean-tree output
  mutate_public_relations.py --anchors           only say which mutants' anchors are not unique in their file
  mutate_public_relations.py NAME...             only the mutants whose name contains one of the words
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("mutate_mcp", ROOT / "artifacts/mdd-042/mutation/mutate_mcp.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

PY = base.PY
FACTS = "crates/mdd-facts/src/public_relations/"
TABLES, CODE, VALUES, DEBUG, ANNOTATIONS = (FACTS + n for n in ("tables.rs", "code.rs", "values.rs", "debug.rs", "annotations.rs"))
PUBLIC = "crates/mdd-sql/src/provider/hostlab/public.rs"
REGISTRY = "crates/mdd-sql/src/provider/hostlab.rs"

# the suites of this task: the crates that hold the projections and the registry, the process tests, the replays
base.UNIT_MCP = [*base.CARGO, "-p", "mdd-facts", "-p", "mdd-sql", "--lib", *base.TAIL]
base.UNIT_SMALI = [*base.CARGO, "-p", "mdd-service", "--lib", *base.TAIL]
BINARY = "target/debug/meguvizdexdash" + (".exe" if sys.platform == "win32" else "")
base.REPLAYS = [
    *base.REPLAYS,
    ("public relations", [PY, "-I", "conformance/relations/public_relations_diff.py", "--binary", BINARY,
                          "--out", "artifacts/local/mdd-070-mutation-diff.json", "--quiet"]),
]
base.CONTROLS = [*base.CONTROLS, [PY, "-I", "conformance/relations/test_public_relations_diff.py"]]
base.SOURCES = [
    *base.SOURCES, TABLES, CODE, VALUES, DEBUG, ANNOTATIONS, FACTS + "mod.rs", FACTS + "tests.rs", PUBLIC, REGISTRY,
    "crates/mdd-sql/src/provider/hostlab/public_tests.rs", "crates/mdd-facts/src/annotations.rs",
    "conformance/relations/public_relations_diff.py", "conformance/relations/test_public_relations_diff.py",
    "conformance/manifests/relations.json", "tests/fixtures/public_relations/generate.py",
    "tests/fixtures/public_relations/manifest.json",
]

MUTANTS = [
    # ---- header and index tables
    ("map_items: the size is one too large", TABLES, [("size: item.count,", "size: item.count + 1,")]),
    ("id_items: an item ends one byte late", TABLES, [("item_end_off: item_off + size,", "item_end_off: item_off + size + 1,")]),
    ("id_items: a call site id has no data offset", TABLES, [("(0x0007, 4, true),", "(0x0007, 4, false),")]),
    ("id_items: a string id has no data offset", TABLES, [("(0x0001, 4, true),", "(0x0001, 4, false),")]),
    ("type_ids: the descriptor index is the type index", TABLES,
     [("descriptor_idx: fact.data.descriptor_string_idx,", "descriptor_idx: fact.data.type_idx,")]),
    ("type_lists: a list ends at its header", TABLES,
     [("type_list_end_off: start + 4 + 2 * u64::from(size),", "type_list_end_off: start + 2 * u64::from(size),")]),
    ("type_list_entries: the position starts at one", TABLES,
     [('ordinal: to_u32(ordinal as u64, "type list position")?,', 'ordinal: to_u32(ordinal as u64 + 1, "type list position")?,')]),
    ("protos: parameters are joined by a semicolon", TABLES, [("joined.push(',');", "joined.push(';');")]),
    ("protos: the return descriptor is the shorty", TABLES,
     [("return_descriptor: self.type_descriptor(fact.data.return_type_idx)?.to_owned(),",
       "return_descriptor: fact.data.shorty.clone(),")]),
    ("class_defs: a missing superclass is an index", TABLES,
     [('superclass_idx: optional(word32(bytes, at + 8, "superclass_idx")?),', 'superclass_idx: Some(word32(bytes, at + 8, "superclass_idx")?),')]),
    ("class_defs: a missing source file is an index", TABLES,
     [('source_file_idx: optional(word32(bytes, at + 16, "source_file_idx")?),', 'source_file_idx: Some(word32(bytes, at + 16, "source_file_idx")?),')]),
    ("class_data_items: the item has no length", TABLES,
     [("class_data_end_off: range.byte_offset.0 + range.byte_length.0,", "class_data_end_off: range.byte_offset.0,")]),
    ("class_data_items: static and instance counts swapped", TABLES,
     [("static_fields_size: class.static_fields_count,", "static_fields_size: class.instance_fields_count,")]),
    ("class_data_items: virtual count is the direct count", TABLES,
     [("virtual_methods_size: class.virtual_methods_count,", "virtual_methods_size: class.direct_methods_count,")]),
    # ---- the code relations
    ("class_data_methods: every method is direct", CODE, [("kind: method.kind.as_str(),", 'kind: "direct",')]),
    ("try_items: the handler offset is dropped", CODE,
     [("handler_off: u32::from(item.handler_relative_byte_offset),", "handler_off: 0,")]),
    ("catch_handlers: the position does not advance", CODE, [("ordinal += 1;", "ordinal += 0;")]),
    ("catch_handlers: a catch-all is not marked", CODE, [("is_catch_all: true,", "is_catch_all: false,")]),
    ("method_numbers: a 32-bit wide literal has no float reading", CODE,
     [('0x17 => ("int", NumberView::Float32),', '0x17 => ("int", NumberView::Plain),')]),
    ("method_numbers: a high16 literal has no float reading", CODE,
     [('0x14 | 0x15 => ("float", NumberView::Float32),', '0x14 | 0x15 => ("float", NumberView::Plain),')]),
    ("method_numbers: the lit8 forms stop one early", CODE, [("0xd8..=0xe2 =>", "0xd8..=0xe1 =>")]),
    ("method_numbers: a wide high16 literal is a 32-bit float", CODE,
     [('0x19 => ("double", NumberView::Float64),', '0x19 => ("double", NumberView::Float32),')]),
    ("method_numbers: the float reading drops a bit", CODE,
     [("NumberView::Float32 => Some(f64::from(f32::from_bits(value as u32))),",
       "NumberView::Float32 => Some(f64::from(f32::from_bits((value >> 1) as u32))),")]),
    ("method_refs: the prototype of an invoke-polymorphic is listed", CODE,
     [("!(site.target_kind == TargetKind::Prototype", "!(site.target_kind == TargetKind::String")]),
    ("method_refs: a prototype is spelled out", CODE, [('TargetKind::Prototype => "proto",', 'TargetKind::Prototype => "prototype",')]),
    ("method_refs: a read is a write", CODE, [('Some("get")', 'Some("put")')]),
    # ---- the encoded value relations
    ("encoded_array_owners: a call site array belongs to a class", VALUES, [('owner_kind: "call_site",', 'owner_kind: "class_static_values",')]),
    ("class_static_values: no value names its field", VALUES, [("field_idx: static_fields.get(ordinal).copied(),", "field_idx: None,")]),
    ("method_handles: no handle has a kind", VALUES, [("method_handle_type: u32::from(target.handle_kind),", "method_handle_type: 0,")]),
    ("call_sites: the value count is fixed", VALUES,
     [('value_count: to_u32(array.elements.len() as u64, "call site value count")?,', "value_count: 3,")]),
    ("encoded_array_values: every node is at depth zero", VALUES, [("depth: value.depth,", "depth: 0,")]),
    ("hiddenapi_flags: a class offset inside the offset table is read", VALUES,
     [("if relative < table || relative >= size {", "if relative >= size {")]),
    ("hiddenapi_flags: a size below the offset table is read", VALUES,
     [("if size < table || start.checked_add(size)", "if start.checked_add(size)")]),
    # ---- the debug relations
    ("debug_positions: a prologue marker is an epilogue marker", DEBUG,
     [("SET_PROLOGUE_END => prologue_end = true,", "SET_PROLOGUE_END => epilogue_begin = true,")]),
    ("debug_positions: a prologue marker outlives its position", DEBUG, [("prologue_end = false;", "prologue_end = prologue_end;")]),
    ("debug_positions: an epilogue marker outlives its position", DEBUG, [("epilogue_begin = false;", "epilogue_begin = epilogue_begin;")]),
    ("debug_positions: a source file is not remembered", DEBUG, [("9 => source_file_idx = event.file_idx,", "9 => {}")]),
    ("debug_opcodes: only advance_pc moves the address", DEBUG,
     [("let moves_pc = event.opcode == ADVANCE_PC || event.opcode >= FIRST_SPECIAL;", "let moves_pc = event.opcode == ADVANCE_PC;")]),
    ("debug_opcodes: only advance_line moves the line", DEBUG,
     [("let moves_line = event.opcode == ADVANCE_LINE || event.opcode >= FIRST_SPECIAL;", "let moves_line = event.opcode == ADVANCE_LINE;")]),
    ("debug_opcodes: no opcode emits a local", DEBUG, [("emits_local: is_local(event.opcode),", "emits_local: false,")]),
    ("debug_locals: a start is not remembered", DEBUG, [("locals.insert(register, local);", "let _ = (register, local);")]),
    ("debug_locals: an end shows nothing", DEBUG, [("_ => locals.get(&register).copied().unwrap_or_default(),", "_ => Local::default(),")]),
    # ---- the annotation relations
    ("annotation_elements_resolved: build visibility is runtime", ANNOTATIONS, [('0 => Some("class"),', '0 => Some("runtime"),')]),
    ("annotation_elements_resolved: system is runtime", ANNOTATIONS, [('2 => Some("system"),', '2 => Some("runtime"),')]),
    ("annotation_elements_resolved: an annotation without elements has no row", ANNOTATIONS, [("if top.is_empty() {", "if false {")]),
    ("annotation_elements_resolved: nested elements are top level", ANNOTATIONS,
     [("values.iter().filter(|value| value.depth == 0).collect();", "values.iter().filter(|value| value.depth <= 1).collect();")]),
    ("annotation_values: a parameter is always the first", ANNOTATIONS,
     [('parameter_idx: Some(to_u32(ordinal as u64, "parameter position")?),', "parameter_idx: Some(0),")]),
    ("annotation_values: a field owner is a method", ANNOTATIONS, [('kind: "field",', 'kind: "method",')]),
    # ---- the registry and the layer gate
    ("gate: the code layout is not required", PUBLIC,
     [("if layers.contains(&FactLayer::CodeLayout) {", "if false && layers.contains(&FactLayer::CodeLayout) {")]),
    ("gate: the annotations are not required", PUBLIC,
     [("if layers.contains(&FactLayer::Annotations) {", "if false && layers.contains(&FactLayer::Annotations) {")]),
    ("gate: the references are not required", PUBLIC,
     [("if layers.contains(&FactLayer::References) {", "if false && layers.contains(&FactLayer::References) {")]),
    ("columns: a nullable column is not nullable", PUBLIC,
     [('("class_annotations_off", SqlType::U64, true),', '("class_annotations_off", SqlType::U64, false),')]),
    ("columns: a signed column is text", PUBLIC, [('("long_value", SqlType::I64, false),\n    ("double_value", SqlType::F64, true),\n];\nconst METHOD_USING', '("long_value", SqlType::Text, false),\n    ("double_value", SqlType::F64, true),\n];\nconst METHOD_USING')]),
    ("registry: the public relations are not listed", REGISTRY,
     [(".filter_map(|name| Self::parse(name))", ".filter_map(|name| HostLabRelation::parse(name).map(Self::Required))")]),
]

base.MUTANTS = MUTANTS


def anchors() -> int:
    """Which anchors are not unique in their file (no build, no run)."""
    bad = 0
    for name, relative, edits in MUTANTS:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for old, _new in edits:
            count = text.count(old)
            if count != 1:
                bad += 1
                print(f"ANCHOR {count}x  {name}  [{relative}]")
    print(f"{len(MUTANTS)} mutants, {bad} anchors that are not unique")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--anchors"]:
        sys.exit(anchors())
    sys.exit(base.main())
