use super::*;
use crate::MetadataFacts;
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_input::{
    archive::{ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec},
};
use std::fs;

/// Every DEX fixture of the instruction layer whose code section reads, as complete code facts.
fn complete_facts_of_instruction_fixtures() -> Vec<(String, CodeFacts)> {
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/instructions/generated");
    let mut out = Vec::new();
    let mut paths: Vec<_> = fs::read_dir(folder)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("dex"))
        .collect();
    paths.sort();
    for path in paths {
        let input = InputSpec {
            path: path.clone(),
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let Ok(snapshot) = Snapshot::capture(&[input], CaptureLimits::default()) else {
            continue;
        };
        let Ok(inventory) = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        ) else {
            continue;
        };
        let Ok(code) =
            CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
        else {
            continue;
        };
        out.push((
            path.file_name().unwrap().to_string_lossy().into_owned(),
            code,
        ));
    }
    out
}

#[test]
fn compact_code_facts_read_every_item_back_equal_to_the_full_ones() {
    let (mut files, mut items, mut with_debug, mut with_payload) = (0, 0, 0, 0);
    for (name, full) in complete_facts_of_instruction_fixtures() {
        assert!(!full.is_compact(), "{name}");
        let compact = full.compacted().unwrap();
        assert!(compact.is_compact(), "{name}");
        assert_eq!(compact.items().len(), full.items().len(), "{name}");
        // Nothing but the instruction-derived parts is gone.
        assert_eq!(compact.scope(), full.scope());
        assert_eq!(compact.source().content_id, full.source().content_id);
        assert_eq!(
            compact.declared_code_item_byte_offsets(),
            full.declared_code_item_byte_offsets()
        );
        assert_eq!(compact.code_layout_coverage(), full.code_layout_coverage());
        let mut reader = compact.reader();
        // Forwards and then backwards, so the decoder's cache of debug programs cannot decide the result.
        let order: Vec<usize> = (0..full.items().len())
            .chain((0..full.items().len()).rev())
            .collect();
        for ordinal in order {
            let (whole, small) = (&full.items()[ordinal], &compact.items()[ordinal]);
            assert_eq!(small.code_item_id(), whole.code_item_id(), "{name}");
            assert_eq!(small.opcodes(), whole.opcodes(), "{name} opcodes");
            let expected: Vec<u8> = whole.data().instructions.iter().map(|i| i.opcode).collect();
            assert_eq!(
                whole.opcodes(),
                expected.as_slice(),
                "{name} opcode bytes are the instructions' opcodes"
            );
            // The compact fact is a header: the heavy parts are empty, the rest equals the full item.
            let header = small.data();
            assert!(header.instructions.is_empty() && header.payloads.is_empty());
            assert!(header.switch_targets.is_empty() && header.debug_info.is_none());
            assert_eq!(
                serde_json::to_value(&header.raw_range).unwrap(),
                serde_json::to_value(&whole.data().raw_range).unwrap()
            );
            assert_eq!(
                serde_json::to_value(&header.insns_range).unwrap(),
                serde_json::to_value(&whole.data().insns_range).unwrap()
            );
            assert_eq!(header.registers_size, whole.data().registers_size);
            assert_eq!(
                header.insns_size_code_units,
                whole.data().insns_size_code_units
            );
            assert_eq!(
                header.debug_info_byte_offset,
                whole.data().debug_info_byte_offset
            );
            assert_eq!(
                serde_json::to_value(&header.tries).unwrap(),
                serde_json::to_value(&whole.data().tries).unwrap()
            );
            assert_eq!(
                serde_json::to_value(&header.handlers).unwrap(),
                serde_json::to_value(&whole.data().handlers).unwrap()
            );
            // The item decoded again is the full item.
            let again = reader.get(ordinal).unwrap();
            assert_eq!(
                serde_json::to_value(again.as_ref()).unwrap(),
                serde_json::to_value(whole.data()).unwrap(),
                "{name} item {ordinal}"
            );
            assert_eq!(
                serde_json::to_value(compact.decoded_item(ordinal).unwrap().as_ref()).unwrap(),
                serde_json::to_value(whole.data()).unwrap(),
                "{name} item {ordinal} through decoded_item"
            );
            // A full value hands out its own item, not a copy.
            assert!(matches!(
                full.decoded_item(ordinal).unwrap(),
                Cow::Borrowed(_)
            ));
            items += 1;
            with_debug += usize::from(whole.data().debug_info.is_some());
            with_payload += usize::from(!whole.data().payloads.is_empty());
        }
        assert!(reader.get(full.items().len()).is_err(), "{name}");
        assert!(compact.decoded_item(usize::MAX).is_err());
        files += 1;
    }
    assert!(
        files >= 15 && items >= 40 && with_debug >= 10 && with_payload >= 3,
        "{files} files, {items} items, {with_debug} with debug, {with_payload} with payloads"
    );
}

/// The compact build reads the section once and keeps no decoded item. It must give exactly what the full build
/// followed by `compacted` gives, and fail with the same error where that fails.
#[test]
fn the_streamed_compact_build_is_the_full_build_compacted() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let (mut built, mut refused, mut shared_debug) = (0, 0, 0);
    for folder in [
        "instructions/generated",
        "definitions/generated",
        "references/generated",
    ] {
        let mut paths: Vec<_> = fs::read_dir(root.join(folder))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("dex"))
            .collect();
        paths.sort();
        for path in paths {
            let name = format!("{folder}/{}", path.file_name().unwrap().to_string_lossy());
            let Ok(snapshot) = Snapshot::capture(
                &[InputSpec {
                    path: path.clone(),
                    kind: InputKind::RawDex,
                    expected_sha256: None,
                }],
                CaptureLimits::default(),
            ) else {
                continue;
            };
            let Ok(inventory) = ArchiveInventory::build(
                &snapshot.sources()[0],
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            ) else {
                continue;
            };
            let limits = CodeLimits::default();
            let whole = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, limits);
            let streamed =
                CodeFacts::build_all_code_items_compact(&snapshot, &inventory, 0, limits);
            match (whole, streamed) {
                (Ok(whole), Ok(streamed)) => {
                    let compacted = whole.compacted().unwrap();
                    assert!(streamed.is_compact(), "{name}");
                    assert_eq!(
                        serde_json::to_value(&streamed).unwrap(),
                        serde_json::to_value(&compacted).unwrap(),
                        "{name}"
                    );
                    assert_eq!(streamed.items().len(), whole.items().len(), "{name}");
                    let (mut left, mut right) = (streamed.reader(), whole.reader());
                    let order: Vec<usize> = (0..whole.items().len())
                        .chain((0..whole.items().len()).rev())
                        .collect();
                    for ordinal in order {
                        let (a, b) = (&streamed.items()[ordinal], &whole.items()[ordinal]);
                        assert_eq!(a.opcodes(), b.opcodes(), "{name} opcodes {ordinal}");
                        assert_eq!(
                            a.names_call_site(),
                            b.names_call_site(),
                            "{name} call site {ordinal}"
                        );
                        assert_eq!(
                            a.names_method_handle(),
                            b.names_method_handle(),
                            "{name} handle {ordinal}"
                        );
                        // The item decoded again from the streamed value is the full item, program and all.
                        assert_eq!(
                            serde_json::to_value(left.get(ordinal).unwrap().as_ref()).unwrap(),
                            serde_json::to_value(right.get(ordinal).unwrap().as_ref()).unwrap(),
                            "{name} item {ordinal}"
                        );
                        // Without its debug program it is the same item without it.
                        let mut bare = left.instructions(ordinal).unwrap().into_owned();
                        assert!(bare.debug_info.is_none(), "{name} {ordinal}");
                        let mut expected = right.get(ordinal).unwrap().into_owned();
                        shared_debug += usize::from(expected.debug_info.is_some());
                        expected.debug_info = None;
                        bare.debug_info = None;
                        assert_eq!(
                            serde_json::to_value(&bare).unwrap(),
                            serde_json::to_value(&expected).unwrap(),
                            "{name} instructions {ordinal}"
                        );
                    }
                    built += 1;
                }
                (Err(whole), Err(streamed)) => {
                    assert_eq!(
                        serde_json::to_value(&streamed).unwrap(),
                        serde_json::to_value(&whole).unwrap(),
                        "{name}"
                    );
                    refused += 1;
                }
                (Ok(_), Err(error)) => {
                    panic!("{name}: only the streamed build fails: {error:?}")
                }
                (Err(error), Ok(_)) => panic!("{name}: only the full build fails: {error:?}"),
            }
        }
    }
    assert!(
        built >= 30 && shared_debug >= 10,
        "{built} built, {refused} refused, {shared_debug} items with a debug program"
    );
}

#[test]
fn compacting_is_refused_twice_and_for_a_scoped_build() {
    let (_, full) = complete_facts_of_instruction_fixtures().remove(0);
    let compact = full.compacted().unwrap();
    let again = compact.compacted().err().expect("already compact");
    assert_eq!(again.code, ErrorCode::InvalidArgument);

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/instructions/generated/unreferenced-two-code.dex");
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap();
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let all =
        CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default()).unwrap();
    let offset = u32::try_from(all.items()[0].data().raw_range.byte_offset.0).unwrap();
    let scoped =
        CodeFacts::build_offsets(&snapshot, &inventory, 0, &[offset], CodeLimits::default())
            .unwrap();
    let refused = scoped.compacted().err().expect("scoped build");
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    // The scoped value is still usable as it was.
    assert_eq!(
        scoped.decoded_item(0).unwrap().raw_range.byte_offset.0,
        u64::from(offset)
    );
}

#[test]
fn method_code_views_bind_exact_source_and_distinguish_body_states() {
    fn build(
        name: &str,
    ) -> (
        Snapshot,
        Vec<ArchiveInventory>,
        Vec<DefinitionFacts>,
        Vec<CodeFacts>,
    ) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated")
            .join(name);
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let inventories: Vec<_> = snapshot
            .sources()
            .iter()
            .map(|source| {
                ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap()
            })
            .collect();
        let definitions = inventories
            .iter()
            .map(|inventory| {
                let metadata =
                    MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default()).unwrap();
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap()
            })
            .collect();
        let code = inventories
            .iter()
            .map(|inventory| {
                CodeFacts::build_all_code_items(&snapshot, inventory, 0, CodeLimits::default())
                    .unwrap()
            })
            .collect();
        (snapshot, inventories, definitions, code)
    }
    let (snapshot, inventories, definitions, codes) = build("definitions-035.dex");
    for ordinal in 0..2 {
        let view = MethodCodeFactViews::build(
            &definitions[ordinal],
            &codes[ordinal],
            MethodCodeViewLimits::default(),
        )
        .unwrap();
        let rows = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
        for row in &rows {
            use crate::metadata::EntityKind;
            let identity = definitions[ordinal]
                .entity(EntityKind::MethodReference, row.method.reference.method_idx)
                .unwrap();
            let direct = view.get(&identity).unwrap();
            assert_eq!(
                direct.method.reference.method_idx,
                row.method.reference.method_idx
            );
            match (&direct.body, &row.body) {
                (MethodCodeBody::ReferenceOnly, MethodCodeBody::ReferenceOnly)
                | (MethodCodeBody::Native, MethodCodeBody::Native)
                | (MethodCodeBody::Abstract, MethodCodeBody::Abstract) => (),
                (
                    MethodCodeBody::Present {
                        code: a,
                        raw_insns: aa,
                    },
                    MethodCodeBody::Present {
                        code: b,
                        raw_insns: bb,
                    },
                ) => {
                    assert_eq!(a.code_item_id(), b.code_item_id());
                    assert_eq!(aa, bb);
                }
                _ => panic!("direct lookup changed body state"),
            }
            let definition = EntityRef {
                kind: EntityKind::MethodDefinition,
                ..identity.clone()
            };
            assert_eq!(
                view.get(&definition).is_ok(),
                row.method.definition.is_some()
            );
            let foreign = EntityRef {
                dex_occurrence_id: "foreign".into(),
                ..identity
            };
            assert_eq!(
                view.get(&foreign).err().unwrap().code,
                ErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            rows.len(),
            definitions[ordinal].definitions().method_references.len()
        );
        assert!(
            rows.iter().all(|row| row.method.source.dex_occurrence_id
                == codes[ordinal].source().dex_occurrence_id)
        );
        assert!(matches!(
            rows.iter()
                .find(|r| r.method.reference.method_name == "externalCall")
                .unwrap()
                .body,
            MethodCodeBody::ReferenceOnly
        ));
        assert!(matches!(
            rows.iter()
                .find(|r| r.method.reference.method_name == "nativeCall")
                .unwrap()
                .body,
            MethodCodeBody::Native
        ));
        assert!(matches!(
            rows.iter()
                .find(|r| r.method.reference.method_name == "abstractCall")
                .unwrap()
                .body,
            MethodCodeBody::Abstract
        ));
        let reference = rows
            .iter()
            .find(|r| r.method.reference.method_name == "externalCall")
            .unwrap();
        assert!(reference.body.decoded_opcode_bytes().is_none());
        assert_eq!(
            reference
                .body
                .opcode_text(OpcodeTextLimits::default())
                .unwrap(),
            None
        );
        for name in ["nativeCall", "abstractCall"] {
            let body = &rows
                .iter()
                .find(|r| r.method.reference.method_name == name)
                .unwrap()
                .body;
            assert_eq!(body.decoded_opcode_bytes().unwrap().count(), 0);
            assert_eq!(
                body.opcode_text(OpcodeTextLimits {
                    max_opcodes: 0,
                    max_text_bytes: 0
                })
                .unwrap(),
                Some(OpcodeText {
                    count: 0,
                    text: String::new()
                })
            );
        }
        let init = rows
            .iter()
            .find(|r| r.method.reference.method_name == "<init>")
            .unwrap();
        assert_eq!(
            init.body.opcode_text(OpcodeTextLimits::default()).unwrap(),
            Some(OpcodeText {
                count: 2,
                text: "70 0e".into()
            })
        );
        assert_eq!(
            init.body
                .opcode_text(OpcodeTextLimits {
                    max_opcodes: 1,
                    max_text_bytes: 5
                })
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            init.body
                .opcode_text(OpcodeTextLimits {
                    max_opcodes: 2,
                    max_text_bytes: 4
                })
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            init.body
                .opcode_text(OpcodeTextLimits {
                    max_opcodes: 2,
                    max_text_bytes: 5
                })
                .unwrap()
                .unwrap()
                .text,
            "70 0e"
        );
        let present = rows
            .iter()
            .find(|r| r.method.reference.method_name == "virtualCall")
            .unwrap();
        let MethodCodeBody::Present { code, raw_insns } = &present.body else {
            panic!("present body lost")
        };
        assert_eq!(
            raw_insns.len() as u64,
            code.data().insns_range.byte_length.0
        );
        assert_eq!(*raw_insns, &[0x0e, 0]);
        assert_eq!(
            present
                .body
                .decoded_opcode_bytes()
                .unwrap()
                .collect::<Vec<_>>(),
            [0x0e]
        );
    }
    assert_ne!(
        codes[0].source().dex_occurrence_id,
        codes[1].source().dex_occurrence_id
    );
    assert_eq!(
        MethodCodeFactViews::build(&definitions[0], &codes[1], MethodCodeViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let projection =
        CodeFacts::build_offsets(&snapshot, &inventories[0], 0, &[], CodeLimits::default())
            .unwrap();
    assert_eq!(
        MethodCodeFactViews::build(
            &definitions[0],
            &projection,
            MethodCodeViewLimits::default()
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::IncompleteFacts
    );
    let mut partial = codes[0].clone();
    partial.code_layout_coverage = Completeness::Partial;
    assert_eq!(
        MethodCodeFactViews::build(&definitions[0], &partial, MethodCodeViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut wrong_start = definitions[0].clone();
    let method = wrong_start
        .definitions
        .method_definitions
        .iter_mut()
        .find(|method| matches!(method.body, MethodBody::Present { .. }))
        .unwrap();
    let MethodBody::Present {
        code_byte_offset, ..
    } = &mut method.body
    else {
        unreachable!()
    };
    *code_byte_offset = DecimalU64(1);
    assert_eq!(
        MethodCodeFactViews::build(&wrong_start, &codes[0], MethodCodeViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
    for limits in [
        MethodCodeViewLimits {
            max_code_items: 0,
            ..MethodCodeViewLimits::default()
        },
        MethodCodeViewLimits {
            max_code_index_bytes: 0,
            ..MethodCodeViewLimits::default()
        },
    ] {
        assert_eq!(
            MethodCodeFactViews::build(&definitions[0], &codes[0], limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let (_, _, zero_definitions, zero_codes) = build("zero-insns-present.dex");
    let zero = MethodCodeFactViews::build(
        &zero_definitions[0],
        &zero_codes[0],
        MethodCodeViewLimits::default(),
    )
    .unwrap();
    let empty = zero
        .iter()
        .find_map(|row| {
            let row = row.unwrap();
            (row.method.reference.method_name == "privateCall").then_some(row)
        })
        .unwrap();
    assert_eq!(empty.body.decoded_opcode_bytes().unwrap().count(), 0);
    assert_eq!(
        empty.body.opcode_text(OpcodeTextLimits::default()).unwrap(),
        Some(OpcodeText {
            count: 0,
            text: String::new()
        })
    );
    assert!(matches!(
        empty.body,
        MethodCodeBody::Present { raw_insns: [], .. }
    ));
}

#[test]
fn decoded_opcode_iteration_excludes_payload_words() {
    for (name, expected) in [
        ("packed-switch.dex", 0x2b),
        ("sparse-switch.dex", 0x2c),
        ("fill-array.dex", 0x26),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/instructions/generated")
            .join(name);
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path,
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        assert_eq!(code.items()[0].data().payloads.len(), 1);
        let body = MethodCodeBody::Present {
            code: &code.items()[0],
            raw_insns: code.raw_insns(0).unwrap(),
        };
        assert_eq!(
            body.decoded_opcode_bytes().unwrap().collect::<Vec<_>>(),
            [expected, 0x0e]
        );
        assert_eq!(
            body.opcode_text(OpcodeTextLimits::default())
                .unwrap()
                .unwrap(),
            OpcodeText {
                count: 2,
                text: format!("{expected:02x} 0e")
            }
        );
        assert!(
            code.raw_insns(0).unwrap().len() > 2 * body.decoded_opcode_bytes().unwrap().count()
        );
    }
}

#[test]
fn all_hand_fixtures_match_independent_python_oracle_fields_and_raw_bytes() {
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/instructions/expected-results.json"
    ))
    .unwrap();
    let mut accepted = 0;
    let mut rejected = 0;
    for record in expected["results"].as_array().unwrap() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/instructions/generated")
            .join(record["path"].as_str().unwrap());
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path,
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let result =
            CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default());
        if record["status"] == "expected_invalid" {
            assert!(result.is_err(), "{}", record["path"]);
            rejected += 1;
            continue;
        }
        let facts = result.unwrap_or_else(|error| panic!("{}: {error}", record["path"]));
        accepted += 1;
        let rows = record["items"].as_array().unwrap();
        assert_eq!(facts.items.len(), rows.len());
        for (ordinal, (native, reference)) in facts.items.iter().zip(rows).enumerate() {
            let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            assert_eq!(
                native.data.raw_range.byte_offset.0,
                reference["offset"].as_u64().unwrap()
            );
            assert_eq!(
                hex(facts.raw_insns(ordinal).unwrap()),
                reference["insns_bytes"].as_str().unwrap()
            );
            assert_eq!(
                hex(facts.raw_code_item(ordinal).unwrap()),
                reference["code_bytes"].as_str().unwrap()
            );
            if let Some(payload) = reference.get("payload") {
                match &native.data.payloads[0].data {
                    mdd_dex::instructions::PayloadData::PackedSwitch {
                        first_key,
                        relative_targets,
                    } => {
                        assert_eq!(serde_json::json!(first_key), payload["first_key"]);
                        assert_eq!(serde_json::json!(relative_targets), payload["targets"]);
                    }
                    mdd_dex::instructions::PayloadData::SparseSwitch {
                        keys,
                        relative_targets,
                    } => {
                        assert_eq!(serde_json::json!(keys), payload["keys"]);
                        assert_eq!(serde_json::json!(relative_targets), payload["targets"]);
                    }
                    mdd_dex::instructions::PayloadData::FillArray {
                        element_width_bytes,
                        element_count,
                        data_range,
                    } => {
                        assert_eq!(serde_json::json!(element_width_bytes), payload["width"]);
                        assert_eq!(serde_json::json!(element_count), payload["count"]);
                        assert_eq!(
                            serde_json::json!(facts.bytes_in(data_range).unwrap()),
                            payload["bytes"]
                        );
                    }
                }
            }
            let tries: Vec<_> = native
                .data
                .tries
                .iter()
                .map(|item| {
                    serde_json::json!([
                        item.start_code_unit,
                        item.code_unit_count,
                        item.handler_relative_byte_offset
                    ])
                })
                .collect();
            assert_eq!(serde_json::json!(tries), reference["tries"]);
            let handlers:Vec<_>=native.data.handlers.iter().map(|item|serde_json::json!({
                "relative":item.relative_byte_offset,"typed":item.typed_catches.iter().map(|p|[p.type_idx,p.address_code_units]).collect::<Vec<_>>(),
                "catch_all":item.catch_all_address_code_units})).collect();
            assert_eq!(serde_json::json!(handlers), reference["handlers"]);
            if let Some(debug) = reference.get("debug") {
                let native = native.data.debug_info.as_ref().unwrap();
                let positions: Vec<_> = native
                    .events
                    .iter()
                    .filter(|e| e.emits_position)
                    .map(|e| serde_json::json!([e.address_code_units, e.encoded_line_decimal.0]))
                    .collect();
                assert_eq!(serde_json::json!(positions), debug["positions"]);
                let view: Vec<_> = native
                    .method_positions()
                    .map(|e| serde_json::json!([e.address_code_units, e.encoded_line_decimal.0]))
                    .collect();
                assert_eq!(serde_json::json!(view), debug["applicable_positions"]);
                let source: Vec<_> = native
                    .usable_source_positions()
                    .map(|e| serde_json::json!([e.address_code_units, e.source_line.unwrap().0]))
                    .collect();
                assert_eq!(serde_json::json!(source), debug["usable_source_positions"]);
                assert_eq!(
                    serde_json::json!(native.representation),
                    debug["representation"]
                );
                assert_eq!(
                    serde_json::json!(native.events.iter().map(|e| e.opcode).collect::<Vec<_>>()),
                    debug["operations"]
                );
            }
        }
    }
    assert_eq!((accepted, rejected), (20, 5));
}

#[test]
fn raw_code_retains_exact_member_lease_scope_and_occurrence_after_source_changes() {
    let directory = std::env::temp_dir().join(mdd_types::opaque_id("code-facts-test").unwrap());
    fs::create_dir(&directory).unwrap();
    let path = directory.join("input.dex");
    let original =
        include_bytes!("../../../tests/fixtures/instructions/generated/unreferenced-two-code.dex");
    fs::write(&path, original).unwrap();
    let spec = InputSpec {
        path: path.clone(),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[spec.clone(), spec], CaptureLimits::default()).unwrap();
    let left = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let right = ArchiveInventory::build(
        &snapshot.sources()[1],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let facts =
        CodeFacts::build_all_code_items(&snapshot, &left, 0, CodeLimits::default()).unwrap();
    let other =
        CodeFacts::build_all_code_items(&snapshot, &right, 0, CodeLimits::default()).unwrap();
    assert_eq!(facts.items.len(), 2);
    assert_ne!(facts.items[0].code_item_id, other.items[0].code_item_id);
    assert!(Arc::ptr_eq(
        &facts.lease(),
        &left.selected_dexes()[0].blob.lease()
    ));
    assert_eq!(facts.raw_insns(0).unwrap(), &[0x0e, 0]);
    let scoped =
        CodeFacts::build_offsets(&snapshot, &left, 0, &[132, 112, 132], CodeLimits::default())
            .unwrap();
    assert_eq!(scoped.items.len(), 3);
    assert!(scoped.scope.starts_with("explicit-code-offsets"));
    assert_eq!(
        scoped.declared_code_item_byte_offsets(),
        &[DecimalU64(112), DecimalU64(132)]
    );
    assert!(scoped.known_code_item_start(132));
    assert!(!scoped.known_code_item_start(113));
    assert!(!facts.references_built);
    assert!(!facts.method_ownership_built);
    assert!(!facts.full_dex_validation_complete);
    fs::write(&path, b"changed external source").unwrap();
    fs::rename(&path, directory.join("renamed.dex")).unwrap();
    drop(snapshot);
    drop(left);
    drop(right);
    assert_eq!(facts.raw_insns(1).unwrap(), &[0x0e, 0]);
    assert_eq!(facts.lease().as_ref(), original);
    assert_eq!(
        other.raw_code_item(0).unwrap(),
        facts.raw_code_item(0).unwrap()
    );
}

/// Independent raw-header oracle for one code item, mirroring the frozen
/// HostLab `raw_fields` layout without reusing the parser under test.
fn raw_code_fields(raw: &[u8], offset: usize) -> serde_json::Value {
    let u16at = |at: usize| u16::from_le_bytes(raw[at..at + 2].try_into().unwrap());
    let u32at = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
    let registers_size = u16at(offset);
    let ins_size = u16at(offset + 2);
    let outs_size = u16at(offset + 4);
    let tries_size = u16at(offset + 6);
    let debug_info_off = u32at(offset + 8);
    let insns_size = u32at(offset + 12);
    let insns_off = offset + 16;
    let insns_end = insns_off + insns_size as usize * 2;
    let tries_off = if tries_size == 0 {
        None
    } else {
        Some(insns_end + (insns_size as usize % 2) * 2)
    };
    let handlers_off = tries_off.map(|at| at + usize::from(tries_size) * 8);
    serde_json::json!({
        "code_off": offset,
        "registers_size": registers_size,
        "ins_size": ins_size,
        "outs_size": outs_size,
        "tries_size": tries_size,
        "debug_info_off": debug_info_off,
        "insns_size": insns_size,
        "insns_off": insns_off,
        "tries_off": tries_off,
        "handlers_off": handlers_off,
    })
}

#[test]
fn code_item_rows_match_independent_raw_header_oracle() {
    use crate::definitions::DefinitionFacts;
    use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/classic-035.dex");
    let raw = fs::read(&path).unwrap();
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path: path.clone(),
            kind: InputKind::RawDex,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap();
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let metadata =
        crate::MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
    let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
    let code =
        CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default()).unwrap();
    let views =
        MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default()).unwrap();
    let rows = views.code_item_rows(0).unwrap();
    let mut expected = Vec::new();
    for definition in &definitions.definitions().method_definitions {
        let MethodBody::Present {
            code_byte_offset, ..
        } = definition.body
        else {
            continue;
        };
        let mut value = raw_code_fields(&raw, code_byte_offset.0 as usize);
        let object = value.as_object_mut().unwrap();
        object.insert("file_id".to_owned(), serde_json::json!(0));
        object.insert(
            "method_idx".to_owned(),
            serde_json::json!(definition.method_idx),
        );
        expected.push(value);
    }
    expected.sort_by_key(|row| row["method_idx"].as_u64().unwrap());
    let actual = serde_json::to_value(&rows).unwrap();
    assert_eq!(actual, serde_json::Value::Array(expected));
    // Shared and physical-only items: this fixture has one code item per
    // present method, and every physical item is method-owned.
    assert_eq!(rows.len(), code.items().len());
    assert!(rows.iter().all(|row| row.tries_off.is_none()));
    assert!(rows.iter().all(|row| row.handlers_off.is_none()));
}

#[test]
fn code_item_rows_expand_shared_bodies_once_per_method_owner() {
    use crate::definitions::DefinitionFacts;
    use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/shared-code-035.dex");
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path: path.clone(),
            kind: InputKind::RawDex,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap();
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let metadata =
        crate::MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
    let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
    let code =
        CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default()).unwrap();
    let views =
        MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default()).unwrap();
    let rows = views.code_item_rows(0).unwrap();
    // The recorded A0 slice for this fixture has three method-owned rows
    // over two physical items, so a shared body must expand per owner.
    assert_eq!(rows.len(), 3);
    assert_eq!(code.items().len(), 2);
    let shared = rows
        .iter()
        .filter(|row| row.code_off == rows[0].code_off)
        .count();
    assert!(shared >= 2, "expected a shared body to expand");
    let mut method_indices = rows.iter().map(|row| row.method_idx).collect::<Vec<_>>();
    method_indices.sort_unstable();
    assert_eq!(
        method_indices,
        rows.iter().map(|row| row.method_idx).collect::<Vec<_>>()
    );
    assert!(
        views
            .require_relation_columns(CodeRelation::CodeItems, &["*"])
            .is_ok()
    );
    assert_eq!(
        views
            .require_relation_columns(CodeRelation::CodeItems, &["opcode_count"])
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
}

/// Build the code-joined `methods` rows for one fixture and compare every
/// column with an independent reading of the same bytes.
fn joined_methods(name: &str) -> Vec<MethodCodeRow> {
    use crate::definitions::DefinitionFacts;
    use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated")
        .join(name);
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap();
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let metadata =
        crate::MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
    let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
    let code =
        CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default()).unwrap();
    let views =
        MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default()).unwrap();
    views.method_rows(0).unwrap()
}

#[test]
fn methods_rows_assemble_all_contract_columns_and_match_recorded_a0() {
    let rows = joined_methods("definitions-035.dex");
    assert_eq!(rows.len(), 13, "recorded A0 slice has 13 method rows");
    // Every contract column is present exactly once. `serde_json` maps sort
    // their keys, so the assertion is set equality; the struct field order in
    // `MethodCodeRow` mirrors `COLUMNS` and the contract.
    let actual = serde_json::to_value(&rows).unwrap();
    let first = actual.as_array().unwrap()[0].as_object().unwrap();
    let mut names = first.keys().map(String::as_str).collect::<Vec<_>>();
    names.sort_unstable();
    let mut expected = MethodCodeRow::COLUMNS.to_vec();
    expected.sort_unstable();
    assert_eq!(names, expected);
    // `param_descriptors` and the two opcode columns are now present, with
    // the opcode columns NULL only for a reference-only method.
    let external = rows.iter().find(|row| row.name == "externalCall").unwrap();
    assert!(
        external.access_flags.is_none()
            && external.opcode_count.is_none()
            && external.opcode_hex.is_none()
    );
    let native = rows.iter().find(|row| row.name == "nativeCall").unwrap();
    assert_eq!(
        (native.opcode_count, native.opcode_hex.as_deref()),
        (Some(0), Some(""))
    );
    let init = rows.iter().find(|row| row.name == "<init>").unwrap();
    assert_eq!(
        (init.opcode_count, init.opcode_hex.as_deref()),
        (Some(2), Some("70 0e"))
    );
    // The parameter descriptor text is the exact ordered vector, not a
    // re-derived prototype string.
    let static_call = rows.iter().find(|row| row.name == "staticCall").unwrap();
    assert_eq!(static_call.param_descriptors, "I");
    assert_eq!(static_call.param_count, 1);
    assert!(init.param_descriptors.is_empty());
    // `insns_size` is not the opcode count: the count is the decoded
    // ordinary-instruction count, so compare against the recorded A0 text.
    let a0 = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../artifacts/mdd-026/method-atom-audit/20261028T165707192974Z/a0-definitions/stdout.txt",
    );
    let table = fs::read_to_string(a0).unwrap();
    let mut checked = 0usize;
    for line in table.lines().filter(|line| line.starts_with('|')) {
        let cells: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells[0] == "file_id" {
            continue;
        }
        assert_eq!(cells.len(), 14, "A0 methods table must have 14 columns");
        let hex_text = |cell: &str| -> Option<String> {
            (cell != "N").then(|| {
                String::from_utf8(
                    cell.as_bytes()
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| {
                            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            })
        };
        let index: u32 = hex_text(cells[1]).unwrap().parse().unwrap();
        let row = rows
            .iter()
            .find(|row| row.method_idx == index)
            .unwrap_or_else(|| panic!("A0 method_idx {index} is missing"));
        let count = hex_text(cells[11]).map(|value| value.parse::<u32>().unwrap());
        assert_eq!(row.opcode_count, count, "method {index} opcode_count");
        assert_eq!(
            row.opcode_hex,
            hex_text(cells[12]),
            "method {index} opcode_hex"
        );
        assert_eq!(
            Some(row.param_descriptors.clone()),
            hex_text(cells[9]),
            "method {index} param_descriptors"
        );
        checked += 1;
    }
    assert_eq!(checked, 13);
}

#[test]
fn methods_rows_reject_unknown_columns_and_accept_the_full_contract() {
    assert!(MethodCodeFactViews::require_method_columns(&["*"]).is_ok());
    assert!(
        MethodCodeFactViews::require_method_columns(MethodCodeRow::COLUMNS).is_ok(),
        "the code-joined projection must accept every contract column"
    );
    let error = MethodCodeFactViews::require_method_columns(&["invented_column"]).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.details["column"], "invented_column");
}
