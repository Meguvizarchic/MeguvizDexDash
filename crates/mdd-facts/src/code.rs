//! Snapshot-bound code layout facts; method ownership is a separate definition layer.
use crate::{
    MetadataSource,
    definitions::{DefinitionFacts, MethodFactView, MethodFactViews, MethodViewLimits},
    metadata::EntityRef,
};
use mdd_dex::{
    definitions::MethodBody,
    instructions::{
        CodeItem, CodeLimits, CodeSection, DebugPolicy, read_code_offsets, read_code_section,
    },
    validate_header,
};
use mdd_input::{
    archive::{ArchiveInventory, MemberBlob},
    snapshot::Snapshot,
};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone, Serialize)]
pub struct CodeFact {
    pub(crate) code_item_id: String,
    pub(crate) data: CodeItem,
}

impl CodeFact {
    pub fn code_item_id(&self) -> &str {
        &self.code_item_id
    }
    pub fn data(&self) -> &CodeItem {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetadataFacts;
    use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
    use mdd_input::{
        archive::{ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec},
    };
    use std::fs;

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
                        MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default())
                            .unwrap();
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
            assert!(rows.iter().all(|row| row.method.source.dex_occurrence_id
                == codes[ordinal].source().dex_occurrence_id));
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
            let code =
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
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
                let hex =
                    |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
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
                        .map(|e| {
                            serde_json::json!([e.address_code_units, e.encoded_line_decimal.0])
                        })
                        .collect();
                    assert_eq!(serde_json::json!(positions), debug["positions"]);
                    let view: Vec<_> = native
                        .method_positions()
                        .map(|e| {
                            serde_json::json!([e.address_code_units, e.encoded_line_decimal.0])
                        })
                        .collect();
                    assert_eq!(serde_json::json!(view), debug["applicable_positions"]);
                    let source: Vec<_> = native
                        .usable_source_positions()
                        .map(|e| {
                            serde_json::json!([e.address_code_units, e.source_line.unwrap().0])
                        })
                        .collect();
                    assert_eq!(serde_json::json!(source), debug["usable_source_positions"]);
                    assert_eq!(
                        serde_json::json!(native.representation),
                        debug["representation"]
                    );
                    assert_eq!(
                        serde_json::json!(
                            native.events.iter().map(|e| e.opcode).collect::<Vec<_>>()
                        ),
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
        let original = include_bytes!(
            "../../../tests/fixtures/instructions/generated/unreferenced-two-code.dex"
        );
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
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        let views =
            MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default())
                .unwrap();
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
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        let views =
            MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default())
                .unwrap();
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
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        let views =
            MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default())
                .unwrap();
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
}

/// Immutable validated encoded facts; source-position semantics remain separate.
/// ```compile_fail
/// # use mdd_facts::code::CodeFacts;
/// fn forge(facts: &mut CodeFacts) { facts.items.clear(); }
/// ```
#[derive(Clone, Serialize)]
pub struct CodeFacts {
    pub(crate) source: MetadataSource,
    pub(crate) scope: String,
    pub(crate) debug_policy: DebugPolicy,
    pub(crate) declared_map_code_item_count: u32,
    pub(crate) declared_code_item_byte_offsets: Vec<DecimalU64>,
    pub(crate) requested_code_byte_offsets: Vec<DecimalU64>,
    pub(crate) items: Vec<CodeFact>,
    pub(crate) code_layout_coverage: Completeness,
    pub(crate) method_ownership_built: bool,
    pub(crate) references_built: bool,
    pub(crate) source_positions_built: bool,
    pub(crate) full_dex_validation_complete: bool,
    #[serde(skip)]
    blob: MemberBlob,
}

impl CodeFacts {
    pub fn build_all_code_items(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        limits: CodeLimits,
    ) -> MddResult<Self> {
        Self::build(snapshot, inventory, dex_index, None, limits)
    }

    pub fn build_offsets(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        offsets: &[u32],
        limits: CodeLimits,
    ) -> MddResult<Self> {
        Self::build(snapshot, inventory, dex_index, Some(offsets), limits)
    }

    fn build(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        offsets: Option<&[u32]>,
        limits: CodeLimits,
    ) -> MddResult<Self> {
        let source_entry = snapshot
            .manifest()
            .sources
            .iter()
            .find(|source| {
                source.occurrence_id == inventory.manifest().source_occurrence_id
                    && source.content_id == inventory.manifest().source_content_id
            })
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.code",
                    "inventory does not belong to snapshot",
                )
            })?;
        let candidate = inventory.selected_dexes().get(dex_index).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "DEX occurrence index outside inventory",
            )
        })?;
        let source = MetadataSource {
            snapshot_id: snapshot.manifest().snapshot_id.clone(),
            dex_occurrence_id: candidate.dex_occurrence_id.clone(),
            physical_dex_id: candidate.physical_dex_id.clone(),
            member_id: candidate.blob.identity.member_id.clone(),
            source_occurrence_id: source_entry.occurrence_id.clone(),
            content_id: candidate.blob.content_id.clone(),
        };
        let bind = |error: MddError| {
            error
                .detail("source_binding", "snapshot_member_lease")
                .detail("snapshot_id", source.snapshot_id.clone())
                .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
                .detail("member_id", source.member_id.clone())
                .detail("content_id", source.content_id.clone())
        };
        if candidate.logical_header_byte_offset.0 != 0
            || candidate.blob.identity.source_occurrence_id != source_entry.occurrence_id
        {
            return Err(bind(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "unsupported logical offset or mismatched source",
            )));
        }
        if content_id(candidate.blob.bytes()) != source.content_id {
            return Err(bind(MddError::new(
                ErrorCode::InternalFault,
                "facts.code",
                "held bytes differ from content identity",
            )));
        }
        let header = validate_header(candidate.blob.bytes()).map_err(bind)?;
        let section: CodeSection = match offsets {
            None => read_code_section(candidate.blob.bytes(), &header, limits),
            Some(offsets) => read_code_offsets(candidate.blob.bytes(), &header, offsets, limits),
        }
        .map_err(bind)?;
        let items = section
            .items
            .into_iter()
            .map(|data| CodeFact {
                code_item_id: format!(
                    "{}:code-byte:{}",
                    source.dex_occurrence_id, data.raw_range.byte_offset.0
                ),
                data,
            })
            .collect();
        Ok(Self {
            source,
            scope: section.scope,
            debug_policy: limits.debug_policy,
            declared_map_code_item_count: section.declared_code_item_count,
            declared_code_item_byte_offsets: section.declared_code_item_byte_offsets,
            requested_code_byte_offsets: offsets
                .unwrap_or(&[])
                .iter()
                .map(|n| DecimalU64(u64::from(*n)))
                .collect(),
            items,
            code_layout_coverage: Completeness::Complete,
            method_ownership_built: false,
            references_built: false,
            source_positions_built: false,
            full_dex_validation_complete: false,
            blob: candidate.blob.clone(),
        })
    }

    pub fn lease(&self) -> Arc<[u8]> {
        self.blob.lease()
    }

    pub fn source(&self) -> &MetadataSource {
        &self.source
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn debug_policy(&self) -> DebugPolicy {
        self.debug_policy
    }
    pub fn declared_map_code_item_count(&self) -> u32 {
        self.declared_map_code_item_count
    }
    pub fn declared_code_item_byte_offsets(&self) -> &[DecimalU64] {
        &self.declared_code_item_byte_offsets
    }
    pub fn known_code_item_start(&self, offset: u64) -> bool {
        self.declared_code_item_byte_offsets
            .binary_search_by_key(&offset, |item| item.0)
            .is_ok()
    }
    pub fn requested_code_byte_offsets(&self) -> &[DecimalU64] {
        &self.requested_code_byte_offsets
    }
    pub fn items(&self) -> &[CodeFact] {
        &self.items
    }
    pub fn code_layout_coverage(&self) -> Completeness {
        self.code_layout_coverage
    }
    pub fn method_ownership_built(&self) -> bool {
        self.method_ownership_built
    }
    pub fn references_built(&self) -> bool {
        self.references_built
    }
    pub fn source_positions_built(&self) -> bool {
        self.source_positions_built
    }
    pub fn full_dex_validation_complete(&self) -> bool {
        self.full_dex_validation_complete
    }

    fn bytes_in(&self, range: &mdd_dex::DexRange) -> MddResult<&[u8]> {
        mdd_dex::checked_reader::CheckedReader::new(self.blob.bytes())
            .range(range.byte_offset.0, range.byte_length.0)
    }

    pub fn raw_insns(&self, ordinal: usize) -> MddResult<&[u8]> {
        let item = self.items.get(ordinal).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "code ordinal outside scope",
            )
        })?;
        self.bytes_in(&item.data.insns_range)
    }

    pub fn raw_code_item(&self, ordinal: usize) -> MddResult<&[u8]> {
        let item = self.items.get(ordinal).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "code ordinal outside scope",
            )
        })?;
        self.bytes_in(&item.data.raw_range)
    }
}

/// Logical join limits. These are not an allocator or process RSS bound.
#[derive(Clone, Copy, Debug)]
pub struct MethodCodeViewLimits {
    pub methods: MethodViewLimits,
    pub max_code_items: u64,
    pub max_code_index_bytes: u64,
}
impl Default for MethodCodeViewLimits {
    fn default() -> Self {
        Self {
            methods: MethodViewLimits::default(),
            max_code_items: 4_000_000,
            max_code_index_bytes: 256 * 1024 * 1024,
        }
    }
}

/// These variants distinguish a reference from actual definitions without bodies.
/// `Present` contains exact validated code facts, not a legacy opcode projection.
pub enum MethodCodeBody<'a> {
    ReferenceOnly,
    Native,
    Abstract,
    Present {
        code: &'a CodeFact,
        raw_insns: &'a [u8],
    },
}

/// Logical limits for a single opcode text projection; not an RSS bound.
#[derive(Clone, Copy, Debug)]
pub struct OpcodeTextLimits {
    pub max_opcodes: u64,
    pub max_text_bytes: u64,
}
impl Default for OpcodeTextLimits {
    fn default() -> Self {
        Self {
            max_opcodes: 4_000_000,
            max_text_bytes: 12_000_000,
        }
    }
}

/// Exact ordinary-instruction count and lower-case hexadecimal text, in order.
/// The underlying `MethodCodeBody` retains the specific definition/body state.
#[derive(Debug, Eq, PartialEq)]
pub struct OpcodeText {
    pub count: u32,
    pub text: String,
}

impl MethodCodeBody<'_> {
    /// Iterates decoded ordinary-instruction opcode bytes in code-unit order.
    /// Payloads are separately represented by `CodeItem::payloads` and are not
    /// instructions. The original body variant still distinguishes native,
    /// abstract and present-empty; a reference has no defined opcode sequence.
    /// This is not a legacy hexadecimal rendering or a profile qualification.
    pub fn decoded_opcode_bytes(&self) -> Option<impl ExactSizeIterator<Item = u8> + '_> {
        let instructions: &[mdd_dex::instructions::Instruction] = match self {
            Self::ReferenceOnly => return None,
            Self::Native | Self::Abstract => &[],
            Self::Present { code, .. } => &code.data().instructions,
        };
        Some(instructions.iter().map(|instruction| instruction.opcode))
    }

    /// Render ordinary opcodes as two lower-case hex digits separated by a
    /// single space. Reference-only methods return None; native, abstract and
    /// present-empty definitions return a zero count and empty text. Payload
    /// words are not included. Limits cover logical opcode/text bytes only.
    pub fn opcode_text(&self, limits: OpcodeTextLimits) -> MddResult<Option<OpcodeText>> {
        let Some(opcodes) = self.decoded_opcode_bytes() else {
            return Ok(None);
        };
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.opcode_text",
                "opcode text projection budget exceeded",
            )
        };
        let count = u64::try_from(opcodes.len()).map_err(|_| quota())?;
        let count_u32 = u32::try_from(count).map_err(|_| quota())?;
        let bytes = count
            .checked_mul(3)
            .and_then(|value| {
                if count == 0 {
                    Some(0)
                } else {
                    value.checked_sub(1)
                }
            })
            .ok_or_else(quota)?;
        if count > limits.max_opcodes || bytes > limits.max_text_bytes {
            return Err(quota());
        }
        let mut text = String::new();
        text.try_reserve_exact(usize::try_from(bytes).map_err(|_| quota())?)
            .map_err(|_| quota())?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (ordinal, opcode) in opcodes.enumerate() {
            if ordinal != 0 {
                text.push(' ');
            }
            text.push(char::from(HEX[usize::from(opcode >> 4)]));
            text.push(char::from(HEX[usize::from(opcode & 0x0f)]));
        }
        Ok(Some(OpcodeText {
            count: count_u32,
            text,
        }))
    }
}
pub struct MethodCodeFactView<'a> {
    pub method: MethodFactView<'a>,
    pub body: MethodCodeBody<'a>,
}
pub struct MethodCodeFactViews<'a> {
    methods: MethodFactViews<'a>,
    code: &'a CodeFacts,
    code_index: Vec<usize>,
}
impl<'a> MethodCodeFactViews<'a> {
    /// Bind complete same-occurrence definitions and code layout. A scoped code
    /// projection is accepted only when every present method body is included.
    pub fn build(
        definitions: &'a DefinitionFacts,
        code: &'a CodeFacts,
        limits: MethodCodeViewLimits,
    ) -> MddResult<Self> {
        let source = definitions.metadata().source();
        let actual = code.source();
        if source.snapshot_id != actual.snapshot_id
            || source.dex_occurrence_id != actual.dex_occurrence_id
            || source.physical_dex_id != actual.physical_dex_id
            || source.member_id != actual.member_id
            || source.source_occurrence_id != actual.source_occurrence_id
            || source.content_id != actual.content_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.method_code",
                "definitions and code do not bind the same source generation",
            ));
        }
        if code.code_layout_coverage() != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.method_code",
                "complete code layout for requested items is required",
            ));
        }
        let methods = definitions.method_fact_views(limits.methods)?;
        let count = u64::try_from(code.items().len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.method_code",
                "code index count overflow",
            )
        })?;
        let bytes = count
            .checked_mul(std::mem::size_of::<usize>() as u64)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.method_code",
                    "code index byte overflow",
                )
            })?;
        if count > limits.max_code_items || bytes > limits.max_code_index_bytes {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.method_code",
                "code index budget exceeded",
            ));
        }
        let mut code_index = Vec::new();
        code_index
            .try_reserve_exact(code.items().len())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.method_code",
                    "code index allocation failed",
                )
            })?;
        code_index.extend(0..code.items().len());
        code_index
            .sort_unstable_by_key(|&ordinal| code.items()[ordinal].data().raw_range.byte_offset.0);
        let view = Self {
            methods,
            code,
            code_index,
        };
        // Fail before exposing any rows if a selected projection omitted a real body.
        for method in view.methods.iter() {
            view.body(&method?)?;
        }
        Ok(view)
    }

    fn body(&self, method: &MethodFactView<'a>) -> MddResult<MethodCodeBody<'a>> {
        let Some(definition) = method.definition else {
            return Ok(MethodCodeBody::ReferenceOnly);
        };
        match &definition.body {
            MethodBody::Native => Ok(MethodCodeBody::Native),
            MethodBody::Abstract => Ok(MethodCodeBody::Abstract),
            MethodBody::Present {
                code_byte_offset,
                declared_insns_size,
            } => {
                let at = code_byte_offset.0;
                if !self.code.known_code_item_start(at) {
                    return Err(MddError::new(
                        ErrorCode::InvalidInput,
                        "facts.method_code",
                        "method body is not a physical code item start",
                    )
                    .detail("method_idx", definition.method_idx.to_string())
                    .detail("code_item_byte_offset", at.to_string()));
                }
                let position = self
                    .code_index
                    .binary_search_by_key(&at, |&ordinal| {
                        self.code.items()[ordinal].data().raw_range.byte_offset.0
                    })
                    .map_err(|_| {
                        MddError::new(
                            ErrorCode::IncompleteFacts,
                            "facts.method_code",
                            "method body absent from selected code projection",
                        )
                        .detail("method_idx", definition.method_idx.to_string())
                        .detail("code_item_byte_offset", at.to_string())
                    })?;
                let ordinal = self.code_index[position];
                let code: &'a CodeFacts = self.code;
                let item = &code.items()[ordinal];
                let data = item.data();
                let expected = u64::from(*declared_insns_size) * 2;
                if data.insns_size_code_units != *declared_insns_size
                    || data.insns_range.byte_length.0 != expected
                    || at.checked_add(16) != Some(data.insns_range.byte_offset.0)
                {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "facts.method_code",
                        "definition and code instruction intervals disagree",
                    ));
                }
                let raw_insns = code.raw_insns(ordinal)?;
                Ok(MethodCodeBody::Present {
                    code: item,
                    raw_insns,
                })
            }
        }
    }

    /// Look up a method identity in the already validated source-bound view.
    /// Reference-only, native, abstract and present bodies remain distinct.
    pub fn get(&self, entity: &EntityRef) -> MddResult<MethodCodeFactView<'a>> {
        let method = self.methods.get(entity)?;
        let body = self.body(&method)?;
        Ok(MethodCodeFactView { method, body })
    }

    /// Iterate every method reference in DEX order, including reference-only rows.
    pub fn iter(&self) -> impl Iterator<Item = MddResult<MethodCodeFactView<'a>>> + '_ {
        self.methods.iter().map(|method| {
            let method = method?;
            let body = self.body(&method)?;
            Ok(MethodCodeFactView { method, body })
        })
    }

    /// Gate a requested `code_items` column list before projection.
    pub fn require_relation_columns(
        &self,
        relation: CodeRelation,
        columns: &[&str],
    ) -> MddResult<()> {
        let CodeRelation::CodeItems = relation;
        require_code_item_columns(columns)
    }

    /// Gate a requested `methods` column list for the code-joined projection.
    ///
    /// Unlike [`DefinitionFacts::require_relation_columns`], this gate accepts
    /// `opcode_count`/`opcode_hex` because the code-layout layer is present, and
    /// it accepts `*` because every contract column of `methods` is produced
    /// here.
    pub fn require_method_columns(columns: &[&str]) -> MddResult<()> {
        for column in columns {
            if *column != "*" && !MethodCodeRow::COLUMNS.contains(column) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.method_code",
                    "unknown methods column",
                )
                .detail("column", (*column).to_owned()));
            }
        }
        Ok(())
    }

    /// Project one complete `methods` row per encoded method_id, in DEX order.
    ///
    /// The 12 definition-layer columns keep their reference-only NULLs;
    /// `opcode_count`/`opcode_hex` are the exact decoded ordinary-instruction
    /// count and lower-case hex text of the same occurrence, and are `None`
    /// exactly for a reference-only method. `insns_size` is never used as a
    /// proxy for the opcode count and payload words are never rendered.
    ///
    /// This is the MDD-032 complete legacy `Methods` relation; the tokenizer
    /// shape itself is a compatibility projection, not a native atom.
    pub fn method_rows(&self, file_id: u32) -> MddResult<Vec<MethodCodeRow>> {
        Self::require_method_columns(MethodCodeRow::COLUMNS)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.methods.method_count())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.method_code",
                    "methods row allocation failed",
                )
            })?;
        for view in self.iter() {
            let view = view?;
            let reference = view.method.reference;
            let param_count =
                u32::try_from(reference.parameter_descriptors.len()).map_err(|_| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.method_code",
                        "validated parameter count exceeds UInt32",
                    )
                    .detail("method_idx", u64::from(reference.method_idx))
                })?;
            let (opcode_count, opcode_hex) =
                match view.body.opcode_text(OpcodeTextLimits::default()) {
                    Ok(Some(text)) => (Some(text.count), Some(text.text)),
                    Ok(None) => (None, None),
                    Err(error) => {
                        return Err(error
                            .detail("method_idx", u64::from(reference.method_idx))
                            .detail("column", "opcode_hex"));
                    }
                };
            rows.push(MethodCodeRow {
                file_id,
                method_idx: reference.method_idx,
                class_idx: reference.class_idx,
                class_descriptor: reference.class_descriptor.clone(),
                proto_idx: reference.proto_idx,
                name: reference.method_name.clone(),
                descriptor: reference.descriptor.clone(),
                return_descriptor: reference.return_descriptor.clone(),
                param_count,
                param_descriptors: crate::definitions::parameter_descriptors_text(
                    &reference.parameter_descriptors,
                )?,
                access_flags: view
                    .method
                    .definition
                    .map(|definition| definition.access_flags),
                opcode_count,
                opcode_hex,
                method_kind: view
                    .method
                    .definition
                    .map(|definition| definition.kind.as_str().to_owned()),
            });
        }
        Ok(rows)
    }

    /// Project one `code_items` row per method-owned present body, in
    /// `method_idx` order. A physical code item with no declaring method is not
    /// a row of this relation because `method_idx` is NOT NULL; a shared body
    /// expands once per owning method.
    ///
    /// `debug_info_off` projects the encoded header word, so an absent debug
    /// section is the encoded zero offset rather than NULL. `tries_off` and
    /// `handlers_off` are NULL exactly when the encoded try list is empty.
    pub fn code_item_rows(&self, file_id: u32) -> MddResult<Vec<CodeItemRow>> {
        self.require_relation_columns(CodeRelation::CodeItems, CodeItemRow::COLUMNS)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.code.items().len())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.code.projection",
                    "code item row allocation failed",
                )
            })?;
        for view in self.iter() {
            let view = view?;
            let MethodCodeBody::Present { code: item, .. } = view.body else {
                continue;
            };
            let data = item.data();
            let insns_size = data.insns_size_code_units;
            let method_idx = view.method.reference.method_idx;
            let insns_off = u32::try_from(data.insns_range.byte_offset.0).map_err(|_| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.code.projection",
                    "validated insns offset exceeds UInt32",
                )
                .detail("method_idx", u64::from(method_idx))
            })?;
            let tries_size = u32::try_from(data.tries.len()).map_err(|_| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.code.projection",
                    "validated try count exceeds UInt32",
                )
                .detail("method_idx", u64::from(method_idx))
            })?;
            // The encoded instruction array is followed by one alignment word
            // only when its code-unit count is odd; the try block table starts
            // there. This mirrors the raw header layout exactly.
            let tries_off = if tries_size == 0 {
                None
            } else {
                Some(
                    insns_off
                        .checked_add(insns_size.saturating_mul(2))
                        .and_then(|end| end.checked_add(insns_size % 2 * 2))
                        .ok_or_else(|| {
                            MddError::new(
                                ErrorCode::InternalFault,
                                "facts.code.projection",
                                "validated try offset overflow",
                            )
                            .detail("method_idx", u64::from(method_idx))
                        })?,
                )
            };
            let handlers_off = match tries_off {
                Some(offset) => Some(
                    offset
                        .checked_add(tries_size.saturating_mul(8))
                        .ok_or_else(|| {
                            MddError::new(
                                ErrorCode::InternalFault,
                                "facts.code.projection",
                                "validated handler offset overflow",
                            )
                            .detail("method_idx", u64::from(method_idx))
                        })?,
                ),
                None => None,
            };
            rows.push(CodeItemRow {
                file_id,
                method_idx,
                code_off: u32::try_from(data.raw_range.byte_offset.0).map_err(|_| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.code.projection",
                        "validated code offset exceeds UInt32",
                    )
                    .detail("method_idx", u64::from(method_idx))
                })?,
                registers_size: u32::from(data.registers_size),
                ins_size: u32::from(data.ins_size),
                outs_size: u32::from(data.outs_size),
                tries_size,
                debug_info_off: u32::try_from(
                    data.debug_info_byte_offset.map_or(0u64, |value| value.0),
                )
                .map_err(|_| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.code.projection",
                        "validated debug info offset exceeds UInt32",
                    )
                    .detail("method_idx", u64::from(method_idx))
                })?,
                insns_size,
                insns_off,
                tries_off,
                handlers_off,
            });
        }
        Ok(rows)
    }
}

/// Compatibility relation names whose columns the code layer can project.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeRelation {
    CodeItems,
}

/// Gate a requested `code_items` column list without materialising the
/// method/code join. Coverage needs the same rejection contract as
/// [`MethodCodeFactViews::code_item_rows`] without paying for
/// [`MethodCodeFactViews::build`] once per requested column.
pub fn require_code_item_columns(columns: &[&str]) -> MddResult<()> {
    for column in columns {
        if *column != "*" && !CodeItemRow::COLUMNS.contains(column) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code.projection",
                "unknown code_items column",
            )
            .detail("column", (*column).to_owned()));
        }
    }
    Ok(())
}

/// One `code_items` row bound to one method-owned present body.
#[derive(Clone, Debug, Serialize)]
pub struct CodeItemRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub code_off: u32,
    pub registers_size: u32,
    pub ins_size: u32,
    pub outs_size: u32,
    pub tries_size: u32,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub insns_off: u32,
    pub tries_off: Option<u32>,
    pub handlers_off: Option<u32>,
}

impl CodeItemRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &[
        "file_id",
        "method_idx",
        "code_off",
        "registers_size",
        "ins_size",
        "outs_size",
        "tries_size",
        "debug_info_off",
        "insns_size",
        "insns_off",
        "tries_off",
        "handlers_off",
    ];
}

/// One complete 14-column `methods` row: the 12 definition-layer columns plus
/// the two code-layout opcode columns.
///
/// The row exists only when [`MethodCodeFactViews`] was built, so
/// `opcode_count`/`opcode_hex` come from the exact decoded instruction stream
/// of the same occurrence, never from `insns_size`. They are NULL exactly for a
/// reference-only method (no definition body at all); native, abstract and
/// present-empty definitions report `0` and `""`, matching the reference.
/// Payload pseudo-instructions are not counted and are not rendered.
#[derive(Clone, Debug, Serialize)]
pub struct MethodCodeRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub class_idx: u32,
    pub class_descriptor: String,
    pub proto_idx: u32,
    pub name: String,
    pub descriptor: String,
    pub return_descriptor: String,
    pub param_count: u32,
    pub param_descriptors: String,
    pub access_flags: Option<u32>,
    pub opcode_count: Option<u32>,
    pub opcode_hex: Option<String>,
    pub method_kind: Option<String>,
}

impl MethodCodeRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &[
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
    ];
}
