use super::*;
use mdd_dex::strings::StringLimits;
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use serde_json::Value;
use std::path::PathBuf;
fn build_two() -> Vec<DefinitionFacts> {
    build_named("definitions-035.dex")
}
fn build_named(name: &str) -> Vec<DefinitionFacts> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated")
        .join(name);
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    snapshot
        .sources()
        .iter()
        .map(|source| {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            DefinitionFacts::build(
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
                DefinitionLimits::default(),
            )
            .unwrap()
        })
        .collect()
}
#[test]
fn prototype_parameter_types_preserve_identity_without_annotations() {
    let facts = build_two();
    for fact in &facts {
        assert!(
            fact.unbuilt_layers()
                .iter()
                .any(|layer| layer == "annotations")
        );
        let views = fact.method_fact_views(MethodViewLimits::default()).unwrap();
        for name in ["staticCall", "externalCall"] {
            let reference = fact
                .definitions()
                .method_references
                .iter()
                .find(|reference| reference.method_name == name)
                .unwrap();
            let id = fact
                .entity(EntityKind::MethodReference, reference.method_idx)
                .unwrap();
            let params = views
                .parameter_types(&id, PrototypeParameterLimits::default())
                .unwrap();
            assert_eq!(
                params.source.dex_occurrence_id,
                fact.metadata().source().dex_occurrence_id
            );
            assert_eq!(params.definition.is_none(), name == "externalCall");
            let types = params.iter().collect::<MddResult<Vec<_>>>().unwrap();
            assert_eq!(types.len(), 1);
            assert_eq!(types[0].ordinal, 0);
            assert_eq!(types[0].type_fact.data.descriptor, "I");
            assert_eq!(
                types[0].type_fact.entity.dex_occurrence_id,
                id.dex_occurrence_id
            );
            assert_eq!(
                views
                    .parameter_types(&id, PrototypeParameterLimits { max_parameters: 0 })
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
            if name == "externalCall" {
                let forged = EntityRef {
                    kind: EntityKind::MethodDefinition,
                    ..id.clone()
                };
                assert_eq!(
                    views
                        .parameter_types(&forged, PrototypeParameterLimits::default())
                        .err()
                        .unwrap()
                        .code,
                    ErrorCode::InvalidArgument
                );
            }
        }
        let reference = fact
            .definitions()
            .method_references
            .iter()
            .find(|reference| reference.method_name == "virtualCall")
            .unwrap();
        let id = fact
            .entity(EntityKind::MethodDefinition, reference.method_idx)
            .unwrap();
        let empty = views
            .parameter_types(&id, PrototypeParameterLimits { max_parameters: 0 })
            .unwrap();
        assert_eq!(empty.iter().count(), 0);
    }
    let other = facts[1]
        .definitions()
        .method_references
        .iter()
        .find(|reference| reference.method_name == "staticCall")
        .unwrap();
    let foreign = facts[1]
        .entity(EntityKind::MethodReference, other.method_idx)
        .unwrap();
    let views = facts[0]
        .method_fact_views(MethodViewLimits::default())
        .unwrap();
    assert_eq!(
        views
            .parameter_types(&foreign, PrototypeParameterLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );

    let mut corrupted = facts[0].clone();
    let reference = corrupted
        .definitions
        .method_references
        .iter_mut()
        .find(|reference| reference.method_name == "staticCall")
        .unwrap();
    reference.parameter_descriptors[0] = "J".into();
    let index = reference.method_idx;
    let views = corrupted
        .method_fact_views(MethodViewLimits::default())
        .unwrap();
    let id = corrupted
        .entity(EntityKind::MethodReference, index)
        .unwrap();
    assert_eq!(
        views
            .parameter_types(&id, PrototypeParameterLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );

    // A second physical fixture has two differently typed parameters;
    // only metadata and definitions are built, not annotation facts.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
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
    let metadata = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
    let facts = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
    let reference = facts
        .definitions()
        .method_references
        .iter()
        .find(|reference| reference.method_name == "m")
        .unwrap();
    let id = facts
        .entity(EntityKind::MethodReference, reference.method_idx)
        .unwrap();
    let views = facts
        .method_fact_views(MethodViewLimits::default())
        .unwrap();
    let params = views
        .parameter_types(&id, PrototypeParameterLimits::default())
        .unwrap();
    let values = params
        .iter()
        .map(|value| value.unwrap().type_fact.data.descriptor.as_str())
        .collect::<Vec<_>>();
    assert_eq!(values, ["Ljava/util/List;", "I"]);
}
#[test]
fn class_members_preserve_direct_owners_order_and_limits() {
    let facts = build_two();
    for fact in &facts {
        let view = fact.class_fact_views(ClassViewLimits::default()).unwrap();
        let scanned = (fact.definitions.field_definitions.len()
            + fact.definitions.method_definitions.len()) as u64;
        for row in view.iter() {
            let class = row.unwrap().definition;
            let id = fact
                .entity(EntityKind::ClassDefinition, class.class_def_idx)
                .unwrap();
            let members = view.members(&id, scanned).unwrap();
            let expected_fields: Vec<_> = fact
                .definitions
                .field_definitions
                .iter()
                .filter(|v| v.class_def_idx == class.class_def_idx)
                .map(|v| (v.field_idx, v.kind, v.ordinal))
                .collect();
            let expected_methods: Vec<_> = fact
                .definitions
                .method_definitions
                .iter()
                .filter(|v| v.class_def_idx == class.class_def_idx)
                .map(|v| (v.method_idx, v.kind, v.ordinal))
                .collect();
            assert_eq!(
                members
                    .fields
                    .iter()
                    .map(|v| (v.field_idx, v.kind, v.ordinal))
                    .collect::<Vec<_>>(),
                expected_fields
            );
            assert_eq!(
                members
                    .methods
                    .iter()
                    .map(|v| (v.method_idx, v.kind, v.ordinal))
                    .collect::<Vec<_>>(),
                expected_methods
            );
            assert_eq!(
                members.source.dex_occurrence_id,
                fact.metadata.source().dex_occurrence_id
            );
            if scanned > 0 {
                assert_eq!(
                    view.members(&id, scanned - 1).err().unwrap().code,
                    ErrorCode::QuotaExceeded
                );
            }
            let foreign = EntityRef {
                dex_occurrence_id: "foreign".into(),
                ..id
            };
            assert_eq!(
                view.members(&foreign, scanned).err().unwrap().code,
                ErrorCode::InvalidArgument
            );
        }
    }
    let mut invalid = facts[0].clone();
    invalid.definitions.field_definitions[0].ordinal += 1;
    let id = invalid
        .entity(
            EntityKind::ClassDefinition,
            invalid.definitions.field_definitions[0].class_def_idx,
        )
        .unwrap();
    let view = invalid
        .class_fact_views(ClassViewLimits::default())
        .unwrap();
    assert_eq!(
        view.members(&id, u64::MAX).err().unwrap().code,
        ErrorCode::InternalFault
    );
}
#[test]
fn direct_class_lookup_preserves_identity_and_interfaces() {
    let facts = build_two();
    for fact in &facts {
        let view = fact.class_fact_views(ClassViewLimits::default()).unwrap();
        for expected in view.iter() {
            let expected = expected.unwrap();
            let identity = fact
                .entity(
                    EntityKind::ClassDefinition,
                    expected.definition.class_def_idx,
                )
                .unwrap();
            let actual = view.get(&identity).unwrap();
            assert_eq!(
                actual.definition.class_def_idx,
                expected.definition.class_def_idx
            );
            assert_eq!(actual.class_type.descriptor, expected.class_type.descriptor);
            assert_eq!(actual.interfaces.len(), expected.interfaces.len());
            assert_eq!(
                actual.source_file.map(|v| &v.text.raw_mutf8),
                expected.source_file.map(|v| &v.text.raw_mutf8)
            );
            if actual.definition.descriptor == "Lfixture/Base;" {
                assert_eq!(actual.source_file.unwrap().text.raw_mutf8, b"Base.java");
                assert_eq!(actual.interfaces.len(), 1);
                assert_eq!(actual.interfaces[0].interface_descriptor, "Lfixture/I1;");
            }
            let wrong = EntityRef {
                dex_occurrence_id: "foreign".into(),
                ..identity.clone()
            };
            assert_eq!(
                view.get(&wrong).err().unwrap().code,
                ErrorCode::InvalidArgument
            );
            let wrong = EntityRef {
                snapshot_id: "foreign".into(),
                ..identity.clone()
            };
            assert_eq!(
                view.get(&wrong).err().unwrap().code,
                ErrorCode::InvalidArgument
            );
            let wrong = EntityRef {
                kind: EntityKind::Type,
                ..identity.clone()
            };
            assert_eq!(
                view.get(&wrong).err().unwrap().code,
                ErrorCode::InvalidArgument
            );
            let wrong = EntityRef {
                local_index: u32::MAX,
                ..identity
            };
            assert_eq!(
                view.get(&wrong).err().unwrap().code,
                ErrorCode::InvalidArgument
            );
        }
    }
}
#[test]
fn borrowed_class_views_preserve_occurrences_direct_interfaces_and_lossless_source() {
    let facts = build_two();
    for fact in &facts {
        let view = fact.class_fact_views(ClassViewLimits::default()).unwrap();
        let rows = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
        assert_eq!(rows.len(), fact.definitions().classes.len());
        assert!(rows.iter().enumerate().all(|(index, row)| {
            row.definition.class_def_idx as usize == index
                && row.source.dex_occurrence_id == fact.metadata().source().dex_occurrence_id
                && row.class_type.type_idx == row.definition.class_idx
                && row.class_type.descriptor == row.definition.descriptor
        }));
        let base = rows
            .iter()
            .find(|row| row.definition.descriptor == "Lfixture/Base;")
            .unwrap();
        assert_eq!(base.superclass.unwrap().descriptor, "Ljava/lang/Object;");
        assert_eq!(
            base.source_file.unwrap().text.strict_utf8().unwrap(),
            "Base.java"
        );
        assert_eq!(base.interfaces.len(), 1);
        assert_eq!(base.interfaces[0].ordinal, 0);
        assert_eq!(base.interfaces[0].interface_descriptor, "Lfixture/I1;");
        let child = rows
            .iter()
            .find(|row| row.definition.descriptor == "Lfixture/Child;")
            .unwrap();
        assert!(child.interfaces.is_empty());
    }
    assert_eq!(
        facts[0].metadata().source().snapshot_id,
        facts[1].metadata().source().snapshot_id
    );
    assert_ne!(
        facts[0].metadata().source().dex_occurrence_id,
        facts[1].metadata().source().dex_occurrence_id
    );
    let surrogate = build_named("source-file-surrogate.dex");
    let view = surrogate[0]
        .class_fact_views(ClassViewLimits::default())
        .unwrap();
    let base = view
        .iter()
        .find_map(|row| {
            let row = row.unwrap();
            (row.definition.descriptor == "Lfixture/Base;").then_some(row)
        })
        .unwrap();
    assert_eq!(base.source_file.unwrap().text.utf16_units, [0xd800]);
    assert_eq!(base.source_file.unwrap().text.raw_mutf8, [0xed, 0xa0, 0x80]);
    let root = build_named("nullable-root-class.dex");
    let view = root[0]
        .class_fact_views(ClassViewLimits::default())
        .unwrap();
    let object = view
        .iter()
        .find_map(|row| {
            let row = row.unwrap();
            (row.definition.descriptor == "Ljava/lang/Object;").then_some(row)
        })
        .unwrap();
    assert!(
        object.superclass.is_none() && object.source_file.is_none() && object.interfaces.is_empty()
    );
    for limits in [
        ClassViewLimits {
            max_classes: 0,
            ..ClassViewLimits::default()
        },
        ClassViewLimits {
            max_interfaces: 0,
            ..ClassViewLimits::default()
        },
    ] {
        assert_eq!(
            facts[0].class_fact_views(limits).err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
    }
    let mut incomplete = facts[0].clone();
    incomplete.definition_coverage = Completeness::Partial;
    assert_eq!(
        incomplete
            .class_fact_views(ClassViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut malformed = facts[0].clone();
    malformed.definitions.interfaces[0].ordinal = 1;
    assert_eq!(
        malformed
            .class_fact_views(ClassViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
}
#[test]
fn direct_member_lookup_matches_iteration_and_binds_occurrence() {
    let facts = build_two();
    for fact in &facts {
        let fields = fact.field_fact_views(FieldViewLimits::default()).unwrap();
        for row in fields.iter() {
            let row = row.unwrap();
            let id = fact
                .entity(EntityKind::FieldReference, row.reference.field_idx)
                .unwrap();
            let found = fields.get(&id).unwrap();
            assert_eq!(found.reference.field_idx, row.reference.field_idx);
            assert_eq!(
                found.definition.map(|d| d.field_idx),
                row.definition.map(|d| d.field_idx)
            );
            let definition_id = EntityRef {
                kind: EntityKind::FieldDefinition,
                ..id.clone()
            };
            assert_eq!(fields.get(&definition_id).is_ok(), row.definition.is_some());
            let foreign = EntityRef {
                dex_occurrence_id: "foreign".into(),
                ..id
            };
            assert_eq!(
                fields.get(&foreign).err().unwrap().code,
                ErrorCode::InvalidArgument
            );
        }
        let methods = fact.method_fact_views(MethodViewLimits::default()).unwrap();
        for row in methods.iter() {
            let row = row.unwrap();
            let id = fact
                .entity(EntityKind::MethodReference, row.reference.method_idx)
                .unwrap();
            let found = methods.get(&id).unwrap();
            assert_eq!(found.reference.method_idx, row.reference.method_idx);
            assert_eq!(
                found.definition.map(|d| d.method_idx),
                row.definition.map(|d| d.method_idx)
            );
            let definition_id = EntityRef {
                kind: EntityKind::MethodDefinition,
                ..id.clone()
            };
            assert_eq!(
                methods.get(&definition_id).is_ok(),
                row.definition.is_some()
            );
            let foreign = EntityRef {
                snapshot_id: "foreign".into(),
                ..id
            };
            assert_eq!(
                methods.get(&foreign).err().unwrap().code,
                ErrorCode::InvalidArgument
            );
        }
    }
    let fields = facts[0]
        .field_fact_views(FieldViewLimits::default())
        .unwrap();
    let wrong = EntityRef {
        snapshot_id: facts[0].metadata.source.snapshot_id.clone(),
        dex_occurrence_id: facts[0].metadata.source.dex_occurrence_id.clone(),
        kind: EntityKind::MethodReference,
        local_index: 0,
    };
    assert_eq!(
        fields.get(&wrong).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    let missing = EntityRef {
        kind: EntityKind::FieldReference,
        local_index: u32::MAX,
        ..wrong
    };
    assert_eq!(
        fields.get(&missing).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
}
#[test]
fn borrowed_field_views_distinguish_reference_static_and_instance() {
    use mdd_dex::definitions::FieldKind;
    let facts = build_two();
    for fact in &facts {
        let view = fact.field_fact_views(FieldViewLimits::default()).unwrap();
        let rows = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
        assert_eq!(rows.len(), fact.definitions().field_references.len());
        assert!(
            rows.windows(2)
                .all(|r| r[0].reference.field_idx < r[1].reference.field_idx)
        );
        assert!(rows.iter().all(|r| {
            r.source.dex_occurrence_id == fact.metadata().source().dex_occurrence_id
                && r.field_type.type_idx == r.reference.type_idx
                && r.field_type.descriptor == r.reference.type_descriptor
        }));
        let external = rows
            .iter()
            .find(|r| r.reference.field_name == "outside")
            .unwrap();
        assert!(external.definition.is_none());
        let static_field = rows
            .iter()
            .find(|r| r.reference.field_name == "sValue")
            .unwrap();
        assert_eq!(static_field.definition.unwrap().kind, FieldKind::Static);
        let instance = rows
            .iter()
            .find(|r| r.reference.field_name == "iValue")
            .unwrap();
        assert_eq!(instance.definition.unwrap().kind, FieldKind::Instance);
        for row in rows.iter().filter_map(|r| r.definition.map(|d| (r, d))) {
            assert_eq!(row.0.reference.field_idx, row.1.field_idx);
            assert_eq!(row.0.reference.class_idx, row.1.class_idx);
        }
    }
    assert_eq!(
        facts[0].metadata().source().snapshot_id,
        facts[1].metadata().source().snapshot_id
    );
    assert_ne!(
        facts[0].metadata().source().dex_occurrence_id,
        facts[1].metadata().source().dex_occurrence_id
    );
    for limits in [
        FieldViewLimits {
            max_definition_entries: 0,
            ..FieldViewLimits::default()
        },
        FieldViewLimits {
            max_index_bytes: 0,
            ..FieldViewLimits::default()
        },
    ] {
        assert_eq!(
            facts[0].field_fact_views(limits).err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
    }
    let mut incomplete = facts[0].clone();
    incomplete.definition_coverage = Completeness::Partial;
    assert_eq!(
        incomplete
            .field_fact_views(FieldViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut duplicate = facts[0].clone();
    duplicate
        .definitions
        .field_definitions
        .push(duplicate.definitions.field_definitions[0].clone());
    assert_eq!(
        duplicate
            .field_fact_views(FieldViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
}
#[test]
fn borrowed_method_views_distinguish_reference_native_abstract_and_present() {
    use mdd_dex::definitions::MethodBody;
    let facts = build_two();
    for fact in &facts {
        let view = fact.method_fact_views(MethodViewLimits::default()).unwrap();
        let rows = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
        assert_eq!(rows.len(), fact.definitions().method_references.len());
        assert!(
            rows.windows(2)
                .all(|r| r[0].reference.method_idx < r[1].reference.method_idx)
        );
        assert!(rows.iter().all(|r| r.source.dex_occurrence_id
            == fact.metadata().source().dex_occurrence_id
            && r.prototype.proto_idx == r.reference.proto_idx));
        let external = rows
            .iter()
            .find(|r| r.reference.method_name == "externalCall")
            .unwrap();
        assert!(external.definition.is_none());
        let native = rows
            .iter()
            .find(|r| r.reference.method_name == "nativeCall")
            .unwrap();
        assert!(matches!(
            native.definition.unwrap().body,
            MethodBody::Native
        ));
        let abstract_method = rows
            .iter()
            .find(|r| r.reference.method_name == "abstractCall")
            .unwrap();
        assert!(matches!(
            abstract_method.definition.unwrap().body,
            MethodBody::Abstract
        ));
        let present = rows
            .iter()
            .find(|r| r.reference.method_name == "virtualCall")
            .unwrap();
        assert!(matches!(
            present.definition.unwrap().body,
            MethodBody::Present { .. }
        ));
        let parameterized = rows
            .iter()
            .find(|r| r.reference.method_name == "staticCall")
            .unwrap();
        assert_eq!(parameterized.reference.parameter_descriptors, ["I"]);
        assert_eq!(parameterized.reference.return_descriptor, "I");
        assert_eq!(
            present.prototype.parameter_type_indices,
            fact.metadata().prototypes()[present.reference.proto_idx as usize]
                .data
                .parameter_type_indices
        );
        assert!(
            fact.require_relation_columns(DefinitionRelation::Methods, &["opcode_hex"])
                .is_err()
        );
        // `param_descriptors` needs no code layout: its native vector is
        // exact and the comma join is total over validated descriptors.
        assert!(
            fact.require_relation_columns(DefinitionRelation::Methods, &["param_descriptors"])
                .is_ok()
        );
    }
    assert_eq!(
        facts[0].metadata().source().snapshot_id,
        facts[1].metadata().source().snapshot_id
    );
    assert_ne!(
        facts[0].metadata().source().dex_occurrence_id,
        facts[1].metadata().source().dex_occurrence_id
    );
    for limits in [
        MethodViewLimits {
            max_definition_entries: 0,
            ..MethodViewLimits::default()
        },
        MethodViewLimits {
            max_index_bytes: 0,
            ..MethodViewLimits::default()
        },
    ] {
        assert_eq!(
            facts[0].method_fact_views(limits).err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
    }
    let mut incomplete = facts[0].clone();
    incomplete.definition_coverage = Completeness::Partial;
    assert_eq!(
        incomplete
            .method_fact_views(MethodViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn class_lookup_rejects_unbuilt_partial_and_duplicate_occurrences() {
    let error = match resolve_class(&[], "Lfixture/Base;") {
        Err(error) => error,
        _ => panic!("unprovided facts must not prove absence"),
    };
    assert_eq!(error.code, ErrorCode::IncompleteFacts);

    let facts = build_two();
    let mut partial = facts[0].clone();
    partial.definition_coverage = Completeness::Partial;
    let error = match resolve_class(&[partial], "Lfixture/Base;") {
        Err(error) => error,
        _ => panic!("partial definitions must not prove a class result"),
    };
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    let duplicate = vec![facts[0].clone(), facts[0].clone()];
    let error = match resolve_class(&duplicate, "Lfixture/Base;") {
        Err(error) => error,
        _ => panic!("one occurrence must not be counted twice"),
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(matches!(
        resolve_class(&facts[..1], "Lfixture/Absent;").unwrap(),
        ClassResolution::Missing
    ));
    assert!(matches!(
        resolve_class(&facts, "Lfixture/Base;").unwrap(),
        ClassResolution::Ambiguous(ref matches) if matches.len() == 2
    ));
}

#[test]
fn occurrences_and_reference_definition_kinds_remain_distinct() {
    let facts = build_two();
    match resolve_class(&facts, "Lfixture/Base;").unwrap() {
        ClassResolution::Ambiguous(rows) => {
            assert_eq!(rows.len(), 2);
            assert_ne!(
                rows[0].facts.metadata.source.dex_occurrence_id,
                rows[1].facts.metadata.source.dex_occurrence_id
            );
        }
        _ => panic!("same descriptor from two occurrences must remain ambiguous"),
    }
    let first = &facts[0];
    assert!(first.entity(EntityKind::ClassDefinition, 0).is_ok());
    assert!(
        first
            .entity(
                EntityKind::ClassDefinition,
                first.definitions.classes[0].class_idx
            )
            .is_err()
    );
    let method = first.definitions.method_definitions[0].method_idx;
    assert_ne!(
        first.entity(EntityKind::MethodReference, method).unwrap(),
        first.entity(EntityKind::MethodDefinition, method).unwrap()
    );
    let external = first
        .definitions
        .method_references
        .iter()
        .find(|r| r.method_name == "externalCall")
        .unwrap();
    assert!(
        first
            .entity(EntityKind::MethodReference, external.method_idx)
            .is_ok()
    );
    assert!(
        first
            .entity(EntityKind::MethodDefinition, external.method_idx)
            .is_err()
    );
    assert!(!first.bytes().is_empty());
    assert!(first.completed_layers.iter().any(|s| s == "definitions"));
    assert!(first.unbuilt_layers.iter().any(|s| s == "code_layout"));
    assert_eq!(
        first
            .require_relation_columns(DefinitionRelation::Methods, &["opcode_count"])
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
    assert_eq!(
        first
            .require_relation_columns(DefinitionRelation::Methods, &["*"])
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
    assert_eq!(
        first
            .require_relation_columns(DefinitionRelation::Methods, &["opcod_count"])
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(
        first
            .require_relation_columns(
                DefinitionRelation::Methods,
                &[
                    "file_id",
                    "method_idx",
                    "class_descriptor",
                    "return_descriptor"
                ]
            )
            .is_ok()
    );
    let mut mixed = build_two();
    let other = build_two().remove(0);
    mixed.push(other);
    assert!(resolve_class(&mixed, "Lfixture/Base;").is_err());
}
#[test]
fn wildcard_definition_columns_match_frozen_reference_schema() {
    let facts = build_two();
    let first = &facts[0];
    let schema: Value = serde_json::from_str(include_str!(
        "../../../conformance/manifests/relations.json"
    ))
    .unwrap();
    let field = serde_json::to_value(&first.class_field_rows(7)[0]).unwrap();
    let method = serde_json::to_value(&first.class_method_rows(7)[0]).unwrap();
    for (relation, row) in [("class_fields", field), ("class_methods", method)] {
        let expected = schema["relations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == relation)
            .unwrap();
        assert_eq!(row.as_object().unwrap().len(), 8);
        for column in expected["columns"].as_array().unwrap() {
            assert!(row.get(column["name"].as_str().unwrap()).is_some());
        }
        let relation = if relation == "class_fields" {
            DefinitionRelation::ClassFields
        } else {
            DefinitionRelation::ClassMethods
        };
        assert_eq!(row["file_id"], 7);
        assert!(first.require_relation_columns(relation, &["*"]).is_ok());
    }
    assert_eq!(first.class_interface_rows(7).len(), 2);
}

#[test]
fn methods_and_classes_wildcard_columns_match_frozen_reference_schema() {
    let facts = build_two();
    let first = &facts[0];
    let schema: Value = serde_json::from_str(include_str!(
        "../../../conformance/manifests/relations.json"
    ))
    .unwrap();
    let method = serde_json::to_value(first.method_rows(7).unwrap()).unwrap();
    let class = serde_json::to_value(first.class_rows(7).unwrap()).unwrap();
    for (relation, rows, expected_columns, gate) in [
        (
            "methods",
            method.as_array().unwrap(),
            MethodRow::COLUMNS,
            DefinitionRelation::Methods,
        ),
        (
            "classes",
            class.as_array().unwrap(),
            ClassRow::COLUMNS,
            DefinitionRelation::Classes,
        ),
    ] {
        let entry = schema["relations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == relation)
            .unwrap();
        assert!(
            first
                .require_relation_columns(gate, expected_columns)
                .is_ok()
        );
        for column in expected_columns {
            let spec = entry["columns"]
                .as_array()
                .unwrap()
                .iter()
                .find(|spec| spec["name"].as_str().unwrap() == *column)
                .unwrap_or_else(|| panic!("{relation}.{column} missing from contract"));
            let value = &rows[0][spec["name"].as_str().unwrap()];
            if value.is_null() {
                assert!(spec["nullable"].as_bool().unwrap(), "{relation}.{column}");
                continue;
            }
            match spec["data_type"].as_str().unwrap() {
                "UInt32" => assert!(value.is_u64(), "{relation}.{column}: {value}"),
                "Utf8" | "Utf8View" => {
                    assert!(value.is_string(), "{relation}.{column}: {value}")
                }
                other => panic!("unhandled contract type {other}"),
            }
        }
    }
    // The assembled column set must be exactly the contract set minus the
    // documented code-layout columns.
    let contract_methods = schema["relations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "methods")
        .unwrap();
    let unassembled = contract_methods["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|column| column["name"].as_str().unwrap())
        .filter(|name| !MethodRow::COLUMNS.contains(name))
        .collect::<Vec<_>>();
    assert_eq!(unassembled, ["opcode_count", "opcode_hex"]);
    for row in method.as_array().unwrap() {
        // `param_descriptors` is now the exact comma-joined native vector.
        assert!(row["param_descriptors"].is_string());
        assert!(row.get("opcode_count").is_none());
        assert!(row.get("opcode_hex").is_none());
        assert!(row.get("access_flags").is_some());
    }
}

#[test]
fn method_rows_preserve_reference_only_nulls_and_definition_join() {
    let facts = build_two();
    for fact in &facts {
        let rows = fact.method_rows(0).unwrap();
        assert_eq!(rows.len(), fact.definitions().method_references.len());
        let definitions = fact
            .definitions()
            .method_definitions
            .iter()
            .map(|definition| definition.method_idx)
            .collect::<std::collections::BTreeSet<_>>();
        let mut reference_only = 0;
        for (ordinal, row) in rows.iter().enumerate() {
            let reference = &fact.definitions().method_references[ordinal];
            assert_eq!(row.file_id, 0);
            assert_eq!(row.method_idx, reference.method_idx);
            assert_eq!(row.class_idx, reference.class_idx);
            assert_eq!(row.class_descriptor, reference.class_descriptor);
            assert_eq!(row.proto_idx, reference.proto_idx);
            assert_eq!(row.name, reference.method_name);
            assert_eq!(row.descriptor, reference.descriptor);
            assert_eq!(row.return_descriptor, reference.return_descriptor);
            assert_eq!(
                row.param_count,
                u32::try_from(reference.parameter_descriptors.len()).unwrap()
            );
            assert_eq!(
                row.param_descriptors,
                reference.parameter_descriptors.join(","),
                "param_descriptors must be the exact ordered vector joined by ','"
            );
            let defined = definitions.contains(&reference.method_idx);
            assert_eq!(row.access_flags.is_some(), defined);
            assert_eq!(row.method_kind.is_some(), defined);
            if !defined {
                reference_only += 1;
            } else {
                let definition = fact
                    .definitions()
                    .method_definitions
                    .iter()
                    .find(|value| value.method_idx == reference.method_idx)
                    .unwrap();
                assert_eq!(row.access_flags, Some(definition.access_flags));
                assert_eq!(row.method_kind, Some(definition.kind.as_str().to_owned()));
            }
            // Reference IDs stay unique across the occurrence.
            assert_eq!(
                rows.iter()
                    .filter(|value| value.method_idx == row.method_idx)
                    .count(),
                1
            );
        }
        // This fixture has reference-only members, so the NULL path is real.
        assert!(
            reference_only > 0,
            "fixture lost its reference-only methods"
        );
    }
}

/// `param_descriptors` matches the recorded A0 `methods` slice exactly for
/// all three frozen fixtures. A0 renders the same comma join, so this is
/// both a value check and a compatibility-encoding check.
#[test]
fn param_descriptors_match_recorded_a0_rows() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let audit = root.join("artifacts/mdd-026/method-atom-audit/20261028T165707192974Z");
    for (case, fixture, expected_rows) in [
        (
            "definitions",
            "tests/fixtures/definitions/generated/definitions-035.dex",
            13usize,
        ),
        (
            "shared",
            "tests/fixtures/references/generated/shared-code-035.dex",
            5,
        ),
        (
            "dynamic",
            "tests/fixtures/references/generated/poly-custom-038.dex",
            6,
        ),
    ] {
        let path = root.join(fixture);
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let facts = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        let rows = facts.method_rows(0).unwrap();
        let table = std::fs::read_to_string(audit.join(format!("a0-{case}/stdout.txt"))).unwrap();
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
        let mut compared = 0usize;
        for line in table.lines().filter(|line| line.starts_with('|')) {
            let cells: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
            if cells[0] == "file_id" {
                continue;
            }
            assert_eq!(cells.len(), 14, "{case}");
            let index: u32 = hex_text(cells[1]).unwrap().parse().unwrap();
            let row = rows
                .iter()
                .find(|row| row.method_idx == index)
                .unwrap_or_else(|| panic!("{case} method {index} missing"));
            assert_eq!(
                Some(row.param_descriptors.clone()),
                hex_text(cells[9]),
                "{case} method {index}"
            );
            // The comma join must agree with the declared count as well.
            assert_eq!(
                row.param_count as usize,
                if row.param_descriptors.is_empty() {
                    0
                } else {
                    row.param_descriptors.matches(',').count() + 1
                },
                "{case} method {index}"
            );
            compared += 1;
        }
        assert_eq!(compared, expected_rows, "{case} row count");
    }
}

#[test]
fn class_rows_match_independent_raw_class_def_oracle() {
    let name = "definitions-035.dex";
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated")
        .join(name);
    let raw = std::fs::read(&path).unwrap();
    let facts = build_named(name).remove(0);
    let u32at = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
    let string_ids_off = u32at(60) as usize;
    let type_ids_off = u32at(68) as usize;
    let raw_string = |index: u32| -> String {
        let data_off = u32at(string_ids_off + index as usize * 4) as usize;
        let mut at = data_off;
        while raw[at] >= 0x80 {
            at += 1;
        }
        at += 1;
        let end = at + raw[at..].iter().position(|byte| *byte == 0).unwrap();
        String::from_utf8(raw[at..end].to_vec()).unwrap()
    };
    let type_descriptor =
        |type_idx: u32| -> String { raw_string(u32at(type_ids_off + type_idx as usize * 4)) };
    let class_count = u32at(96) as usize;
    let class_off = u32at(100) as usize;
    let mut expected = Vec::new();
    for class_def_idx in 0..class_count {
        let at = class_off + class_def_idx * 32;
        let class_idx = u32at(at);
        let superclass_idx = u32at(at + 8);
        let interfaces_off = u32at(at + 12);
        let source_file_idx = u32at(at + 16);
        expected.push(serde_json::json!({
            "file_id": 0,
            "class_def_idx": class_def_idx,
            "class_idx": class_idx,
            "descriptor": type_descriptor(class_idx),
            "access_flags": u32at(at + 4),
            "superclass_descriptor": if superclass_idx == u32::MAX {
                Value::Null
            } else {
                Value::String(type_descriptor(superclass_idx))
            },
            "interface_count": if interfaces_off == 0 {
                0
            } else {
                u32at(interfaces_off as usize)
            },
            "source_file": if source_file_idx == u32::MAX {
                Value::Null
            } else {
                Value::String(raw_string(source_file_idx))
            },
        }));
    }
    let actual = serde_json::to_value(facts.class_rows(0).unwrap()).unwrap();
    assert_eq!(actual, Value::Array(expected));
    // This fixture has no NO_INDEX superclass or source file, and exactly
    // two classes declare a one-entry interface list.
    let rows = facts.class_rows(0).unwrap();
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|row| row.superclass_descriptor.is_some()));
    assert!(rows.iter().all(|row| row.source_file.is_some()));
    assert_eq!(rows.iter().filter(|row| row.interface_count > 0).count(), 2);
    assert!(
        rows.iter()
            .filter(|row| row.interface_count > 0)
            .all(|row| row.interface_count == 1)
    );
}

#[test]
fn class_rows_project_encoded_no_index_as_genuine_null() {
    let name = "classic-035.dex";
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated")
        .join(name);
    let raw = std::fs::read(&path).unwrap();
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let facts = DefinitionFacts::build(
        MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
        DefinitionLimits::default(),
    )
    .unwrap();
    let rows = facts.class_rows(0).unwrap();
    assert_eq!(rows.len(), 1);
    // The raw class_def encodes source_file_idx as NO_INDEX for this class,
    // so the relation cell is a genuine NULL and not an unbuilt layer.
    let class_off = u32::from_le_bytes(raw[100..104].try_into().unwrap()) as usize;
    let source_file_idx =
        u32::from_le_bytes(raw[class_off + 16..class_off + 20].try_into().unwrap());
    assert_eq!(source_file_idx, u32::MAX);
    assert_eq!(rows[0].source_file, None);
    assert!(rows[0].superclass_descriptor.is_some());
}
