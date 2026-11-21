use super::*;
use crate::MetadataFacts;
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::DecimalU64;
use std::path::PathBuf;
fn build(path: &str) -> AnnotationFacts {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path);
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
    let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
    AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap()
}
#[test]
fn signature_physical_search_keeps_shared_empty_and_orphan_items() {
    for path in [
        "tests/fixtures/annotations/generated/parameter-shared-signature.dex",
        "tests/fixtures/annotations/generated/parameter-shared-empty-set.dex",
        "tests/fixtures/annotations/generated/valid-orphan-annotation.dex",
    ] {
        let facts = build(path);
        let data = &facts.data;
        assert!(
            data.sets
                .windows(2)
                .all(|items| items[0].byte_offset < items[1].byte_offset)
        );
        assert!(
            data.annotation_items
                .windows(2)
                .all(|items| items[0].byte_offset < items[1].byte_offset)
        );
        for item in &data.sets {
            assert!(std::ptr::eq(
                physical_annotation_set(data, item.byte_offset).unwrap(),
                item
            ));
            for offset in &item.annotation_offsets {
                let expected = data
                    .annotation_items
                    .iter()
                    .find(|item| item.byte_offset == *offset)
                    .unwrap();
                assert!(std::ptr::eq(
                    physical_annotation_item(data, *offset).unwrap(),
                    expected
                ));
            }
        }
        for item in &data.annotation_items {
            assert!(std::ptr::eq(
                physical_annotation_item(data, item.byte_offset).unwrap(),
                item
            ));
        }
        assert_eq!(
            physical_annotation_set(data, u32::MAX).unwrap_err().code,
            ErrorCode::InternalFault
        );
        assert_eq!(
            physical_annotation_item(data, u32::MAX).unwrap_err().code,
            ErrorCode::InternalFault
        );
    }
}
#[test]
fn signature_type_search_matches_linear_physical_sets() {
    for path in [
        "tests/fixtures/annotations/generated/parameter-shared-signature.dex",
        "tests/fixtures/annotations/generated/parameter-shared-empty-set.dex",
        "tests/fixtures/annotations/generated/valid-orphan-annotation.dex",
    ] {
        let facts = build(path);
        let data = &facts.data;
        for set in &data.sets {
            for target in facts
                .definitions
                .metadata
                .types
                .iter()
                .map(|item| item.data.type_idx)
                .chain(std::iter::once(u32::MAX))
            {
                let expected = set
                    .annotation_offsets
                    .iter()
                    .map(|offset| physical_annotation_item(data, *offset).unwrap())
                    .find(|item| item.type_idx == target)
                    .map(|item| item.byte_offset);
                let actual = physical_annotation_of_type(data, set, target)
                    .unwrap()
                    .map(|item| item.byte_offset);
                assert_eq!(actual, expected, "{path}: type {target}");
            }
        }
    }
    let facts = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
    let data = &facts.data;
    let mut bad = data
        .sets
        .iter()
        .find(|set| !set.annotation_offsets.is_empty())
        .unwrap()
        .clone();
    bad.annotation_offsets[0] = u32::MAX;
    assert_eq!(
        physical_annotation_of_type(data, &bad, 0).unwrap_err().code,
        ErrorCode::InternalFault
    );
}
#[test]
fn signature_absent_preserves_shared_empty_and_orphan_sets() {
    let facts =
        build("artifacts/mdd-022/signature-type-search-20261101/no-signature-shared-empty.dex");
    assert!(
        facts
            .definitions
            .metadata
            .types
            .iter()
            .all(|item| { item.data.descriptor != "Ldalvik/annotation/Signature;" })
    );
    assert!(facts.signatures().is_empty());
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/parameter-shared-empty-set.json"
    ))
    .unwrap();
    let empty = expected["empty_set_offset"].as_u64().unwrap() as u32;
    let orphan = expected["orphan_set_offset"].as_u64().unwrap() as u32;
    assert!(
        physical_annotation_set(&facts.data, empty)
            .unwrap()
            .annotation_offsets
            .is_empty()
    );
    assert!(
        physical_annotation_set(&facts.data, orphan)
            .unwrap()
            .annotation_offsets
            .is_empty()
    );
    assert_eq!(
        facts
            .data
            .owner_bindings
            .iter()
            .filter(|owner| {
                owner.kind == AnnotationOwnerKind::Parameter
                    && owner.annotation_set_offset == Some(empty)
            })
            .count(),
        4
    );
    assert!(
        !facts
            .data
            .owner_bindings
            .iter()
            .any(|owner| { owner.annotation_set_offset == Some(orphan) })
    );
}
#[test]
fn signature_name_matches_utf16_units_without_losing_errors() {
    let base = "artifacts/mdd-022/signature-name-units-20261101/";
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../artifacts/mdd-022/signature-name-units-20261101/fixture.json"
    ))
    .unwrap();
    let signature_offset = expected["signature_byte_offset"].as_u64().unwrap();
    let valid = build(&format!("{base}valid.dex"));
    assert_eq!(valid.signatures().len(), 4);
    for name in ["long-name.dex", "surrogate-name.dex"] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(base)
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
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        if name == "surrogate-name.dex" {
            let index = expected["name_string_index"].as_u64().unwrap() as usize;
            assert_eq!(
                metadata.strings[index].data.text.utf16_units,
                [0x76, 0xd800, 0x65]
            );
            assert_eq!(
                metadata.strings[index].data.text.raw_mutf8,
                [0x76, 0xed, 0xa0, 0x80, 0x65]
            );
            assert!(metadata.strings[index].data.text.strict_utf8().is_err());
        } else {
            let index = expected["long_name_string_index"].as_u64().unwrap() as usize;
            assert_eq!(
                metadata.strings[index].data.text.strict_utf8().unwrap(),
                "v_infinity_float"
            );
        }
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        let source = definitions.metadata.source().clone();
        let error = match AnnotationFacts::build(definitions, AnnotationLimits::default()) {
            Ok(_) => panic!("invalid Signature name was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::InvalidInput, "{name}");
        let (reason, stage, offset) = if name == "surrogate-name.dex" {
            // The physical annotation reader rejects a non-scalar name
            // before Signature expansion; do not reclassify that error.
            (
                "ANNOTATION_NAME_NON_SCALAR",
                "dex.annotations",
                signature_offset + 3,
            )
        } else {
            ("SIGNATURE_SHAPE", "facts.annotations", signature_offset)
        };
        assert_eq!(error.stage, stage);
        assert_eq!(
            error.details.get("reason").and_then(|value| value.as_str()),
            Some(reason)
        );
        assert_eq!(
            error
                .details
                .get("snapshot_id")
                .and_then(|value| value.as_str()),
            Some(source.snapshot_id.as_str())
        );
        assert_eq!(
            error
                .details
                .get("dex_occurrence_id")
                .and_then(|value| value.as_str()),
            Some(source.dex_occurrence_id.as_str())
        );
        assert_eq!(
            error
                .details
                .get("member_id")
                .and_then(|value| value.as_str()),
            Some(source.member_id.as_str())
        );
        assert_eq!(
            error
                .details
                .get("content_id")
                .and_then(|value| value.as_str()),
            Some(source.content_id.as_str())
        );
        assert_eq!(
            error
                .details
                .get("byte_offset")
                .and_then(|value| value.as_str()),
            Some(offset.to_string().as_str())
        );
    }
}
#[test]
fn signature_owner_lookup_keeps_member_kinds_and_rejects_bad_layout() {
    let facts = build("artifacts/mdd-022/signature-owner-layout-20261101/mixed-members.dex");
    let definitions = &facts.definitions;
    validate_owner_definition_layout(definitions).unwrap();
    assert_eq!(definitions.definitions.classes[0].static_fields_count, 1);
    assert_eq!(definitions.definitions.classes[0].instance_fields_count, 1);
    assert_eq!(definitions.definitions.classes[0].direct_methods_count, 1);
    assert_eq!(definitions.definitions.classes[0].virtual_methods_count, 1);
    let mut field_count = 0;
    let mut method_count = 0;
    for owner in &facts.data.owner_bindings {
        let expected = match owner.kind {
            AnnotationOwnerKind::Class => true,
            AnnotationOwnerKind::Field => {
                field_count += 1;
                definitions
                    .definitions
                    .field_definitions
                    .iter()
                    .any(|item| item.field_idx == owner.local_index)
            }
            _ => {
                method_count += 1;
                definitions
                    .definitions
                    .method_definitions
                    .iter()
                    .any(|item| item.method_idx == owner.local_index)
            }
        };
        let actual = owner_has_definition(definitions, owner).unwrap();
        assert_eq!(actual, expected);
        let projected = owner_ref(definitions, owner, actual).unwrap();
        if let Some(definition) = projected.definition {
            assert_eq!(
                definition,
                definitions
                    .entity(definition.kind, owner.local_index)
                    .unwrap()
            );
            assert_eq!(definition.snapshot_id, facts.source().snapshot_id);
            assert_eq!(
                definition.dex_occurrence_id,
                facts.source().dex_occurrence_id
            );
        }
    }
    assert!(field_count >= 2 && method_count >= 2);

    // Simulated partial definition lists preserve reference-only members;
    // the original physical fixture above always contains all four kinds.
    let mut reference_only = DefinitionFacts::clone(definitions);
    reference_only.definitions.field_definitions.remove(1);
    reference_only.definitions.classes[0].instance_fields_count = 0;
    reference_only.definitions.method_definitions.remove(1);
    reference_only.definitions.classes[0].virtual_methods_count = 0;
    validate_owner_definition_layout(&reference_only).unwrap();
    for owner in &facts.data.owner_bindings {
        if owner.local_index == 1 && owner.kind != AnnotationOwnerKind::Class {
            assert!(!owner_has_definition(&reference_only, owner).unwrap());
            assert!(
                owner_ref(&reference_only, owner, false)
                    .unwrap()
                    .definition
                    .is_none()
            );
        }
    }

    // Synthetic in-memory identities stress interleaved index domains:
    // the two individual lists are sorted, but their concatenation is not.
    let mut interleaved = DefinitionFacts::clone(definitions);
    let field_static = interleaved.definitions.field_definitions[0].clone();
    let field_instance = interleaved.definitions.field_definitions[1].clone();
    let method_direct = interleaved.definitions.method_definitions[0].clone();
    let method_virtual = interleaved.definitions.method_definitions[1].clone();
    interleaved.definitions.classes[0].static_fields_count = 2;
    interleaved.definitions.classes[0].instance_fields_count = 2;
    interleaved.definitions.classes[0].direct_methods_count = 2;
    interleaved.definitions.classes[0].virtual_methods_count = 2;
    interleaved.definitions.field_definitions =
        [(0, 0, true), (3, 1, true), (1, 0, false), (2, 1, false)]
            .into_iter()
            .map(|(index, ordinal, first)| {
                let mut item = if first {
                    field_static.clone()
                } else {
                    field_instance.clone()
                };
                item.field_idx = index;
                item.ordinal = ordinal;
                item
            })
            .collect();
    interleaved.definitions.method_definitions =
        [(0, 0, true), (3, 1, true), (1, 0, false), (2, 1, false)]
            .into_iter()
            .map(|(index, ordinal, first)| {
                let mut item = if first {
                    method_direct.clone()
                } else {
                    method_virtual.clone()
                };
                item.method_idx = index;
                item.ordinal = ordinal;
                item
            })
            .collect();
    let field_reference = interleaved.definitions.field_references[0].clone();
    let method_reference = interleaved.definitions.method_references[0].clone();
    interleaved.definitions.field_references = (0..5)
        .map(|index| {
            let mut item = field_reference.clone();
            item.field_idx = index;
            item
        })
        .collect();
    interleaved.definitions.method_references = (0..5)
        .map(|index| {
            let mut item = method_reference.clone();
            item.method_idx = index;
            item
        })
        .collect();
    validate_owner_definition_layout(&interleaved).unwrap();
    let field_owner = facts
        .data
        .owner_bindings
        .iter()
        .find(|owner| owner.kind == AnnotationOwnerKind::Field)
        .unwrap();
    let method_owner = facts
        .data
        .owner_bindings
        .iter()
        .find(|owner| owner.kind == AnnotationOwnerKind::Parameter)
        .unwrap();
    for owner in [field_owner, method_owner] {
        for index in 0..5 {
            let mut candidate = owner.clone();
            candidate.local_index = index;
            let expected = index < 4;
            assert_eq!(
                owner_has_definition(&interleaved, &candidate).unwrap(),
                expected
            );
            assert_eq!(
                owner_ref(&interleaved, &candidate, expected)
                    .unwrap()
                    .definition
                    .is_some(),
                expected
            );
        }
    }
    let mut empty = DefinitionFacts::clone(definitions);
    empty.definitions.classes.clear();
    empty.definitions.field_definitions.clear();
    empty.definitions.method_definitions.clear();
    validate_owner_definition_layout(&empty).unwrap();
    assert_eq!(
        owner_has_definition(&empty, field_owner).unwrap_err().code,
        ErrorCode::InternalFault
    );

    let mut broken = DefinitionFacts::clone(definitions);
    broken.definitions.field_definitions.swap(0, 1);
    assert_eq!(
        validate_owner_definition_layout(&broken).unwrap_err().code,
        ErrorCode::InternalFault
    );
    let mut foreign = facts.data.owner_bindings[0].clone();
    foreign.class_idx = u32::MAX;
    assert_eq!(
        owner_has_definition(definitions, &foreign)
            .unwrap_err()
            .code,
        ErrorCode::InternalFault
    );
}

#[test]
fn signature_expansion_charges_every_retained_owner_identity() {
    let facts = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
    let source = facts.source();
    let identity_bytes = (source.snapshot_id.len() + source.dex_occurrence_id.len() + 32) as u64;
    let mut old_total = facts.data.usage.decoded_bytes;
    let mut missing_identities = 0u64;
    for signature in facts.signatures() {
        old_total += (signature.utf16_units.len() as u64) * 2
            + (signature.parts.len() as u64) * identity_bytes
            + 2 * identity_bytes
            + signature.string_pool_id.len() as u64;
        missing_identities += u64::from(signature.owner.definition.is_some());
    }
    assert!(
        missing_identities > 0,
        "fixture must retain owner definitions"
    );
    let exact_total = old_total + missing_identities * identity_bytes;
    let limited = AnnotationLimits {
        max_decoded_bytes: exact_total - 1,
        ..AnnotationLimits::default()
    };
    let failure = AnnotationFacts::build_arc(facts.definitions.clone(), limited)
        .err()
        .expect("missing identity budget must not be admitted");
    assert_eq!(failure.code, ErrorCode::QuotaExceeded);
    assert_eq!(
        failure
            .details
            .get("reason")
            .and_then(|value| value.as_str()),
        Some("SIGNATURE_BYTE_BUDGET")
    );
    let exact = AnnotationFacts::build_arc(
        facts.definitions.clone(),
        AnnotationLimits {
            max_decoded_bytes: exact_total,
            ..limited
        },
    )
    .unwrap();
    assert_eq!(exact.signatures.len(), facts.signatures.len());
}
#[test]
fn physical_collection_views_preserve_bytes_nulls_and_scope() {
    let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
    let make = |kind, byte_offset| AnnotationCollectionRef {
        snapshot_id: facts.source().snapshot_id.clone(),
        dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
        byte_offset,
        kind,
    };
    for set in &facts.data.sets {
        let reference = make(AnnotationCollectionKind::Set, set.byte_offset);
        let AnnotationCollectionView::Set {
            source,
            item,
            raw_encoded,
        } = facts
            .collection_by_ref(
                &reference,
                facts.data.sets.len() as u64,
                set.annotation_offsets.len() as u64,
            )
            .unwrap()
        else {
            panic!("unexpected collection kind")
        };
        assert_eq!(source.dex_occurrence_id, facts.source().dex_occurrence_id);
        assert_eq!(raw_encoded.len(), 4 + item.annotation_offsets.len() * 4);
        assert_eq!(
            u32::from_le_bytes(raw_encoded[..4].try_into().unwrap()) as usize,
            item.annotation_offsets.len()
        );
        // The 4-byte framing here is len-validated above, so `chunks_exact`
        // expresses the intent more directly than `as_chunks`.
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (slot, expected) in raw_encoded[4..]
            .chunks_exact(4)
            .zip(&item.annotation_offsets)
        {
            assert_eq!(u32::from_le_bytes(slot.try_into().unwrap()), *expected);
        }
    }
    let mut saw_null = false;
    for list in &facts.data.ref_lists {
        let reference = make(AnnotationCollectionKind::SetRefList, list.byte_offset);
        let AnnotationCollectionView::SetRefList {
            item, raw_encoded, ..
        } = facts
            .collection_by_ref(
                &reference,
                facts.data.ref_lists.len() as u64,
                list.annotation_set_offsets.len() as u64,
            )
            .unwrap()
        else {
            panic!("unexpected collection kind")
        };
        assert_eq!(raw_encoded.len(), 4 + item.annotation_set_offsets.len() * 4);
        assert_eq!(
            u32::from_le_bytes(raw_encoded[..4].try_into().unwrap()) as usize,
            item.annotation_set_offsets.len()
        );
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (slot, expected) in raw_encoded[4..]
            .chunks_exact(4)
            .zip(&item.annotation_set_offsets)
        {
            let raw = u32::from_le_bytes(slot.try_into().unwrap());
            assert_eq!((raw != 0).then_some(raw), *expected);
            saw_null |= expected.is_none();
        }
    }
    assert!(saw_null, "fixture must contain an encoded null slot");
    let nonempty_set = facts
        .data
        .sets
        .iter()
        .find(|v| !v.annotation_offsets.is_empty())
        .unwrap();
    let set_limited = make(AnnotationCollectionKind::Set, nonempty_set.byte_offset);
    assert_eq!(
        facts
            .collection_by_ref(
                &set_limited,
                u64::MAX,
                nonempty_set.annotation_offsets.len() as u64 - 1
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    let nonempty_list = facts
        .data
        .ref_lists
        .iter()
        .find(|v| !v.annotation_set_offsets.is_empty())
        .unwrap();
    let list_limited = make(
        AnnotationCollectionKind::SetRefList,
        nonempty_list.byte_offset,
    );
    assert_eq!(
        facts
            .collection_by_ref(
                &list_limited,
                u64::MAX,
                nonempty_list.annotation_set_offsets.len() as u64 - 1
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    let orphan = build("tests/fixtures/annotations/generated/valid-orphan-empty-set.dex");
    let empty = orphan
        .data
        .sets
        .iter()
        .find(|set| {
            set.annotation_offsets.is_empty()
                && !orphan
                    .data
                    .owner_bindings
                    .iter()
                    .any(|owner| owner.annotation_set_offset == Some(set.byte_offset))
        })
        .expect("fixture must include an unowned empty set");
    let orphan_ref = AnnotationCollectionRef {
        snapshot_id: orphan.source().snapshot_id.clone(),
        dex_occurrence_id: orphan.source().dex_occurrence_id.clone(),
        byte_offset: empty.byte_offset,
        kind: AnnotationCollectionKind::Set,
    };
    let AnnotationCollectionView::Set {
        item, raw_encoded, ..
    } = orphan
        .collection_by_ref(&orphan_ref, orphan.data.sets.len() as u64, 0)
        .unwrap()
    else {
        panic!("unexpected orphan collection kind")
    };
    assert!(item.annotation_offsets.is_empty());
    assert_eq!(raw_encoded, [0, 0, 0, 0]);
    let set = &facts.data.sets[0];
    let reference = make(AnnotationCollectionKind::Set, set.byte_offset);
    assert_eq!(
        facts
            .collection_by_ref(&reference, 0, u64::MAX)
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    let foreign = AnnotationCollectionRef {
        snapshot_id: "other".into(),
        ..reference.clone()
    };
    assert_eq!(
        facts
            .collection_by_ref(&foreign, u64::MAX, u64::MAX)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let fake = AnnotationCollectionRef {
        byte_offset: set.byte_offset + 1,
        ..reference.clone()
    };
    assert_eq!(
        facts
            .collection_by_ref(&fake, u64::MAX, u64::MAX)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut partial = facts.clone();
    partial.annotation_coverage = Completeness::Partial;
    assert_eq!(
        partial
            .collection_by_ref(&reference, u64::MAX, u64::MAX)
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut duplicate = facts.clone();
    duplicate.data.sets.push(set.clone());
    assert_eq!(
        duplicate
            .collection_by_ref(&reference, u64::MAX, u64::MAX)
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
}

#[test]
fn owner_annotation_view_preserves_slots_sets_and_occurrences() {
    let input = InputSpec {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/parameter-shared-signature.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let occurrences: Vec<_> = snapshot
        .sources()
        .iter()
        .map(|source| {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let definitions =
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap()
        })
        .collect();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/parameter-shared-signature.json"
    ))
    .unwrap();
    let expected_set = expected["parameter_set_offset"].as_u64().unwrap() as u32;
    let expected_item = expected["signature_offset"].as_u64().unwrap() as u32;
    for facts in &occurrences {
        for method_index in [0, 1] {
            let method = facts
                .definitions()
                .entity(EntityKind::MethodReference, method_index)
                .unwrap();
            for slot in [0, 2] {
                let view = facts
                    .owner_annotation_facts(
                        &method,
                        Some(slot),
                        AnnotationOwnerViewLimits::default(),
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    view.source.dex_occurrence_id,
                    facts.source().dex_occurrence_id
                );
                assert_eq!(view.owner.parameter_ordinal, Some(slot));
                assert_eq!(view.owner.parameter_position_in_prototype, None);
                assert_eq!(view.set.unwrap().byte_offset, expected_set);
                assert_eq!(view.annotations.len(), 1);
                assert_eq!(view.annotations[0].annotation.byte_offset, expected_item);
                assert_eq!(view.annotations[0].set_ordinal, 0);
            }
            let zero = facts
                .owner_annotation_facts(&method, Some(1), AnnotationOwnerViewLimits::default())
                .unwrap()
                .unwrap();
            assert!(zero.set.is_none());
            assert!(zero.annotations.is_empty());
            assert!(
                facts
                    .owner_annotation_facts(&method, Some(3), AnnotationOwnerViewLimits::default())
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                facts
                    .owner_annotation_facts(
                        &method,
                        Some(0),
                        AnnotationOwnerViewLimits {
                            max_scanned_entries: u64::MAX,
                            max_matches: 0,
                        }
                    )
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
            assert_eq!(
                facts
                    .owner_annotation_facts(
                        &method,
                        Some(0),
                        AnnotationOwnerViewLimits {
                            max_scanned_entries: 0,
                            max_matches: u64::MAX,
                        }
                    )
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
        let method = facts
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let direct = facts
            .owner_annotation_facts(&method, None, AnnotationOwnerViewLimits::default())
            .unwrap()
            .unwrap();
        assert_eq!(direct.owner.kind, AnnotationOwnerKind::Method);
        assert_eq!(direct.annotations.len(), 1);
        assert_eq!(direct.annotations[0].annotation.byte_offset, expected_item);
    }
    let foreign = occurrences[1]
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    assert_eq!(
        occurrences[0]
            .owner_annotation_facts(&foreign, Some(0), AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );

    let mut broken = occurrences[0].clone();
    let method = broken
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    broken
        .data
        .sets
        .iter_mut()
        .find(|set| set.byte_offset == expected_set)
        .unwrap()
        .encoded_range
        .byte_length = DecimalU64(u64::MAX);
    assert_eq!(
        broken
            .owner_annotation_facts(&method, Some(0), AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
    let mut broken = occurrences[0].clone();
    broken
        .data
        .annotation_items
        .iter_mut()
        .find(|item| item.byte_offset == expected_item)
        .unwrap()
        .encoded_range
        .byte_length = DecimalU64(u64::MAX);
    assert_eq!(
        broken
            .owner_annotation_facts(&method, Some(0), AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );

    let facts = build("tests/fixtures/annotations/generated/parameter-shared-empty-set.dex");
    let method = facts
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    let empty = facts
        .owner_annotation_facts(&method, Some(0), AnnotationOwnerViewLimits::default())
        .unwrap()
        .unwrap();
    assert!(empty.set.is_some());
    assert!(empty.annotations.is_empty());
    let zero = facts
        .owner_annotation_facts(&method, Some(1), AnnotationOwnerViewLimits::default())
        .unwrap()
        .unwrap();
    assert!(zero.set.is_none());
    let mut partial = facts.clone();
    partial.annotation_coverage = Completeness::Unknown;
    assert_eq!(
        partial
            .owner_annotation_facts(&method, Some(0), AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn annotation_owner_view_preserves_shared_sets_slots_and_scope() {
    let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
    let reference = |offset| AnnotationRef {
        snapshot_id: facts.source().snapshot_id.clone(),
        dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
        annotation_byte_offset: offset,
    };
    // The independent fixture lists set 1164 for two distinct fields,
    // both pointing to physical annotation 1120 at ordinal zero.
    let fields = facts
        .annotation_owner_facts(&reference(1120), AnnotationOwnerViewLimits::default())
        .unwrap();
    let got = fields
        .iter()
        .map(|fact| {
            (
                fact.owner.kind,
                fact.owner.local_index,
                fact.set.byte_offset,
                fact.set_ordinal,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        got,
        vec![
            (AnnotationOwnerKind::Field, 0, 1164, 0),
            (AnnotationOwnerKind::Field, 1, 1164, 0)
        ]
    );
    assert!(fields.iter().all(|fact| fact.source.dex_occurrence_id
        == facts.source().dex_occurrence_id
        && fact.annotation.byte_offset == 1120));

    // 1012 occurs once in the class set and once in the parameter set;
    // that parameter set is referenced by two methods at encoded slot 0.
    let owners = facts
        .annotation_owner_facts(&reference(1012), AnnotationOwnerViewLimits::default())
        .unwrap();
    let got = owners
        .iter()
        .map(|fact| {
            (
                fact.owner.kind,
                fact.owner.local_index,
                fact.owner.parameter_ordinal,
                fact.set.byte_offset,
                fact.set_ordinal,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].0, AnnotationOwnerKind::Class);
    assert_eq!((got[0].3, got[0].4), (1152, 1));
    assert_eq!(
        got[1],
        (AnnotationOwnerKind::Parameter, 0, Some(0), 1180, 0)
    );
    assert_eq!(
        got[2],
        (AnnotationOwnerKind::Parameter, 1, Some(0), 1180, 0)
    );

    let visits = facts.data.annotation_items.len() as u64
        + facts.data.owner_bindings.len() as u64
        + facts
            .data
            .owner_bindings
            .iter()
            .filter_map(|owner| owner.annotation_set_offset)
            .map(|offset| {
                facts.data.sets.len() as u64
                    + facts
                        .data
                        .sets
                        .iter()
                        .find(|set| set.byte_offset == offset)
                        .unwrap()
                        .annotation_offsets
                        .len() as u64
            })
            .sum::<u64>();
    assert_eq!(
        facts
            .annotation_owner_facts(
                &reference(1012),
                AnnotationOwnerViewLimits {
                    max_scanned_entries: visits,
                    max_matches: 3
                }
            )
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        facts
            .annotation_owner_facts(
                &reference(1012),
                AnnotationOwnerViewLimits {
                    max_scanned_entries: visits - 1,
                    max_matches: 3
                }
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        facts
            .annotation_owner_facts(
                &reference(1012),
                AnnotationOwnerViewLimits {
                    max_scanned_entries: visits,
                    max_matches: 2
                }
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        facts
            .annotation_owner_facts(&reference(1013), AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut foreign = reference(1012);
    foreign.dex_occurrence_id = "foreign".into();
    assert_eq!(
        facts
            .annotation_owner_facts(&foreign, AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut partial = facts.clone();
    partial.annotation_coverage = Completeness::Partial;
    assert_eq!(
        partial
            .annotation_owner_facts(&reference(1012), AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    // Injected inconsistent state must be an internal error, never empty success.
    let mut broken = facts.clone();
    broken.data.owner_bindings[0].annotation_set_offset = Some(u32::MAX);
    assert_eq!(
        broken
            .annotation_owner_facts(&reference(1012), AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
    let mut orphan = facts.clone();
    orphan.data.owner_bindings.clear();
    assert!(
        orphan
            .annotation_owner_facts(&reference(1012), AnnotationOwnerViewLimits::default())
            .unwrap()
            .is_empty()
    );

    // Two captured occurrences of the same physical bytes remain distinct.
    let input = InputSpec {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let occurrences: Vec<_> = snapshot
        .sources()
        .iter()
        .map(|source| {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let definitions =
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap()
        })
        .collect();
    assert_ne!(
        occurrences[0].source().dex_occurrence_id,
        occurrences[1].source().dex_occurrence_id
    );
    let from_second = AnnotationRef {
        snapshot_id: snapshot.manifest().snapshot_id.clone().into(),
        dex_occurrence_id: occurrences[1].source().dex_occurrence_id.clone(),
        annotation_byte_offset: 1120,
    };
    assert_eq!(
        occurrences[1]
            .annotation_owner_facts(&from_second, AnnotationOwnerViewLimits::default())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        occurrences[0]
            .annotation_owner_facts(&from_second, AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
}
#[test]
fn shared_call_sites_retain_independent_identity_and_physical_bytes() {
    let facts = build("artifacts/mdd-022/shared-callsite-view-20261101/shared.dex");
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../artifacts/mdd-022/shared-callsite-view-20261101/fixture.json"
    ))
    .unwrap();
    let array_offset = fixture["array_offset"].as_u64().unwrap() as u32;
    let section_offset = fixture["call_site_ids_offset"].as_u64().unwrap() as usize;
    let make = |call_site_idx| EncodedCallSiteRef {
        snapshot_id: facts.source().snapshot_id.to_string(),
        dex_occurrence_id: facts.source().dex_occurrence_id.to_string(),
        call_site_idx,
    };
    let limits = AnnotationOwnerViewLimits {
        max_scanned_entries: 2,
        max_matches: 1,
    };
    for index in 0..2 {
        let view = facts
            .encoded_call_site(&make(index), limits)
            .unwrap()
            .unwrap();
        assert_eq!(
            view.source.dex_occurrence_id,
            facts.source().dex_occurrence_id
        );
        assert_eq!(view.binding.call_site_idx, index);
        assert_eq!(view.array.byte_offset, array_offset);
        let at = section_offset + 4 * index as usize;
        assert_eq!(&facts.bytes()[at..at + 4], &array_offset.to_le_bytes());
        assert_eq!(view.raw_encoded.len(), 7);
        assert_eq!(view.raw_encoded[0], 3);
        assert_eq!(view.raw_encoded[1], 0x16);
        assert_eq!(view.raw_encoded[3], 0x17);
        assert_eq!(view.raw_encoded[5], 0x15);
        assert_eq!(
            view.binding.bootstrap_method_handle_idx,
            u32::from(view.raw_encoded[2])
        );
        assert_eq!(view.binding.name_string_idx, u32::from(view.raw_encoded[4]));
        assert_eq!(view.binding.method_type_idx, u32::from(view.raw_encoded[6]));
    }
    let array_ref = EncodedArrayRef {
        snapshot_id: facts.source().snapshot_id.to_string(),
        dex_occurrence_id: facts.source().dex_occurrence_id.to_string(),
        byte_offset: array_offset,
    };
    let reverse = facts
        .encoded_array_bindings(&array_ref, AnnotationOwnerViewLimits::default())
        .unwrap();
    let indices: Vec<_> = reverse
        .bindings
        .iter()
        .map(|binding| match binding {
            EncodedArrayBinding::CallSite(call) => call.call_site_idx,
            _ => panic!("unexpected static array binding"),
        })
        .collect();
    assert_eq!(indices, [0, 1]);
    assert!(facts.encoded_call_site(&make(2), limits).unwrap().is_none());
    for invalid_limits in [
        AnnotationOwnerViewLimits {
            max_scanned_entries: 1,
            max_matches: 1,
        },
        AnnotationOwnerViewLimits {
            max_scanned_entries: 2,
            max_matches: 0,
        },
    ] {
        assert_eq!(
            facts
                .encoded_call_site(&make(0), invalid_limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let mut foreign = make(0);
    foreign.dex_occurrence_id = "foreign".into();
    assert_eq!(
        facts
            .encoded_call_site(&foreign, limits)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut partial = facts.clone();
    partial.annotation_coverage = Completeness::Partial;
    assert_eq!(
        partial
            .encoded_call_site(&make(2), limits)
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut corrupted = facts.clone();
    corrupted.data.call_site_arrays[1].encoded_array_index = u32::MAX;
    assert_eq!(
        corrupted
            .encoded_call_site(&make(1), limits)
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
}
#[test]
fn nested_annotation_in_array_keeps_tree_and_cross_array_identity() {
    let facts = build("artifacts/mdd-022/nested-annotation-array-20261101/nested.dex");
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../artifacts/mdd-022/nested-annotation-array-20261101/fixture.json"
    ))
    .unwrap();
    let make = |field: &str| EncodedArrayRef {
        snapshot_id: facts.source().snapshot_id.to_string(),
        dex_occurrence_id: facts.source().dex_occurrence_id.to_string(),
        byte_offset: expected[field].as_u64().unwrap() as u32,
    };
    let first = make("first_array_offset");
    let second = make("second_array_offset");
    let limits = AnnotationValueViewLimits::default();
    let first_view = facts.encoded_array_view(&first, limits).unwrap();
    let view = facts.encoded_array_view(&second, limits).unwrap();
    let ty = expected["nested_type_index"].as_u64().unwrap() as u8;
    let name = expected["element_name_index"].as_u64().unwrap() as u8;
    assert_eq!(first_view.raw_encoded, &[1, 0x04, 0x2a]);
    assert_eq!(
        view.raw_encoded,
        &[1, 0x1d, ty, 1, name, 0x1c, 2, 0x1e, 0x3f]
    );
    assert_eq!(view.values.len(), 4);
    let root = &view.values[0];
    let nested = &view.values[1];
    let null = &view.values[2];
    let boolean = &view.values[3];
    assert_eq!(root.value.kind, EncodedKind::Annotation);
    assert_eq!(root.value.value_index, Some(u32::from(ty)));
    assert_eq!(root.value.depth, 0);
    assert_eq!(root.value.children, vec![nested.value.node_id]);
    assert_eq!(root.raw_encoded, &view.raw_encoded[1..]);
    assert_eq!(nested.value.kind, EncodedKind::Array);
    assert_eq!(nested.value.name_idx, Some(u32::from(name)));
    assert_eq!(nested.value.depth, 1);
    assert_eq!(
        nested.value.children,
        vec![null.value.node_id, boolean.value.node_id]
    );
    assert_eq!(nested.raw_encoded, &[0x1c, 2, 0x1e, 0x3f]);
    assert_eq!(null.value.kind, EncodedKind::Null);
    assert_eq!(null.value.depth, 2);
    assert_eq!(null.raw_encoded, &[0x1e]);
    assert_eq!(boolean.value.kind, EncodedKind::Boolean);
    assert_eq!(boolean.value.depth, 2);
    assert_eq!(boolean.value.ordinal, 1);
    assert_eq!(boolean.value.value_i64.as_deref(), Some("1"));
    assert_eq!(boolean.raw_encoded, &[0x3f]);
    let ref_for = |array: EncodedArrayRef, node_id| EncodedArrayValueRef { array, node_id };
    let nested_ref = ref_for(second.clone(), nested.value.node_id);
    let direct = facts
        .encoded_array_value(&nested_ref, limits)
        .unwrap()
        .unwrap();
    assert_eq!(direct.raw_encoded, nested.raw_encoded);
    assert!(
        facts
            .encoded_array_value(&ref_for(first.clone(), nested.value.node_id), limits)
            .unwrap()
            .is_none()
    );
    assert!(
        facts
            .encoded_array_value(&ref_for(second, first_view.values[0].value.node_id), limits)
            .unwrap()
            .is_none()
    );
    assert_eq!(first_view.values[0].value.value_i64.as_deref(), Some("42"));
}
#[test]
fn nested_array_direct_value_is_source_bound_and_preserves_raw_tree() {
    let facts = build("artifacts/mdd-022/nested-array-direct-20261101/nested.dex");
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../artifacts/mdd-022/nested-array-direct-20261101/fixture.json"
    ))
    .unwrap();
    let array_ref = EncodedArrayRef {
        snapshot_id: facts.source().snapshot_id.to_string(),
        dex_occurrence_id: facts.source().dex_occurrence_id.to_string(),
        byte_offset: expected["array_offset"].as_u64().unwrap() as u32,
    };
    let all = facts
        .encoded_array_view(&array_ref, AnnotationValueViewLimits::default())
        .unwrap();
    assert_eq!(all.raw_encoded, &[1, 0x1c, 1, 0x1e]);
    assert_eq!(all.values.len(), 2);
    let parent_id = all.array.elements[0];
    let parent_ref = EncodedArrayValueRef {
        array: array_ref.clone(),
        node_id: parent_id,
    };
    let parent = facts
        .encoded_array_value(&parent_ref, AnnotationValueViewLimits::default())
        .unwrap()
        .unwrap();
    assert_eq!(parent.source.dex_occurrence_id, array_ref.dex_occurrence_id);
    assert_eq!(parent.value.kind, EncodedKind::Array);
    assert_eq!(parent.value.depth, 0);
    assert_eq!(parent.raw_encoded, &[0x1c, 1, 0x1e]);
    assert_eq!(parent.value.children.len(), 1);
    let child_ref = EncodedArrayValueRef {
        array: array_ref.clone(),
        node_id: parent.value.children[0],
    };
    let child = facts
        .encoded_array_value(&child_ref, AnnotationValueViewLimits::default())
        .unwrap()
        .unwrap();
    assert_eq!(child.value.kind, EncodedKind::Null);
    assert_eq!(child.value.depth, 1);
    assert_eq!(child.value.ordinal, 0);
    assert_eq!(child.raw_encoded, &[0x1e]);
    assert_eq!(all.values[1].value.node_id, child.value.node_id);
    let visits = facts.data.encoded_arrays.len() as u64 + 1;
    for limits in [
        AnnotationValueViewLimits {
            max_scanned_entries: visits - 1,
            max_values: 1,
        },
        AnnotationValueViewLimits {
            max_scanned_entries: visits,
            max_values: 0,
        },
    ] {
        assert_eq!(
            facts
                .encoded_array_value(&child_ref, limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    assert!(
        facts
            .encoded_array_value(
                &child_ref,
                AnnotationValueViewLimits {
                    max_scanned_entries: visits,
                    max_values: 1
                }
            )
            .unwrap()
            .is_some()
    );
    let mut bad = child_ref.clone();
    bad.array.byte_offset += 1;
    assert_eq!(
        facts
            .encoded_array_value(&bad, AnnotationValueViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    bad = child_ref.clone();
    bad.array.dex_occurrence_id = "foreign".into();
    assert_eq!(
        facts
            .encoded_array_value(&bad, AnnotationValueViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    bad = child_ref.clone();
    bad.node_id = u32::MAX;
    assert!(
        facts
            .encoded_array_value(&bad, AnnotationValueViewLimits::default())
            .unwrap()
            .is_none()
    );
    bad.node_id = facts
        .data
        .values
        .iter()
        .find(|v| v.annotation_byte_offset.is_some())
        .unwrap()
        .node_id;
    assert!(
        facts
            .encoded_array_value(&bad, AnnotationValueViewLimits::default())
            .unwrap()
            .is_none()
    );
    let mut partial = facts.clone();
    partial.annotation_coverage = Completeness::Partial;
    assert_eq!(
        partial
            .encoded_array_value(&child_ref, AnnotationValueViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut corrupted = facts.clone();
    corrupted.data.values[child_ref.node_id as usize]
        .encoded_range
        .byte_length
        .0 = 2;
    assert_eq!(
        corrupted
            .encoded_array_value(&child_ref, AnnotationValueViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
}

#[test]
fn encoded_array_bindings_keep_shared_classes_call_sites_and_orphans() {
    let facts = build("artifacts/mdd-022/array-bindings-20261101/shared-static-empty.dex");
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../artifacts/mdd-022/array-bindings-20261101/fixture.json"
    ))
    .unwrap();
    let offset = expected["array_offset"].as_u64().unwrap() as u32;
    let reference = EncodedArrayRef {
        snapshot_id: facts.source().snapshot_id.to_string(),
        dex_occurrence_id: facts.source().dex_occurrence_id.to_string(),
        byte_offset: offset,
    };
    let result = facts
        .encoded_array_bindings(&reference, AnnotationOwnerViewLimits::default())
        .unwrap();
    assert_eq!(result.source.dex_occurrence_id, reference.dex_occurrence_id);
    assert_eq!(result.array.byte_offset, offset);
    assert_eq!(result.bindings.len(), 2);
    for (ordinal, binding) in result.bindings.iter().enumerate() {
        let EncodedArrayBinding::StaticValues(class) = binding else {
            panic!("expected class binding")
        };
        assert_eq!(class.class_def_idx, ordinal as u32);
        let at = class.encoded_range.byte_offset.0 as usize + 28;
        assert_eq!(&facts.bytes()[at..at + 4], &offset.to_le_bytes());
    }
    let visits = facts.data.encoded_arrays.len() as u64
        + facts.definitions.definitions.classes.len() as u64
        + facts.data.call_site_arrays.len() as u64;
    for limits in [
        AnnotationOwnerViewLimits {
            max_scanned_entries: visits - 1,
            max_matches: 2,
        },
        AnnotationOwnerViewLimits {
            max_scanned_entries: visits,
            max_matches: 1,
        },
    ] {
        assert_eq!(
            facts
                .encoded_array_bindings(&reference, limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let result = facts
        .encoded_array_bindings(
            &reference,
            AnnotationOwnerViewLimits {
                max_scanned_entries: visits,
                max_matches: 2,
            },
        )
        .unwrap();
    assert_eq!(result.bindings.len(), 2);
    let mut bad = reference.clone();
    bad.dex_occurrence_id = "foreign".into();
    assert_eq!(
        facts
            .encoded_array_bindings(&bad, AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    bad = reference.clone();
    bad.byte_offset += 2;
    assert_eq!(
        facts
            .encoded_array_bindings(&bad, AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut incomplete = facts.clone();
    incomplete.annotation_coverage = Completeness::Partial;
    assert_eq!(
        incomplete
            .encoded_array_bindings(&reference, AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );

    let orphan = build("tests/fixtures/annotations/generated/valid-orphan-arrays.dex");
    let orphan_ref = EncodedArrayRef {
        snapshot_id: orphan.source().snapshot_id.to_string(),
        dex_occurrence_id: orphan.source().dex_occurrence_id.to_string(),
        byte_offset: orphan.data.encoded_arrays[0].byte_offset,
    };
    assert!(
        orphan
            .encoded_array_bindings(&orphan_ref, AnnotationOwnerViewLimits::default())
            .unwrap()
            .bindings
            .is_empty()
    );

    let call = build("tests/fixtures/annotations/generated/valid-call-site-array.dex");
    let call_ref = EncodedArrayRef {
        snapshot_id: call.source().snapshot_id.to_string(),
        dex_occurrence_id: call.source().dex_occurrence_id.to_string(),
        byte_offset: call.data.encoded_arrays[0].byte_offset,
    };
    let result = call
        .encoded_array_bindings(&call_ref, AnnotationOwnerViewLimits::default())
        .unwrap();
    let [EncodedArrayBinding::CallSite(binding)] = result.bindings.as_slice() else {
        panic!("expected call site")
    };
    assert_eq!(binding.call_site_idx, 0);
    assert_eq!(binding.encoded_array_byte_offset, call_ref.byte_offset);
    let mut corrupted = call.clone();
    corrupted.data.call_site_arrays[0].encoded_array_index = u32::MAX;
    assert_eq!(
        corrupted
            .encoded_array_bindings(&call_ref, AnnotationOwnerViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
}
#[test]
fn encoded_array_view_retains_physical_items_and_enforces_scope() {
    let facts = build("tests/fixtures/annotations/generated/valid-orphan-arrays.dex");
    assert_eq!(facts.data.encoded_arrays.len(), 2);
    let reference = |offset| EncodedArrayRef {
        snapshot_id: facts.source().snapshot_id.to_string(),
        dex_occurrence_id: facts.source().dex_occurrence_id.to_string(),
        byte_offset: offset,
    };
    let empty = reference(facts.data.encoded_arrays[0].byte_offset);
    let populated = reference(facts.data.encoded_arrays[1].byte_offset);
    let view = facts
        .encoded_array_view(&empty, AnnotationValueViewLimits::default())
        .unwrap();
    assert_eq!(view.raw_encoded, &[0]);
    assert!(view.values.is_empty());
    let view = facts
        .encoded_array_view(&populated, AnnotationValueViewLimits::default())
        .unwrap();
    assert_eq!(view.source.dex_occurrence_id, populated.dex_occurrence_id);
    assert_eq!(view.raw_encoded.len(), 3);
    assert_eq!(view.raw_encoded[0..2], [1, 0x17]);
    assert_eq!(view.values.len(), 1);
    assert_eq!(view.values[0].value.kind, EncodedKind::String);
    assert_eq!(view.values[0].raw_encoded, &view.raw_encoded[1..]);
    let visits = facts.data.encoded_arrays.len() as u64 + 2 * facts.data.values.len() as u64 + 1;
    assert_eq!(
        facts
            .encoded_array_view(
                &populated,
                AnnotationValueViewLimits {
                    max_scanned_entries: visits - 1,
                    max_values: 1
                }
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        facts
            .encoded_array_view(
                &populated,
                AnnotationValueViewLimits {
                    max_scanned_entries: visits,
                    max_values: 0
                }
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        facts
            .encoded_array_view(
                &populated,
                AnnotationValueViewLimits {
                    max_scanned_entries: visits,
                    max_values: 1
                }
            )
            .unwrap()
            .values
            .len(),
        1
    );
    let mut invalid = populated.clone();
    invalid.byte_offset += 1;
    assert_eq!(
        facts
            .encoded_array_view(&invalid, AnnotationValueViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    invalid = populated.clone();
    invalid.dex_occurrence_id = "foreign".into();
    assert_eq!(
        facts
            .encoded_array_view(&invalid, AnnotationValueViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut partial = facts.clone();
    partial.annotation_coverage = Completeness::Partial;
    assert_eq!(
        partial
            .encoded_array_view(&populated, AnnotationValueViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut corrupted = facts.clone();
    let root = corrupted.data.encoded_arrays[1].elements[0] as usize;
    corrupted.data.values[root].ordinal = 42;
    assert_eq!(
        corrupted
            .encoded_array_view(&populated, AnnotationValueViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );

    let call = build("tests/fixtures/annotations/generated/valid-call-site-array.dex");
    let item = &call.data.encoded_arrays[0];
    let reference = EncodedArrayRef {
        snapshot_id: call.source().snapshot_id.to_string(),
        dex_occurrence_id: call.source().dex_occurrence_id.to_string(),
        byte_offset: item.byte_offset,
    };
    let view = call
        .encoded_array_view(&reference, AnnotationValueViewLimits::default())
        .unwrap();
    assert_eq!(view.raw_encoded[0], 3);
    assert_eq!(
        view.values
            .iter()
            .map(|value| value.value.kind)
            .collect::<Vec<_>>(),
        vec![
            EncodedKind::MethodHandle,
            EncodedKind::String,
            EncodedKind::MethodType
        ]
    );
    assert_eq!(
        call.data.call_site_arrays[0].encoded_array_byte_offset,
        view.array.byte_offset
    );
}
#[test]
fn annotation_value_view_preserves_raw_nodes_scope_and_budgets() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut facts = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        facts.push(AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap());
    }
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/oracle-results.json"
    ))
    .unwrap();
    let expected = oracle["positive"]["annotation_elements"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["annotation_off"].as_u64() == Some(1012))
        .collect::<Vec<_>>();
    assert!(!expected.is_empty());
    let mut occurrences = Vec::new();
    for item in &facts {
        let annotation = AnnotationRef {
            snapshot_id: snapshot.manifest().snapshot_id.clone().into(),
            dex_occurrence_id: item.source().dex_occurrence_id.clone(),
            annotation_byte_offset: 1012,
        };
        let values = item
            .annotation_value_facts(&annotation, AnnotationValueViewLimits::default())
            .unwrap()
            .collect::<MddResult<Vec<_>>>()
            .unwrap();
        assert_eq!(values.len(), expected.len());
        for (actual, reference) in values.iter().zip(&expected) {
            assert_eq!(
                actual.source.dex_occurrence_id,
                annotation.dex_occurrence_id
            );
            assert_eq!(actual.annotation.byte_offset, 1012);
            assert_eq!(
                u64::from(actual.value.depth),
                reference["depth"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(actual.value.ordinal),
                reference["ordinal"].as_u64().unwrap()
            );
            assert_eq!(
                actual.value.kind.as_str(),
                reference["value_kind"].as_str().unwrap()
            );
            assert_eq!(
                actual.value.value_index.map(u64::from),
                reference["value_index"].as_u64()
            );
            let start = reference["value_off"].as_u64().unwrap() as usize;
            let end = reference["value_end_off"].as_u64().unwrap() as usize;
            assert_eq!(actual.raw_encoded, &item.bytes()[start..end]);
        }
        assert!(
            values
                .iter()
                .any(|node| node.value.kind == EncodedKind::Null && node.raw_encoded == [0x1e])
        );
        assert!(
            values
                .iter()
                .any(|node| node.value.kind == EncodedKind::Float
                    && node.value.float_bit_width == Some(32)
                    && node.value.float_bits == Some(DecimalU64(0x8000_0000)))
        );
        let root = item
            .data
            .annotation_items
            .iter()
            .find(|node| node.byte_offset == 1012)
            .unwrap();
        let visits = item.data.annotation_items.len() as u64
            + 2 * item.data.values.len() as u64
            + root.elements.len() as u64;
        assert_eq!(
            item.annotation_value_facts(
                &annotation,
                AnnotationValueViewLimits {
                    max_scanned_entries: visits - 1,
                    ..AnnotationValueViewLimits::default()
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            item.annotation_value_facts(
                &annotation,
                AnnotationValueViewLimits {
                    max_scanned_entries: visits,
                    max_values: expected.len() as u64,
                }
            )
            .unwrap()
            .count(),
            expected.len()
        );
        assert_eq!(
            item.annotation_value_facts(
                &annotation,
                AnnotationValueViewLimits {
                    max_values: expected.len() as u64 - 1,
                    ..AnnotationValueViewLimits::default()
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
        let mut interior = annotation.clone();
        interior.annotation_byte_offset += 1;
        assert_eq!(
            item.annotation_value_facts(&interior, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let mut foreign = annotation.clone();
        foreign.snapshot_id = "other".into();
        assert_eq!(
            item.annotation_value_facts(&foreign, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let mut partial = item.clone();
        partial.annotation_coverage = Completeness::Partial;
        assert_eq!(
            partial
                .annotation_value_facts(&annotation, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut corrupt = item.clone();
        let node = corrupt
            .data
            .values
            .iter_mut()
            .find(|node| node.annotation_byte_offset == Some(1012))
            .unwrap();
        node.encoded_range.byte_offset = DecimalU64(1011);
        assert_eq!(
            corrupt
                .annotation_value_facts(&annotation, AnnotationValueViewLimits::default())
                .unwrap()
                .next()
                .unwrap()
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
        occurrences.push(annotation.dex_occurrence_id);
    }
    assert_ne!(occurrences[0], occurrences[1]);
    let cross = AnnotationRef {
        snapshot_id: facts[0].source().snapshot_id.clone(),
        dex_occurrence_id: facts[1].source().dex_occurrence_id.clone(),
        annotation_byte_offset: 1012,
    };
    assert_eq!(
        facts[0]
            .annotation_value_facts(&cross, AnnotationValueViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
}
#[test]
fn encoded_parameter_list_retains_unknown_positions_and_physical_bytes() {
    let short = build("tests/fixtures/annotations/generated/bad-parameter-arity.dex");
    let method = short
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    let view = short
        .method_encoded_parameter_list(&method, ParameterViewLimits::default())
        .unwrap()
        .unwrap();
    assert_eq!(
        view.source.dex_occurrence_id,
        short.source().dex_occurrence_id
    );
    assert_eq!(
        view.binding.prototype_position_coverage,
        Completeness::Unknown
    );
    assert_eq!(view.binding.prototype_parameter_count, 2);
    assert_eq!(view.binding.encoded_slot_count, 1);
    assert_eq!(view.list.annotation_set_offsets.len(), 1);
    let raw = view.raw_encoded;
    assert_eq!(raw.len(), 8);
    assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 1);
    let encoded_set = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    assert_eq!(
        view.list.annotation_set_offsets[0],
        (encoded_set != 0).then_some(encoded_set)
    );
    assert_eq!(
        short
            .method_parameter_facts(&method, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    for limits in [
        ParameterViewLimits {
            max_scan_entries: 0,
            ..ParameterViewLimits::default()
        },
        ParameterViewLimits {
            max_parameters: 0,
            ..ParameterViewLimits::default()
        },
    ] {
        assert_eq!(
            short
                .method_encoded_parameter_list(&method, limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let mut partial = short.clone();
    partial.annotation_coverage = Completeness::Unknown;
    assert_eq!(
        partial
            .method_encoded_parameter_list(&method, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut incomplete_slots = short.clone();
    incomplete_slots.data.parameter_lists[0].encoded_slots_complete = false;
    assert_eq!(
        incomplete_slots
            .method_encoded_parameter_list(&method, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut duplicate = short.clone();
    duplicate
        .data
        .parameter_lists
        .push(duplicate.data.parameter_lists[0].clone());
    assert_eq!(
        duplicate
            .method_encoded_parameter_list(&method, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
    let other = build("tests/fixtures/annotations/generated/bad-parameter-arity.dex");
    let foreign = other
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    assert_eq!(
        short
            .method_encoded_parameter_list(&foreign, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let plain = build("tests/fixtures/definitions/generated/definitions-035.dex");
    let external = plain
        .definitions()
        .definitions()
        .method_references
        .iter()
        .find(|m| m.method_name == "externalCall")
        .unwrap();
    let unbound = plain
        .definitions()
        .entity(EntityKind::MethodReference, external.method_idx)
        .unwrap();
    assert!(
        plain
            .method_encoded_parameter_list(&unbound, ParameterViewLimits::default())
            .unwrap()
            .is_none()
    );
}
#[test]
fn method_parameter_view_distinguishes_missing_list_zero_slot_and_unknown_position() {
    let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
    let reference = facts
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    let definition = facts
        .definitions()
        .entity(EntityKind::MethodDefinition, 0)
        .unwrap();
    for method in [&reference, &definition] {
        let view = facts
            .method_parameter_facts(method, ParameterViewLimits::default())
            .unwrap();
        assert_eq!(view.source().snapshot_id, facts.source().snapshot_id);
        assert_eq!(
            view.source().dex_occurrence_id,
            facts.source().dex_occurrence_id
        );
        assert_eq!(view.source().content_id, facts.source().content_id);
        assert!(view.definition.is_some());
        assert!(view.encoded_list.is_some());
        let parameters = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
        assert_eq!(parameters.len(), 2);
        assert_eq!(parameters[0].ordinal, 0);
        assert_eq!(parameters[0].parameter_type.descriptor, "Ljava/util/List;");
        assert!(
            matches!(parameters[0].annotation_encoding, ParameterAnnotationEncoding::SetOffset(offset) if offset > 0)
        );
        assert_eq!(parameters[1].ordinal, 1);
        assert_eq!(parameters[1].parameter_type.descriptor, "I");
        assert_eq!(
            parameters[1].annotation_encoding,
            ParameterAnnotationEncoding::ExplicitZeroSlot
        );
    }
    let no_list = build("tests/fixtures/definitions/generated/definitions-035.dex");
    let external = no_list
        .definitions()
        .definitions()
        .method_references
        .iter()
        .find(|method| method.method_name == "externalCall")
        .unwrap();
    let method = no_list
        .definitions()
        .entity(EntityKind::MethodReference, external.method_idx)
        .unwrap();
    let view = no_list
        .method_parameter_facts(&method, ParameterViewLimits::default())
        .unwrap();
    assert!(view.definition.is_none());
    assert!(view.encoded_list.is_none());
    let parameters = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
    assert_eq!(parameters.len(), 1);
    assert_eq!(
        parameters[0].annotation_encoding,
        ParameterAnnotationEncoding::NoEncodedList
    );
    let short = build("tests/fixtures/annotations/generated/bad-parameter-arity.dex");
    let short_method = short
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    let error = short
        .method_parameter_facts(&short_method, ParameterViewLimits::default())
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    assert_eq!(
        error.details["required_layer"],
        "prototype_parameter_annotation_positions"
    );
    for limits in [
        ParameterViewLimits {
            max_scan_entries: 0,
            ..ParameterViewLimits::default()
        },
        ParameterViewLimits {
            max_parameters: 0,
            ..ParameterViewLimits::default()
        },
    ] {
        assert_eq!(
            facts
                .method_parameter_facts(&reference, limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let mut incomplete = facts.clone();
    incomplete.annotation_coverage = Completeness::Unknown;
    assert_eq!(
        incomplete
            .method_parameter_facts(&reference, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let mut inconsistent = facts.clone();
    inconsistent.data.parameter_lists[0].prototype_parameter_count += 1;
    assert_eq!(
        inconsistent
            .method_parameter_facts(&reference, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InternalFault
    );
    let other = build("tests/fixtures/annotations/generated/annotations-038.dex");
    let foreign = other
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    assert_eq!(
        facts
            .method_parameter_facts(&foreign, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let wrong_kind = facts
        .definitions()
        .entity(EntityKind::FieldReference, 0)
        .unwrap();
    assert_eq!(
        facts
            .method_parameter_facts(&wrong_kind, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let repeated: Vec<_> = snapshot
        .sources()
        .iter()
        .map(|source| {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let definitions =
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap()
        })
        .collect();
    assert_eq!(
        repeated[0].source().snapshot_id,
        repeated[1].source().snapshot_id
    );
    assert_eq!(
        repeated[0].source().content_id,
        repeated[1].source().content_id
    );
    assert_ne!(
        repeated[0].source().dex_occurrence_id,
        repeated[1].source().dex_occurrence_id
    );
    let other_occurrence = repeated[1]
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    assert_eq!(
        repeated[0]
            .method_parameter_facts(&other_occurrence, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
}
fn canonical(rows: &serde_json::Value) -> Vec<String> {
    let mut values = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| serde_json::to_string(row).unwrap())
        .collect::<Vec<_>>();
    values.sort();
    values
}
/// Legal items nothing references stay facts, but the SQL projections only
/// see what a class-bound directory reaches (the frozen backend does the
/// same). The expected counts are the frozen backend's own row counts on
/// these fixtures (`artifacts/mdd-032-audit/a0-differential-20261112/`).
#[test]
fn unreferenced_items_stay_facts_but_are_not_reachable() {
    // (fixture, physical sets/annotations/elements, reachable sets/annotations/elements)
    let cases: [(&str, [usize; 3], [usize; 3]); 3] = [
        ("valid-orphan-annotation.dex", [5, 5, 44], [5, 4, 44]),
        ("valid-shared-empty-directory.dex", [5, 4, 44], [0, 0, 0]),
        ("valid-shared-empty-set.dex", [5, 4, 44], [4, 3, 40]),
    ];
    for (name, physical, reachable) in cases {
        let facts = build(&format!("tests/fixtures/annotations/generated/{name}"));
        assert_eq!(
            [
                facts.set_entry_rows(0).len(),
                facts.annotation_rows(0).len(),
                facts.element_rows(0).len()
            ],
            physical,
            "{name}: the fact layer keeps every legal item"
        );
        assert_eq!(
            [
                facts.reachable_set_entry_rows(0).len(),
                facts.reachable_annotation_rows(0).len(),
                facts.reachable_element_rows(0).len()
            ],
            reachable,
            "{name}: only directory-reachable items are projected"
        );
    }
}
#[test]
fn six_full_relations_equal_independent_oracle_and_reference() {
    let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/oracle-results.json"
    ))
    .unwrap();
    let data = &reference["positive"];
    for (name, native) in [
        (
            "annotation_directories",
            serde_json::to_value(facts.directory_rows(0)).unwrap(),
        ),
        (
            "annotation_directory_entries",
            serde_json::to_value(facts.directory_entry_rows(0)).unwrap(),
        ),
        (
            "annotation_set_entries",
            serde_json::to_value(facts.set_entry_rows(0)).unwrap(),
        ),
        (
            "annotation_set_refs",
            serde_json::to_value(facts.set_ref_rows(0)).unwrap(),
        ),
        (
            "annotations",
            serde_json::to_value(facts.annotation_rows(0)).unwrap(),
        ),
        (
            "annotation_elements",
            serde_json::to_value(facts.element_rows(0)).unwrap(),
        ),
    ] {
        assert_eq!(canonical(&native), canonical(&data[name]), "{name}");
    }
    assert!(
        facts
            .require_relation_columns(AnnotationRelation::Elements, &["*"])
            .is_ok()
    );
    assert_eq!(
        facts
            .require_relation_columns(AnnotationRelation::Elements, &["value_i65"])
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
}
#[test]
fn signature_parts_keep_array_order_pool_and_owner_source() {
    let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/expected.json"
    ))
    .unwrap();
    assert_eq!(facts.signatures.len(), 4);
    for signature in &facts.signatures {
        let key = match signature.owner.kind {
            AnnotationOwnerKind::Class => "class".to_owned(),
            AnnotationOwnerKind::Field => {
                format!("field:{}", signature.owner.reference.local_index)
            }
            AnnotationOwnerKind::Method => {
                format!("method:{}", signature.owner.reference.local_index)
            }
            AnnotationOwnerKind::Parameter => {
                panic!("fixture parameter has Values, not Signature")
            }
        };
        assert_eq!(
            signature.strict_utf8().unwrap(),
            expected["signatures"][key].as_str().unwrap()
        );
        assert_eq!(
            signature.string_pool_id,
            facts.definitions.metadata.string_pool.string_pool_id
        );
        assert!(
            signature
                .parts
                .iter()
                .all(|part| part.snapshot_id == facts.source().snapshot_id
                    && part.dex_occurrence_id == facts.source().dex_occurrence_id
                    && part.kind == EntityKind::String)
        );
    }
    let other = build("tests/fixtures/annotations/generated/annotations-038.dex");
    assert_ne!(facts.signatures[0].parts[0], other.signatures[0].parts[0]);
    assert_eq!(
        facts.signatures[0].string_pool_id,
        other.signatures[0].string_pool_id
    );
    assert_eq!(facts.annotation_coverage, Completeness::Complete);
    assert!(
        facts
            .unbuilt_layers
            .iter()
            .any(|layer| layer == "code_layout")
    );
}

#[test]
fn owner_signature_view_preserves_reference_definition_and_occurrence() {
    let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/expected.json"
    ))
    .unwrap();
    for signature in facts.signatures() {
        let expected_key = match signature.owner.kind {
            AnnotationOwnerKind::Class => "class".to_owned(),
            AnnotationOwnerKind::Field => {
                format!("field:{}", signature.owner.reference.local_index)
            }
            AnnotationOwnerKind::Method => {
                format!("method:{}", signature.owner.reference.local_index)
            }
            AnnotationOwnerKind::Parameter => panic!("fixture has no parameter Signature"),
        };
        for owner in
            std::iter::once(&signature.owner.reference).chain(signature.owner.definition.as_ref())
        {
            let got = facts
                .owner_signatures(owner, SignatureViewLimits::default())
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(got.len(), 1);
            assert_eq!(
                got[0].strict_utf8().unwrap(),
                expected["signatures"][&expected_key].as_str().unwrap()
            );
            assert_eq!(got[0].annotation, signature.annotation);
            assert_eq!(got[0].parts, signature.parts);
            assert_eq!(got[0].string_pool_id, signature.string_pool_id);
        }
    }
    let owner = facts.signatures()[0].owner.reference.clone();
    let limits = SignatureViewLimits {
        max_scanned_entries: 2 * facts.signatures().len() as u64,
        max_matches: 1,
    };
    assert_eq!(facts.owner_signatures(&owner, limits).unwrap().count(), 1);
    assert_eq!(
        facts
            .owner_signatures(
                &owner,
                SignatureViewLimits {
                    max_scanned_entries: limits.max_scanned_entries - 1,
                    ..limits
                },
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        facts
            .owner_signatures(
                &owner,
                SignatureViewLimits {
                    max_matches: 0,
                    ..limits
                }
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    let other = build("tests/fixtures/annotations/generated/annotations-038.dex");
    let foreign = other.signatures()[0].owner.reference.clone();
    assert_eq!(
        facts.owner_signatures(&foreign, limits).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    let mut invalid_owner = owner.clone();
    invalid_owner.local_index = u32::MAX;
    assert_eq!(
        facts
            .owner_signatures(&invalid_owner, limits)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    invalid_owner.local_index = 0;
    invalid_owner.kind = EntityKind::String;
    assert_eq!(
        facts
            .owner_signatures(&invalid_owner, limits)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let plain = build("tests/fixtures/definitions/generated/definitions-035.dex");
    let unannotated = plain
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    assert_eq!(
        plain
            .owner_signatures(&unannotated, SignatureViewLimits::default())
            .unwrap()
            .count(),
        0
    );
    let mut partial = facts.clone();
    partial.annotation_coverage = Completeness::Partial;
    assert_eq!(
        partial.owner_signatures(&owner, limits).err().unwrap().code,
        ErrorCode::IncompleteFacts
    );
    let mut repeated = facts.clone();
    repeated.signatures.push(repeated.signatures[0].clone());
    let repeated_view = repeated
        .owner_signatures(&owner, SignatureViewLimits::default())
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(repeated_view.len(), 2);
    assert_eq!(repeated_view[0].annotation, repeated_view[1].annotation);
    assert_eq!(repeated_view[0].parts, repeated_view[1].parts);

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut pair = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        pair.push(AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap());
    }
    let first = &pair[0].signatures()[0].owner.reference;
    let second = &pair[1].signatures()[0].owner.reference;
    assert_eq!(first.snapshot_id, second.snapshot_id);
    assert_ne!(first.dex_occurrence_id, second.dex_occurrence_id);
    assert_eq!(
        pair[0]
            .owner_signatures(first, SignatureViewLimits::default())
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        pair[1]
            .owner_signatures(second, SignatureViewLimits::default())
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        pair[0]
            .owner_signatures(second, SignatureViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn same_snapshot_duplicate_occurrences_keep_distinct_annotation_refs() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut facts = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        facts.push(AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap());
    }
    assert_eq!(facts[0].source().snapshot_id, facts[1].source().snapshot_id);
    assert_ne!(
        facts[0].signatures()[0].annotation,
        facts[1].signatures()[0].annotation
    );
    assert_ne!(
        facts[0].signatures()[0].parts[0],
        facts[1].signatures()[0].parts[0]
    );
    assert_eq!(
        facts[0].signatures()[0].string_pool_id,
        facts[1].signatures()[0].string_pool_id
    );
    drop(snapshot);
    assert_eq!(facts[0].bytes(), facts[1].bytes());
}

#[test]
fn short_parameter_lists_have_explicit_unknown_prototype_coverage() {
    let facts = build("tests/fixtures/annotations/generated/bad-parameter-arity.dex");
    assert_eq!(facts.annotation_coverage(), Completeness::Complete);
    assert_eq!(facts.set_ref_rows(0).len(), 1);
    let error = facts.require_complete_parameter_positions().unwrap_err();
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    assert_eq!(
        error.details["required_layer"],
        "prototype_parameter_annotation_positions"
    );
    assert!(
        facts
            .unbuilt_layers()
            .iter()
            .any(|layer| layer == "prototype_parameter_annotation_positions")
    );
}

#[test]
fn empty_and_long_encoded_lists_are_not_inferred_as_complete_positions() {
    for (path, expected_slots) in [
        (
            "tests/fixtures/annotations/generated/parameter-empty-nonzero-proto.dex",
            0usize,
        ),
        (
            "tests/fixtures/annotations/generated/parameter-long-nonzero-proto.dex",
            3usize,
        ),
    ] {
        let facts = build(path);
        let method = facts
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let list = facts
            .method_encoded_parameter_list(&method, ParameterViewLimits::default())
            .unwrap()
            .expect("an encoded list exists, even when its length is zero");
        assert_eq!(
            list.binding.prototype_position_coverage,
            Completeness::Unknown
        );
        assert_eq!(list.binding.prototype_parameter_count, 2);
        assert_eq!(list.list.annotation_set_offsets.len(), expected_slots);
        assert_eq!(list.raw_encoded.len(), 4 + expected_slots * 4);
        assert_eq!(
            u32::from_le_bytes(list.raw_encoded[..4].try_into().unwrap()) as usize,
            expected_slots
        );
        assert_eq!(
            facts
                .method_parameter_facts(&method, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        assert_eq!(
            facts
                .require_complete_parameter_positions()
                .unwrap_err()
                .code,
            ErrorCode::IncompleteFacts
        );
        if expected_slots == 3 {
            assert_eq!(list.list.annotation_set_offsets[1], None);
            assert_eq!(
                list.list.annotation_set_offsets[0],
                list.list.annotation_set_offsets[2]
            );
            assert!(list.list.annotation_set_offsets[0].is_some());
        }
    }
}

#[test]
fn empty_parameter_list_and_absent_binding_remain_distinct() {
    let explicit = build("tests/fixtures/annotations/generated/parameter-empty-zero-proto.dex");
    let absent =
        build("tests/fixtures/annotations/generated/parameter-orphan-empty-no-binding.dex");
    for (facts, has_binding) in [(&explicit, true), (&absent, false)] {
        let method = facts
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let encoded = facts
            .method_encoded_parameter_list(&method, ParameterViewLimits::default())
            .unwrap();
        assert_eq!(encoded.is_some(), has_binding);
        if let Some(encoded) = encoded {
            assert_eq!(
                encoded.binding.prototype_position_coverage,
                Completeness::Complete
            );
            assert_eq!(encoded.raw_encoded, &[0, 0, 0, 0]);
        }
        let view = facts
            .method_parameter_facts(&method, ParameterViewLimits::default())
            .unwrap();
        assert_eq!(view.encoded_list.is_some(), has_binding);
        assert_eq!(view.iter().count(), 0);
        facts.require_complete_parameter_positions().unwrap();
        // Physical empty list can be an orphan; absence of an owner binding
        // must not make the parser reject the valid physical item.
        assert_eq!(facts.data.ref_lists.len(), 1);
        assert!(facts.data.ref_lists[0].annotation_set_offsets.is_empty());
    }
}

#[test]
fn long_parameter_lists_keep_duplicate_source_occurrences_distinct() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/annotations/generated/parameter-long-nonzero-proto.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut pair = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        pair.push(AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap());
    }
    let first = pair[0]
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    let second = pair[1]
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    assert_eq!(first.snapshot_id, second.snapshot_id);
    assert_ne!(first.dex_occurrence_id, second.dex_occurrence_id);
    let left = pair[0]
        .method_encoded_parameter_list(&first, ParameterViewLimits::default())
        .unwrap()
        .unwrap();
    let right = pair[1]
        .method_encoded_parameter_list(&second, ParameterViewLimits::default())
        .unwrap()
        .unwrap();
    assert_eq!(left.raw_encoded, right.raw_encoded);
    assert_ne!(
        left.source.dex_occurrence_id,
        right.source.dex_occurrence_id
    );
    assert_eq!(
        left.binding.prototype_position_coverage,
        Completeness::Unknown
    );
    assert_eq!(
        right.binding.prototype_position_coverage,
        Completeness::Unknown
    );
    assert_eq!(
        pair[0]
            .method_encoded_parameter_list(&second, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn shared_parameter_signature_keeps_method_and_unknown_encoded_slots_distinct() {
    let facts = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/parameter-shared-signature.json"
    ))
    .unwrap();
    let signature_offset = expected["signature_offset"].as_u64().unwrap() as u32;
    let shared: Vec<_> = facts
        .signatures()
        .iter()
        .filter(|signature| signature.annotation.annotation_byte_offset == signature_offset)
        .collect();
    // One method-level annotation plus two encoded slots on each method.
    assert_eq!(shared.len(), 5);
    let mut parameter_owners = Vec::new();
    let mut method_owners = Vec::new();
    for signature in &shared {
        let fragments: Vec<_> = signature
            .parts
            .iter()
            .map(|part| {
                let string = &facts.definitions().metadata().strings()[part.local_index as usize];
                assert_eq!(string.entity, *part);
                string.data.text.strict_utf8().unwrap()
            })
            .collect();
        let expected_fragments: Vec<_> = expected["fragments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(fragments, expected_fragments);
        assert_eq!(
            signature.strict_utf8().unwrap(),
            expected_fragments.concat()
        );
        assert_eq!(signature.annotation.snapshot_id, facts.source().snapshot_id);
        assert_eq!(
            signature.annotation.dex_occurrence_id,
            facts.source().dex_occurrence_id
        );
        match signature.owner.kind {
            AnnotationOwnerKind::Parameter => parameter_owners.push((
                signature.owner.reference.local_index,
                signature.owner.parameter_ordinal.unwrap(),
            )),
            AnnotationOwnerKind::Method => method_owners.push((
                signature.owner.reference.local_index,
                signature.owner.parameter_ordinal,
            )),
            _ => panic!("unexpected owner for shared Signature item"),
        }
    }
    parameter_owners.sort_unstable();
    assert_eq!(parameter_owners, vec![(0, 0), (0, 2), (1, 0), (1, 2)]);
    assert_eq!(method_owners, vec![(0, None)]);
    for method_idx in [0, 1] {
        let method = facts
            .definitions()
            .entity(EntityKind::MethodReference, method_idx)
            .unwrap();
        let list = facts
            .method_encoded_parameter_list(&method, ParameterViewLimits::default())
            .unwrap()
            .unwrap();
        assert_eq!(
            list.binding.prototype_position_coverage,
            Completeness::Unknown
        );
        assert_eq!(
            facts
                .method_parameter_facts(&method, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let method_only: Vec<_> = facts
            .owner_signatures(&method, SignatureViewLimits::default())
            .unwrap()
            .collect();
        assert_eq!(method_only.len(), usize::from(method_idx == 0));
        assert!(
            method_only
                .iter()
                .all(|item| item.owner.kind == AnnotationOwnerKind::Method)
        );
    }
    assert!(
        facts
            .data()
            .owner_bindings
            .iter()
            .filter(|owner| owner.kind == AnnotationOwnerKind::Parameter)
            .all(|owner| owner.parameter_position_in_prototype.is_none())
    );
}

#[test]
fn signature_parameter_position_distinguishes_unknown_and_proven_slots() {
    let unknown = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
    let complete =
        build("tests/fixtures/annotations/generated/parameter-shared-signature-complete.dex");
    let mut counts = [0usize; 2];
    for (facts, expected_unknown) in [(&unknown, true), (&complete, false)] {
        for signature in facts.signatures() {
            let position = facts
                .signature_parameter_position(signature, SignaturePositionLimits::default())
                .unwrap();
            if signature.owner.kind == AnnotationOwnerKind::Parameter {
                let slot = signature.owner.parameter_ordinal.unwrap();
                if expected_unknown {
                    assert_eq!(
                        position,
                        SignatureParameterPosition::Unknown { encoded_slot: slot }
                    );
                    counts[0] += 1;
                } else {
                    assert_eq!(
                        position,
                        SignatureParameterPosition::Known { ordinal: slot }
                    );
                    counts[1] += 1;
                }
            } else {
                assert_eq!(position, SignatureParameterPosition::NotParameter);
            }
        }
    }
    assert_eq!(counts, [4, 2]);
    let signature = unknown
        .signatures()
        .iter()
        .find(|value| value.owner.kind == AnnotationOwnerKind::Parameter)
        .unwrap();
    assert_eq!(
        unknown
            .signature_parameter_position(
                signature,
                SignaturePositionLimits {
                    max_signatures: 0,
                    ..SignaturePositionLimits::default()
                }
            )
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        unknown
            .signature_parameter_position(
                signature,
                SignaturePositionLimits {
                    owners: AnnotationOwnerViewLimits {
                        max_scanned_entries: 0,
                        ..AnnotationOwnerViewLimits::default()
                    },
                    ..SignaturePositionLimits::default()
                }
            )
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let mut clone = signature.clone();
    assert_eq!(
        unknown
            .signature_parameter_position(&clone, SignaturePositionLimits::default())
            .unwrap(),
        SignatureParameterPosition::Unknown {
            encoded_slot: signature.owner.parameter_ordinal.unwrap()
        }
    );
    assert_eq!(
        unknown
            .signature_parameter_position(
                &clone,
                SignaturePositionLimits {
                    max_identity_bytes: 0,
                    ..SignaturePositionLimits::default()
                }
            )
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    clone.utf16_units.push(0);
    assert_eq!(
        unknown
            .signature_parameter_position(&clone, SignaturePositionLimits::default())
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    let foreign = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
    let foreign_signature = foreign
        .signatures()
        .iter()
        .find(|value| value.owner.kind == AnnotationOwnerKind::Parameter)
        .unwrap();
    assert_ne!(
        signature.annotation.snapshot_id,
        foreign_signature.annotation.snapshot_id
    );
    assert_eq!(
        unknown
            .signature_parameter_position(foreign_signature, SignaturePositionLimits::default())
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut inconsistent = unknown.clone();
    let owner = inconsistent
        .data
        .owner_bindings
        .iter_mut()
        .find(|owner| {
            owner.kind == AnnotationOwnerKind::Parameter
                && owner.local_index == signature.owner.reference.local_index
                && owner.parameter_ordinal == signature.owner.parameter_ordinal
        })
        .unwrap();
    owner.parameter_position_in_prototype = Some(true);
    let inconsistent_signature = inconsistent
        .signatures()
        .iter()
        .find(|value| {
            value.owner.kind == AnnotationOwnerKind::Parameter
                && value.owner.reference.local_index == signature.owner.reference.local_index
                && value.owner.parameter_ordinal == signature.owner.parameter_ordinal
        })
        .unwrap();
    assert_eq!(
        inconsistent
            .signature_parameter_position(
                inconsistent_signature,
                SignaturePositionLimits::default()
            )
            .unwrap_err()
            .code,
        ErrorCode::InternalFault
    );
}

#[test]
fn encoded_parameter_slots_preserve_zero_shared_and_absent_lists() {
    let facts = build("tests/fixtures/annotations/generated/parameter-long-nonzero-proto.dex");
    let method = facts
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    let visits = u64::try_from(facts.data.sets.len()).unwrap() * 2;
    let view = facts
        .method_encoded_parameter_slots(&method, ParameterViewLimits::default(), visits)
        .unwrap()
        .unwrap();
    assert_eq!(
        view.binding.prototype_position_coverage,
        Completeness::Unknown
    );
    let slots = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
    assert_eq!(
        slots.iter().map(|slot| slot.ordinal).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(slots[1].set.is_none());
    let first = slots[0].set.unwrap();
    let last = slots[2].set.unwrap();
    assert!(std::ptr::eq(first, last));
    let raw = &facts.bytes()[view.list.byte_offset as usize..];
    assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 3);
    assert_eq!(
        u32::from_le_bytes(raw[4..8].try_into().unwrap()),
        first.byte_offset
    );
    assert_eq!(u32::from_le_bytes(raw[8..12].try_into().unwrap()), 0);
    assert_eq!(
        u32::from_le_bytes(raw[12..16].try_into().unwrap()),
        last.byte_offset
    );
    assert_eq!(
        facts
            .method_encoded_parameter_slots(&method, ParameterViewLimits::default(), visits - 1)
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        facts
            .method_parameter_facts(&method, ParameterViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );

    let empty = build("tests/fixtures/annotations/generated/parameter-empty-zero-proto.dex");
    let empty_method = empty
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    let empty_slots = empty
        .method_encoded_parameter_slots(&empty_method, ParameterViewLimits::default(), 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        empty_slots.binding.prototype_position_coverage,
        Completeness::Complete
    );
    assert_eq!(empty_slots.iter().count(), 0);
    let absent =
        build("tests/fixtures/annotations/generated/parameter-orphan-empty-no-binding.dex");
    let absent_method = absent
        .definitions()
        .entity(EntityKind::MethodReference, 0)
        .unwrap();
    assert!(
        absent
            .method_encoded_parameter_slots(&absent_method, ParameterViewLimits::default(), 0)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        facts
            .method_encoded_parameter_slots(&absent_method, ParameterViewLimits::default(), visits)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );

    // Explicitly injected dangling set identity must fail rather than look empty.
    let mut broken = facts.clone();
    broken
        .data
        .sets
        .retain(|set| set.byte_offset != first.byte_offset);
    let invalid = broken
        .method_encoded_parameter_slots(&method, ParameterViewLimits::default(), u64::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(
        invalid.iter().next().unwrap().err().unwrap().code,
        ErrorCode::InternalFault
    );
}

#[test]
fn encoded_slots_distinguish_shared_physical_empty_set_zero_and_orphan() {
    let facts = build("tests/fixtures/annotations/generated/parameter-shared-empty-set.dex");
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/parameter-shared-empty-set.json"
    ))
    .unwrap();
    let empty_offset = expected["empty_set_offset"].as_u64().unwrap() as u32;
    let orphan_offset = expected["orphan_set_offset"].as_u64().unwrap() as u32;
    assert_ne!(empty_offset, orphan_offset);
    assert_eq!(
        &facts.bytes()[empty_offset as usize..empty_offset as usize + 4],
        &[0, 0, 0, 0]
    );
    assert_eq!(
        &facts.bytes()[orphan_offset as usize..orphan_offset as usize + 4],
        &[0, 0, 0, 0]
    );
    let mut previous_set = None;
    for method_idx in [0, 1] {
        let method = facts
            .definitions()
            .entity(EntityKind::MethodReference, method_idx)
            .unwrap();
        let budget = u64::try_from(facts.data.sets.len()).unwrap() * 2;
        let view = facts
            .method_encoded_parameter_slots(&method, ParameterViewLimits::default(), budget)
            .unwrap()
            .unwrap();
        assert_eq!(
            view.binding.prototype_position_coverage,
            Completeness::Unknown
        );
        let slots = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
        assert_eq!(
            slots.iter().map(|slot| slot.ordinal).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        let set = slots[0]
            .set
            .expect("nonzero offset must resolve to a physical set");
        assert_eq!(set.byte_offset, empty_offset);
        assert!(set.annotation_offsets.is_empty());
        assert!(slots[1].set.is_none());
        assert!(std::ptr::eq(set, slots[2].set.unwrap()));
        if let Some(previous) = previous_set {
            assert!(std::ptr::eq(previous, set));
        }
        previous_set = Some(set);
        assert_eq!(
            facts
                .method_parameter_facts(&method, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
    }
    let matching = facts
        .data
        .owner_bindings
        .iter()
        .filter(|owner| {
            owner.kind == AnnotationOwnerKind::Parameter
                && owner.annotation_set_offset == Some(empty_offset)
        })
        .count();
    assert_eq!(matching, 4);
    assert!(
        !facts
            .data
            .owner_bindings
            .iter()
            .any(|owner| owner.annotation_set_offset == Some(orphan_offset))
    );
    assert!(
        !facts
            .data
            .ref_lists
            .iter()
            .flat_map(|list| list.annotation_set_offsets.iter())
            .any(|offset| *offset == Some(orphan_offset))
    );
    let reference = AnnotationCollectionRef {
        snapshot_id: facts.source().snapshot_id.clone(),
        dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
        byte_offset: orphan_offset,
        kind: AnnotationCollectionKind::Set,
    };
    let AnnotationCollectionView::Set {
        item, raw_encoded, ..
    } = facts
        .collection_by_ref(&reference, facts.data.sets.len() as u64, 0)
        .unwrap()
    else {
        panic!("orphan collection is not a set")
    };
    assert!(item.annotation_offsets.is_empty());
    assert_eq!(raw_encoded, &[0, 0, 0, 0]);
}
