use super::*;
use crate::coverage::{ColumnDomain, ColumnRequirement, CoverageLedger, InputNeed};
use crate::{
    MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    raw_fingerprints::{FingerprintLimits, RawCodeEvidence},
    references::{ReferenceFacts, ReferenceLimits},
};
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::Completeness;
use std::path::PathBuf;

struct Data {
    snapshot: Snapshot,
    inventories: Vec<ArchiveInventory>,
    definitions: Vec<DefinitionFacts>,
    codes: Vec<CodeFacts>,
}
fn setup(relative: &str, copies: usize) -> Data {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(relative);
    let inputs = (0..copies)
        .map(|_| InputSpec {
            path: path.clone(),
            kind: InputKind::RawDex,
            expected_sha256: None,
        })
        .collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&inputs, CaptureLimits::default()).unwrap();
    let inventories = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let definitions = inventories
        .iter()
        .map(|inventory| {
            DefinitionFacts::build(
                MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default()).unwrap(),
                DefinitionLimits::default(),
            )
            .unwrap()
        })
        .collect();
    let codes = inventories
        .iter()
        .map(|inventory| {
            CodeFacts::build_all_code_items(&snapshot, inventory, 0, CodeLimits::default()).unwrap()
        })
        .collect();
    Data {
        snapshot,
        inventories,
        definitions,
        codes,
    }
}
fn scope(data: &Data) -> SelectedScope {
    SelectedScope::from_inventories(&data.snapshot, &data.inventories.iter().collect::<Vec<_>>())
        .unwrap()
}
fn column(
    scope: &SelectedScope,
    relation: &str,
    name: &str,
    domain: ColumnDomain,
) -> CoverageRequest {
    let mut request = CoverageRequest::for_scope(scope, &[]);
    request.required_columns.push(ColumnRequirement {
        relation: relation.into(),
        column: name.into(),
        domain,
    });
    request
}
fn error(code: ErrorCode, tag: &str) -> MddError {
    MddError::new(code, "facts.test", tag).detail("test_marker", tag)
}

#[test]
fn utf16_raw_candidates_match_scalar_and_hand_oracle_without_occurrence_dedup() {
    let data = setup("generated/strings-mutf8-035.dex", 2);
    let views = data
        .definitions
        .iter()
        .map(|d| {
            FactView::unbuilt(&d.metadata().source().dex_occurrence_id).with_metadata(d.metadata())
        })
        .collect::<Vec<_>>();
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    // Hand oracle: this fixture's ordered string pool is [], NUL, A, 中, high,
    // paired surrogate, low. Prefix/contains operate on code units, not UTF-8.
    let cases = [
        (Utf16Predicate::Any, vec![0, 1, 2, 3, 4, 5, 6]),
        (Utf16Predicate::Equal(vec![0]), vec![1]),
        (Utf16Predicate::Equal(vec![0xd800]), vec![4]),
        (Utf16Predicate::Prefix(vec![0xd83d]), vec![5]),
        (Utf16Predicate::Contains(vec![0xde00]), vec![5]),
        (Utf16Predicate::Contains(vec![0xd83d, 0xdc00]), vec![]),
        (Utf16Predicate::Prefix(vec![]), vec![0, 1, 2, 3, 4, 5, 6]),
        (Utf16Predicate::Contains(vec![]), vec![0, 1, 2, 3, 4, 5, 6]),
    ];
    for (predicate, expected) in cases {
        let indexed = index.strings_indexed(&predicate).unwrap();
        let scalar = index.strings_scalar(&predicate).unwrap();
        assert_eq!(indexed.entities, scalar.entities);
        assert_eq!(
            indexed
                .entities
                .iter()
                .map(|e| e.local_index)
                .collect::<Vec<_>>(),
            expected.repeat(2)
        );
        if indexed.entities.len() >= 2 {
            assert_ne!(
                indexed.entities[0].dex_occurrence_id,
                indexed.entities[indexed.entities.len() / 2].dex_occurrence_id
            );
        }
        assert_eq!(indexed.coverage.facts, Completeness::Complete);
        assert!(!indexed.coverage.profile_admitted);
    }
    let residual = index
        .strings_indexed(&Utf16Predicate::Contains(vec![0xd83d, 0xdc00]))
        .unwrap();
    assert_eq!(residual.candidate_count, 2);
    assert_eq!(residual.exact_match_count, 0);
    assert!(residual.absence_proven_within_selected_scope);
    assert_eq!(
        index
            .strings_raw_mutf8(&[0xc0, 0x80])
            .unwrap()
            .entities
            .iter()
            .map(|e| e.local_index)
            .collect::<Vec<_>>(),
        [1, 1]
    );
    assert!(index.strings_raw_mutf8(&[0]).unwrap().entities.is_empty());
    assert_eq!(index.audits().unwrap()[0].attempts.len(), 1);
}

#[test]
fn exact_class_lookup_exposes_scope_and_rejects_unbuilt_coverage() {
    let data = setup("references/generated/defined-field-035.dex", 2);
    let views = data
        .definitions
        .iter()
        .map(|facts| {
            FactView::unbuilt(&facts.metadata().source().dex_occurrence_id).with_definitions(facts)
        })
        .collect::<Vec<_>>();
    let full_scope = scope(&data);
    let descriptor = data.definitions[0].definitions().classes[0]
        .descriptor
        .encode_utf16()
        .collect::<Vec<_>>();
    let index = SnapshotFactIndex::new(full_scope.clone(), &views, IndexLimits::default()).unwrap();
    let indexed = index.classes_exact(&descriptor).unwrap();
    let scalar = index.classes_exact_scalar(&descriptor).unwrap();
    assert_eq!(indexed.entities, scalar.entities);
    assert_eq!(indexed.entities.len(), 2);
    assert_ne!(
        indexed.entities[0].dex_occurrence_id,
        indexed.entities[1].dex_occurrence_id
    );
    assert_eq!(indexed.snapshot_id, data.snapshot.manifest().snapshot_id);
    assert_eq!(indexed.scope_id, full_scope.scope_id());
    assert_eq!(indexed.coverage.input, Completeness::Complete);
    assert_eq!(indexed.coverage.facts, Completeness::Complete);
    assert!(indexed.covers_all_captured_sources);
    assert!(!indexed.coverage.profile_admitted);

    let selected =
        SelectedScope::from_inventories(&data.snapshot, &[&data.inventories[0]]).unwrap();
    let subset =
        SnapshotFactIndex::new(selected.clone(), &views[..1], IndexLimits::default()).unwrap();
    let absent = subset
        .classes_exact(&"Lmissing/Absent;".encode_utf16().collect::<Vec<_>>())
        .unwrap();
    assert!(absent.absence_proven_within_selected_scope);
    assert!(!absent.covers_all_captured_sources);
    assert_eq!(absent.scope_id, selected.scope_id());
    assert_ne!(absent.scope_id, full_scope.scope_id());

    let missing = [FactView::unbuilt(
        data.definitions[0]
            .metadata()
            .source()
            .dex_occurrence_id
            .clone(),
    )];
    let missing_index = SnapshotFactIndex::new(selected, &missing, IndexLimits::default()).unwrap();
    assert_eq!(
        missing_index.classes_exact(&descriptor).unwrap_err().code,
        ErrorCode::IncompleteFacts
    );
    let pending = SnapshotFactIndex::new(
        SelectedScope::pending(&data.snapshot),
        &[],
        IndexLimits::default(),
    )
    .unwrap();
    assert_eq!(
        pending.classes_exact(&descriptor).unwrap_err().code,
        ErrorCode::IncompleteFacts
    );
    assert_eq!(
        index.classes_exact(&vec![0; 1_000_001]).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
}

#[test]
fn definitions_owners_and_encoded_reference_symbols_preserve_distinct_sites() {
    let data = setup("references/generated/defined-field-035.dex", 2);
    let refs = data
        .definitions
        .iter()
        .zip(&data.codes)
        .map(|(d, c)| {
            ReferenceFacts::build(d.clone(), c.clone(), ReferenceLimits::default()).unwrap()
        })
        .collect::<Vec<_>>();
    let views = refs
        .iter()
        .map(|r| FactView::unbuilt(&r.source().dex_occurrence_id).with_references(r))
        .collect::<Vec<_>>();
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    for kind in [
        DefinitionKind::Class,
        DefinitionKind::Field,
        DefinitionKind::Method,
    ] {
        for predicate in [
            Utf16Predicate::Any,
            Utf16Predicate::Equal("caller".encode_utf16().collect()),
            Utf16Predicate::Prefix(vec![b't' as u16]),
            Utf16Predicate::Contains(vec![b'a' as u16]),
        ] {
            assert_eq!(
                index.definition_names(kind, &predicate).unwrap().entities,
                index
                    .definition_names_scalar(kind, &predicate)
                    .unwrap()
                    .entities
            );
        }
    }
    let classes = index
        .definition_names(DefinitionKind::Class, &Utf16Predicate::Any)
        .unwrap();
    assert_eq!(
        classes
            .entities
            .iter()
            .map(|e| e.local_index)
            .collect::<Vec<_>>(),
        [0, 0]
    );
    assert_ne!(data.definitions[0].definitions().classes[0].class_idx, 0);
    for owner in &classes.entities {
        for (kind, expected_count) in [(DefinitionKind::Field, 1), (DefinitionKind::Method, 3)] {
            let members = index
                .owner_members(owner, kind, &Utf16Predicate::Any)
                .unwrap();
            assert_eq!(members.entities.len(), expected_count);
            assert!(
                members
                    .entities
                    .iter()
                    .all(|e| e.dex_occurrence_id == owner.dex_occurrence_id)
            );
        }
        let mut wrong = owner.clone();
        wrong.kind = EntityKind::Type;
        assert_eq!(
            index
                .owner_members(&wrong, DefinitionKind::Method, &Utf16Predicate::Any)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    for r in &refs {
        for site in r.sites() {
            let target = r
                .target_id(site.target_kind, site.target_local_index)
                .unwrap();
            assert_eq!(
                index.references_local(&target).unwrap(),
                r.find_target_scalar(&target).unwrap()
            );
        }
    }
    let target = data.definitions[0]
        .definitions()
        .method_references
        .iter()
        .find(|m| m.method_name == "target")
        .unwrap();
    let symbol = MethodSymbol {
        owner: target.class_descriptor.clone(),
        name: target.method_name.clone(),
        prototype: data.definitions[0].metadata().prototypes()[target.proto_idx as usize]
            .data
            .descriptor
            .clone(),
    };
    let found = index.references_to_method_symbol(&symbol).unwrap();
    let expected = refs
        .iter()
        .flat_map(|r| {
            r.find_target_scalar(&r.target_id(TargetKind::Method, target.method_idx).unwrap())
                .unwrap()
                .sites
        })
        .collect::<Vec<_>>();
    assert_eq!(found.sites, expected);
    assert_eq!(found.sites.len(), 2); // Hand oracle: target once per occurrence.
    assert_eq!(
        found.sites,
        index
            .references_to_method_symbol_scalar(&symbol)
            .unwrap()
            .sites
    );
    let external = data.definitions[0]
        .definitions()
        .method_references
        .iter()
        .find(|m| m.method_name == "external")
        .unwrap();
    let external_symbol = MethodSymbol {
        owner: external.class_descriptor.clone(),
        name: external.method_name.clone(),
        prototype: "()V".into(),
    };
    assert_eq!(
        index
            .references_to_method_symbol(&external_symbol)
            .unwrap()
            .sites
            .len(),
        6
    ); // Three distinct operands per occurrence.
    let mut foreign = refs[0]
        .target_id(TargetKind::Method, target.method_idx)
        .unwrap();
    foreign.snapshot_id = "foreign".into();
    assert_eq!(
        index.references_local(&foreign).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn caller_site_index_rechecks_occurrence_kind_duplicates_and_coverage() {
    let data = setup("references/generated/shared-code-035.dex", 2);
    let refs = data
        .definitions
        .iter()
        .zip(&data.codes)
        .map(|(definition, code)| {
            ReferenceFacts::build(definition.clone(), code.clone(), ReferenceLimits::default())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let views = refs
        .iter()
        .map(|facts| FactView::unbuilt(&facts.source().dex_occurrence_id).with_references(facts))
        .collect::<Vec<_>>();
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    for (source, facts) in refs.iter().enumerate() {
        for method in &data.definitions[source].definitions().method_definitions {
            let caller = data.definitions[source]
                .entity(EntityKind::MethodDefinition, method.method_idx)
                .unwrap();
            for kind in [
                None,
                Some(TargetKind::String),
                Some(TargetKind::Method),
                Some(TargetKind::Field),
                Some(TargetKind::Type),
            ] {
                let indexed = index.references_from_method(&caller, kind).unwrap();
                let scalar = index.references_from_method_scalar(&caller, kind).unwrap();
                let expected = facts
                    .sites()
                    .iter()
                    .filter(|site| {
                        site.caller_method_idx == caller.local_index
                            && kind.is_none_or(|kind| site.target_kind == kind)
                    })
                    .map(|site| facts.site_id(site.site_ordinal).unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(indexed.sites, expected);
                assert_eq!(scalar.sites, expected);
                assert_eq!(
                    indexed.absence_proven_within_selected_encoded_scope,
                    expected.is_empty()
                );
                assert!(
                    indexed
                        .sites
                        .iter()
                        .all(|site| site.caller_method_definition == caller)
                );
            }
        }
    }
    let caller = data.definitions[0]
        .definitions()
        .method_definitions
        .iter()
        .find(|method| {
            refs[0]
                .sites()
                .iter()
                .any(|site| site.caller_method_idx == method.method_idx)
        })
        .map(|method| {
            data.definitions[0]
                .entity(EntityKind::MethodDefinition, method.method_idx)
                .unwrap()
        })
        .unwrap();
    let indexed = index.references_from_method(&caller, None).unwrap();
    let scalar = index.references_from_method_scalar(&caller, None).unwrap();
    assert!(indexed.candidate_reference_count < scalar.candidate_reference_count);
    assert_eq!(
        indexed.index_attempt.as_ref().unwrap().phase,
        lazy::IndexPhase::Ready
    );
    assert_eq!(indexed.index_attempt.as_ref().unwrap().attempts.len(), 1);

    let mut bad = caller.clone();
    bad.snapshot_id = "foreign".into();
    assert_eq!(
        index.references_from_method(&bad, None).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    bad = caller.clone();
    bad.dex_occurrence_id = "foreign".into();
    assert_eq!(
        index.references_from_method(&bad, None).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    bad = caller.clone();
    bad.kind = EntityKind::MethodReference;
    assert_eq!(
        index.references_from_method(&bad, None).unwrap_err().code,
        ErrorCode::InvalidArgument
    );

    let limited = SnapshotFactIndex::new(
        scope(&data),
        &views,
        IndexLimits {
            max_entries: data.definitions[0].definitions().method_definitions.len() as u64,
            ..IndexLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        limited
            .references_from_method(&caller, None)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        limited.retry_caller_site_index().unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    let audit = limited
        .audits()
        .unwrap()
        .into_iter()
        .find(|audit| audit.index_name == "encoded-caller-site-candidates-v1")
        .unwrap();
    assert_eq!(audit.phase, lazy::IndexPhase::Failed);
    assert_eq!(audit.attempts.len(), 2);
    for limits in [
        IndexLimits {
            max_result_entries: 0,
            ..IndexLimits::default()
        },
        IndexLimits {
            max_result_bytes: 0,
            ..IndexLimits::default()
        },
    ] {
        let limited = SnapshotFactIndex::new(scope(&data), &views, limits).unwrap();
        assert_eq!(
            limited
                .references_from_method(&caller, None)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let partial =
        SnapshotFactIndex::new(scope(&data), &views[..1], IndexLimits::default()).unwrap();
    assert_eq!(
        partial
            .references_from_method(&caller, None)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn field_symbol_indexes_preserve_sites_and_source_occurrences() {
    let data = setup("references/generated/defined-field-035.dex", 2);
    let refs = data
        .definitions
        .iter()
        .zip(&data.codes)
        .map(|(definition, code)| {
            ReferenceFacts::build(definition.clone(), code.clone(), ReferenceLimits::default())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let views = refs
        .iter()
        .map(|r| FactView::unbuilt(&r.source().dex_occurrence_id).with_references(r))
        .collect::<Vec<_>>();
    let site = refs[0]
        .sites()
        .iter()
        .find(|site| site.target_kind == TargetKind::Field)
        .expect("fixture must have an encoded field operand");
    let field =
        &data.definitions[0].definitions().field_references[site.target_local_index as usize];
    let symbol = FieldSymbol {
        owner: field.class_descriptor.clone(),
        name: field.field_name.clone(),
        field_type: field.type_descriptor.clone(),
    };
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    let indexed = index.references_to_field_symbol(&symbol).unwrap();
    let scalar = index.references_to_field_symbol_scalar(&symbol).unwrap();
    let expected = refs
        .iter()
        .flat_map(|r| {
            let target = r.target_id(TargetKind::Field, field.field_idx).unwrap();
            r.find_target_scalar(&target).unwrap().sites
        })
        .collect::<Vec<_>>();
    assert!(!expected.is_empty());
    assert_eq!(indexed.sites, expected);
    assert_eq!(scalar.sites, expected);
    assert!(indexed.sites.iter().any(
        |s| s.caller_method_definition.dex_occurrence_id == refs[0].source().dex_occurrence_id
    ));
    assert!(indexed.sites.iter().any(
        |s| s.caller_method_definition.dex_occurrence_id == refs[1].source().dex_occurrence_id
    ));
    assert!(!indexed.runtime_resolution.contains("dispatch"));
    assert_eq!(indexed.coverage.facts, Completeness::Complete);
    let mut missing = symbol.clone();
    missing.field_type.push('X');
    let absent = index.references_to_field_symbol(&missing).unwrap();
    assert!(absent.sites.is_empty());
    assert!(absent.absence_proven_within_selected_encoded_scope);

    let limited = SnapshotFactIndex::new(
        scope(&data),
        &views,
        IndexLimits {
            max_entries: 0,
            ..IndexLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        limited
            .references_to_field_symbol(&symbol)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        limited
            .references_to_field_symbol_scalar(&symbol)
            .unwrap()
            .sites,
        expected
    );
    assert_eq!(limited.audits().unwrap()[3].phase, lazy::IndexPhase::Failed);
    assert_eq!(
        limited
            .retry_field_reference_symbol_index()
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );

    let partial =
        SnapshotFactIndex::new(scope(&data), &[views[0].clone()], IndexLimits::default()).unwrap();
    assert_eq!(
        partial
            .references_to_field_symbol(&symbol)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn string_utf16_reference_index_preserves_nonscalar_sites_and_occurrences() {
    let data = setup("references/generated/nonscalar-string-035.dex", 2);
    let refs = data
        .definitions
        .iter()
        .zip(&data.codes)
        .map(|(definition, code)| {
            ReferenceFacts::build(definition.clone(), code.clone(), ReferenceLimits::default())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let views = refs
        .iter()
        .map(|r| FactView::unbuilt(&r.source().dex_occurrence_id).with_references(r))
        .collect::<Vec<_>>();
    let mut expected = Vec::new();
    for r in &refs {
        for string in r.definitions().metadata().strings() {
            if string.data.text.utf16_units == [0xd800] {
                let target = r
                    .target_id(TargetKind::String, string.data.string_idx)
                    .unwrap();
                expected.extend(r.find_target_scalar(&target).unwrap().sites);
            }
        }
    }
    assert!(!expected.is_empty());
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    let indexed = index.references_to_string_utf16(&[0xd800]).unwrap();
    let scalar = index.references_to_string_utf16_scalar(&[0xd800]).unwrap();
    assert_eq!(indexed.sites, expected);
    assert_eq!(scalar.sites, expected);
    assert!(indexed.sites.iter().any(
        |s| s.caller_method_definition.dex_occurrence_id == refs[0].source().dex_occurrence_id
    ));
    assert!(indexed.sites.iter().any(
        |s| s.caller_method_definition.dex_occurrence_id == refs[1].source().dex_occurrence_id
    ));
    assert_eq!(indexed.coverage.facts, Completeness::Complete);
    assert!(
        index
            .references_to_string_utf16(&[0xd801])
            .unwrap()
            .absence_proven_within_selected_encoded_scope
    );

    let limited = SnapshotFactIndex::new(
        scope(&data),
        &views,
        IndexLimits {
            max_entries: 0,
            ..IndexLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        limited
            .references_to_string_utf16(&[0xd800])
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        limited
            .references_to_string_utf16_scalar(&[0xd800])
            .unwrap()
            .sites,
        expected
    );
    assert_eq!(limited.audits().unwrap()[0].phase, lazy::IndexPhase::Failed);
    let partial =
        SnapshotFactIndex::new(scope(&data), &[views[0].clone()], IndexLimits::default()).unwrap();
    assert_eq!(
        partial
            .references_to_string_utf16(&[0xd800])
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn type_descriptor_reference_index_preserves_exact_sites_and_occurrences() {
    let data = setup("references/generated/type-names-035.dex", 2);
    let refs = data
        .definitions
        .iter()
        .zip(&data.codes)
        .map(|(definition, code)| {
            ReferenceFacts::build(definition.clone(), code.clone(), ReferenceLimits::default())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let views = refs
        .iter()
        .map(|r| FactView::unbuilt(&r.source().dex_occurrence_id).with_references(r))
        .collect::<Vec<_>>();
    let site = refs[0]
        .sites()
        .iter()
        .find(|site| site.target_kind == TargetKind::Type)
        .expect("fixture must contain an encoded type operand");
    let expected_type =
        &refs[0].definitions().metadata().types()[site.target_local_index as usize].data;
    let descriptor = expected_type.descriptor.clone();
    let mut expected = Vec::new();
    for r in &refs {
        for ty in r.definitions().metadata().types() {
            if ty.data.descriptor == descriptor {
                let target = r.target_id(TargetKind::Type, ty.data.type_idx).unwrap();
                expected.extend(r.find_target_scalar(&target).unwrap().sites);
            }
        }
    }
    assert!(!expected.is_empty());
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    let indexed = index.references_to_type_descriptor(&descriptor).unwrap();
    assert_eq!(indexed.sites, expected);
    assert_eq!(
        index
            .references_to_type_descriptor_scalar(&descriptor)
            .unwrap()
            .sites,
        expected
    );
    assert!(indexed.sites.iter().any(
        |s| s.caller_method_definition.dex_occurrence_id == refs[0].source().dex_occurrence_id
    ));
    assert!(indexed.sites.iter().any(
        |s| s.caller_method_definition.dex_occurrence_id == refs[1].source().dex_occurrence_id
    ));
    assert_eq!(indexed.coverage.facts, Completeness::Complete);
    assert!(
        index
            .references_to_type_descriptor("Lnonexistent/example;")
            .unwrap()
            .absence_proven_within_selected_encoded_scope
    );
    assert_eq!(
        indexed.runtime_resolution,
        "encoded_type_operands_only;runtime_resolution_not_inferred"
    );

    let limited = SnapshotFactIndex::new(
        scope(&data),
        &views,
        IndexLimits {
            max_entries: 0,
            ..IndexLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        limited
            .references_to_type_descriptor(&descriptor)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        limited
            .references_to_type_descriptor_scalar(&descriptor)
            .unwrap()
            .sites,
        expected
    );
    assert_eq!(limited.audits().unwrap()[4].phase, lazy::IndexPhase::Failed);
    assert_eq!(
        limited.retry_type_reference_index().unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    let partial =
        SnapshotFactIndex::new(scope(&data), &[views[0].clone()], IndexLimits::default()).unwrap();
    assert_eq!(
        partial
            .references_to_type_descriptor(&descriptor)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn prototype_descriptor_reference_index_preserves_encoded_sites_and_occurrences() {
    for (fixture, expected_pc) in [
        ("references/generated/poly-custom-038.dex", &[26, 30][..]),
        ("references/generated/handles-039.dex", &[28][..]),
    ] {
        let data = setup(fixture, 2);
        let refs = data
            .definitions
            .iter()
            .zip(&data.codes)
            .map(|(definition, code)| {
                ReferenceFacts::build(definition.clone(), code.clone(), ReferenceLimits::default())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let views = refs
            .iter()
            .map(|r| FactView::unbuilt(&r.source().dex_occurrence_id).with_references(r))
            .collect::<Vec<_>>();
        let sites = refs[0]
            .sites()
            .iter()
            .filter(|site| site.target_kind == TargetKind::Prototype)
            .collect::<Vec<_>>();
        assert_eq!(
            sites
                .iter()
                .map(|site| site.code_unit_pc)
                .collect::<Vec<_>>(),
            expected_pc
        );
        let descriptor = refs[0].definitions().metadata().prototypes()
            [sites[0].target_local_index as usize]
            .data
            .descriptor
            .clone();
        let mut expected = Vec::new();
        for r in &refs {
            for prototype in r.definitions().metadata().prototypes() {
                if prototype.data.descriptor == descriptor {
                    let target = r
                        .target_id(TargetKind::Prototype, prototype.data.proto_idx)
                        .unwrap();
                    expected.extend(r.find_target_scalar(&target).unwrap().sites);
                }
            }
        }
        let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
        let indexed = index
            .references_to_prototype_descriptor(&descriptor)
            .unwrap();
        assert_eq!(indexed.sites, expected);
        assert_eq!(
            index
                .references_to_prototype_descriptor_scalar(&descriptor)
                .unwrap()
                .sites,
            expected
        );
        assert_eq!(indexed.sites.len(), expected_pc.len() * 2);
        assert!(
            indexed
                .sites
                .iter()
                .any(|s| s.caller_method_definition.dex_occurrence_id
                    == refs[0].source().dex_occurrence_id)
        );
        assert!(
            indexed
                .sites
                .iter()
                .any(|s| s.caller_method_definition.dex_occurrence_id
                    == refs[1].source().dex_occurrence_id)
        );
        assert_eq!(indexed.coverage.facts, Completeness::Complete);
        assert!(
            index
                .references_to_prototype_descriptor("(Lmissing;)V")
                .unwrap()
                .absence_proven_within_selected_encoded_scope
        );
        assert_eq!(
            indexed.runtime_resolution,
            "encoded_prototype_operands_only;runtime_dispatch_not_inferred"
        );
        let limited = SnapshotFactIndex::new(
            scope(&data),
            &views,
            IndexLimits {
                max_entries: 0,
                ..IndexLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            limited
                .references_to_prototype_descriptor(&descriptor)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            limited
                .references_to_prototype_descriptor_scalar(&descriptor)
                .unwrap()
                .sites,
            expected
        );
        assert_eq!(limited.audits().unwrap()[5].phase, lazy::IndexPhase::Failed);
        assert_eq!(
            limited.retry_prototype_reference_index().unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
        let partial =
            SnapshotFactIndex::new(scope(&data), &[views[0].clone()], IndexLimits::default())
                .unwrap();
        assert_eq!(
            partial
                .references_to_prototype_descriptor(&descriptor)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteFacts
        );
    }
}

#[test]
fn method_handle_index_keeps_exact_kind_target_and_occurrence_sites() {
    let data = setup("references/generated/handles-039.dex", 2);
    let refs = data
        .definitions
        .iter()
        .zip(&data.codes)
        .map(|(definition, code)| {
            ReferenceFacts::build(definition.clone(), code.clone(), ReferenceLimits::default())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let views = refs
        .iter()
        .map(|r| FactView::unbuilt(&r.source().dex_occurrence_id).with_references(r))
        .collect::<Vec<_>>();
    let handles = refs[0].method_handle_metadata().unwrap();
    assert_eq!(handles.len(), 2);
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    for handle in handles {
        let symbol = handle_target(&refs[0], handle).unwrap().owned();
        let expected_pc = match symbol {
            MethodHandleSymbol::Method { .. } => 24,
            MethodHandleSymbol::Field { .. } => 26,
        };
        let actual = index.references_to_method_handle_symbol(&symbol).unwrap();
        assert_eq!(actual.sites.len(), 2);
        assert!(
            actual
                .sites
                .iter()
                .all(|site| site.code_unit_pc == expected_pc
                    && site.operand_kind == TargetKind::MethodHandle)
        );
        assert_ne!(
            actual.sites[0].caller_method_definition.dex_occurrence_id,
            actual.sites[1].caller_method_definition.dex_occurrence_id
        );
        assert_eq!(
            index
                .references_to_method_handle_symbol_scalar(&symbol)
                .unwrap()
                .sites,
            actual.sites
        );
        assert_eq!(
            actual.runtime_resolution,
            "encoded_method_handle_operands_only;no_implied_call_or_field_access"
        );
        let mut different_kind = symbol.clone();
        match &mut different_kind {
            MethodHandleSymbol::Field { handle_kind, .. } => *handle_kind = (*handle_kind + 1) % 4,
            MethodHandleSymbol::Method { handle_kind, .. } => {
                *handle_kind = 4 + ((*handle_kind - 4 + 1) % 5)
            }
        }
        assert!(
            index
                .references_to_method_handle_symbol(&different_kind)
                .unwrap()
                .absence_proven_within_selected_encoded_scope
        );
        let limited = SnapshotFactIndex::new(
            scope(&data),
            &views,
            IndexLimits {
                max_entries: 0,
                ..IndexLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            limited
                .references_to_method_handle_symbol(&symbol)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            limited
                .references_to_method_handle_symbol_scalar(&symbol)
                .unwrap()
                .sites,
            actual.sites
        );
        assert_eq!(
            limited.retry_method_handle_index().unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
        let partial =
            SnapshotFactIndex::new(scope(&data), &[views[0].clone()], IndexLimits::default())
                .unwrap();
        assert_eq!(
            partial
                .references_to_method_handle_symbol(&symbol)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteFacts
        );
    }
    let ordinary = setup("references/generated/classic-035.dex", 1);
    let facts = ReferenceFacts::build(
        ordinary.definitions[0].clone(),
        ordinary.codes[0].clone(),
        ReferenceLimits::default(),
    )
    .unwrap();
    assert!(facts.method_handle_metadata().is_none());
    let view = FactView::unbuilt(&facts.source().dex_occurrence_id).with_references(&facts);
    let empty = SnapshotFactIndex::new(scope(&ordinary), &[view], IndexLimits::default()).unwrap();
    let symbol = handle_target(&refs[0], &handles[0]).unwrap().owned();
    assert!(
        empty
            .references_to_method_handle_symbol(&symbol)
            .unwrap()
            .absence_proven_within_selected_encoded_scope
    );
}

#[test]
fn callsite_encoded_byte_key_keeps_same_content_and_all_occurrence_sites() {
    let data = setup("references/generated/poly-custom-038.dex", 2);
    let refs = data
        .definitions
        .iter()
        .zip(&data.codes)
        .map(|(definition, code)| {
            ReferenceFacts::build(definition.clone(), code.clone(), ReferenceLimits::default())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let views = refs
        .iter()
        .map(|r| FactView::unbuilt(&r.source().dex_occurrence_id).with_references(r))
        .collect::<Vec<_>>();
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    let target = refs[0].target_id(TargetKind::CallSite, 0).unwrap();
    let key = index.call_site_encoded_key(&target).unwrap();
    let section = refs[0].call_site_metadata().unwrap();
    let binding = &section.call_site_arrays[0];
    let array = &section.arrays[binding.encoded_array_index as usize];
    let start = array.encoded_range.byte_offset.0 as usize;
    let end = start + array.encoded_range.byte_length.0 as usize;
    assert_eq!(
        key.encoded_array(),
        &refs[0].definitions().bytes()[start..end]
    );
    assert_eq!(key.encoded_array()[0], 3); // fixture has bootstrap, name and proto, no extras
    assert_eq!(key.dex_content_id(), refs[0].source().content_id);
    let result = index.references_to_call_site_encoded_key(&key).unwrap();
    assert_eq!(
        result
            .sites
            .iter()
            .map(|s| s.code_unit_pc)
            .collect::<Vec<_>>(),
        vec![34, 37, 34, 37]
    );
    assert!(
        result
            .sites
            .iter()
            .all(|site| site.operand_kind == TargetKind::CallSite)
    );
    assert_ne!(
        result.sites[0].caller_method_definition.dex_occurrence_id,
        result.sites[2].caller_method_definition.dex_occurrence_id
    );
    assert_eq!(
        index
            .references_to_call_site_encoded_key_scalar(&key)
            .unwrap()
            .sites,
        result.sites
    );
    assert_eq!(
        result.runtime_resolution,
        "same_dex_content_and_encoded_array_bytes_only;dynamic_target_not_inferred"
    );
    let mut changed = key.clone();
    changed.encoded_array.push(0x1e);
    assert!(
        index
            .references_to_call_site_encoded_key(&changed)
            .unwrap()
            .absence_proven_within_selected_encoded_scope
    );
    let mut foreign_content = key.clone();
    foreign_content.dex_content_id = "different-dex-content".into();
    assert!(
        index
            .references_to_call_site_encoded_key(&foreign_content)
            .unwrap()
            .absence_proven_within_selected_encoded_scope
    );
    let mut foreign_key = key.clone();
    foreign_key.snapshot_id = "foreign-snapshot".into();
    assert_eq!(
        index
            .references_to_call_site_encoded_key(&foreign_key)
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut foreign_target = target.clone();
    foreign_target.snapshot_id = "foreign-snapshot".into();
    assert_eq!(
        index
            .call_site_encoded_key(&foreign_target)
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    let limited = SnapshotFactIndex::new(
        scope(&data),
        &views,
        IndexLimits {
            max_entries: 0,
            ..IndexLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        limited
            .references_to_call_site_encoded_key(&key)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let partial =
        SnapshotFactIndex::new(scope(&data), &[views[0].clone()], IndexLimits::default()).unwrap();
    assert_eq!(
        partial.call_site_encoded_key(&target).unwrap_err().code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn descriptor_owner_members_preserve_occurrences_and_exact_direct_declarations() {
    let data = setup("references/generated/defined-field-035.dex", 2);
    let views = data
        .definitions
        .iter()
        .map(|d| FactView::unbuilt(&d.metadata().source().dex_occurrence_id).with_definitions(d))
        .collect::<Vec<_>>();
    let descriptor = data.definitions[0].definitions().classes[0]
        .descriptor
        .clone();
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    for (kind, count) in [(DefinitionKind::Field, 2), (DefinitionKind::Method, 6)] {
        for predicate in [
            Utf16Predicate::Any,
            Utf16Predicate::Prefix(vec![b'c' as u16]),
            Utf16Predicate::Contains(vec![b'a' as u16]),
        ] {
            let indexed = index
                .owner_members_by_descriptor(&descriptor, kind, &predicate)
                .unwrap();
            let scalar = index
                .owner_members_by_descriptor_scalar(&descriptor, kind, &predicate)
                .unwrap();
            assert_eq!(indexed.entities, scalar.entities);
            assert_eq!(indexed.coverage.facts, Completeness::Complete);
            if matches!(predicate, Utf16Predicate::Any) {
                assert_eq!(indexed.entities.len(), count);
                assert!(indexed.entities.iter().any(|v| v.dex_occurrence_id
                    == data.definitions[0].metadata().source().dex_occurrence_id));
                assert!(indexed.entities.iter().any(|v| v.dex_occurrence_id
                    == data.definitions[1].metadata().source().dex_occurrence_id));
            }
        }
    }
    assert!(
        index
            .owner_members_by_descriptor(
                "Lmissing/Owner;",
                DefinitionKind::Method,
                &Utf16Predicate::Any
            )
            .unwrap()
            .absence_proven_within_selected_scope
    );
    assert_eq!(
        index
            .owner_members_by_descriptor(&descriptor, DefinitionKind::Class, &Utf16Predicate::Any)
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    let limited = SnapshotFactIndex::new(
        scope(&data),
        &views,
        IndexLimits {
            max_result_entries: 1,
            ..IndexLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        limited
            .owner_members_by_descriptor(&descriptor, DefinitionKind::Method, &Utf16Predicate::Any)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        limited
            .owner_members_by_descriptor_scalar(
                &descriptor,
                DefinitionKind::Method,
                &Utf16Predicate::Any
            )
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let partial =
        SnapshotFactIndex::new(scope(&data), &[views[0].clone()], IndexLimits::default()).unwrap();
    assert_eq!(
        partial
            .owner_members_by_descriptor(&descriptor, DefinitionKind::Method, &Utf16Predicate::Any)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn explicit_subset_negative_proof_and_foreign_generation_are_bounded() {
    let data = setup("generated/strings-mutf8-035.dex", 2);
    let selected =
        SelectedScope::from_inventories(&data.snapshot, &[&data.inventories[0]]).unwrap();
    let metadata = data.definitions[0].metadata();
    let view = FactView::unbuilt(&metadata.source().dex_occurrence_id).with_metadata(metadata);
    let index = SnapshotFactIndex::new(
        selected.clone(),
        std::slice::from_ref(&view),
        IndexLimits::default(),
    )
    .unwrap();
    let missing = index
        .strings_indexed(&Utf16Predicate::Equal(vec![0x1234]))
        .unwrap();
    assert!(missing.absence_proven_within_selected_scope);
    assert!(!missing.covers_all_captured_sources);
    assert!(!missing.coverage.covers_all_captured_sources);
    assert_eq!(missing.coverage.selected_dex_occurrences.len(), 1);
    assert_eq!(
        missing.coverage.scope_content_key,
        selected.scope_content_key()
    );
    let foreign = setup("generated/strings-mutf8-035.dex", 1);
    let foreign_view =
        FactView::unbuilt(view.occurrence()).with_metadata(foreign.definitions[0].metadata());
    assert_eq!(
        SnapshotFactIndex::new(selected, &[foreign_view], IndexLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let empty = SnapshotFactIndex::new(scope(&data), &[], IndexLimits::default()).unwrap();
    assert_eq!(
        empty
            .strings_indexed(&Utf16Predicate::Equal(vec![0x1234]))
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
    // A validated header declaring zero definitions does not replace a required producer.
    assert_eq!(
        index
            .definition_names(DefinitionKind::Class, &Utf16Predicate::Any)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn coverage_retains_late_genuine_errors_and_rejects_terminal_overwrite() {
    let data = setup("generated/strings-mutf8-035.dex", 1);
    let selected = scope(&data);
    let occurrence = &selected.dexes()[0].dex_occurrence_id;
    let mut ledger = CoverageLedger::new(selected.clone(), &[]).unwrap();
    ledger
        .record_failure(
            occurrence,
            FactLayer::AllMethodBodies,
            error(ErrorCode::InvalidInput, "bad-body"),
        )
        .unwrap();
    let request = column(
        &selected,
        "methods",
        "opcode_count",
        ColumnDomain::NativeAtoms,
    );
    let report = ledger.evaluate(&request).unwrap();
    assert_eq!(report.facts, Completeness::Partial);
    assert_eq!(
        report.require_complete().unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        report.require_complete().unwrap_err().details["test_marker"],
        "bad-body"
    );
    ledger
        .record_input_failure(error(ErrorCode::UnsupportedCapability, "fallback-input"))
        .unwrap();
    assert_eq!(
        ledger
            .evaluate(&request)
            .unwrap()
            .require_complete()
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        ledger
            .record_failure(
                occurrence,
                FactLayer::AllMethodBodies,
                error(ErrorCode::UnsupportedQuery, "overwrite")
            )
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        ledger
            .record_input_failure(error(ErrorCode::InvalidInput, "overwrite-input"))
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        ledger
            .evaluate(&request)
            .unwrap()
            .require_complete()
            .unwrap_err()
            .details["test_marker"],
        "bad-body"
    );
    let mut deps = CoverageLedger::new(selected.clone(), &[]).unwrap();
    deps.record_failure(
        occurrence,
        FactLayer::Metadata,
        error(ErrorCode::UnsupportedQuery, "first"),
    )
    .unwrap();
    deps.record_failure(
        occurrence,
        FactLayer::CodeProjection,
        error(ErrorCode::InvalidInput, "later-dependency"),
    )
    .unwrap();
    assert_eq!(
        deps.evaluate(&CoverageRequest::for_scope(
            &selected,
            &[FactLayer::References]
        ))
        .unwrap()
        .require_complete()
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
    let pending = SelectedScope::pending(&data.snapshot);
    let mut ledger = CoverageLedger::new(pending.clone(), &[]).unwrap();
    let r = ledger
        .evaluate(&CoverageRequest::for_scope(
            &pending,
            &[FactLayer::Metadata],
        ))
        .unwrap();
    assert_eq!(r.facts, Completeness::Unknown);
    assert_eq!(r.input, Completeness::Unknown);
    ledger
        .record_input_failure(error(ErrorCode::InvalidInput, "broken-empty-roster"))
        .unwrap();
    let mut request = CoverageRequest::for_scope(&pending, &[]);
    request.input = InputNeed::CapturedBytes;
    assert_eq!(
        ledger
            .evaluate(&request)
            .unwrap()
            .require_complete()
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
}

#[test]
fn fine_coverage_parameter_positions_projection_bodies_source_and_resource() {
    let data = setup("annotations/generated/bad-parameter-arity.dex", 1);
    let annotations =
        AnnotationFacts::build(data.definitions[0].clone(), AnnotationLimits::default()).unwrap();
    let selected = scope(&data);
    let view = FactView::unbuilt(&annotations.source().dex_occurrence_id)
        .with_annotations(&annotations)
        .with_code(&data.codes[0]);
    let ledger = CoverageLedger::new(selected.clone(), &[view]).unwrap();
    ledger
        .evaluate(&CoverageRequest::for_scope(
            &selected,
            &[FactLayer::Annotations],
        ))
        .unwrap()
        .require_complete()
        .unwrap();
    let r = ledger
        .evaluate(&CoverageRequest::for_scope(
            &selected,
            &[FactLayer::PrototypeParameterPositions],
        ))
        .unwrap();
    assert_eq!(r.facts, Completeness::Unknown);
    assert_eq!(
        r.require_complete().unwrap_err().code,
        ErrorCode::IncompleteFacts
    );
    let native = column(
        &selected,
        "methods",
        "param_descriptors",
        ColumnDomain::NativeAtoms,
    );
    ledger
        .evaluate(&native)
        .unwrap()
        .require_complete()
        .unwrap();
    let frozen = column(
        &selected,
        "methods",
        "param_descriptors",
        ColumnDomain::FrozenProjection,
    );
    let r = ledger.evaluate(&frozen).unwrap();
    assert_eq!(r.facts, Completeness::Unknown);
    assert!(
        r.issues
            .iter()
            .any(|issue| issue.column.as_deref() == Some("methods.param_descriptors"))
    );
    let mut missing = CoverageRequest::for_scope(&selected, &[]);
    missing
        .required_resource_members
        .push("unbuilt-member".into());
    assert_eq!(
        ledger.evaluate(&missing).unwrap().facts,
        Completeness::Unknown
    );
    assert_eq!(
        ledger
            .evaluate(&CoverageRequest::for_scope(
                &selected,
                &[FactLayer::SourcePositions]
            ))
            .unwrap()
            .facts,
        Completeness::Unknown
    );
    let unknown = column(
        &selected,
        "methods",
        "invented_column",
        ColumnDomain::NativeAtoms,
    );
    assert_eq!(
        ledger.evaluate(&unknown).unwrap().facts,
        Completeness::Unknown
    );
    let data = setup("references/generated/classic-035.dex", 1);
    let projected = CodeFacts::build_offsets(
        &data.snapshot,
        &data.inventories[0],
        0,
        &[],
        CodeLimits::default(),
    )
    .unwrap();
    let selected = scope(&data);
    let view = FactView::unbuilt(&data.definitions[0].metadata().source().dex_occurrence_id)
        .with_definitions(&data.definitions[0])
        .with_code(&projected);
    let ledger = CoverageLedger::new(selected.clone(), &[view]).unwrap();
    ledger
        .evaluate(&CoverageRequest::for_scope(
            &selected,
            &[FactLayer::CodeProjection],
        ))
        .unwrap()
        .require_complete()
        .unwrap();
    for layer in [FactLayer::AllPhysicalCode, FactLayer::AllMethodBodies] {
        assert_eq!(
            ledger
                .evaluate(&CoverageRequest::for_scope(&selected, &[layer]))
                .unwrap()
                .facts,
            Completeness::Partial
        );
    }
    let refs = ReferenceFacts::build(
        data.definitions[0].clone(),
        data.codes[0].clone(),
        ReferenceLimits::default(),
    )
    .unwrap();
    let raw = RawCodeEvidence::build(
        &data.definitions[0],
        &data.codes[0],
        FingerprintLimits::default(),
    )
    .unwrap();
    let view = FactView::unbuilt(&refs.source().dex_occurrence_id)
        .with_references(&refs)
        .with_raw_code(&raw);
    let mut ledger = CoverageLedger::new(selected.clone(), &[view]).unwrap();
    ledger
        .record_failure(
            &refs.source().dex_occurrence_id,
            FactLayer::Annotations,
            error(ErrorCode::InvalidInput, "unrelated-annotation"),
        )
        .unwrap();
    ledger
        .evaluate(&CoverageRequest::for_scope(
            &selected,
            &[
                FactLayer::References,
                FactLayer::AllMethodBodies,
                FactLayer::RawCode,
            ],
        ))
        .unwrap()
        .require_complete()
        .unwrap();
    assert_eq!(
        ledger
            .evaluate(&CoverageRequest::for_scope(
                &selected,
                &[FactLayer::Annotations]
            ))
            .unwrap()
            .require_complete()
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
}

#[test]
fn index_quota_deadline_and_unbuilt_failures_never_publish_ready_or_zero() {
    let data = setup("generated/strings-mutf8-035.dex", 1);
    let view = FactView::unbuilt(&data.definitions[0].metadata().source().dex_occurrence_id)
        .with_metadata(data.definitions[0].metadata());
    for (limits, expected) in [
        (
            IndexLimits {
                max_entries: 0,
                ..IndexLimits::default()
            },
            ErrorCode::QuotaExceeded,
        ),
        (
            IndexLimits {
                max_index_bytes: 0,
                ..IndexLimits::default()
            },
            ErrorCode::QuotaExceeded,
        ),
        (
            IndexLimits {
                build_duration: Some(Duration::ZERO),
                ..IndexLimits::default()
            },
            ErrorCode::DeadlineExceeded,
        ),
    ] {
        let index =
            SnapshotFactIndex::new(scope(&data), std::slice::from_ref(&view), limits).unwrap();
        assert_eq!(
            index
                .strings_indexed(&Utf16Predicate::Any)
                .unwrap_err()
                .code,
            expected
        );
        assert_eq!(
            index
                .strings_indexed(&Utf16Predicate::Equal(vec![]))
                .unwrap_err()
                .code,
            expected
        );
        assert_eq!(index.audits().unwrap()[0].phase, lazy::IndexPhase::Failed);
        assert_eq!(index.retry_string_index().unwrap_err().code, expected);
        assert_eq!(index.audits().unwrap()[0].attempts.len(), 2);
    }
    for limits in [
        IndexLimits {
            max_result_entries: 0,
            ..IndexLimits::default()
        },
        IndexLimits {
            max_result_bytes: 0,
            ..IndexLimits::default()
        },
    ] {
        let index =
            SnapshotFactIndex::new(scope(&data), std::slice::from_ref(&view), limits).unwrap();
        for result in [
            index.strings_indexed(&Utf16Predicate::Any),
            index.strings_scalar(&Utf16Predicate::Any),
            index.strings_raw_mutf8(&[]),
        ] {
            assert_eq!(result.unwrap_err().code, ErrorCode::QuotaExceeded);
        }
    }
    assert_eq!(column_specs().len(), 156);
    assert_eq!(
        column_specs()
            .iter()
            .filter(|c| !c.assembled_projection)
            .count(),
        69
    );
}

#[test]
fn exhaustive_candidate_probe_for_independent_code_unit_oracle() {
    let data = setup("generated/strings-mutf8-035.dex", 2);
    let views = data
        .definitions
        .iter()
        .map(|d| {
            FactView::unbuilt(&d.metadata().source().dex_occurrence_id).with_metadata(d.metadata())
        })
        .collect::<Vec<_>>();
    let index = SnapshotFactIndex::new(scope(&data), &views, IndexLimits::default()).unwrap();
    let alphabet = [0, 65, 0x4e2d, 0xd800, 0xd83d, 0xde00, 0xdc00, 0xffff];
    let mut patterns = vec![vec![]];
    for left in alphabet {
        patterns.push(vec![left]);
        for right in alphabet {
            patterns.push(vec![left, right]);
        }
    }
    let mut rows = Vec::new();
    for pattern in patterns {
        for (kind, predicate) in [
            ("equal", Utf16Predicate::Equal(pattern.clone())),
            ("prefix", Utf16Predicate::Prefix(pattern.clone())),
            ("contains", Utf16Predicate::Contains(pattern.clone())),
        ] {
            let indexed = index.strings_indexed(&predicate).unwrap();
            let scalar = index.strings_scalar(&predicate).unwrap();
            assert_eq!(indexed.entities, scalar.entities);
            rows.push(serde_json::json!({"kind":kind,"pattern":pattern,"locals":indexed.entities.iter().map(|e|e.local_index).collect::<Vec<_>>(),"candidates":indexed.candidate_count,"occurrences":indexed.entities.iter().map(|e|e.dex_occurrence_id.clone()).collect::<Vec<_>>()}));
        }
    }
    println!("INDEX_ORACLE_JSON={}",serde_json::to_string(&serde_json::json!({"rows":rows,"snapshot_id":index.scope().snapshot_id(),"scope_id":index.scope().scope_id(),"selected_dex_occurrences":index.scope().dexes().iter().map(|d|d.dex_occurrence_id.clone()).collect::<Vec<_>>(),"source_content_ids":data.definitions.iter().map(|d|d.metadata().source().content_id.clone()).collect::<Vec<_>>(),"columns":column_specs()})).unwrap());
}

#[test]
fn scalar_reference_scan_is_independent_of_lazy_candidate_failure() {
    let data = setup("references/generated/classic-035.dex", 1);
    let refs = ReferenceFacts::build(
        data.definitions[0].clone(),
        data.codes[0].clone(),
        ReferenceLimits::default(),
    )
    .unwrap();
    let view = FactView::unbuilt(&refs.source().dex_occurrence_id).with_references(&refs);
    let index = SnapshotFactIndex::new(
        scope(&data),
        &[view],
        IndexLimits {
            max_entries: 0,
            ..IndexLimits::default()
        },
    )
    .unwrap();
    let symbol = MethodSymbol {
        owner: "Lfixture/External;".into(),
        name: "external".into(),
        prototype: "()V".into(),
    };
    assert_eq!(
        index
            .references_to_method_symbol_scalar(&symbol)
            .unwrap()
            .sites
            .len(),
        3
    );
    assert_eq!(index.audits().unwrap()[2].phase, lazy::IndexPhase::Unbuilt);
    assert_eq!(
        index.references_to_method_symbol(&symbol).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        index
            .references_to_method_symbol_scalar(&symbol)
            .unwrap()
            .sites
            .len(),
        3
    );
    assert_eq!(index.audits().unwrap()[2].phase, lazy::IndexPhase::Failed);
    assert_eq!(
        index.retry_reference_symbol_index().unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
}
