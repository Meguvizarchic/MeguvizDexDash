use super::facts::{
    AnnotationCatalog, MemoryCatalog, NativeCatalog, OccurrenceFacts, ReferenceCatalog, Table,
};
use super::*;
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_facts::{
    EntityKind, EntityRef, MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    references::{ReferenceFacts, ReferenceLimits, TargetKind},
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema_version: String,
    snapshot_id: String,
    catalog_epoch: DecimalU64,
    ready_layers: BTreeSet<FactLayer>,
    tables: BTreeMap<String, Table>,
    cases: Vec<Case>,
}

fn native_references() -> (NativeCatalog, Vec<Arc<ReferenceFacts>>) {
    native_references_fixture("poly-custom-038.dex")
}

fn native_references_fixture(name: &str) -> (NativeCatalog, Vec<Arc<ReferenceFacts>>) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated")
        .join(name);
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut occurrences = Vec::new();
    let mut references = Vec::new();
    for input in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(input, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions =
            DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap();
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        references.push(Arc::new(
            ReferenceFacts::build(
                definitions.clone(),
                code.clone(),
                ReferenceLimits::default(),
            )
            .unwrap(),
        ));
        occurrences.push(OccurrenceFacts {
            metadata: Arc::new(metadata),
            definitions: Some(Arc::new(definitions)),
            code: Some(Arc::new(code)),
        });
    }
    (
        NativeCatalog::new(
            snapshot.manifest().snapshot_id.clone(),
            DecimalU64(7),
            occurrences,
        )
        .unwrap(),
        references,
    )
}

#[test]
fn typed_signature_catalog_keeps_owner_fragments_and_occurrences() {
    let input = InputSpec {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut metadata = Vec::new();
    let mut definitions = Vec::new();
    let mut codes = Vec::new();
    let mut annotations = Vec::new();
    let mut references = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let meta = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let defs = DefinitionFacts::build(meta.clone(), DefinitionLimits::default()).unwrap();
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        annotations.push(Arc::new(
            AnnotationFacts::build(defs.clone(), AnnotationLimits::default()).unwrap(),
        ));
        references.push(Arc::new(
            ReferenceFacts::build(defs.clone(), code.clone(), ReferenceLimits::default()).unwrap(),
        ));
        metadata.push(Arc::new(meta));
        definitions.push(Arc::new(defs));
        codes.push(Arc::new(code));
    }
    let make_native = || {
        NativeCatalog::new(
            snapshot.manifest().snapshot_id.clone(),
            DecimalU64(7),
            (0..2)
                .map(|i| OccurrenceFacts {
                    metadata: metadata[i].clone(),
                    definitions: Some(definitions[i].clone()),
                    code: Some(codes[i].clone()),
                })
                .collect(),
        )
        .unwrap()
    };
    assert_eq!(
        AnnotationCatalog::new(make_native(), annotations[..1].to_vec())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    assert_eq!(
        AnnotationCatalog::new(
            make_native(),
            vec![annotations[0].clone(), annotations[0].clone()]
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::InvalidArgument
    );
    let other = Snapshot::capture(
        &[InputSpec {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/annotations/generated/annotations-038.dex"),
            kind: InputKind::RawDex,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap();
    let inventory = ArchiveInventory::build(
        &other.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let other_meta = MetadataFacts::build(&other, &inventory, 0, StringLimits::default()).unwrap();
    let other_defs = DefinitionFacts::build(other_meta, DefinitionLimits::default()).unwrap();
    let other_ann =
        Arc::new(AnnotationFacts::build(other_defs, AnnotationLimits::default()).unwrap());
    assert!(
        AnnotationCatalog::new(make_native(), vec![annotations[0].clone(), other_ann]).is_err()
    );
    let reference_catalog = ReferenceCatalog::new(make_native(), references).unwrap();
    let catalog = AnnotationCatalog::with_references(
        reference_catalog,
        vec![annotations[1].clone(), annotations[0].clone()],
    )
    .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/expected.json"
    ))
    .unwrap();
    let scan = |name: &str| Node::Scan {
        relation: name.into(),
    };
    let headers = prepare(
        query(
            scan("annotation_signatures"),
            catalog.snapshot_id(),
            catalog.catalog_epoch(),
        ),
        &catalog,
    )
    .unwrap();
    let parts = prepare(
        query(
            scan("annotation_signature_fragments"),
            catalog.snapshot_id(),
            catalog.catalog_epoch(),
        ),
        &catalog,
    )
    .unwrap();
    assert!(headers.required_layers().contains(&FactLayer::Annotations));
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let header_rows = execute(
            &headers,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        let part_rows = execute(
            &parts,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        assert_eq!(header_rows.rows().len(), 8);
        let mut reconstructed = BTreeMap::<(String, u64), Vec<(u64, Vec<u16>)>>::new();
        for row in part_rows.rows() {
            let (
                Value::Utf16(source),
                Value::U64(DecimalU64(signature)),
                Value::Entity(owner),
                Value::U64(DecimalU64(part)),
                Value::Entity(string),
                Value::Utf16(units),
                Value::Bytes(raw),
            ) = (
                &row[0], &row[1], &row[3], &row[5], &row[6], &row[7], &row[8],
            )
            else {
                panic!("unexpected fragment");
            };
            let source = String::from_utf16(source).unwrap();
            assert_eq!(owner.dex_occurrence_id, source);
            assert_eq!(string.dex_occurrence_id, source);
            assert_eq!(owner.snapshot_id, string.snapshot_id);
            assert_eq!(string.kind, EntityKind::String);
            // This handwritten fixture's signature fragments are all ASCII.
            assert_eq!(
                String::from_utf16(units).unwrap().as_bytes(),
                raw.0.as_slice()
            );
            reconstructed
                .entry((source, *signature))
                .or_default()
                .push((*part, units.clone()));
        }
        let mut observed_sources = BTreeSet::new();
        for row in header_rows.rows() {
            let (
                Value::Utf16(source),
                Value::U64(DecimalU64(ordinal)),
                Value::Utf16(kind),
                Value::Entity(owner),
                Value::Utf16(units),
                Value::U64(DecimalU64(count)),
            ) = (&row[0], &row[1], &row[3], &row[4], &row[8], &row[9])
            else {
                panic!("unexpected signature");
            };
            let source = String::from_utf16(source).unwrap();
            let kind = String::from_utf16(kind).unwrap();
            assert_eq!(owner.dex_occurrence_id, source);
            assert_eq!(row[6], Value::Null);
            let key = match kind.as_str() {
                "class" => "class".to_owned(),
                "field" | "method" => format!("{kind}:{}", owner.local_index),
                _ => panic!("unexpected owner kind"),
            };
            assert_eq!(
                String::from_utf16(units).unwrap(),
                expected["signatures"][key].as_str().unwrap()
            );
            let fragments = reconstructed.get_mut(&(source.clone(), *ordinal)).unwrap();
            fragments.sort_by_key(|entry| entry.0);
            assert_eq!(fragments.len() as u64, *count);
            assert!(
                fragments
                    .iter()
                    .enumerate()
                    .all(|(i, entry)| entry.0 == i as u64)
            );
            let combined: Vec<u16> = fragments
                .iter()
                .flat_map(|entry| entry.1.iter().copied())
                .collect();
            assert_eq!(&combined, units);
            observed_sources.insert(source);
        }
        assert_eq!(observed_sources.len(), 2);
        let join = Node::EquiJoin {
            left: Box::new(scan("annotation_signatures")),
            right: Box::new(scan("methods")),
            left_keys: vec![4],
            right_keys: vec![0],
            kind: JoinKind::Inner,
        };
        let join_plan = prepare(
            query(join, catalog.snapshot_id(), catalog.catalog_epoch()),
            &catalog,
        )
        .unwrap();
        let joined = execute(
            &join_plan,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        assert_eq!(joined.rows().len(), 2);
        for row in joined.rows() {
            assert_eq!(row[4], row[10]);
        }
    }
    let base_only = AnnotationCatalog::new(make_native(), annotations).unwrap();
    assert_eq!(
        base_only
            .relation_schema("reference_sites")
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn typed_annotation_owner_sets_preserve_sources_and_shared_entries() {
    let input = InputSpec {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut occurrences = Vec::new();
    let mut annotations = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions =
            DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap();
        annotations.push(Arc::new(
            AnnotationFacts::build(definitions.clone(), AnnotationLimits::default()).unwrap(),
        ));
        occurrences.push(OccurrenceFacts {
            metadata: Arc::new(metadata),
            definitions: Some(Arc::new(definitions)),
            code: None,
        });
    }
    let native = NativeCatalog::new(
        snapshot.manifest().snapshot_id.clone(),
        DecimalU64(7),
        occurrences,
    )
    .unwrap();
    let catalog = AnnotationCatalog::new(native, annotations.clone()).unwrap();
    let scan = |relation: &str| Node::Scan {
        relation: relation.into(),
    };
    let plan = |root| {
        prepare(
            query(root, catalog.snapshot_id(), catalog.catalog_epoch()),
            &catalog,
        )
        .unwrap()
    };
    let sets = plan(scan("annotation_sets"));
    let entries = plan(scan("annotation_set_entries"));
    let owners = plan(scan("annotation_owners"));
    let joined = plan(Node::EquiJoin {
        left: Box::new(scan("annotation_owners")),
        right: Box::new(scan("annotation_set_entries")),
        left_keys: vec![0, 5],
        right_keys: vec![0, 1],
        kind: JoinKind::Inner,
    });
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/oracle-results.json"
    ))
    .unwrap();
    let expected: BTreeSet<_> = oracle["positive"]["annotation_set_entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["annotation_set_off"].as_u64().unwrap(),
                entry["ordinal"].as_u64().unwrap(),
                entry["annotation_off"].as_u64().unwrap(),
            )
        })
        .collect();
    let num = |value: &Value| match value {
        Value::U64(DecimalU64(n)) => *n,
        other => panic!("expected number: {other:?}"),
    };
    let text = |value: &Value| match value {
        Value::Utf16(units) => String::from_utf16(units).unwrap(),
        other => panic!("expected text: {other:?}"),
    };
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let get = |prepared: &PreparedQuery| {
            execute(
                prepared,
                &catalog,
                mode,
                &mut Control::new(ExecutionLimits::default()),
            )
            .unwrap()
        };
        let set_rows = get(&sets);
        let entry_rows = get(&entries);
        let owner_rows = get(&owners);
        let joined_rows = get(&joined);
        let mut by_source = BTreeMap::<String, BTreeSet<(u64, u64, u64)>>::new();
        for row in entry_rows.rows() {
            assert!(by_source.entry(text(&row[0])).or_default().insert((
                num(&row[1]),
                num(&row[2]),
                num(&row[3])
            )));
        }
        assert_eq!(by_source.len(), 2);
        assert!(by_source.values().all(|rows| rows == &expected));
        for row in set_rows.rows() {
            let source = text(&row[0]);
            let facts = annotations
                .iter()
                .find(|facts| facts.source().dex_occurrence_id == source)
                .unwrap();
            let offset = num(&row[1]) as usize;
            let count =
                u32::from_le_bytes(facts.bytes()[offset..offset + 4].try_into().unwrap()) as u64;
            assert_eq!(count, num(&row[2]));
            assert_eq!(num(&row[3]), 4 + count * 4);
        }
        assert_eq!(joined_rows.rows().len(), 14);
        let mut fields = BTreeMap::<String, BTreeSet<u32>>::new();
        let mut null_parameter_slots = 0;
        for row in owner_rows.rows() {
            let source = text(&row[0]);
            let (Value::Entity(class), Value::Entity(owner)) = (&row[1], &row[3]) else {
                panic!("expected source-bound owners")
            };
            assert_eq!(class.dex_occurrence_id, source);
            assert_eq!(owner.dex_occurrence_id, source);
            assert_eq!(class.snapshot_id, snapshot.manifest().snapshot_id);
            assert_eq!(owner.snapshot_id, class.snapshot_id);
            assert_eq!(
                text(&row[7]),
                if text(&row[2]) == "parameter" {
                    "complete"
                } else {
                    "not_applicable"
                }
            );
            if text(&row[2]) == "parameter" && row[5] == Value::Null {
                assert_eq!(num(&row[4]), 1);
                null_parameter_slots += 1;
            }
        }
        assert_eq!(null_parameter_slots, 4);
        for row in joined_rows.rows() {
            assert_eq!(row[0], row[8]);
            assert_eq!(row[5], row[9]);
            if text(&row[2]) == "field" && num(&row[11]) == 1120 {
                let Value::Entity(owner) = &row[3] else {
                    panic!("expected field")
                };
                fields
                    .entry(text(&row[0]))
                    .or_default()
                    .insert(owner.local_index);
            }
        }
        assert_eq!(fields.len(), 2);
        assert!(
            fields
                .values()
                .all(|indices| indices == &BTreeSet::from([0, 1]))
        );
    }
    let mut limits = ExecutionLimits::default();
    limits.max_output_rows = 1;
    assert_eq!(
        execute(
            &entries,
            &catalog,
            ExecutionMode::Streaming,
            &mut Control::new(limits)
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::QuotaExceeded
    );

    let short_input = InputSpec {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/bad-parameter-arity.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let short_snapshot = Snapshot::capture(&[short_input], CaptureLimits::default()).unwrap();
    let inventory = ArchiveInventory::build(
        &short_snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let metadata =
        MetadataFacts::build(&short_snapshot, &inventory, 0, StringLimits::default()).unwrap();
    let definitions =
        DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap();
    let short_annotations =
        AnnotationFacts::build(definitions.clone(), AnnotationLimits::default()).unwrap();
    let short_catalog = AnnotationCatalog::new(
        NativeCatalog::new(
            short_snapshot.manifest().snapshot_id.clone(),
            DecimalU64(0),
            vec![OccurrenceFacts {
                metadata: Arc::new(metadata),
                definitions: Some(Arc::new(definitions)),
                code: None,
            }],
        )
        .unwrap(),
        vec![Arc::new(short_annotations)],
    )
    .unwrap();
    let short_plan = prepare(
        query(
            scan("annotation_owners"),
            short_catalog.snapshot_id(),
            short_catalog.catalog_epoch(),
        ),
        &short_catalog,
    )
    .unwrap();
    let result = execute(
        &short_plan,
        &short_catalog,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
    .unwrap();
    let parameters: Vec<_> = result
        .rows()
        .iter()
        .filter(|row| text(&row[2]) == "parameter")
        .collect();
    assert_eq!(parameters.len(), 2);
    for row in parameters {
        assert_eq!(num(&row[4]), 0);
        assert_eq!(text(&row[7]), "unknown");
    }
}

#[test]
fn typed_annotation_physical_values_keep_identity_bits_and_string_links() {
    let input = InputSpec {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut occurrences = Vec::new();
    let mut annotations = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions =
            DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap();
        annotations.push(Arc::new(
            AnnotationFacts::build(definitions.clone(), AnnotationLimits::default()).unwrap(),
        ));
        occurrences.push(OccurrenceFacts {
            metadata: Arc::new(metadata),
            definitions: Some(Arc::new(definitions)),
            code: None,
        });
    }
    let native = NativeCatalog::new(
        snapshot.manifest().snapshot_id.clone(),
        DecimalU64(7),
        occurrences,
    )
    .unwrap();
    let catalog = AnnotationCatalog::new(native, annotations.clone()).unwrap();
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/annotations/oracle-results.json"
    ))
    .unwrap();
    let num = |value: &Value| match value {
        Value::U64(DecimalU64(value)) => Some(*value),
        Value::Null => None,
        other => panic!("unexpected number {other:?}"),
    };
    let text = |value: &Value| match value {
        Value::Utf16(value) => Some(String::from_utf16(value).unwrap()),
        Value::Null => None,
        other => panic!("unexpected text {other:?}"),
    };
    let canonical = |value: serde_json::Value| serde_json::to_string(&value).unwrap();
    let expected_items: BTreeSet<_> = oracle["positive"]["annotations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            canonical(serde_json::json!({
                "annotation_off":v["annotation_off"], "visibility":v["visibility"],
                "type_idx":v["type_idx"], "element_count":v["element_count"]
            }))
        })
        .collect();
    let expected_values: BTreeSet<_> = oracle["positive"]["annotation_elements"].as_array().unwrap().iter().map(|v| canonical(serde_json::json!({
        "annotation_off":v["annotation_off"], "depth":v["depth"], "ordinal":v["ordinal"],
        "name_idx":v["name_idx"], "value_kind":v["value_kind"], "value_index":v["value_index"],
        "value_i64":v["value_i64"], "value_off":v["value_off"], "value_end_off":v["value_end_off"]
    }))).collect();
    let scan = |relation: &str| Node::Scan {
        relation: relation.into(),
    };
    let plan = |root| {
        prepare(
            query(root, catalog.snapshot_id(), catalog.catalog_epoch()),
            &catalog,
        )
        .unwrap()
    };
    let items = plan(scan("annotation_items"));
    let values = plan(scan("annotation_values"));
    let joined = plan(Node::EquiJoin {
        left: Box::new(scan("annotation_values")),
        right: Box::new(scan("strings")),
        left_keys: vec![9],
        right_keys: vec![0],
        kind: JoinKind::Inner,
    });
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let item_rows = execute(
            &items,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        let value_rows = execute(
            &values,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        let join_rows = execute(
            &joined,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        let mut seen_items = BTreeMap::<String, BTreeSet<String>>::new();
        let mut seen_values = BTreeMap::<String, BTreeSet<String>>::new();
        let mut string_count = 0;
        let mut float_bits = BTreeSet::new();
        let mut null_count = 0;
        for row in item_rows.rows() {
            let source = text(&row[0]).unwrap();
            let Value::Entity(ty) = &row[3] else {
                panic!("missing type entity")
            };
            assert_eq!(ty.dex_occurrence_id, source);
            assert_eq!(ty.snapshot_id, snapshot.manifest().snapshot_id);
            assert_eq!(ty.kind, EntityKind::Type);
            let key = canonical(
                serde_json::json!({"annotation_off":num(&row[1]), "visibility":num(&row[2]),
                "type_idx":ty.local_index, "element_count":num(&row[4])}),
            );
            assert!(seen_items.entry(source).or_default().insert(key));
        }
        for row in value_rows.rows() {
            let source = text(&row[0]).unwrap();
            let facts = annotations
                .iter()
                .find(|a| a.source().dex_occurrence_id == source)
                .unwrap();
            let start = num(&row[13]).unwrap() as usize;
            let length = num(&row[14]).unwrap() as usize;
            let Value::Bytes(raw) = &row[15] else {
                panic!("missing raw scalar")
            };
            assert!(start + length <= facts.bytes().len());
            assert!(1 + raw.0.len() <= length);
            assert_eq!(
                raw.0.as_slice(),
                &facts.bytes()[start + 1..start + 1 + raw.0.len()]
            );
            let kind = text(&row[6]).unwrap();
            if kind == "string" {
                let Value::Entity(entity) = &row[9] else {
                    panic!("missing string reference")
                };
                assert_eq!(entity.dex_occurrence_id, source);
                assert_eq!(entity.snapshot_id, snapshot.manifest().snapshot_id);
                assert_eq!(Some(u64::from(entity.local_index)), num(&row[8]));
                string_count += 1;
            } else {
                assert_eq!(row[9], Value::Null);
            }
            if kind == "null" {
                assert_eq!(row[10], Value::Null);
                assert!(raw.0.is_empty());
                null_count += 1;
            }
            if let Some(bits) = num(&row[11]) {
                float_bits.insert(bits);
            }
            if let Some(annotation) = num(&row[2]) {
                let key = canonical(
                    serde_json::json!({"annotation_off":annotation, "depth":num(&row[3]),
                    "ordinal":num(&row[4]), "name_idx":num(&row[5]), "value_kind":kind,
                    "value_index":num(&row[8]), "value_i64":text(&row[10]), "value_off":start,
                    "value_end_off":start + length}),
                );
                assert!(seen_values.entry(source).or_default().insert(key));
            }
        }
        assert_eq!(seen_items.len(), 2);
        assert_eq!(seen_values.len(), 2);
        assert!(seen_items.values().all(|v| v == &expected_items));
        assert!(seen_values.values().all(|v| v == &expected_values));
        assert_eq!(join_rows.rows().len(), string_count);
        for row in join_rows.rows() {
            assert_eq!(row[9], row[17]);
        }
        assert!(null_count >= 2);
        assert!(float_bits.contains(&0x7fc01234));
        assert!(float_bits.contains(&0x7ff8000000001234));
    }
    let mut limits = ExecutionLimits::default();
    limits.max_output_rows = 1;
    assert_eq!(
        execute(
            &values,
            &catalog,
            ExecutionMode::Streaming,
            &mut Control::new(limits)
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::QuotaExceeded
    );
}

#[test]
fn typed_string_reference_query_preserves_raw_text_sources_and_sites() {
    let (native, references) = native_references_fixture("nonscalar-string-035.dex");
    let catalog = ReferenceCatalog::new(native, references.clone()).unwrap();
    let plan = prepare(catalog.string_reference_query(&[0xd800]).unwrap(), &catalog).unwrap();
    assert!(plan.required_layers().contains(&FactLayer::References));
    // Retained independent fixture has two encoded references per occurrence,
    // at PC 0 and 2, to string index 13 containing the isolated surrogate.
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let output = execute(
            &plan,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        assert_eq!(output.rows().len(), 4);
        let mut by_source = BTreeMap::<String, Vec<u64>>::new();
        for row in output.rows() {
            let (Value::Entity(caller), Value::Entity(string)) = (&row[2], &row[7]) else {
                panic!("expected source-bound entities");
            };
            assert_eq!(caller.kind, EntityKind::MethodDefinition);
            assert_eq!(caller.local_index, 0);
            assert_eq!(string.kind, EntityKind::String);
            assert_eq!(string.local_index, 13);
            assert_eq!(caller.snapshot_id, string.snapshot_id);
            assert_eq!(caller.dex_occurrence_id, string.dex_occurrence_id);
            assert_eq!(row[0], Value::text(&caller.dex_occurrence_id));
            assert_eq!(row[9], Value::Utf16(vec![0xd800]));
            assert_eq!(row[10], Value::Bytes(Bytes(vec![0xed, 0xa0, 0x80])));
            let Value::U64(DecimalU64(pc)) = row[3] else {
                panic!("expected code-unit PC");
            };
            by_source
                .entry(caller.dex_occurrence_id.clone())
                .or_default()
                .push(pc);
        }
        assert_eq!(by_source.len(), 2);
        for pcs in by_source.values_mut() {
            pcs.sort_unstable();
            assert_eq!(pcs, &[0, 2]);
        }
        let missing =
            prepare(catalog.string_reference_query(&[0xfffd]).unwrap(), &catalog).unwrap();
        assert!(
            execute(
                &missing,
                &catalog,
                mode,
                &mut Control::new(ExecutionLimits::default())
            )
            .unwrap()
            .rows()
            .is_empty()
        );
        let limits = ExecutionLimits {
            max_output_rows: 1,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            execute(&plan, &catalog, mode, &mut Control::new(limits))
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    assert_eq!(
        catalog
            .string_reference_query(&vec![0; 1_000_001])
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let (mut incomplete, references) = native_references_fixture("nonscalar-string-035.dex");
    incomplete.occurrences[0].code = None;
    let incomplete = ReferenceCatalog::new(incomplete, references).unwrap();
    assert_eq!(
        prepare(
            incomplete.string_reference_query(&[0xd800]).unwrap(),
            &incomplete
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn typed_method_call_query_preserves_oracle_sites_and_occurrences() {
    let (native, references) = native_references();
    let catalog = ReferenceCatalog::new(native, references).unwrap();
    let descriptor = "Lfixture/External;->external()V";
    let units = descriptor.encode_utf16().collect::<Vec<_>>();
    let plan = prepare(catalog.method_call_query(&units).unwrap(), &catalog).unwrap();
    assert!(plan.required_layers().contains(&FactLayer::References));
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let result = execute(
            &plan,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        assert_eq!(result.rows().len(), 6);
        let mut by_source = BTreeMap::<String, Vec<u64>>::new();
        for row in result.rows() {
            let (
                Value::Entity(caller),
                Value::Entity(callee),
                Value::Entity(owner),
                Value::Entity(proto),
            ) = (&row[2], &row[8], &row[9], &row[11])
            else {
                panic!("expected source-bound method identities");
            };
            assert_eq!(caller.kind, EntityKind::MethodDefinition);
            assert_eq!(callee.kind, EntityKind::MethodReference);
            assert_eq!(callee.local_index, 4);
            assert_eq!(owner.kind, EntityKind::Type);
            assert_eq!(proto.kind, EntityKind::Prototype);
            for entity in [callee, owner, proto] {
                assert_eq!(caller.snapshot_id, entity.snapshot_id);
                assert_eq!(caller.dex_occurrence_id, entity.dex_occurrence_id);
            }
            assert_eq!(row[0], Value::text(&caller.dex_occurrence_id));
            assert_eq!(row[10], Value::text("external"));
            assert_eq!(row[12], Value::Utf16(units.clone()));
            assert!(matches!(&row[7], Value::Utf16(_)));
            let Value::U64(DecimalU64(pc)) = row[3] else {
                panic!("missing PC")
            };
            by_source
                .entry(caller.dex_occurrence_id.clone())
                .or_default()
                .push(pc);
        }
        assert_eq!(by_source.len(), 2);
        for pcs in by_source.values_mut() {
            pcs.sort_unstable();
            // Independent saved poly-custom fixture method-site oracle.
            assert_eq!(pcs, &[12, 15, 18]);
        }
        let missing = prepare(
            catalog
                .method_call_query(&"Lmissing;->x()V".encode_utf16().collect::<Vec<_>>())
                .unwrap(),
            &catalog,
        )
        .unwrap();
        assert!(
            execute(
                &missing,
                &catalog,
                mode,
                &mut Control::new(ExecutionLimits::default())
            )
            .unwrap()
            .rows()
            .is_empty()
        );
        let limits = ExecutionLimits {
            max_output_rows: 1,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            execute(&plan, &catalog, mode, &mut Control::new(limits))
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    assert_eq!(
        catalog
            .method_call_query(&vec![0; 1_000_001])
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let (mut incomplete, references) = native_references();
    incomplete.occurrences[0].code = None;
    let incomplete = ReferenceCatalog::new(incomplete, references).unwrap();
    assert_eq!(
        prepare(incomplete.method_call_query(&units).unwrap(), &incomplete)
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn typed_type_reference_query_preserves_oracle_sites_and_occurrences() {
    let (native, references) = native_references_fixture("type-names-035.dex");
    let catalog = ReferenceCatalog::new(native, references).unwrap();
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/references/oracle-results.json"
    ))
    .unwrap();
    let record = oracle["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| {
            record["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("/type-names-035.dex"))
        })
        .unwrap();
    for (descriptor, type_index) in [("Ljava/lang/String;", 4u32), ("I", 0), ("[I", 6)] {
        let units = descriptor.encode_utf16().collect::<Vec<_>>();
        let mut expected = record["sites"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|site| site["kind"] == "type" && site["index"] == type_index)
            .map(|site| {
                (
                    site["caller_method_idx"].as_u64().unwrap(),
                    site["pc"].as_u64().unwrap(),
                    site["operand_ordinal"].as_u64().unwrap(),
                    site["opcode"].as_u64().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        expected.sort_unstable();
        assert!(!expected.is_empty());
        let plan = prepare(catalog.type_reference_query(&units).unwrap(), &catalog).unwrap();
        assert!(plan.required_layers().contains(&FactLayer::References));
        for mode in [
            ExecutionMode::Streaming,
            ExecutionMode::MaterializedReference,
        ] {
            let output = execute(
                &plan,
                &catalog,
                mode,
                &mut Control::new(ExecutionLimits::default()),
            )
            .unwrap();
            assert_eq!(output.rows().len(), expected.len() * 2);
            let mut by_source = BTreeMap::<String, Vec<(u64, u64, u64, u64)>>::new();
            for row in output.rows() {
                let (Value::Entity(caller), Value::Entity(ty), Value::Entity(text)) =
                    (&row[2], &row[7], &row[9])
                else {
                    panic!("expected source-bound entities")
                };
                assert_eq!(caller.kind, EntityKind::MethodDefinition);
                assert_eq!(ty.kind, EntityKind::Type);
                assert_eq!(ty.local_index, type_index);
                assert_eq!(text.kind, EntityKind::String);
                for entity in [ty, text] {
                    assert_eq!(entity.snapshot_id, caller.snapshot_id);
                    assert_eq!(entity.dex_occurrence_id, caller.dex_occurrence_id);
                }
                assert_eq!(row[0], Value::text(&caller.dex_occurrence_id));
                assert_eq!(row[8], Value::Utf16(units.clone()));
                let (
                    Value::U64(DecimalU64(pc)),
                    Value::U64(DecimalU64(operand)),
                    Value::U64(DecimalU64(opcode)),
                ) = (&row[3], &row[5], &row[6])
                else {
                    panic!("expected encoded site coordinates")
                };
                by_source
                    .entry(caller.dex_occurrence_id.clone())
                    .or_default()
                    .push((u64::from(caller.local_index), *pc, *operand, *opcode));
            }
            assert_eq!(by_source.len(), 2);
            for sites in by_source.values_mut() {
                sites.sort_unstable();
                assert_eq!(sites, &expected);
            }
            let limits = ExecutionLimits {
                max_output_rows: 0,
                ..ExecutionLimits::default()
            };
            assert_eq!(
                execute(&plan, &catalog, mode, &mut Control::new(limits))
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
    }
    let missing = prepare(catalog.type_reference_query(&[0xd800]).unwrap(), &catalog).unwrap();
    assert!(
        execute(
            &missing,
            &catalog,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap()
        .rows()
        .is_empty()
    );
    assert_eq!(
        catalog
            .type_reference_query(&vec![0; 1_000_001])
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let (mut incomplete, references) = native_references_fixture("type-names-035.dex");
    incomplete.occurrences[0].code = None;
    let incomplete = ReferenceCatalog::new(incomplete, references).unwrap();
    let units = "Ljava/lang/String;".encode_utf16().collect::<Vec<_>>();
    assert_eq!(
        prepare(
            incomplete.type_reference_query(&units).unwrap(),
            &incomplete
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn typed_field_reference_query_preserves_oracle_sites_and_occurrences() {
    let (native, references) = native_references_fixture("classic-035.dex");
    let catalog = ReferenceCatalog::new(native, references).unwrap();
    let descriptor = "Lfixture/External;->shared:Ljava/lang/String;";
    let units = descriptor.encode_utf16().collect::<Vec<_>>();
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/references/oracle-results.json"
    ))
    .unwrap();
    let record = oracle["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| {
            record["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("/classic-035.dex"))
        })
        .unwrap();
    let mut oracle_sites = record["sites"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|site| site["kind"] == "field" && site["index"] == 0)
        .map(|site| {
            (
                site["pc"].as_u64().unwrap(),
                site["opcode"].as_u64().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    oracle_sites.sort_unstable();
    assert_eq!(oracle_sites.len(), 2);
    let plan = prepare(catalog.field_reference_query(&units).unwrap(), &catalog).unwrap();
    assert!(plan.required_layers().contains(&FactLayer::References));
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let result = execute(
            &plan,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        assert_eq!(result.rows().len(), 4);
        let mut by_source = BTreeMap::<String, Vec<(u64, u64)>>::new();
        for row in result.rows() {
            let (
                Value::Entity(caller),
                Value::Entity(field),
                Value::Entity(owner),
                Value::Entity(ty),
            ) = (&row[2], &row[7], &row[8], &row[10])
            else {
                panic!("expected source-bound field identities");
            };
            assert_eq!(caller.kind, EntityKind::MethodDefinition);
            assert_eq!(caller.local_index, 0);
            assert_eq!(field.kind, EntityKind::FieldReference);
            assert_eq!(field.local_index, 0);
            assert_eq!(owner.kind, EntityKind::Type);
            assert_eq!(ty.kind, EntityKind::Type);
            for entity in [field, owner, ty] {
                assert_eq!(caller.snapshot_id, entity.snapshot_id);
                assert_eq!(caller.dex_occurrence_id, entity.dex_occurrence_id);
            }
            assert_eq!(row[0], Value::text(&caller.dex_occurrence_id));
            assert_eq!(row[5], Value::U64(DecimalU64(0)));
            assert_eq!(row[9], Value::text("shared"));
            assert_eq!(row[11], Value::Utf16(units.clone()));
            let (Value::U64(DecimalU64(pc)), Value::U64(DecimalU64(opcode))) = (&row[3], &row[6])
            else {
                panic!("expected encoded PC and opcode");
            };
            by_source
                .entry(caller.dex_occurrence_id.clone())
                .or_default()
                .push((*pc, *opcode));
        }
        assert_eq!(by_source.len(), 2);
        for pairs in by_source.values_mut() {
            pairs.sort_unstable();
            assert_eq!(pairs.as_slice(), oracle_sites.as_slice());
        }
        let missing = prepare(
            catalog
                .field_reference_query(&"Lmissing;->x:I".encode_utf16().collect::<Vec<_>>())
                .unwrap(),
            &catalog,
        )
        .unwrap();
        assert!(
            execute(
                &missing,
                &catalog,
                mode,
                &mut Control::new(ExecutionLimits::default()),
            )
            .unwrap()
            .rows()
            .is_empty()
        );
        let limits = ExecutionLimits {
            max_output_rows: 1,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            execute(&plan, &catalog, mode, &mut Control::new(limits))
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    assert_eq!(
        catalog
            .field_reference_query(&vec![0; 1_000_001])
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let (mut incomplete, references) = native_references_fixture("classic-035.dex");
    incomplete.occurrences[0].code = None;
    let incomplete = ReferenceCatalog::new(incomplete, references).unwrap();
    assert_eq!(
        prepare(
            incomplete.field_reference_query(&units).unwrap(),
            &incomplete
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn typed_reference_catalog_preserves_sites_and_joins_with_definitions() {
    let (native, mut references) = native_references();
    // A caller may provide facts in another order; output remains catalog ordered.
    references.reverse();
    let catalog = ReferenceCatalog::new(native, references.clone()).unwrap();
    let scan = Node::Scan {
        relation: "reference_sites".into(),
    };
    let plan = prepare(
        query(scan, catalog.snapshot_id(), catalog.catalog_epoch()),
        &catalog,
    )
    .unwrap();
    assert!(plan.required_layers().contains(&FactLayer::References));
    let expected_count: usize = references.iter().map(|facts| facts.sites().len()).sum();
    assert!(expected_count > 0);
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let result = execute(
            &plan,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        assert_eq!(result.rows().len(), expected_count);
        let first = references.last().unwrap();
        assert_eq!(
            result.rows()[0][0],
            Value::text(&first.source().dex_occurrence_id)
        );
        for facts in &references {
            for site in facts.sites() {
                let matching: Vec<_> = result
                    .rows()
                    .iter()
                    .filter(|row| {
                        row[0] == Value::text(&facts.source().dex_occurrence_id)
                            && row[1] == Value::U64(DecimalU64(u64::from(site.site_ordinal)))
                    })
                    .collect();
                assert_eq!(matching.len(), 1);
                let row = matching[0];
                assert_eq!(row[3], Value::U64(DecimalU64(u64::from(site.code_unit_pc))));
                assert_eq!(
                    row[5],
                    Value::U64(DecimalU64(u64::from(site.operand_ordinal)))
                );
                if matches!(
                    site.target_kind,
                    TargetKind::CallSite | TargetKind::MethodHandle
                ) {
                    assert_eq!(row[8], Value::Null);
                } else if site.target_kind == TargetKind::Method {
                    assert_eq!(
                        row[8],
                        Value::Entity(EntityRef {
                            snapshot_id: facts.source().snapshot_id.clone(),
                            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
                            kind: EntityKind::MethodReference,
                            local_index: site.target_local_index,
                        })
                    );
                }
            }
        }
        let limited = ExecutionLimits {
            max_output_rows: 1,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            execute(&plan, &catalog, mode, &mut Control::new(limited))
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let join = Node::EquiJoin {
        left: Box::new(Node::Scan {
            relation: "reference_sites".into(),
        }),
        right: Box::new(Node::Scan {
            relation: "method_definitions".into(),
        }),
        left_keys: vec![2],
        right_keys: vec![0],
        kind: JoinKind::Inner,
    };
    let plan = prepare(
        query(join, catalog.snapshot_id(), catalog.catalog_epoch()),
        &catalog,
    )
    .unwrap();
    let joined = execute(
        &plan,
        &catalog,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
    .unwrap();
    assert_eq!(joined.rows().len(), expected_count);
    for row in joined.rows() {
        assert_eq!(row[2], row[11]);
        assert!(matches!(&row[2], Value::Entity(entity)
            if entity.kind == EntityKind::MethodDefinition
            && row[0] == Value::text(&entity.dex_occurrence_id)
            && entity.snapshot_id == catalog.snapshot_id()));
    }
    let target_join = Node::EquiJoin {
        left: Box::new(Node::Scan {
            relation: "reference_sites".into(),
        }),
        right: Box::new(Node::Scan {
            relation: "methods".into(),
        }),
        left_keys: vec![8],
        right_keys: vec![0],
        kind: JoinKind::Inner,
    };
    let target_plan = prepare(
        query(target_join, catalog.snapshot_id(), catalog.catalog_epoch()),
        &catalog,
    )
    .unwrap();
    let target_expected = references
        .iter()
        .flat_map(|facts| facts.sites())
        .filter(|site| site.target_kind == TargetKind::Method)
        .count();
    assert!(target_expected > 0);
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let result = execute(
            &target_plan,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        assert_eq!(result.rows().len(), target_expected);
        for row in result.rows() {
            assert_eq!(row[8], row[11]);
            assert!(matches!(&row[8], Value::Entity(entity)
                if entity.kind == EntityKind::MethodReference
                && row[0] == Value::text(&entity.dex_occurrence_id)
                && entity.snapshot_id == catalog.snapshot_id()));
        }
    }
    let (missing_native, _) = native_references();
    assert_eq!(
        ReferenceCatalog::new(missing_native, vec![])
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let (duplicate_native, duplicate_refs) = native_references();
    assert_eq!(
        ReferenceCatalog::new(
            duplicate_native,
            vec![duplicate_refs[0].clone(), duplicate_refs[0].clone()]
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::InvalidArgument
    );
    let (foreign_native, _) = native_references();
    assert_eq!(
        ReferenceCatalog::new(foreign_native, references)
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    query: QueryIr,
    expected_rows: Option<Vec<Row>>,
    expected_error: Option<ExpectedError>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedError {
    code: ErrorCode,
    reason: String,
    stage: String,
}
fn fixture() -> Fixture {
    serde_json::from_str(include_str!("../../../../tests/fixtures/query/cases.json")).unwrap()
}
fn source(f: Fixture) -> MemoryCatalog {
    MemoryCatalog::new(f.snapshot_id, f.catalog_epoch, f.tables, f.ready_layers).unwrap()
}
fn check_error(error: MddError, expected: &ExpectedError, id: &str) {
    assert_eq!(error.code, expected.code, "{id}: {error:?}");
    let field = if error.code == ErrorCode::IncompleteFacts {
        "required_layer"
    } else {
        "reason"
    };
    assert_eq!(
        error.details.get(field).and_then(serde_json::Value::as_str),
        Some(expected.reason.as_str()),
        "{id}: {error:?}"
    );
}

#[test]
fn independent_small_table_oracle_both_execution_paths() {
    let data = fixture();
    assert_eq!(data.schema_version, "mdd.hand-query-cases.v1");
    let catalog = source(fixture());
    let mut passed = 0;
    for case in data.cases {
        let prepared = prepare(case.query.clone(), &catalog);
        if let Some(expected) = &case.expected_error
            && expected.stage == "prepare"
        {
            match prepared {
                Err(error) => check_error(error, expected, &case.id),
                Ok(_) => panic!("{} incorrectly prepared", case.id),
            };
            passed += 1;
            continue;
        }
        let prepared = prepared.unwrap_or_else(|error| panic!("{}: {error:?}", case.id));
        for mode in [
            ExecutionMode::Streaming,
            ExecutionMode::MaterializedReference,
        ] {
            let result = execute(
                &prepared,
                &catalog,
                mode,
                &mut Control::new(ExecutionLimits::default()),
            );
            if let Some(expected) = &case.expected_error {
                match result {
                    Err(error) => check_error(error, expected, &case.id),
                    Ok(_) => panic!("{} incorrectly executed", case.id),
                }
            } else {
                let result = result.unwrap_or_else(|e| panic!("{}: {e:?}", case.id));
                assert_eq!(
                    result.rows(),
                    case.expected_rows.as_ref().unwrap(),
                    "{} {mode:?}",
                    case.id
                );
                assert!(result.execution_complete());
                println!(
                    "{}",
                    serde_json::json!({"case":case.id,"actual":result,"plan":prepared.nodes()})
                );
            }
        }
        passed += 1;
    }
    assert_eq!(passed, 36);
}

fn query(node: Node, snapshot: &str, epoch: DecimalU64) -> QueryIr {
    QueryIr {
        schema_version: IR_VERSION.into(),
        text_semantics: TEXT_VERSION.into(),
        snapshot_id: snapshot.into(),
        catalog_epoch: epoch,
        require_stable_order: false,
        root: node,
    }
}
fn col(name: &str, ty: DataType, nullable: bool) -> Column {
    Column {
        id: name.into(),
        display_name: name.into(),
        data_type: ty,
        nullable,
    }
}
#[test]
fn prepared_source_generation_cancel_and_budget_are_real_failures() {
    let a = source(fixture());
    let b = source(fixture());
    let q = query(
        Node::Scan {
            relation: "left".into(),
        },
        a.snapshot_id(),
        a.catalog_epoch(),
    );
    let plan = prepare(q.clone(), &a).unwrap();
    let error = execute(
        &plan,
        &b,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
    .err()
    .unwrap();
    assert_eq!(
        error.details["reason"],
        "PREPARED_SOURCE_OR_GENERATION_CHANGED"
    );
    let mut wrong = q;
    wrong.catalog_epoch = DecimalU64(0);
    assert!(prepare(wrong, &a).is_err());
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let mut control = Control::new(ExecutionLimits::default()).with_hook(|point| {
            if point.phase == "scan_row" {
                Err(MddError::new(
                    ErrorCode::Cancelled,
                    "query.test",
                    "real checkpoint cancellation",
                ))
            } else {
                Ok(())
            }
        });
        assert_eq!(
            execute(&plan, &a, mode, &mut control).err().unwrap().code,
            ErrorCode::Cancelled
        );
        for limits in [
            ExecutionLimits {
                max_steps: 0,
                ..ExecutionLimits::default()
            },
            ExecutionLimits {
                max_output_rows: 0,
                ..ExecutionLimits::default()
            },
            ExecutionLimits {
                max_buffered_bytes: 0,
                ..ExecutionLimits::default()
            },
            ExecutionLimits {
                max_cell_bytes: 0,
                ..ExecutionLimits::default()
            },
        ] {
            assert_eq!(
                execute(&plan, &a, mode, &mut Control::new(limits))
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
    }
}

fn native(filename: &str, with_code: bool) -> NativeCatalog {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated")
        .join(filename);
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut occurrences = Vec::new();
    for input in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(input, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = Arc::new(
            DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap(),
        );
        let code = with_code.then(|| {
            Arc::new(
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                    .unwrap(),
            )
        });
        occurrences.push(OccurrenceFacts {
            metadata: Arc::new(metadata),
            definitions: Some(definitions),
            code,
        });
    }
    NativeCatalog::new(
        snapshot.manifest().snapshot_id.clone(),
        DecimalU64(u64::MAX),
        occurrences,
    )
    .unwrap()
}
fn read_literal(
    catalog: &NativeCatalog,
    entity: EntityRef,
    offset: u64,
    length: Option<u64>,
) -> MddResult<QueryOutput> {
    let node = Node::Project {
        input: Box::new(Node::Limit {
            input: Box::new(Node::Scan {
                relation: "method_definitions".into(),
            }),
            offset: DecimalU64(0),
            count: DecimalU64(1),
        }),
        columns: vec![Projection {
            column: col("body", DataType::Bytes, true),
            expression: Expr::ReadCodeBytes {
                entity: Box::new(Expr::Literal {
                    value: Value::Entity(entity),
                }),
                byte_offset: DecimalU64(offset),
                byte_length: length.map(DecimalU64),
            },
        }],
    };
    let plan = prepare(
        query(node, catalog.snapshot_id(), catalog.catalog_epoch()),
        catalog,
    )?;
    assert!(plan.required_layers().contains(&FactLayer::CodeLayout));
    assert!(plan.required_layers().contains(&FactLayer::Structure));
    execute(
        &plan,
        catalog,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
}
#[test]
fn native_occurrence_and_pool_join_preserves_source_multiplicity() {
    let catalog = native("definitions-038.dex", false);
    let metadata_only = NativeCatalog::new(
        catalog.snapshot_id().into(),
        catalog.catalog_epoch(),
        catalog
            .occurrences
            .iter()
            .map(|o| OccurrenceFacts {
                metadata: o.metadata.clone(),
                definitions: None,
                code: None,
            })
            .collect(),
    )
    .unwrap();
    let node = Node::EquiJoin {
        left: Box::new(Node::Scan {
            relation: "string_pools".into(),
        }),
        right: Box::new(Node::Scan {
            relation: "dex_occurrences".into(),
        }),
        left_keys: vec![0],
        right_keys: vec![1],
        kind: JoinKind::Inner,
    };
    let plan = prepare(
        query(
            node,
            metadata_only.snapshot_id(),
            metadata_only.catalog_epoch(),
        ),
        &metadata_only,
    )
    .unwrap();
    assert_eq!(
        plan.required_layers(),
        &BTreeSet::from([FactLayer::Metadata])
    );
    let expected: Vec<Row> = metadata_only
        .occurrences
        .iter()
        .map(|occurrence| {
            let source = occurrence.metadata.source();
            let pool = occurrence.metadata.string_pool();
            vec![
                Value::text(&pool.dex_occurrence_id),
                Value::text(&pool.string_pool_id),
                Value::text(&pool.physical_dex_id),
                Value::text(&pool.content_id),
                Value::U64(pool.string_ids_byte_offset),
                Value::U64(DecimalU64(pool.string_count.into())),
                Value::text(&source.snapshot_id),
                Value::text(&source.dex_occurrence_id),
                Value::text(&source.physical_dex_id),
                Value::text(&source.member_id),
                Value::text(&source.source_occurrence_id),
                Value::text(&source.content_id),
            ]
        })
        .collect();
    assert_eq!(expected.len(), 2);
    assert_ne!(expected[0][0], expected[1][0]);
    assert_eq!(expected[0][1], expected[1][1]);
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let result = execute(
            &plan,
            &metadata_only,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        let mut actual = result.rows().to_vec();
        let mut wanted = expected.clone();
        actual.sort();
        wanted.sort();
        assert_eq!(actual, wanted);
        let limited = ExecutionLimits {
            max_output_rows: 1,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            execute(&plan, &metadata_only, mode, &mut Control::new(limited))
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
}
#[test]
fn native_class_definition_details_preserve_ranges_and_occurrences() {
    let catalog = native("definitions-038.dex", false);
    let plan = prepare(
        query(
            Node::Scan {
                relation: "class_definition_details".into(),
            },
            catalog.snapshot_id(),
            catalog.catalog_epoch(),
        ),
        &catalog,
    )
    .unwrap();
    assert_eq!(
        plan.required_layers(),
        &BTreeSet::from([FactLayer::Structure])
    );
    let mut expected = Vec::new();
    for occurrence in &catalog.occurrences {
        let source = occurrence.metadata.source();
        for class in &occurrence
            .definitions
            .as_ref()
            .unwrap()
            .definitions()
            .classes
        {
            let class_data = class.class_data_range.as_ref();
            let id = EntityRef {
                snapshot_id: source.snapshot_id.clone(),
                dex_occurrence_id: source.dex_occurrence_id.clone(),
                kind: EntityKind::ClassDefinition,
                local_index: class.class_def_idx,
            };
            expected.push(vec![
                Value::Entity(id),
                Value::U64(DecimalU64(class.access_flags.into())),
                class
                    .annotations_byte_offset
                    .map_or(Value::Null, Value::U64),
                class
                    .static_values_byte_offset
                    .map_or(Value::Null, Value::U64),
                class_data.map_or(Value::Null, |r| Value::U64(r.byte_offset)),
                class_data.map_or(Value::Null, |r| Value::U64(r.byte_length)),
                Value::U64(DecimalU64(class.static_fields_count.into())),
                Value::U64(DecimalU64(class.instance_fields_count.into())),
                Value::U64(DecimalU64(class.direct_methods_count.into())),
                Value::U64(DecimalU64(class.virtual_methods_count.into())),
                Value::U64(class.encoded_range.byte_offset),
                Value::U64(class.encoded_range.byte_length),
            ]);
        }
    }
    assert!(!expected.is_empty());
    assert!(expected.iter().any(|row| row[2] == Value::Null));
    assert!(expected.iter().any(|row| row[3] == Value::Null));
    expected.sort();
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let mut actual = execute(
            &plan,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap()
        .rows()
        .to_vec();
        actual.sort();
        assert_eq!(actual, expected);
        let limited = ExecutionLimits {
            max_output_rows: 0,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            execute(&plan, &catalog, mode, &mut Control::new(limited))
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let nullable = native("nullable-root-class.dex", false);
    let nullable_plan = prepare(
        query(
            Node::Scan {
                relation: "class_definition_details".into(),
            },
            nullable.snapshot_id(),
            nullable.catalog_epoch(),
        ),
        &nullable,
    )
    .unwrap();
    let null_rows = execute(
        &nullable_plan,
        &nullable,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
    .unwrap();
    let root_classes: Vec<_> = null_rows
        .rows()
        .iter()
        .filter(|row| matches!(&row[0], Value::Entity(e) if e.local_index == 0))
        .collect();
    assert_eq!(root_classes.len(), 2);
    assert!(
        root_classes
            .iter()
            .all(|row| row[4] == Value::Null && row[5] == Value::Null)
    );
    let missing = NativeCatalog::new(
        catalog.snapshot_id().into(),
        catalog.catalog_epoch(),
        vec![OccurrenceFacts {
            metadata: catalog.occurrences[0].metadata.clone(),
            definitions: None,
            code: None,
        }],
    )
    .unwrap();
    assert_eq!(
        prepare(
            query(
                Node::Scan {
                    relation: "class_definition_details".into()
                },
                missing.snapshot_id(),
                missing.catalog_epoch()
            ),
            &missing
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn native_class_field_members_preserve_occurrence_and_kind_ordinal() {
    let catalog = native("definitions-038.dex", false);
    let plan = prepare(
        query(
            Node::Scan {
                relation: "class_field_members".into(),
            },
            catalog.snapshot_id(),
            catalog.catalog_epoch(),
        ),
        &catalog,
    )
    .unwrap();
    assert_eq!(
        plan.required_layers(),
        &BTreeSet::from([FactLayer::Structure])
    );
    let mut expected: Vec<Row> = catalog
        .occurrences
        .iter()
        .flat_map(|occurrence| {
            let source = occurrence.metadata.source();
            occurrence
                .definitions
                .as_ref()
                .unwrap()
                .definitions()
                .field_definitions
                .iter()
                .map(move |field| {
                    vec![
                        Value::Entity(EntityRef {
                            snapshot_id: source.snapshot_id.clone(),
                            dex_occurrence_id: source.dex_occurrence_id.clone(),
                            kind: EntityKind::ClassDefinition,
                            local_index: field.class_def_idx,
                        }),
                        Value::Entity(EntityRef {
                            snapshot_id: source.snapshot_id.clone(),
                            dex_occurrence_id: source.dex_occurrence_id.clone(),
                            kind: EntityKind::FieldDefinition,
                            local_index: field.field_idx,
                        }),
                        Value::text(field.kind.as_str()),
                        Value::U64(DecimalU64(u64::from(field.ordinal))),
                    ]
                })
        })
        .collect();
    assert!(!expected.is_empty());
    let definitions = catalog.occurrences[0]
        .definitions
        .as_ref()
        .unwrap()
        .definitions();
    assert!(
        definitions
            .field_definitions
            .iter()
            .any(|field| field.kind.as_str() == "static")
    );
    assert!(
        definitions
            .field_definitions
            .iter()
            .any(|field| field.kind.as_str() == "instance")
    );
    expected.sort();
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let mut actual = execute(
            &plan,
            &catalog,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap()
        .rows()
        .to_vec();
        actual.sort();
        assert_eq!(actual, expected);
        let limits = ExecutionLimits {
            max_output_rows: 0,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            execute(&plan, &catalog, mode, &mut Control::new(limits))
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let missing = NativeCatalog::new(
        catalog.snapshot_id().into(),
        catalog.catalog_epoch(),
        vec![OccurrenceFacts {
            metadata: catalog.occurrences[0].metadata.clone(),
            definitions: None,
            code: None,
        }],
    )
    .unwrap();
    assert_eq!(
        prepare(
            query(
                Node::Scan {
                    relation: "class_field_members".into()
                },
                missing.snapshot_id(),
                missing.catalog_epoch()
            ),
            &missing
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn native_class_method_members_preserve_occurrence_and_kind_ordinal() {
    let catalog = native("definitions-038.dex", false);
    let plan = prepare(
        query(
            Node::Scan {
                relation: "class_method_members".into(),
            },
            catalog.snapshot_id(),
            catalog.catalog_epoch(),
        ),
        &catalog,
    )
    .unwrap();
    assert_eq!(
        plan.required_layers(),
        &BTreeSet::from([FactLayer::Structure])
    );
    let result = execute(
        &plan,
        &catalog,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
    .unwrap();
    let expected: Vec<Row> = catalog
        .occurrences
        .iter()
        .flat_map(|occurrence| {
            let source = occurrence.metadata.source();
            occurrence
                .definitions
                .as_ref()
                .unwrap()
                .definitions()
                .method_definitions
                .iter()
                .map(move |method| {
                    vec![
                        Value::Entity(EntityRef {
                            snapshot_id: source.snapshot_id.clone(),
                            dex_occurrence_id: source.dex_occurrence_id.clone(),
                            kind: EntityKind::ClassDefinition,
                            local_index: method.class_def_idx,
                        }),
                        Value::Entity(EntityRef {
                            snapshot_id: source.snapshot_id.clone(),
                            dex_occurrence_id: source.dex_occurrence_id.clone(),
                            kind: EntityKind::MethodDefinition,
                            local_index: method.method_idx,
                        }),
                        Value::text(method.kind.as_str()),
                        Value::U64(DecimalU64(u64::from(method.ordinal))),
                    ]
                })
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(result.rows(), expected.as_slice());
    let midpoint = expected.len() / 2;
    assert_eq!(expected.len() % 2, 0);
    assert_ne!(expected[0][0], expected[midpoint][0]);
    assert!(
        catalog.occurrences[0]
            .definitions
            .as_ref()
            .unwrap()
            .definitions()
            .method_definitions
            .iter()
            .any(|v| v.kind.as_str() == "direct")
    );
    assert!(
        catalog.occurrences[0]
            .definitions
            .as_ref()
            .unwrap()
            .definitions()
            .method_definitions
            .iter()
            .any(|v| v.kind.as_str() == "virtual")
    );
    let metadata_only = NativeCatalog::new(
        catalog.snapshot_id().into(),
        catalog.catalog_epoch(),
        vec![OccurrenceFacts {
            metadata: catalog.occurrences[0].metadata.clone(),
            definitions: None,
            code: None,
        }],
    )
    .unwrap();
    let absent = prepare(
        query(
            Node::Scan {
                relation: "class_method_members".into(),
            },
            metadata_only.snapshot_id(),
            metadata_only.catalog_epoch(),
        ),
        &metadata_only,
    );
    assert_eq!(absent.err().unwrap().code, ErrorCode::IncompleteFacts);
}

#[test]
fn native_prototype_parameters_preserve_occurrence_and_ordinal() {
    let catalog = native("definitions-038.dex", false);
    let metadata_only = NativeCatalog::new(
        catalog.snapshot_id().into(),
        catalog.catalog_epoch(),
        catalog
            .occurrences
            .iter()
            .map(|o| OccurrenceFacts {
                metadata: o.metadata.clone(),
                definitions: None,
                code: None,
            })
            .collect(),
    )
    .unwrap();
    let plan = prepare(
        query(
            Node::Scan {
                relation: "prototype_parameters".into(),
            },
            metadata_only.snapshot_id(),
            metadata_only.catalog_epoch(),
        ),
        &metadata_only,
    )
    .unwrap();
    assert_eq!(
        plan.required_layers(),
        &BTreeSet::from([FactLayer::Metadata])
    );
    let rows = execute(
        &plan,
        &metadata_only,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
    .unwrap();
    let expected: Vec<Row> = metadata_only
        .occurrences
        .iter()
        .flat_map(|o| {
            o.metadata.prototypes().iter().flat_map(|p| {
                p.parameter_types.iter().enumerate().map(|(i, ty)| {
                    vec![
                        Value::Entity(p.entity.clone()),
                        Value::U64(DecimalU64(i as u64)),
                        Value::Entity(ty.clone()),
                    ]
                })
            })
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(rows.rows(), expected.as_slice());
    let midpoint = expected.len() / 2;
    assert_eq!(expected.len() % 2, 0);
    assert_ne!(expected[0][0], expected[midpoint][0]);
}

#[test]
fn native_code_items_do_not_require_method_definitions() {
    let complete = native("definitions-038.dex", true);
    let code_only = NativeCatalog::new(
        complete.snapshot_id().into(),
        complete.catalog_epoch(),
        complete
            .occurrences
            .iter()
            .map(|item| OccurrenceFacts {
                metadata: item.metadata.clone(),
                definitions: None,
                code: item.code.clone(),
            })
            .collect(),
    )
    .unwrap();
    let plan = prepare(
        query(
            Node::Scan {
                relation: "code_items".into(),
            },
            code_only.snapshot_id(),
            code_only.catalog_epoch(),
        ),
        &code_only,
    )
    .unwrap();
    let output = execute(
        &plan,
        &code_only,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
    .unwrap();
    assert!(!output.rows().is_empty());
    let definitions = prepare(
        query(
            Node::Scan {
                relation: "method_definitions".into(),
            },
            code_only.snapshot_id(),
            code_only.catalog_epoch(),
        ),
        &code_only,
    );
    assert_eq!(definitions.err().unwrap().code, ErrorCode::IncompleteFacts);
    let original = &complete.occurrences[0];
    let method_idx = original
        .definitions
        .as_ref()
        .unwrap()
        .definitions()
        .method_definitions
        .first()
        .unwrap()
        .method_idx;
    let method = EntityRef {
        snapshot_id: complete.snapshot_id().into(),
        dex_occurrence_id: original.metadata.source().dex_occurrence_id.clone(),
        kind: EntityKind::MethodDefinition,
        local_index: method_idx,
    };
    let projected = Node::Project {
        input: Box::new(Node::Scan {
            relation: "code_items".into(),
        }),
        columns: vec![Projection {
            column: col("body", DataType::Bytes, true),
            expression: Expr::ReadCodeBytes {
                entity: Box::new(Expr::Literal {
                    value: Value::Entity(method),
                }),
                byte_offset: DecimalU64(0),
                byte_length: None,
            },
        }],
    };
    let failure = prepare(
        query(
            projected,
            code_only.snapshot_id(),
            code_only.catalog_epoch(),
        ),
        &code_only,
    );
    assert_eq!(failure.err().unwrap().code, ErrorCode::IncompleteFacts);
}

#[test]
fn native_code_items_preserve_physical_identity_and_occurrences() {
    let catalog = native("definitions-038.dex", true);
    let plan = prepare(
        query(
            Node::Scan {
                relation: "code_items".into(),
            },
            catalog.snapshot_id(),
            catalog.catalog_epoch(),
        ),
        &catalog,
    )
    .unwrap();
    assert!(plan.required_layers().contains(&FactLayer::CodeLayout));
    let actual = execute(
        &plan,
        &catalog,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
    .unwrap();
    let expected: Vec<Row> = catalog
        .occurrences
        .iter()
        .flat_map(|occurrence| {
            let source = occurrence.metadata.source();
            occurrence
                .code
                .as_ref()
                .unwrap()
                .items()
                .iter()
                .map(move |item| {
                    let code = item.data();
                    vec![
                        Value::text(&source.dex_occurrence_id),
                        Value::text(item.code_item_id()),
                        Value::text(&source.physical_dex_id),
                        Value::U64(code.raw_range.byte_offset),
                        Value::U64(code.raw_range.byte_length),
                        Value::U64(code.insns_range.byte_offset),
                        Value::U64(code.insns_range.byte_length),
                        Value::U64(DecimalU64(u64::from(code.registers_size))),
                        Value::U64(DecimalU64(u64::from(code.ins_size))),
                        Value::U64(DecimalU64(u64::from(code.outs_size))),
                        Value::U64(DecimalU64(u64::from(code.insns_size_code_units))),
                        code.debug_info_byte_offset.map_or(Value::Null, Value::U64),
                    ]
                })
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(actual.rows(), expected.as_slice());
    let middle = expected.len() / 2;
    assert_ne!(expected[0][0], expected[middle][0]);
    assert_ne!(expected[0][1], expected[middle][1]);
    assert_eq!(expected[0][2], expected[middle][2]);
    let incomplete = native("definitions-038.dex", false);
    let err = prepare(
        query(
            Node::Scan {
                relation: "code_items".into(),
            },
            incomplete.snapshot_id(),
            incomplete.catalog_epoch(),
        ),
        &incomplete,
    )
    .err()
    .unwrap();
    assert_eq!(err.code, ErrorCode::IncompleteFacts);
}

#[test]
fn native_facts_duplicate_occurrences_and_bound_raw_code() {
    let catalog = native("definitions-038.dex", true);
    let plan = prepare(
        query(
            Node::Scan {
                relation: "methods".into(),
            },
            catalog.snapshot_id(),
            catalog.catalog_epoch(),
        ),
        &catalog,
    )
    .unwrap();
    let rows = execute(
        &plan,
        &catalog,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()),
    )
    .unwrap();
    assert_eq!(rows.rows().len(), 26);
    assert_ne!(rows.rows()[0][0], rows.rows()[13][0]);
    let o = &catalog.occurrences[0];
    let definitions = o.definitions.as_ref().unwrap();
    let method = |name: &str| {
        let reference = definitions
            .definitions()
            .method_references
            .iter()
            .find(|v| v.class_descriptor == "Lfixture/Base;" && v.method_name == name)
            .unwrap();
        EntityRef {
            snapshot_id: catalog.snapshot_id().into(),
            dex_occurrence_id: o.metadata.source().dex_occurrence_id.clone(),
            kind: EntityKind::MethodDefinition,
            local_index: reference.method_idx,
        }
    };
    assert_eq!(
        read_literal(&catalog, method("privateCall"), 0, None)
            .unwrap()
            .rows(),
        &[vec![Value::Bytes(Bytes(vec![0x0e, 0]))]]
    );
    assert_eq!(
        read_literal(&catalog, method("privateCall"), 1, Some(1))
            .unwrap()
            .rows(),
        &[vec![Value::Bytes(Bytes(vec![0]))]]
    );
    assert_eq!(
        read_literal(&catalog, method("nativeCall"), 0, None)
            .unwrap()
            .rows(),
        &[vec![Value::Null]]
    );
    assert_eq!(
        read_literal(&catalog, method("privateCall"), 3, Some(1))
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut foreign = method("privateCall");
    foreign.snapshot_id = "foreign".into();
    assert!(read_literal(&catalog, foreign, 0, None).is_err());
    let no_code = native("definitions-038.dex", false);
    let o = &no_code.occurrences[0];
    let reference = o
        .definitions
        .as_ref()
        .unwrap()
        .definitions()
        .method_references
        .iter()
        .find(|v| v.method_name == "privateCall")
        .unwrap();
    let entity = EntityRef {
        snapshot_id: no_code.snapshot_id().into(),
        dex_occurrence_id: o.metadata.source().dex_occurrence_id.clone(),
        kind: EntityKind::MethodDefinition,
        local_index: reference.method_idx,
    };
    assert_eq!(
        read_literal(&no_code, entity, 0, None).err().unwrap().code,
        ErrorCode::IncompleteFacts
    );
    let metadata_only = NativeCatalog::new(
        catalog.snapshot_id().into(),
        catalog.catalog_epoch(),
        vec![OccurrenceFacts {
            metadata: catalog.occurrences[0].metadata.clone(),
            definitions: None,
            code: None,
        }],
    )
    .unwrap();
    let unbuilt = prepare(
        query(
            Node::Limit {
                input: Box::new(Node::Scan {
                    relation: "methods".into(),
                }),
                offset: DecimalU64(0),
                count: DecimalU64(0),
            },
            metadata_only.snapshot_id(),
            metadata_only.catalog_epoch(),
        ),
        &metadata_only,
    );
    assert_eq!(unbuilt.err().unwrap().code, ErrorCode::IncompleteFacts);
    assert!(
        prepare(
            query(
                Node::Scan {
                    relation: "strings".into()
                },
                metadata_only.snapshot_id(),
                metadata_only.catalog_epoch()
            ),
            &metadata_only
        )
        .is_ok()
    );
    assert!(
        NativeCatalog::new(
            catalog.snapshot_id().into(),
            catalog.catalog_epoch(),
            vec![OccurrenceFacts {
                metadata: catalog.occurrences[0].metadata.clone(),
                definitions: catalog.occurrences[0].definitions.clone(),
                code: catalog.occurrences[1].code.clone()
            }]
        )
        .is_err()
    );
}

#[test]
fn present_empty_body_is_distinct_from_no_body_and_invalid_entity_is_not_empty_success() {
    let catalog = native("zero-insns-present.dex", true);
    let occurrence = &catalog.occurrences[0];
    let method = occurrence
        .definitions
        .as_ref()
        .unwrap()
        .definitions()
        .method_references
        .iter()
        .find(|m| m.method_name == "privateCall")
        .unwrap();
    let mut entity = EntityRef {
        snapshot_id: catalog.snapshot_id().into(),
        dex_occurrence_id: occurrence.metadata.source().dex_occurrence_id.clone(),
        kind: EntityKind::MethodDefinition,
        local_index: method.method_idx,
    };
    assert_eq!(
        read_literal(&catalog, entity.clone(), 0, None)
            .unwrap()
            .rows(),
        &[vec![Value::Bytes(Bytes(Vec::new()))]]
    );
    entity.local_index = u32::MAX;
    assert!(read_literal(&catalog, entity, 0, None).is_err());
    let generic = source(fixture());
    let invalid = EntityRef {
        snapshot_id: generic.snapshot_id().into(),
        dex_occurrence_id: "not-in-this-catalog".into(),
        kind: EntityKind::MethodReference,
        local_index: 0,
    };
    let empty = Node::Project {
        input: Box::new(Node::Scan {
            relation: "empty".into(),
        }),
        columns: vec![Projection {
            column: col("invalid", DataType::Entity, false),
            expression: Expr::Literal {
                value: Value::Entity(invalid),
            },
        }],
    };
    assert_eq!(
        prepare(
            query(empty, generic.snapshot_id(), generic.catalog_epoch()),
            &generic
        )
        .err()
        .unwrap()
        .details["reason"],
        "ENTITY_OUTSIDE_CATALOG"
    );
}

#[test]
fn exact_cell_codec_preserves_large_integers_bytes_and_surrogates() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/query/codec-cases.json"
    ))
    .unwrap();
    for case in cases["accepted"].as_array().unwrap() {
        let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
        let value = Value::Bytes(Bytes(bytes));
        let expected = serde_json::json!({"type":"bytes","value":case["base64"]});
        assert_eq!(serde_json::to_value(&value).unwrap(), expected);
        assert_eq!(serde_json::from_value::<Value>(expected).unwrap(), value);
    }
    for case in cases["rejected"].as_array().unwrap() {
        let wire = serde_json::json!({"type":"bytes","value":case});
        assert!(serde_json::from_value::<Value>(wire).is_err(), "{case}");
    }
    for value in [
        Value::Null,
        Value::Bytes(Bytes(vec![])),
        Value::Bytes(Bytes(vec![0, 255, 128, 1])),
        Value::Utf16(vec![0, 0xd800, 0xdc00]),
        Value::I64(Signed64(i64::MIN)),
        Value::U64(DecimalU64(u64::MAX)),
    ] {
        let wire = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&wire).unwrap(), value);
    }
    for bad in [
        r#"{"type":"i64","value":"-0"}"#,
        r#"{"type":"u64","value":"18446744073709551616"}"#,
        r#"{"type":"i64","value":9007199254740993}"#,
        r#"{"type":"bytes","value":"AB=="}"#,
        r#"{"type":"bytes","value":"AA=A"}"#,
    ] {
        assert!(serde_json::from_str::<Value>(bad).is_err(), "{bad}");
    }
    for bad in [
        "A", "AAA", "_A==", " A==", "AA==\n", "=AAA", "A===", "AA==AAAA", "AAB=", "____",
    ] {
        let wire = serde_json::json!({"type":"bytes","value":bad}).to_string();
        assert!(serde_json::from_str::<Value>(&wire).is_err(), "{wire}");
    }
    for (wire, expected) in [
        ("", vec![]),
        ("AA==", vec![0]),
        ("AAAA", vec![0, 0, 0]),
        ("AP+A", vec![0, 255, 128]),
    ] {
        let value = Value::Bytes(Bytes(expected));
        let encoded = serde_json::json!({"type":"bytes","value":wire}).to_string();
        assert_eq!(serde_json::from_str::<Value>(&encoded).unwrap(), value);
    }
}

#[test]
fn native_utf16_like_escape_matches_hand_and_independent_python_oracles() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/query/like-cases.json"
    ))
    .unwrap();
    let catalog = source(fixture());
    for case in cases["cases"].as_array().unwrap() {
        let text: Option<Vec<u16>> = serde_json::from_value(case["text"].clone()).unwrap();
        let pattern: Vec<u16> = serde_json::from_value(case["pattern"].clone()).unwrap();
        let escape: Option<u16> = serde_json::from_value(case["escape"].clone()).unwrap();
        let pattern = operators::native_like_pattern(&pattern, escape);
        if case["expected"].is_string() {
            assert_eq!(pattern.err().unwrap().details["reason"], case["expected"]);
            continue;
        }
        let predicate = Predicate::Like {
            value: Expr::Literal {
                value: text.map_or(Value::Null, Value::Utf16),
            },
            pattern: pattern.unwrap(),
        };
        let expected = match case["expected"].as_bool() {
            Some(true) => Truth::True,
            Some(false) => Truth::False,
            None => Truth::Unknown,
        };
        operators::check_predicate(&predicate, &Vec::new(), 0).unwrap();
        for reference in [false, true] {
            assert_eq!(
                operators::predicate(
                    &predicate,
                    &Vec::new(),
                    &catalog,
                    &mut Control::new(ExecutionLimits::default()),
                    reference
                )
                .unwrap(),
                expected,
                "{} reference={reference}",
                case["id"]
            );
        }
    }
}

#[test]
fn empty_right_join_keeps_schema_and_empty_grouped_aggregate_has_no_row() {
    let mut data = fixture();
    data.tables.get_mut("right").unwrap().rows.clear();
    let expected_left = data.tables["left"].rows.clone();
    let catalog = source(data);
    let join = Node::EquiJoin {
        left: Box::new(Node::Scan {
            relation: "left".into(),
        }),
        right: Box::new(Node::Scan {
            relation: "right".into(),
        }),
        left_keys: vec![2],
        right_keys: vec![0],
        kind: JoinKind::Left,
    };
    let aggregate = Node::Aggregate {
        input: Box::new(Node::Scan {
            relation: "empty".into(),
        }),
        group_by: vec![0],
        aggregates: vec![Aggregate {
            kind: AggregateKind::CountStar,
            ordinal: None,
            column: col("count", DataType::U64, false),
        }],
    };
    for node in [join, aggregate] {
        let plan = prepare(
            query(node, catalog.snapshot_id(), catalog.catalog_epoch()),
            &catalog,
        )
        .unwrap();
        for mode in [
            ExecutionMode::Streaming,
            ExecutionMode::MaterializedReference,
        ] {
            let result = execute(
                &plan,
                &catalog,
                mode,
                &mut Control::new(ExecutionLimits::default()),
            )
            .unwrap();
            if plan.schema().len() == 6 {
                let expected: Vec<Row> = expected_left
                    .iter()
                    .cloned()
                    .map(|mut r| {
                        r.extend([Value::Null, Value::Null]);
                        r
                    })
                    .collect();
                assert_eq!(result.rows(), expected);
                assert!(plan.schema()[4..].iter().all(|c| c.nullable));
            } else {
                assert!(result.rows().is_empty());
            }
        }
    }
}
