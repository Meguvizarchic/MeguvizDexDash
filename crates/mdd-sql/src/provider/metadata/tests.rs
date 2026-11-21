use super::*;
use crate::{SqlBridge, control::SqlLimits, dialects::SqlDialect};
use mdd_dex::strings::StringLimits;
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
#[test]
fn annotation_directories_preserve_physical_entries_and_shared_bindings() {
    use mdd_dex::{annotations::AnnotationLimits, definitions::DefinitionLimits};
    use mdd_facts::{annotations::AnnotationFacts, definitions::DefinitionFacts};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/annotations/generated");
    let specs = [
        "annotations-038.dex",
        "annotations-038.dex",
        "valid-orphan-empty-directory.dex",
        "valid-orphan-known-directory.dex",
        "valid-shared-empty-directory.dex",
    ]
    .into_iter()
    .map(|name| InputSpec {
        path: root.join(name),
        kind: InputKind::RawDex,
        expected_sha256: None,
    })
    .collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default()).unwrap();
    let mut facts = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        facts.push(Arc::new(
            AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap(),
        ));
    }
    let bridge = SqlBridge::new(
        Arc::new(AnnotationSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap()),
        SqlDialect::NativeV1,
        SqlLimits::default(),
    )
    .unwrap();
    let mut expected: [Vec<Vec<String>>; 3] = Default::default();
    let mut shared = false;
    for (fact, spec) in facts.iter().zip(&specs) {
        let bytes = std::fs::read(&spec.path).unwrap();
        let read = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let source = &fact.source().dex_occurrence_id;
        for directory in &fact.data().directories {
            let at = directory.byte_offset as usize;
            let class_offset = read(at);
            let field = read(at + 4);
            let method = read(at + 8);
            let parameter = read(at + 12);
            let count = field as usize + method as usize + parameter as usize;
            assert_eq!(count, directory.entries.len());
            let nullable = if class_offset == 0 {
                "<NULL>".into()
            } else {
                class_offset.to_string()
            };
            expected[0].push(vec![
                source.to_string(),
                directory.byte_offset.to_string(),
                nullable,
                field.to_string(),
                method.to_string(),
                parameter.to_string(),
                (16 + 8 * count).to_string(),
            ]);
            for i in 0..count {
                let kind = if i < field as usize {
                    "field"
                } else if i < (field + method) as usize {
                    "method"
                } else {
                    "parameter"
                };
                expected[1].push(vec![
                    source.to_string(),
                    directory.byte_offset.to_string(),
                    i.to_string(),
                    kind.into(),
                    read(at + 16 + i * 8).to_string(),
                    read(at + 20 + i * 8).to_string(),
                ]);
            }
        }
        let class_count = read(0x60) as usize;
        let class_offset = read(0x64) as usize;
        let mut offsets = std::collections::BTreeMap::new();
        for i in 0..class_count {
            let at = class_offset + i * 32;
            let directory = read(at + 20);
            if directory != 0 {
                *offsets.entry(directory).or_insert(0usize) += 1;
                expected[2].push(vec![
                    source.to_string(),
                    i.to_string(),
                    read(at).to_string(),
                    directory.to_string(),
                ]);
            }
        }
        shared |= offsets.values().any(|count| *count > 1);
    }
    assert!(shared, "shared directory fixture not exercised");
    assert!(expected[0].iter().any(|row| row[2] == "<NULL>"));
    assert!(expected[1].iter().any(|row| row[3] == "parameter"));
    for (i, name) in [
        "native_annotation_directories",
        "native_annotation_directory_entries",
        "native_annotation_directory_bindings",
    ]
    .iter()
    .enumerate()
    {
        let result = bridge.query(&format!("SELECT * FROM {name}")).unwrap();
        let mut actual = result
            .rows()
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| match value {
                        SqlValue::Null => "<NULL>".to_owned(),
                        SqlValue::U64(n) => n.0.to_string(),
                        SqlValue::I64(n) => n.0.to_string(),
                        SqlValue::Text(v) => v.strict_utf8().unwrap(),
                        other => panic!("unexpected value: {other:?}"),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        actual.sort();
        expected[i].sort();
        assert_eq!(actual, expected[i], "{name}");
    }
}
#[test]
fn annotation_sets_and_ref_lists_preserve_physical_entries_and_empty_headers() {
    use mdd_dex::{annotations::AnnotationLimits, definitions::DefinitionLimits};
    use mdd_facts::{annotations::AnnotationFacts, definitions::DefinitionFacts};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/annotations/generated");
    let specs = [
        "annotations-038.dex",
        "annotations-038.dex",
        "valid-orphan-empty-set.dex",
        "valid-orphan-empty-ref-list.dex",
        "bad-parameter-arity.dex",
        "bad-parameter-arity.dex",
    ]
    .into_iter()
    .map(|name| InputSpec {
        path: root.join(name),
        kind: InputKind::RawDex,
        expected_sha256: None,
    })
    .collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default()).unwrap();
    let mut facts = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let defs = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        facts.push(Arc::new(
            AnnotationFacts::build(defs, AnnotationLimits::default()).unwrap(),
        ));
    }
    let provider = Arc::new(AnnotationSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let mut expected: [Vec<Vec<String>>; 5] = Default::default();
    for (fact, spec) in facts.iter().zip(&specs) {
        // Independent raw little-endian decode of the physical containers;
        // start-offset validation remains the parser's separate responsibility.
        let bytes = std::fs::read(&spec.path).unwrap();
        let read_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
        };
        let source = &fact.source().dex_occurrence_id;
        for set in &fact.data().sets {
            let start = set.byte_offset as usize;
            assert_eq!(read_u32(start) as usize, set.annotation_offsets.len());
            for (ordinal, value) in set.annotation_offsets.iter().enumerate() {
                assert_eq!(read_u32(start + 4 + ordinal * 4), *value);
            }
            expected[0].push(vec![
                source.to_string(),
                set.byte_offset.to_string(),
                set.annotation_offsets.len().to_string(),
                set.encoded_range.byte_length.0.to_string(),
            ]);
            for (ordinal, offset) in set.annotation_offsets.iter().enumerate() {
                expected[1].push(vec![
                    source.to_string(),
                    set.byte_offset.to_string(),
                    ordinal.to_string(),
                    offset.to_string(),
                ]);
            }
        }
        for list in &fact.data().ref_lists {
            let start = list.byte_offset as usize;
            assert_eq!(read_u32(start) as usize, list.annotation_set_offsets.len());
            for (ordinal, value) in list.annotation_set_offsets.iter().enumerate() {
                assert_eq!(read_u32(start + 4 + ordinal * 4), value.unwrap_or(0));
            }
            expected[2].push(vec![
                source.to_string(),
                list.byte_offset.to_string(),
                list.annotation_set_offsets.len().to_string(),
                list.encoded_range.byte_length.0.to_string(),
            ]);
            for (ordinal, offset) in list.annotation_set_offsets.iter().enumerate() {
                expected[3].push(vec![
                    source.to_string(),
                    list.byte_offset.to_string(),
                    ordinal.to_string(),
                    offset.map_or("<NULL>".to_owned(), |v| v.to_string()),
                ]);
            }
        }
        for list in &fact.data().parameter_lists {
            let coverage = match list.prototype_position_coverage {
                Completeness::Complete => "complete",
                Completeness::Partial => "partial",
                Completeness::Unknown => "unknown",
            };
            expected[4].push(vec![
                source.to_string(),
                list.class_def_idx.to_string(),
                list.method_idx.to_string(),
                list.ref_list_byte_offset.to_string(),
                list.encoded_slot_count.to_string(),
                list.prototype_parameter_count.to_string(),
                u8::from(list.encoded_slots_complete).to_string(),
                coverage.into(),
            ]);
        }
    }
    assert!(
        expected[0].iter().any(|r| r[2] == "0"),
        "physical empty set fixture missing"
    );
    assert!(
        expected[2].iter().any(|r| r[2] == "0"),
        "physical empty ref-list fixture missing"
    );
    assert!(
        expected[3].iter().any(|r| r[3] == "<NULL>"),
        "encoded null slot fixture missing"
    );
    assert!(
        expected[4].iter().any(|r| r[7] != "complete"),
        "unknown parameter coverage fixture missing"
    );
    let short_source = &facts.last().unwrap().source().dex_occurrence_id;
    let owners = bridge.query("SELECT dex_occurrence_id,kind,parameter_ordinal,parameter_position_in_prototype FROM native_annotation_owners").unwrap();
    let short_owners: Vec<_> = owners.rows().iter().filter(|row| {
        matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == *short_source)
            && matches!(&row[1], SqlValue::Text(text) if text.strict_utf8().unwrap() == "parameter")
    }).collect();
    assert_eq!(short_owners.len(), 2);
    for row in short_owners {
        assert_eq!(row[2], SqlValue::U64(DecimalU64(0)));
        // NULL denotes unproven position; the parameter-list relation
        // below separately exposes the authoritative Unknown coverage.
        assert_eq!(row[3], SqlValue::Null);
    }
    let lists = bridge.query("SELECT dex_occurrence_id,prototype_position_coverage FROM native_annotation_parameter_lists").unwrap();
    let short_lists: Vec<_> = lists.rows().iter().filter(|row| {
        matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == *short_source)
    }).collect();
    assert_eq!(short_lists.len(), 2);
    assert!(short_lists.iter().all(
        |row| matches!(&row[1], SqlValue::Text(text) if text.strict_utf8().unwrap() == "unknown")
    ));
    // Coverage must be associated through all source-local keys; NULL
    // alone is not a proof of an absent or mapped prototype parameter.
    let short_sources: std::collections::BTreeSet<_> = facts[facts.len() - 2..]
        .iter()
        .map(|f| f.source().dex_occurrence_id.to_string())
        .collect();
    assert_eq!(short_sources.len(), 2);
    let joined = bridge.query("SELECT o.dex_occurrence_id,o.class_def_idx,o.local_index,o.kind,o.parameter_ordinal,o.parameter_position_in_prototype,p.dex_occurrence_id,p.class_def_idx,p.method_idx,p.prototype_position_coverage FROM native_annotation_owners o JOIN native_annotation_parameter_lists p ON o.dex_occurrence_id=p.dex_occurrence_id AND o.class_def_idx=p.class_def_idx AND o.local_index=p.method_idx").unwrap();
    let mut matches = std::collections::BTreeMap::<String, std::collections::BTreeSet<u64>>::new();
    for row in joined.rows() {
        let SqlValue::Text(source) = &row[0] else {
            panic!("missing occurrence")
        };
        let source = source.strict_utf8().unwrap();
        if !short_sources.contains(&source)
            || !matches!(&row[3], SqlValue::Text(text) if text.strict_utf8().unwrap() == "parameter")
        {
            continue;
        }
        assert_eq!(row[0], row[6]);
        assert_eq!(row[1], row[7]);
        assert_eq!(row[2], row[8]);
        assert_eq!(row[4], SqlValue::U64(DecimalU64(0)));
        assert_eq!(row[5], SqlValue::Null);
        assert!(
            matches!(&row[9], SqlValue::Text(text) if text.strict_utf8().unwrap() == "unknown")
        );
        let SqlValue::U64(DecimalU64(method)) = row[2] else {
            panic!("missing method")
        };
        assert!(matches.entry(source).or_default().insert(method));
    }
    assert_eq!(matches.len(), 2);
    assert!(
        matches
            .values()
            .all(|methods| methods == &std::collections::BTreeSet::from([0, 1]))
    );
    for (index, name) in [
        "native_annotation_sets",
        "native_annotation_set_entries",
        "native_annotation_ref_lists",
        "native_annotation_ref_entries",
        "native_annotation_parameter_lists",
    ]
    .iter()
    .enumerate()
    {
        let result = bridge.query(&format!("SELECT * FROM {name}")).unwrap();
        let mut actual = result
            .rows()
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| match value {
                        SqlValue::Null => "<NULL>".to_owned(),
                        SqlValue::U64(n) => n.0.to_string(),
                        SqlValue::I64(n) => n.0.to_string(),
                        SqlValue::Bool(v) => u8::from(*v).to_string(),
                        SqlValue::Text(text) => text.strict_utf8().unwrap(),
                        other => panic!("unexpected cell: {other:?}"),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        actual.sort();
        expected[index].sort();
        assert_eq!(actual, expected[index], "{name}");
    }
}
#[test]
fn native_annotations_preserve_occurrences_values_and_owner_slots() {
    use mdd_dex::{annotations::AnnotationLimits, definitions::DefinitionLimits};
    use mdd_facts::{annotations::AnnotationFacts, definitions::DefinitionFacts};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut metas = Vec::new();
    let mut defs = Vec::new();
    let mut facts = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let meta = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definition = DefinitionFacts::build(meta.clone(), DefinitionLimits::default()).unwrap();
        facts.push(Arc::new(
            AnnotationFacts::build(definition.clone(), AnnotationLimits::default()).unwrap(),
        ));
        metas.push(Arc::new(meta));
        defs.push(Arc::new(definition));
    }
    let annotations = Arc::new(AnnotationSqlProvider::new(facts.clone(), DecimalU64(4)).unwrap());
    let make_combined = || {
        CombinedSqlProvider::new(
            Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(4)).unwrap()),
            Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(4)).unwrap()),
        )
        .unwrap()
    };
    let provider = Arc::new(
        make_combined()
            .with_annotations(annotations.clone())
            .unwrap(),
    );
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    for (table, expected) in [
        (
            "native_annotation_items",
            facts
                .iter()
                .map(|f| f.data().annotation_items.len())
                .sum::<usize>(),
        ),
        (
            "native_encoded_value_nodes",
            facts.iter().map(|f| f.data().values.len()).sum::<usize>(),
        ),
        (
            "native_annotation_owners",
            facts
                .iter()
                .map(|f| f.data().owner_bindings.len())
                .sum::<usize>(),
        ),
    ] {
        let result = bridge.query(&format!("SELECT * FROM {table}")).unwrap();
        assert_eq!(result.rows().len(), expected, "{table}");
    }
    let values = bridge.query("SELECT dex_occurrence_id,node_id,annotation_byte_offset,float_bits,float_bit_width FROM native_encoded_value_nodes").unwrap();
    let mut observed = BTreeSet::new();
    for row in values.rows() {
        let SqlValue::Text(source) = &row[0] else {
            panic!("source type")
        };
        let SqlValue::U64(node) = row[1] else {
            panic!("node type")
        };
        let selected = facts
            .iter()
            .find(|f| f.source().dex_occurrence_id == source.strict_utf8().unwrap())
            .unwrap();
        let expected = &selected.data().values[node.0 as usize];
        assert_eq!(
            row[2],
            expected
                .annotation_byte_offset
                .map_or(SqlValue::Null, |v| SqlValue::U64(DecimalU64(v.into())))
        );
        assert_eq!(
            row[3],
            expected.float_bits.map_or(SqlValue::Null, SqlValue::U64)
        );
        assert_eq!(
            row[4],
            expected
                .float_bit_width
                .map_or(SqlValue::Null, |v| SqlValue::U64(DecimalU64(v.into())))
        );
        assert!(observed.insert((source.strict_utf8().unwrap(), node.0)));
    }
    let owners = bridge.query("SELECT dex_occurrence_id,kind,local_index,parameter_ordinal,annotation_set_offset,parameter_position_in_prototype FROM native_annotation_owners").unwrap();
    assert!(!owners.rows().is_empty());
    assert!(owners.rows().iter().any(|row| row[3] != SqlValue::Null));
    let mut actual_owners = owners
        .rows()
        .iter()
        .map(|row| {
            let SqlValue::Text(source) = &row[0] else {
                panic!("owner source type")
            };
            let SqlValue::Text(kind) = &row[1] else {
                panic!("owner kind type")
            };
            let SqlValue::U64(index) = row[2] else {
                panic!("owner index type")
            };
            let numeric = |v: &SqlValue| match v {
                SqlValue::Null => None,
                SqlValue::U64(n) => Some(n.0),
                _ => panic!("owner optional type"),
            };
            let position = match &row[5] {
                SqlValue::Null => None,
                SqlValue::Bool(v) => Some(*v),
                SqlValue::I64(v) if v.0 == 0 || v.0 == 1 => Some(v.0 == 1),
                _ => panic!("owner position type"),
            };
            (
                source.strict_utf8().unwrap(),
                kind.strict_utf8().unwrap(),
                index.0,
                numeric(&row[3]),
                numeric(&row[4]),
                position,
            )
        })
        .collect::<Vec<_>>();
    let mut expected_owners = Vec::new();
    for fact in &facts {
        for owner in &fact.data().owner_bindings {
            let kind = match owner.kind {
                mdd_dex::annotations::AnnotationOwnerKind::Class => "class",
                mdd_dex::annotations::AnnotationOwnerKind::Field => "field",
                mdd_dex::annotations::AnnotationOwnerKind::Method => "method",
                mdd_dex::annotations::AnnotationOwnerKind::Parameter => "parameter",
            };
            expected_owners.push((
                fact.source().dex_occurrence_id.to_string(),
                kind.to_string(),
                owner.local_index.into(),
                owner.parameter_ordinal.map(u64::from),
                owner.annotation_set_offset.map(u64::from),
                owner.parameter_position_in_prototype,
            ));
        }
    }
    actual_owners.sort();
    expected_owners.sort();
    assert_eq!(actual_owners, expected_owners);
    let partial =
        Arc::new(AnnotationSqlProvider::new(vec![facts[0].clone()], DecimalU64(4)).unwrap());
    assert!(make_combined().with_annotations(partial).is_err());
    assert!(
        AnnotationSqlProvider::new(vec![facts[0].clone(), facts[0].clone()], DecimalU64(4))
            .is_err()
    );
    let wrong_epoch = Arc::new(AnnotationSqlProvider::new(facts, DecimalU64(5)).unwrap());
    assert!(make_combined().with_annotations(wrong_epoch).is_err());
}
#[test]
fn combined_references_and_code_preserve_shared_owners_and_occurrences() {
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
    use mdd_facts::{
        code::CodeFacts,
        references::{ReferenceFacts, ReferenceLimits},
    };
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/shared-code-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let (mut metas, mut definitions, mut codes, mut references) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let meta = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let defs = DefinitionFacts::build(meta.clone(), DefinitionLimits::default()).unwrap();
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        let refs =
            ReferenceFacts::build(defs.clone(), code.clone(), ReferenceLimits::default()).unwrap();
        metas.push(Arc::new(meta));
        definitions.push(Arc::new(defs));
        codes.push(Arc::new(code));
        references.push(Arc::new(refs));
    }
    let mut expected = Vec::new();
    for (refs, code) in references.iter().zip(&codes) {
        for site in refs.sites() {
            let index = code
                .items()
                .iter()
                .position(|item| item.data().raw_range.byte_offset == site.code_item_byte_offset)
                .unwrap();
            expected.push((
                refs.source().dex_occurrence_id.to_string(),
                u64::from(site.caller_method_idx),
                site.code_item_byte_offset.0,
                u64::from(site.code_unit_pc),
                u64::from(site.operand_ordinal),
                code.raw_insns(index).unwrap().to_vec(),
            ));
        }
    }
    expected.sort();
    assert!(!expected.is_empty());
    assert_ne!(
        references[0].source().dex_occurrence_id,
        references[1].source().dex_occurrence_id
    );
    let callers: std::collections::BTreeSet<_> = expected.iter().map(|item| item.1).collect();
    assert!(
        callers.len() >= 2,
        "fixture must exercise shared-body owners"
    );
    for reverse in [false, true] {
        let combined = CombinedSqlProvider::new(
            Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(7)).unwrap()),
            Arc::new(DefinitionSqlProvider::new(definitions.clone(), DecimalU64(7)).unwrap()),
        )
        .unwrap();
        let code = Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(7)).unwrap());
        let refs = Arc::new(ReferenceSqlProvider::new(references.clone(), DecimalU64(7)).unwrap());
        let combined = if reverse {
            combined
                .with_references(refs)
                .unwrap()
                .with_code(code)
                .unwrap()
        } else {
            combined
                .with_code(code)
                .unwrap()
                .with_references(refs)
                .unwrap()
        };
        let bridge = SqlBridge::new(
            Arc::new(combined),
            SqlDialect::NativeV1,
            SqlLimits::default(),
        )
        .unwrap();
        let result = bridge.query("SELECT r.dex_occurrence_id,r.caller_method_idx,r.code_item_byte_offset,r.code_unit_pc,r.operand_ordinal,b.insns_raw FROM native_reference_sites r JOIN native_method_definitions m ON r.dex_occurrence_id=m.dex_occurrence_id AND r.caller_method_idx=m.method_idx AND r.code_item_byte_offset=m.code_byte_offset JOIN native_code_bytes b ON r.dex_occurrence_id=b.dex_occurrence_id AND r.code_item_byte_offset=b.code_byte_offset").unwrap();
        let mut actual: Vec<_> = result
            .rows()
            .iter()
            .map(
                |row| match (&row[0], &row[1], &row[2], &row[3], &row[4], &row[5]) {
                    (
                        SqlValue::Text(source),
                        SqlValue::U64(caller),
                        SqlValue::U64(offset),
                        SqlValue::U64(pc),
                        SqlValue::U64(ordinal),
                        SqlValue::Bytes(bytes),
                    ) => (
                        source.strict_utf8().unwrap(),
                        caller.0,
                        offset.0,
                        pc.0,
                        ordinal.0,
                        bytes.clone(),
                    ),
                    _ => panic!("unexpected result type"),
                },
            )
            .collect();
        actual.sort();
        assert_eq!(actual, expected);
    }
}
#[test]
fn combined_code_items_require_same_scope_and_keep_shared_owners() {
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
    use mdd_facts::code::CodeFacts;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/shared-code-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot =
        Snapshot::capture(&[input.clone(), input.clone()], CaptureLimits::default()).unwrap();
    let (mut metas, mut defs, mut codes) = (Vec::new(), Vec::new(), Vec::new());
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        defs.push(Arc::new(
            DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap(),
        ));
        metas.push(Arc::new(metadata));
        codes.push(Arc::new(
            CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                .unwrap(),
        ));
    }
    let base = || {
        CombinedSqlProvider::new(
            Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(7)).unwrap()),
            Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(7)).unwrap()),
        )
        .unwrap()
    };
    let partial = Arc::new(CodeSqlProvider::new(vec![codes[0].clone()], DecimalU64(7)).unwrap());
    assert_eq!(
        base().with_code(partial).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    let wrong_epoch = Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(8)).unwrap());
    assert_eq!(
        base().with_code(wrong_epoch).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    let other = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
    let inv = ArchiveInventory::build(
        &other.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let foreign = Arc::new(
        CodeSqlProvider::new(
            vec![Arc::new(
                CodeFacts::build_all_code_items(&other, &inv, 0, CodeLimits::default()).unwrap(),
            )],
            DecimalU64(7),
        )
        .unwrap(),
    );
    assert_eq!(
        base().with_code(foreign).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    let code = Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(7)).unwrap());
    assert_eq!(
        base()
            .with_code(code.clone())
            .unwrap()
            .with_code(code.clone())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let bridge = SqlBridge::new(
        Arc::new(base().with_code(code).unwrap()),
        SqlDialect::NativeV1,
        SqlLimits::default(),
    )
    .unwrap();
    let result = bridge.query("SELECT m.dex_occurrence_id,m.method_idx,c.code_byte_offset,b.insns_raw FROM native_method_definitions m JOIN native_code_items c ON m.dex_occurrence_id=c.dex_occurrence_id AND m.code_byte_offset=c.code_byte_offset JOIN native_code_bytes b ON c.dex_occurrence_id=b.dex_occurrence_id AND c.code_byte_offset=b.code_byte_offset").unwrap();
    let mut expected = Vec::new();
    for (definitions, facts) in defs.iter().zip(&codes) {
        for method in &definitions.definitions().method_definitions {
            if let mdd_dex::definitions::MethodBody::Present {
                code_byte_offset, ..
            } = method.body
            {
                let ordinal = facts
                    .items()
                    .iter()
                    .position(|item| item.data().raw_range.byte_offset == code_byte_offset)
                    .unwrap();
                expected.push((
                    facts.source().dex_occurrence_id.to_string(),
                    u64::from(method.method_idx),
                    code_byte_offset.0,
                    facts.raw_insns(ordinal).unwrap().to_vec(),
                ));
            }
        }
    }
    let actual: Vec<_> = result
        .rows()
        .iter()
        .map(|row| match (&row[0], &row[1], &row[2], &row[3]) {
            (
                SqlValue::Text(source),
                SqlValue::U64(method),
                SqlValue::U64(offset),
                SqlValue::Bytes(bytes),
            ) => (
                source.strict_utf8().unwrap(),
                method.0,
                offset.0,
                bytes.clone(),
            ),
            _ => panic!("unexpected joined row"),
        })
        .collect();
    let mut actual = actual;
    actual.sort();
    expected.sort();
    assert!(!expected.is_empty());
    assert_eq!(actual, expected);
}
#[test]
fn native_code_try_handlers_preserve_physical_offsets_and_catches() {
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
    use mdd_facts::code::CodeFacts;
    fn row_for<'a>(rows: &'a [Vec<SqlValue>], id: &str) -> &'a [SqlValue] {
        rows.iter()
            .find(|row| matches!(&row[0], SqlValue::Text(s) if s.strict_utf8().unwrap() == id))
            .unwrap()
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (path, typed) in [
        (
            "tests/fixtures/owned_try/generated/owned-try-even.dex",
            false,
        ),
        (
            "tests/fixtures/owned_try/generated/owned-try-odd.dex",
            false,
        ),
        (
            "artifacts/mdd-031-audit/native-code-handlers-20261030/typed-catch.dex",
            true,
        ),
    ] {
        let path = root.join(path);
        let raw = std::fs::read(&path).unwrap();
        let words = u32::from_le_bytes(raw[248..252].try_into().unwrap()) as usize;
        let tries_offset = 252 + words * 2 + (words % 2) * 2;
        let start = u32::from_le_bytes(raw[tries_offset..tries_offset + 4].try_into().unwrap());
        let units = u16::from_le_bytes(raw[tries_offset + 4..tries_offset + 6].try_into().unwrap());
        let handler_rel =
            u16::from_le_bytes(raw[tries_offset + 6..tries_offset + 8].try_into().unwrap());
        let handlers_offset = tries_offset + 8;
        assert_eq!(raw[handlers_offset], 1); // one handler in the independent fixture
        assert_eq!(handler_rel, 1);
        let encoded = if typed {
            &[1u8, 1, 0, 2][..]
        } else {
            &[1u8, 0, 2][..]
        };
        assert_eq!(
            &raw[handlers_offset..handlers_offset + encoded.len()],
            encoded
        );
        let spec = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot = Snapshot::capture(&[spec.clone(), spec], CaptureLimits::default()).unwrap();
        let mut codes = Vec::new();
        let mut metas = Vec::new();
        let mut defs = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            defs.push(Arc::new(
                DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap(),
            ));
            metas.push(Arc::new(metadata));
            codes.push(Arc::new(
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                    .unwrap(),
            ));
        }
        let code_provider = Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(1)).unwrap());
        let bridge = SqlBridge::new(
            code_provider.clone(),
            SqlDialect::NativeV1,
            SqlLimits::default(),
        )
        .unwrap();
        let combined = SqlBridge::new(
            Arc::new(
                CombinedSqlProvider::new(
                    Arc::new(MetadataSqlProvider::new(metas, DecimalU64(1)).unwrap()),
                    Arc::new(DefinitionSqlProvider::new(defs, DecimalU64(1)).unwrap()),
                )
                .unwrap()
                .with_code(code_provider)
                .unwrap(),
            ),
            SqlDialect::NativeV1,
            SqlLimits::default(),
        )
        .unwrap();
        let tries = bridge.query("SELECT dex_occurrence_id,code_byte_offset,try_ordinal,try_byte_offset,start_code_unit,code_unit_count,handler_relative_byte_offset FROM native_code_tries").unwrap();
        let handlers = bridge.query("SELECT dex_occurrence_id,code_byte_offset,handler_ordinal,handler_byte_offset,relative_byte_offset,typed_catch_count,catch_all_address_code_units,handler_byte_length FROM native_code_handlers").unwrap();
        let catches = bridge.query("SELECT dex_occurrence_id,code_byte_offset,handler_ordinal,catch_ordinal,type_idx,address_code_units FROM native_code_catches").unwrap();
        assert_eq!(tries.rows().len(), 2);
        assert_eq!(handlers.rows().len(), 2);
        assert_eq!(catches.rows().len(), if typed { 2 } else { 0 });
        for table in [
            "native_code_tries",
            "native_code_handlers",
            "native_code_catches",
        ] {
            let query = format!("SELECT * FROM {table}");
            let direct = bridge.query(&query).unwrap();
            let via_combined = combined.query(&query).unwrap();
            assert_eq!(direct.rows().len(), via_combined.rows().len());
            for facts in &codes {
                let id = &facts.source().dex_occurrence_id;
                if direct.rows().iter().any(
                    |row| matches!(&row[0], SqlValue::Text(s) if s.strict_utf8().unwrap() == *id),
                ) {
                    assert_eq!(row_for(direct.rows(), id), row_for(via_combined.rows(), id));
                }
            }
        }
        let u = |v| SqlValue::U64(DecimalU64(v));
        for facts in &codes {
            let id = &facts.source().dex_occurrence_id;
            assert_eq!(
                &row_for(tries.rows(), id)[1..],
                &[
                    u(236),
                    u(0),
                    u(tries_offset as u64),
                    u(start.into()),
                    u(units.into()),
                    u(handler_rel.into())
                ]
            );
            assert_eq!(
                &row_for(handlers.rows(), id)[1..],
                &[
                    u(236),
                    u(0),
                    u((handlers_offset + 1) as u64),
                    u(1),
                    u(u64::from(typed)),
                    if typed { SqlValue::Null } else { u(2) },
                    u((encoded.len() - 1) as u64)
                ]
            );
            if typed {
                assert_eq!(
                    &row_for(catches.rows(), id)[1..],
                    &[u(236), u(0), u(0), u(0), u(2)]
                );
            }
        }
    }
}

#[test]
fn native_code_items_preserve_physical_bytes_and_scope() {
    use mdd_dex::instructions::CodeLimits;
    use mdd_facts::code::CodeFacts;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/shared-code-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut codes = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        codes.push(Arc::new(
            CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                .unwrap(),
        ));
    }
    let expected: usize = codes.iter().map(|c| c.items().len()).sum();
    assert!(expected > 0);
    let provider = Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(1)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let result = bridge.query("SELECT dex_occurrence_id,code_byte_offset,insns_raw,code_item_raw FROM native_code_bytes").unwrap();
    assert_eq!(result.rows().len(), expected);
    for (facts, rows) in codes
        .iter()
        .zip(result.rows().chunks(codes[0].items().len()))
    {
        for (index, row) in rows.iter().enumerate() {
            assert!(
                matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == facts.source().dex_occurrence_id)
            );
            assert!(
                matches!(&row[1], SqlValue::U64(offset) if *offset == facts.items()[index].data().raw_range.byte_offset)
            );
            assert!(
                matches!(&row[2], SqlValue::Bytes(raw) if raw == facts.raw_insns(index).unwrap())
            );
            assert!(
                matches!(&row[3], SqlValue::Bytes(raw) if raw == facts.raw_code_item(index).unwrap())
            );
        }
    }
    assert!(CodeSqlProvider::new(vec![codes[0].clone(), codes[0].clone()], DecimalU64(1)).is_err());
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let partial =
        CodeFacts::build_offsets(&snapshot, &inventory, 0, &[], CodeLimits::default()).unwrap();
    let error = match CodeSqlProvider::new(vec![Arc::new(partial)], DecimalU64(1)) {
        Err(error) => error,
        Ok(_) => panic!("partial code admitted"),
    };
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    let low = SqlControl::new(
        SqlLimits {
            max_cell_bytes: 2,
            ..SqlLimits::default()
        },
        None,
    );
    assert_eq!(
        code_bytes(&[1, 2, 3], &low).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
}
#[test]
fn combined_reference_sites_join_only_matching_occurrences() {
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
    use mdd_facts::{
        code::CodeFacts,
        references::{ReferenceFacts, ReferenceLimits},
    };
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/poly-custom-038.dex");
    let spec = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot =
        Snapshot::capture(&[spec.clone(), spec.clone()], CaptureLimits::default()).unwrap();
    let (mut metas, mut defs, mut refs) = (Vec::new(), Vec::new(), Vec::new());
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions =
            DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap();
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        refs.push(Arc::new(
            ReferenceFacts::build(definitions.clone(), code, ReferenceLimits::default()).unwrap(),
        ));
        defs.push(Arc::new(definitions));
        metas.push(Arc::new(metadata));
    }
    let make_combined = || {
        CombinedSqlProvider::new(
            Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(7)).unwrap()),
            Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(7)).unwrap()),
        )
        .unwrap()
    };
    let partial =
        Arc::new(ReferenceSqlProvider::new(vec![refs[0].clone()], DecimalU64(7)).unwrap());
    assert_eq!(
        make_combined().with_references(partial).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    let first_inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let partial_code =
        CodeFacts::build_offsets(&snapshot, &first_inventory, 0, &[], CodeLimits::default())
            .unwrap();
    let partial_refs = Arc::new(
        ReferenceFacts::build((*defs[0]).clone(), partial_code, ReferenceLimits::default())
            .unwrap(),
    );
    assert_eq!(
        ReferenceSqlProvider::new(vec![partial_refs], DecimalU64(7))
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
    let foreign_epoch = Arc::new(ReferenceSqlProvider::new(refs.clone(), DecimalU64(8)).unwrap());
    assert_eq!(
        make_combined()
            .with_references(foreign_epoch)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let other = Snapshot::capture(&[spec], CaptureLimits::default()).unwrap();
    let other_inventory = ArchiveInventory::build(
        &other.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let other_meta =
        MetadataFacts::build(&other, &other_inventory, 0, StringLimits::default()).unwrap();
    let other_defs = DefinitionFacts::build(other_meta, DefinitionLimits::default()).unwrap();
    let other_code =
        CodeFacts::build_all_code_items(&other, &other_inventory, 0, CodeLimits::default())
            .unwrap();
    let other_refs = Arc::new(
        ReferenceFacts::build(other_defs, other_code, ReferenceLimits::default()).unwrap(),
    );
    let other_provider =
        Arc::new(ReferenceSqlProvider::new(vec![other_refs], DecimalU64(7)).unwrap());
    assert_ne!(
        other_provider.binding.snapshot_id,
        snapshot.manifest().snapshot_id
    );
    assert_eq!(
        make_combined()
            .with_references(other_provider)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let full = Arc::new(ReferenceSqlProvider::new(refs.clone(), DecimalU64(7)).unwrap());
    let combined = make_combined().with_references(full.clone()).unwrap();
    assert_eq!(
        combined.with_references(full.clone()).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    let combined = Arc::new(make_combined().with_references(full).unwrap());
    let bridge = SqlBridge::new(combined, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let dynamic = bridge.query("SELECT d.dex_occurrence_id,d.site_ordinal FROM native_dynamic_call_sites d JOIN native_reference_sites r ON d.dex_occurrence_id=r.dex_occurrence_id AND d.site_ordinal=r.site_ordinal").unwrap();
    assert_eq!(dynamic.rows().len(), 4);
    let call_rows = bridge
        .query("SELECT dex_occurrence_id,site_ordinal FROM native_method_call_sites")
        .unwrap();
    let expected_call_count = refs
        .iter()
        .flat_map(|r| r.sites())
        .filter(|site| {
            site.target_kind == mdd_facts::references::TargetKind::Method
                && site.invoke_kind.is_some()
        })
        .count();
    assert!(expected_call_count > 0);
    assert_eq!(call_rows.rows().len(), expected_call_count);
    let result = bridge.query("SELECT s.dex_occurrence_id,s.site_ordinal FROM native_reference_sites s JOIN native_method_references m ON s.dex_occurrence_id=m.dex_occurrence_id AND s.caller_method_idx=m.method_idx").unwrap();
    let actual: BTreeSet<_> = result
        .rows()
        .iter()
        .map(|row| match (&row[0], &row[1]) {
            (SqlValue::Text(source), SqlValue::U64(ordinal)) => {
                (source.strict_utf8().unwrap(), ordinal.0)
            }
            _ => panic!("unexpected joined identity"),
        })
        .collect();
    let expected: BTreeSet<_> = refs
        .iter()
        .flat_map(|facts| {
            facts.sites().iter().map(move |site| {
                (
                    facts.source().dex_occurrence_id.to_string(),
                    u64::from(site.site_ordinal),
                )
            })
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(result.rows().len(), expected.len());
    assert_eq!(actual, expected);
}
#[test]
fn native_reference_sites_keep_operand_and_occurrence_identity() {
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
    use mdd_facts::{
        code::CodeFacts,
        references::{ReferenceFacts, ReferenceLimits},
    };
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/poly-custom-038.dex");
    let spec = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[spec.clone(), spec], CaptureLimits::default()).unwrap();
    let mut sources = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        sources.push(Arc::new(
            ReferenceFacts::build(definitions, code, ReferenceLimits::default()).unwrap(),
        ));
    }
    assert!(!sources[0].sites().is_empty());
    assert!(
        ReferenceSqlProvider::new(vec![sources[0].clone(), sources[0].clone()], DecimalU64(0))
            .is_err()
    );
    let provider = Arc::new(ReferenceSqlProvider::new(sources.clone(), DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let result = bridge.query("SELECT dex_occurrence_id,site_ordinal,caller_method_idx,code_unit_pc,operand_ordinal,target_kind,target_local_index,opcode,instruction_byte_offset,operand_byte_offset FROM native_reference_sites").unwrap();
    let expected: Vec<_> = sources
        .iter()
        .flat_map(|source| {
            source
                .sites()
                .iter()
                .map(move |site| (source.source().dex_occurrence_id.to_string(), site))
        })
        .collect();
    assert_eq!(result.rows().len(), expected.len());
    for (row, (source, site)) in result.rows().iter().zip(expected) {
        assert!(matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == source));
        for (index, expected) in [
            (1, site.site_ordinal as u64),
            (2, site.caller_method_idx as u64),
            (3, site.code_unit_pc as u64),
            (4, site.operand_ordinal as u64),
            (6, site.target_local_index as u64),
            (7, site.opcode as u64),
            (8, site.instruction_range.byte_offset.0),
            (9, site.operand_range.byte_offset.0),
        ] {
            assert_eq!(row[index], SqlValue::U64(DecimalU64(expected)));
        }
    }
    assert_ne!(
        sources[0].source().dex_occurrence_id,
        sources[1].source().dex_occurrence_id
    );
    let calls = bridge.query("SELECT dex_occurrence_id,site_ordinal,caller_method_idx,code_unit_pc,operand_ordinal,target_local_index,invoke_kind FROM native_method_call_sites").unwrap();
    let expected_calls: Vec<_> = sources
        .iter()
        .flat_map(|source| {
            source
                .sites()
                .iter()
                .filter(|site| {
                    site.target_kind == mdd_facts::references::TargetKind::Method
                        && site.invoke_kind.is_some()
                })
                .map(move |site| (source.source().dex_occurrence_id.as_str(), site))
        })
        .collect();
    // The retained independent fixture oracle has six call rows per occurrence.
    assert_eq!(expected_calls.len(), 12);
    assert_eq!(calls.rows().len(), expected_calls.len());
    let mut oracle_targets = std::collections::BTreeMap::<String, Vec<u64>>::new();
    for (row, (source, site)) in calls.rows().iter().zip(expected_calls) {
        assert!(matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == source));
        for (index, expected) in [
            (1, site.site_ordinal as u64),
            (2, site.caller_method_idx as u64),
            (3, site.code_unit_pc as u64),
            (4, site.operand_ordinal as u64),
            (5, site.target_local_index as u64),
        ] {
            assert_eq!(row[index], SqlValue::U64(DecimalU64(expected)));
        }
        assert!(matches!(&row[6], SqlValue::Text(_)));
        oracle_targets
            .entry(source.to_owned())
            .or_default()
            .push(site.target_local_index as u64);
    }
    assert_eq!(oracle_targets.len(), 2);
    for targets in oracle_targets.values_mut() {
        targets.sort_unstable();
        assert_eq!(targets, &[2, 4, 4, 4, 5, 5]);
    }
    let dynamic = bridge.query("SELECT dex_occurrence_id,site_ordinal,caller_method_idx,code_unit_pc,operand_ordinal,call_site_idx,bootstrap_method_handle_idx,bootstrap_target_kind,bootstrap_target_index,method_type_idx,name_string_idx,runtime_target_status FROM native_dynamic_call_sites").unwrap();
    assert_eq!(dynamic.rows().len(), 4);
    let mut pcs = std::collections::BTreeMap::<String, Vec<u64>>::new();
    for row in dynamic.rows() {
        let SqlValue::Text(source) = &row[0] else {
            panic!("missing source")
        };
        let source = source.strict_utf8().unwrap();
        let facts = sources
            .iter()
            .find(|facts| facts.source().dex_occurrence_id == source)
            .unwrap();
        let SqlValue::U64(DecimalU64(site_ordinal)) = row[1] else {
            panic!("missing ordinal")
        };
        let call = facts
            .dynamic_calls()
            .iter()
            .find(|call| u64::from(call.site_ordinal) == site_ordinal)
            .unwrap();
        let site = &facts.sites()[call.site_ordinal as usize];
        for (index, expected) in [
            (2, site.caller_method_idx),
            (3, site.code_unit_pc),
            (4, site.operand_ordinal),
            (5, call.call_site_idx),
            (6, call.bootstrap_method_handle_idx),
            (8, call.bootstrap_target_index),
            (9, call.method_type_idx),
            (10, call.name_string_idx),
        ] {
            assert_eq!(row[index], SqlValue::U64(DecimalU64(u64::from(expected))));
        }
        assert!(
            matches!(&row[7], SqlValue::Text(value) if value.strict_utf8().unwrap() == call.bootstrap_target_kind.as_str())
        );
        assert!(
            matches!(&row[11], SqlValue::Text(value) if value.strict_utf8().unwrap() == call.runtime_target_status)
        );
        assert_eq!(site.caller_method_idx, 0);
        assert_eq!(call.call_site_idx, 0);
        pcs.entry(source)
            .or_default()
            .push(u64::from(site.code_unit_pc));
    }
    assert_eq!(pcs.len(), 2);
    for offsets in pcs.values_mut() {
        offsets.sort_unstable();
        assert_eq!(offsets, &[34, 37]); // retained independent fixture oracle
    }
    let joined = bridge.query("SELECT d.dex_occurrence_id,d.site_ordinal FROM native_dynamic_call_sites d JOIN native_reference_sites r ON d.dex_occurrence_id=r.dex_occurrence_id AND d.site_ordinal=r.site_ordinal").unwrap();
    assert_eq!(joined.rows().len(), 4);
}
#[test]
fn native_string_pools_bind_each_occurrence_without_cross_source_duplication() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
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
        facts.push(Arc::new(
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
        ));
    }
    assert_ne!(
        facts[0].source().dex_occurrence_id,
        facts[1].source().dex_occurrence_id
    );
    assert_eq!(
        facts[0].string_pool().string_pool_id,
        facts[1].string_pool().string_pool_id
    );
    let provider = Arc::new(MetadataSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let pools = bridge.query("SELECT dex_occurrence_id,string_pool_id,physical_dex_id,content_id,string_ids_byte_offset,string_count FROM native_string_pools").unwrap();
    assert_eq!(pools.rows().len(), facts.len());
    for (row, fact) in pools.rows().iter().zip(&facts) {
        let pool = fact.string_pool();
        for (index, expected) in [
            (0, &pool.dex_occurrence_id),
            (1, &pool.string_pool_id),
            (2, &pool.physical_dex_id),
            (3, &pool.content_id),
        ] {
            assert!(
                matches!(&row[index], SqlValue::Text(text) if text.strict_utf8().unwrap() == *expected)
            );
        }
        assert_eq!(row[4], SqlValue::U64(pool.string_ids_byte_offset));
        assert_eq!(
            row[5],
            SqlValue::U64(DecimalU64(u64::from(pool.string_count)))
        );
    }
    let joined = bridge.query("SELECT p.dex_occurrence_id,p.string_pool_id,s.string_idx FROM native_string_pools p JOIN native_strings s ON p.dex_occurrence_id=s.dex_occurrence_id AND p.string_pool_id=s.string_pool_id").unwrap();
    let mut expected = BTreeSet::new();
    for fact in &facts {
        for string in fact.strings() {
            expected.insert((
                fact.source().dex_occurrence_id.to_string(),
                string.string_pool_id.to_string(),
                u64::from(string.data.string_idx),
            ));
        }
    }
    let actual: BTreeSet<_> = joined
        .rows()
        .iter()
        .map(|row| {
            let text = |index| match &row[index] {
                SqlValue::Text(value) => value.strict_utf8().unwrap(),
                _ => panic!("unexpected identity"),
            };
            let index = match &row[2] {
                SqlValue::U64(value) => value.0,
                _ => panic!("unexpected index"),
            };
            (text(0), text(1), index)
        })
        .collect();
    assert_eq!(joined.rows().len(), expected.len());
    assert_eq!(actual, expected);
}
#[test]
fn native_dex_occurrences_preserve_source_identities() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut facts = Vec::new();
    let mut expected = BTreeSet::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let id = metadata.source();
        expected.insert(vec![
            id.snapshot_id.to_string(),
            id.dex_occurrence_id.to_string(),
            id.physical_dex_id.clone(),
            id.member_id.clone(),
            id.source_occurrence_id.clone(),
            id.content_id.clone(),
        ]);
        facts.push(Arc::new(metadata));
    }
    assert_eq!(expected.len(), 2);
    let provider = Arc::new(MetadataSqlProvider::new(facts, DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let rows = bridge.query("SELECT snapshot_id,dex_occurrence_id,physical_dex_id,member_id,source_occurrence_id,content_id FROM native_dex_occurrences").unwrap();
    let actual = rows
        .rows()
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| match cell {
                    SqlValue::Text(text) => text.strict_utf8().unwrap(),
                    _ => panic!("unexpected source identity cell"),
                })
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    let left = actual.iter().next().unwrap();
    let right = actual.iter().nth(1).unwrap();
    assert_ne!(left[1], right[1]);
    assert_eq!(left[2], right[2]);
    assert_eq!(left[5], right[5]);
}
#[test]
fn combined_metadata_definitions_join_same_occurrences() {
    use mdd_dex::definitions::DefinitionLimits;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut metas = Vec::new();
    let mut defs = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let meta = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        defs.push(Arc::new(
            DefinitionFacts::build(meta.clone(), DefinitionLimits::default()).unwrap(),
        ));
        metas.push(Arc::new(meta));
    }
    let meta = Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(3)).unwrap());
    let definitions = Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(3)).unwrap());
    let combined = Arc::new(CombinedSqlProvider::new(meta, definitions).unwrap());
    let bridge = SqlBridge::new(combined, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let result = bridge.query("SELECT r.dex_occurrence_id,r.method_idx,p.proto_idx FROM native_method_references r JOIN native_prototypes p ON r.dex_occurrence_id=p.dex_occurrence_id AND r.prototype_idx=p.proto_idx").unwrap();
    let expected: usize = defs
        .iter()
        .map(|f| f.definitions().method_references.len())
        .sum();
    assert_eq!(result.rows().len(), expected);
    let partial =
        Arc::new(MetadataSqlProvider::new(vec![metas[0].clone()], DecimalU64(3)).unwrap());
    let both = Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(3)).unwrap());
    assert!(CombinedSqlProvider::new(partial, both).is_err());
    let mismatch = Arc::new(MetadataSqlProvider::new(metas, DecimalU64(4)).unwrap());
    let both = Arc::new(DefinitionSqlProvider::new(defs, DecimalU64(3)).unwrap());
    assert!(CombinedSqlProvider::new(mismatch, both).is_err());
}
#[test]
fn native_member_relations_keep_references_definitions_and_sources_distinct() {
    use mdd_dex::definitions::{DefinitionLimits, MethodBody};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = root.join("tests/fixtures/definitions/generated/definitions-035.dex");
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
        facts.push(Arc::new(
            DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap(),
        ));
    }
    let bridge = SqlBridge::new(
        Arc::new(DefinitionSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap()),
        SqlDialect::NativeV1,
        SqlLimits::default(),
    )
    .unwrap();
    let method_refs = bridge.query("SELECT dex_occurrence_id,method_idx,class_type_idx,class_descriptor,class_descriptor_mutf8,prototype_idx,name_idx,name,name_mutf8 FROM native_method_references").unwrap();
    let method_defs = bridge.query("SELECT dex_occurrence_id,class_def_idx,class_type_idx,method_idx,kind,ordinal,access_flags,body_state,code_byte_offset,declared_insns_size FROM native_method_definitions").unwrap();
    let field_refs = bridge.query("SELECT dex_occurrence_id,field_idx,class_type_idx,class_descriptor,class_descriptor_mutf8,field_type_idx,type_descriptor,type_descriptor_mutf8,name_idx,name,name_mutf8 FROM native_field_references").unwrap();
    let field_defs = bridge.query("SELECT dex_occurrence_id,class_def_idx,class_type_idx,field_idx,kind,ordinal,access_flags FROM native_field_definitions").unwrap();
    let as_u64 = |v: u32| SqlValue::U64(DecimalU64(u64::from(v)));
    let text = |v: &SqlValue| match v {
        SqlValue::Text(v) => v.strict_utf8().unwrap(),
        other => panic!("expected text: {other:?}"),
    };
    let mut saw_reference_only = false;
    let mut states = BTreeSet::new();
    for f in &facts {
        let source = &f.metadata().source().dex_occurrence_id;
        let mrefs: Vec<_> = method_refs
            .rows()
            .iter()
            .filter(|row| text(&row[0]) == *source)
            .collect();
        let mdefs: Vec<_> = method_defs
            .rows()
            .iter()
            .filter(|row| text(&row[0]) == *source)
            .collect();
        let frefs: Vec<_> = field_refs
            .rows()
            .iter()
            .filter(|row| text(&row[0]) == *source)
            .collect();
        let fdefs: Vec<_> = field_defs
            .rows()
            .iter()
            .filter(|row| text(&row[0]) == *source)
            .collect();
        assert_eq!(mrefs.len(), f.definitions().method_references.len());
        assert_eq!(mdefs.len(), f.definitions().method_definitions.len());
        assert_eq!(frefs.len(), f.definitions().field_references.len());
        assert_eq!(fdefs.len(), f.definitions().field_definitions.len());
        for (row, reference) in mrefs.iter().zip(&f.definitions().method_references) {
            assert_eq!(row[1], as_u64(reference.method_idx));
            assert_eq!(row[2], as_u64(reference.class_idx));
            assert_eq!(row[5], as_u64(reference.proto_idx));
            assert_eq!(row[6], as_u64(reference.name_idx));
            assert_eq!(text(&row[7]), reference.method_name);
            let name = &f.metadata().strings()[reference.name_idx as usize]
                .data
                .text;
            assert!(
                matches!(&row[8], SqlValue::DexMutf8 { bytes, .. } if bytes == &name.raw_mutf8)
            );
            if !f
                .definitions()
                .method_definitions
                .iter()
                .any(|d| d.method_idx == reference.method_idx)
            {
                saw_reference_only = true;
            }
        }
        for (row, definition) in mdefs.iter().zip(&f.definitions().method_definitions) {
            assert_eq!(row[1], as_u64(definition.class_def_idx));
            assert_eq!(row[2], as_u64(definition.class_idx));
            assert_eq!(row[3], as_u64(definition.method_idx));
            assert_eq!(text(&row[4]), definition.kind.as_str());
            assert_eq!(row[5], as_u64(definition.ordinal));
            assert_eq!(row[6], as_u64(definition.access_flags));
            assert_eq!(text(&row[7]), definition.body.state());
            states.insert(definition.body.state());
            match &definition.body {
                MethodBody::Present {
                    code_byte_offset,
                    declared_insns_size,
                } => {
                    assert_eq!(row[8], SqlValue::U64(*code_byte_offset));
                    assert_eq!(row[9], as_u64(*declared_insns_size));
                }
                _ => assert_eq!((&row[8], &row[9]), (&SqlValue::Null, &SqlValue::Null)),
            }
        }
        for (row, reference) in frefs.iter().zip(&f.definitions().field_references) {
            assert_eq!(row[1], as_u64(reference.field_idx));
            assert_eq!(row[2], as_u64(reference.class_idx));
            assert_eq!(row[5], as_u64(reference.type_idx));
            assert_eq!(row[8], as_u64(reference.name_idx));
            assert_eq!(text(&row[9]), reference.field_name);
            let name = &f.metadata().strings()[reference.name_idx as usize]
                .data
                .text;
            assert!(
                matches!(&row[10], SqlValue::DexMutf8 { bytes, .. } if bytes == &name.raw_mutf8)
            );
        }
        for (row, definition) in fdefs.iter().zip(&f.definitions().field_definitions) {
            assert_eq!(row[1], as_u64(definition.class_def_idx));
            assert_eq!(row[2], as_u64(definition.class_idx));
            assert_eq!(row[3], as_u64(definition.field_idx));
            assert_eq!(text(&row[4]), definition.kind.as_str());
            assert_eq!(row[5], as_u64(definition.ordinal));
            assert_eq!(row[6], as_u64(definition.access_flags));
        }
    }
    assert_ne!(
        facts[0].metadata().source().dex_occurrence_id,
        facts[1].metadata().source().dex_occurrence_id
    );
    assert!(saw_reference_only);
    assert!(states.contains("native") && states.contains("abstract") && states.contains("present"));
    let joined = bridge.query("SELECT r.dex_occurrence_id,r.method_idx,d.method_idx,d.body_state FROM native_method_references r LEFT JOIN native_method_definitions d ON r.dex_occurrence_id=d.dex_occurrence_id AND r.method_idx=d.method_idx").unwrap();
    assert_eq!(joined.rows().len(), method_refs.rows().len());
    for row in joined.rows() {
        let source = text(&row[0]);
        let occurrence = facts
            .iter()
            .find(|facts| facts.metadata().source().dex_occurrence_id == source)
            .unwrap();
        let definition = occurrence
            .definitions()
            .method_definitions
            .iter()
            .find(|d| as_u64(d.method_idx) == row[1]);
        match definition {
            Some(definition) => {
                assert_eq!(row[2], row[1]);
                assert_eq!(text(&row[3]), definition.body.state());
            }
            None => assert_eq!((&row[2], &row[3]), (&SqlValue::Null, &SqlValue::Null)),
        }
    }
    let joined_fields = bridge.query("SELECT r.dex_occurrence_id,r.field_idx,d.field_idx FROM native_field_references r LEFT JOIN native_field_definitions d ON r.dex_occurrence_id=d.dex_occurrence_id AND r.field_idx=d.field_idx").unwrap();
    assert_eq!(joined_fields.rows().len(), field_refs.rows().len());
    for row in joined_fields.rows() {
        let source = text(&row[0]);
        let occurrence = facts
            .iter()
            .find(|facts| facts.metadata().source().dex_occurrence_id == source)
            .unwrap();
        if occurrence
            .definitions()
            .field_definitions
            .iter()
            .any(|d| as_u64(d.field_idx) == row[1])
        {
            assert_eq!(row[2], row[1]);
        } else {
            assert_eq!(row[2], SqlValue::Null);
        }
    }
    let small = SqlBridge::new(
        Arc::new(DefinitionSqlProvider::new(facts, DecimalU64(0)).unwrap()),
        SqlDialect::NativeV1,
        SqlLimits {
            max_cell_bytes: 1,
            ..SqlLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        small
            .query("SELECT name FROM native_method_references")
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
}
#[test]
fn native_class_definition_details_preserve_raw_offsets_and_sources() {
    use mdd_dex::definitions::DefinitionLimits;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated");
    let inputs = [
        "definitions-035.dex",
        "definitions-035.dex",
        "nullable-root-class.dex",
        "empty-class-data.dex",
    ]
    .map(|name| InputSpec {
        path: root.join(name),
        kind: InputKind::RawDex,
        expected_sha256: None,
    });
    let snapshot = Snapshot::capture(&inputs, CaptureLimits::default()).unwrap();
    let mut occurrences = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        occurrences.push(Arc::new(
            DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap(),
        ));
    }
    let bridge = SqlBridge::new(
        Arc::new(DefinitionSqlProvider::new(occurrences.clone(), DecimalU64(0)).unwrap()),
        SqlDialect::NativeV1,
        SqlLimits::default(),
    )
    .unwrap();
    let result = bridge.query("SELECT dex_occurrence_id,class_def_idx,access_flags,annotations_offset,static_values_offset,class_data_offset,class_data_length,static_fields_count,instance_fields_count,direct_methods_count,virtual_methods_count,encoded_offset,encoded_length FROM native_class_definition_details").unwrap();
    let expected_count: usize = occurrences
        .iter()
        .map(|facts| facts.definitions().classes.len())
        .sum();
    assert_eq!(result.rows().len(), expected_count);
    let u64_value = |v: u64| SqlValue::U64(DecimalU64(v));
    let mut saw_absent_data = false;
    let mut saw_empty_data = false;
    for (facts, input) in occurrences.iter().zip(&inputs) {
        let bytes = std::fs::read(&input.path).unwrap();
        let read_u32 =
            |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let class_defs_offset = read_u32(0x64) as usize;
        let source = &facts.metadata().source().dex_occurrence_id;
        for class in &facts.definitions().classes {
            let row = result.rows().iter().find(|row| {
                matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == *source)
                    && row[1] == u64_value(class.class_def_idx.into())
            }).unwrap();
            let at = class_defs_offset + class.class_def_idx as usize * 32;
            let nullable_offset = |value: u32| {
                if value == 0 {
                    SqlValue::Null
                } else {
                    u64_value(value.into())
                }
            };
            assert_eq!(row[2], u64_value(read_u32(at + 4).into()));
            assert_eq!(row[3], nullable_offset(read_u32(at + 20)));
            assert_eq!(row[4], nullable_offset(read_u32(at + 28)));
            let data_offset = read_u32(at + 24);
            assert_eq!(row[5], nullable_offset(data_offset));
            assert_eq!(row[11], u64_value(at as u64));
            assert_eq!(row[12], u64_value(32));
            let mut counts = [0u32; 4];
            if data_offset != 0 {
                let mut cursor = data_offset as usize;
                for count in &mut counts {
                    let mut terminated = false;
                    for shift in (0..35).step_by(7) {
                        let byte = bytes[cursor];
                        cursor += 1;
                        *count |= u32::from(byte & 0x7f) << shift;
                        if byte & 0x80 == 0 {
                            terminated = true;
                            break;
                        }
                    }
                    assert!(terminated);
                }
                assert_eq!(
                    row[6],
                    SqlValue::U64(class.class_data_range.as_ref().unwrap().byte_length)
                );
                saw_empty_data |= counts == [0; 4];
            } else {
                assert_eq!(row[6], SqlValue::Null);
                saw_absent_data = true;
            }
            for (i, count) in counts.into_iter().enumerate() {
                assert_eq!(row[7 + i], u64_value(count.into()));
            }
        }
    }
    assert_ne!(
        occurrences[0].metadata().source().dex_occurrence_id,
        occurrences[1].metadata().source().dex_occurrence_id
    );
    assert!(saw_absent_data && saw_empty_data);
}
#[test]
fn native_class_interface_join_keeps_distinct_occurrences() {
    use mdd_dex::definitions::DefinitionLimits;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
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
        facts.push(Arc::new(
            DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap(),
        ));
    }
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/definitions/expected.json"
    ))
    .unwrap();
    let mut expected = Vec::new();
    for item in &facts {
        let occurrence = item.metadata().source().dex_occurrence_id.to_string();
        for triple in oracle["definitions-035"]["interfaces"].as_array().unwrap() {
            expected.push((
                occurrence.clone(),
                triple[0].as_str().unwrap().to_owned(),
                triple[2].as_str().unwrap().to_owned(),
                triple[1].as_u64().unwrap(),
            ));
        }
    }
    expected.sort();
    assert_eq!(expected.len(), 4);
    assert_ne!(
        facts[0].metadata().source().dex_occurrence_id,
        facts[1].metadata().source().dex_occurrence_id
    );
    let provider = Arc::new(DefinitionSqlProvider::new(facts, DecimalU64(0)).unwrap());
    let sql = "SELECT i.dex_occurrence_id,c.descriptor,i.descriptor,i.ordinal FROM native_class_interfaces i JOIN native_classes c ON c.dex_occurrence_id=i.dex_occurrence_id AND c.type_idx=i.class_type_idx WHERE c.descriptor IN ('Lfixture/I1;','Lfixture/Base;') ORDER BY i.dex_occurrence_id,i.class_type_idx,i.ordinal";
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
        let result = bridge.query(sql).unwrap();
        let mut actual = result
            .rows()
            .iter()
            .map(|row| {
                let text = |value: &SqlValue| match value {
                    SqlValue::Text(value) => value.strict_utf8().unwrap(),
                    other => panic!("unexpected text: {other:?}"),
                };
                let SqlValue::U64(DecimalU64(ordinal)) = row[3] else {
                    panic!("unexpected interface ordinal: {:?}", row[3]);
                };
                (text(&row[0]), text(&row[1]), text(&row[2]), ordinal)
            })
            .collect::<Vec<_>>();
        actual.sort();
        assert_eq!(actual, expected, "{dialect:?}");
    }
}
#[test]
fn native_return_discovery_keeps_occurrences_and_distinct_classes() {
    use mdd_dex::definitions::DefinitionLimits;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let mut metadata = Vec::new();
    let mut definitions = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let facts =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        definitions.push(Arc::new(
            DefinitionFacts::build(facts.clone(), DefinitionLimits::default()).unwrap(),
        ));
        metadata.push(Arc::new(facts));
    }
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/definitions/expected.json"
    ))
    .unwrap();
    let mut expected_methods = Vec::new();
    let mut expected_classes = std::collections::BTreeSet::new();
    for method in oracle["definitions-035"]["methods"].as_array().unwrap() {
        let descriptor = method[0].as_str().unwrap();
        if descriptor.ends_with(")I") {
            let (owner, name_and_proto) = descriptor.split_once("->").unwrap();
            let name = name_and_proto.split_once('(').unwrap().0;
            expected_classes.insert(owner.to_owned());
            for item in &metadata {
                expected_methods.push((
                    item.source().dex_occurrence_id.to_string(),
                    owner.to_owned(),
                    name.to_owned(),
                ));
            }
        }
    }
    expected_methods.sort();
    assert_eq!(expected_methods.len(), 4);
    let meta = Arc::new(MetadataSqlProvider::new(metadata, DecimalU64(0)).unwrap());
    let defs = Arc::new(DefinitionSqlProvider::new(definitions, DecimalU64(0)).unwrap());
    let provider = Arc::new(CombinedSqlProvider::new(meta, defs).unwrap());
    let join = " FROM native_method_definitions d JOIN native_method_references m ON d.dex_occurrence_id=m.dex_occurrence_id AND d.method_idx=m.method_idx JOIN native_prototypes p ON m.dex_occurrence_id=p.dex_occurrence_id AND m.prototype_idx=p.proto_idx JOIN native_types t ON p.dex_occurrence_id=t.dex_occurrence_id AND p.return_type_idx=t.type_idx";
    let text = |value: &SqlValue| match value {
        SqlValue::Text(value) => value.strict_utf8().unwrap(),
        other => panic!("unexpected text: {other:?}"),
    };
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
        let sql = format!(
            "SELECT d.dex_occurrence_id,m.dex_occurrence_id,p.dex_occurrence_id,t.dex_occurrence_id,m.class_descriptor,m.name{join} WHERE t.descriptor='I'"
        );
        let result = bridge.query(&sql).unwrap();
        let mut actual = Vec::new();
        for row in result.rows() {
            let occurrence = text(&row[0]);
            for source in &row[1..4] {
                assert_eq!(text(source), occurrence, "cross-source join in {dialect:?}");
            }
            actual.push((occurrence, text(&row[4]), text(&row[5])));
        }
        actual.sort();
        assert_eq!(actual, expected_methods, "{dialect:?}");
        let distinct = bridge.query(&format!("SELECT DISTINCT m.class_descriptor{join} WHERE t.descriptor='I' ORDER BY m.class_descriptor")).unwrap();
        let classes = distinct
            .rows()
            .iter()
            .map(|row| text(&row[0]))
            .collect::<Vec<_>>();
        assert_eq!(
            classes,
            expected_classes.iter().cloned().collect::<Vec<_>>(),
            "{dialect:?}"
        );
        let outer = "SELECT d.dex_occurrence_id,t.descriptor FROM native_method_definitions d LEFT JOIN native_types t ON d.dex_occurrence_id=t.dex_occurrence_id AND d.class_type_idx=t.type_idx AND t.descriptor='Lfixture/Missing;' WHERE t.descriptor IS NULL";
        let rows = bridge.query(outer).unwrap();
        assert_eq!(rows.rows().len(), 20, "{dialect:?}");
        assert!(rows.rows().iter().all(|row| row[1] == SqlValue::Null));
    }
}
#[test]
fn native_class_relations_preserve_sources_nulls_and_interfaces() {
    use mdd_dex::definitions::DefinitionLimits;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inputs = [
        "tests/fixtures/definitions/generated/definitions-035.dex",
        "tests/fixtures/definitions/generated/definitions-035.dex",
        "tests/fixtures/class_source_boundary/generated/null-source.dex",
        "tests/fixtures/class_source_boundary/generated/empty-source.dex",
        "tests/fixtures/class_source_boundary/generated/surrogate-source.dex",
        "tests/fixtures/class_source_boundary/generated/root-empty-source.dex",
    ]
    .map(|path| InputSpec {
        path: root.join(path),
        kind: InputKind::RawDex,
        expected_sha256: None,
    });
    let snapshot = Snapshot::capture(&inputs, CaptureLimits::default()).unwrap();
    let mut occurrences = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        occurrences.push(Arc::new(
            DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap(),
        ));
    }
    let duplicate = DefinitionSqlProvider::new(
        vec![occurrences[0].clone(), occurrences[0].clone()],
        DecimalU64(0),
    );
    assert!(matches!(duplicate, Err(error) if error.code == ErrorCode::InvalidArgument));
    let source_ids: Vec<_> = occurrences
        .iter()
        .map(|facts| facts.metadata().source().dex_occurrence_id.to_string())
        .collect();
    let classes: usize = occurrences
        .iter()
        .map(|facts| facts.definitions().classes.len())
        .sum();
    let interfaces: usize = occurrences
        .iter()
        .map(|facts| facts.definitions().interfaces.len())
        .sum();
    let provider =
        Arc::new(DefinitionSqlProvider::new(occurrences.clone(), DecimalU64(0)).unwrap());
    let bridge =
        SqlBridge::new(provider.clone(), SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let result = bridge.query("SELECT dex_occurrence_id,class_def_idx,type_idx,descriptor,descriptor_mutf8,access_flags,superclass_type_idx,source_file_string_idx,source_file,source_file_mutf8 FROM native_classes").unwrap();
    assert_eq!(result.rows().len(), classes);
    for (index, facts) in occurrences.iter().enumerate() {
        for class in &facts.definitions().classes {
            let row = result.rows().iter().find(|row| matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == source_ids[index])
                && row[1] == SqlValue::U64(DecimalU64(u64::from(class.class_def_idx)))).unwrap();
            assert_eq!(
                row[2],
                SqlValue::U64(DecimalU64(u64::from(class.class_idx)))
            );
            assert!(
                matches!(&row[3], SqlValue::Text(text) if text.strict_utf8().unwrap() == class.descriptor)
            );
            assert_eq!(
                row[5],
                SqlValue::U64(DecimalU64(u64::from(class.access_flags)))
            );
            assert_eq!(
                row[6],
                class
                    .superclass_idx
                    .map_or(SqlValue::Null, |v| SqlValue::U64(DecimalU64(u64::from(v))))
            );
            match class.source_file_idx {
                None => assert_eq!(
                    (&row[7], &row[8], &row[9]),
                    (&SqlValue::Null, &SqlValue::Null, &SqlValue::Null)
                ),
                Some(idx) => {
                    let text = &facts.metadata().strings()[idx as usize].data.text;
                    assert_eq!(row[7], SqlValue::U64(DecimalU64(u64::from(idx))));
                    assert!(
                        matches!(&row[8], SqlValue::Text(value) if value.utf16 == text.utf16_units)
                    );
                    assert!(
                        matches!(&row[9], SqlValue::DexMutf8 {bytes, utf16_code_units} if *bytes == text.raw_mutf8 && utf16_code_units.0 == text.utf16_units.len() as u64)
                    );
                }
            }
        }
    }
    assert_ne!(source_ids[0], source_ids[1]);
    let boundary = |index: usize| {
        result.rows().iter().find(|row| matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == source_ids[index])).unwrap()
    };
    assert_eq!(boundary(2)[8], SqlValue::Null);
    assert!(matches!(&boundary(3)[8], SqlValue::Text(text) if text.utf16.is_empty()));
    assert!(matches!(&boundary(4)[8], SqlValue::Text(text) if text.utf16 == [0xd800]));
    assert!(
        matches!(&boundary(4)[9], SqlValue::DexMutf8 {bytes, ..} if *bytes == [0xed,0xa0,0x80])
    );
    assert_eq!(boundary(5)[6], SqlValue::Null);
    let interfaces_result = bridge.query("SELECT dex_occurrence_id,class_def_idx,class_type_idx,ordinal,interface_type_idx,descriptor,descriptor_mutf8 FROM native_class_interfaces").unwrap();
    assert_eq!(interfaces_result.rows().len(), interfaces);
    assert!(interfaces >= 2);
    for facts in &occurrences[..2] {
        let source_id = &facts.metadata().source().dex_occurrence_id;
        assert!(interfaces_result.rows().iter().any(|row| matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == *source_id)
            && row[3] == SqlValue::U64(DecimalU64(0))
            && matches!(&row[5], SqlValue::Text(text) if text.strict_utf8().unwrap() == "Lfixture/I1;")));
    }
    let limits = SqlLimits {
        max_cell_bytes: 1,
        ..SqlLimits::default()
    };
    let small = SqlBridge::new(provider, SqlDialect::NativeV1, limits).unwrap();
    assert_eq!(
        small
            .query("SELECT descriptor FROM native_classes")
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
}
#[test]
fn real_metadata_same_snapshot_duplicates_and_lossless_values() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/nonscalar-string-035.dex");
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
        facts.push(Arc::new(
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
        ));
    }
    let strings = facts[0].strings().len();
    let source_id = snapshot.manifest().snapshot_id.clone();
    let provider = Arc::new(MetadataSqlProvider::new(facts, DecimalU64(0)).unwrap());
    assert_eq!(provider.occurrence_count(), 2);
    drop(snapshot);
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let result=bridge.query("SELECT dex_occurrence_id,string_idx,value,raw_mutf8 FROM native_strings ORDER BY dex_occurrence_id,string_idx").unwrap();
    assert_eq!(result.binding().snapshot_id, source_id);
    assert_eq!(result.rows().len(), strings * 2);
    assert_ne!(result.rows()[0][0], result.rows()[strings][0]);
    assert!(
        result
            .rows()
            .iter()
            .any(|row| matches!(&row[2],SqlValue::Text(text) if text.strict_utf8().is_err()))
    );
    let count = bridge.query("SELECT COUNT(*) AS n FROM native_strings WHERE value = ?");
    assert!(count.is_err());
}

#[test]
fn native_types_and_prototypes_preserve_occurrences_and_parameter_order() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let snapshot_id = snapshot.manifest().snapshot_id.clone();
    let mut occurrences = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        occurrences.push(Arc::new(
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
        ));
    }
    let type_count = occurrences[0].types().len();
    let prototype_count = occurrences[0].prototypes().len();
    let provider = Arc::new(MetadataSqlProvider::new(occurrences, DecimalU64(0)).unwrap());
    drop(snapshot);
    let bridge =
        SqlBridge::new(provider.clone(), SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let types = bridge.query("SELECT dex_occurrence_id,type_idx,descriptor,descriptor_mutf8 FROM native_types ORDER BY dex_occurrence_id,type_idx").unwrap();
    assert_eq!(types.binding().snapshot_id, snapshot_id);
    assert_eq!(types.rows().len(), 2 * type_count);
    let mut source_ids = BTreeSet::new();
    let mut int_types = BTreeSet::new();
    for row in types.rows() {
        let (
            SqlValue::Text(source),
            SqlValue::U64(index),
            SqlValue::Text(descriptor),
            SqlValue::DexMutf8 { bytes, .. },
        ) = (&row[0], &row[1], &row[2], &row[3])
        else {
            panic!("unexpected native type row")
        };
        let source = source.strict_utf8().unwrap();
        source_ids.insert(source.clone());
        if descriptor.utf16 == [u16::from(b'I')] {
            assert_eq!(bytes, b"I");
            int_types.insert((source, index.0));
        }
    }
    assert_eq!(source_ids.len(), 2);
    assert_eq!(int_types.len(), 2);

    let prototypes = bridge.query("SELECT dex_occurrence_id,proto_idx,parameters_byte_offset,parameter_count,descriptor FROM native_prototypes ORDER BY dex_occurrence_id,proto_idx").unwrap();
    assert_eq!(prototypes.rows().len(), 2 * prototype_count);
    let mut one_parameter = BTreeSet::new();
    let mut no_parameter_sources = BTreeSet::new();
    for row in prototypes.rows() {
        let (
            SqlValue::Text(source),
            SqlValue::U64(index),
            _,
            SqlValue::U64(count),
            SqlValue::Text(descriptor),
        ) = (&row[0], &row[1], &row[2], &row[3], &row[4])
        else {
            panic!("unexpected prototype row")
        };
        let source = source.strict_utf8().unwrap();
        match descriptor.strict_utf8().unwrap().as_str() {
            "()V" => {
                assert_eq!(count.0, 0);
                assert_eq!(row[2], SqlValue::Null);
                no_parameter_sources.insert(source);
            }
            "(I)I" => {
                assert_eq!(count.0, 1);
                assert!(matches!(row[2], SqlValue::U64(_)));
                one_parameter.insert((source, index.0));
            }
            _ => (),
        }
    }
    assert_eq!(no_parameter_sources, source_ids);
    assert_eq!(one_parameter.len(), 2);
    let parameters = bridge.query("SELECT dex_occurrence_id,proto_idx,ordinal,type_idx FROM native_prototype_parameters ORDER BY dex_occurrence_id,proto_idx,ordinal").unwrap();
    let mut matched = BTreeSet::new();
    for row in parameters.rows() {
        let (
            SqlValue::Text(source),
            SqlValue::U64(proto),
            SqlValue::U64(ordinal),
            SqlValue::U64(kind),
        ) = (&row[0], &row[1], &row[2], &row[3])
        else {
            panic!("unexpected parameter row")
        };
        let source = source.strict_utf8().unwrap();
        if one_parameter.contains(&(source.clone(), proto.0)) {
            assert_eq!(ordinal.0, 0);
            assert!(int_types.contains(&(source.clone(), kind.0)));
            matched.insert((source, proto.0));
        }
    }
    assert_eq!(matched, one_parameter);
    // Exercise the fact cursor directly: with a one-byte SQLite length
    // limit, SQLite can reject virtual-table construction before xFilter.
    // That separate bridge error classification remains unqualified.
    let mut cursor = Arc::clone(&provider)
        .open_cursor(
            "native_types",
            SqlControl::new(
                SqlLimits {
                    max_cell_bytes: 1,
                    ..SqlLimits::default()
                },
                None,
            ),
        )
        .unwrap();
    let error = cursor.next_row().unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded, "{error:?}");
    drop(cursor);
    // Actual bridge must also preserve the quota error under the same
    // one-byte cell limit, rather than fail during virtual-table declaration.
    let limited = SqlBridge::new(
        provider,
        SqlDialect::NativeV1,
        SqlLimits {
            max_cell_bytes: 1,
            ..SqlLimits::default()
        },
    )
    .unwrap();
    let error = limited
        .query("SELECT descriptor FROM native_types")
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded, "{error:?}");
}

#[test]
fn schema_only_prepare_reuses_eponymous_connection_after_restoring_cell_limit() {
    use crate::virtual_tables::{self, Source, TEST_CONNECTS, TEST_OPENS};
    use rusqlite::{
        Connection,
        hooks::{AuthAction, AuthContext, Authorization},
        limits::Limit,
    };

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
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
    let facts =
        Arc::new(MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap());
    let provider = Arc::new(MetadataSqlProvider::new(vec![facts], DecimalU64(0)).unwrap());
    let relation = provider
        .relations()
        .unwrap()
        .into_iter()
        .find(|r| r.name == "native_types")
        .unwrap();
    let binding = provider.binding().clone();
    let control = SqlControl::new(
        SqlLimits {
            max_cell_bytes: 1,
            ..SqlLimits::default()
        },
        None,
    );
    let db = Connection::open_in_memory().unwrap();
    db.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0).unwrap();
    virtual_tables::register(
        &db,
        Arc::new(Source {
            provider,
            relation,
            binding,
            control: control.clone(),
            partition_key: None,
        }),
    )
    .unwrap();
    db.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
        AuthAction::Select => Authorization::Allow,
        AuthAction::Read { table_name, .. } if table_name.eq_ignore_ascii_case("native_types") => {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }))
    .unwrap();
    TEST_CONNECTS.with(|count| count.set(0));
    TEST_OPENS.with(|count| count.set(0));
    let warmup = db
        .prepare("SELECT * FROM \"native_types\" LIMIT 0")
        .unwrap();
    assert!(warmup.readonly());
    drop(warmup);
    assert_eq!(TEST_CONNECTS.with(|count| count.get()), 1);
    assert_eq!(TEST_OPENS.with(|count| count.get()), 0);
    db.set_limit(Limit::SQLITE_LIMIT_LENGTH, 65).unwrap();
    assert_eq!(db.limit(Limit::SQLITE_LIMIT_LENGTH).unwrap(), 65);
    let mut statement = db.prepare("SELECT descriptor FROM native_types").unwrap();
    assert!(statement.readonly());
    assert_eq!(
        TEST_CONNECTS.with(|count| count.get()),
        1,
        "SQLite reconnected the virtual table"
    );
    assert_eq!(TEST_OPENS.with(|count| count.get()), 0);
    let mut rows = statement.query([]).unwrap();
    assert!(
        rows.next().is_err(),
        "one-byte value budget unexpectedly returned a row"
    );
    assert_eq!(control.error().unwrap().code, ErrorCode::QuotaExceeded);
    assert_eq!(db.limit(Limit::SQLITE_LIMIT_LENGTH).unwrap(), 65);
    assert!(TEST_OPENS.with(|count| count.get()) > 0);
    drop(rows);
    drop(statement);
    assert!(db.prepare("SELECT name FROM sqlite_master").is_err());
    assert!(
        db.execute("ATTACH DATABASE ':memory:' AS other", [])
            .is_err()
    );
}
