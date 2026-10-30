use super::facts::{MemoryCatalog, NativeCatalog, OccurrenceFacts, ReferenceCatalog, Table};
use super::*;
use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
use mdd_facts::{
    EntityKind, EntityRef, MetadataFacts,
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
