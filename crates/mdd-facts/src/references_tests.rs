use super::*;
use crate::MetadataFacts;
use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
use mdd_input::{
    archive::{ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec},
};
use serde_json::Value;
use std::path::PathBuf;

struct Setup {
    snapshot: Snapshot,
    inventories: Vec<ArchiveInventory>,
    definitions: Vec<DefinitionFacts>,
    code: Vec<CodeFacts>,
}
fn setup(case: &str, count: usize) -> MddResult<Setup> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated")
        .join(format!("{case}.dex"));
    let specs = (0..count)
        .map(|_| InputSpec {
            path: path.clone(),
            kind: InputKind::RawDex,
            expected_sha256: None,
        })
        .collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default())?;
    let mut inventories = Vec::new();
    let mut definitions = Vec::new();
    let mut code = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())?;
        let metadata = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())?;
        definitions.push(DefinitionFacts::build(
            metadata,
            DefinitionLimits::default(),
        )?);
        code.push(CodeFacts::build_all_code_items(
            &snapshot,
            &inventory,
            0,
            CodeLimits::default(),
        )?);
        inventories.push(inventory);
    }
    Ok(Setup {
        snapshot,
        inventories,
        definitions,
        code,
    })
}
fn build(case: &str, limits: ReferenceLimits) -> MddResult<ReferenceFacts> {
    let data = setup(case, 1)?;
    ReferenceFacts::build(data.definitions[0].clone(), data.code[0].clone(), limits)
}
fn canonical(rows: &Value) -> Vec<String> {
    let mut values = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| serde_json::to_string(row).unwrap())
        .collect::<Vec<_>>();
    values.sort();
    values
}

/// References built from the compact code (the instructions of each caller decoded again, one at a time) are the
/// references built from the full code, and fail with the same error where those fail.
#[test]
fn references_from_compact_code_are_the_references_from_full_code() {
    let folder =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/references/generated");
    let mut cases: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            (path.extension()?.to_str()? == "dex")
                .then(|| path.file_stem().unwrap().to_string_lossy().into_owned())
        })
        .collect();
    cases.sort();
    let (mut built, mut refused, mut dynamic) = (0, 0, 0);
    for case in cases {
        let Ok(data) = setup(&case, 1) else { continue };
        let definitions = Arc::new(data.definitions[0].clone());
        let full = ReferenceFacts::build_arc(
            Arc::clone(&definitions),
            Arc::new(data.code[0].clone()),
            ReferenceLimits::default(),
        );
        let streamed = CodeFacts::build_all_code_items_compact(
            &data.snapshot,
            &data.inventories[0],
            0,
            CodeLimits::default(),
        )
        .unwrap();
        let (sidecar_code, sidecar_refs) = CodeFacts::build_all_code_items_compact_with_refs(
            &data.snapshot,
            &data.inventories[0],
            0,
            CodeLimits::default(),
        )
        .unwrap();
        let sidecar_built = ReferenceFacts::build_arc_with_compact_refs(
            Arc::clone(&definitions),
            Arc::new(sidecar_code),
            sidecar_refs,
            ReferenceLimits::default(),
        );
        for (compact_kind, from_compact) in [
            (
                "compacted",
                ReferenceFacts::build_arc(
                    Arc::clone(&definitions),
                    Arc::new(data.code[0].compacted().unwrap()),
                    ReferenceLimits::default(),
                ),
            ),
            (
                "streamed",
                ReferenceFacts::build_arc(
                    Arc::clone(&definitions),
                    Arc::new(streamed),
                    ReferenceLimits::default(),
                ),
            ),
            ("compact_with_refs", sidecar_built),
        ] {
            match (&full, &from_compact) {
                (Ok(full), Ok(compact)) => {
                    assert!(compact.code().is_compact(), "{case} ({compact_kind})");
                    for (name, left, right) in [
                        (
                            "sites",
                            serde_json::to_value(compact.sites()).unwrap(),
                            serde_json::to_value(full.sites()).unwrap(),
                        ),
                        (
                            "dynamic calls",
                            serde_json::to_value(compact.dynamic_calls()).unwrap(),
                            serde_json::to_value(full.dynamic_calls()).unwrap(),
                        ),
                        (
                            "coverage",
                            serde_json::to_value(compact.coverage()).unwrap(),
                            serde_json::to_value(full.coverage()).unwrap(),
                        ),
                        (
                            "usage",
                            serde_json::to_value(compact.usage()).unwrap(),
                            serde_json::to_value(full.usage()).unwrap(),
                        ),
                    ] {
                        assert_eq!(left, right, "{case} ({compact_kind}): {name}");
                    }
                    assert_eq!(
                        compact.call_site_metadata().is_some(),
                        full.call_site_metadata().is_some(),
                        "{case} ({compact_kind})"
                    );
                    assert_eq!(
                        compact.method_handle_metadata().is_some(),
                        full.method_handle_metadata().is_some(),
                        "{case} ({compact_kind})"
                    );
                    if let Some(first_site) = full.sites().first() {
                        let target = full
                            .target_id(first_site.target_kind, first_site.target_local_index)
                            .unwrap();
                        assert_eq!(
                            compact.find_target_indexed(&target).unwrap(),
                            full.find_target_indexed(&target).unwrap(),
                            "{case} ({compact_kind}): indexed lookup"
                        );
                    }
                    dynamic += compact.dynamic_calls().len();
                    built += 1;
                }
                (Err(full), Err(compact)) => {
                    assert_eq!(
                        serde_json::to_value(compact).unwrap(),
                        serde_json::to_value(full).unwrap(),
                        "{case} ({compact_kind})"
                    );
                    refused += 1;
                }
                (Ok(_), Err(error)) => {
                    panic!("{case} ({compact_kind}): only the compact build fails: {error:?}")
                }
                (Err(error), Ok(_)) => {
                    panic!("{case} ({compact_kind}): only the full build fails: {error:?}")
                }
            }
        }
    }
    assert!(
        built >= 10 && refused >= 6 && dynamic >= 1,
        "{built} built, {refused} refused, {dynamic} dynamic calls"
    );
}

#[test]
fn exact_site_lookup_preserves_occurrence_and_complete_scope() {
    let data = setup("poly-custom-038", 2).unwrap();
    let left = ReferenceFacts::build(
        data.definitions[0].clone(),
        data.code[0].clone(),
        ReferenceLimits::default(),
    )
    .unwrap();
    let right = ReferenceFacts::build(
        data.definitions[1].clone(),
        data.code[1].clone(),
        ReferenceLimits::default(),
    )
    .unwrap();
    assert!(!left.sites().is_empty());
    let limit = left.sites().len() as u64;
    for site in left.sites() {
        let id = left.site_id(site.site_ordinal).unwrap();
        let resolved = left.site_by_id(&id, limit).unwrap().unwrap();
        assert_eq!(resolved.site_ordinal, site.site_ordinal);
        assert_eq!(
            left.raw_operand(resolved.site_ordinal).unwrap(),
            left.raw_operand(site.site_ordinal).unwrap()
        );
        assert_eq!(
            right.site_by_id(&id, limit).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }
    let id = left.site_id(0).unwrap();
    assert_eq!(
        left.site_by_id(&id, limit - 1).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    let mut missing = id.clone();
    missing.code_unit_pc = u32::MAX;
    assert!(left.site_by_id(&missing, limit).unwrap().is_none());
    let mut wrong_kind = id.clone();
    wrong_kind.caller_method_definition.kind = EntityKind::MethodReference;
    assert_eq!(
        left.site_by_id(&wrong_kind, limit).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let mut partial = left.clone();
    partial.coverage.facts = Completeness::Partial;
    assert_eq!(
        partial.site_by_id(&id, limit).unwrap_err().code,
        ErrorCode::IncompleteFacts
    );
    let mut duplicate = left.clone();
    duplicate.sites.push(duplicate.sites[0].clone());
    assert_eq!(
        duplicate.site_by_id(&id, limit + 1).unwrap_err().code,
        ErrorCode::InternalFault
    );
}

#[test]
fn borrowed_string_sites_preserve_nonscalar_bytes_occurrences_and_coverage() {
    let data = setup("nonscalar-string-035", 2).unwrap();
    let mut occurrences = Vec::new();
    for ordinal in 0..2 {
        let facts = ReferenceFacts::build(
            data.definitions[ordinal].clone(),
            data.code[ordinal].clone(),
            ReferenceLimits::default(),
        )
        .unwrap();
        let sites = facts
            .string_reference_sites(StringReferenceViewLimits::default())
            .unwrap()
            .collect::<MddResult<Vec<_>>>()
            .unwrap();
        let expected = facts
            .sites()
            .iter()
            .filter(|site| site.target_kind == TargetKind::String)
            .count();
        assert!(expected > 0);
        assert_eq!(sites.len(), expected);
        for view in sites {
            assert_eq!(
                view.source.snapshot_id,
                data.snapshot.manifest().snapshot_id
            );
            assert_eq!(view.site.target_kind, TargetKind::String);
            assert_eq!(view.site.caller_method_idx, view.caller.method_idx);
            assert_eq!(view.site.target_local_index, view.string.data.string_idx);
            assert_eq!(view.string.data.text.utf16_units, [0xd800]);
            assert_eq!(view.string.data.text.raw_mutf8, [0xed, 0xa0, 0x80]);
            assert_eq!(view.string_pool.string_pool_id, view.string.string_pool_id);
            assert_eq!(
                facts.raw_operand(view.site.site_ordinal).unwrap().len() as u64,
                view.site.operand_range.byte_length.0
            );
        }
        assert_eq!(
            facts
                .string_reference_sites(StringReferenceViewLimits {
                    max_scanned_sites: 0,
                    ..StringReferenceViewLimits::default()
                })
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        let visits = (facts.sites().len() as u64) * 2;
        assert_eq!(
            facts
                .string_reference_sites(StringReferenceViewLimits {
                    max_scanned_sites: visits - 1,
                    ..StringReferenceViewLimits::default()
                })
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts
                .string_reference_sites(StringReferenceViewLimits {
                    max_scanned_sites: visits,
                    ..StringReferenceViewLimits::default()
                })
                .unwrap()
                .count(),
            expected
        );
        assert_eq!(
            facts
                .string_reference_sites(StringReferenceViewLimits {
                    max_result_sites: 0,
                    ..StringReferenceViewLimits::default()
                })
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        occurrences.push(facts.source().dex_occurrence_id.clone());
    }
    assert_ne!(occurrences[0], occurrences[1]);

    let partial = CodeFacts::build_offsets(
        &data.snapshot,
        &data.inventories[0],
        0,
        &[],
        CodeLimits::default(),
    )
    .unwrap();
    let facts = ReferenceFacts::build(
        data.definitions[0].clone(),
        partial,
        ReferenceLimits::default(),
    )
    .unwrap();
    assert_eq!(facts.coverage().facts, Completeness::Partial);
    assert_eq!(
        facts
            .string_reference_sites(StringReferenceViewLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn borrowed_method_calls_match_independent_oracle_and_preserve_sites() {
    let data = setup("shared-code-035", 2).unwrap();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bytes = std::fs::read(root.join("tests/fixtures/references/oracle-results.json")).unwrap();
    assert_eq!(
        mdd_types::sha256(&bytes),
        "2a4decaf563592449229a9a494c804609b686fc8bbe4eb4cb21cf588db3070ad"
    );
    let oracle: Value = serde_json::from_slice(&bytes).unwrap();
    let sample = oracle["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["path"] == "tests/fixtures/references/generated/shared-code-035.dex")
        .unwrap();
    let mut expected: Vec<_> = sample["relations"]["method_calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["method_idx"].as_u64().unwrap(),
                row["callee_method_idx"].as_u64().unwrap(),
                row["method"].as_str().unwrap().to_owned(),
                row["callee"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    expected.sort();
    let mut sources = Vec::new();
    for index in 0..2 {
        let facts = ReferenceFacts::build(
            data.definitions[index].clone(),
            data.code[index].clone(),
            ReferenceLimits::default(),
        )
        .unwrap();
        let limit = NamedReferenceViewLimits {
            max_scanned_sites: (facts.sites.len() as u64) * 2,
            max_result_sites: expected.len() as u64,
        };
        let sites = facts
            .method_call_sites(limit)
            .unwrap()
            .collect::<MddResult<Vec<_>>>()
            .unwrap();
        let mut actual: Vec<_> = sites
            .iter()
            .map(|row| {
                assert_eq!(
                    row.source.dex_occurrence_id,
                    facts.source().dex_occurrence_id
                );
                assert!(row.site.invoke_kind.is_some());
                assert_eq!(
                    facts.raw_operand(row.site.site_ordinal).unwrap().len() as u64,
                    row.site.operand_range.byte_length.0
                );
                (
                    u64::from(row.caller.method_idx),
                    u64::from(row.callee.method_idx),
                    row.caller.descriptor.clone(),
                    row.callee.descriptor.clone(),
                )
            })
            .collect();
        actual.sort();
        assert_eq!(actual, expected);
        assert_eq!(
            facts
                .method_call_sites(NamedReferenceViewLimits {
                    max_scanned_sites: limit.max_scanned_sites - 1,
                    ..limit
                })
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts
                .method_call_sites(NamedReferenceViewLimits {
                    max_result_sites: limit.max_result_sites - 1,
                    ..limit
                })
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        let mut partial = facts.clone();
        partial.coverage.facts = Completeness::Partial;
        assert_eq!(
            partial.method_call_sites(limit).err().unwrap().code,
            ErrorCode::IncompleteFacts
        );
        let mut noncall = facts.clone();
        noncall
            .sites
            .retain(|site| site.target_kind == TargetKind::Method && site.invoke_kind.is_some());
        for site in &mut noncall.sites {
            site.invoke_kind = None;
        }
        assert_eq!(
            noncall
                .method_call_sites(NamedReferenceViewLimits::default())
                .unwrap()
                .count(),
            0
        );
        sources.push(facts.source().dex_occurrence_id.clone());
    }
    assert_ne!(sources[0], sources[1]);
}

#[test]
fn borrowed_named_sites_preserve_target_kind_occurrences_and_coverage() {
    let data = setup("shared-code-035", 2).unwrap();
    let mut occurrences = Vec::new();
    for ordinal in 0..2 {
        let facts = ReferenceFacts::build(
            data.definitions[ordinal].clone(),
            data.code[ordinal].clone(),
            ReferenceLimits::default(),
        )
        .unwrap();
        for (kind, expected) in [
            (NamedReferenceKind::Method, 8),
            (NamedReferenceKind::Field, 4),
            (NamedReferenceKind::Type, 4),
        ] {
            let views = facts
                .named_reference_sites(kind, NamedReferenceViewLimits::default())
                .unwrap()
                .collect::<MddResult<Vec<_>>>()
                .unwrap();
            assert_eq!(views.len(), expected, "{kind:?}");
            let mut site_ids = BTreeSet::new();
            for view in views {
                assert_eq!(
                    view.source.snapshot_id,
                    data.snapshot.manifest().snapshot_id
                );
                assert_eq!(
                    view.source.dex_occurrence_id,
                    facts.source().dex_occurrence_id
                );
                assert_eq!(view.site.caller_method_idx, view.caller.method_idx);
                assert_eq!(view.site.target_kind, kind.target_kind());
                match view.target {
                    NamedReferenceTarget::Method(target) => {
                        assert_eq!(kind, NamedReferenceKind::Method);
                        assert_eq!(target.method_idx, view.site.target_local_index);
                    }
                    NamedReferenceTarget::Field(target) => {
                        assert_eq!(kind, NamedReferenceKind::Field);
                        assert_eq!(target.field_idx, view.site.target_local_index);
                    }
                    NamedReferenceTarget::Type(target) => {
                        assert_eq!(kind, NamedReferenceKind::Type);
                        assert_eq!(target.data.type_idx, view.site.target_local_index);
                        assert_eq!(
                            target.entity.dex_occurrence_id,
                            view.source.dex_occurrence_id
                        );
                    }
                }
                assert_eq!(
                    facts.raw_operand(view.site.site_ordinal).unwrap().len() as u64,
                    view.site.operand_range.byte_length.0
                );
                site_ids.insert(
                    serde_json::to_string(&facts.site_id(view.site.site_ordinal).unwrap()).unwrap(),
                );
            }
            assert_eq!(site_ids.len(), expected, "{kind:?}");
            let visits = (facts.sites().len() as u64) * 2;
            assert_eq!(
                facts
                    .named_reference_sites(
                        kind,
                        NamedReferenceViewLimits {
                            max_scanned_sites: visits - 1,
                            ..NamedReferenceViewLimits::default()
                        },
                    )
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
            assert_eq!(
                facts
                    .named_reference_sites(
                        kind,
                        NamedReferenceViewLimits {
                            max_result_sites: 0,
                            ..NamedReferenceViewLimits::default()
                        },
                    )
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
        occurrences.push(facts.source().dex_occurrence_id.clone());
    }
    assert_ne!(occurrences[0], occurrences[1]);

    let partial = CodeFacts::build_offsets(
        &data.snapshot,
        &data.inventories[0],
        0,
        &[],
        CodeLimits::default(),
    )
    .unwrap();
    let facts = ReferenceFacts::build(
        data.definitions[0].clone(),
        partial,
        ReferenceLimits::default(),
    )
    .unwrap();
    for kind in [
        NamedReferenceKind::Method,
        NamedReferenceKind::Field,
        NamedReferenceKind::Type,
    ] {
        assert_eq!(
            facts
                .named_reference_sites(kind, NamedReferenceViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
    }
}
fn target_method(facts: &DefinitionFacts, name: &str) -> u32 {
    facts
        .definitions()
        .method_references
        .iter()
        .find(|method| method.method_name == name)
        .unwrap()
        .method_idx
}

#[test]
fn all_hand_fixtures_match_independent_sites_ranges_and_complete_rows() {
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/references/oracle-results.json"
    ))
    .unwrap();
    let mut accepted = 0;
    let mut rejected = 0;
    for reference in oracle["results"].as_array().unwrap() {
        let case = PathBuf::from(reference["path"].as_str().unwrap())
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let result = build(&case, ReferenceLimits::default());
        if reference["status"] == "invalid" {
            let error = result
                .err()
                .unwrap_or_else(|| panic!("invalid fixture accepted: {case}"));
            assert_eq!(error.code, ErrorCode::InvalidInput, "{case}: {error}");
            rejected += 1;
            continue;
        }
        let facts = result.unwrap_or_else(|error| panic!("{case}: {error}"));
        facts.require_complete().unwrap();
        accepted += 1;
        assert_eq!(
            facts.sites().len(),
            reference["sites"].as_array().unwrap().len(),
            "{case}"
        );
        let mut ids = BTreeSet::new();
        for (site, expected) in facts
            .sites()
            .iter()
            .zip(reference["sites"].as_array().unwrap())
        {
            assert_eq!(
                u64::from(site.caller_method_idx),
                expected["caller_method_idx"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(site.code_unit_pc),
                expected["pc"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(site.operand_ordinal),
                expected["operand_ordinal"].as_u64().unwrap()
            );
            assert_eq!(
                serde_json::to_value(site.target_kind).unwrap(),
                expected["kind"]
            );
            assert_eq!(
                u64::from(site.target_local_index),
                expected["index"].as_u64().unwrap()
            );
            assert_eq!(
                site.operand_range.byte_offset.0,
                expected["byte_offset"].as_u64().unwrap()
            );
            assert_eq!(
                site.operand_range.byte_length.0,
                expected["byte_length"].as_u64().unwrap()
            );
            let raw = facts.raw_operand(site.site_ordinal).unwrap();
            let actual = if raw.len() == 4 {
                u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
            } else {
                u32::from(u16::from_le_bytes([raw[0], raw[1]]))
            };
            assert_eq!(actual, site.target_local_index);
            ids.insert(serde_json::to_string(&facts.site_id(site.site_ordinal).unwrap()).unwrap());
            let target = facts
                .target_id(site.target_kind, site.target_local_index)
                .unwrap();
            assert_eq!(
                facts.find_target_indexed(&target).unwrap(),
                facts.find_target_scalar(&target).unwrap()
            );
        }
        assert_eq!(
            ids.len(),
            facts.sites().len(),
            "each caller/PC/operand identity must remain distinct"
        );
        if reference["plain_scalar_string_projection"] == true {
            assert_eq!(
                canonical(&serde_json::to_value(facts.method_string_rows(0).unwrap()).unwrap()),
                canonical(&reference["relations"]["method_strings"]),
                "{case} strings"
            );
        } else {
            assert_eq!(
                facts.method_string_rows(0).err().unwrap().code,
                ErrorCode::UnsupportedQuery
            );
            let index = facts
                .sites()
                .iter()
                .find(|site| site.target_kind == TargetKind::String)
                .unwrap()
                .target_local_index;
            assert_eq!(
                facts.definitions().metadata().strings()[index as usize]
                    .data
                    .text
                    .utf16_units,
                [0xd800]
            );
        }
        for (name, rows) in [
            (
                "method_calls",
                serde_json::to_value(facts.method_call_rows(0).unwrap()).unwrap(),
            ),
            (
                "method_field_accesses",
                serde_json::to_value(facts.method_field_rows(0).unwrap()).unwrap(),
            ),
            (
                "method_used_types",
                serde_json::to_value(facts.method_type_rows(0).unwrap()).unwrap(),
            ),
        ] {
            assert_eq!(
                canonical(&rows),
                canonical(&reference["relations"][name]),
                "{case} {name}"
            );
        }
        assert_eq!(
            facts.dynamic_calls().len(),
            reference["dynamic_calls"].as_array().unwrap().len()
        );
        assert_eq!(
            facts.coverage().unowned_physical_code_items as usize,
            reference["unowned_code_offsets"].as_array().unwrap().len()
        );
    }
    assert_eq!((accepted, rejected), (11, 7));
}

#[test]
fn shared_code_expands_callers_without_counting_projection_duplicates_or_fake_callers() {
    let shared = build("shared-code-035", ReferenceLimits::default()).unwrap();
    assert_eq!(shared.sites().len(), 20);
    assert_eq!(shared.method_call_rows(0).unwrap().len(), 8);
    assert_eq!(shared.coverage().no_body_methods, 1);
    let orphan = build("orphan-code-035", ReferenceLimits::default()).unwrap();
    assert_eq!(orphan.coverage().unowned_physical_code_items, 1);
    assert_eq!(orphan.sites().len(), 10);
    let data = setup("classic-035", 1).unwrap();
    let offsets = data.code[0]
        .declared_code_item_byte_offsets()
        .iter()
        .map(|offset| offset.0 as u32)
        .collect::<Vec<_>>();
    let projected = CodeFacts::build_offsets(
        &data.snapshot,
        &data.inventories[0],
        0,
        &[offsets[0], offsets[0], offsets[1]],
        CodeLimits::default(),
    )
    .unwrap();
    let facts = ReferenceFacts::build(
        data.definitions[0].clone(),
        projected,
        ReferenceLimits::default(),
    )
    .unwrap();
    assert_eq!(facts.sites().len(), 10);
    facts.require_complete().unwrap();
}

#[test]
fn partial_or_missing_code_never_becomes_complete_empty_rows() {
    let data = setup("classic-035", 1).unwrap();
    let target = data.definitions[0]
        .definitions()
        .method_definitions
        .iter()
        .find(|method| {
            data.definitions[0].definitions().method_references[method.method_idx as usize]
                .method_name
                == "target"
        })
        .unwrap();
    let MethodBody::Present {
        code_byte_offset, ..
    } = target.body
    else {
        panic!("target body")
    };
    let code = CodeFacts::build_offsets(
        &data.snapshot,
        &data.inventories[0],
        0,
        &[code_byte_offset.0 as u32],
        CodeLimits::default(),
    )
    .unwrap();
    let facts = ReferenceFacts::build(
        data.definitions[0].clone(),
        code,
        ReferenceLimits::default(),
    )
    .unwrap();
    assert_eq!(facts.coverage().facts, Completeness::Partial);
    assert!(facts.sites().is_empty());
    assert_eq!(
        facts.require_complete().err().unwrap().code,
        ErrorCode::IncompleteFacts
    );
    assert_eq!(
        facts.method_call_rows(0).err().unwrap().code,
        ErrorCode::IncompleteFacts
    );
    let index = facts
        .definitions()
        .metadata()
        .strings()
        .iter()
        .find(|item| item.data.text.strict_utf8().ok().as_deref() == Some("repeat"))
        .unwrap()
        .data
        .string_idx;
    let target = facts.target_id(TargetKind::String, index).unwrap();
    let matches = facts.find_target_indexed(&target).unwrap();
    assert!(matches.sites.is_empty());
    assert_eq!(matches.coverage, Completeness::Partial);
    assert!(!matches.absence_proven_within_encoded_operand_scope);
}

#[test]
fn source_and_snapshot_guards_reject_local_id_cross_joins() {
    let data = setup("classic-035", 2).unwrap();
    assert_eq!(
        ReferenceFacts::build(
            data.definitions[0].clone(),
            data.code[1].clone(),
            ReferenceLimits::default()
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::InvalidArgument
    );
    let a = ReferenceFacts::build(
        data.definitions[0].clone(),
        data.code[0].clone(),
        ReferenceLimits::default(),
    )
    .unwrap();
    let b = ReferenceFacts::build(
        data.definitions[1].clone(),
        data.code[1].clone(),
        ReferenceLimits::default(),
    )
    .unwrap();
    assert_ne!(a.site_id(0).unwrap(), b.site_id(0).unwrap());
    assert_eq!(a.source().snapshot_id, b.source().snapshot_id);
    let foreign = b
        .target_id(TargetKind::String, b.sites()[0].target_local_index)
        .unwrap();
    assert_eq!(
        a.find_target_indexed(&foreign).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn ordinary_scope_does_not_consume_unrelated_annotations_and_custom_does_not_fake_callee() {
    let ordinary = build(
        "ordinary-unrelated-bad-annotation",
        ReferenceLimits::default(),
    )
    .unwrap();
    assert!(ordinary.call_site_metadata().is_none());
    assert!(ordinary.method_handle_metadata().is_none());
    assert_eq!(ordinary.method_call_rows(0).unwrap().len(), 4);
    let custom = build("poly-custom-038", ReferenceLimits::default()).unwrap();
    assert_eq!(custom.dynamic_calls().len(), 2);
    assert_eq!(custom.method_call_rows(0).unwrap().len(), 6);
    assert!(custom.dynamic_calls().iter().all(|call| {
        call.runtime_target_status
            .contains("unknown_dynamic_target")
    }));
    assert!(
        custom
            .method_call_rows(0)
            .unwrap()
            .iter()
            .all(|row| row.callee_name != "bootstrap")
    );
    let handles = build("handles-039", ReferenceLimits::default()).unwrap();
    assert_eq!(handles.method_handle_metadata().unwrap().len(), 2);
    assert_eq!(handles.method_call_rows(0).unwrap().len(), 4);
    assert_eq!(handles.method_field_rows(0).unwrap().len(), 2);
}

#[test]
fn csr_target_index_matches_independent_per_target_scan() {
    for case in ["classic-035", "shared-code-035", "poly-custom-038"] {
        let facts = build(case, ReferenceLimits::default()).unwrap();
        let mut expected: BTreeMap<(TargetKind, u32), Vec<u32>> = BTreeMap::new();
        for site in facts.sites() {
            expected
                .entry((site.target_kind, site.target_local_index))
                .or_default()
                .push(site.site_ordinal);
        }
        let index = facts.target_index();
        assert_eq!(index.target_count(), expected.len(), "{case}");
        assert_eq!(index.keys, expected.keys().copied().collect::<Vec<_>>());
        for (key, ordinals) in &expected {
            assert_eq!(
                index.postings(key.0, key.1),
                ordinals.as_slice(),
                "{case} {key:?}"
            );
            let target = facts.target_id(key.0, key.1).unwrap();
            assert_eq!(
                facts
                    .find_target_indexed(&target)
                    .unwrap()
                    .sites
                    .iter()
                    .map(|site| site.operand_ordinal)
                    .collect::<Vec<_>>(),
                facts
                    .find_target_scalar(&target)
                    .unwrap()
                    .sites
                    .iter()
                    .map(|site| site.operand_ordinal)
                    .collect::<Vec<_>>(),
                "{case} {key:?}"
            );
        }
        for site in facts.sites() {
            let target = facts
                .target_id(site.target_kind, site.target_local_index)
                .unwrap();
            assert_eq!(
                facts.find_target_indexed(&target).unwrap(),
                facts.find_target_scalar(&target).unwrap(),
                "{case} site {}",
                site.site_ordinal
            );
        }
    }
}

#[test]
fn dynamic_call_reference_view_preserves_oracle_sites_and_sources() {
    let data = setup("poly-custom-038", 2).unwrap();
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/references/oracle-results.json"
    ))
    .unwrap();
    let expected = oracle["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["path"]
                .as_str()
                .unwrap()
                .ends_with("/poly-custom-038.dex")
        })
        .unwrap()["dynamic_calls"]
        .as_array()
        .unwrap();
    let mut occurrences = Vec::new();
    for ordinal in 0..2 {
        let facts = ReferenceFacts::build(
            data.definitions[ordinal].clone(),
            data.code[ordinal].clone(),
            ReferenceLimits::default(),
        )
        .unwrap();
        let visits = facts.sites().len() as u64 + 2 * facts.dynamic_calls().len() as u64;
        let limits = NamedReferenceViewLimits {
            max_scanned_sites: visits,
            max_result_sites: expected.len() as u64,
        };
        let calls = facts
            .dynamic_call_reference_sites(limits)
            .unwrap()
            .collect::<MddResult<Vec<_>>>()
            .unwrap();
        assert_eq!(calls.len(), expected.len());
        for (call, row) in calls.iter().zip(expected) {
            assert_eq!(
                u64::from(call.caller.method_idx),
                row["caller_method_idx"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(call.site.code_unit_pc),
                row["pc"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(call.dynamic.call_site_idx),
                row["call_site_idx"].as_u64().unwrap()
            );
            assert!(
                call.dynamic
                    .runtime_target_status
                    .contains(row["runtime_target"].as_str().unwrap())
            );
            assert_eq!(
                call.source.dex_occurrence_id,
                facts.source().dex_occurrence_id
            );
        }
        assert_eq!(
            facts
                .dynamic_call_reference_sites(NamedReferenceViewLimits {
                    max_scanned_sites: visits - 1,
                    ..limits
                })
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts
                .dynamic_call_reference_sites(NamedReferenceViewLimits {
                    max_result_sites: 1,
                    ..limits
                })
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        occurrences.push(facts.source().dex_occurrence_id.clone());
        let mut partial = facts.clone();
        partial.coverage.facts = Completeness::Partial;
        assert_eq!(
            partial
                .dynamic_call_reference_sites(limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut duplicate = facts.clone();
        duplicate.dynamic_calls[1].site_ordinal = duplicate.dynamic_calls[0].site_ordinal;
        assert_eq!(
            duplicate
                .dynamic_call_reference_sites(limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
        let mut broken = facts.clone();
        broken.dynamic_calls[0].call_site_idx += 1;
        assert_eq!(
            broken
                .dynamic_call_reference_sites(limits)
                .unwrap()
                .next()
                .unwrap()
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
    }
    assert_ne!(occurrences[0], occurrences[1]);
    let ordinary = build("classic-035", ReferenceLimits::default()).unwrap();
    assert_eq!(
        ordinary
            .dynamic_call_reference_sites(NamedReferenceViewLimits::default())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn index_and_scalar_definition_search_keep_world_scope_external_and_ambiguity() {
    let data = setup("defined-field-035", 2).unwrap();
    let facts = vec![&data.definitions[0], &data.definitions[1]];
    let inventories = data.inventories.iter().collect::<Vec<_>>();
    let complete = DefinitionWorld::from_complete_selected_inputs(
        &data.snapshot,
        &inventories,
        &facts,
        DefinitionSearchLimits::default(),
    )
    .unwrap();
    let provided =
        DefinitionWorld::from_provided(&facts[..1], DefinitionSearchLimits::default()).unwrap();
    let unbuilt = DefinitionWorld::unbuilt(&data.snapshot);
    for method in &data.definitions[0].definitions().method_references {
        let indexed = complete
            .resolve_method_reference(&data.definitions[0], method.method_idx)
            .unwrap();
        let scalar = complete
            .resolve_method_scalar(&data.definitions[0], method.method_idx)
            .unwrap();
        assert_eq!(
            serde_json::to_value(indexed).unwrap(),
            serde_json::to_value(scalar).unwrap()
        );
    }
    for field in &data.definitions[0].definitions().field_references {
        assert_eq!(
            serde_json::to_value(
                complete
                    .resolve_field_reference(&data.definitions[0], field.field_idx)
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(
                complete
                    .resolve_field_scalar(&data.definitions[0], field.field_idx)
                    .unwrap()
            )
            .unwrap()
        );
    }
    let target = target_method(&data.definitions[0], "target");
    let ambiguous = complete
        .resolve_method_reference(&data.definitions[0], target)
        .unwrap();
    assert_eq!(
        ambiguous.state,
        DefinitionResolutionState::AmbiguousDefinitionsInScope
    );
    assert_eq!(ambiguous.candidates.len(), 2);
    assert_ne!(
        ambiguous.candidates[0].definition,
        ambiguous.candidates[1].definition
    );
    let one = provided
        .resolve_method_reference(&data.definitions[0], target)
        .unwrap();
    assert_eq!(one.state, DefinitionResolutionState::OneDefinitionInScope);
    assert!(!one.search_scope_covers_selected_inputs);
    let external = target_method(&data.definitions[0], "external");
    let unknown = provided
        .resolve_method_reference(&data.definitions[0], external)
        .unwrap();
    assert_eq!(
        unknown.state,
        DefinitionResolutionState::NoDefinitionInProvidedFacts
    );
    assert!(!unknown.absence_proven_in_selected_inputs);
    let absent = complete
        .resolve_method_reference(&data.definitions[0], external)
        .unwrap();
    assert_eq!(
        absent.state,
        DefinitionResolutionState::NoDefinitionInSelectedInputs
    );
    assert!(absent.absence_proven_in_selected_inputs);
    assert!(absent.runtime_resolution.contains("not_inferred"));
    assert_eq!(
        unbuilt
            .resolve_method_reference(&data.definitions[0], target)
            .unwrap()
            .state,
        DefinitionResolutionState::NotBuilt
    );
    assert_eq!(
        DefinitionWorld::from_complete_selected_inputs(
            &data.snapshot,
            &inventories,
            &facts[..1],
            DefinitionSearchLimits::default()
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::IncompleteFacts
    );
    let foreign = setup("classic-035", 1).unwrap();
    assert_eq!(
        complete
            .resolve_method_reference(&foreign.definitions[0], 0)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        DefinitionWorld::from_provided(
            &[facts[0], &foreign.definitions[0]],
            DefinitionSearchLimits::default()
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn caller_site_expansion_query_and_search_budgets_fail_before_partial_success() {
    for limits in [
        ReferenceLimits {
            max_callers: 0,
            ..ReferenceLimits::default()
        },
        ReferenceLimits {
            max_sites: 0,
            ..ReferenceLimits::default()
        },
        ReferenceLimits {
            max_expanded_code_units: 0,
            ..ReferenceLimits::default()
        },
        ReferenceLimits {
            max_fact_bytes: 0,
            ..ReferenceLimits::default()
        },
    ] {
        assert_eq!(
            build("shared-code-035", limits).err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
    }
    let facts = build(
        "classic-035",
        ReferenceLimits {
            max_lookup_candidates: 0,
            ..ReferenceLimits::default()
        },
    )
    .unwrap();
    let target = facts
        .target_id(
            facts.sites()[0].target_kind,
            facts.sites()[0].target_local_index,
        )
        .unwrap();
    assert_eq!(
        facts.find_target_indexed(&target).err().unwrap().code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        facts.find_target_scalar(&target).err().unwrap().code,
        ErrorCode::QuotaExceeded
    );
    let facts = build(
        "classic-035",
        ReferenceLimits {
            max_projection_bytes: 0,
            ..ReferenceLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        facts.method_call_rows(0).err().unwrap().code,
        ErrorCode::QuotaExceeded
    );
    let data = setup("classic-035", 1).unwrap();
    assert_eq!(
        DefinitionWorld::from_provided(
            &[&data.definitions[0]],
            DefinitionSearchLimits {
                max_definitions: 0,
                ..DefinitionSearchLimits::default()
            }
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::QuotaExceeded
    );
}

#[test]
fn physical_invalid_body_is_not_downgraded_to_unbuilt_partial_scope() {
    let data = setup("bad-body-interior-pointer", 1).unwrap();
    let projected = CodeFacts::build_offsets(
        &data.snapshot,
        &data.inventories[0],
        0,
        &[],
        CodeLimits::default(),
    )
    .unwrap();
    let error = ReferenceFacts::build(
        data.definitions[0].clone(),
        projected,
        ReferenceLimits::default(),
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.details["reason"], "METHOD_BODY_NOT_CODE_ITEM_START");
}

#[test]
fn custom_narrow_metadata_scope_and_definition_candidate_budget_are_explicit() {
    let custom = build(
        "poly-custom-unrelated-bad-annotation",
        ReferenceLimits::default(),
    )
    .unwrap();
    assert_eq!(custom.dynamic_calls().len(), 2);
    assert!(custom.call_site_metadata().is_some());
    custom.require_complete().unwrap();
    let data = setup("classic-035", 2).unwrap();
    let world = DefinitionWorld::from_provided(
        &[&data.definitions[0], &data.definitions[1]],
        DefinitionSearchLimits {
            max_candidates: 1,
            ..DefinitionSearchLimits::default()
        },
    )
    .unwrap();
    let index = target_method(&data.definitions[0], "target");
    assert_eq!(
        world
            .resolve_method_reference(&data.definitions[0], index)
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        world
            .resolve_method_scalar(&data.definitions[0], index)
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
}
