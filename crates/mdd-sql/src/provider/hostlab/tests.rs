//! Contract-level tests for the seventeen HostLab relation names.
//!
//! Every test runs against real fixtures and, where an A0 observation exists,
//! compares the bridge result to that recorded table instead of to a value the
//! engine itself produced. The A0 tables live under `artifacts/mdd-026` and are
//! read-only inputs here.
use super::*;
use crate::{SqlBridge, SqlResult, control::SqlLimits, dialects::SqlDialect};
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_facts::{
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    references::{ReferenceFacts, ReferenceLimits},
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(relative: &str) -> PathBuf {
    root().join(relative)
}

/// One captured snapshot, its inventories and the selected scope.
struct Harness {
    snapshot: Snapshot,
    inventories: Vec<ArchiveInventory>,
    scope: SelectedScope,
    /// Cached `(metadata, definitions, code, references, annotations)` per
    /// selected roster position, built on first use.
    layers: Mutex<Vec<Option<CachedLayers>>>,
}

#[derive(Clone, Default)]
struct CachedLayers {
    metadata: Option<Arc<MetadataFacts>>,
    definitions: Option<Arc<DefinitionFacts>>,
}

fn open(inputs: &[(&str, InputKind)]) -> Harness {
    let specs: Vec<InputSpec> = inputs
        .iter()
        .map(|(relative, kind)| InputSpec {
            path: fixture(relative),
            kind: *kind,
            expected_sha256: None,
        })
        .collect();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default()).unwrap();
    let inventories: Vec<ArchiveInventory> = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap()
        })
        .collect();
    let scope = SelectedScope::from_inventories(&snapshot, &inventories.iter().collect::<Vec<_>>())
        .unwrap();
    let slots = scope.dexes().len();
    Harness {
        snapshot,
        inventories,
        scope,
        layers: Mutex::new(vec![None; slots]),
    }
}

impl Harness {
    /// Map a selected-roster position back to `(inventory, local DEX index)`.
    fn locate(&self, roster_position: usize) -> (&ArchiveInventory, usize) {
        let mut remaining = roster_position;
        for inventory in &self.inventories {
            let count = inventory.selected_dexes().len();
            if remaining < count {
                return (inventory, remaining);
            }
            remaining -= count;
        }
        panic!("roster position outside the captured inventories");
    }

    fn layers(&self, roster_position: usize) -> CachedLayers {
        let mut slots = self.layers.lock().unwrap();
        if let Some(cached) = &slots[roster_position] {
            return cached.clone();
        }
        let (inventory, local) = self.locate(roster_position);
        let metadata = Arc::new(
            MetadataFacts::build(&self.snapshot, inventory, local, StringLimits::default())
                .unwrap(),
        );
        let definitions = Arc::new(
            DefinitionFacts::build_arc(Arc::clone(&metadata), DefinitionLimits::default()).unwrap(),
        );
        let cached = CachedLayers {
            metadata: Some(metadata),
            definitions: Some(definitions),
        };
        slots[roster_position] = Some(cached.clone());
        cached
    }

    fn provider(&self, code: bool, references: bool, annotations: bool) -> Arc<HostLabSqlProvider> {
        let mut facts = Vec::new();
        for position in 0..self.scope.dexes().len() {
            let base = self.layers(position);
            let metadata = base.metadata.clone().unwrap();
            let definitions = base.definitions.clone().unwrap();
            let (inventory, local) = self.locate(position);
            let code_facts = if code || references {
                Some(Arc::new(
                    CodeFacts::build_all_code_items(
                        &self.snapshot,
                        inventory,
                        local,
                        CodeLimits::default(),
                    )
                    .unwrap(),
                ))
            } else {
                None
            };
            let reference_facts = if references {
                Some(Arc::new(
                    ReferenceFacts::build_arc(
                        Arc::clone(&definitions),
                        Arc::clone(code_facts.as_ref().unwrap()),
                        ReferenceLimits::default(),
                    )
                    .unwrap(),
                ))
            } else {
                None
            };
            let annotation_facts = if annotations {
                Some(Arc::new(
                    AnnotationFacts::build((*definitions).clone(), AnnotationLimits::default())
                        .unwrap(),
                ))
            } else {
                None
            };
            facts.push(HostLabOccurrenceFacts {
                metadata,
                definitions: Some(definitions),
                code: code_facts,
                references: reference_facts,
                annotations: annotation_facts,
            });
        }
        Arc::new(HostLabSqlProvider::from_scope(&self.scope, facts, DecimalU64(0)).unwrap())
    }

    fn bridge(&self, dialect: SqlDialect) -> SqlBridge {
        SqlBridge::new(
            self.provider(true, true, true),
            dialect,
            SqlLimits::default(),
        )
        .unwrap()
    }
}

fn cell_text(value: &SqlValue) -> Option<String> {
    match value {
        SqlValue::Null => None,
        SqlValue::U64(value) => Some(value.0.to_string()),
        SqlValue::I64(value) => Some(value.0.to_string()),
        SqlValue::F64(bits) => Some(f64::from_bits(bits.0).to_string()),
        SqlValue::Text(text) => text.strict_utf8().ok(),
        other => panic!("unexpected cell carrier {other:?}"),
    }
}

fn row_strings(result: &SqlResult) -> Vec<Vec<Option<String>>> {
    result
        .rows()
        .iter()
        .map(|row| row.iter().map(cell_text).collect())
        .collect()
}

/// Parse one recorded A0 markdown table into `(header, rows)`.
fn read_a0_table(relative: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let text = std::fs::read_to_string(fixture(relative)).unwrap();
    let mut header: Option<Vec<String>> = None;
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|cell| cell.trim().to_owned())
            .collect();
        if header.is_none() {
            header = Some(cells);
            continue;
        }
        if cells
            .iter()
            .all(|cell| cell.chars().all(|c| c == '-' || c == '+' || c == ' '))
        {
            continue;
        }
        rows.push(cells);
    }
    (header.unwrap(), rows)
}

/// A0 renders every cell as hex of the text form, with `N` for NULL.
fn a0_text(cell: &str) -> Option<String> {
    if cell == "N" {
        return None;
    }
    if cell.is_empty() {
        return Some(String::new());
    }
    let bytes = (0..cell.len() / 2)
        .map(|index| u8::from_str_radix(&cell[index * 2..index * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>();
    Some(String::from_utf8(bytes).unwrap())
}

fn contract_relation(name: &str) -> serde_json::Value {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture("conformance/manifests/relations.json")).unwrap(),
    )
    .unwrap();
    manifest["relations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|relation| relation["name"] == name)
        .unwrap()
        .clone()
}

#[test]
fn dex_files_registers_every_contract_column_and_matches_a0_rows() {
    // Q01 `inventory` and Q01 `pool_mapping` over two distinct raw DEX inputs,
    // compared row by row with the recorded A0 table for the same inputs.
    let harness = open(&[
        (
            "tests/fixtures/references/generated/classic-035.dex",
            InputKind::RawDex,
        ),
        (
            "tests/fixtures/references/generated/shared-code-035.dex",
            InputKind::RawDex,
        ),
    ]);
    let provider = harness.provider(false, false, false);
    let relations = provider.relations().unwrap();
    let dex_files = relations
        .iter()
        .find(|relation| relation.name == "dex_files")
        .unwrap();
    assert_eq!(dex_files.columns.len(), 28);
    let contract = contract_relation("dex_files");
    let expected_columns: Vec<&str> = contract["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|column| column["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        dex_files
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        expected_columns
    );
    let bridge = SqlBridge::new(provider, SqlDialect::DexSql011, SqlLimits::default()).unwrap();
    let inventory = bridge
        .query("SELECT file_id,entry_name FROM dex_files ORDER BY file_id")
        .unwrap();
    let (header, recorded) = read_a0_table(
        "artifacts/mdd-026/cross-dex-audit/20261028T164250980578Z/a0-dex-files-two-distinct-raw/stdout.txt",
    );
    assert_eq!(
        header,
        ["file_id", "string_pool_id", "source_path", "entry_name"]
    );
    let position = |name: &str| header.iter().position(|cell| cell == name).unwrap();
    let expected: Vec<Vec<Option<String>>> = recorded
        .iter()
        .map(|row| {
            vec![
                a0_text(&row[position("file_id")]),
                a0_text(&row[position("entry_name")]),
            ]
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(row_strings(&inventory), expected);

    let pool_mapping = bridge
        .query("SELECT file_id,string_pool_id FROM dex_files ORDER BY file_id")
        .unwrap();
    let expected_pools: Vec<Vec<Option<String>>> = recorded
        .iter()
        .map(|row| {
            vec![
                a0_text(&row[position("file_id")]),
                a0_text(&row[position("string_pool_id")]),
            ]
        })
        .collect();
    assert_eq!(row_strings(&pool_mapping), expected_pools);

    // `entry_name` is the raw-DEX member label the snapshot layer produced and
    // can be compared with A0 verbatim. `source_path` is the captured input path
    // of *this* checkout, so it is checked against that value rather than
    // against the path recorded on the machine that produced the A0 table.
    let provenance = bridge
        .query("SELECT file_id,source_path,entry_name FROM dex_files ORDER BY file_id")
        .unwrap();
    // A0 recorded the `source_path` of the machine that produced the table, so
    // only the basename and the `entry_name` are comparable here; both inputs
    // are raw DEX captures, whose `entry_name` is the captured file's name.
    let paths = [
        fixture("tests/fixtures/references/generated/classic-035.dex"),
        fixture("tests/fixtures/references/generated/shared-code-035.dex"),
    ];
    for ((row, a0), expected_path) in provenance.rows().iter().zip(&recorded).zip(&paths) {
        assert_eq!(
            cell_text(&row[1]),
            Some(expected_path.to_str().unwrap().to_owned())
        );
        assert_eq!(cell_text(&row[2]), a0_text(&a0[position("entry_name")]));
    }

    // The full 28-column shape must also be answerable.
    let all = bridge
        .query("SELECT * FROM dex_files ORDER BY file_id")
        .unwrap();
    assert_eq!(all.columns().len(), 28);
    assert!(all.calculation_complete());
    assert_eq!(all.rows().len(), 2);
}

#[test]
fn strings_and_types_match_recorded_a0_rows_value_for_value() {
    // `strings` and `types` are metadata-only relations; the recorded A0 tables
    // for the same fixture are compared row by row, including NULL/empty
    // distinction and order.
    let harness = open(&[(
        "tests/fixtures/definitions/generated/definitions-035.dex",
        InputKind::RawDex,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let (header, recorded) = read_a0_table(
        "artifacts/mdd-026/column-audit-v10/_probe-verify_type_text_atoms/20261109T045613053519Z/a0-types-definitions/stdout.txt",
    );
    let position = |name: &str| header.iter().position(|cell| cell == name).unwrap();
    let result = bridge
        .query("SELECT file_id,type_idx,descriptor,java_name FROM types ORDER BY type_idx")
        .unwrap();
    let expected: Vec<Vec<Option<String>>> = recorded
        .iter()
        .map(|row| {
            ["file_id", "type_idx", "descriptor", "java_name"]
                .iter()
                .map(|name| a0_text(&row[position(name)]))
                .collect()
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(row_strings(&result), expected);
}

#[test]
fn methods_match_recorded_a0_rows_value_for_value() {
    // The 14-column `methods` relation, including the opcode and
    // parameter-descriptor tokenizer columns, is compared with A0 verbatim.
    let harness = open(&[(
        "tests/fixtures/definitions/generated/definitions-035.dex",
        InputKind::RawDex,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let (header, recorded) = read_a0_table(
        "artifacts/mdd-026/column-audit-v10/_probe-verify_method_atoms/20261109T045613053519Z/a0-definitions/stdout.txt",
    );
    let position = |name: &str| header.iter().position(|cell| cell == name).unwrap();
    let columns = [
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
    let result = bridge
        .query(&format!(
            "SELECT {} FROM methods ORDER BY method_idx",
            columns.join(",")
        ))
        .unwrap();
    let expected: Vec<Vec<Option<String>>> = recorded
        .iter()
        .map(|row| {
            columns
                .iter()
                .map(|name| a0_text(&row[position(name)]))
                .collect()
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(row_strings(&result), expected);
}

#[test]
fn annotation_elements_convert_integers_and_floats_exactly() {
    // `annotation_elements.value_i64`/`value_f64` are the two carrier
    // conversions this module performs. The fixture encodes negative integers,
    // NaN, infinity and zero; each must keep its exact value and stay distinct
    // from NULL.
    let harness = open(&[(
        "tests/fixtures/annotations/generated/annotations-038.dex",
        InputKind::RawDex,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let rows = bridge
        .query("SELECT value_kind,value_i64,value_f64 FROM annotation_elements WHERE value_i64 IS NOT NULL OR value_f64 IS NOT NULL ORDER BY annotation_off,ordinal")
        .unwrap();
    assert!(!rows.rows().is_empty());
    let mut saw_negative = false;
    let mut saw_nan = false;
    let mut saw_infinite = false;
    let mut saw_zero_float = false;
    for row in rows.rows() {
        let kind = cell_text(&row[0]).unwrap();
        match (row[1].clone(), row[2].clone()) {
            (SqlValue::I64(value), SqlValue::Null) => {
                assert!(
                    matches!(
                        kind.as_str(),
                        "byte" | "short" | "int" | "long" | "char" | "boolean"
                    ),
                    "{kind}"
                );
                if value.0 < 0 {
                    saw_negative = true;
                }
            }
            (SqlValue::Null, SqlValue::F64(bits)) => {
                assert!(matches!(kind.as_str(), "float" | "double"), "{kind}");
                let value = f64::from_bits(bits.0);
                if value.is_nan() {
                    saw_nan = true;
                } else if value.is_infinite() {
                    saw_infinite = true;
                } else if value == 0.0 {
                    saw_zero_float = true;
                }
            }
            other => panic!("unexpected value carrier pair {other:?} for kind {kind}"),
        }
    }
    // The fixture is known to carry all four shapes; asserting them prevents a
    // future parser change from silently narrowing this test to nothing.
    assert!(saw_negative, "no negative integer value observed");
    assert!(saw_nan, "no NaN float value observed");
    assert!(saw_infinite, "no infinite float value observed");
    assert!(saw_zero_float, "no zero float value observed");
}

/// Parse one `### <relation>` block of the recorded A0 readback.
///
/// The readback is plain (non-hex) output, so `NULL` is the only sentinel and an
/// empty cell is the empty string, which must stay distinct from NULL.
struct A0Block {
    input: String,
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

fn read_a0_readback_blocks() -> std::collections::BTreeMap<String, A0Block> {
    let text = std::fs::read_to_string(fixture(
        "artifacts/mdd-032-audit/relation-registration-20261111/a0-readback.txt",
    ))
    .unwrap();
    let mut blocks = std::collections::BTreeMap::new();
    let mut current: Option<(String, String)> = None;
    let mut header: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("### ") {
            if let Some((name, input)) = current.take() {
                blocks.insert(
                    name,
                    A0Block {
                        input,
                        header: std::mem::take(&mut header),
                        rows: std::mem::take(&mut rows),
                    },
                );
            }
            // `### <relation>  input=<path relative to the repository root>`
            let mut fields = rest.split_whitespace();
            let name = fields.next().unwrap().to_owned();
            let input = rest
                .split_once("input=")
                .map(|(_, path)| path.trim().to_owned())
                .expect("readback block must name its input");
            current = Some((name, input));
            continue;
        }
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|cell| cell.trim().to_owned())
            .collect();
        if header.is_empty() {
            header = cells;
            continue;
        }
        if cells
            .iter()
            .all(|cell| cell.chars().all(|c| c == '-' || c == '+' || c == ' '))
        {
            continue;
        }
        rows.push(cells);
    }
    if let Some((name, input)) = current {
        blocks.insert(
            name,
            A0Block {
                input,
                header,
                rows,
            },
        );
    }
    blocks
}

/// Parse the two float spellings A0 and Rust use, so the comparison is on the
/// binary64 value rather than on a formatting convention.
fn parse_float_text(text: &str) -> Option<f64> {
    match text {
        "NaN" | "nan" => Some(f64::NAN),
        "Inf" | "inf" | "Infinity" | "infinity" => Some(f64::INFINITY),
        "-Inf" | "-inf" | "-Infinity" | "-infinity" => Some(f64::NEG_INFINITY),
        other => other.parse::<f64>().ok(),
    }
}

fn readback_text(cell: &str) -> Option<String> {
    if cell == "NULL" {
        None
    } else {
        Some(cell.to_owned())
    }
}

#[test]
fn every_relation_matches_the_recorded_a0_readback_row_for_row() {
    // The readback was produced by the frozen backend
    // (`dexsql-windows-amd64.exe`, sha256:f354ebcf…) over the input named in
    // each block, so each relation is compared on exactly that snapshot rather
    // than on a combined multi-input roster.
    let blocks = read_a0_readback_blocks();
    assert_eq!(blocks.len(), 17, "readback must cover all 17 relations");
    for (relation, sql) in A0_READBACK_QUERIES {
        let block = blocks
            .get(*relation)
            .unwrap_or_else(|| panic!("readback block {relation} missing"));
        assert!(!block.rows.is_empty(), "{relation} readback is empty");
        let kind = if block.input.ends_with(".apk") {
            InputKind::Apk
        } else {
            InputKind::RawDex
        };
        let harness = open(&[(&*block.input, kind)]);
        let bridge = harness.bridge(SqlDialect::DexSql011);
        let result = bridge
            .query(sql)
            .unwrap_or_else(|error| panic!("{relation}: {error:?}"));
        assert_eq!(
            result.columns(),
            block.header.as_slice(),
            "{relation} column order and names"
        );
        let actual: Vec<Vec<Option<String>>> = row_strings(&result);
        let expected: Vec<Vec<Option<String>>> = block
            .rows
            .iter()
            .map(|row| row.iter().map(|cell| readback_text(cell)).collect())
            .collect();
        assert_eq!(actual.len(), expected.len(), "{relation} row count");
        let float_column = block.header.iter().position(|column| column == "value_f64");
        for (ordinal, (actual_row, expected_row)) in actual.iter().zip(&expected).enumerate() {
            for (column, (actual_cell, expected_cell)) in
                actual_row.iter().zip(expected_row).enumerate()
            {
                if Some(column) == float_column {
                    // A0 renders the float as text (`1.0`, `Inf`, `NaN`, `-0`)
                    // while this engine renders the same binary64 with Rust's
                    // shortest form (`1`, `inf`, `-0`). The contract value is the
                    // bit pattern, so the two texts are parsed and compared as
                    // bits; anything else stays an exact string comparison.
                    match (actual_cell, expected_cell) {
                        (None, None) => continue,
                        (Some(actual), Some(expected)) => {
                            let actual = parse_float_text(actual);
                            let expected = parse_float_text(expected);
                            assert_eq!(
                                actual.map(f64::to_bits),
                                expected.map(f64::to_bits),
                                "{relation} row {ordinal} column {column}: {actual:?} != {expected:?}"
                            );
                            continue;
                        }
                        other => panic!("{relation} row {ordinal} NULL mismatch: {other:?}"),
                    }
                }
                assert_eq!(
                    actual_cell, expected_cell,
                    "{relation} row {ordinal} column {}",
                    block.header[column]
                );
            }
        }
    }
}

/// The exact A0 statements recorded in `a0-readback.txt`, one per relation.
const A0_READBACK_QUERIES: &[(&str, &str)] = &[
    (
        "dex_files",
        "SELECT file_id,string_pool_id,entry_name FROM dex_files ORDER BY file_id",
    ),
    (
        "strings",
        "SELECT string_pool_id,string_idx,value FROM strings ORDER BY string_pool_id,string_idx LIMIT 5",
    ),
    (
        "types",
        "SELECT file_id,type_idx,descriptor,java_name FROM types ORDER BY type_idx",
    ),
    (
        "methods",
        "SELECT file_id,method_idx,class_idx,param_descriptors,opcode_count,opcode_hex,method_kind FROM methods ORDER BY method_idx",
    ),
    (
        "classes",
        "SELECT file_id,class_def_idx,class_idx,descriptor,access_flags,superclass_descriptor,interface_count,source_file FROM classes ORDER BY class_def_idx",
    ),
    (
        "class_interfaces",
        "SELECT file_id,class_idx,ordinal,interface_type_idx,interface_descriptor FROM class_interfaces ORDER BY file_id,class_idx,ordinal",
    ),
    (
        "class_fields",
        "SELECT file_id,class_idx,class_descriptor,field_idx,field_name,field_descriptor,kind,access_flags FROM class_fields ORDER BY file_id,class_idx,kind,field_idx",
    ),
    (
        "class_methods",
        "SELECT file_id,class_idx,class_descriptor,method_idx,method_name,method_descriptor,kind,access_flags FROM class_methods ORDER BY file_id,class_idx,kind,method_idx",
    ),
    (
        "code_items",
        "SELECT file_id,method_idx,code_off,registers_size,ins_size,outs_size,tries_size,debug_info_off,insns_size,insns_off,tries_off,handlers_off FROM code_items ORDER BY method_idx",
    ),
    (
        "annotation_directory_entries",
        "SELECT file_id,class_idx,annotations_off,entry_kind,entry_idx,annotation_set_off,annotation_set_ref_list_off FROM annotation_directory_entries ORDER BY file_id,class_idx,entry_kind,entry_idx",
    ),
    (
        "annotation_set_entries",
        "SELECT file_id,annotation_set_off,ordinal,annotation_off FROM annotation_set_entries ORDER BY file_id,annotation_set_off,ordinal",
    ),
    (
        "annotations",
        "SELECT file_id,annotation_off,visibility,type_idx,element_count FROM annotations ORDER BY file_id,annotation_off",
    ),
    (
        "annotation_elements",
        "SELECT file_id,annotation_off,depth,ordinal,name_idx,value_off,value_end_off,value_kind,value_index,value_i64,value_f64 FROM annotation_elements ORDER BY file_id,annotation_off,ordinal LIMIT 30",
    ),
    (
        "method_strings",
        "SELECT method,method_class,method_name,value,file_id,class_idx,method_idx,string_idx FROM method_strings ORDER BY file_id,method_idx",
    ),
    (
        "method_calls",
        "SELECT method,method_class,method_name,callee,callee_class,callee_name,file_id,class_idx,method_idx,callee_method_idx FROM method_calls ORDER BY file_id,method_idx",
    ),
    (
        "method_field_accesses",
        "SELECT method,method_class,method_name,field,field_class,field_name,field_type,using_type,file_id,class_idx,method_idx,field_idx FROM method_field_accesses ORDER BY file_id,method_idx",
    ),
    (
        "method_used_types",
        "SELECT method,method_class,method_name,type_descriptor,type_name,file_id,class_idx,method_idx,type_idx FROM method_used_types ORDER BY file_id,method_idx",
    ),
];

#[test]
fn dex_files_uses_archive_roster_order_not_numeric_member_order() {
    // A0 (`dexsql-windows-amd64.exe`, sha256:f354ebcf…) answers this exact
    // archive in ZIP enumeration order: classes10.dex first. A numeric
    // "classes<N>.dex" rule would answer classes2.dex first.
    let harness = open(&[("tests/fixtures/generated/member-policy.apk", InputKind::Apk)]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let result = bridge
        .query("SELECT file_id,entry_name FROM dex_files ORDER BY file_id")
        .unwrap();
    assert_eq!(
        row_strings(&result),
        vec![
            vec![Some("0".into()), Some("classes10.dex".into())],
            vec![Some("1".into()), Some("classes2.dex".into())],
        ]
    );
}

#[test]
fn dex_files_string_pool_ids_follow_occurrence_not_physical_pool() {
    // Two selected occurrences share one byte-identical member; A0 still gives
    // them pool ids 0 and 1 because the pool is a selected-occurrence
    // coordinate, not a content hash.
    let harness = open(&[(
        "tests/fixtures/generated/duplicate-content.apk",
        InputKind::Apk,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let result = bridge
        .query("SELECT file_id,string_pool_id,entry_name FROM dex_files ORDER BY file_id")
        .unwrap();
    assert_eq!(
        row_strings(&result),
        vec![
            vec![
                Some("0".into()),
                Some("0".into()),
                Some("classes.dex".into())
            ],
            vec![
                Some("1".into()),
                Some("1".into()),
                Some("classes2.dex".into())
            ],
        ]
    );
    let rows = bridge
        .query("SELECT string_pool_id,string_idx,value FROM strings ORDER BY string_pool_id,string_idx")
        .unwrap();
    // Both pools expose their own identically numbered strings; a shared
    // physical pool must not collapse the two occurrences into one.
    let pools: std::collections::BTreeSet<String> = rows
        .rows()
        .iter()
        .filter_map(|row| cell_text(&row[0]))
        .collect();
    assert_eq!(
        pools,
        ["0".to_owned(), "1".to_owned()].into_iter().collect()
    );
    assert!(!rows.rows().is_empty());
}

#[test]
fn dex_files_provenance_is_the_resolved_snapshot_and_inventory_value() {
    // `source_path` is the captured input path and `entry_name` the archive
    // member name for the same occurrence; neither is re-derived here.
    let harness = open(&[(
        "tests/fixtures/generated/multidex-stored.apk",
        InputKind::Apk,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let result = bridge
        .query("SELECT file_id,source_path,entry_name FROM dex_files ORDER BY file_id")
        .unwrap();
    assert_eq!(result.rows().len(), 2);
    let expected_path = fixture("tests/fixtures/generated/multidex-stored.apk")
        .to_str()
        .unwrap()
        .to_owned();
    for (position, row) in result.rows().iter().enumerate() {
        assert_eq!(cell_text(&row[1]), Some(expected_path.clone()));
        let expected_name = if position == 0 {
            "classes.dex"
        } else {
            "classes2.dex"
        };
        assert_eq!(cell_text(&row[2]), Some(expected_name.to_owned()));
    }
    // A raw DEX capture has no archive member, so the resolver reports the
    // captured file's own name. Empty text and NULL must never appear.
    let raw = open(&[(
        "tests/fixtures/references/generated/classic-035.dex",
        InputKind::RawDex,
    )]);
    let raw_bridge = raw.bridge(SqlDialect::DexSql011);
    let raw_result = raw_bridge
        .query("SELECT source_path,entry_name FROM dex_files")
        .unwrap();
    assert_eq!(
        cell_text(&raw_result.rows()[0][1]),
        Some("classic-035.dex".into())
    );
    assert!(cell_text(&raw_result.rows()[0][0]).is_some_and(|path| !path.is_empty()));
}

#[test]
fn provenance_gap_mapping_names_the_column_and_keeps_the_cause() {
    // The provider cannot fabricate a non-UTF-8 capture path on this platform,
    // so the mapping itself is exercised directly: it must name the column,
    // state the NOT NULL contract, and preserve the upstream error identity.
    let harness = open(&[(
        "tests/fixtures/references/generated/classic-035.dex",
        InputKind::RawDex,
    )]);
    let provider = harness.provider(false, false, false);
    let cause = MddError::new(
        ErrorCode::UnsupportedQuery,
        "facts.scope_provenance",
        "captured source has no lossless UTF-8 path representation",
    )
    .detail("reason", "SOURCE_PATH_NOT_UTF8");
    let occurrence = &provider.occurrences[0];
    let error = provenance_gap(occurrence, "source_path", cause);
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    assert_eq!(error.details["column"], "source_path");
    assert_eq!(error.details["nullable_contract"], "false");
    assert_eq!(error.details["cause_code"], "UNSUPPORTED_QUERY");
    assert_eq!(error.details["cause_reason"], "SOURCE_PATH_NOT_UTF8");
    assert!(error.details.contains_key("dex_occurrence_id"));
}

#[test]
fn coverage_ledger_gates_each_relation_on_the_layers_that_prove_it() {
    let harness = open(&[(
        "tests/fixtures/references/generated/classic-035.dex",
        InputKind::RawDex,
    )]);
    // With every layer attached the ledger proves all seventeen relations.
    let full = harness.provider(true, true, true);
    for relation in HostLabRelation::ALL {
        full.require_coverage(relation)
            .unwrap_or_else(|error| panic!("{}: {error:?}", relation.name()));
    }
    // Code without the reference layer cannot prove method-to-body bindings
    // (ADR-017 keeps `MethodBindings` and `AllMethodBodies` distinct), so the
    // relations built on those bodies are refused and the refusal names the layer.
    let partial = harness.provider(true, false, true);
    for relation in [HostLabRelation::Methods, HostLabRelation::CodeItems] {
        let error = partial.require_coverage(relation).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::IncompleteFacts,
            "{}",
            relation.name()
        );
        assert_eq!(error.details["relation"], relation.name());
        assert!(
            error.details["first_blocking_issues"]
                .as_str()
                .unwrap()
                .contains("MethodBindings"),
            "{error:?}"
        );
    }
    let error = partial
        .require_coverage(HostLabRelation::MethodCalls)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    // Relations whose layers are all attached are not affected.
    for relation in [
        HostLabRelation::DexFiles,
        HostLabRelation::Strings,
        HostLabRelation::Classes,
        HostLabRelation::ClassFields,
        HostLabRelation::AnnotationSetEntries,
    ] {
        partial
            .require_coverage(relation)
            .unwrap_or_else(|error| panic!("{}: {error:?}", relation.name()));
    }
    // The gate also guards the direct cursor path, not only `require_relation`:
    // a consumer that opens a cursor without asking first still gets a refusal.
    let direct = Arc::clone(&partial)
        .open_cursor(
            "methods",
            crate::control::SqlControl::new(SqlLimits::default(), None),
        )
        .map(|_| ())
        .unwrap_err();
    assert_eq!(direct.code, ErrorCode::IncompleteFacts);
    assert!(
        Arc::clone(&full)
            .open_cursor(
                "methods",
                crate::control::SqlControl::new(SqlLimits::default(), None),
            )
            .is_ok()
    );
    // The verdict is computed once and replayed, refusals included.
    let again = partial
        .require_coverage(HostLabRelation::Methods)
        .unwrap_err();
    assert_eq!(again.details["first_blocking_issues"], {
        partial
            .require_coverage(HostLabRelation::Methods)
            .unwrap_err()
            .details["first_blocking_issues"]
            .clone()
    });
}

#[test]
fn every_contract_relation_name_is_registered_with_its_contract_columns() {
    let harness = open(&[(
        "tests/fixtures/references/generated/classic-035.dex",
        InputKind::RawDex,
    )]);
    let provider = harness.provider(true, true, true);
    let relations = provider.relations().unwrap();
    let mut registered: Vec<&str> = relations.iter().map(|r| r.name.as_str()).collect();
    registered.sort_unstable();
    let mut expected: Vec<&str> = HostLabRelation::ALL.iter().map(|r| r.name()).collect();
    expected.sort_unstable();
    assert_eq!(registered, expected);
    // Column names, order, carrier type and nullability come from the contract
    // manifest, not from a hand-maintained duplicate.
    for relation in &relations {
        let contract = contract_relation(&relation.name);
        assert_eq!(
            contract["columns"].as_array().unwrap().len(),
            relation.columns.len(),
            "{}",
            relation.name
        );
        for (position, column) in relation.columns.iter().enumerate() {
            let expected_column = &contract["columns"][position];
            assert_eq!(column.name, expected_column["name"].as_str().unwrap());
            assert_eq!(
                column.nullable,
                expected_column["nullable"].as_bool().unwrap(),
                "{}.{}",
                relation.name,
                column.name
            );
            let carrier = match expected_column["data_type"].as_str().unwrap() {
                "UInt32" | "UInt64" => SqlType::U64,
                "Int64" => SqlType::I64,
                "Float64" => SqlType::F64,
                "Utf8" | "Utf8View" => SqlType::Text,
                other => panic!("unmapped contract type {other}"),
            };
            assert_eq!(
                column.data_type, carrier,
                "{}.{}",
                relation.name, column.name
            );
        }
    }
}

#[test]
fn q02_class_surfaces_match_a0_rows() {
    let harness = open(&[(
        "tests/fixtures/definitions/generated/definitions-035.dex",
        InputKind::RawDex,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let (header, recorded) = read_a0_table(
        "artifacts/mdd-026/column-audit-v10/ordered-a0/20261109T052446057985Z/class_fields/stdout.txt",
    );
    let position = |name: &str| header.iter().position(|cell| cell == name).unwrap();
    let result = bridge
        .query("SELECT file_id,class_idx,class_descriptor,field_idx,field_name,field_descriptor,kind,access_flags FROM class_fields ORDER BY file_id,class_idx,kind,field_idx")
        .unwrap();
    let expected: Vec<Vec<Option<String>>> = recorded
        .iter()
        .map(|row| {
            [
                "file_id",
                "class_idx",
                "class_descriptor",
                "field_idx",
                "field_name",
                "field_descriptor",
                "kind",
                "access_flags",
            ]
            .iter()
            .map(|name| a0_text(&row[position(name)]))
            .collect()
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(row_strings(&result), expected);

    let classes = bridge
        .query("SELECT file_id,class_def_idx,class_idx,descriptor,access_flags,superclass_descriptor FROM classes ORDER BY file_id,class_idx")
        .unwrap();
    assert_eq!(classes.rows().len(), 4);
    let method_wildcard = bridge
        .query("SELECT cm.* FROM class_methods cm WHERE class_descriptor IN ('Lfixture/Base;') ORDER BY file_id,class_idx,kind,method_idx")
        .unwrap();
    assert_eq!(method_wildcard.columns().len(), 8);
    assert_eq!(method_wildcard.rows().len(), 5);
}

#[test]
fn q03_interface_join_is_answerable() {
    let harness = open(&[(
        "tests/fixtures/definitions/generated/definitions-035.dex",
        InputKind::RawDex,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let result = bridge
        .query("SELECT ci.interface_descriptor,c.descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE c.descriptor IN ('Lfixture/Base;') ORDER BY ci.file_id,ci.class_idx,ci.ordinal")
        .unwrap();
    assert_eq!(
        row_strings(&result),
        vec![vec![
            Some("Lfixture/I1;".into()),
            Some("Lfixture/Base;".into())
        ]]
    );
}

#[test]
fn q04_annotation_chain_is_answerable() {
    let harness = open(&[(
        "tests/fixtures/annotations/generated/annotations-038.dex",
        InputKind::RawDex,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    for sql in [
        "SELECT file_id,type_idx FROM types WHERE descriptor='Ldalvik/annotation/Signature;' ORDER BY file_id,type_idx",
        "SELECT file_id,entry_kind,entry_idx,annotation_set_off FROM annotation_directory_entries ORDER BY file_id,entry_kind,entry_idx",
        "SELECT file_id,annotation_set_off,annotation_off FROM annotation_set_entries ORDER BY file_id,annotation_set_off,ordinal",
        "SELECT file_id,annotation_off,type_idx FROM annotations ORDER BY file_id,annotation_off",
        "SELECT file_id,annotation_off,ordinal,value_index FROM annotation_elements WHERE depth=1 AND value_kind='string' ORDER BY file_id,annotation_off,ordinal",
        "SELECT string_pool_id,string_idx,value FROM strings ORDER BY string_pool_id,string_idx",
    ] {
        let result = bridge
            .query(sql)
            .unwrap_or_else(|error| panic!("{sql}: {error:?}"));
        assert!(!result.rows().is_empty(), "{sql} returned no rows");
    }
}

#[test]
fn q05_q06_q07_q10_q11_q12_are_answerable() {
    let harness = open(&[
        (
            "tests/fixtures/references/generated/classic-035.dex",
            InputKind::RawDex,
        ),
        (
            "tests/fixtures/references/generated/poly-custom-038.dex",
            InputKind::RawDex,
        ),
    ]);
    for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
        let bridge = harness.bridge(dialect);
        for (label, sql) in [
            (
                "Q05",
                "SELECT DISTINCT m.class_descriptor FROM class_methods c JOIN methods m ON m.file_id=c.file_id AND m.method_idx=c.method_idx WHERE m.return_descriptor='V' ORDER BY m.class_descriptor",
            ),
            (
                "Q06",
                "SELECT DISTINCT file_id,method_idx,value FROM method_strings WHERE method_class IN ('Lfixture/A;') AND (value LIKE '%repeat%' OR value LIKE '%pref\\_x%' ESCAPE '\\') ORDER BY file_id,method_idx,value",
            ),
            ("Q07", "SELECT COUNT(*) AS n FROM classes ORDER BY n"),
            (
                "Q10",
                "SELECT file_id,method,callee,COUNT(*) AS n FROM method_calls WHERE file_id=0 AND (callee_class LIKE 'Lfixture/%' ESCAPE '\\') GROUP BY file_id,method,callee ORDER BY file_id,method,callee",
            ),
            (
                "Q11",
                "SELECT file_id,method_descriptor FROM class_methods WHERE file_id=0 AND (class_descriptor IN ('Lfixture/A;') OR class_descriptor LIKE 'Lcom/bapis/%Moss;') ORDER BY file_id,class_idx,method_idx",
            ),
            (
                "Q12",
                "SELECT file_id,method AS descriptor FROM method_calls WHERE callee='Lfixture/External;->external()V' ORDER BY file_id,method_idx",
            ),
        ] {
            let result = bridge
                .query(sql)
                .unwrap_or_else(|error| panic!("{label} {dialect:?}: {error:?}"));
            assert!(
                !result.rows().is_empty(),
                "{label} {dialect:?} returned no rows"
            );
        }
    }
}

#[test]
fn q08_q09_q15_are_answerable() {
    let harness = open(&[(
        "tests/fixtures/references/generated/classic-035.dex",
        InputKind::RawDex,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    for (label, sql) in [
        (
            "Q08",
            "SELECT file_id,class_def_idx,descriptor,superclass_descriptor FROM classes WHERE file_id=0 AND (descriptor LIKE 'Lfixture/%' ESCAPE '\\') ORDER BY file_id,class_def_idx",
        ),
        (
            "Q09",
            "SELECT method_idx,insns_off,insns_size FROM code_items WHERE file_id=0 AND method_idx BETWEEN 0 AND 8 ORDER BY method_idx",
        ),
        (
            "Q15",
            "SELECT file_id,class_descriptor||'->'||name||descriptor AS descriptor FROM methods WHERE name='caller' ORDER BY file_id,descriptor",
        ),
    ] {
        let result = bridge
            .query(sql)
            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
        assert!(!result.rows().is_empty(), "{label} returned no rows");
    }
}

/// The exactly-required hostlab-audit-v1 variant set: Q01-Q12 and Q15, 29
/// variants. Q13 `boundary` (multi-statement) and all of Q14 (response paging)
/// are excluded by design and stay unclaimed.
///
/// Every row is `(family, variant, sql)`. The test asserts each statement
/// prepares against the real provider (so the relation names and columns are
/// genuine), executes completely, and returns the shape the corpus records.
const REQUIRED_HOSTLAB_VARIANTS: &[(&str, &str, &str)] = &[
    (
        "Q01",
        "inventory",
        "SELECT file_id,entry_name FROM dex_files ORDER BY file_id",
    ),
    (
        "Q01",
        "pool_mapping",
        "SELECT file_id,string_pool_id FROM dex_files ORDER BY file_id",
    ),
    (
        "Q02",
        "cf_wildcard",
        "SELECT cf.* FROM class_fields cf WHERE class_descriptor IN ('Lfixture/Base;') ORDER BY file_id,class_idx,kind,field_idx",
    ),
    (
        "Q02",
        "cm_wildcard",
        "SELECT cm.* FROM class_methods cm WHERE class_descriptor IN ('Lfixture/Base;') ORDER BY file_id,class_idx,kind,method_idx",
    ),
    (
        "Q02",
        "class_meta",
        "SELECT file_id,class_idx,descriptor,access_flags,superclass_descriptor FROM classes WHERE descriptor IN ('Lfixture/Base;') ORDER BY file_id,class_idx",
    ),
    (
        "Q03",
        "interface_join",
        "SELECT ci.interface_descriptor,c.descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE c.descriptor IN ('Lfixture/Base;') ORDER BY ci.file_id,ci.class_idx,ci.ordinal",
    ),
    (
        "Q04",
        "Signature_type",
        "SELECT file_id,type_idx FROM types WHERE descriptor='Ldalvik/annotation/Signature;' ORDER BY file_id,type_idx",
    ),
    (
        "Q04",
        "directory",
        "SELECT file_id,entry_kind,entry_idx,annotation_set_off FROM annotation_directory_entries WHERE entry_kind IN ('field','method') ORDER BY file_id,entry_kind,entry_idx",
    ),
    (
        "Q04",
        "set_entries",
        "SELECT file_id,annotation_set_off,annotation_off FROM annotation_set_entries ORDER BY file_id,annotation_set_off,ordinal",
    ),
    (
        "Q04",
        "annotation_type",
        "SELECT file_id,annotation_off,type_idx FROM annotations ORDER BY file_id,annotation_off",
    ),
    (
        "Q04",
        "elements",
        "SELECT file_id,annotation_off,ordinal,value_index FROM annotation_elements WHERE depth=1 AND value_kind='string' ORDER BY file_id,annotation_off,ordinal",
    ),
    (
        "Q04",
        "string_pool",
        "SELECT string_pool_id,string_idx,value FROM strings ORDER BY string_pool_id,string_idx",
    ),
    (
        "Q05",
        "return_discovery",
        "SELECT DISTINCT m.class_descriptor FROM class_methods c JOIN methods m ON m.file_id=c.file_id AND m.method_idx=c.method_idx WHERE m.return_descriptor='V' ORDER BY m.class_descriptor",
    ),
    (
        "Q06",
        "string_candidates",
        r"SELECT DISTINCT file_id,method_idx,value FROM method_strings WHERE method_class IN ('Lfixture/A;') AND (value LIKE '%repeat%' OR value LIKE '%pref\_x%' ESCAPE '\') ORDER BY file_id,method_idx,value",
    ),
    (
        "Q07",
        "class_count",
        "SELECT COUNT(*) AS n FROM classes ORDER BY n",
    ),
    (
        "Q08",
        "class_surface",
        "SELECT file_id,class_def_idx,descriptor,superclass_descriptor FROM classes ORDER BY file_id,class_def_idx",
    ),
    (
        "Q08",
        "field_surface",
        "SELECT file_id,class_descriptor,field_name,field_descriptor FROM class_fields ORDER BY file_id,class_descriptor,field_idx",
    ),
    (
        "Q08",
        "method_surface",
        "SELECT file_id,class_descriptor,method_idx,method_name,method_descriptor FROM class_methods ORDER BY file_id,class_descriptor,method_idx",
    ),
    (
        "Q09",
        "raw_body_ranges",
        "SELECT method_idx,insns_off,insns_size FROM code_items ORDER BY method_idx",
    ),
    (
        "Q10",
        "call_counts",
        "SELECT file_id,method,callee,COUNT(*) AS n FROM method_calls GROUP BY file_id,method,callee ORDER BY file_id,method,callee",
    ),
    // The corpus binds a real product class (`Lfixture/Protocol;`) and the
    // `Lcom/bapis/%Moss;` LIKE prefix; the fixture substitutes the descriptor it
    // actually defines so the same IN-plus-LIKE shape is exercised.
    (
        "Q11",
        "protocol_definitions",
        "SELECT file_id,method_descriptor FROM class_methods WHERE file_id=0 AND (class_descriptor IN ('Lfixture/Base;') OR class_descriptor LIKE 'Lcom/bapis/%Moss;') ORDER BY file_id,class_idx,method_idx",
    ),
    (
        "Q12",
        "locate_class",
        "SELECT file_id,descriptor FROM classes WHERE descriptor='Lfixture/Base;' ORDER BY file_id",
    ),
    (
        "Q12",
        "locate_method",
        "SELECT file_id,method_descriptor AS descriptor FROM class_methods WHERE method_name='caller' ORDER BY file_id,descriptor",
    ),
    (
        "Q12",
        "locate_field",
        "SELECT file_id,field_descriptor AS descriptor FROM class_fields WHERE field_name='iValue' ORDER BY file_id,descriptor",
    ),
    (
        "Q12",
        "refs_string",
        "SELECT file_id,method AS descriptor FROM method_strings WHERE value='repeat' ORDER BY file_id,method_idx",
    ),
    (
        "Q12",
        "refs_method",
        "SELECT file_id,method AS descriptor FROM method_calls WHERE callee='Lfixture/External;->external()V' ORDER BY file_id,method_idx",
    ),
    (
        "Q12",
        "refs_field",
        "SELECT file_id,method AS descriptor FROM method_field_accesses WHERE field='Lfixture/External;->shared:Ljava/lang/String;' ORDER BY file_id,method_idx",
    ),
    (
        "Q12",
        "refs_type",
        "SELECT file_id,method AS descriptor FROM method_used_types WHERE type_descriptor='Ljava/lang/String;' ORDER BY file_id,method_idx",
    ),
    (
        "Q15",
        "legacy_locate_method",
        "SELECT file_id,class_descriptor||'->'||name||descriptor AS descriptor FROM methods WHERE name='caller' ORDER BY file_id,descriptor",
    ),
];

#[test]
fn all_seventeen_relations_return_rows_from_real_facts() {
    // Registration alone would let a name resolve to an always-empty cursor.
    // Each relation is scanned over fixtures that do contain its subject, and
    // the row count is compared with the fact layer's own count, so a silently
    // dropped projection is visible.
    let harness = open(&[
        (
            "tests/fixtures/definitions/generated/definitions-035.dex",
            InputKind::RawDex,
        ),
        (
            "tests/fixtures/references/generated/classic-035.dex",
            InputKind::RawDex,
        ),
        (
            "tests/fixtures/annotations/generated/annotations-038.dex",
            InputKind::RawDex,
        ),
    ]);
    let provider = harness.provider(true, true, true);
    let bridge = SqlBridge::new(
        provider.clone(),
        SqlDialect::DexSql011,
        SqlLimits::default(),
    )
    .unwrap();
    let mut seen = Vec::new();
    for relation in HostLabRelation::ALL {
        let name = relation.name();
        let result = bridge
            .query(&format!("SELECT * FROM {name}"))
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(
            result.columns().len(),
            relation.columns().len(),
            "{name} column count"
        );
        assert!(!result.rows().is_empty(), "{name} produced no rows");
        seen.push(name);
    }
    assert_eq!(seen.len(), 17);
    // `strings` and `types` are per-DEX tables; the totals must equal the fact
    // layer counts summed over the same roster, not a filtered subset.
    let strings = bridge.query("SELECT COUNT(*) AS n FROM strings").unwrap();
    let expected: u64 = provider
        .occurrences
        .iter()
        .map(|occurrence| occurrence.facts.metadata.strings().len() as u64)
        .sum();
    let counted = match strings.rows()[0][0] {
        SqlValue::I64(value) => value.0 as u64,
        SqlValue::U64(value) => value.0,
        ref other => panic!("unexpected COUNT carrier {other:?}"),
    };
    assert_eq!(counted, expected);
}

#[test]
fn required_q01_q12_and_q15_variants_all_execute_on_real_facts() {
    // The fixture set is chosen so no variant is trivially empty: definitions
    // carry class/field/method definitions, classic-035 carries the four
    // reference relations, annotations-038 carries the annotation chain, and
    // classic-035 carries method bodies for `code_items`.
    let harness = open(&[
        (
            "tests/fixtures/definitions/generated/definitions-035.dex",
            InputKind::RawDex,
        ),
        (
            "tests/fixtures/references/generated/classic-035.dex",
            InputKind::RawDex,
        ),
        (
            "tests/fixtures/annotations/generated/annotations-038.dex",
            InputKind::RawDex,
        ),
    ]);
    assert_eq!(REQUIRED_HOSTLAB_VARIANTS.len(), 29);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let mut families = std::collections::BTreeSet::new();
    for (family, variant, sql) in REQUIRED_HOSTLAB_VARIANTS {
        families.insert(*family);
        let prepared = bridge
            .prepare(sql)
            .unwrap_or_else(|error| panic!("{family}/{variant} prepare: {error:?}"));
        let result = bridge
            .execute(
                &prepared,
                crate::control::SqlControl::new(bridge_limits(), None),
            )
            .unwrap_or_else(|error| panic!("{family}/{variant} execute: {error:?}"));
        assert!(
            result.calculation_complete(),
            "{family}/{variant} incomplete"
        );
        assert!(
            !result.rows().is_empty(),
            "{family}/{variant} returned no rows; the fixture must exercise the shape"
        );
        assert!(
            !result.columns().is_empty(),
            "{family}/{variant} returned no columns"
        );
    }
    assert_eq!(
        families,
        [
            "Q01", "Q02", "Q03", "Q04", "Q05", "Q06", "Q07", "Q08", "Q09", "Q10", "Q11", "Q12",
            "Q15"
        ]
        .into_iter()
        .collect()
    );
}

fn bridge_limits() -> SqlLimits {
    SqlLimits::default()
}

#[test]
fn reference_relations_match_recorded_relation_counts() {
    // `tests/fixtures/references/expected.json` is the hand-maintained model for
    // classic-035; the four reference relations must reproduce its counts and
    // the documented get/put pair rather than a self-consistent re-derivation.
    let harness = open(&[(
        "tests/fixtures/references/generated/classic-035.dex",
        InputKind::RawDex,
    )]);
    let bridge = harness.bridge(SqlDialect::DexSql011);
    let expected: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture("tests/fixtures/references/expected.json")).unwrap(),
    )
    .unwrap();
    for relation in [
        "method_strings",
        "method_calls",
        "method_field_accesses",
        "method_used_types",
    ] {
        let sql = format!("SELECT * FROM {relation} ORDER BY file_id,method_idx");
        let result = bridge.query(&sql).unwrap();
        assert_eq!(
            result.rows().len() as u64,
            expected["classic"]["relation_counts"][relation]
                .as_u64()
                .unwrap(),
            "{relation}"
        );
    }
    let usages = bridge
        .query("SELECT DISTINCT using_type FROM method_field_accesses ORDER BY using_type")
        .unwrap();
    assert_eq!(
        row_strings(&usages),
        vec![vec![Some("get".into())], vec![Some("put".into())]]
    );
}

// ---------------------------------------------------------------------------
// Independent A0 differential over the whole fixture corpus.
//
// `a0-differential-20261112/a0-corpus.json` is produced by that directory's
// `generate.py` from the frozen backend (`dexsql 0.1.0`) alone; nothing in it
// comes from this engine. Each record is A0's answer to one relation query on
// one fixture, every cell rendered as `typeof(c)||':'||hex(c)` (or `N` for
// NULL) so NULL, the empty string and the text `NULL` stay distinct. The
// bridge's AST adapter does not implement `typeof`, so the engine side selects
// plain columns and applies the same encoding here; rows are compared as a
// multiset because A0 ordered by the encoded text.

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// Same encoding as A0's `CASE WHEN c IS NULL THEN 'N' ELSE typeof(c)||':'||hex(c) END`.
/// The one binary64 column is compared by storage class only; its bit-level
/// comparison lives in `every_relation_matches_the_recorded_a0_readback_row_for_row`.
fn encode_cell(relation: &str, column: &str, value: &SqlValue) -> String {
    match value {
        SqlValue::Null => "N".to_owned(),
        SqlValue::U64(value) => format!("integer:{}", hex_upper(value.0.to_string().as_bytes())),
        SqlValue::I64(value) => format!("integer:{}", hex_upper(value.0.to_string().as_bytes())),
        SqlValue::F64(_) if (relation, column) == ("annotation_elements", "value_f64") => {
            "real".to_owned()
        }
        SqlValue::Text(text) => match text.strict_utf8() {
            Ok(text) => format!("text:{}", hex_upper(text.as_bytes())),
            Err(_) => "text:<non-scalar>".to_owned(),
        },
        other => format!("<unexpected carrier {other:?}>"),
    }
}

fn decode_cell(cell: &str) -> String {
    match cell.split_once(':') {
        Some((kind, hex)) => {
            let bytes: Vec<u8> = (0..hex.len() / 2)
                .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                .collect();
            format!("{kind}:{:?}", String::from_utf8_lossy(&bytes))
        }
        None => cell.to_owned(),
    }
}

/// Build a bridge the way production composes the layers, but tolerate a
/// failing optional layer: that layer becomes absent and the relations which
/// need it must then fail closed instead of answering.
fn try_bridge(relative: &str) -> Result<SqlBridge, String> {
    let kind = if relative.ends_with(".apk") {
        InputKind::Apk
    } else {
        InputKind::RawDex
    };
    let spec = InputSpec {
        path: fixture(relative),
        kind,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[spec], CaptureLimits::default())
        .map_err(|error| format!("capture: {}", error.message))?;
    let mut inventories = Vec::new();
    for source in snapshot.sources() {
        inventories.push(
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .map_err(|error| format!("inventory: {}", error.message))?,
        );
    }
    let scope = SelectedScope::from_inventories(&snapshot, &inventories.iter().collect::<Vec<_>>())
        .map_err(|error| format!("scope: {}", error.message))?;
    let mut facts = Vec::new();
    for inventory in &inventories {
        for local in 0..inventory.selected_dexes().len() {
            let metadata = Arc::new(
                MetadataFacts::build(&snapshot, inventory, local, StringLimits::default())
                    .map_err(|error| format!("metadata: {}", error.message))?,
            );
            let definitions =
                DefinitionFacts::build_arc(Arc::clone(&metadata), DefinitionLimits::default())
                    .ok()
                    .map(Arc::new);
            let code = definitions.as_ref().and_then(|_| {
                CodeFacts::build_all_code_items(&snapshot, inventory, local, CodeLimits::default())
                    .ok()
                    .map(Arc::new)
            });
            let references = match (&definitions, &code) {
                (Some(definitions), Some(code)) => ReferenceFacts::build_arc(
                    Arc::clone(definitions),
                    Arc::clone(code),
                    ReferenceLimits::default(),
                )
                .ok()
                .map(Arc::new),
                _ => None,
            };
            let annotations = definitions.as_ref().and_then(|definitions| {
                AnnotationFacts::build((**definitions).clone(), AnnotationLimits::default())
                    .ok()
                    .map(Arc::new)
            });
            facts.push(HostLabOccurrenceFacts {
                metadata,
                definitions,
                code,
                references,
                annotations,
            });
        }
    }
    let provider = HostLabSqlProvider::from_scope(&scope, facts, DecimalU64(0))
        .map_err(|error| format!("provider: {}", error.message))?;
    SqlBridge::new(
        Arc::new(provider),
        SqlDialect::DexSql011,
        SqlLimits::default(),
    )
    .map_err(|error| format!("bridge: {}", error.message))
}

/// `(input suffix, relation)` pairs where this engine answers and A0 answers
/// differently, with the reason. Every other answered record must be equal.
///
/// * Non-BMP text: MUTF-8 stores a supplementary character as two 3-byte
///   surrogates. This engine decodes the pair to the scalar; A0 replaces every
///   byte with U+FFFD, a lossy projection this engine deliberately does not copy.
///
/// Legal unreferenced (orphan) annotation sets and items are *not* a divergence:
/// the SQL annotation relations project only what a class-bound directory
/// reaches, as A0 does, while the fact layer keeps the orphans.
const ANSWERED_DIVERGENCES: &[(&str, &str)] = &[
    (
        "parameter_descriptors/unicode-parameters-038.dex",
        "strings",
    ),
    ("parameter_descriptors/unicode-parameters-038.dex", "types"),
    (
        "parameter_descriptors/unicode-parameters-038.dex",
        "methods",
    ),
];

/// Inputs where this engine answers a relation although A0 refuses to load the
/// input: the relation does not depend on the part of the file A0 rejects.
const ENGINE_ONLY_ANSWERS: &[(&str, &str)] = &[
    (
        "raw_fingerprints/bad-code-item-reference.dex",
        "class_methods",
    ),
    (
        "references/generated/bad-body-interior-pointer.dex",
        "class_methods",
    ),
];

/// Every error this engine may return where A0 answered. Each is an explicit
/// refusal (a missing layer, a legal non-scalar string a plain UTF-8 column
/// cannot carry, or an input that fails structural validation), never an empty
/// success.
fn is_fail_closed(error: &str) -> bool {
    [
        "facts are not attached to this occurrence",
        "plain UTF8 relation cannot losslessly represent",
        "method body is not a physical code item start",
        "method body pointer is not a physical code item start",
        "required input/fact/column scope is not complete",
        "metadata: ",
        "inventory: ",
        "capture: ",
        "scope: ",
        "provider: ",
    ]
    .iter()
    .any(|marker| error.contains(marker))
}

#[test]
fn a0_differential_over_the_fixture_corpus_has_only_declared_divergences() {
    let corpus: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture(
            "artifacts/mdd-032-audit/a0-differential-20261112/a0-corpus.json",
        ))
        .unwrap(),
    )
    .unwrap();
    let records = corpus["records"].as_array().unwrap();
    let mut bridges: std::collections::BTreeMap<String, Result<SqlBridge, String>> =
        std::collections::BTreeMap::new();
    let (mut equal, mut both_fail) = (0usize, 0usize);
    let mut divergent: Vec<(String, String)> = Vec::new();
    let mut engine_only: Vec<(String, String)> = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    for record in records {
        let input = record["input"].as_str().unwrap().to_owned();
        let short = input
            .strip_prefix("tests/fixtures/")
            .unwrap_or(&input)
            .to_owned();
        let relation = record["relation"].as_str().unwrap().to_owned();
        let columns: Vec<String> = record["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|column| column.as_str().unwrap().to_owned())
            .collect();
        let sql = format!("SELECT {} FROM {}", columns.join(","), relation);
        let a0_ok = record["a0"]["ok"].as_bool().unwrap();
        let bridge = bridges
            .entry(input.clone())
            .or_insert_with(|| try_bridge(&input));
        let outcome = match bridge {
            Err(error) => Err(error.clone()),
            Ok(bridge) => bridge
                .query(&sql)
                .map_err(|error| error.message.to_string()),
        };
        match (a0_ok, outcome) {
            (false, Err(_)) => both_fail += 1,
            (false, Ok(_)) => engine_only.push((short, relation)),
            (true, Err(error)) => {
                if !is_fail_closed(&error) {
                    problems.push(format!("{short} {relation}: unexpected refusal: {error}"));
                }
            }
            (true, Ok(result)) => {
                let mut expected: Vec<Vec<String>> = record["a0"]["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| {
                        row.as_array()
                            .unwrap()
                            .iter()
                            .map(|cell| cell.as_str().unwrap().to_owned())
                            .collect()
                    })
                    .collect();
                let mut actual: Vec<Vec<String>> = result
                    .rows()
                    .iter()
                    .map(|row| {
                        row.iter()
                            .zip(&columns)
                            .map(|(cell, column)| encode_cell(&relation, column, cell))
                            .collect()
                    })
                    .collect();
                // A0 echoes the path text it was given and this harness gives
                // it a different spelling, so the column is checked against the
                // path the capture was handed and then masked on both sides.
                if let Some(at) = columns.iter().position(|column| column == "source_path") {
                    let wanted = format!(
                        "text:{}",
                        hex_upper(fixture(&input).to_str().unwrap().as_bytes())
                    );
                    for row in &mut actual {
                        if row[at] != wanted {
                            problems.push(format!(
                                "{short} {relation}: source_path is {}",
                                decode_cell(&row[at])
                            ));
                        }
                        row[at] = "masked".into();
                    }
                    for row in &mut expected {
                        row[at] = "masked".into();
                    }
                }
                actual.sort();
                expected.sort();
                if actual == expected {
                    equal += 1;
                } else {
                    divergent.push((short, relation));
                }
            }
        }
    }
    divergent.sort();
    let mut declared: Vec<(String, String)> = ANSWERED_DIVERGENCES
        .iter()
        .map(|(input, relation)| ((*input).to_owned(), (*relation).to_owned()))
        .collect();
    declared.sort();
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(
        divergent, declared,
        "answered divergences from A0 changed: fix them or update the declared list with a reason"
    );
    engine_only.sort();
    let mut declared_only: Vec<(String, String)> = ENGINE_ONLY_ANSWERS
        .iter()
        .map(|(input, relation)| ((*input).to_owned(), (*relation).to_owned()))
        .collect();
    declared_only.sort();
    assert_eq!(engine_only, declared_only);
    // Guard against the comparison silently shrinking: these are the records
    // on which both engines answered identically when the corpus was frozen.
    assert_eq!(equal, EXPECTED_EQUAL_RECORDS, "records equal to A0");
    assert_eq!(both_fail, EXPECTED_BOTH_FAIL_RECORDS, "records both refuse");
}

// 2,097 records were identical before the coverage ledger gated the provider.
// The six that dropped out are `methods` and `code_items` on three fixtures
// whose reference layer cannot be built (`bad-caller-ins-size`,
// `bad-custom-argument-count`, `bad-custom-prefix`): A0 answers them, while
// the ledger cannot prove method-to-body bindings without that layer, so the
// engine refuses. Any further drop is a new refusal and must be explained.
const EXPECTED_EQUAL_RECORDS: usize = 2091;
const EXPECTED_BOTH_FAIL_RECORDS: usize = 440;
