//! MDD-035: one request, three execution paths, one hand oracle.
//!
//! Every request below runs through three paths: the typed IR executor in
//! `Streaming` mode (operator fast paths), the typed IR executor in
//! `MaterializedReference` mode (the conservative path), and the SQL bridge
//! (`NativeV1`) on top of the SQLite virtual-table layer.
//!
//! All three read the very same immutable facts, and each result is compared with
//! one computed directly from those facts by plain iteration. This proves the
//! paths agree with each other and with the facts they read; that the facts are
//! right is shown by the A0 golden, and only the UTF-16/UTF-8 order has an
//! independent Python record here. A path that
//! disagrees with the oracle, or with another path, fails the test: no silent
//! semantic difference.
//!
//! The fixture holds supplementary-plane text and is captured twice, so ordering
//! (UTF-16 code-unit order versus UTF-8 byte order) and per-occurrence
//! multiplicity are both exercised. Cells are normalised to integers, UTF-16
//! units and bytes; entities are never compared across paths because the SQL
//! bridge has no entity type.
use std::{path::PathBuf, sync::Arc};

use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{DefinitionFacts, MetadataFacts};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_query::{
    executor::{
        Control, ExecutionLimits, ExecutionMode, FactSource, execute,
        facts::{NativeCatalog, OccurrenceFacts},
        prepare,
    },
    ir::{
        Aggregate, AggregateKind, Column, DataType, Expr, IR_VERSION, JoinKind, Node, OrderKey,
        Predicate, Projection, QueryIr, TEXT_VERSION, Value,
    },
};
use mdd_sql::{
    SqlBridge,
    control::SqlLimits,
    dialects::SqlDialect,
    provider::metadata::{DefinitionSqlProvider, MetadataSqlProvider},
    values::SqlValue,
};
use mdd_types::DecimalU64;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Cell {
    Null,
    Unsigned(u64),
    Signed(i64),
    Text(Vec<u16>),
    Bytes(Vec<u8>),
}
type Rows = Vec<Vec<Cell>>;

fn typed_cell(value: &Value) -> Cell {
    match value {
        Value::Null => Cell::Null,
        Value::U64(number) => Cell::Unsigned(number.0),
        Value::I64(number) => Cell::Signed(number.0),
        Value::Utf16(units) => Cell::Text(units.clone()),
        Value::Bytes(bytes) => Cell::Bytes(bytes.0.clone()),
        other => panic!("cell kind not comparable across paths: {other:?}"),
    }
}

fn sql_cell(value: &SqlValue) -> Cell {
    match value {
        SqlValue::Null => Cell::Null,
        SqlValue::U64(number) => Cell::Unsigned(number.0),
        SqlValue::I64(number) => Cell::Signed(number.0),
        SqlValue::Text(text) => Cell::Text(text.utf16.clone()),
        SqlValue::Bytes(bytes) => Cell::Bytes(bytes.clone()),
        // The SQL layer tags original MUTF-8 as its own cell kind; the bytes are
        // compared here and the declared UTF-16 unit count is checked on its own.
        SqlValue::DexMutf8 { bytes, .. } => Cell::Bytes(bytes.clone()),
        other => panic!("cell kind not comparable across paths: {other:?}"),
    }
}

fn text(units: &[u16]) -> Cell {
    Cell::Text(units.to_vec())
}

fn int(number: u64) -> Cell {
    Cell::Unsigned(number)
}

struct World {
    catalog: NativeCatalog,
    bridge: SqlBridge,
    facts: Vec<Arc<MetadataFacts>>,
}

fn world() -> World {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/query/generated/unicode-order-038.dex");
    // The capture itself checks the fixture bytes against the independent Python record.
    let spec = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: Some(recorded_fixture_sha256()),
    };
    let snapshot = Snapshot::capture(&[spec.clone(), spec], CaptureLimits::default()).unwrap();
    let mut facts = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        facts.push(Arc::new(
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
        ));
    }
    let occurrences = facts
        .iter()
        .map(|metadata| OccurrenceFacts {
            metadata: Arc::clone(metadata),
            definitions: None,
            code: None,
        })
        .collect();
    let catalog = NativeCatalog::new(
        snapshot.manifest().snapshot_id.clone(),
        DecimalU64(0),
        occurrences,
    )
    .unwrap();
    let provider = Arc::new(MetadataSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    World {
        catalog,
        bridge,
        facts,
    }
}

fn column(id: &str, data_type: DataType, nullable: bool) -> Column {
    Column {
        id: id.into(),
        display_name: id.into(),
        data_type,
        nullable,
    }
}

fn scan(relation: &str) -> Node {
    Node::Scan {
        relation: relation.into(),
    }
}

/// Project `(output id, type, source ordinal)` triples; no column is nullable here.
fn project(input: Node, columns: &[(&str, DataType, usize)]) -> Node {
    Node::Project {
        input: Box::new(input),
        columns: columns
            .iter()
            .map(|(id, data_type, ordinal)| Projection {
                column: column(id, *data_type, false),
                expression: Expr::Column { ordinal: *ordinal },
            })
            .collect(),
    }
}

fn order(input: Node, ordinals: &[usize]) -> Node {
    Node::Order {
        input: Box::new(input),
        keys: ordinals
            .iter()
            .map(|ordinal| OrderKey {
                ordinal: *ordinal,
                descending: false,
                nulls_first: false,
            })
            .collect(),
    }
}

/// Both typed modes. Each must complete; they are returned separately so a
/// disagreement between the fast path and the reference path is visible.
fn typed(world: &World, root: Node) -> (Rows, Rows) {
    typed_on(&world.catalog, root)
}

fn typed_on(catalog: &NativeCatalog, root: Node) -> (Rows, Rows) {
    let query = QueryIr {
        schema_version: IR_VERSION.into(),
        text_semantics: TEXT_VERSION.into(),
        snapshot_id: catalog.snapshot_id().into(),
        catalog_epoch: catalog.catalog_epoch(),
        require_stable_order: false,
        root,
    };
    let plan = prepare(query, catalog).unwrap();
    let run = |mode| {
        let mut control = Control::new(ExecutionLimits::default());
        let output = execute(&plan, catalog, mode, &mut control).unwrap();
        assert!(output.execution_complete(), "{mode:?} did not complete");
        output
            .rows()
            .iter()
            .map(|row| row.iter().map(typed_cell).collect())
            .collect::<Rows>()
    };
    (
        run(ExecutionMode::Streaming),
        run(ExecutionMode::MaterializedReference),
    )
}

fn sql(world: &World, statement: &str) -> Rows {
    sql_on(&world.bridge, statement)
}

fn sql_on(bridge: &SqlBridge, statement: &str) -> Rows {
    bridge
        .query(statement)
        .unwrap_or_else(|error| panic!("{statement}: {error:?}"))
        .rows()
        .iter()
        .map(|row| row.iter().map(sql_cell).collect())
        .collect()
}

fn sorted(mut rows: Rows) -> Rows {
    rows.sort();
    rows
}

/// First place where two row lists differ, or `None`; used by the harness check too.
fn first_difference(left: &Rows, right: &Rows) -> Option<String> {
    if left.len() != right.len() {
        return Some(format!("row count {} vs {}", left.len(), right.len()));
    }
    left.iter()
        .zip(right)
        .position(|(a, b)| a != b)
        .map(|at| format!("row {at}: {:?} vs {:?}", left[at], right[at]))
}

/// All four must agree. `ordered` says whether row order is part of the request.
fn agree(name: &str, ordered: bool, oracle: Rows, typed_pair: (Rows, Rows), sql_rows: Rows) {
    let (streaming, reference) = typed_pair;
    let norm = |rows: Rows| if ordered { rows } else { sorted(rows) };
    let oracle = norm(oracle);
    for (path, rows) in [
        ("typed streaming", streaming),
        ("typed reference", reference),
        ("sql bridge", sql_rows),
    ] {
        if let Some(difference) = first_difference(&norm(rows), &oracle) {
            panic!("{name}: {path} differs from the hand oracle: {difference}");
        }
    }
}

struct StringRow {
    idx: u32,
    units: Vec<u16>,
    raw: Vec<u8>,
}

fn oracle_strings(world: &World) -> Vec<StringRow> {
    world
        .facts
        .iter()
        .flat_map(|facts| {
            facts.strings().iter().map(|fact| StringRow {
                idx: fact.data.string_idx,
                units: fact.data.text.utf16_units.clone(),
                raw: fact.data.text.raw_mutf8.clone(),
            })
        })
        .collect()
}

/// `(type_idx, descriptor string idx, descriptor units)` per occurrence.
fn oracle_types(world: &World) -> Vec<(u32, u32, Vec<u16>)> {
    world
        .facts
        .iter()
        .flat_map(|facts| {
            facts.types().iter().map(|fact| {
                let descriptor = facts
                    .strings()
                    .iter()
                    .find(|string| string.data.string_idx == fact.data.descriptor_string_idx)
                    .expect("a validated type names an existing string");
                (
                    fact.data.type_idx,
                    fact.data.descriptor_string_idx,
                    descriptor.data.text.utf16_units.clone(),
                )
            })
        })
        .collect()
}

fn ordered_string_rows(world: &World) -> Rows {
    let mut strings = oracle_strings(world);
    strings.sort_by(|a, b| a.units.cmp(&b.units).then(a.idx.cmp(&b.idx)));
    strings
        .iter()
        .map(|row| vec![text(&row.units), int(u64::from(row.idx))])
        .collect()
}

#[test]
fn fixture_discriminates_utf16_order_from_utf8_order() {
    // Without this the ordering requests below could not tell the two orders apart.
    let world = world();
    let strings = oracle_strings(&world);
    assert!(
        strings
            .iter()
            .any(|row| row.units.iter().any(|unit| (0xD800..0xE000).contains(unit))),
        "the fixture no longer holds a supplementary-plane string"
    );
    let utf8 = |units: &[u16]| String::from_utf16(units).ok().map(String::into_bytes);
    let mut by_units: Vec<_> = strings
        .iter()
        .filter_map(|row| utf8(&row.units).map(|bytes| (row.units.clone(), bytes)))
        .collect();
    by_units.sort_by(|a, b| a.0.cmp(&b.0));
    let mut by_bytes = by_units.clone();
    by_bytes.sort_by(|a, b| a.1.cmp(&b.1));
    assert!(
        by_units != by_bytes,
        "UTF-16 and UTF-8 order coincide on this fixture, so the ordering check is vacuous"
    );
    // The independent Python record names the same two strings in the same order.
    let record = recorded_order();
    // Two captured occurrences hold every string twice; the record lists each once.
    let mut present: Vec<String> = by_units
        .iter()
        .filter_map(|(units, _)| String::from_utf16(units).ok())
        .filter(|text| record.utf16_order.contains(text))
        .collect();
    present.dedup();
    assert_eq!(
        present, record.utf16_order,
        "facts disagree with the recorded order"
    );
}

struct RecordedOrder {
    utf16_order: Vec<String>,
    utf8_order: Vec<String>,
}

fn recorded() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/query/generated/unicode-order-038.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn recorded_fixture_sha256() -> String {
    recorded()["fixture_sha256"].as_str().unwrap().to_owned()
}

fn recorded_order() -> RecordedOrder {
    let record = recorded();
    let list = |key: &str| -> Vec<String> {
        record[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    };
    RecordedOrder {
        utf16_order: list("order_by_utf16_units"),
        utf8_order: list("order_by_utf8_bytes"),
    }
}

#[test]
fn sql_order_puts_the_supplementary_string_where_the_python_record_does() {
    // The recorded order comes from a separate Python writer, not from either engine
    // path; byte order would put the two strings the other way round.
    let world = world();
    let record = recorded_order();
    assert_ne!(record.utf16_order, record.utf8_order);
    let result = sql(
        &world,
        "SELECT value FROM native_strings ORDER BY value,string_idx",
    );
    let position = |wanted: &str| {
        let units: Vec<u16> = wanted.encode_utf16().collect();
        result
            .iter()
            .position(|row| row[0] == Cell::Text(units.clone()))
            .unwrap_or_else(|| panic!("{wanted:?} missing from the ordered result"))
    };
    assert!(position(&record.utf16_order[0]) < position(&record.utf16_order[1]));
}

#[test]
fn sql_original_mutf8_cells_declare_the_unit_count_of_their_text() {
    let world = world();
    let result = world
        .bridge
        .query("SELECT value,raw_mutf8 FROM native_strings")
        .unwrap();
    assert_eq!(result.rows().len(), oracle_strings(&world).len());
    for row in result.rows() {
        let (
            SqlValue::Text(value),
            SqlValue::DexMutf8 {
                utf16_code_units, ..
            },
        ) = (&row[0], &row[1])
        else {
            panic!("native_strings.raw_mutf8 is no longer an original MUTF-8 cell: {row:?}");
        };
        assert_eq!(utf16_code_units.0, value.utf16.len() as u64);
    }
}

#[test]
fn full_scan_projection_agrees_on_all_paths() {
    let world = world();
    let oracle: Rows = oracle_strings(&world)
        .iter()
        .map(|row| {
            vec![
                int(u64::from(row.idx)),
                text(&row.units),
                Cell::Bytes(row.raw.clone()),
            ]
        })
        .collect();
    assert!(
        oracle.len() >= 2 && oracle.len().is_multiple_of(2),
        "two occurrences"
    );
    agree(
        "full scan",
        false,
        oracle,
        typed(
            &world,
            project(
                scan("strings"),
                &[
                    ("idx", DataType::U64, 1),
                    ("text", DataType::Utf16, 3),
                    ("raw", DataType::Bytes, 4),
                ],
            ),
        ),
        sql(
            &world,
            "SELECT string_idx,value,raw_mutf8 FROM native_strings",
        ),
    );
}

#[test]
fn order_by_text_follows_utf16_code_units_on_all_paths() {
    let world = world();
    let strings = project(
        scan("strings"),
        &[("text", DataType::Utf16, 3), ("idx", DataType::U64, 1)],
    );
    agree(
        "order by text",
        true,
        ordered_string_rows(&world),
        typed(&world, order(strings, &[0, 1])),
        sql(
            &world,
            "SELECT value,string_idx FROM native_strings ORDER BY value,string_idx",
        ),
    );
}

#[test]
fn offset_window_over_an_ordered_request_agrees_on_all_paths() {
    let world = world();
    let all = ordered_string_rows(&world);
    assert!(all.len() > 8, "the window must fall inside the data");
    let ordered = order(
        project(
            scan("strings"),
            &[("text", DataType::Utf16, 3), ("idx", DataType::U64, 1)],
        ),
        &[0, 1],
    );
    agree(
        "offset window",
        true,
        all[3..8].to_vec(),
        typed(
            &world,
            Node::Limit {
                input: Box::new(ordered),
                offset: DecimalU64(3),
                count: DecimalU64(5),
            },
        ),
        sql(
            &world,
            "SELECT value,string_idx FROM native_strings ORDER BY value,string_idx LIMIT 5 OFFSET 3",
        ),
    );
}

#[test]
fn grouped_count_keeps_the_multiplicity_of_both_occurrences() {
    let world = world();
    let mut groups: std::collections::BTreeMap<Vec<u16>, u64> = Default::default();
    for (_, _, descriptor) in oracle_types(&world) {
        *groups.entry(descriptor).or_default() += 1;
    }
    assert!(
        groups.values().all(|count| count % 2 == 0),
        "two occurrences"
    );
    let oracle: Rows = groups
        .iter()
        .map(|(descriptor, count)| vec![text(descriptor), int(*count)])
        .collect();
    let histogram = Node::Aggregate {
        input: Box::new(project(
            scan("types"),
            &[("descriptor", DataType::Utf16, 2)],
        )),
        group_by: vec![0],
        aggregates: vec![Aggregate {
            kind: AggregateKind::CountStar,
            ordinal: None,
            column: column("n", DataType::U64, false),
        }],
    };
    agree(
        "grouped count",
        true,
        oracle,
        typed(&world, order(histogram, &[0])),
        count_column_as_unsigned(
            sql(
                &world,
                "SELECT descriptor,COUNT(*) FROM native_types GROUP BY descriptor ORDER BY descriptor",
            ),
            1,
        ),
    );
}

/// The one declared representation difference between the two request surfaces:
/// `COUNT(*)` is unsigned in the typed IR and a signed integer in the SQL bridge.
/// Only the SQL side of this one column is converted, and only from a non-negative
/// signed cell, so a change on either side fails here and in the pin test below.
fn count_column_as_unsigned(rows: Rows, column: usize) -> Rows {
    rows.into_iter()
        .map(|mut row| {
            row[column] = match &row[column] {
                Cell::Signed(number) => Cell::Unsigned(
                    u64::try_from(*number).expect("COUNT(*) became negative in the SQL bridge"),
                ),
                other => {
                    panic!("COUNT(*) is no longer a signed integer in the SQL bridge: {other:?}")
                }
            };
            row
        })
        .collect()
}

#[test]
fn count_star_is_unsigned_in_the_typed_ir_and_signed_in_the_sql_bridge() {
    // Pins both kinds. If either surface changes, this fails and someone has to decide
    // whether the difference is now gone, moved or wrong, instead of it going unseen.
    let world = world();
    let total = u64::try_from(oracle_strings(&world).len()).unwrap();
    let count_all = Node::Aggregate {
        input: Box::new(scan("strings")),
        group_by: Vec::new(),
        aggregates: vec![Aggregate {
            kind: AggregateKind::CountStar,
            ordinal: None,
            column: column("n", DataType::U64, false),
        }],
    };
    let (streaming, reference) = typed(&world, count_all);
    assert_eq!(streaming, vec![vec![Cell::Unsigned(total)]]);
    assert_eq!(reference, streaming);
    assert_eq!(
        sql(&world, "SELECT COUNT(*) FROM native_strings"),
        vec![vec![Cell::Signed(i64::try_from(total).unwrap())]]
    );
}

#[test]
fn equality_filter_hits_and_misses_agree_on_all_paths() {
    let world = world();
    // A literal that SQL can quote and that holds the supplementary plane when the
    // fixture has one; otherwise any quotable string.
    let strings = oracle_strings(&world);
    let quotable = |row: &&StringRow| {
        !row.units.is_empty() && String::from_utf16(&row.units).is_ok_and(|s| !s.contains('\''))
    };
    let picked = strings
        .iter()
        .filter(quotable)
        .find(|row| row.units.iter().any(|unit| (0xD800..0xE000).contains(unit)))
        .or_else(|| strings.iter().find(quotable))
        .expect("a quotable string exists");
    let literal = String::from_utf16(&picked.units).unwrap();
    let hit_oracle: Rows = strings
        .iter()
        .filter(|row| row.units == picked.units)
        .map(|row| vec![int(u64::from(row.idx))])
        .collect();
    assert!(
        hit_oracle.len() >= 2,
        "the string occurs in both occurrences"
    );
    let filter = |units: Vec<u16>| {
        project(
            Node::Filter {
                input: Box::new(scan("strings")),
                predicate: Predicate::Eq {
                    left: Expr::Column { ordinal: 3 },
                    right: Expr::Literal {
                        value: Value::Utf16(units),
                    },
                },
            },
            &[("idx", DataType::U64, 1)],
        )
    };
    agree(
        "equality hit",
        false,
        hit_oracle,
        typed(&world, filter(picked.units.clone())),
        sql(
            &world,
            &format!("SELECT string_idx FROM native_strings WHERE value = '{literal}'"),
        ),
    );
    // A miss is an empty complete result on every path, never an error.
    let absent = "no-such-string-in-this-fixture";
    assert!(
        !strings
            .iter()
            .any(|row| row.units == absent.encode_utf16().collect::<Vec<_>>())
    );
    agree(
        "equality miss",
        false,
        Vec::new(),
        typed(&world, filter(absent.encode_utf16().collect())),
        sql(
            &world,
            &format!("SELECT string_idx FROM native_strings WHERE value = '{absent}'"),
        ),
    );
}

#[test]
fn join_through_the_descriptor_string_keeps_occurrence_identity() {
    let world = world();
    let oracle: Rows = oracle_types(&world)
        .iter()
        .map(|(type_idx, string_idx, units)| {
            vec![
                int(u64::from(*type_idx)),
                int(u64::from(*string_idx)),
                text(units),
            ]
        })
        .collect();
    // types ++ strings columns: 0..3 are types, 4..8 are strings.
    let joined = Node::EquiJoin {
        left: Box::new(scan("types")),
        right: Box::new(scan("strings")),
        left_keys: vec![3],
        right_keys: vec![0],
        kind: JoinKind::Inner,
    };
    agree(
        "descriptor join",
        false,
        oracle,
        typed(
            &world,
            project(
                joined,
                &[
                    ("type_idx", DataType::U64, 1),
                    ("string_idx", DataType::U64, 5),
                    ("descriptor", DataType::Utf16, 7),
                ],
            ),
        ),
        sql(
            &world,
            "SELECT t.type_idx,s.string_idx,s.value FROM native_types t \
             JOIN native_strings s ON s.dex_occurrence_id=t.dex_occurrence_id \
             AND s.string_idx=t.descriptor_string_idx",
        ),
    );
}

struct DefinitionWorld {
    catalog: NativeCatalog,
    bridge: SqlBridge,
    facts: Vec<Arc<DefinitionFacts>>,
}

/// The same class/field/method fixture the typed IR tests use, captured twice.
fn definition_world() -> DefinitionWorld {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-038.dex");
    let spec = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[spec.clone(), spec], CaptureLimits::default()).unwrap();
    let mut facts = Vec::new();
    let mut occurrences = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap();
        let metadata = Arc::new(
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
        );
        let definitions = Arc::new(
            DefinitionFacts::build_arc(Arc::clone(&metadata), DefinitionLimits::default()).unwrap(),
        );
        occurrences.push(OccurrenceFacts {
            metadata,
            definitions: Some(Arc::clone(&definitions)),
            code: None,
        });
        facts.push(definitions);
    }
    let catalog = NativeCatalog::new(
        snapshot.manifest().snapshot_id.clone(),
        DecimalU64(0),
        occurrences,
    )
    .unwrap();
    let provider = Arc::new(DefinitionSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    DefinitionWorld {
        catalog,
        bridge,
        facts,
    }
}

fn utf16(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

#[test]
fn class_scan_agrees_on_all_paths_for_definition_relations() {
    let world = definition_world();
    let oracle: Rows = world
        .facts
        .iter()
        .flat_map(|facts| facts.definitions().classes.iter())
        .map(|class| {
            vec![
                int(u64::from(class.class_def_idx)),
                text(&utf16(&class.descriptor)),
            ]
        })
        .collect();
    assert!(
        oracle.len() >= 2,
        "the fixture defines classes in both occurrences"
    );
    agree(
        "class scan",
        false,
        oracle,
        typed_on(
            &world.catalog,
            project(
                scan("classes"),
                &[
                    ("idx", DataType::U64, 1),
                    ("descriptor", DataType::Utf16, 3),
                ],
            ),
        ),
        sql_on(
            &world.bridge,
            "SELECT class_def_idx,descriptor FROM native_classes",
        ),
    );
}

#[test]
fn field_kind_histogram_agrees_on_all_paths_for_definition_relations() {
    let world = definition_world();
    let mut groups: std::collections::BTreeMap<Vec<u16>, u64> = Default::default();
    for facts in &world.facts {
        for field in &facts.definitions().field_definitions {
            *groups.entry(utf16(field.kind.as_str())).or_default() += 1;
        }
    }
    assert!(
        groups.len() >= 2,
        "the fixture has static and instance fields"
    );
    let oracle: Rows = groups
        .iter()
        .map(|(kind, count)| vec![text(kind), int(*count)])
        .collect();
    let histogram = Node::Aggregate {
        input: Box::new(project(
            scan("field_definitions"),
            &[("kind", DataType::Utf16, 4)],
        )),
        group_by: vec![0],
        aggregates: vec![Aggregate {
            kind: AggregateKind::CountStar,
            ordinal: None,
            column: column("n", DataType::U64, false),
        }],
    };
    agree(
        "field kind histogram",
        true,
        oracle,
        typed_on(&world.catalog, order(histogram, &[0])),
        count_column_as_unsigned(
            sql_on(
                &world.bridge,
                "SELECT kind,COUNT(*) FROM native_field_definitions GROUP BY kind ORDER BY kind",
            ),
            1,
        ),
    );
}

#[test]
fn field_to_class_join_keeps_occurrence_identity_for_definition_relations() {
    let world = definition_world();
    let oracle: Rows = world
        .facts
        .iter()
        .flat_map(|facts| {
            let definitions = facts.definitions();
            definitions.field_definitions.iter().map(move |field| {
                let class = definitions
                    .classes
                    .iter()
                    .find(|class| class.class_def_idx == field.class_def_idx)
                    .expect("a defined field names a defined class");
                vec![
                    text(&utf16(&class.descriptor)),
                    text(&utf16(field.kind.as_str())),
                    int(u64::from(field.ordinal)),
                ]
            })
        })
        .collect();
    let field_count: usize = world
        .facts
        .iter()
        .map(|facts| facts.definitions().field_definitions.len())
        .sum();
    assert_eq!(
        oracle.len(),
        field_count,
        "one joined row per defined field"
    );
    // field_definitions columns 0..=5, then classes columns 6..=11.
    let joined = Node::EquiJoin {
        left: Box::new(scan("field_definitions")),
        right: Box::new(scan("classes")),
        left_keys: vec![2],
        right_keys: vec![0],
        kind: JoinKind::Inner,
    };
    agree(
        "field to class join",
        false,
        oracle,
        typed_on(
            &world.catalog,
            project(
                joined,
                &[
                    ("class", DataType::Utf16, 9),
                    ("kind", DataType::Utf16, 4),
                    ("ordinal", DataType::U64, 5),
                ],
            ),
        ),
        sql_on(
            &world.bridge,
            "SELECT c.descriptor,f.kind,f.ordinal FROM native_field_definitions f \
             JOIN native_classes c ON c.dex_occurrence_id=f.dex_occurrence_id \
             AND c.class_def_idx=f.class_def_idx",
        ),
    );
}

#[test]
fn class_interface_pairs_agree_on_all_paths_for_definition_relations() {
    let world = definition_world();
    let oracle: Rows = world
        .facts
        .iter()
        .flat_map(|facts| facts.definitions().interfaces.iter())
        .map(|interface| {
            vec![
                int(u64::from(interface.class_def_idx)),
                int(u64::from(interface.ordinal)),
            ]
        })
        .collect();
    assert!(
        oracle.len() >= 2,
        "the fixture implements an interface in both occurrences"
    );
    // class_interfaces columns 0..=2, then classes columns 3..=8: typed IR reaches the
    // class index through the class entity, the SQL relation carries it directly.
    let joined = Node::EquiJoin {
        left: Box::new(scan("class_interfaces")),
        right: Box::new(scan("classes")),
        left_keys: vec![0],
        right_keys: vec![0],
        kind: JoinKind::Inner,
    };
    agree(
        "class interface pairs",
        false,
        oracle,
        typed_on(
            &world.catalog,
            project(
                joined,
                &[("class", DataType::U64, 4), ("ordinal", DataType::U64, 1)],
            ),
        ),
        sql_on(
            &world.bridge,
            "SELECT class_def_idx,ordinal FROM native_class_interfaces",
        ),
    );
}

#[test]
fn the_comparison_itself_rejects_a_wrong_row_a_missing_row_and_a_wrong_order() {
    let rows: Rows = vec![vec![int(1)], vec![int(2)]];
    assert_eq!(first_difference(&rows, &rows), None);
    assert!(first_difference(&rows, &vec![vec![int(1)], vec![int(3)]]).is_some());
    assert!(first_difference(&rows, &vec![vec![int(1)]]).is_some());
    let swapped: Rows = vec![vec![int(2)], vec![int(1)]];
    assert!(first_difference(&rows, &swapped).is_some());
    assert_eq!(sorted(swapped), rows);
    // Null, empty text and zero are three different cells.
    assert_ne!(Cell::Null, text(&[]));
    assert_ne!(Cell::Null, int(0));
    assert_ne!(text(&[]), Cell::Bytes(Vec::new()));
}
