use super::*;
use mdd_input::{
    archive::{ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec},
};
use serde_json::Value;
use std::path::PathBuf;

#[test]
fn java_type_names_are_bounded_and_bound_to_occurrences() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/type-names-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let inventories: Vec<_> = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap()
        })
        .collect();
    let left =
        MetadataFacts::build(&snapshot, &inventories[0], 0, StringLimits::default()).unwrap();
    let right =
        MetadataFacts::build(&snapshot, &inventories[1], 0, StringLimits::default()).unwrap();
    // These seven values are also observed in the fixed A0 fixture record.
    for (descriptor, expected) in [
        ("I", "int"),
        ("Lfixture/A;", "fixture.A"),
        ("Lfixture/External;", "fixture.External"),
        ("Ljava/lang/Object;", "java.lang.Object"),
        ("Ljava/lang/String;", "java.lang.String"),
        ("V", "void"),
        ("[I", "int[]"),
    ] {
        let fact = left
            .types()
            .iter()
            .find(|fact| fact.data.descriptor == descriptor)
            .unwrap();
        let rendered = left
            .java_type_name(&fact.entity, TypeNameLimits::default())
            .unwrap();
        assert_eq!(rendered.value, expected);
        assert_eq!(rendered.entity, &fact.entity);
        assert_eq!(
            rendered.source.dex_occurrence_id,
            left.source().dex_occurrence_id
        );
        assert_eq!(fact.data.descriptor, descriptor);
        let other = &right.types()[fact.entity.local_index as usize];
        assert_eq!(
            left.java_type_name(&other.entity, TypeNameLimits::default())
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    for (descriptor, expected) in [
        ("Z", "boolean"),
        ("B", "byte"),
        ("S", "short"),
        ("C", "char"),
        ("J", "long"),
        ("F", "float"),
        ("D", "double"),
        ("[[Lpkg/Outer$Inner;", "pkg.Outer$Inner[][]"),
        ("Lpkg/雪;", "pkg.雪"),
    ] {
        assert_eq!(
            java_type_name_value(descriptor, "035", TypeNameLimits::default()).unwrap(),
            expected
        );
    }
    let output = java_type_name_value(
        "[[I",
        "035",
        TypeNameLimits {
            max_descriptor_bytes: 3,
            max_output_bytes: 7,
        },
    )
    .unwrap();
    assert_eq!(output, "int[][]");
    assert_eq!(
        java_type_name_value(
            "[[I",
            "035",
            TypeNameLimits {
                max_descriptor_bytes: 3,
                max_output_bytes: 6
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        java_type_name_value(
            "[[I",
            "035",
            TypeNameLimits {
                max_descriptor_bytes: 2,
                max_output_bytes: 100
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        java_type_name_value("[V", "035", TypeNameLimits::default())
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        java_type_name_value(
            &format!("{}I", "[".repeat(256)),
            "035",
            TypeNameLimits::default()
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
    let mut incomplete = left.clone();
    incomplete.metadata_coverage = Completeness::Partial;
    assert_eq!(
        incomplete
            .java_type_name(&left.types()[0].entity, TypeNameLimits::default())
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
    assert_eq!(
        left.java_type_name(&left.strings()[0].entity, TypeNameLimits::default())
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn duplicate_content_occurrences_keep_distinct_refs_and_owned_leases() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated/structured-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let first = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let second = ArchiveInventory::build(
        &snapshot.sources()[1],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let left = MetadataFacts::build(&snapshot, &first, 0, StringLimits::default()).unwrap();
    let right = MetadataFacts::build(&snapshot, &second, 0, StringLimits::default()).unwrap();
    assert_eq!(left.source.content_id, right.source.content_id);
    assert_eq!(
        left.string_pool.string_pool_id,
        right.string_pool.string_pool_id
    );
    assert_ne!(left.strings[0].entity, right.strings[0].entity);
    assert_ne!(left.types[0].entity, right.types[0].entity);
    assert_eq!(left.types[0].descriptor_string, left.strings[0].entity);
    assert_eq!(left.prototypes[0].return_type, left.types[2].entity);
    assert_eq!(
        left.string_pool.string_pool_id,
        format!("{}:string-pool:112:7", left.source.physical_dex_id)
    );
    let lease = left.lease();
    drop(first);
    drop(second);
    drop(snapshot);
    assert_eq!(left.bytes(), right.bytes());
    assert_eq!(lease.as_ref(), left.bytes());
    assert_eq!(
        left.unbuilt_layers,
        [
            "definitions",
            "annotations",
            "code_layout",
            "references",
            "resources",
            "derived_analysis"
        ]
    );
    assert!(left.entity(EntityKind::String, 7).is_err());
}

#[test]
fn unrelated_snapshot_inventory_and_zero_quota_fail_closed() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated/structured-035.dex");
    let input = InputSpec {
        path,
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let a = Snapshot::capture(std::slice::from_ref(&input), CaptureLimits::default()).unwrap();
    let b = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
    let inventory = ArchiveInventory::build(
        &a.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(
        MetadataFacts::build(&b, &inventory, 0, StringLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    let error = MetadataFacts::build(
        &a,
        &inventory,
        0,
        StringLimits {
            max_strings: 0,
            ..StringLimits::default()
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["snapshot_id"], a.manifest().snapshot_id);
    assert!(error.details.contains_key("content_id"));
}

#[test]
fn same_archive_duplicate_dexes_retain_independent_local_indices() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated/duplicate-content.apk");
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path,
            kind: InputKind::Apk,
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
    assert_eq!(inventory.selected_dexes().len(), 2);
    let a = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
    let b = MetadataFacts::build(&snapshot, &inventory, 1, StringLimits::default()).unwrap();
    assert_eq!(a.source.source_occurrence_id, b.source.source_occurrence_id);
    assert_ne!(a.source.member_id, b.source.member_id);
    assert_eq!(a.string_pool.string_pool_id, b.string_pool.string_pool_id);
    assert_ne!(a.strings[0].entity, b.strings[0].entity);
    assert_eq!(
        a.strings[0].entity.local_index,
        b.strings[0].entity.local_index
    );
    assert_eq!(
        a.types[0].descriptor_string.dex_occurrence_id,
        a.source.dex_occurrence_id
    );
    assert_eq!(
        b.types[0].descriptor_string.dex_occurrence_id,
        b.source.dex_occurrence_id
    );
}

fn build_one(name: &str) -> MetadataFacts {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated")
        .join(name);
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
    MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap()
}

fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in bytes.chunks(5552) {
        for value in chunk {
            a += u32::from(*value);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[test]
fn dex_file_rows_project_validated_raw_header_words() {
    let name = "classic-035.dex";
    let facts = build_one(name);
    let raw = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated")
            .join(name),
    )
    .unwrap();
    let word = |offset: usize| u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap());
    assert_eq!(raw.len(), facts.bytes().len());
    let rows = facts.dex_file_rows(7, 9).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.file_id, 7);
    assert_eq!(row.string_pool_id, 9);
    assert_eq!(row.byte_len, raw.len() as u64);
    assert_eq!(
        row.dex_version,
        String::from_utf8(raw[4..7].to_vec()).unwrap()
    );
    assert_eq!(row.checksum, adler32(&raw[12..]));
    assert_eq!(row.signature_hex, hex_lower(&raw[12..32]));
    assert_eq!(row.file_size, word(32));
    assert_eq!(row.header_size, word(36));
    assert_eq!(row.endian_tag, word(40));
    assert_eq!(row.link_size, word(44));
    assert_eq!(row.link_off, word(48));
    assert_eq!(row.map_off, word(52));
    assert_eq!(row.string_count, word(56));
    assert_eq!(row.string_ids_off, word(60));
    assert_eq!(row.type_count, word(64));
    assert_eq!(row.type_ids_off, word(68));
    assert_eq!(row.proto_count, word(72));
    assert_eq!(row.proto_ids_off, word(76));
    assert_eq!(row.field_count, word(80));
    assert_eq!(row.field_ids_off, word(84));
    assert_eq!(row.method_count, word(88));
    assert_eq!(row.method_ids_off, word(92));
    assert_eq!(row.class_count, word(96));
    assert_eq!(row.class_defs_off, word(100));
    assert_eq!(row.data_size, word(104));
    assert_eq!(row.data_off, word(108));
    // The raw link words are retained even when no link section exists, so
    // an absent section must project as its encoded zero rather than NULL.
    assert_eq!((row.link_size, row.link_off), (word(44), word(48)));
    assert_eq!(row.endian_tag, 0x1234_5678);
    // The table atoms must agree with the header facts that were built from
    // the same occurrence, not with a second parse.
    assert_eq!(row.string_count, facts.string_pool().string_count);
    assert_eq!(
        row.string_ids_off,
        facts.string_pool().string_ids_byte_offset.0 as u32
    );
    assert_eq!(
        row.header_size,
        facts.header().header_range.byte_length.0 as u32
    );
    assert_eq!(row.data_off, facts.header().data_range.byte_offset.0 as u32);
    assert_eq!(
        row.data_size,
        facts.header().data_range.byte_length.0 as u32
    );
}

#[test]
fn dex_file_relation_rejects_provenance_columns_and_star() {
    let facts = build_one("classic-035.dex");
    for column in ["source_path", "entry_name"] {
        let error = facts
            .require_relation_columns(MetadataRelation::DexFiles, &[column])
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::IncompleteFacts, "{column}");
        assert_eq!(
            error
                .details
                .get("required_layer")
                .and_then(|value| value.as_str()),
            Some("input_inventory"),
            "{column}"
        );
    }
    let error = facts
        .require_relation_columns(MetadataRelation::DexFiles, &["*"])
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    assert!(
        facts
            .require_relation_columns(MetadataRelation::DexFiles, DexFileRow::COLUMNS)
            .is_ok()
    );
}

#[test]
fn string_rows_preserve_dex_order_and_lossless_text() {
    let facts = build_one("classic-035.dex");
    let rows = facts.string_rows(3, 4).unwrap();
    assert_eq!(rows.len(), facts.strings().len());
    for (ordinal, row) in rows.iter().enumerate() {
        assert_eq!(row.file_id, 3);
        assert_eq!(row.string_pool_id, 4);
        assert_eq!(row.string_idx, u32::try_from(ordinal).unwrap());
        let fact = &facts.strings()[ordinal];
        assert_eq!(row.string_idx, fact.data.string_idx);
        assert_eq!(
            row.value,
            fact.data.text.strict_utf8().unwrap(),
            "row {ordinal} must be the exact validated text"
        );
    }
    assert!(rows.iter().any(|row| row.value == "Lfixture/A;"));
    assert!(
        facts
            .require_relation_columns(MetadataRelation::Strings, &["*"])
            .is_ok()
    );
}

#[test]
fn type_rows_use_exact_descriptor_display_names() {
    let facts = build_one("type-names-035.dex");
    let rows = facts.type_rows(5).unwrap();
    assert_eq!(rows.len(), facts.types().len());
    for (ordinal, row) in rows.iter().enumerate() {
        assert_eq!(row.file_id, 5);
        assert_eq!(row.type_idx, u32::try_from(ordinal).unwrap());
        let fact = &facts.types()[ordinal];
        assert_eq!(row.type_idx, fact.data.type_idx);
        assert_eq!(row.descriptor, fact.data.descriptor);
        let expected = facts
            .java_type_name(&fact.entity, TypeNameLimits::default())
            .unwrap();
        assert_eq!(row.java_name, expected.value);
    }
    let named = rows
        .iter()
        .find(|row| row.descriptor == "Lfixture/A;")
        .unwrap();
    assert_eq!(named.java_name, "fixture.A");
}

fn contract() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/manifests/relations.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn contract_entry(contract: &Value, relation: &str) -> Value {
    contract["relations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == relation)
        .unwrap_or_else(|| panic!("contract relation {relation} missing"))
        .clone()
}

/// Assert that one assembled relation projects exactly its declared column
/// set with the contract's data type and nullability, and that the only
/// unprojected columns are the documented fact-layer gaps.
fn assert_contract_projection(
    relation: &str,
    columns: &[&str],
    unassembled: &[&str],
    rows: &[Value],
) {
    let entry = contract_entry(&contract(), relation);
    let specs = entry["columns"].as_array().unwrap();
    let contract_names = specs
        .iter()
        .map(|spec| spec["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    for column in columns {
        assert!(
            contract_names.contains(column),
            "{relation}.{column} is not a contract column"
        );
    }
    let extra = columns
        .iter()
        .filter(|column| !contract_names.contains(column))
        .collect::<Vec<_>>();
    assert!(extra.is_empty(), "{relation} projects non-contract columns");
    let mut expected_unassembled = contract_names
        .iter()
        .filter(|name| !columns.contains(name))
        .copied()
        .collect::<Vec<_>>();
    expected_unassembled.sort_unstable();
    let mut unassembled = unassembled.to_vec();
    unassembled.sort_unstable();
    assert_eq!(
        expected_unassembled, unassembled,
        "{relation}: unassembled column set differs from the documented gap"
    );
    for row in rows {
        for spec in specs {
            let name = spec["name"].as_str().unwrap();
            if !columns.contains(&name) {
                assert!(
                    row.get(name).is_none(),
                    "{relation}.{name} must not be projected"
                );
                continue;
            }
            let value = &row[name];
            let nullable = spec["nullable"].as_bool().unwrap();
            if value.is_null() {
                assert!(
                    nullable,
                    "{relation}.{name}: NULL for a non-nullable column"
                );
                continue;
            }
            match spec["data_type"].as_str().unwrap() {
                "UInt32" | "UInt64" => assert!(
                    value.is_u64(),
                    "{relation}.{name}: expected an unsigned integer, got {value}"
                ),
                "Utf8" | "Utf8View" => assert!(
                    value.is_string(),
                    "{relation}.{name}: expected text, got {value}"
                ),
                other => panic!("unhandled contract data type {other}"),
            }
        }
    }
}

#[test]
fn relation_projections_match_contract_columns_types_and_nullability() {
    use crate::code::{CodeItemRow, CodeRelation, MethodCodeFactViews, MethodCodeViewLimits};
    use crate::definitions::{ClassRow, DefinitionRelation, MethodRow};
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};

    // dex_files / strings / types come from one metadata occurrence.
    let metadata = build_one("classic-035.dex");
    let dex_rows = serde_json::to_value(metadata.dex_file_rows(0, 0).unwrap()).unwrap();
    assert_contract_projection(
        "dex_files",
        DexFileRow::COLUMNS,
        &["source_path", "entry_name"],
        dex_rows.as_array().unwrap(),
    );
    let string_rows = serde_json::to_value(metadata.string_rows(0, 0).unwrap()).unwrap();
    assert_contract_projection(
        "strings",
        StringRow::COLUMNS,
        &[],
        string_rows.as_array().unwrap(),
    );
    let metadata = build_one("type-names-035.dex");
    let type_rows = serde_json::to_value(metadata.type_rows(0).unwrap()).unwrap();
    assert_contract_projection(
        "types",
        TypeRow::COLUMNS,
        &[],
        type_rows.as_array().unwrap(),
    );

    // methods / classes / code_items need definitions and code facts.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
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
    let metadata = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
    let definitions =
        crate::definitions::DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
    let code = crate::code::CodeFacts::build_all_code_items(
        &snapshot,
        &inventory,
        0,
        CodeLimits::default(),
    )
    .unwrap();
    let method_rows = serde_json::to_value(definitions.method_rows(0).unwrap()).unwrap();
    assert_contract_projection(
        "methods",
        MethodRow::COLUMNS,
        &["opcode_count", "opcode_hex"],
        method_rows.as_array().unwrap(),
    );
    let class_rows = serde_json::to_value(definitions.class_rows(0).unwrap()).unwrap();
    assert_contract_projection(
        "classes",
        ClassRow::COLUMNS,
        &[],
        class_rows.as_array().unwrap(),
    );
    let views =
        MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default()).unwrap();
    views
        .require_relation_columns(CodeRelation::CodeItems, CodeItemRow::COLUMNS)
        .unwrap();
    // The code-joined projection covers all 14 `methods` columns.
    let joined_methods = serde_json::to_value(views.method_rows(0).unwrap()).unwrap();
    assert_contract_projection(
        "methods",
        crate::code::MethodCodeRow::COLUMNS,
        &[],
        joined_methods.as_array().unwrap(),
    );
    let code_rows = serde_json::to_value(views.code_item_rows(0).unwrap()).unwrap();
    assert_contract_projection(
        "code_items",
        CodeItemRow::COLUMNS,
        &[],
        code_rows.as_array().unwrap(),
    );
    assert!(
        definitions
            .require_relation_columns(DefinitionRelation::Classes, ClassRow::COLUMNS)
            .is_ok()
    );
}

#[test]
fn method_relation_keeps_restricted_columns_rejected() {
    use crate::definitions::DefinitionRelation;
    use mdd_dex::definitions::DefinitionLimits;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
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
    let metadata = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
    let definitions =
        crate::definitions::DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
    // `param_descriptors` is assembled by the definition layer; only the two
    // code-layout opcode columns stay rejected there.
    assert!(
        definitions
            .require_relation_columns(DefinitionRelation::Methods, &["param_descriptors"])
            .is_ok()
    );
    for column in ["opcode_count", "opcode_hex"] {
        let error = definitions
            .require_relation_columns(DefinitionRelation::Methods, &[column])
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::IncompleteFacts, "{column}");
        assert_eq!(
            error
                .details
                .get("required_layer")
                .and_then(|value| value.as_str()),
            Some("code_layout"),
            "{column}"
        );
    }
    // A restricted column must never be silently included by a star request.
    assert!(
        definitions
            .require_relation_columns(DefinitionRelation::Methods, &["*"])
            .is_err()
    );
}
