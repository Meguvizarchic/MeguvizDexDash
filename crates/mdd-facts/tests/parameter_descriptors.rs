//! Scoped A0 and independent synthetic comparisons, not profile qualification.
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{
    MetadataFacts,
    definitions::{
        DefinitionFacts, MethodViewLimits, ParameterDescriptorLimits, PrototypeParameterLimits,
    },
    metadata::EntityKind,
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::ErrorCode;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

fn decode_hex(input: &str) -> Vec<u8> {
    assert_ne!(input, "N");
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}

fn facts(path: &Path, copies: usize) -> Vec<DefinitionFacts> {
    let input = InputSpec {
        path: path.into(),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&vec![input; copies], CaptureLimits::default()).unwrap();
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
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap()
        })
        .collect()
}

#[test]
fn parameter_text_matches_retained_a0_rows() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let audit = root.join("artifacts/mdd-026/method-atom-audit/20261028T165707192974Z");
    let cases = [
        (
            "definitions",
            "tests/fixtures/definitions/generated/definitions-035.dex",
            "4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc",
            "eedd5fd9929af81b06fbae0024c63e95acf0bcc552c9019cee0793a17b0fb9b8",
            13usize,
        ),
        (
            "shared",
            "tests/fixtures/references/generated/shared-code-035.dex",
            "22eb2d4020f172334a99f5c75538af5f2b3e80673adb11803b368cc68aaec0ab",
            "34f201838aaf6da5464344c179905d9678b7b9ebeedb268143afa892c79927e9",
            5,
        ),
        (
            "dynamic",
            "tests/fixtures/references/generated/poly-custom-038.dex",
            "25bc5a03641d31d87212a9a292d798e64c563e2666d03f579e7fc894ac8ee425",
            "d6ec188cd22987cba17c800231be0e0e0550e09d37c715e4158f5e23e4cb678d",
            6,
        ),
    ];
    for (case, name, input_hash, output_hash, count) in cases {
        let path = root.join(name);
        assert_eq!(mdd_types::sha256(&fs::read(&path).unwrap()), input_hash);
        let raw = fs::read(audit.join(format!("a0-{case}/stdout.txt"))).unwrap();
        assert_eq!(mdd_types::sha256(&raw), output_hash);
        let table = std::str::from_utf8(&raw).unwrap();
        let mut expected = BTreeMap::new();
        for line in table.lines().filter(|line| line.starts_with('|')) {
            let cells: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
            if cells[0] == "file_id" {
                continue;
            }
            assert_eq!(cells.len(), 14);
            let index: u32 = String::from_utf8(decode_hex(cells[1]))
                .unwrap()
                .parse()
                .unwrap();
            let n: usize = String::from_utf8(decode_hex(cells[8]))
                .unwrap()
                .parse()
                .unwrap();
            assert!(expected.insert(index, (n, decode_hex(cells[9]))).is_none());
        }
        assert_eq!(expected.len(), count);
        let all = facts(&path, 1);
        let fact = &all[0];
        let view = fact.method_fact_views(MethodViewLimits::default()).unwrap();
        for row in view.iter() {
            let row = row.unwrap();
            let id = fact
                .entity(EntityKind::MethodReference, row.reference.method_idx)
                .unwrap();
            let params = view
                .parameter_types(&id, PrototypeParameterLimits::default())
                .unwrap();
            let got = params
                .descriptor_text(ParameterDescriptorLimits::default())
                .unwrap();
            let (expected_count, bytes) = expected.remove(&id.local_index).unwrap();
            assert_eq!(params.iter().count(), expected_count);
            assert_eq!(got.raw_mutf8, bytes, "{case} method {}", id.local_index);
            assert_eq!(
                got.utf16_units,
                std::str::from_utf8(&bytes)
                    .unwrap()
                    .encode_utf16()
                    .collect::<Vec<_>>()
            );
        }
        assert!(expected.is_empty());
    }
}

#[test]
fn parameter_text_preserves_utf16_mutf8_occurrences_and_limits() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let base = root.join("tests/fixtures/parameter_descriptors");
    let oracle: serde_json::Value =
        serde_json::from_slice(&fs::read(base.join("expected.json")).unwrap()).unwrap();
    let dex = base.join("unicode-parameters-038.dex");
    assert_eq!(
        mdd_types::sha256(&fs::read(&dex).unwrap()),
        oracle["fixture_sha256"].as_str().unwrap()
    );
    let raw = decode_hex(oracle["raw_mutf8_hex"].as_str().unwrap());
    let units: Vec<u16> = oracle["utf16_units"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| u16::try_from(v.as_u64().unwrap()).unwrap())
        .collect();
    assert!(std::str::from_utf8(&raw).is_err());
    let all = facts(&dex, 2);
    assert_ne!(
        all[0].metadata().source().dex_occurrence_id,
        all[1].metadata().source().dex_occurrence_id
    );
    for fact in &all {
        let view = fact.method_fact_views(MethodViewLimits::default()).unwrap();
        let row = view
            .iter()
            .map(Result::unwrap)
            .find(|row| row.reference.method_name == "bootstrap")
            .unwrap();
        assert!(row.definition.is_none());
        let id = fact
            .entity(EntityKind::MethodReference, row.reference.method_idx)
            .unwrap();
        let params = view
            .parameter_types(&id, PrototypeParameterLimits::default())
            .unwrap();
        let exact = ParameterDescriptorLimits {
            max_parameters: 3,
            max_raw_bytes: raw.len() as u64,
            max_utf16_units: units.len() as u64,
        };
        let got = params.descriptor_text(exact).unwrap();
        assert_eq!(got.raw_mutf8, raw);
        assert_eq!(got.utf16_units, units);
        for limited in [
            ParameterDescriptorLimits {
                max_parameters: 2,
                ..exact
            },
            ParameterDescriptorLimits {
                max_raw_bytes: raw.len() as u64 - 1,
                ..exact
            },
            ParameterDescriptorLimits {
                max_utf16_units: units.len() as u64 - 1,
                ..exact
            },
        ] {
            assert_eq!(
                params.descriptor_text(limited).unwrap_err().code,
                ErrorCode::QuotaExceeded
            );
        }
    }
    let view = all[0]
        .method_fact_views(MethodViewLimits::default())
        .unwrap();
    let other = all[1]
        .method_fact_views(MethodViewLimits::default())
        .unwrap();
    let index = other
        .iter()
        .map(Result::unwrap)
        .find(|row| row.reference.method_name == "bootstrap")
        .unwrap()
        .reference
        .method_idx;
    let foreign = all[1].entity(EntityKind::MethodReference, index).unwrap();
    assert_eq!(
        view.parameter_types(&foreign, PrototypeParameterLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn nonscalar_parameter_descriptor_is_rejected_during_metadata_read() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let base = root.join("tests/fixtures/parameter_descriptors");
    let oracle: serde_json::Value =
        serde_json::from_slice(&fs::read(base.join("expected.json")).unwrap()).unwrap();
    let dex = base.join("nonscalar-parameters-038.dex");
    assert_eq!(
        mdd_types::sha256(&fs::read(&dex).unwrap()),
        oracle["nonscalar_fixture_sha256"].as_str().unwrap()
    );
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path: dex,
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
    let error = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.message, "NON_SCALAR_DESCRIPTOR_OR_SHORTY");
}
