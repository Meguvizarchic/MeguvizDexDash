//! Comparison with retained fixed-A0 synthetic output; not full compatibility.
use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
use mdd_facts::{
    MetadataFacts,
    code::{CodeFacts, MethodCodeFactViews, MethodCodeViewLimits, OpcodeTextLimits},
    definitions::DefinitionFacts,
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use std::{collections::BTreeMap, fs, path::PathBuf};

fn decode_cell(input: &str) -> Option<String> {
    if input == "N" {
        return None;
    }
    assert_eq!(input.len() % 2, 0);
    let bytes = input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect::<Vec<_>>();
    Some(String::from_utf8(bytes).unwrap())
}

#[test]
fn opcode_projection_matches_retained_a0_synthetic_methods() {
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
    for (case, fixture, expected_input_hash, expected_output_hash, expected_count) in cases {
        let path = root.join(fixture);
        assert_eq!(
            mdd_types::sha256(&fs::read(&path).unwrap()),
            expected_input_hash
        );
        let saved = fs::read(audit.join(format!("a0-{case}/stdout.txt"))).unwrap();
        assert_eq!(mdd_types::sha256(&saved), expected_output_hash);
        let table = std::str::from_utf8(&saved).unwrap();
        let mut expected = BTreeMap::new();
        for line in table.lines().filter(|line| line.starts_with('|')) {
            let cells: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
            if cells[0] == "file_id" {
                continue;
            }
            assert_eq!(cells.len(), 14);
            let index: u32 = decode_cell(cells[1]).unwrap().parse().unwrap();
            let count = decode_cell(cells[11]).map(|value| value.parse::<u32>().unwrap());
            let text = decode_cell(cells[12]);
            assert!(expected.insert(index, (count, text)).is_none());
        }
        assert_eq!(expected.len(), expected_count);
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
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        let view = MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default())
            .unwrap();
        for row in view.iter() {
            let row = row.unwrap();
            let projection = row.body.opcode_text(OpcodeTextLimits::default()).unwrap();
            let actual = match projection {
                Some(value) => (Some(value.count), Some(value.text)),
                None => (None, None),
            };
            assert_eq!(
                Some(actual),
                expected.remove(&row.method.reference.method_idx),
                "{case} method {}",
                row.method.reference.method_idx
            );
        }
        assert!(
            expected.is_empty(),
            "{case} contains undelivered method rows"
        );
    }
}
