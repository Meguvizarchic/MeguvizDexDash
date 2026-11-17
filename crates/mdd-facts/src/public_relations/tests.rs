//! Row projections of the public relations: the cases the recorded reference answers do not reach, and the
//! malformed input the hidden API section must refuse.
use super::values::read_uleb128_for_tests;
use crate::{DefinitionFacts, MetadataFacts, code::*};
use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::ErrorCode;
use sha1::{Digest, Sha1};
use std::{fs, path::PathBuf};

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn definitions_at(path: PathBuf) -> (Snapshot, ArchiveInventory, DefinitionFacts) {
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
    let metadata = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
    let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
    (snapshot, inventory, definitions)
}

fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for value in bytes {
        a = (a + u32::from(*value)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// The DEX with its signature and checksum made right again after a byte was changed.
fn sealed(mut bytes: Vec<u8>) -> Vec<u8> {
    let signature = Sha1::digest(&bytes[32..]);
    bytes[12..32].copy_from_slice(&signature);
    let checksum = adler32(&bytes[12..]);
    bytes[8..12].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

/// Where the hidden API section starts, read from the map.
fn hiddenapi_start(bytes: &[u8]) -> usize {
    let map_off = u32::from_le_bytes(bytes[52..56].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(bytes[map_off..map_off + 4].try_into().unwrap()) as usize;
    (0..count)
        .map(|index| map_off + 4 + 12 * index)
        .find(|at| u16::from_le_bytes(bytes[*at..*at + 2].try_into().unwrap()) == 0xF000)
        .map(|at| u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize)
        .expect("the fixture has a hidden API section")
}

fn temp_copy(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "mdd-public-relations-{}-{name}.dex",
        std::process::id()
    ));
    fs::write(&path, bytes).unwrap();
    path
}

/// A way to damage a copy of the fixture.
type Damage = Box<dyn Fn(&mut Vec<u8>)>;

fn flags_of(path: PathBuf) -> Result<Vec<(u32, &'static str, u32, u32)>, mdd_types::MddError> {
    let (_, _, definitions) = definitions_at(path);
    definitions.hiddenapi_flag_rows(0).map(|rows| {
        rows.into_iter()
            .map(|row| (row.ordinal, row.member_kind, row.member_idx, row.flag))
            .collect()
    })
}

#[test]
fn hidden_api_flags_follow_the_class_data_order_and_name_members_by_their_index() {
    // fields a (instance, index 0) and b (static, index 1); methods m (virtual, index 0) and n (direct, index 1).
    // The class data lists the static field, the instance field, the direct method, then the virtual method.
    let rows = flags_of(fixture(
        "tests/fixtures/public_relations/generated/hiddenapi-order-039.dex",
    ))
    .unwrap();
    assert_eq!(
        rows,
        vec![
            (0, "field", 1, 5),
            (1, "field", 0, 6),
            (2, "method", 1, 7),
            (3, "method", 0, 8),
        ]
    );
}

#[test]
fn a_dex_without_hidden_api_data_has_no_hidden_api_rows() {
    let rows = flags_of(fixture("tests/fixtures/generated/minimal-035.dex")).unwrap();
    assert!(rows.is_empty());
}

#[test]
fn malformed_hidden_api_data_is_refused_not_read_past() {
    let original = fs::read(fixture(
        "tests/fixtures/public_relations/generated/hiddenapi-039.dex",
    ))
    .unwrap();
    let start = hiddenapi_start(&original);
    // the item is: size, one class offset (8), then four flags padded to a word
    let cases: [(&str, &str, Damage); 5] = [
        (
            "size beyond the section",
            "HIDDENAPI_SIZE",
            Box::new(move |b| {
                b[start..start + 4].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
            }),
        ),
        (
            "size below the offset table",
            "HIDDENAPI_SIZE",
            Box::new(move |b| {
                b[start..start + 4].copy_from_slice(&4u32.to_le_bytes());
            }),
        ),
        (
            "class offset inside the offset table",
            "HIDDENAPI_CLASS_OFFSET",
            Box::new(move |b| {
                b[start + 4..start + 8].copy_from_slice(&4u32.to_le_bytes());
            }),
        ),
        (
            "class offset past the item",
            "HIDDENAPI_CLASS_OFFSET",
            Box::new(move |b| {
                b[start + 4..start + 8].copy_from_slice(&0x1000u32.to_le_bytes());
            }),
        ),
        (
            "a flag that never ends",
            "HIDDENAPI_FLAGS",
            Box::new(move |b| {
                // every flag byte of the fixture becomes a continuation byte
                b[start + 8..start + 12].fill(0x80);
            }),
        ),
    ];
    for (name, reason, damage) in cases {
        let mut bytes = original.clone();
        damage(&mut bytes);
        let path = temp_copy(&name.replace(' ', "-"), &sealed(bytes));
        let result = flags_of(path.clone());
        let _ = fs::remove_file(&path);
        let error = result.expect_err(name);
        assert_eq!(error.code, ErrorCode::InvalidInput, "{name}");
        assert_eq!(error.details["reason"], reason, "{name}: {error:?}");
    }
}

#[test]
fn a_flag_is_an_unsigned_leb128_of_at_most_five_bytes_below_the_limit() {
    assert_eq!(read_uleb128_for_tests(&[0x05], 1), Some((5, 1)));
    assert_eq!(read_uleb128_for_tests(&[0x80, 0x01], 2), Some((128, 2)));
    assert_eq!(
        read_uleb128_for_tests(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F], 5),
        Some((u32::MAX, 5))
    );
    // too many bytes, a value above 32 bits, and a limit that cuts the value off
    assert_eq!(
        read_uleb128_for_tests(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00], 6),
        None
    );
    assert_eq!(
        read_uleb128_for_tests(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F], 5),
        None
    );
    assert_eq!(read_uleb128_for_tests(&[0x80, 0x01], 1), None);
    assert_eq!(read_uleb128_for_tests(&[], 0), None);
}

#[test]
fn a_literal_is_also_read_as_a_float_by_the_bits_of_the_value_not_of_the_field() {
    // decode-all holds const/high16, const-wide/high16 and the 32- and 64-bit constants, with -0.0, NaN and 1.0
    let (snapshot, inventory, definitions) =
        definitions_at(fixture("tests/fixtures/decode/generated/decode-all.dex"));
    let code =
        CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default()).unwrap();
    let views =
        MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default()).unwrap();
    let rows = views.method_number_rows(0).unwrap();
    let find = |opcode: u32, value: i64| {
        rows.iter()
            .find(|row| row.opcode == opcode && row.long_value == value)
            .unwrap_or_else(|| panic!("no literal {value} under opcode {opcode}"))
    };
    // const/high16 0x80000000: the float -0.0, not the tiny number the 16-bit field alone would be
    let negative_zero = find(0x15, -2_147_483_648).double_value.unwrap();
    assert!(negative_zero == 0.0 && negative_zero.is_sign_negative());
    assert_eq!(find(0x15, 1_065_353_216).double_value, Some(1.0));
    // const-wide/high16 0xBFF0...: the double -1.0
    assert_eq!(
        find(0x19, -4_616_189_618_054_758_400).double_value,
        Some(-1.0)
    );
    // the byte, short and 16-bit wide literals have no floating point reading
    assert!(
        rows.iter()
            .filter(|row| matches!(row.number_type, "byte" | "short"))
            .all(|row| row.double_value.is_none())
    );
    assert!(!rows.is_empty() && rows.iter().all(|row| row.file_id == 0));
}
