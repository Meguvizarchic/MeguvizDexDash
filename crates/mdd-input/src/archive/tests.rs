use super::*;
use crate::snapshot::{CaptureLimits, InputSpec, Snapshot};
use mdd_types::opaque_id;
use serde_json::Value;
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated")
        .join(name)
}
fn capture(path: PathBuf, kind: InputKind) -> Snapshot {
    Snapshot::capture(
        &[InputSpec {
            path,
            kind,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap()
}
fn generic() -> InventoryPolicy {
    InventoryPolicy {
        dex_selection: DexSelection::AllDexMembers,
        reject_duplicate_selected_names: false,
        require_dex: true,
    }
}
fn temporary(bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(opaque_id("mdd-archive-test").unwrap());
    fs::create_dir(&path).unwrap();
    let file = path.join("input.apk");
    fs::write(&file, bytes).unwrap();
    file
}
fn inventory(name: &str, policy: InventoryPolicy) -> ArchiveInventory {
    let snapshot = capture(fixture(name), InputKind::Apk);
    ArchiveInventory::build(&snapshot.sources()[0], policy, ArchiveLimits::default()).unwrap()
}
fn one_resource() -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "assets/raw.bin",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(b"\0\xffresource").unwrap();
    writer.finish().unwrap().into_inner()
}
/// Build a single-member archive whose payload is `payload`, so the preallocated
/// read path can be exercised with sizes well beyond the 4 MiB eager window.
fn one_member(payload: &[u8], method: zip::CompressionMethod) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "assets/payload.bin",
            zip::write::SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
    writer.write_all(payload).unwrap();
    writer.finish().unwrap().into_inner()
}
fn raw_policy() -> InventoryPolicy {
    InventoryPolicy {
        dex_selection: DexSelection::ResourcesOnly,
        reject_duplicate_selected_names: false,
        require_dex: false,
    }
}

#[test]
fn fixtures_match_independent_physical_inventory_and_raw_content() {
    let manifest: Value =
        serde_json::from_str(include_str!("../../../../tests/fixtures/manifest.json")).unwrap();
    let mut checked = 0;
    for case in manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "zip")
    {
        let name = Path::new(case["path"].as_str().unwrap())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let snapshot = capture(fixture(name), InputKind::Apk);
        let outcome =
            ArchiveInventory::build(&snapshot.sources()[0], generic(), ArchiveLimits::default());
        if case["expected"] == "CRC_MISMATCH" || case["expected"] == "invalid_selected_dex_magic" {
            assert_eq!(
                outcome.err().unwrap().code,
                ErrorCode::InvalidInput,
                "{name}"
            );
            checked += 1;
            continue;
        }
        let result = outcome.unwrap();
        let names: Vec<_> = result
            .manifest()
            .members
            .iter()
            .map(|m| m.name_utf8.as_deref().unwrap())
            .collect();
        let expected: Vec<_> = case["member_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        assert_eq!(names, expected, "{name}");
        for (ordinal, m) in result.manifest().members.iter().enumerate() {
            assert_eq!(m.archive_member_ordinal, Some(DecimalU64(ordinal as u64)));
        }
        for selected in result.selected_dexes() {
            assert_eq!(selected.logical_header_byte_offset, DecimalU64(0));
            assert_eq!(selected.blob.bytes().get(..4), Some(b"dex\n".as_slice()));
        }
        if name.starts_with("multidex-") {
            let dexes = result.selected_dexes();
            assert_eq!(dexes.len(), 2);
            assert_eq!(
                dexes[0].blob.content_id,
                "sha256:108cf907d330b823c6e32d38eaab8f23709fe493f52537688bbd09ba3e271605"
            );
            assert_eq!(
                dexes[1].blob.content_id,
                "sha256:e0aeaa1d698e1d1149ffdcf116e7b3e98b3a3097814e01718c80caaee147b7ae"
            );
            let resource = result
                .manifest()
                .members
                .iter()
                .find(|m| m.raw_name == b"assets/raw.bin")
                .unwrap();
            assert_eq!(
                result.read_member(&resource.member_id).unwrap().bytes(),
                b"\0\xffresource"
            );
        }
        println!(
            "MDD_INVENTORY {}",
            serde_json::json!({"fixture":name,"manifest":result.manifest(),"selected_dexes":result.selected_dexes()})
        );
        checked += 1;
    }
    assert_eq!(checked, 8);
}

#[test]
fn duplicate_names_and_contents_retain_distinct_occurrences() {
    let bytes = fs::read(fixture("duplicate-name.apk")).unwrap();
    assert_eq!(zip::ZipArchive::new(Cursor::new(&bytes)).unwrap().len(), 1);
    let result = inventory("duplicate-name.apk", generic());
    assert_eq!(result.manifest().members.len(), 2);
    assert_eq!(result.selected_dexes().len(), 2);
    assert_eq!(
        result.manifest().members[0].raw_name,
        result.manifest().members[1].raw_name
    );
    assert_ne!(
        result.selected_dexes()[0].dex_occurrence_id,
        result.selected_dexes()[1].dex_occurrence_id
    );
    assert_ne!(
        result.selected_dexes()[0].blob.content_id,
        result.selected_dexes()[1].blob.content_id
    );
    let snapshot = capture(fixture("duplicate-name.apk"), InputKind::Apk);
    assert_eq!(
        ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default()
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::AmbiguousEntity
    );
    let same = inventory("duplicate-content.apk", InventoryPolicy::default());
    assert_eq!(
        same.selected_dexes()[0].blob.content_id,
        same.selected_dexes()[1].blob.content_id
    );
    assert_eq!(
        same.selected_dexes()[0].physical_dex_id,
        same.selected_dexes()[1].physical_dex_id
    );
    assert_ne!(
        same.selected_dexes()[0].dex_occurrence_id,
        same.selected_dexes()[1].dex_occurrence_id
    );
}

#[test]
fn selection_scope_resource_only_and_raw_dex_are_explicit() {
    let top = inventory("member-policy.apk", InventoryPolicy::default());
    assert_eq!(top.selected_dexes().len(), 2);
    assert_eq!(
        top.selected_dexes()[0].blob.identity.raw_name,
        b"classes10.dex"
    );
    assert_eq!(
        top.selected_dexes()[1].blob.identity.raw_name,
        b"classes2.dex"
    );
    let all = inventory("member-policy.apk", generic());
    assert_eq!(all.selected_dexes().len(), 4);
    assert_eq!(
        all.selected_dexes()[3].blob.identity.raw_name,
        b"../escape.dex"
    );
    let bytes = one_resource();
    let path = temporary(&bytes);
    let snapshot = capture(path.clone(), InputKind::Apk);
    let policy = InventoryPolicy {
        dex_selection: DexSelection::ResourcesOnly,
        reject_duplicate_selected_names: false,
        require_dex: false,
    };
    let resources =
        ArchiveInventory::build(&snapshot.sources()[0], policy, ArchiveLimits::default()).unwrap();
    assert!(resources.selected_dexes().is_empty());
    assert_eq!(
        resources
            .read_member(&resources.manifest().members[0].member_id)
            .unwrap()
            .bytes(),
        b"\0\xffresource"
    );
    assert_eq!(
        ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default()
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::PartialInput
    );
    let raw = capture(fixture("minimal-035.dex"), InputKind::RawDex);
    let result = ArchiveInventory::build(
        &raw.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(result.manifest().members[0].archive_member_ordinal, None);
    assert_eq!(
        result.selected_dexes()[0].blob.bytes(),
        raw.sources()[0].bytes()
    );
    assert_eq!(
        ArchiveInventory::build(&raw.sources()[0], policy, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(!path.parent().unwrap().join("escape.dex").exists());
}

#[test]
fn all_reads_use_owned_capture_and_member_identity() {
    let bytes = fs::read(fixture("multidex-deflated.apk")).unwrap();
    let path = temporary(&bytes);
    let inputs = [
        InputSpec {
            path: path.clone(),
            kind: InputKind::Apk,
            expected_sha256: None,
        },
        InputSpec {
            path: path.clone(),
            kind: InputKind::Apk,
            expected_sha256: None,
        },
    ];
    let snapshot = Snapshot::capture(&inputs, CaptureLimits::default()).unwrap();
    let times = fs::metadata(&path).unwrap();
    fs::write(&path, vec![b'x'; bytes.len()]).unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(times.modified().unwrap()))
        .unwrap();
    fs::rename(&path, path.with_extension("renamed")).unwrap();
    let one = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let two = ArchiveInventory::build(
        &snapshot.sources()[1],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(
        one.selected_dexes()[0].blob.content_id,
        two.selected_dexes()[0].blob.content_id
    );
    assert_ne!(
        one.selected_dexes()[0].dex_occurrence_id,
        two.selected_dexes()[0].dex_occurrence_id
    );
    let resource = one.manifest().members[3].member_id.clone();
    assert_eq!(
        one.read_member(&resource).unwrap().bytes(),
        b"\0\xffresource"
    );
    assert_eq!(
        two.read_member(&resource).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    drop(snapshot);
    assert_eq!(
        one.read_member(&resource).unwrap().bytes(),
        b"\0\xffresource"
    );
}

#[test]
fn budgets_corrupt_ranges_crc_and_unsupported_formats_fail_closed() {
    let snapshot = capture(fixture("multidex-deflated.apk"), InputKind::Apk);
    for limits in [
        ArchiveLimits {
            max_members: 0,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            max_directory_bytes: 0,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            max_member_bytes: 0,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            max_total_uncompressed_bytes: 0,
            ..ArchiveLimits::default()
        },
    ] {
        assert_eq!(
            ArchiveInventory::build(&snapshot.sources()[0], generic(), limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    let corrupt = capture(fixture("bad-crc.apk"), InputKind::Apk);
    let error = ArchiveInventory::build(&corrupt.sources()[0], generic(), ArchiveLimits::default())
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.stage, "archive.member_bytes");
    assert_eq!(error.details["input_coverage"], "partial");
    let mut bytes = one_resource();
    let end = bytes.len() - 22;
    bytes[end + 10..end + 12].copy_from_slice(&u16::MAX.to_le_bytes());
    let source = capture(temporary(&bytes), InputKind::Apk);
    assert_eq!(
        ArchiveInventory::build(&source.sources()[0], generic(), ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
    let mut bytes = one_resource();
    let end = bytes.len() - 22;
    bytes[end + 16..end + 20].copy_from_slice(&0xfffffff0u32.to_le_bytes());
    let source = capture(temporary(&bytes), InputKind::Apk);
    assert_eq!(
        ArchiveInventory::build(&source.sources()[0], generic(), ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
    for version in ["036", "041"] {
        let source = capture(
            fixture(&format!("unsupported-{version}.dex")),
            InputKind::RawDex,
        );
        assert_eq!(
            ArchiveInventory::build(&source.sources()[0], generic(), ArchiveLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::UnsupportedCapability
        );
    }
}

#[test]
fn data_descriptor_and_lazy_resource_crc_are_checked() {
    let bytes = one_resource();
    let end = bytes.len() - 22;
    let central = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
    let mut descriptor = Vec::from(b"PK\x07\x08".as_slice());
    descriptor.extend_from_slice(&bytes[14..26]);
    let mut transformed = bytes[..central].to_vec();
    transformed.extend_from_slice(&descriptor);
    transformed.extend_from_slice(&bytes[central..]);
    let new_central = central + 16;
    let new_end = end + 16;
    transformed[6..8].copy_from_slice(&8u16.to_le_bytes());
    transformed[14..26].fill(0);
    transformed[new_central + 8..new_central + 10].copy_from_slice(&8u16.to_le_bytes());
    transformed[new_end + 16..new_end + 20].copy_from_slice(&(new_central as u32).to_le_bytes());
    let policy = InventoryPolicy {
        dex_selection: DexSelection::ResourcesOnly,
        reject_duplicate_selected_names: false,
        require_dex: false,
    };
    let source = capture(temporary(&transformed), InputKind::Apk);
    let result =
        ArchiveInventory::build(&source.sources()[0], policy, ArchiveLimits::default()).unwrap();
    assert_eq!(
        result
            .read_member(&result.manifest().members[0].member_id)
            .unwrap()
            .bytes(),
        b"\0\xffresource"
    );
    transformed[central + 4] ^= 1;
    let source = capture(temporary(&transformed), InputKind::Apk);
    assert_eq!(
        ArchiveInventory::build(&source.sources()[0], policy, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
    let mut corrupt = one_resource();
    corrupt[30 + "assets/raw.bin".len()] ^= 1;
    let source = capture(temporary(&corrupt), InputKind::Apk);
    let result =
        ArchiveInventory::build(&source.sources()[0], policy, ArchiveLimits::default()).unwrap();
    assert_eq!(
        result.manifest().resource_byte_validation,
        "lazy; each read checks size and CRC before returning bytes"
    );
    assert_eq!(
        result
            .read_member(&result.manifest().members[0].member_id)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
}

#[test]
fn raw_member_names_and_malformed_declared_sizes_are_not_normalized() {
    let policy = InventoryPolicy {
        dex_selection: DexSelection::ResourcesOnly,
        reject_duplicate_selected_names: false,
        require_dex: false,
    };
    let mut bytes = one_resource();
    let end = bytes.len() - 22;
    let central = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
    bytes[30] = 0xff;
    bytes[central + 46] = 0xff;
    let source = capture(temporary(&bytes), InputKind::Apk);
    let result =
        ArchiveInventory::build(&source.sources()[0], policy, ArchiveLimits::default()).unwrap();
    assert_eq!(result.manifest().members[0].raw_name[0], 0xff);
    assert!(result.manifest().members[0].name_utf8.is_none());
    assert_eq!(
        result
            .read_member(&result.manifest().members[0].member_id)
            .unwrap()
            .bytes(),
        b"\0\xffresource"
    );
    let mut bytes = one_resource();
    let end = bytes.len() - 22;
    let central = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
    bytes[22..26].copy_from_slice(&1u32.to_le_bytes());
    bytes[central + 24..central + 28].copy_from_slice(&1u32.to_le_bytes());
    let source = capture(temporary(&bytes), InputKind::Apk);
    assert_eq!(
        ArchiveInventory::build(&source.sources()[0], policy, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
    let mut bytes = one_resource();
    let end = bytes.len() - 22;
    bytes[end + 8..end + 10].copy_from_slice(&0u16.to_le_bytes());
    let source = capture(temporary(&bytes), InputKind::Apk);
    assert_eq!(
        ArchiveInventory::build(&source.sources()[0], policy, ArchiveLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
}

#[test]
fn preallocated_reads_fill_exactly_declared_bytes_for_stored_and_deflated() {
    // Payload spans several multiplications of the 4 MiB eager window so both the
    // reservation and the doubling growth path are exercised.
    let payload: Vec<u8> = (0..(9 * 1024 * 1024u32 + 12345))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 17) as u8)
        .collect();
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let bytes = one_member(&payload, method);
        let source = capture(temporary(&bytes), InputKind::Apk);
        let result =
            ArchiveInventory::build(&source.sources()[0], raw_policy(), ArchiveLimits::default())
                .unwrap();
        let blob = result
            .read_member(&result.manifest().members[0].member_id)
            .unwrap();
        assert_eq!(blob.bytes(), payload.as_slice(), "{method:?}");
        assert_eq!(blob.content_id, content_id(&payload));
    }
}

#[test]
fn empty_and_single_byte_members_keep_crc_semantics() {
    for payload in [&b""[..], &b"x"[..]] {
        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let bytes = one_member(payload, method);
            let source = capture(temporary(&bytes), InputKind::Apk);
            let result = ArchiveInventory::build(
                &source.sources()[0],
                raw_policy(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let blob = result
                .read_member(&result.manifest().members[0].member_id)
                .unwrap();
            assert_eq!(blob.bytes(), payload, "{method:?}");
        }
    }
}

#[test]
fn declared_size_smaller_than_payload_is_rejected_before_returning_bytes() {
    // Patch the central and local declared size down by one byte; the stored
    // member then decompresses to more bytes than declared.
    let mut bytes = one_member(b"0123456789abcdef", zip::CompressionMethod::Stored);
    let end = bytes.len() - 22;
    let central = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
    for at in [22usize, central + 24] {
        bytes[at..at + 4].copy_from_slice(&15u32.to_le_bytes());
    }
    let source = capture(temporary(&bytes), InputKind::Apk);
    let error =
        ArchiveInventory::build(&source.sources()[0], raw_policy(), ArchiveLimits::default())
            .err()
            .unwrap();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert!(error.details.contains_key("source_occurrence_id"));
}

#[test]
fn declared_size_larger_than_payload_fails_as_length_mismatch() {
    // DEFLATE keeps a compressed size that disagrees with the payload length, so
    // the directory scan admits the member and only the read-time length check
    // can catch the over-declaration.
    let mut bytes = one_member(b"0123456789abcdef", zip::CompressionMethod::Deflated);
    let end = bytes.len() - 22;
    let central = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
    for at in [22usize, central + 24] {
        bytes[at..at + 4].copy_from_slice(&17u32.to_le_bytes());
    }
    let source = capture(temporary(&bytes), InputKind::Apk);
    let result =
        ArchiveInventory::build(&source.sources()[0], raw_policy(), ArchiveLimits::default())
            .unwrap();
    let error = result
        .read_member(&result.manifest().members[0].member_id)
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.stage, "archive.member_bytes");
    assert_eq!(
        error.message,
        "actual decompressed length differs from declared size"
    );
}

#[test]
fn read_budget_is_checked_before_allocating_the_declared_size() {
    // The directory scan admits this member under default limits; a reused
    // inventory with a tighter member budget must refuse before allocating.
    let bytes = one_member(&vec![7u8; 8 * 1024 * 1024], zip::CompressionMethod::Stored);
    let source = capture(temporary(&bytes), InputKind::Apk);
    let result = ArchiveInventory::build(
        &source.sources()[0],
        raw_policy(),
        ArchiveLimits {
            max_member_bytes: 1024 * 1024,
            ..ArchiveLimits::default()
        },
    );
    let error = result.err().unwrap();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.stage, "archive.budget");
}

#[test]
fn preallocated_read_still_verifies_crc_for_stored_and_deflated_members() {
    // Flip one payload byte while leaving the central sizes and CRC untouched, so
    // only the CRC comparison can reject the read. Both single-allocation paths
    // (stored passthrough and inflated) must surface the same stage and reason as
    // the previous buffered loop.
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let mut bytes = one_member(b"payload-abcdefghijklmnopqrstuvwxyz", method);
        let end = bytes.len() - 22;
        let local = 30 + "assets/payload.bin".len();
        bytes[local] ^= 1;
        assert_eq!(&bytes[end..end + 4], b"PK\x05\x06");
        let source = capture(temporary(&bytes), InputKind::Apk);
        let result =
            ArchiveInventory::build(&source.sources()[0], raw_policy(), ArchiveLimits::default())
                .unwrap();
        let error = result
            .read_member(&result.manifest().members[0].member_id)
            .err()
            .unwrap_or_else(|| panic!("{method:?} accepted corrupted payload"));
        assert_eq!(error.code, ErrorCode::InvalidInput, "{method:?}");
        assert_eq!(error.stage, "archive.member_bytes", "{method:?}");
        assert_eq!(
            error.details["reason"], "CRC_OR_DECOMPRESSION_FAILURE",
            "{method:?}"
        );
        assert_eq!(error.details["input_coverage"], "partial", "{method:?}");
        assert_eq!(error.details["member_ordinal"], "0", "{method:?}");
    }
}

#[test]
fn partially_overlapping_physical_members_are_rejected() {
    let mut bytes = fs::read(fixture("duplicate-content.apk")).unwrap();
    let end = bytes.len() - 22;
    let central = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
    let second_central = central + 46 + "classes.dex".len();
    let second_local = u32::from_le_bytes(
        bytes[second_central + 42..second_central + 46]
            .try_into()
            .unwrap(),
    ) as usize;
    let second_size = u32::from_le_bytes(
        bytes[second_central + 20..second_central + 24]
            .try_into()
            .unwrap(),
    ) as usize;
    let local_record =
        bytes[second_local..second_local + 30 + "classes2.dex".len() + second_size].to_vec();
    let embedded = 30 + "classes.dex".len() + 16;
    bytes[embedded..embedded + local_record.len()].copy_from_slice(&local_record);
    bytes[second_central + 42..second_central + 46]
        .copy_from_slice(&(embedded as u32).to_le_bytes());
    let snapshot = capture(temporary(&bytes), InputKind::Apk);
    let error =
        ArchiveInventory::build(&snapshot.sources()[0], generic(), ArchiveLimits::default())
            .err()
            .unwrap();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.message, "physical member ranges partially overlap");
}
