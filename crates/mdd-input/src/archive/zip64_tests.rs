use super::*;
use crate::snapshot::{CaptureLimits, InputSpec, Snapshot};
use serde_json::{Value, json};
use std::path::PathBuf;

fn source(name: &str) -> Snapshot {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/zip64/generated")
        .join(format!("{name}.zip"));
    Snapshot::capture(
        &[InputSpec {
            path,
            kind: InputKind::Apk,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap()
}
fn policy(empty: bool) -> InventoryPolicy {
    InventoryPolicy {
        dex_selection: if empty {
            DexSelection::ResourcesOnly
        } else {
            DexSelection::AllDexMembers
        },
        reject_duplicate_selected_names: false,
        require_dex: !empty,
        hold_dex_bytes: true,
    }
}

#[test]
fn real_zip64_and_python_force_local_members_are_fully_consumed() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/zip64/manifest.json"
    ))
    .unwrap();
    let dex = include_bytes!("../../../../tests/fixtures/generated/minimal-035.dex");
    let other = include_bytes!("../../../../tests/fixtures/generated/structured-035.dex");
    let mut tested = 0;
    for row in manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["expected"] == "ok")
    {
        let name = row["id"].as_str().unwrap();
        let snapshot = source(name);
        let captured = &snapshot.sources()[0];
        let inventory =
            ArchiveInventory::build(captured, policy(name == "empty"), ArchiveLimits::default())
                .unwrap();
        let large = row["large_metadata"].as_bool().unwrap_or(false);
        let count = if large {
            row["expected_count"].as_u64().unwrap() as usize
        } else if row["layout"].is_null() {
            1
        } else {
            row["layout"]["members"].as_array().unwrap().len()
        };
        assert_eq!(inventory.manifest().members.len(), count, "{name}");
        for (ordinal, member) in inventory.manifest().members.iter().enumerate() {
            assert_eq!(
                member.archive_member_ordinal,
                Some(DecimalU64(ordinal as u64))
            );
            if large {
                assert_eq!(
                    member.raw_name,
                    if ordinal == 0 {
                        b"classes.dex".as_slice()
                    } else {
                        b"r".as_slice()
                    }
                );
                if ordinal > 0 && ordinal + 1 != count {
                    continue;
                }
            }
            if !row["layout"].is_null() {
                assert_eq!(
                    member.name_utf8.as_ref().unwrap(),
                    row["layout"]["members"][ordinal]["name"].as_str().unwrap()
                );
            }
            let blob = inventory.read_member(&member.member_id).unwrap();
            let expected: &[u8] = if name == "duplicate-name" && ordinal == 1 {
                other
            } else if member.raw_name.ends_with(b".dex") {
                dex
            } else if large {
                b""
            } else {
                b"\0\xffresource"
            };
            assert_eq!(&*blob.lease(), expected, "{name}/{ordinal}");
            assert_eq!(blob.content_id, content_id(expected));
        }
        if name == "duplicate-name" || name == "duplicate-content" {
            assert_eq!(inventory.selected_dexes().len(), 2);
            assert_ne!(
                inventory.selected_dexes()[0].dex_occurrence_id,
                inventory.selected_dexes()[1].dex_occurrence_id
            );
        }
        assert!(
            inventory.manifest().directory_complete
                && inventory.manifest().selected_dex_bytes_complete
        );
        println!(
            "MDD_ZIP64_POSITIVE {}",
            json!({"id":name,"members":count,"selected_dexes":inventory.selected_dexes().len(),"source_content_id":captured.identity().content_id})
        );
        tested += 1;
    }
    assert_eq!(tested, 26);
}

#[test]
fn malformed_or_huge_zip64_is_not_unsupported_or_empty_success() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/zip64/manifest.json"
    ))
    .unwrap();
    let mut tested = 0;
    for row in manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["expected"] != "ok")
    {
        let name = row["id"].as_str().unwrap();
        let snapshot = source(name);
        let limits = if name == "declared-total-overflow" {
            ArchiveLimits {
                max_member_bytes: u64::MAX,
                max_total_uncompressed_bytes: u64::MAX,
                ..ArchiveLimits::default()
            }
        } else {
            ArchiveLimits::default()
        };
        let error = ArchiveInventory::build(&snapshot.sources()[0], policy(false), limits)
            .err()
            .unwrap();
        let expected = match row["expected"].as_str().unwrap() {
            "INVALID_INPUT" => ErrorCode::InvalidInput,
            "QUOTA_EXCEEDED" => ErrorCode::QuotaExceeded,
            "UNSUPPORTED_CAPABILITY" => ErrorCode::UnsupportedCapability,
            _ => panic!("unknown fixture error"),
        };
        println!("MDD_ZIP64_NEGATIVE {}", json!({"id":name,"error":error}));
        assert_eq!(error.code, expected, "{name}: {error:?}");
        assert!(error.details.contains_key("source_occurrence_id"));
        tested += 1;
    }
    assert_eq!(tested, 26);
}

#[test]
fn zip64_tail_uses_u64_without_allocating_a_fake_large_archive() {
    let position = u64::from(u32::MAX) + 123;
    let tail = zip64::tail(position, 97, false).unwrap();
    assert_eq!(tail.len(), 98);
    assert_eq!(&tail[..4], b"PK\x06\x06");
    assert_eq!(zip64::u64_at(&tail, 48).unwrap(), position);
    assert_eq!(zip64::u64_at(&tail, 64).unwrap(), position + 97);
    assert_eq!(central::u32_at(&tail, 92).unwrap(), u32::MAX);
    assert!(zip64::tail(u64::MAX, 1, true).is_err());
    assert!(zip64::tail(u64::MAX - 1, 1, true).is_err());
    let crc = 0x08074b50u32;
    let mut descriptor = crc.to_le_bytes().to_vec();
    descriptor.extend_from_slice(&7u32.to_le_bytes());
    descriptor.extend_from_slice(&11u32.to_le_bytes());
    assert_eq!(
        central::descriptor_end(&descriptor, 0, descriptor.len(), crc, 7, 11, false).unwrap(),
        12
    );
}

#[test]
fn spilled_zip64_positive_and_negative_vectors_match_in_memory() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/zip64/manifest.json"
    ))
    .unwrap();
    let dex = include_bytes!("../../../../tests/fixtures/generated/minimal-035.dex");
    let other = include_bytes!("../../../../tests/fixtures/generated/structured-035.dex");
    let mut tested = 0;
    for row in manifest["files"].as_array().unwrap() {
        let name = row["id"].as_str().unwrap();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/zip64/generated")
            .join(format!("{name}.zip"));
        let snapshot = Snapshot::capture_with_spill_threshold(
            &[InputSpec {
                path,
                kind: InputKind::Apk,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
            Some(64),
        )
        .unwrap();
        let captured = &snapshot.sources()[0];
        assert!(captured.try_bytes().is_none(), "{name}");
        let expected_outcome = row["expected"].as_str().unwrap();
        if expected_outcome == "ok" {
            let inv = ArchiveInventory::build(
                captured,
                policy(name == "empty"),
                ArchiveLimits::default(),
            )
            .unwrap();
            let large = row["large_metadata"].as_bool().unwrap_or(false);
            let count = if large {
                row["expected_count"].as_u64().unwrap() as usize
            } else if row["layout"].is_null() {
                1
            } else {
                row["layout"]["members"].as_array().unwrap().len()
            };
            assert_eq!(inv.manifest().members.len(), count, "{name}");
            for (ordinal, member) in inv.manifest().members.iter().enumerate() {
                if large && ordinal > 0 && ordinal + 1 != count {
                    continue;
                }
                let blob = inv.read_member(&member.member_id).unwrap();
                let expected: &[u8] = if name == "duplicate-name" && ordinal == 1 {
                    other
                } else if member.raw_name.ends_with(b".dex") {
                    dex
                } else if large {
                    b""
                } else {
                    b"\0\xffresource"
                };
                assert_eq!(&*blob.lease(), expected, "{name}/{ordinal}");
            }
        } else {
            let limits = if name == "declared-total-overflow" {
                ArchiveLimits {
                    max_member_bytes: u64::MAX,
                    max_total_uncompressed_bytes: u64::MAX,
                    ..ArchiveLimits::default()
                }
            } else {
                ArchiveLimits::default()
            };
            let error = ArchiveInventory::build(captured, policy(false), limits)
                .err()
                .unwrap();
            let expected = match expected_outcome {
                "INVALID_INPUT" => ErrorCode::InvalidInput,
                "QUOTA_EXCEEDED" => ErrorCode::QuotaExceeded,
                "UNSUPPORTED_CAPABILITY" => ErrorCode::UnsupportedCapability,
                _ => panic!("unknown fixture error"),
            };
            assert_eq!(error.code, expected, "{name}: {error:?}");
            assert!(error.details.contains_key("source_occurrence_id"));
        }
        assert!(captured.try_bytes().is_none(), "{name}");
        tested += 1;
    }
    assert_eq!(tested, 52);
}
