//! Verifies DEX `041` container validation, shared-string preservation, and `mdd-cache` invalidation
//! when forward-shared container bytes change by 1 byte.

use mdd_cache::dependency_tracking::SharedContainerDependency;
use mdd_cache::key::{FactCacheKeySpec, MemberKey, SemanticsIdentity, SourceOccurrenceKey};
use mdd_input::optional_formats::validate_and_extract_dex041_container;
use mdd_types::{DecimalU64, ErrorCode};
use sha1::{Digest as Sha1Digest, Sha1};

fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in bytes.chunks(5552) {
        for v in chunk {
            a += u32::from(*v);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn encode_string_item(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let utf16_len = text.encode_utf16().count() as u32;
    let mut val = utf16_len;
    loop {
        let mut b = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            b |= 0x80;
        }
        out.push(b);
        if val == 0 {
            break;
        }
    }
    out.extend_from_slice(text.as_bytes());
    out.push(0);
    out
}

/// Build a synthetic valid multi-logical-DEX `041` container with shared tail strings and non-shared
/// identical-value strings.
fn build_two_logical_041_container(shared_str: &str) -> Vec<u8> {
    // Layout:
    // Logical DEX 0 at [0..144): 120B header + 24B private section (8B string_ids + private string "local" + padding to 4B)
    // Logical DEX 1 at [144..288): 120B header + 24B private section (8B string_ids + duplicate non-shared string "local" + padding)
    // Shared tail at [288..): shared_str encoded once, referenced by BOTH logical DEX string_ids[1] via ContainerOffset!
    let private_item = encode_string_item("dup_val"); // uleb(7)=1 + 7 + 1 = 9 bytes
    let shared_item = encode_string_item(shared_str);

    // 120 header + 8 (2 * 4 string_ids) + 9 (private_item) = 137 -> pad to 144 (4B aligned)
    let dex_span = 144usize;
    let tail_start = dex_span * 2;
    let total_size = tail_start + shared_item.len();

    let mut buf = vec![0u8; total_size];
    buf[tail_start..].copy_from_slice(&shared_item);

    for ord in 0..2usize {
        let base = ord * dex_span;
        let string_ids_off = (base + 120) as u32;
        let private_str_off = (base + 128) as u32;
        let shared_str_off = tail_start as u32;

        buf[base + 128..base + 128 + private_item.len()].copy_from_slice(&private_item);
        buf[base + 120..base + 124].copy_from_slice(&private_str_off.to_le_bytes());
        buf[base + 124..base + 128].copy_from_slice(&shared_str_off.to_le_bytes());

        buf[base..base + 8].copy_from_slice(b"dex\n041\0");
        buf[base + 32..base + 36].copy_from_slice(&(dex_span as u32).to_le_bytes());
        buf[base + 36..base + 40].copy_from_slice(&120u32.to_le_bytes());
        buf[base + 40..base + 44].copy_from_slice(&0x12345678u32.to_le_bytes());
        buf[base + 56..base + 60].copy_from_slice(&2u32.to_le_bytes());
        buf[base + 60..base + 64].copy_from_slice(&string_ids_off.to_le_bytes());
        buf[base + 112..base + 116].copy_from_slice(&(total_size as u32).to_le_bytes());
        buf[base + 116..base + 120].copy_from_slice(&(base as u32).to_le_bytes());

        let sig = Sha1::digest(&buf[base + 32..base + dex_span]);
        buf[base + 12..base + 32].copy_from_slice(&sig);
        let csum = adler32(&buf[base + 12..base + dex_span]);
        buf[base + 8..base + 12].copy_from_slice(&csum.to_le_bytes());
    }
    buf
}

#[test]
fn dex041_container_preserves_occurrences_and_invalidates_shared_cache() {
    let c1 = build_two_logical_041_container("Lshared/A;");
    let c2 = build_two_logical_041_container("Lshared/B;");
    assert_eq!(c1.len(), c2.len());

    // Standard DEX 035-040 reader must still reject 041!
    assert_eq!(
        mdd_dex::validate_header(&c1).err().unwrap().code,
        ErrorCode::UnsupportedCapability
    );

    let r1 = validate_and_extract_dex041_container(&c1).unwrap();
    let r2 = validate_and_extract_dex041_container(&c2).unwrap();
    assert_eq!(r1.logical_dex_count, 2);
    // Each logical DEX keeps both its local string ("dup_val") and shared string ("Lshared/A;"), 4 rows total (not merged).
    assert_eq!(r1.total_logical_string_occurrences, 4);
    assert_eq!(r1.physical_shared_string_offsets, 1);
    assert_eq!(r1.logical_dexes[0].strings[1].value, "Lshared/A;");
    assert_eq!(r1.logical_dexes[1].strings[1].value, "Lshared/A;");
    assert!(r1.logical_dexes[0].strings[1].shared_across_dexes);
    assert!(!r1.logical_dexes[0].strings[0].shared_across_dexes);

    // Cache dependency check: 1-byte change in shared tail invalidates container dependency & cache key.
    let dep = SharedContainerDependency {
        container_format: r1.container_format.clone(),
        physical_container_content_id: format!("sha256:{}", r1.physical_container_sha256),
        physical_container_bytes: r1.physical_container_bytes,
        logical_dex_ordinal: 0,
        logical_header_offset: DecimalU64(r1.logical_dexes[0].header_offset.0),
        shared_ranges_sha256: r1.shared_ranges_sha256.clone(),
    };
    assert!(
        dep.verify_against_container(
            &format!("sha256:{}", r2.physical_container_sha256),
            &r2.shared_ranges_sha256
        )
        .err()
        .unwrap()
        .code
            == ErrorCode::StaleCache
    );

    let spec1 = FactCacheKeySpec {
        semantics: SemanticsIdentity::default(),
        occurrences: vec![SourceOccurrenceKey {
            input_ordinal: 0,
            content_id: format!("sha256:{}", r1.physical_container_sha256),
            byte_length: r1.physical_container_bytes.0,
            input_kind: "dex-041-container".to_owned(),
            selected_members: vec![MemberKey {
                member_ordinal: 0,
                raw_name_hex: "636c6173736573".to_owned(),
                content_id: format!("sha256:{}", r1.physical_container_sha256),
                byte_length: r1.physical_container_bytes.0,
                logical_header_offset: 0,
                container_dependency_sha256: Some(r1.shared_ranges_sha256.clone()),
            }],
        }],
    };
    let spec2 = FactCacheKeySpec {
        semantics: SemanticsIdentity::default(),
        occurrences: vec![SourceOccurrenceKey {
            input_ordinal: 0,
            content_id: format!("sha256:{}", r2.physical_container_sha256),
            byte_length: r2.physical_container_bytes.0,
            input_kind: "dex-041-container".to_owned(),
            selected_members: vec![MemberKey {
                member_ordinal: 0,
                raw_name_hex: "636c6173736573".to_owned(),
                content_id: format!("sha256:{}", r2.physical_container_sha256),
                byte_length: r2.physical_container_bytes.0,
                logical_header_offset: 0,
                container_dependency_sha256: Some(r2.shared_ranges_sha256.clone()),
            }],
        }],
    };
    assert_ne!(
        spec1.canonical_cache_key().unwrap(),
        spec2.canonical_cache_key().unwrap()
    );
}
