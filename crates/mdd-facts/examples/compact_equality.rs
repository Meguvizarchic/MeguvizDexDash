//! Does decoding one code item again give the item that was decoded with the whole section? Development check on a
//! real archive: `compact_equality INPUT [FIRST [COUNT]]`.
//!
//! For each selected DEX it builds the code facts in full, compacts them, and for every code item compares the item
//! of the full facts with the item the compact facts decode again, as serialized JSON bytes (so every field counts,
//! instructions and debug events included). It also checks that the retained opcode bytes are the opcodes of the
//! decoded instructions. Prints one JSON line per DEX and a total; exits 1 on the first difference.
use mdd_dex::instructions::CodeLimits;
use mdd_facts::code::CodeFacts;
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use serde_json::json;
use std::{path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let path = PathBuf::from(
        arguments
            .next()
            .expect("usage: compact_equality INPUT [FIRST [COUNT]]"),
    );
    let first: usize = arguments
        .next()
        .map(|a| a.to_string_lossy().parse().unwrap())
        .unwrap_or(0);
    let count: usize = arguments
        .next()
        .map(|a| a.to_string_lossy().parse().unwrap())
        .unwrap_or(usize::MAX);
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
        InventoryPolicy {
            require_dex: false,
            ..InventoryPolicy::default()
        },
        ArchiveLimits::default(),
    )
    .unwrap();
    let total = inventory.selected_dexes().len();
    let (mut all_items, mut all_instructions, mut all_events) = (0u64, 0u64, 0u64);
    for local in first..total.min(first.saturating_add(count)) {
        let full =
            CodeFacts::build_all_code_items(&snapshot, &inventory, local, CodeLimits::default())
                .unwrap();
        let compact = full.compacted().unwrap();
        let mut reader = compact.reader();
        let (mut instructions, mut events) = (0u64, 0u64);
        for (ordinal, whole) in full.items().iter().enumerate() {
            let again = reader.get(ordinal).unwrap();
            let left = serde_json::to_vec(whole.data()).unwrap();
            let right = serde_json::to_vec(again.as_ref()).unwrap();
            if left != right {
                println!(
                    "{}",
                    json!({"dex": local, "ordinal": ordinal, "result": "DIFFERENT",
                           "bytes_full": left.len(), "bytes_decoded_again": right.len()})
                );
                return ExitCode::FAILURE;
            }
            let opcodes: Vec<u8> = whole.data().instructions.iter().map(|i| i.opcode).collect();
            if compact.items()[ordinal].opcodes() != opcodes.as_slice() {
                println!(
                    "{}",
                    json!({"dex": local, "ordinal": ordinal, "result": "OPCODES_DIFFER"})
                );
                return ExitCode::FAILURE;
            }
            instructions += whole.data().instructions.len() as u64;
            events += whole
                .data()
                .debug_info
                .as_ref()
                .map_or(0, |d| d.events.iter().count() as u64);
        }
        println!(
            "{}",
            json!({"dex": local, "items": full.items().len(), "instructions": instructions,
                   "debug_events": events, "result": "equal"})
        );
        all_items += full.items().len() as u64;
        all_instructions += instructions;
        all_events += events;
    }
    println!(
        "{}",
        json!({"total": {"items": all_items, "instructions": all_instructions,
                         "debug_events": all_events}, "result": "equal"})
    );
    ExitCode::SUCCESS
}
