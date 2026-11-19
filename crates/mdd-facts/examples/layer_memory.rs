//! Memory of each fact layer, measured by a counting allocator. Development probe, not a product tool.
//!
//! `layer_memory INPUT [FIRST [COUNT]]` builds, for each selected DEX in `FIRST..FIRST+COUNT`, the same layers in the same
//! order as `Dataset::open` (contract dialect) - metadata, definitions, code, annotations, references - keeps every one of
//! them alive like the session does, and prints after each layer the bytes that are live and the peak so far. "live" counts
//! only what the allocator handed out and has not got back; it is the heap the layers hold, not the working set of the
//! process.
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_facts::{
    MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    references::{ReferenceFacts, ReferenceLimits},
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use serde_json::json;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::Relaxed},
    },
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let now = LIVE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

// SAFETY: every call is forwarded unchanged to the system allocator; the counters only observe sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grow(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn mib(bytes: usize) -> f64 {
    (bytes as f64 / 1048576.0 * 10.0).round() / 10.0
}

thread_local! {
    static STAMP: std::cell::Cell<Option<std::time::Instant>> = const { std::cell::Cell::new(None) };
}

fn report(dex: usize, layer: &str, before: usize) {
    let live = LIVE.load(Relaxed);
    let now = std::time::Instant::now();
    // Milliseconds since the previous report: the time of the layer that has just been built.
    let since = STAMP.with(|stamp| {
        stamp
            .replace(Some(now))
            .map_or(0, |last| now.duration_since(last).as_millis() as u64)
    });
    println!(
        "{}",
        json!({"dex": dex, "layer": layer, "added_mib": mib(live.saturating_sub(before)), "live_mib": mib(live),
               "peak_mib": mib(PEAK.load(Relaxed)), "ms": since})
    );
}

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let path = PathBuf::from(
        arguments
            .next()
            .expect("usage: layer_memory INPUT [FIRST [COUNT]]"),
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
    report(usize::MAX, "snapshot+inventory", 0);
    let total = inventory.selected_dexes().len();
    let mut kept = Vec::new();
    for local in first..total.min(first.saturating_add(count)) {
        let mut before = LIVE.load(Relaxed);
        let metadata = Arc::new(
            MetadataFacts::build(&snapshot, &inventory, local, StringLimits::default()).unwrap(),
        );
        report(local, "metadata", before);
        before = LIVE.load(Relaxed);
        let definitions = Arc::new(
            DefinitionFacts::build_arc(Arc::clone(&metadata), DefinitionLimits::default()).unwrap(),
        );
        report(local, "definitions", before);
        before = LIVE.load(Relaxed);
        let code = Arc::new(
            CodeFacts::build_all_code_items(&snapshot, &inventory, local, CodeLimits::default())
                .unwrap(),
        );
        report(local, "code", before);
        {
            // What the decoded instructions alone weigh, counted from their types: the instruction records, the heap their
            // reference operands and spilled registers own, and the per-item vectors.
            let (mut instructions, mut operand_heap, mut items_with_code) =
                (0usize, 0usize, 0usize);
            for item in code.items() {
                let data = item.data();
                instructions += data.instructions.len();
                items_with_code += 1;
                operand_heap += data
                    .instructions
                    .iter()
                    .map(|i| i.references.capacity())
                    .sum::<usize>()
                    * std::mem::size_of::<mdd_dex::instructions::ReferenceOperand>();
            }
            let mut seen = std::collections::HashSet::new();
            let (
                mut payloads,
                mut switch_units,
                mut switches,
                mut tries,
                mut handlers,
                mut events,
                mut programs,
                mut text,
            ) = (
                0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize,
            );
            for item in code.items() {
                let data = item.data();
                payloads += data.payloads.len();
                switches += data.switch_targets.len();
                switch_units += data
                    .switch_targets
                    .iter()
                    .map(|s| s.target_code_units.capacity())
                    .sum::<usize>();
                tries += data.tries.len();
                handlers += data.handlers.len();
                text += data.validation_scope.capacity() + item.code_item_id().len();
                if let Some(debug) = data
                    .debug_info
                    .as_ref()
                    .filter(|debug| seen.insert(std::sync::Arc::as_ptr(debug)))
                {
                    programs += 1;
                    events += debug.events.iter().count();
                    text += debug.validation_scope.capacity();
                }
            }
            println!(
                "{}",
                json!({"dex": local, "layer": "code-rest", "payloads": payloads, "size_of_payload": std::mem::size_of::<mdd_dex::instructions::Payload>(),
                       "switches": switches, "switch_target_units_mib": mib(switch_units * 4),
                       "size_of_switch": std::mem::size_of::<mdd_dex::instructions::SwitchTargets>(), "tries": tries, "handlers": handlers,
                       "debug_programs": programs, "debug_events": events, "size_of_event": std::mem::size_of::<mdd_dex::instructions::DebugEvent>(),
                       "debug_events_mib": mib(events * std::mem::size_of::<mdd_dex::instructions::DebugEvent>()), "item_text_mib": mib(text)})
            );
            println!(
                "{}",
                json!({"dex": local, "layer": "code-detail", "code_items": items_with_code, "instructions": instructions,
                       "size_of_instruction": std::mem::size_of::<mdd_dex::instructions::Instruction>(),
                       "instruction_records_mib": mib(instructions * std::mem::size_of::<mdd_dex::instructions::Instruction>()),
                       "operand_heap_mib": mib(operand_heap),
                       "size_of_code_item": std::mem::size_of::<mdd_dex::instructions::CodeItem>()})
            );
        }
        before = LIVE.load(Relaxed);
        let annotations = Arc::new(
            AnnotationFacts::build_arc(Arc::clone(&definitions), AnnotationLimits::default())
                .unwrap(),
        );
        report(local, "annotations", before);
        before = LIVE.load(Relaxed);
        let references = Arc::new(
            ReferenceFacts::build_arc(
                Arc::clone(&definitions),
                Arc::clone(&code),
                ReferenceLimits::default(),
            )
            .unwrap(),
        );
        report(local, "references", before);
        kept.push((metadata, definitions, code, annotations, references));
    }
    report(usize::MAX, "all kept", 0);
    drop(kept);
}
