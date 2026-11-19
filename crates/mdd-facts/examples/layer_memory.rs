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
/// Live bytes and live allocation count by size class (power of two), to show whether memory sits in a few large
/// tables or in very many small objects.
const BUCKETS: usize = 40;
static BUCKET_BYTES: [AtomicUsize; BUCKETS] = [const { AtomicUsize::new(0) }; BUCKETS];
static BUCKET_COUNT: [AtomicUsize; BUCKETS] = [const { AtomicUsize::new(0) }; BUCKETS];

fn bucket(size: usize) -> usize {
    (usize::BITS - size.max(1).leading_zeros()) as usize
}

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
            BUCKET_BYTES[bucket(layout.size())].fetch_add(layout.size(), Relaxed);
            BUCKET_COUNT[bucket(layout.size())].fetch_add(1, Relaxed);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
        BUCKET_BYTES[bucket(layout.size())].fetch_sub(layout.size(), Relaxed);
        BUCKET_COUNT[bucket(layout.size())].fetch_sub(1, Relaxed);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
            BUCKET_BYTES[bucket(layout.size())].fetch_sub(layout.size(), Relaxed);
            BUCKET_COUNT[bucket(layout.size())].fetch_sub(1, Relaxed);
            BUCKET_BYTES[bucket(new_size)].fetch_add(new_size, Relaxed);
            BUCKET_COUNT[bucket(new_size)].fetch_add(1, Relaxed);
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
            hold_dex_bytes: false,
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
        // The same steps, in the same order, as `Dataset::open` (contract dialect): the code layer is built compact, one
        // code item at a time, and the references decode the callers' instructions again from the DEX bytes.
        before = LIVE.load(Relaxed);
        let compact = Arc::new(
            CodeFacts::build_all_code_items_compact(
                &snapshot,
                &inventory,
                local,
                CodeLimits::default(),
            )
            .unwrap(),
        );
        report(local, "code (compact, streamed)", before);
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
                Arc::clone(&compact),
                ReferenceLimits::default(),
            )
            .unwrap(),
        );
        report(local, "references", before);
        // the DEX bytes were read for this DEX only: the inventory lets its copy go, the layers keep theirs
        inventory.selected_dexes()[local].blob.release();
        report(local, "inventory copy released", LIVE.load(Relaxed));
        kept.push((metadata, definitions, compact, annotations, references));
    }
    report(usize::MAX, "all kept", 0);
    if std::env::var_os("LAYER_MEMORY_HISTOGRAM").is_some() {
        let rows: Vec<_> = (0..BUCKETS)
            .filter(|b| BUCKET_COUNT[*b].load(Relaxed) > 0)
            .map(|b| {
                json!({"size_class_bytes": format!("{}..{}", if b == 0 { 0 } else { 1usize << (b - 1) }, 1usize << b),
                       "live_mib": mib(BUCKET_BYTES[b].load(Relaxed)), "live_count": BUCKET_COUNT[b].load(Relaxed)})
            })
            .collect();
        println!("{}", json!({"histogram": rows}));
    }
    drop(kept);
}
