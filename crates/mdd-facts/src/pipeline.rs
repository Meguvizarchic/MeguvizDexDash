//! DEX-parallel fact construction over one immutable snapshot.
//!
//! The staged builders remain the only fact constructors. This module decides
//! which occurrence a worker builds, in which order occurrences are scheduled,
//! and when a finished occurrence is delivered; it never decides what a builder
//! computes. Every occurrence runs the same chain as the serial facade:
//!
//! ```text
//! metadata -> definitions -> { code, annotations, references }
//! ```
//!
//! Safety and determinism argument:
//!
//! * Inputs are shared immutably. `Snapshot` and `ArchiveInventory` only hold
//!   captured bytes and validated plain vectors, and every staged builder takes
//!   them by reference; no worker mutates either.
//! * Each occurrence is claimed exactly once from an atomic cursor, so the same
//!   DEX index is never built twice and no builder sees another worker's state.
//! * Occurrences are claimed only from the window `[cursor, cursor + window)` and
//!   delivered strictly in inventory order. A different completion order can
//!   only change when a slot is filled, never which DEX is delivered when, so
//!   the caller observes exactly the serial order and the serial abort position:
//!   the first failing index, with no occurrence past it delivered.
//! * Because claims are restricted to that window, at most `window` occurrences
//!   hold a full fact set at once and the next index to deliver can never be
//!   starved by heavy occurrences later in the input.
//!
//! Default thread count caveat: `available_parallelism()` reports the machine's
//! logical processors, so a process confined to a CPU lease (for example a
//! Windows processor-affinity mask) must pass `PipelineConfig::threads`
//! explicitly. Oversubscribing a small lease multiplies allocation pressure and
//! is measurably slower than the serial chain.
//! * Each `Arc` in a result is created once per occurrence and shared, exactly
//!   as the serial chain shares it: `DefinitionFacts` owns the same
//!   `Arc<MetadataFacts>` it was built from, and `ReferenceFacts` shares the
//!   pipeline's `Arc<DefinitionFacts>` and `Arc<CodeFacts>` through `build_arc`
//!   instead of cloning a second copy. No fact object is rebuilt or copied to
//!   satisfy parallelism.
//! * Per-layer limits are occurrence-scoped: `StringLimits`,
//!   `DefinitionLimits`, `CodeLimits`, `ReferenceLimits` and `AnnotationLimits`
//!   are applied inside one builder call and are never read from a shared
//!   accumulator. The same configured limits are passed verbatim to every
//!   occurrence, so a thread pool cannot bypass or multiply a `max_*` check.
//!   Capture and archive limits are consumed once while opening the pipeline and
//!   are not revisited by workers.
//! * Every layer is internally ordered (`Vec` in encoded order, `BTreeMap` for
//!   lookups), so thread choice cannot perturb a serialized fact.

use crate::{
    FactsLimits, MetadataFacts, annotations::AnnotationFacts, code::CodeFacts,
    definitions::DefinitionFacts, references::ReferenceFacts,
};
use mdd_input::{
    archive::{ArchiveInventory, InventoryPolicy},
    snapshot::{InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

/// Worker-pool configuration for one build.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipelineConfig {
    /// `None` uses `available_parallelism()` capped by the DEX count. `Some(0)`
    /// is rejected; `Some(n)` is capped by the DEX count. `Some(1)` builds in
    /// inventory order on the calling thread without spawning.
    pub threads: Option<usize>,
    /// How many occurrences may be built ahead of the delivery cursor. `None`
    /// uses `2 * threads`, the usual load-balancing sweet spot; `Some(n)` keeps
    /// `max(n, threads)` occurrences in flight. Every in-flight occurrence holds
    /// a full fact set, so this is the primary memory knob.
    pub max_in_flight: Option<usize>,
}

impl PipelineConfig {
    /// Resolve the effective worker count for `dex_count`.
    ///
    /// The result is never larger than the number of selected occurrences, so a
    /// single-DEX input never starts a pool with idle workers.
    pub fn resolve_threads(self, dex_count: usize) -> MddResult<usize> {
        if dex_count == 0 {
            return Ok(0);
        }
        match self.threads {
            Some(0) => Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.pipeline",
                "thread count must be positive",
            )
            .detail("threads", "0")),
            Some(requested) => Ok(requested.min(dex_count)),
            None => {
                // Respect the CPU lease: the portable API overcounts under a
                // Windows job/affinity restriction and can spawn a pool that is
                // both slower and memory-hungrier than running serially.
                let available = crate::threads::default_threads();
                Ok(available.min(dex_count))
            }
        }
    }

    /// Resolve the delivery window for an effective `threads` count.
    pub fn resolve_in_flight(self, threads: usize, dex_count: usize) -> MddResult<usize> {
        if dex_count == 0 {
            return Ok(0);
        }
        let threads = threads.max(1);
        let requested = match self.max_in_flight {
            Some(0) => {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.pipeline",
                    "in-flight occurrence window must be positive",
                )
                .detail("max_in_flight", "0"));
            }
            Some(value) => value,
            None => threads.saturating_mul(2),
        };
        Ok(requested.max(threads).min(dex_count))
    }
}

/// Every fact layer of one DEX occurrence.
///
/// The `Arc` sharing graph is the serial graph: `metadata` is the lease held by
/// `definitions`, `definitions` and `code` are the leases held by `references`,
/// and `annotations` owns the definition clone its constructor requires.
pub struct DexFacts {
    pub index: usize,
    pub occurrence: String,
    pub metadata: Arc<MetadataFacts>,
    pub definitions: Arc<DefinitionFacts>,
    pub code: Arc<CodeFacts>,
    pub annotations: Arc<AnnotationFacts>,
    pub references: Arc<ReferenceFacts>,
}

/// Wall-clock attribution for one occurrence. Timing never feeds a fact.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DexStageTimings {
    pub metadata: Duration,
    pub definitions: Duration,
    pub code: Duration,
    pub annotations: Duration,
    pub references: Duration,
    /// Whole occurrence chain, including the annotation definition clone.
    pub build: Duration,
}

/// Summary of one streaming batch. Fact values are delivered, not retained here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipelineSummary {
    /// Effective worker count (`1` means the calling thread).
    pub threads: usize,
    /// Number of delivered DEX occurrences, in inventory order.
    pub dexes: usize,
    /// Wall clock of the fact batch only; capture and inventory are outside it.
    pub wall: Duration,
}

/// Deterministic retained batch, used by equivalence checks and small inputs.
///
/// Retains every occurrence's full fact set, so memory grows with the whole
/// input. Production consumers that process one occurrence at a time should use
/// [`FactsPipeline::for_each`].
pub struct PipelineReport {
    pub threads: usize,
    pub wall: Duration,
    /// One entry per selected DEX occurrence, in inventory order.
    pub dexes: Vec<DexFacts>,
    /// One entry per selected DEX occurrence, parallel to `dexes`.
    pub timings: Vec<DexStageTimings>,
}

/// A captured input plus the limits used to build every occurrence.
pub struct FactsPipeline {
    snapshot: Snapshot,
    inventory: ArchiveInventory,
    limits: FactsLimits,
}

impl FactsPipeline {
    /// Capture `path` and build its inventory with default limits.
    pub fn open(path: impl AsRef<Path>) -> MddResult<Self> {
        Self::open_with(path, FactsLimits::default())
    }

    /// Capture `path` and build its inventory with explicit limits.
    pub fn open_with(path: impl AsRef<Path>, limits: FactsLimits) -> MddResult<Self> {
        let path = path.as_ref();
        let kind = InputKind::detect(path)?;
        Self::open_spec(
            InputSpec {
                path: path.to_path_buf(),
                kind,
                expected_sha256: None,
            },
            limits,
        )
    }

    /// Capture an explicit input specification, including an expected digest.
    pub fn open_spec(spec: InputSpec, limits: FactsLimits) -> MddResult<Self> {
        let snapshot = Snapshot::capture(std::slice::from_ref(&spec), limits.capture)?;
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            limits.archive,
        )?;
        Self::from_snapshot(snapshot, inventory, limits)
    }

    /// Build from an existing snapshot and inventory without recapturing.
    ///
    /// The pair is checked before any worker starts, so an inventory from a
    /// different capture can never be bound to this snapshot's occurrences.
    pub fn from_snapshot(
        snapshot: Snapshot,
        inventory: ArchiveInventory,
        limits: FactsLimits,
    ) -> MddResult<Self> {
        let source = inventory.manifest();
        let bound = snapshot.manifest().sources.iter().any(|candidate| {
            candidate.occurrence_id == source.source_occurrence_id
                && candidate.content_id == source.source_content_id
        });
        if !bound {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.pipeline",
                "inventory does not belong to snapshot",
            )
            .detail("source_occurrence_id", source.source_occurrence_id.clone()));
        }
        if inventory.selected_dexes().is_empty() {
            return Err(MddError::new(
                ErrorCode::PartialInput,
                "facts.pipeline",
                "selected DEX occurrences are empty",
            )
            .detail("input_coverage", "partial"));
        }
        Ok(Self {
            snapshot,
            inventory,
            limits,
        })
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn inventory(&self) -> &ArchiveInventory {
        &self.inventory
    }
    pub fn limits(&self) -> &FactsLimits {
        &self.limits
    }
    pub fn dex_count(&self) -> usize {
        self.inventory.selected_dexes().len()
    }

    /// Logical occurrence identity for `index`, matching `selected_dexes()`.
    pub fn occurrence(&self, index: usize) -> MddResult<&str> {
        self.inventory
            .selected_dexes()
            .get(index)
            .map(|dex| dex.dex_occurrence_id.as_str())
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.pipeline",
                    "DEX occurrence index outside inventory",
                )
                .detail("dex_index", index.to_string())
            })
    }

    /// Build every selected occurrence once and deliver each one in inventory
    /// order through `visit`.
    ///
    /// Scheduling is a sliding window with persistent workers, not a barrier per
    /// chunk: a worker claims the next occurrence as soon as the window has room,
    /// so one slow DEX never idles the pool. Delivery is still strictly by
    /// inventory index, and the window bounds how many full fact sets are alive
    /// at once; the visitor borrows each fact set only for its own call.
    ///
    /// Delivery stops at the first failing inventory index, exactly like the
    /// serial chain: no occurrence past that index is ever delivered, even if a
    /// worker already finished it.
    pub fn for_each<F>(&self, config: PipelineConfig, mut visit: F) -> MddResult<PipelineSummary>
    where
        F: FnMut(usize, &DexFacts, &DexStageTimings) -> MddResult<()>,
    {
        let count = self.dex_count();
        let threads = config.resolve_threads(count)?;
        let window = config.resolve_in_flight(threads, count)?;
        let started = Instant::now();
        let mut delivered = 0usize;
        if count == 0 {
            return Ok(PipelineSummary {
                threads,
                dexes: 0,
                wall: started.elapsed(),
            });
        }
        // Claim largest-first so heavy occurrences enter the window early; delivery
        // below walks inventory order regardless of claim order.
        let claim_order = self.claim_order(0, count);
        windowed_map(
            threads,
            window,
            count,
            &claim_order,
            |index| self.run_dex(index),
            |index, item| {
                let BuiltDex {
                    facts,
                    timing,
                    error,
                } = item;
                let Some(facts) = facts else {
                    return Err(error.unwrap_or_else(|| internal_missing(index)));
                };
                visit(index, &facts, &timing)?;
                delivered += 1;
                Ok(())
            },
        )?;
        Ok(PipelineSummary {
            threads,
            dexes: delivered,
            wall: started.elapsed(),
        })
    }

    /// Build every selected occurrence once and return all facts in inventory
    /// order. Intended for equivalence checks and small inputs; see
    /// [`FactsPipeline::for_each`] for the memory-bounded production shape.
    pub fn build(&self, config: PipelineConfig) -> MddResult<PipelineReport> {
        let count = self.dex_count();
        let threads = config.resolve_threads(count)?;
        let mut dexes = Vec::with_capacity(count);
        let mut timings = Vec::with_capacity(count);
        let summary = self.for_each(config, |_, facts, timing| {
            dexes.push(DexFacts {
                index: facts.index,
                occurrence: facts.occurrence.clone(),
                metadata: Arc::clone(&facts.metadata),
                definitions: Arc::clone(&facts.definitions),
                code: Arc::clone(&facts.code),
                annotations: Arc::clone(&facts.annotations),
                references: Arc::clone(&facts.references),
            });
            timings.push(*timing);
            Ok(())
        })?;
        debug_assert_eq!(dexes.len(), summary.dexes);
        Ok(PipelineReport {
            threads,
            wall: summary.wall,
            dexes,
            timings,
        })
    }

    /// Claim order for one window: largest occurrences first. Ties keep
    /// inventory order, so the schedule is reproducible.
    fn claim_order(&self, start: usize, end: usize) -> Vec<usize> {
        let mut order: Vec<usize> = (start..end).collect();
        order.sort_by_key(|index| {
            Reverse(self.inventory.selected_dexes()[*index].blob.bytes().len())
        });
        order
    }

    /// Build one occurrence, capturing a failure instead of aborting the window.
    ///
    /// Building the rest of the window after a failure cannot leak a fact to the
    /// caller: delivery stops at the first failing inventory index.
    fn run_dex(&self, index: usize) -> BuiltDex {
        let mut timing = DexStageTimings::default();
        let build_started = Instant::now();
        let result = self.build_chain(index, &mut timing);
        timing.build = build_started.elapsed();
        match result {
            Ok(facts) => BuiltDex {
                facts: Some(facts),
                timing,
                error: None,
            },
            Err(error) => BuiltDex {
                facts: None,
                timing,
                error: Some(error),
            },
        }
    }

    fn build_chain(&self, index: usize, timing: &mut DexStageTimings) -> MddResult<DexFacts> {
        let occurrence = self.occurrence(index)?.to_owned();

        let started = Instant::now();
        let metadata = Arc::new(MetadataFacts::build(
            &self.snapshot,
            &self.inventory,
            index,
            self.limits.strings,
        )?);
        timing.metadata = started.elapsed();

        let started = Instant::now();
        let definitions = Arc::new(DefinitionFacts::build_arc(
            Arc::clone(&metadata),
            self.limits.definitions,
        )?);
        timing.definitions = started.elapsed();

        let started = Instant::now();
        let code = Arc::new(CodeFacts::build_all_code_items(
            &self.snapshot,
            &self.inventory,
            index,
            self.limits.code,
        )?);
        timing.code = started.elapsed();

        // `AnnotationFacts::build` owns a `DefinitionFacts`, exactly like the
        // serial facade; the clone is per occurrence and never shared across
        // DEX indexes.
        let started = Instant::now();
        let annotations = Arc::new(AnnotationFacts::build(
            (*definitions).clone(),
            self.limits.annotations,
        )?);
        timing.annotations = started.elapsed();

        // `build_arc` shares the pipeline's leases instead of deep-copying the
        // definition and code facts, so the `Arc` graph matches the serial one.
        let started = Instant::now();
        let references = Arc::new(ReferenceFacts::build_arc(
            Arc::clone(&definitions),
            Arc::clone(&code),
            self.limits.references,
        )?);
        timing.references = started.elapsed();

        Ok(DexFacts {
            index,
            occurrence,
            metadata,
            definitions,
            code,
            annotations,
            references,
        })
    }
}

/// One occurrence's outcome, retained only until its window is delivered.
struct BuiltDex {
    facts: Option<DexFacts>,
    timing: DexStageTimings,
    error: Option<MddError>,
}

fn internal_missing(index: usize) -> MddError {
    MddError::new(
        ErrorCode::InternalFault,
        "facts.pipeline",
        "DEX worker did not publish a result",
    )
    .detail("dex_index", index.to_string())
}

/// Persistent worker pool with a bounded in-flight window and in-order delivery.
///
/// `task` must be a pure function of the index. Concurrency comes from the number
/// of workers; determinism comes from two independent guarantees:
///
/// * every index is claimed at most once (claims happen under one mutex),
/// * `deliver` runs on the calling thread in ascending index order, so completion
///   order can only change when a slot is filled, never which occurrence is
///   observed when.
///
/// Claims are restricted to the window `[cursor, cursor + window)`. That is both
/// the correctness rule and the memory bound: the next index to deliver is always
/// inside the window, so delivery can never be starved, and at most `window`
/// occurrences hold a full fact set at any time. `priority` is a preference order
/// (lower is claimed first) used *inside* the window, so heavy occurrences start
/// early without letting late occurrences crowd out the delivery cursor.
///
/// Workers block on a condition variable instead of polling and stop as soon as a
/// delivery fails, so a failure cannot strand a worker holding unused facts.
fn windowed_map<T, F, V>(
    threads: usize,
    window: usize,
    count: usize,
    priority: &[usize],
    task: F,
    mut deliver: V,
) -> MddResult<()>
where
    T: Send,
    F: Fn(usize) -> T + Send + Sync,
    V: FnMut(usize, T) -> MddResult<()>,
{
    debug_assert_eq!(priority.len(), count);
    if count == 0 {
        return Ok(());
    }
    if threads <= 1 || count == 1 {
        // Serial chain: build and deliver in inventory order, no worker spawn.
        for index in 0..count {
            deliver(index, task(index))?;
        }
        return Ok(());
    }
    let window = window.max(1).min(count);
    let state = Mutex::new(WindowState::<T> {
        pending: BTreeMap::new(),
        claimed: BTreeSet::new(),
        cursor: 0,
        stopped: false,
    });
    let ready = Condvar::new();
    thread::scope(|scope| {
        for _ in 0..threads.min(count) {
            let state = &state;
            let ready = &ready;
            let task = &task;
            scope.spawn(move || {
                loop {
                    let index = {
                        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                        loop {
                            if state.stopped || state.cursor >= count {
                                return;
                            }
                            if let Some(index) = next_claim(&mut state, priority, window, count) {
                                break index;
                            }
                            state = ready.wait(state).unwrap_or_else(|e| e.into_inner());
                        }
                    };
                    let item = task(index);
                    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                    if state.stopped {
                        // Delivery already failed; drop the unused fact set.
                        state.claimed.remove(&index);
                        ready.notify_all();
                        return;
                    }
                    state.pending.insert(index, item);
                    ready.notify_all();
                }
            });
        }

        // The calling thread is the only deliverer. It waits for the cursor's
        // outcome, delivers every contiguous finished index, then wakes workers
        // so they can claim the slots just freed.
        loop {
            let batch = {
                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if state.pending.contains_key(&state.cursor) {
                        break;
                    }
                    if state.stopped {
                        return Ok(());
                    }
                    // `cursor < count` here, so the claim window is non-empty and
                    // some worker owns the cursor or will claim it next.
                    state = ready.wait(state).unwrap_or_else(|e| e.into_inner());
                }
                let mut batch = Vec::new();
                loop {
                    let cursor = state.cursor;
                    let Some(item) = state.pending.remove(&cursor) else {
                        break;
                    };
                    state.claimed.remove(&cursor);
                    batch.push((cursor, item));
                    state.cursor += 1;
                }
                let done = state.cursor >= count;
                // Delivering frees window slots, so blocked workers must be woken
                // here; otherwise a worker parked in `ready.wait` after the last
                // publish would never observe the free capacity (lost wakeup).
                if !batch.is_empty() {
                    ready.notify_all();
                }
                (batch, done)
            };
            let (batch, done) = batch;
            for (index, item) in batch {
                if let Err(error) = deliver(index, item) {
                    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                    state.stopped = true;
                    ready.notify_all();
                    return Err(error);
                }
            }
            if done {
                return Ok(());
            }
        }
    })
}

/// Claim the highest-priority unclaimed index inside the delivery window.
fn next_claim<T>(
    state: &mut WindowState<T>,
    priority: &[usize],
    window: usize,
    count: usize,
) -> Option<usize> {
    let end = state.cursor.saturating_add(window).min(count);
    let mut best: Option<usize> = None;
    for index in state.cursor..end {
        if state.claimed.contains(&index) {
            continue;
        }
        best = match best {
            Some(current) if priority[current] <= priority[index] => Some(current),
            _ => Some(index),
        };
    }
    let index = best?;
    state.claimed.insert(index);
    Some(index)
}

/// Outstanding work and delivery position for one batch.
struct WindowState<T> {
    /// Finished occurrences waiting for the delivery cursor, keyed by index.
    pending: BTreeMap<usize, T>,
    /// Claimed but not yet delivered indexes. Bounded by the window, and every
    /// entry is inside `[cursor, cursor + window)`.
    claimed: BTreeSet<usize>,
    /// Lowest inventory index not yet delivered.
    cursor: usize,
    /// Set when delivery failed so every worker stops instead of finishing work
    /// whose result can never be observed.
    stopped: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(index: usize) -> MddError {
        MddError::new(ErrorCode::InternalFault, "facts.pipeline.test", "injected")
            .detail("dex_index", index.to_string())
    }

    /// Collect a full windowed run into inventory order for assertions.
    fn collect<T, F>(
        threads: usize,
        window: usize,
        count: usize,
        order: &[usize],
        task: F,
    ) -> Vec<(usize, T)>
    where
        T: Send,
        F: Fn(usize) -> T + Send + Sync,
    {
        let mut out = Vec::new();
        windowed_map(threads, window, count, order, task, |index, item| {
            out.push((index, item));
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn windowed_map_delivers_in_inventory_order_not_completion_order() {
        // Index 0 is the slowest, so it completes last; delivery must still start
        // with index 0 and stay ascending.
        let order: Vec<usize> = (0..6).collect();
        let got = collect(3, 3, 6, &order, |index| {
            if index == 0 {
                thread::sleep(Duration::from_millis(40));
            }
            index * 10
        });
        assert_eq!(
            got.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            (0..6).collect::<Vec<_>>()
        );
        assert_eq!(
            got.iter().map(|(_, value)| *value).collect::<Vec<_>>(),
            vec![0, 10, 20, 30, 40, 50]
        );
    }

    #[test]
    fn windowed_map_claims_each_index_exactly_once() {
        let order: Vec<usize> = (0..33).collect();
        // Reverse claim order: heaviest DEX first, inventory order still delivered.
        let mut claim = order.clone();
        claim.reverse();
        let got = collect(4, 8, 33, &claim, |index| index);
        assert_eq!(got.len(), 33);
        assert_eq!(
            got.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            order
        );
        let mut seen = got.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 33, "each index must be built exactly once");
    }

    #[test]
    fn windowed_map_stops_at_the_first_failing_index() {
        let order: Vec<usize> = (0..8).collect();
        let mut delivered = Vec::new();
        let error = windowed_map(
            4,
            4,
            8,
            &order,
            |index| {
                if index == 3 {
                    thread::sleep(Duration::from_millis(30));
                }
                index
            },
            |index, _| {
                delivered.push(index);
                if index == 3 {
                    return Err(failure(3));
                }
                Ok(())
            },
        )
        .unwrap_err();
        // Serial abort position: indexes 0..=2 delivered, index 3 raised, 4.. never
        // observed even though workers may have finished them.
        assert_eq!(delivered, vec![0, 1, 2, 3]);
        assert_eq!(error.details["dex_index"], "3");
    }

    #[test]
    fn windowed_map_serial_path_matches_pool_path() {
        let order: Vec<usize> = (0..12).collect();
        let task = |index: usize| index * 3;
        assert_eq!(
            collect(1, 1, 12, &order, task),
            collect(4, 4, 12, &order, task)
        );
    }

    #[test]
    fn windowed_map_handles_empty_and_single_occurrence_inputs() {
        fn task(index: usize) -> usize {
            index
        }
        assert!(collect(4, 4, 0, &[], task).is_empty());
        assert_eq!(collect(4, 4, 1, &[0], task), vec![(0, 0)]);
        // A window smaller than the worker count must not deadlock or skip work.
        let order: Vec<usize> = (0..10).collect();
        assert_eq!(collect(4, 1, 10, &order, task).len(), 10);
    }

    #[test]
    fn in_flight_window_is_bounded_and_rejects_zero() {
        let config = PipelineConfig::default();
        assert_eq!(config.resolve_in_flight(4, 33).unwrap(), 8);
        assert_eq!(config.resolve_in_flight(4, 3).unwrap(), 3);
        let explicit = PipelineConfig {
            max_in_flight: Some(2),
            ..PipelineConfig::default()
        };
        // Never below the worker count, otherwise workers would idle.
        assert_eq!(explicit.resolve_in_flight(4, 33).unwrap(), 4);
        let zero = PipelineConfig {
            max_in_flight: Some(0),
            ..PipelineConfig::default()
        };
        assert_eq!(
            zero.resolve_in_flight(4, 33).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(config.resolve_in_flight(4, 0).unwrap(), 0);
    }
}
