//! The contract relations served from column stores that are built one DEX at a time.
//!
//! A provider made by `from_scope` is handed the fact layers of every selected DEX and keeps them: for an archive of
//! thirty-three DEX that is several gigabytes of objects behind a few hundred megabytes of rows. A provider made by
//! `from_loader` is handed a way to build the layers of one DEX instead. The first time a relation is asked for it
//! loads the DEX one after the other, takes from each its layer check, its coverage states and its rows, puts the rows
//! into a `RelationStore` and lets that DEX's layers go. What stays is the stores, the text dictionary they share, and
//! a few facts about each DEX.
//!
//! Nothing about what a relation answers changes: the rows come from the same `occurrence_rows`, the layer check is the
//! same function, and the coverage report is the one the ledger gives for the states of all the DEX
//! (`CoverageLedger::evaluate_from_states`). A relation that is refused is refused with the same error, and the refusal
//! is kept; a failure that depends on the caller (cancel, deadline, budget) is not kept, so the next caller builds again.
use super::*;
use crate::{
    column_store::{
        Cell, Derive, DerivedColumn, RefTable, RelationStore, RelationStoreBuilder, RowSink,
        TextDict,
    },
    control::SqlLimits,
};
use mdd_facts::coverage::OccurrenceStates;
use std::sync::Mutex;

/// What a pass over one DEX needs built beyond the metadata and definitions, which are always built.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LayerNeeds {
    pub code: bool,
    pub references: bool,
    pub annotations: bool,
}

impl LayerNeeds {
    pub fn for_layers(layers: &[FactLayer]) -> Self {
        let references = layers.contains(&FactLayer::References);
        Self {
            code: references || layers.contains(&FactLayer::CodeLayout),
            references,
            annotations: layers.contains(&FactLayer::Annotations),
        }
    }
}

/// Builds the fact layers of one selected DEX, on request. The provider drops what it gets as soon as it has taken its
/// rows from it, so an implementation should not keep it either.
///
/// A layer that cannot be built is not an error of `load`: the facts come back without it (see
/// `HostLabOccurrenceFacts::structural`) and the relation that needs it is refused with the layer error. An error of
/// `load` is for what stops the whole pass: the metadata or definitions of the DEX cannot be built, or the caller cancelled.
pub trait OccurrenceLoader: Send + Sync {
    fn load(&self, position: usize, needs: LayerNeeds) -> MddResult<HostLabOccurrenceFacts>;
}

/// What the provider keeps about a selected DEX between passes.
struct Descriptor {
    provenance: Result<HostLabProvenance, MddError>,
    file_id: u32,
    string_pool_id: u32,
}

enum Slot {
    Empty,
    Ready(Arc<RelationStore>),
    /// A refusal that is a property of the input, kept so it is not worked out again.
    Failed(MddError),
}

pub(super) struct LazyStores {
    loader: Arc<dyn OccurrenceLoader>,
    descriptors: Vec<Descriptor>,
    dict: Arc<TextDict>,
    slots: Vec<(ContractRelation, Mutex<Slot>)>,
}

impl LazyStores {
    /// Rows of a relation whose store is built; nothing is claimed for one that is not.
    pub(super) fn stored_rows(&self, relation: ContractRelation) -> Option<u64> {
        let (_, slot) = self
            .slots
            .iter()
            .find(|(candidate, _)| candidate.name() == relation.name())?;
        match &*slot.lock().ok()? {
            Slot::Ready(store) => Some(store.rows()),
            _ => None,
        }
    }

    /// Bytes the built stores, the reference tables they share and their dictionary hold.
    pub(super) fn bytes_used(&self) -> usize {
        let mut tables: std::collections::BTreeMap<usize, usize> =
            std::collections::BTreeMap::new();
        let stores: usize = self
            .slots
            .iter()
            .filter_map(|(_, slot)| match &*slot.lock().ok()? {
                Slot::Ready(store) => {
                    for table in store.tables() {
                        tables.insert(Arc::as_ptr(table) as usize, table.bytes_used());
                    }
                    Some(store.bytes_used())
                }
                _ => None,
            })
            .sum();
        stores + tables.values().sum::<usize>() + self.dict.bytes_used()
    }
}

/// The columns of a relation that are not stored because the row names the text by an index: a call, a field access or a
/// type use names its method, field and type by the index the DEX gives them, and the DEX lists the text of each once.
fn derived_columns(
    relation: ContractRelation,
    schema: &[crate::provider::SqlColumn],
) -> Vec<DerivedColumn> {
    use Derive::{
        FieldClass, FieldDescriptor, FieldName, FieldType, MethodClass, MethodDescriptor,
        MethodName, TypeDescriptor, TypeName,
    };
    let ContractRelation::Required(required) = relation else {
        return Vec::new();
    };
    // (column, the column that holds the index, what the index names)
    let spec: &[(&str, &str, Derive)] = match required {
        HostLabRelation::MethodCalls => &[
            ("method", "method_idx", MethodDescriptor),
            ("method_class", "method_idx", MethodClass),
            ("method_name", "method_idx", MethodName),
            ("callee", "callee_method_idx", MethodDescriptor),
            ("callee_class", "callee_method_idx", MethodClass),
            ("callee_name", "callee_method_idx", MethodName),
        ],
        HostLabRelation::MethodFieldAccesses => &[
            ("method", "method_idx", MethodDescriptor),
            ("method_class", "method_idx", MethodClass),
            ("method_name", "method_idx", MethodName),
            ("field", "field_idx", FieldDescriptor),
            ("field_class", "field_idx", FieldClass),
            ("field_name", "field_idx", FieldName),
            ("field_type", "field_idx", FieldType),
        ],
        HostLabRelation::MethodUsedTypes => &[
            ("method", "method_idx", MethodDescriptor),
            ("method_class", "method_idx", MethodClass),
            ("method_name", "method_idx", MethodName),
            ("type_descriptor", "type_idx", TypeDescriptor),
            ("type_name", "type_idx", TypeName),
        ],
        HostLabRelation::ClassMethods => &[
            ("class_descriptor", "method_idx", MethodClass),
            ("method_name", "method_idx", MethodName),
            ("method_descriptor", "method_idx", MethodDescriptor),
        ],
        HostLabRelation::ClassFields => &[
            ("class_descriptor", "field_idx", FieldClass),
            ("field_name", "field_idx", FieldName),
            ("field_descriptor", "field_idx", FieldDescriptor),
        ],
        _ => &[],
    };
    let at = |name: &str| schema.iter().position(|column| column.name == name);
    spec.iter()
        .filter_map(|(column, index, derive)| {
            Some(DerivedColumn {
                column: at(column)?,
                index_column: at(index)?,
                derive: *derive,
            })
        })
        .collect()
}

/// A refusal belongs to the input and is kept; what depends on the caller is not.
fn is_property_of_the_input(error: &MddError) -> bool {
    !matches!(
        error.code,
        ErrorCode::Cancelled
            | ErrorCode::DeadlineExceeded
            | ErrorCode::QuotaExceeded
            | ErrorCode::WorkerLost
    )
}

impl HostLabSqlProvider {
    /// As `from_scope`, without the facts: `loader` builds the layers of one DEX when a relation needs them.
    ///
    /// The scope supplies the pool coordinate (the roster position, as `occurrence_pool_coordinates` gives for every
    /// observed sample) and the provenance text. Each DEX is checked against the scope when it is loaded, so a loader that
    /// builds from the wrong input is refused on first use instead of answering for another archive.
    pub fn from_loader(
        scope: &SelectedScope,
        loader: Arc<dyn OccurrenceLoader>,
        epoch: DecimalU64,
    ) -> MddResult<Self> {
        if !scope.roster_complete() {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "sql.hostlab",
                "selected DEX roster is incomplete",
            ));
        }
        let count = scope.dexes().len();
        if count == 0 {
            return Err(invalid("HOSTLAB_SCOPE_HAS_NO_DEX"));
        }
        if u64::try_from(count).unwrap_or(u64::MAX) > MAX_HOSTLAB_OCCURRENCES {
            return Err(quota("HOSTLAB_SCOPE_TOO_LARGE"));
        }
        let descriptors = (0..count)
            .map(|position| {
                let ordinal =
                    u32::try_from(position).map_err(|_| quota("HOSTLAB_SCOPE_TOO_LARGE"))?;
                Ok(Descriptor {
                    provenance: scope.dex_file_provenance(&scope.dexes()[position]).map(
                        |resolved| HostLabProvenance {
                            source_path: resolved.source_path,
                            entry_name: resolved.entry_name,
                        },
                    ),
                    file_id: ordinal,
                    string_pool_id: ordinal,
                })
            })
            .collect::<MddResult<Vec<_>>>()?;
        let slots = ContractRelation::all()
            .into_iter()
            .map(|relation| (relation, Mutex::new(Slot::Empty)))
            .collect();
        Ok(Self {
            binding: SqlBinding {
                provider_identity: mdd_types::opaque_id("sql-hostlab-provider")?,
                snapshot_id: scope.snapshot_id().to_owned(),
                catalog_epoch: epoch,
            },
            occurrences: Vec::new(),
            count,
            lazy: Some(LazyStores {
                loader,
                descriptors,
                dict: TextDict::new(),
                slots,
            }),
            scope: scope.clone(),
            coverage: std::array::from_fn(|_| std::sync::OnceLock::new()),
        })
    }

    /// Bytes held by the stores built so far and their shared dictionary; `None` for a provider that holds the layers.
    pub fn stored_bytes(&self) -> Option<usize> {
        self.lazy.as_ref().map(LazyStores::bytes_used)
    }

    /// The store of `relation`, built now if it is not built yet. `control` is the caller's (cancel, deadline, budget);
    /// without one the build is bounded by nothing but the input.
    pub(super) fn ensure_store(
        &self,
        relation: ContractRelation,
        control: Option<&SqlControl>,
    ) -> MddResult<Arc<RelationStore>> {
        let lazy = self.lazy.as_ref().ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "sql.hostlab",
                "this provider holds its layers and builds no stores",
            )
        })?;
        let (_, slot) = lazy
            .slots
            .iter()
            .find(|(candidate, _)| candidate.name() == relation.name())
            .ok_or_else(|| invalid("UNKNOWN_HOSTLAB_RELATION"))?;
        let mut slot = slot.lock().map_err(|_| {
            MddError::new(
                ErrorCode::InternalFault,
                "sql.hostlab",
                "a store build panicked",
            )
        })?;
        match &*slot {
            Slot::Ready(store) => return Ok(Arc::clone(store)),
            Slot::Failed(error) => return Err(error.clone()),
            Slot::Empty => {}
        }
        let unbounded;
        let control = match control {
            Some(control) => control,
            None => {
                unbounded = unbounded_control();
                &unbounded
            }
        };
        let built = self
            .build_group(lazy, &[relation], control)?
            .pop()
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "sql.hostlab",
                    "a store build returned nothing",
                )
            })?;
        Self::settle(&mut slot, built)
    }

    /// Build the stores of every relation that has none yet, in one pass over the DEX: each DEX is loaded once, every
    /// relation takes its rows from it, and its layers are let go before the next. Building them relation by relation
    /// loads every DEX again for each. A relation that is refused is refused as it is by `ensure_store`; the pass itself
    /// fails only when a DEX cannot be loaded or the caller's control stops it.
    pub fn prepare_all(&self, control: Option<&SqlControl>) -> MddResult<()> {
        self.prepare_where(|_| true, control)
    }

    /// `prepare_all` for the seventeen relations the HostLab queries read. The public relations beyond them (the
    /// instruction-level ones among them hold tens of millions of rows for a large archive) are built when a statement
    /// first asks for one, not before.
    pub fn prepare_required(&self, control: Option<&SqlControl>) -> MddResult<()> {
        self.prepare_where(
            |relation| matches!(relation, ContractRelation::Required(_)),
            control,
        )
    }

    fn prepare_where(
        &self,
        wanted: impl Fn(ContractRelation) -> bool,
        control: Option<&SqlControl>,
    ) -> MddResult<()> {
        let lazy = self.lazy.as_ref().ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "sql.hostlab",
                "this provider holds its layers and builds no stores",
            )
        })?;
        // The slots are locked in their fixed order for the whole pass, so a caller that asks for one of these
        // relations meanwhile waits for the pass and then finds its store.
        let mut guards = Vec::new();
        for (relation, slot) in &lazy.slots {
            let guard = slot.lock().map_err(|_| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "sql.hostlab",
                    "a store build panicked",
                )
            })?;
            if matches!(&*guard, Slot::Empty) && wanted(*relation) {
                guards.push((*relation, guard));
            }
        }
        if guards.is_empty() {
            return Ok(());
        }
        let unbounded;
        let control = match control {
            Some(control) => control,
            None => {
                unbounded = unbounded_control();
                &unbounded
            }
        };
        let relations: Vec<ContractRelation> =
            guards.iter().map(|(relation, _)| *relation).collect();
        let built = self.build_group(lazy, &relations, control)?;
        for ((_, guard), built) in guards.iter_mut().zip(built) {
            // The refusals are kept in their slots; what the caller can do about them is up to the statement that asks.
            let _ = Self::settle(guard, built);
        }
        Ok(())
    }

    /// Keep the outcome of one relation's build in its slot: a store, or a refusal that belongs to the input.
    fn settle(
        slot: &mut Slot,
        built: MddResult<Arc<RelationStore>>,
    ) -> MddResult<Arc<RelationStore>> {
        match built {
            Ok(store) => {
                *slot = Slot::Ready(Arc::clone(&store));
                Ok(store)
            }
            Err(error) => {
                if is_property_of_the_input(&error) {
                    *slot = Slot::Failed(error.clone());
                }
                Err(error)
            }
        }
    }

    /// What a pass over one DEX must build for `relation`: its own layers, and what the ledger asks of the DEX before it
    /// accepts the relation. The ledger proves that a method is bound to its code item (`MethodBindings`) from the
    /// reference layer, so `methods` and `code_items` are refused without it, as they are when the layers are held.
    fn needs_of(relation: ContractRelation) -> LayerNeeds {
        let mut needs = LayerNeeds::for_layers(&relation.required_layers());
        if matches!(
            relation,
            ContractRelation::Required(HostLabRelation::Methods | HostLabRelation::CodeItems)
        ) {
            needs.code = true;
            needs.references = true;
        }
        needs
    }

    /// The stores of `relations`, built in one pass over the DEX; one outcome per relation, in the order given.
    ///
    /// Each DEX is loaded once, with what any of the relations needs. For each relation that is still being built it takes
    /// the layer check, the coverage states and the rows, exactly as a pass for that relation alone would, and then the
    /// layers are let go. A relation whose layer check fails stops there with that error, as it ends a pass of its own;
    /// the others go on. The outer error is for what stops the whole pass: a DEX that cannot be loaded, or the control.
    ///
    /// The relations of one DEX are fed by several threads, one relation to a thread at a time: each has a builder of its
    /// own, so no relation sees its rows in another order than the DEX order, whatever the number of threads.
    fn build_group(
        &self,
        lazy: &LazyStores,
        relations: &[ContractRelation],
        control: &SqlControl,
    ) -> MddResult<Vec<MddResult<Arc<RelationStore>>>> {
        let mut passes = Vec::with_capacity(relations.len());
        for &relation in relations {
            let schema = Self::relation(relation).columns;
            // Only the contract relations are proven column by column by the ledger.
            let request = match relation {
                ContractRelation::Required(required) => Some(CoverageRequest::for_relations(
                    &self.scope,
                    &[required.name()],
                )?),
                ContractRelation::Public(_) => None,
            };
            let derived = derived_columns(relation, &schema);
            passes.push(Pass {
                relation,
                builder: Some(RelationStoreBuilder::with_derived(
                    &schema,
                    Arc::clone(&lazy.dict),
                    &derived,
                )),
                request,
                states: Vec::new(),
                stopped: None,
                row_error: None,
                cost: std::time::Duration::ZERO,
            });
        }
        let threads = pass_threads();
        for (position, descriptor) in lazy.descriptors.iter().enumerate() {
            let mut needs = LayerNeeds::default();
            for pass in passes.iter().filter(|pass| pass.stopped.is_none()) {
                let wanted = Self::needs_of(pass.relation);
                needs.code |= wanted.code;
                needs.references |= wanted.references;
                needs.annotations |= wanted.annotations;
            }
            if passes.iter().all(|pass| pass.stopped.is_some()) {
                break;
            }
            let loaded = lazy.loader.load(position, needs)?;
            let occurrence = HostLabOccurrence {
                facts: loaded,
                provenance: descriptor.provenance.clone(),
                file_id: descriptor.file_id,
                string_pool_id: descriptor.string_pool_id,
            };
            let expected = &self.scope.dexes()[position].dex_occurrence_id;
            if &occurrence.source().dex_occurrence_id != expected {
                return Err(invalid("HOSTLAB_SCOPE_METADATA_MISMATCH"));
            }
            let view = Self::view_of(&occurrence);
            let ledger = CoverageLedger::new(self.scope.clone(), std::slice::from_ref(&view))?;
            // The texts the references of this DEX name, once for every relation that reads them by index. A DEX whose
            // definitions cannot be built has none; the relations that need them are stopped by their layer check, which
            // comes before any row.
            let wants_table = passes.iter().any(|pass| {
                pass.stopped.is_none()
                    && pass
                        .builder
                        .as_ref()
                        .is_some_and(RelationStoreBuilder::has_derived)
            });
            let table = if wants_table {
                Self::ref_table(&occurrence, &lazy.dict).ok().map(Arc::new)
            } else {
                None
            };
            // The relations that cost the most so far are taken first, so the last thread to finish is not the one that
            // started the biggest relation late.
            let mut live: Vec<&mut Pass> = passes
                .iter_mut()
                .filter(|pass| pass.stopped.is_none())
                .collect();
            live.sort_by_key(|pass| pass.cost);
            let workers = threads.min(live.len());
            if workers <= 1 {
                for pass in live.into_iter().rev() {
                    self.feed(
                        pass,
                        &occurrence,
                        &ledger,
                        expected,
                        control,
                        table.as_ref(),
                    );
                }
            } else {
                let queue = Mutex::new(live);
                std::thread::scope(|scope| {
                    for _ in 0..workers {
                        scope.spawn(|| {
                            loop {
                                let next = queue.lock().ok().and_then(|mut queue| queue.pop());
                                let Some(pass) = next else { break };
                                self.feed(
                                    pass,
                                    &occurrence,
                                    &ledger,
                                    expected,
                                    control,
                                    table.as_ref(),
                                );
                            }
                        });
                    }
                });
            }
        }
        let shell = CoverageLedger::new(self.scope.clone(), &[])?;
        let outcomes: Vec<MddResult<Arc<RelationStore>>> = passes
            .into_iter()
            .map(|pass| {
                if let Some(error) = pass.stopped {
                    return Err(error);
                }
                if let Some(request) = &pass.request {
                    let report = shell.evaluate_from_states(request, &pass.states)?;
                    if let ContractRelation::Required(required) = pass.relation {
                        Self::coverage_verdict(&report, required)?;
                    }
                }
                if let Some(error) = pass.row_error {
                    return Err(error);
                }
                // A pass gives up its builder only for a refusal, and a refusal is an error above.
                pass.builder
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "sql.hostlab",
                            "a relation gave up its rows but was not refused",
                        )
                    })
                    .map(RelationStoreBuilder::finish)
            })
            .collect();
        lazy.dict.shrink_to_fit();
        Ok(outcomes)
    }

    /// The texts that the method, field and type references of one DEX name, as dictionary ids, from the same facts the rows of
    /// the relations that read them by index are made from.
    fn ref_table(occurrence: &HostLabOccurrence, dict: &TextDict) -> MddResult<RefTable> {
        let definitions = occurrence.definitions()?.definitions();
        let mut table = RefTable {
            methods: definitions
                .method_references
                .iter()
                .map(|r| {
                    [
                        dict.intern_str(&r.class_descriptor),
                        dict.intern_str(&r.method_name),
                        dict.intern_str(&r.descriptor),
                    ]
                })
                .collect(),
            fields: definitions
                .field_references
                .iter()
                .map(|r| {
                    [
                        dict.intern_str(&r.class_descriptor),
                        dict.intern_str(&r.field_name),
                        dict.intern_str(&r.descriptor),
                        dict.intern_str(&r.type_descriptor),
                    ]
                })
                .collect(),
            types: occurrence
                .facts
                .metadata
                .types()
                .iter()
                .map(|t| {
                    let descriptor = &t.data.descriptor;
                    [
                        dict.intern_str(descriptor),
                        dict.intern_str(&mdd_facts::references::type_name(descriptor)),
                    ]
                })
                .collect(),
        };
        table.shrink_to_fit();
        Ok(table)
    }

    /// One relation's share of one DEX: the layer check, the coverage state, and the rows into the builder.
    fn feed(
        &self,
        pass: &mut Pass,
        occurrence: &HostLabOccurrence,
        ledger: &CoverageLedger,
        expected: &str,
        control: &SqlControl,
        table: Option<&Arc<RefTable>>,
    ) {
        let started = std::time::Instant::now();
        // The layer check comes first and ends the pass, as `require_layer` ends at the first occurrence that fails it.
        let checked = match pass.relation {
            ContractRelation::Required(required) => Self::check_layer(required, occurrence),
            ContractRelation::Public(public) => self.check_public_layer(public, occurrence),
        };
        if let Err(error) = checked {
            pass.stopped = Some(error);
            return;
        }
        let mut complete = true;
        if let Some(request) = &pass.request {
            let state = ledger.occurrence_states(request, expected);
            complete = state.is_complete();
            pass.states.push(state);
        }
        // A DEX the ledger will refuse gives no rows, and neither does any DEX after it: the ledger refuses the relation
        // whatever the other DEX hold, so the rows already made are let go and the states of the rest are all that is
        // still collected. The refusal is what the caller gets.
        if !complete || pass.row_error.is_some() {
            pass.builder = None;
            return;
        }
        let Some(builder) = pass.builder.as_mut() else {
            return;
        };
        builder.begin_partition(u64::from(occurrence.file_id));
        if builder.has_derived()
            && let Some(table) = table
        {
            builder.set_table(Arc::clone(table));
        }
        let mut sink = Tracked {
            builder,
            refused: None,
        };
        let produced = self.occurrence_into(pass.relation, occurrence, control, &mut sink);
        let refused = sink.refused.take();
        if let Err(error) = produced {
            // a row the store cannot hold ends the relation; a DEX whose rows cannot be made is reported after the verdict
            match refused {
                Some(refused) => pass.stopped = Some(refused),
                None => pass.row_error = Some(error),
            }
        }
        pass.cost += started.elapsed();
    }
}

/// A builder that remembers whether the error that ended a DEX's rows was its own: a row the store cannot hold, as opposed
/// to a DEX whose rows could not be made.
struct Tracked<'a> {
    builder: &'a mut RelationStoreBuilder,
    refused: Option<MddError>,
}

impl RowSink for Tracked<'_> {
    fn row(&mut self, row: SqlRow) -> MddResult<()> {
        self.builder.row(row).inspect_err(|error| {
            self.refused.get_or_insert_with(|| error.clone());
        })
    }

    fn cells(&mut self, cells: &[Cell<'_>]) -> MddResult<()> {
        self.builder.cells(cells).inspect_err(|error| {
            self.refused.get_or_insert_with(|| error.clone());
        })
    }
}

/// One relation while a pass over the DEX builds it.
struct Pass {
    relation: ContractRelation,
    /// `None` once the relation is certain to be refused: its rows are not made and what was made is let go.
    builder: Option<RelationStoreBuilder>,
    request: Option<CoverageRequest>,
    states: Vec<OccurrenceStates>,
    /// What ended this relation's pass early: its layer check, or a row the store cannot hold.
    stopped: Option<MddError>,
    /// The error of the first DEX whose rows could not be produced; reported after the ledger's verdict.
    row_error: Option<MddError>,
    /// Time spent on this relation so far, which orders the relations of the next DEX.
    cost: std::time::Duration,
}

/// How many threads feed the stores of one DEX at once: `MDD_PASS_THREADS` when it is set, else the cores this process
/// may use, at most four. The rows of a DEX take far less time than its layers do, so more threads add memory (each holds
/// the rows it is making) and no speed.
fn pass_threads() -> usize {
    std::env::var("MDD_PASS_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&threads| threads >= 1)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(1, std::num::NonZeroUsize::get)
                .min(4)
        })
}

/// The control for a build nobody bounds: the input is the only limit.
fn unbounded_control() -> SqlControl {
    SqlControl::new(
        SqlLimits {
            max_steps: u64::MAX,
            max_scanned_rows: u64::MAX,
            max_result_rows: u64::MAX,
            ..SqlLimits::default()
        },
        None,
    )
}
