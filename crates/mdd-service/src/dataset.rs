//! One opened input set and the SQL session over it.
//!
//! Opening captures the inputs once into a snapshot, builds the archive inventories,
//! the fact layers and the SQL provider for the chosen dialect, and registers the
//! snapshot and one session with the `mdd-session` lifecycle. A dataset can then run
//! any number of statements (`run`), one at a time. Nothing here is a second parser:
//! every row comes from the same fact layers the other consumers read.
//!
//! Two providers are offered, and the dialect decides which:
//!
//! * `native-v1` reads the metadata and structure layers through the native relation
//!   names.
//! * `dexsql-0.1.0` and `dexsql-0.1.1` read the seventeen HostLab contract relations
//!   over every fact layer. A layer that cannot be built is not an empty table: the
//!   relations that need it refuse with the layer's own error, and the dataset says
//!   which layer is missing and why in `layer_issues`.
use crate::{
    decode::{LazyDexDecode, Occurrence},
    layers::LayerBuilder,
};
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{
    DefinitionFacts, MetadataFacts, coverage::NonScalarTextPolicy, indexes::SelectedScope,
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    manifest::ManifestDocument,
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_session::{Lifecycle, ResourceLimits, SessionHandle, SnapshotHandle};
use mdd_sql::{
    SqlBridge,
    control::SqlLimits,
    dialects::SqlDialect,
    provider::{
        hostlab::{HostLabSqlProvider, OccurrenceLoader},
        metadata::{CombinedSqlProvider, DefinitionSqlProvider, MetadataSqlProvider},
    },
    temp::TempSqlSession,
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

/// The SQL dialect a dataset answers in. The name is the stable spelling used on the
/// command line and in every result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dialect {
    NativeV1,
    DexSql010,
    DexSql011,
}

impl Dialect {
    pub fn parse(name: &str) -> MddResult<Self> {
        match name {
            "native-v1" => Ok(Self::NativeV1),
            "dexsql-0.1.0" => Ok(Self::DexSql010),
            "dexsql-0.1.1" => Ok(Self::DexSql011),
            other => Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cli",
                format!("unknown dialect `{other}`; use native-v1, dexsql-0.1.0 or dexsql-0.1.1"),
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::NativeV1 => "native-v1",
            Self::DexSql010 => "dexsql-0.1.0",
            Self::DexSql011 => "dexsql-0.1.1",
        }
    }

    /// Neither profile is admitted; the name says so.
    pub fn profile(self) -> &'static str {
        match self {
            Self::NativeV1 => "native-unqualified",
            Self::DexSql010 | Self::DexSql011 => "hostlab-contract-unqualified",
        }
    }

    /// The dialect as the SQL layer names it.
    pub fn sql(self) -> SqlDialect {
        match self {
            Self::NativeV1 => SqlDialect::NativeV1,
            Self::DexSql010 => SqlDialect::DexSql010,
            Self::DexSql011 => SqlDialect::DexSql011,
        }
    }
}

pub struct InputRequest {
    pub path: PathBuf,
    /// `None` detects the kind from the file's magic bytes.
    pub kind: Option<InputKind>,
}

/// An optional fact layer that could not be built for one DEX.
#[derive(Clone, Debug)]
pub struct LayerIssue {
    pub dex_occurrence_id: String,
    pub layers: &'static str,
    pub error: MddError,
}

pub struct Dataset {
    pub(crate) lifecycle: Arc<Lifecycle>,
    pub(crate) snapshot: Arc<Snapshot>,
    snapshot_handle: SnapshotHandle,
    pub(crate) session: SessionHandle,
    /// The session's SQL front: plain statements, TEMP definitions and windows. Its
    /// bridge is what `run` prepares and executes against.
    temp: Option<TempSqlSession>,
    pub(crate) scope_id: String,
    pub(crate) dialect: Dialect,
    pub(crate) non_scalar_text_policy: NonScalarTextPolicy,
    pub(crate) limits: ResourceLimits,
    layer_issues: Vec<LayerIssue>,
    dex_count: usize,
    /// Builds the layers of one DEX on request; `None` for the native dialect. The dataset keeps no layer of its own: the
    /// SQL relations were filled from them at open, and `decode` builds the facts it renders from on demand per DEX.
    layers: Option<Arc<LayerBuilder>>,
    /// HostLab SQL provider retained for fast in-memory descriptor resolution without loading unrelated DEXes.
    hostlab_provider: Option<Arc<HostLabSqlProvider>>,
    /// Per-DEX lazy decode cache (indexed by `file_id`); only touched DEXes are opened and parsed.
    lazy_decode: Vec<OnceLock<MddResult<LazyDexDecode>>>,
    /// What `occurrences()` reads, built on demand; empty for the native dialect.
    decode: OnceLock<MddResult<Vec<Occurrence>>>,
    /// One inventory per input, in the order given; `get_manifest` reads from them.
    pub(crate) inventories: Arc<Vec<ArchiveInventory>>,
    /// Parsed manifests by input position, so paging the permissions parses once.
    pub(crate) manifests: Mutex<HashMap<usize, Arc<ManifestDocument>>>,
    /// Resources read, rendered or parsed, so paging through one reads it once.
    pub(crate) resources: Mutex<crate::resources::ResourceCache>,
}

impl Dataset {
    pub fn open(
        inputs: &[InputRequest],
        dialect: Dialect,
        limits: ResourceLimits,
        sql_limits: SqlLimits,
    ) -> MddResult<Self> {
        Self::open_with_non_scalar_policy(
            inputs,
            dialect,
            limits,
            sql_limits,
            NonScalarTextPolicy::Reject,
        )
    }

    /// As [`Self::open`], with an explicit opt-in policy for legal non-scalar UTF-16 strings in
    /// plain-UTF-8 HostLab contract columns (`strings.value`, `classes.source_file`, `method_strings.value`).
    pub fn open_with_non_scalar_policy(
        inputs: &[InputRequest],
        dialect: Dialect,
        limits: ResourceLimits,
        sql_limits: SqlLimits,
        non_scalar_text_policy: NonScalarTextPolicy,
    ) -> MddResult<Self> {
        let mut specs = Vec::with_capacity(inputs.len());
        for input in inputs {
            let kind = match input.kind {
                Some(kind) => kind,
                None => InputKind::detect(&input.path)?,
            };
            specs.push(InputSpec {
                path: input.path.clone(),
                kind,
                expected_sha256: None,
            });
        }
        let snapshot = Arc::new(Snapshot::capture(&specs, CaptureLimits::default())?);
        let mut inventories = Vec::new();
        for source in snapshot.sources() {
            // An archive with resources and no DEX is a valid input: the resource tools
            // read it, and the tools that need code say so (`require_dex`).
            inventories.push(ArchiveInventory::build(
                source,
                InventoryPolicy {
                    require_dex: false,
                    // The decompressed DEX of a large archive are as big as the archive again, and the facts built from
                    // them hold what they need: they are read from the archive when a layer is built.
                    hold_dex_bytes: false,
                    ..InventoryPolicy::default()
                },
                ArchiveLimits::default(),
            )?);
        }
        let refs: Vec<&ArchiveInventory> = inventories.iter().collect();
        let scope = SelectedScope::from_inventories(&snapshot, &refs)?;
        let inventories = Arc::new(inventories);
        let dex_count: usize = inventories.iter().map(|i| i.selected_dexes().len()).sum();
        // No DEX, no SQL: the facts every relation reads do not exist, and an empty provider
        // would answer "no rows" where the truth is "nothing to ask".
        let built = (dex_count > 0).then(|| match dialect {
            Dialect::NativeV1 => Self::native_bridge(&snapshot, &inventories, sql_limits)
                .map(|bridge| (bridge, Vec::new(), None, None)),
            Dialect::DexSql010 | Dialect::DexSql011 => Self::contract_bridge(
                dialect,
                &snapshot,
                &inventories,
                &scope,
                sql_limits,
                non_scalar_text_policy,
            ),
        });
        let built = built.transpose()?;
        // A session or query can only restrict the lifecycle's ceiling, never raise it,
        // so the ceiling is what was asked for: a longer deadline must not be cut to the
        // default without a word.
        let lifecycle = Arc::new(Lifecycle::new(ResourceLimits {
            max_threads: limits.max_threads.max(2),
            deadline_ms: limits.deadline_ms,
            ..ResourceLimits::default()
        })?);
        let snapshot_handle = lifecycle.register_snapshot(Arc::clone(&snapshot))?;
        let session = lifecycle.open_session(&snapshot_handle, limits)?;
        let (temp, layer_issues, layers, hostlab_provider) = match built {
            Some((bridge, layer_issues, layers, provider)) => (
                Some(TempSqlSession::new(
                    Arc::clone(&lifecycle),
                    session.clone(),
                    bridge,
                )?),
                layer_issues,
                layers,
                provider,
            ),
            None => (None, Vec::new(), None, None),
        };
        let lazy_decode = (0..dex_count).map(|_| OnceLock::new()).collect();
        Ok(Self {
            lifecycle,
            snapshot,
            snapshot_handle,
            session,
            temp,
            scope_id: scope.scope_id().to_owned(),
            dialect,
            non_scalar_text_policy,
            limits,
            layer_issues,
            dex_count,
            layers,
            hostlab_provider,
            lazy_decode,
            decode: OnceLock::new(),
            inventories,
            manifests: Mutex::new(HashMap::new()),
            resources: Mutex::new(crate::resources::ResourceCache::default()),
        })
    }

    fn native_bridge(
        snapshot: &Arc<Snapshot>,
        inventories: &[ArchiveInventory],
        sql_limits: SqlLimits,
    ) -> MddResult<SqlBridge> {
        let mut metadata = Vec::new();
        let mut definitions = Vec::new();
        for inventory in inventories {
            for local in 0..inventory.selected_dexes().len() {
                let facts = Arc::new(MetadataFacts::build(
                    snapshot,
                    inventory,
                    local,
                    StringLimits::default(),
                )?);
                definitions.push(Arc::new(DefinitionFacts::build_arc(
                    Arc::clone(&facts),
                    DefinitionLimits::default(),
                )?));
                metadata.push(facts);
            }
        }
        let epoch = DecimalU64(0);
        let provider = CombinedSqlProvider::new(
            Arc::new(MetadataSqlProvider::new(metadata, epoch)?),
            Arc::new(DefinitionSqlProvider::new(definitions, epoch)?),
        )?;
        SqlBridge::new(Arc::new(provider), SqlDialect::NativeV1, sql_limits)
    }

    /// The SQL front over the contract relations (and the public ones beyond them). The seventeen the HostLab queries read
    /// are filled in one pass over the DEX: each is built, the relations take their rows from it, and its layers are let
    /// go before the next is built. The other public relations are built when a statement first asks for one.
    fn contract_bridge(
        dialect: Dialect,
        snapshot: &Arc<Snapshot>,
        inventories: &Arc<Vec<ArchiveInventory>>,
        scope: &SelectedScope,
        sql_limits: SqlLimits,
        non_scalar_text_policy: NonScalarTextPolicy,
    ) -> MddResult<(
        SqlBridge,
        Vec<LayerIssue>,
        Option<Arc<LayerBuilder>>,
        Option<Arc<HostLabSqlProvider>>,
    )> {
        let layers = Arc::new(LayerBuilder::new(
            Arc::clone(snapshot),
            Arc::clone(inventories),
        ));
        let provider = Arc::new(
            HostLabSqlProvider::from_loader(
                scope,
                Arc::clone(&layers) as Arc<dyn OccurrenceLoader>,
                DecimalU64(0),
            )?
            .with_non_scalar_text_policy(non_scalar_text_policy),
        );
        // Metadata and definitions are the base of every relation, so a DEX that cannot build them fails the open. A layer
        // above them that cannot be built is not an error here: the relations that need it refuse with its error, and the
        // dataset names it in `layer_issues`.
        provider.prepare_required(None)?;
        let provider_handle = Arc::clone(&provider);
        let bridge = SqlBridge::new(provider, dialect.sql(), sql_limits)?;
        Ok((bridge, layers.issues(), Some(layers), Some(provider_handle)))
    }

    /// The session's SQL front, for callers that run TEMP definitions and windows. A dataset
    /// without DEX has none.
    pub fn temp(&self) -> MddResult<&TempSqlSession> {
        self.temp.as_ref().ok_or_else(no_dex)
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn bridge(&self) -> MddResult<&SqlBridge> {
        Ok(self.temp()?.bridge())
    }

    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// The input paths of the opened snapshot's sources are not repeated here; the
    /// number of selected DEX occurrences is.
    pub fn dex_count(&self) -> usize {
        self.dex_count
    }

    pub fn has_dex(&self) -> bool {
        self.dex_count > 0
    }

    /// The tools that read code (SQL, decode) refuse a dataset with none, in these words,
    /// so an empty result is never mistaken for "this archive has no such thing".
    pub fn require_dex(&self) -> MddResult<()> {
        if self.has_dex() {
            Ok(())
        } else {
            Err(no_dex())
        }
    }

    pub fn layer_issues(&self) -> &[LayerIssue] {
        &self.layer_issues
    }

    /// The facts of each DEX, in `file_id` order; empty for the native dialect. Built on the first call and kept.
    pub fn occurrences(&self) -> MddResult<&[Occurrence]> {
        self.decode
            .get_or_init(|| {
                let Some(layers) = &self.layers else {
                    return Ok(Vec::new());
                };
                if self.dex_count > 1 && self.limits.max_threads > 1 {
                    let workers = self.limits.max_threads.min(self.dex_count);
                    let next = std::sync::atomic::AtomicUsize::new(0);
                    let slots: Vec<Mutex<Option<MddResult<Occurrence>>>> =
                        (0..self.dex_count).map(|_| Mutex::new(None)).collect();
                    std::thread::scope(|scope| {
                        for _ in 0..workers {
                            scope.spawn(|| {
                                loop {
                                    let pos =
                                        next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    if pos >= self.dex_count {
                                        break;
                                    }
                                    let built = layers.occurrence(pos);
                                    if let Ok(mut guard) = slots[pos].lock() {
                                        *guard = Some(built);
                                    }
                                }
                            });
                        }
                    });
                    slots
                        .into_iter()
                        .map(|slot| {
                            slot.into_inner()
                                .map_err(|_| {
                                    MddError::new(
                                        ErrorCode::InternalFault,
                                        "service",
                                        "parallel decode worker panicked",
                                    )
                                })?
                                .unwrap_or_else(|| {
                                    Err(MddError::new(
                                        ErrorCode::InternalFault,
                                        "service",
                                        "parallel decode worker did not populate slot",
                                    ))
                                })
                        })
                        .collect::<MddResult<Vec<_>>>()
                } else {
                    (0..self.dex_count)
                        .map(|position| layers.occurrence(position))
                        .collect::<MddResult<Vec<_>>>()
                }
            })
            .as_deref()
            .map_err(Clone::clone)
    }

    pub(crate) fn has_decode_layers(&self) -> bool {
        self.layers.is_some()
    }

    pub(crate) fn hostlab_provider(&self) -> Option<&Arc<HostLabSqlProvider>> {
        self.hostlab_provider.as_ref()
    }

    pub(crate) fn layers(&self) -> Option<&Arc<LayerBuilder>> {
        self.layers.as_ref()
    }

    pub(crate) fn decode_dex(&self, file_id: u32) -> MddResult<&LazyDexDecode> {
        let position = usize::try_from(file_id).unwrap_or(usize::MAX);
        let slot = self.lazy_decode.get(position).ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "service.decode",
                "a located file_id vanished",
            )
        })?;
        let layers = self.layers.as_ref().ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "service.decode",
                "no decode layers on this dialect",
            )
        })?;
        slot.get_or_init(|| {
            let (metadata, definitions) = layers.build_base(position)?;
            Ok(LazyDexDecode::new(
                file_id,
                metadata,
                definitions,
                layers.code_validation(position),
                layers.annotations_validation(position),
            ))
        })
        .as_ref()
        .map_err(Clone::clone)
    }

    #[cfg(test)]
    pub(crate) fn loaded_decode_dex_count(&self) -> usize {
        self.lazy_decode
            .iter()
            .filter(|slot| slot.get().is_some())
            .count()
    }

    /// The bytes captured from all inputs: what the snapshot holds, not what a later
    /// `stat` of the paths would say.
    pub fn input_bytes(&self) -> u64 {
        self.snapshot
            .sources()
            .iter()
            .map(|source| source.bytes().len() as u64)
            .sum()
    }

    /// The positions, among the inputs as given, of those that are archives.
    pub fn archive_inputs(&self) -> Vec<usize> {
        self.snapshot
            .sources()
            .iter()
            .enumerate()
            .filter(|(_, source)| matches!(source.kind(), InputKind::Apk))
            .map(|(index, _)| index)
            .collect()
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot.manifest().snapshot_id
    }

    /// What `serve` prints first, and what `query` records about its dataset.
    pub fn description(&self) -> Value {
        let mut out = json!({
            "snapshot_id": self.snapshot_id(),
            "scope_id": self.scope_id,
            "profile": self.dialect.profile(),
            "sql_dialect": self.dialect.name(),
            "dex_count": self.dex_count,
            "layer_issues": self.layer_issues.iter().map(|issue| json!({
                "dex_occurrence_id": issue.dex_occurrence_id,
                "layers": issue.layers,
                "error": issue.error,
            })).collect::<Vec<_>>(),
        });
        if self.non_scalar_text_policy == NonScalarTextPolicy::LossyReplacement
            && let Some(obj) = out.as_object_mut()
        {
            obj.insert(
                "non_scalar_text_policy".to_owned(),
                json!(self.non_scalar_text_policy.as_str()),
            );
        }
        out
    }
}

fn no_dex() -> MddError {
    MddError::new(
        ErrorCode::InvalidInput,
        "service.dataset",
        "this dataset has resources but no DEX; query an input containing DEX",
    )
    .detail("dex_count", "0")
}

impl Drop for Dataset {
    fn drop(&mut self) {
        let _ = self.lifecycle.close_session(&self.session);
        let _ = self.lifecycle.release_session(&self.session);
        let _ = self.lifecycle.close_snapshot(&self.snapshot_handle);
        let _ = self.lifecycle.release_snapshot(&self.snapshot_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> InputRequest {
        InputRequest {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/definitions/generated/definitions-038.dex"),
            kind: None,
        }
    }

    #[test]
    fn a_deadline_above_the_default_is_the_deadline_the_session_runs_under() {
        let limits = ResourceLimits {
            deadline_ms: 900_000,
            ..ResourceLimits::default()
        };
        let dataset = Dataset::open(
            &[fixture()],
            Dialect::NativeV1,
            limits,
            SqlLimits::default(),
        )
        .unwrap();
        assert_eq!(dataset.limits.deadline_ms, 900_000);
        let session = dataset.lifecycle.session_limits(&dataset.session).unwrap();
        assert_eq!(
            session.deadline_ms, 900_000,
            "the lifecycle ceiling must not cut a longer deadline down to the default"
        );
    }

    #[test]
    fn the_sql_budgets_asked_for_are_the_ones_the_bridge_enforces() {
        let asked = SqlLimits {
            max_steps: 11,
            max_scanned_rows: 22,
            max_result_rows: 33,
            ..SqlLimits::default()
        };
        for dialect in [Dialect::NativeV1, Dialect::DexSql010] {
            let dataset =
                Dataset::open(&[fixture()], dialect, ResourceLimits::default(), asked).unwrap();
            let got = dataset.bridge().unwrap().limits();
            assert_eq!(
                (got.max_steps, got.max_scanned_rows, got.max_result_rows),
                (11, 22, 33),
                "{dialect:?}"
            );
        }
    }

    #[test]
    fn dialect_names_round_trip_and_unknown_names_are_refused() {
        for dialect in [Dialect::NativeV1, Dialect::DexSql010, Dialect::DexSql011] {
            assert_eq!(Dialect::parse(dialect.name()).unwrap(), dialect);
        }
        let error = Dialect::parse("sqlite").unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
}
