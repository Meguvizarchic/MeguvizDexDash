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
use crate::decode::{Occurrence, OccurrenceIndex};
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_facts::{
    DefinitionFacts, MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    indexes::SelectedScope,
    references::{ReferenceFacts, ReferenceLimits},
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
        hostlab::{HostLabOccurrenceFacts, HostLabSqlProvider},
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
    pub(crate) limits: ResourceLimits,
    layer_issues: Vec<LayerIssue>,
    dex_count: usize,
    /// The facts of each DEX, for `decode`. Empty for the native dialect.
    occurrences: Vec<Occurrence>,
    decode_indexes: OnceLock<Vec<OccurrenceIndex>>,
    /// One inventory per input, in the order given; `get_manifest` reads from them.
    pub(crate) inventories: Vec<ArchiveInventory>,
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
                    ..InventoryPolicy::default()
                },
                ArchiveLimits::default(),
            )?);
        }
        let refs: Vec<&ArchiveInventory> = inventories.iter().collect();
        let scope = SelectedScope::from_inventories(&snapshot, &refs)?;
        let dex_count: usize = inventories.iter().map(|i| i.selected_dexes().len()).sum();
        // No DEX, no SQL: the facts every relation reads do not exist, and an empty provider
        // would answer "no rows" where the truth is "nothing to ask".
        let built = (dex_count > 0).then(|| match dialect {
            Dialect::NativeV1 => Self::native_bridge(&snapshot, &inventories, sql_limits)
                .map(|bridge| (bridge, Vec::new(), Vec::new())),
            Dialect::DexSql010 | Dialect::DexSql011 => {
                Self::contract_bridge(dialect, &snapshot, &inventories, &scope, sql_limits)
            }
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
        let (temp, layer_issues, occurrences) = match built {
            Some((bridge, layer_issues, occurrences)) => (
                Some(TempSqlSession::new(
                    Arc::clone(&lifecycle),
                    session.clone(),
                    bridge,
                )?),
                layer_issues,
                occurrences,
            ),
            None => (None, Vec::new(), Vec::new()),
        };
        Ok(Self {
            lifecycle,
            snapshot,
            snapshot_handle,
            session,
            temp,
            scope_id: scope.scope_id().to_owned(),
            dialect,
            limits,
            layer_issues,
            dex_count,
            occurrences,
            decode_indexes: OnceLock::new(),
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

    fn contract_bridge(
        dialect: Dialect,
        snapshot: &Arc<Snapshot>,
        inventories: &[ArchiveInventory],
        scope: &SelectedScope,
        sql_limits: SqlLimits,
    ) -> MddResult<(SqlBridge, Vec<LayerIssue>, Vec<Occurrence>)> {
        let mut facts = Vec::new();
        let mut issues = Vec::new();
        let mut occurrences = Vec::new();
        for inventory in inventories {
            for local in 0..inventory.selected_dexes().len() {
                let occurrence = inventory.selected_dexes()[local].dex_occurrence_id.clone();
                // Metadata and definitions are the base of every relation: without
                // them there is nothing to answer from, so they are not optional.
                let metadata = Arc::new(MetadataFacts::build(
                    snapshot,
                    inventory,
                    local,
                    StringLimits::default(),
                )?);
                let definitions = Arc::new(DefinitionFacts::build_arc(
                    Arc::clone(&metadata),
                    DefinitionLimits::default(),
                )?);
                // The code layer is built first and kept on its own: a DEX whose references or
                // annotations cannot be validated can still show its instructions, and `decode`
                // must not lose every method body to a fault in one other layer.
                let code = CodeFacts::build_all_code_items(
                    snapshot,
                    inventory,
                    local,
                    CodeLimits::default(),
                )
                .map(Arc::new);
                let kept_code = code.as_ref().ok().cloned();
                // The annotation layer does not read the code or the references, so a fault in
                // those must not take annotations (and static values) away from `decode`.
                let annotation_layer =
                    AnnotationFacts::build((*definitions).clone(), AnnotationLimits::default())
                        .map(Arc::new);
                let upper = || -> MddResult<_> {
                    let code = Arc::clone(code.as_ref().map_err(Clone::clone)?);
                    let references = Arc::new(ReferenceFacts::build_arc(
                        Arc::clone(&definitions),
                        Arc::clone(&code),
                        ReferenceLimits::default(),
                    )?);
                    let annotations = Arc::clone(annotation_layer.as_ref().map_err(Clone::clone)?);
                    Ok((code, references, annotations))
                };
                let file_id = u32::try_from(facts.len()).map_err(|_| {
                    MddError::new(ErrorCode::QuotaExceeded, "service", "too many DEX files")
                })?;
                let upper_result = upper();
                // The annotation layer is kept beside the code: a text shows annotations when
                // it is built and says so when it is not.
                let kept_annotations = annotation_layer.as_ref().ok().map(Arc::clone);
                occurrences.push(Occurrence {
                    file_id,
                    metadata: Arc::clone(&metadata),
                    definitions: Arc::clone(&definitions),
                    code: kept_code,
                    annotations: kept_annotations,
                });
                match upper_result {
                    Ok((code, references, annotations)) => {
                        facts.push(HostLabOccurrenceFacts::complete(
                            metadata,
                            definitions,
                            code,
                            references,
                            annotations,
                        ));
                    }
                    Err(error) => {
                        issues.push(LayerIssue {
                            dex_occurrence_id: occurrence,
                            layers: "code,references,annotations",
                            error,
                        });
                        facts.push(HostLabOccurrenceFacts::structural(metadata, definitions));
                    }
                }
            }
        }
        let provider = HostLabSqlProvider::from_scope(scope, facts, DecimalU64(0))?;
        let bridge = SqlBridge::new(Arc::new(provider), dialect.sql(), sql_limits)?;
        Ok((bridge, issues, occurrences))
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

    /// The facts of each DEX, in `file_id` order; empty for the native dialect.
    pub fn occurrences(&self) -> &[Occurrence] {
        &self.occurrences
    }

    /// Built on the first decode, once.
    pub(crate) fn decode_indexes(&self) -> &[OccurrenceIndex] {
        self.decode_indexes.get_or_init(|| {
            self.occurrences
                .iter()
                .map(OccurrenceIndex::build)
                .collect()
        })
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
        json!({
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
        })
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
