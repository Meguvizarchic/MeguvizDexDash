//! Session-local TEMP definition catalog: names, dependency graph and generations.
//!
//! The catalog stores names, kinds, dependency names and definition fingerprints
//! only. It never parses SQL and never materializes a relation. A
//! `CREATE TEMP TABLE ... AS SELECT` definition is executed by the SQL layer,
//! which supplies an opaque, hash-bound materialization handle through
//! [`TempCatalog::inject_materialization`]. Until that injection the definition
//! stays [`TempMaterialization::Deferred`] and must not be used for execution.
//!
//! Dependency names are rebound at query time against the query's frozen
//! catalog generation: publishing a definition validates every dependency
//! against the catalog that exists at that moment (no forward references), while
//! an already published definition keeps resolving through the names visible to
//! the query that captured it.

use crate::{Lifecycle, QueryHandle, QueryPhase, SessionHandle};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Catalog object kind. A `TABLE` and a `VIEW` with the same name are two
/// distinct definitions for `DROP` purposes even though they share one name slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TempKind {
    Table,
    View,
}

impl TempKind {
    pub fn keyword(self) -> &'static str {
        match self {
            Self::Table => "TABLE",
            Self::View => "VIEW",
        }
    }
}

/// Where the rows of a definition come from. The session catalog never
/// materializes; the SQL layer hands over a handle bound to the definition hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TempMaterialization {
    /// `AS SELECT` definition accepted but not yet executed by the SQL layer.
    Deferred,
    /// SQL layer supplied an opaque handle for exactly this definition hash.
    Injected { handle: String },
}

/// One published definition plus the generation window in which it is visible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TempDefinition {
    pub name: String,
    pub kind: TempKind,
    /// Fingerprint of the normalized definition (AST plus bound relation names).
    pub definition_hash: String,
    /// Relations this definition references, by name.
    pub dependencies: Vec<String>,
    /// Catalog epoch at which the definition was published.
    pub epoch: u64,
    /// First epoch at which this definition stopped being current.
    pub retired_epoch: Option<u64>,
    pub materialization: TempMaterialization,
}

/// A create request as produced by the SQL layer after parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateTempDefinition {
    pub name: String,
    pub kind: TempKind,
    pub definition_hash: String,
    pub dependencies: Vec<String>,
    pub materialization: TempMaterialization,
}

/// Result of a successful catalog mutation. `Unchanged` and `Absent` are
/// successful no-ops that do not advance the epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum TempCatalogChange {
    Created {
        name: String,
        kind: TempKind,
        epoch: DecimalU64,
    },
    Replaced {
        name: String,
        kind: TempKind,
        previous_kind: TempKind,
        epoch: DecimalU64,
    },
    Injected {
        name: String,
        kind: TempKind,
        epoch: DecimalU64,
    },
    Dropped {
        name: String,
        kind: TempKind,
        epoch: DecimalU64,
    },
    /// `IF NOT EXISTS` found the name already present; the new body is ignored.
    Unchanged {
        name: String,
        kind: TempKind,
        epoch: DecimalU64,
    },
    /// `DROP ... IF EXISTS` found nothing to drop.
    Absent { name: String, epoch: DecimalU64 },
}

/// A definition resolved for one query generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TempRelationBinding {
    pub name: String,
    pub kind: TempKind,
    pub definition_hash: String,
}

/// Immutable TEMP resolution captured when a query is prepared.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TempBinding {
    pub catalog_epoch: DecimalU64,
    pub relations: Vec<TempRelationBinding>,
}

/// Per-session catalog. Retired definitions stay addressable through
/// [`TempCatalog::resolve_at`] so that a query prepared before a redefinition
/// keeps reading exactly the definition it bound.
#[derive(Clone, Debug, Default)]
pub struct TempCatalog {
    current: BTreeMap<String, TempDefinition>,
    retired: Vec<TempDefinition>,
    epoch: u64,
}

impl TempCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Current definition for `name`, regardless of generation.
    pub fn resolve(&self, name: &str) -> Option<&TempDefinition> {
        self.current.get(name)
    }

    /// Definition visible to a query prepared at `epoch`.
    ///
    /// A definition published at epoch `N` is visible from `N` on; a definition
    /// retired at epoch `M` is visible only before `M`. A query never observes a
    /// definition published after its own generation.
    pub fn resolve_at(&self, name: &str, epoch: u64) -> Option<&TempDefinition> {
        if let Some(current) = self.current.get(name)
            && current.epoch <= epoch
        {
            return Some(current);
        }
        self.retired.iter().rev().find(|definition| {
            definition.name == name
                && definition.epoch <= epoch
                && definition
                    .retired_epoch
                    .is_some_and(|retired| retired > epoch)
        })
    }

    /// Every live definition, ordered by name.
    pub fn definitions(&self) -> Vec<TempDefinition> {
        self.current.values().cloned().collect()
    }

    /// Generation-only advance used by the session's `advance_catalog`.
    pub(crate) fn advance(&mut self) -> MddResult<u64> {
        self.bump()
    }

    pub fn create(
        &mut self,
        request: CreateTempDefinition,
        if_not_exists: bool,
    ) -> MddResult<TempCatalogChange> {
        validate_name(&request.name)?;
        validate_hash(&request.definition_hash)?;
        validate_dependency_list(&request.name, &request.dependencies)?;
        if let Some(existing) = self.current.get(&request.name) {
            if if_not_exists {
                // The observed reference engine ignores the whole new body on
                // this branch, including unknown names inside it.
                return Ok(TempCatalogChange::Unchanged {
                    name: request.name,
                    kind: existing.kind,
                    epoch: DecimalU64(self.epoch),
                });
            }
            let previous_kind = existing.kind;
            self.validate_dependencies(&request)?;
            let epoch = self.bump()?;
            let mut replaced = self.current.remove(&request.name).unwrap();
            replaced.retired_epoch = Some(epoch);
            self.retired.push(replaced);
            self.current.insert(
                request.name.clone(),
                TempDefinition {
                    name: request.name.clone(),
                    kind: request.kind,
                    definition_hash: request.definition_hash,
                    dependencies: request.dependencies,
                    epoch,
                    retired_epoch: None,
                    materialization: request.materialization,
                },
            );
            return Ok(TempCatalogChange::Replaced {
                name: request.name,
                kind: request.kind,
                previous_kind,
                epoch: DecimalU64(epoch),
            });
        }
        self.validate_dependencies(&request)?;
        let epoch = self.bump()?;
        self.current.insert(
            request.name.clone(),
            TempDefinition {
                name: request.name.clone(),
                kind: request.kind,
                definition_hash: request.definition_hash,
                dependencies: request.dependencies,
                epoch,
                retired_epoch: None,
                materialization: request.materialization,
            },
        );
        Ok(TempCatalogChange::Created {
            name: request.name,
            kind: request.kind,
            epoch: DecimalU64(epoch),
        })
    }

    /// Inject the SQL layer's materialization handle for a deferred definition.
    /// The handle is bound to the exact definition hash so a redefinition cannot
    /// receive the previous body's rows.
    pub fn inject_materialization(
        &mut self,
        name: &str,
        definition_hash: &str,
        handle: String,
    ) -> MddResult<TempCatalogChange> {
        if handle.is_empty() {
            return Err(invalid("temp materialization handle must be nonempty"));
        }
        let existing = self
            .current
            .get(name)
            .ok_or_else(|| missing_relation(name, TempKind::Table))?;
        if existing.definition_hash != definition_hash {
            return Err(catalog_error(
                "definition_changed",
                "temp definition changed before materialization was injected",
            )
            .detail("relation", name.to_owned())
            .detail("expected_hash", existing.definition_hash.clone())
            .detail("supplied_hash", definition_hash.to_owned()));
        }
        if !matches!(existing.materialization, TempMaterialization::Deferred) {
            return Err(catalog_error(
                "already_materialized",
                "temp definition already has a materialization handle",
            )
            .detail("relation", name.to_owned()));
        }
        let kind = existing.kind;
        let epoch = self.bump()?;
        let definition = self.current.get_mut(name).unwrap();
        definition.materialization = TempMaterialization::Injected { handle };
        Ok(TempCatalogChange::Injected {
            name: name.to_owned(),
            kind,
            epoch: DecimalU64(epoch),
        })
    }

    /// `expected_kind` is the keyword used in the `DROP` statement. A mismatch is
    /// an error even with `IF EXISTS`: the reference engine never swallows it.
    pub fn drop(
        &mut self,
        name: &str,
        expected_kind: TempKind,
        if_exists: bool,
    ) -> MddResult<TempCatalogChange> {
        validate_name(name)?;
        let Some(existing) = self.current.get(name) else {
            if if_exists {
                return Ok(TempCatalogChange::Absent {
                    name: name.to_owned(),
                    epoch: DecimalU64(self.epoch),
                });
            }
            return Err(missing_relation(name, expected_kind));
        };
        if existing.kind != expected_kind {
            return Err(catalog_error(
                "drop_kind_mismatch",
                format!("use DROP {} to delete item", existing.kind.keyword()),
            )
            .detail("relation", name.to_owned())
            .detail("definition_kind", kind_name(existing.kind))
            .detail("drop_kind", kind_name(expected_kind)));
        }
        let kind = existing.kind;
        let epoch = self.bump()?;
        let mut dropped = self.current.remove(name).unwrap();
        dropped.retired_epoch = Some(epoch);
        self.retired.push(dropped);
        Ok(TempCatalogChange::Dropped {
            name: name.to_owned(),
            kind,
            epoch: DecimalU64(epoch),
        })
    }

    fn validate_dependencies(&self, request: &CreateTempDefinition) -> MddResult<()> {
        let mut graph: BTreeMap<String, Vec<String>> = self
            .current
            .iter()
            .filter(|(name, _)| name.as_str() != request.name)
            .map(|(name, definition)| (name.clone(), definition.dependencies.clone()))
            .collect();
        graph.insert(request.name.clone(), request.dependencies.clone());
        for dependency in &request.dependencies {
            if self.resolve(dependency).is_none() {
                return Err(catalog_error(
                    "unknown_relation",
                    format!("unknown relation `{dependency}`"),
                )
                .detail("relation", request.name.clone())
                .detail("dependency", dependency.clone()));
            }
        }
        for dependency in &request.dependencies {
            if dependency == &request.name {
                return Err(cycle_error(
                    request,
                    &[request.name.clone(), request.name.clone()],
                ));
            }
            if let Some(path) = reaches(&graph, dependency, &request.name) {
                let mut cycle = vec![request.name.clone()];
                cycle.extend(path);
                return Err(cycle_error(request, &cycle));
            }
        }
        Ok(())
    }

    fn bump(&mut self) -> MddResult<u64> {
        self.epoch = self.epoch.checked_add(1).ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "catalog",
                "catalog epoch exhausted",
            )
        })?;
        Ok(self.epoch)
    }
}

fn reaches(
    graph: &BTreeMap<String, Vec<String>>,
    start: &str,
    target: &str,
) -> Option<Vec<String>> {
    let mut stack = vec![(start.to_owned(), vec![start.to_owned()])];
    let mut visited = BTreeSet::new();
    while let Some((node, path)) = stack.pop() {
        if !visited.insert(node.clone()) {
            continue;
        }
        let Some(edges) = graph.get(&node) else {
            continue;
        };
        for edge in edges {
            if edge == target {
                let mut cycle = path.clone();
                cycle.push(target.to_owned());
                return Some(cycle);
            }
            if !visited.contains(edge) {
                let mut next = path.clone();
                next.push(edge.clone());
                stack.push((edge.clone(), next));
            }
        }
    }
    None
}

fn validate_name(name: &str) -> MddResult<()> {
    if name.is_empty()
        || name.len() > 128
        || name
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid(
            "temp relation name must be a single nonempty identifier",
        ));
    }
    Ok(())
}

fn validate_hash(hash: &str) -> MddResult<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "temp definition hash must be a lowercase SHA-256 hex digest",
        ));
    }
    Ok(())
}

fn validate_dependency_list(name: &str, dependencies: &[String]) -> MddResult<()> {
    let mut seen = BTreeSet::new();
    for dependency in dependencies {
        validate_name(dependency)?;
        if dependency == name {
            return Err(catalog_error("cycle", "temp definition depends on itself")
                .detail("relation", name.to_owned())
                .detail("path", format!("{name} -> {name}")));
        }
        if !seen.insert(dependency) {
            return Err(invalid("temp dependency list contains a duplicate name")
                .detail("relation", name.to_owned())
                .detail("dependency", dependency.clone()));
        }
    }
    Ok(())
}

fn kind_name(kind: TempKind) -> String {
    kind.keyword().to_ascii_lowercase()
}

fn invalid(reason: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "catalog", reason)
}

fn catalog_error(temp_error: &str, message: impl Into<String>) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "catalog", message).detail("temp_error", temp_error)
}

fn cycle_error(request: &CreateTempDefinition, path: &[String]) -> MddError {
    catalog_error("cycle", "temp definition introduces a dependency cycle")
        .detail("relation", request.name.clone())
        .detail("path", path.join(" -> "))
}

fn missing_relation(name: &str, kind: TempKind) -> MddError {
    MddError::new(
        ErrorCode::InvalidArgument,
        "catalog",
        format!("no such {}: {name}", kind_name(kind)),
    )
    .detail("temp_error", "no_such_relation")
    .detail("relation", name.to_owned())
    .detail("definition_kind", kind_name(kind))
}

fn internal(reason: &str) -> MddError {
    MddError::new(ErrorCode::InternalFault, "catalog", reason)
}

impl Lifecycle {
    /// Publish (or replace, or ignore under `IF NOT EXISTS`) a TEMP definition in
    /// this session's catalog. A successful mutation advances the session's
    /// catalog epoch in the same lifecycle lock.
    pub fn temp_catalog_create(
        &self,
        session: &SessionHandle,
        request: CreateTempDefinition,
        if_not_exists: bool,
    ) -> MddResult<TempCatalogChange> {
        let mut state = self.lock()?;
        state.active_session(session)?;
        let entry = state.sessions.get_mut(session.id()).unwrap();
        entry.temp.create(request, if_not_exists)
    }

    pub fn temp_catalog_inject(
        &self,
        session: &SessionHandle,
        name: &str,
        definition_hash: &str,
        handle: String,
    ) -> MddResult<TempCatalogChange> {
        let mut state = self.lock()?;
        state.active_session(session)?;
        let entry = state.sessions.get_mut(session.id()).unwrap();
        entry
            .temp
            .inject_materialization(name, definition_hash, handle)
    }

    pub fn temp_catalog_drop(
        &self,
        session: &SessionHandle,
        name: &str,
        expected_kind: TempKind,
        if_exists: bool,
    ) -> MddResult<TempCatalogChange> {
        let mut state = self.lock()?;
        state.active_session(session)?;
        let entry = state.sessions.get_mut(session.id()).unwrap();
        entry.temp.drop(name, expected_kind, if_exists)
    }

    pub fn temp_catalog_resolve(
        &self,
        session: &SessionHandle,
        name: &str,
    ) -> MddResult<Option<TempDefinition>> {
        let state = self.lock()?;
        Ok(state.active_session(session)?.temp.resolve(name).cloned())
    }

    pub fn temp_catalog_resolve_at(
        &self,
        session: &SessionHandle,
        name: &str,
        epoch: DecimalU64,
    ) -> MddResult<Option<TempDefinition>> {
        let state = self.lock()?;
        Ok(state
            .active_session(session)?
            .temp
            .resolve_at(name, epoch.0)
            .cloned())
    }

    pub fn temp_catalog_epoch(&self, session: &SessionHandle) -> MddResult<DecimalU64> {
        let state = self.lock()?;
        Ok(DecimalU64(state.active_session(session)?.temp.epoch()))
    }

    pub fn temp_catalog_definitions(
        &self,
        session: &SessionHandle,
    ) -> MddResult<Vec<TempDefinition>> {
        let state = self.lock()?;
        Ok(state.active_session(session)?.temp.definitions())
    }

    /// Capture the TEMP resolution for a query that has not started yet. The
    /// query keeps this generation even after later catalog mutations; a name
    /// published after prepare is not visible to it.
    pub fn bind_query_temp(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
        names: &[String],
    ) -> MddResult<TempBinding> {
        let mut state = self.lock_query(query)?;
        state.owned_query(session, query)?;
        let mut seen = BTreeSet::new();
        let mut relations = Vec::new();
        let epoch = {
            let entry = state.query(query)?;
            if entry.status.phase != QueryPhase::Prepared {
                return Err(invalid("TEMP binding requires a prepared query"));
            }
            let session_entry = state
                .sessions
                .get(&entry.session_id)
                .ok_or_else(|| internal("query owning session is absent"))?;
            let mut requested = BTreeSet::new();
            let mut pending: std::collections::VecDeque<(String, Option<String>)> =
                std::collections::VecDeque::new();
            for name in names {
                if !requested.insert(name.clone()) {
                    return Err(invalid("TEMP binding names contain a duplicate"));
                }
                pending.push_back((name.clone(), None));
            }
            // A definition is bound together with everything it depends on, at the
            // query's own generation. Binding only the names written in the SQL
            // would leave the tables behind a view outside the stored binding, and
            // a later redefinition of one of them could not be told apart from the
            // generation the query actually saw.
            while let Some((name, via)) = pending.pop_front() {
                if !seen.insert(name.clone()) {
                    continue;
                }
                let definition = session_entry
                    .temp
                    .resolve_at(&name, entry.status.catalog_epoch.0)
                    .ok_or_else(|| {
                        let mut error = catalog_error(
                            "unknown_relation",
                            format!("unknown relation `{name}` at the query's catalog generation"),
                        )
                        .detail("relation", name.clone())
                        .detail("catalog_epoch", entry.status.catalog_epoch.0.to_string());
                        if let Some(via) = &via {
                            error = error.detail("required_by", via.clone());
                        }
                        error
                    })?;
                relations.push(TempRelationBinding {
                    name: definition.name.clone(),
                    kind: definition.kind,
                    definition_hash: definition.definition_hash.clone(),
                });
                for dependency in &definition.dependencies {
                    pending.push_back((dependency.clone(), Some(name.clone())));
                }
            }
            entry.status.catalog_epoch
        };
        let binding = TempBinding {
            catalog_epoch: epoch,
            relations,
        };
        state.queries.get_mut(query.id()).unwrap().temp_binding = Some(binding.clone());
        Ok(binding)
    }

    pub fn query_temp_binding(&self, query: &QueryHandle) -> MddResult<Option<TempBinding>> {
        Ok(self
            .lock_query_read(query)?
            .query(query)?
            .temp_binding
            .clone())
    }

    /// Re-resolve the stored binding against the session catalog at the query's
    /// own generation. This must equal the stored binding; a mismatch means the
    /// catalog lost a retained generation, not that the query migrated.
    pub fn verify_query_temp_binding(&self, query: &QueryHandle) -> MddResult<TempBinding> {
        let state = self.lock_query_read(query)?;
        let entry = state.query(query)?;
        let stored = entry
            .temp_binding
            .clone()
            .ok_or_else(|| invalid("query has no TEMP binding"))?;
        let session_entry = state
            .sessions
            .get(&entry.session_id)
            .ok_or_else(|| internal("query owning session is absent"))?;
        for relation in &stored.relations {
            let current = session_entry
                .temp
                .resolve_at(&relation.name, stored.catalog_epoch.0)
                .ok_or_else(|| internal("temp catalog lost a retained generation"))?;
            if current.kind != relation.kind || current.definition_hash != relation.definition_hash
            {
                return Err(internal(
                    "temp catalog rewrote the definition bound by an existing query",
                ));
            }
        }
        Ok(stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lifecycle, QueryBinding, ResourceLimits};
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn definition(name: &str, kind: TempKind, dependencies: &[&str]) -> CreateTempDefinition {
        let dependencies: Vec<String> = dependencies
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
        CreateTempDefinition {
            name: name.to_owned(),
            kind,
            definition_hash: mdd_types::sha256(
                format!("{name}:{kind:?}:{dependencies:?}").as_bytes(),
            ),
            dependencies,
            materialization: TempMaterialization::Deferred,
        }
    }

    fn snapshot() -> Arc<Snapshot> {
        Arc::new(
            Snapshot::capture(
                &[InputSpec {
                    path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../tests/fixtures/generated/minimal-035.dex"),
                    kind: InputKind::RawDex,
                    expected_sha256: None,
                }],
                CaptureLimits::default(),
            )
            .unwrap(),
        )
    }

    fn sessions(count: usize) -> (Lifecycle, Vec<SessionHandle>) {
        let runtime = Lifecycle::new(ResourceLimits::default()).unwrap();
        let snapshot = runtime.register_snapshot(snapshot()).unwrap();
        let sessions = (0..count)
            .map(|_| {
                runtime
                    .open_session(&snapshot, ResourceLimits::default())
                    .unwrap()
            })
            .collect();
        (runtime, sessions)
    }

    fn binding() -> QueryBinding {
        QueryBinding {
            request_key: "request-content-hash".to_owned(),
            schema_id: "catalog-schema".to_owned(),
            semantic_version: "catalog-v1".to_owned(),
        }
    }

    #[test]
    fn create_publishes_names_and_binds_generations() {
        let mut catalog = TempCatalog::new();
        assert!(catalog.definitions().is_empty());
        let created = catalog
            .create(definition("base", TempKind::Table, &[]), false)
            .unwrap();
        assert_eq!(
            created,
            TempCatalogChange::Created {
                name: "base".into(),
                kind: TempKind::Table,
                epoch: DecimalU64(1)
            }
        );
        assert_eq!(catalog.epoch(), 1);
        let dependent = definition("derived", TempKind::View, &["base"]);
        let hash = dependent.definition_hash.clone();
        assert_eq!(
            catalog.create(dependent, false).unwrap(),
            TempCatalogChange::Created {
                name: "derived".into(),
                kind: TempKind::View,
                epoch: DecimalU64(2)
            }
        );
        assert_eq!(catalog.definitions().len(), 2);
        // The dependent name is invisible before its own generation.
        assert!(catalog.resolve_at("derived", 1).is_none());
        assert_eq!(
            catalog.resolve_at("derived", 2).unwrap().definition_hash,
            hash
        );
        assert!(catalog.resolve("derived").is_some());
    }

    #[test]
    fn cycle_and_self_reference_are_rejected_without_advancing_the_epoch() {
        let mut catalog = TempCatalog::new();
        catalog
            .create(definition("a", TempKind::Table, &[]), false)
            .unwrap();
        catalog
            .create(definition("b", TempKind::Table, &["a"]), false)
            .unwrap();
        let epoch = catalog.epoch();
        let original = catalog.resolve("a").unwrap().definition_hash.clone();
        let cycle = catalog
            .create(definition("a", TempKind::Table, &["b"]), false)
            .unwrap_err();
        assert_eq!(cycle.code, ErrorCode::InvalidArgument);
        assert_eq!(cycle.details["temp_error"], "cycle");
        assert_eq!(cycle.details["path"], "a -> b -> a");
        assert_eq!(catalog.epoch(), epoch);
        assert_eq!(catalog.resolve("a").unwrap().definition_hash, original);
        assert_eq!(
            catalog.resolve("a").unwrap().dependencies,
            Vec::<String>::new()
        );

        let self_cycle = catalog
            .create(definition("c", TempKind::View, &["c"]), false)
            .unwrap_err();
        assert_eq!(self_cycle.details["temp_error"], "cycle");
        assert_eq!(catalog.epoch(), epoch);
        assert!(catalog.resolve("c").is_none());
    }

    #[test]
    fn if_not_exists_keeps_the_original_definition_and_ignores_the_new_body() {
        let mut catalog = TempCatalog::new();
        let first = definition("t", TempKind::Table, &[]);
        let original = first.definition_hash.clone();
        catalog.create(first, false).unwrap();
        let epoch = catalog.epoch();
        // The oracle ignores the whole body on this branch, including a name that
        // does not exist and a different kind.
        let ignored = catalog
            .create(definition("t", TempKind::View, &["never_defined"]), true)
            .unwrap();
        assert_eq!(
            ignored,
            TempCatalogChange::Unchanged {
                name: "t".into(),
                kind: TempKind::Table,
                epoch: DecimalU64(epoch)
            }
        );
        assert_eq!(catalog.epoch(), epoch);
        let current = catalog.resolve("t").unwrap();
        assert_eq!(current.kind, TempKind::Table);
        assert_eq!(current.definition_hash, original);
    }

    #[test]
    fn redefine_replaces_kind_and_drop_requires_the_matching_kind() {
        let mut catalog = TempCatalog::new();
        catalog
            .create(definition("t", TempKind::Table, &[]), false)
            .unwrap();
        let replaced = catalog
            .create(definition("t", TempKind::View, &[]), false)
            .unwrap();
        assert_eq!(
            replaced,
            TempCatalogChange::Replaced {
                name: "t".into(),
                kind: TempKind::View,
                previous_kind: TempKind::Table,
                epoch: DecimalU64(2)
            }
        );
        assert_eq!(catalog.resolve("t").unwrap().kind, TempKind::View);
        let epoch = catalog.epoch();
        for if_exists in [false, true] {
            let mismatch = catalog.drop("t", TempKind::Table, if_exists).unwrap_err();
            assert_eq!(mismatch.code, ErrorCode::InvalidArgument);
            assert_eq!(mismatch.details["temp_error"], "drop_kind_mismatch");
            assert_eq!(mismatch.message, "use DROP VIEW to delete item");
            assert_eq!(catalog.epoch(), epoch);
            assert!(catalog.resolve("t").is_some());
        }
        assert_eq!(
            catalog.drop("t", TempKind::View, false).unwrap(),
            TempCatalogChange::Dropped {
                name: "t".into(),
                kind: TempKind::View,
                epoch: DecimalU64(3)
            }
        );
        assert!(catalog.resolve("t").is_none());
        // The retired definition is still addressable for an older generation.
        assert!(catalog.resolve_at("t", 2).is_some());
        assert!(catalog.resolve_at("t", 3).is_none());
    }

    #[test]
    fn drop_of_an_absent_name_reports_the_kind_and_if_exists_is_a_noop() {
        let mut catalog = TempCatalog::new();
        let table = catalog.drop("absent", TempKind::Table, false).unwrap_err();
        assert_eq!(table.message, "no such table: absent");
        assert_eq!(table.details["temp_error"], "no_such_relation");
        let view = catalog.drop("absent", TempKind::View, false).unwrap_err();
        assert_eq!(view.message, "no such view: absent");
        for kind in [TempKind::Table, TempKind::View] {
            assert_eq!(
                catalog.drop("absent", kind, true).unwrap(),
                TempCatalogChange::Absent {
                    name: "absent".into(),
                    epoch: DecimalU64(0)
                }
            );
        }
        assert_eq!(catalog.epoch(), 0);
    }

    #[test]
    fn forward_reference_is_rejected_and_the_definition_is_not_published() {
        let mut catalog = TempCatalog::new();
        let error = catalog
            .create(definition("derived", TempKind::View, &["future"]), false)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.message, "unknown relation `future`");
        assert_eq!(error.details["temp_error"], "unknown_relation");
        assert_eq!(catalog.epoch(), 0);
        assert!(catalog.resolve("derived").is_none());
        // Publishing the name later does not resurrect the failed definition.
        catalog
            .create(definition("future", TempKind::Table, &[]), false)
            .unwrap();
        assert!(catalog.resolve("derived").is_none());
    }

    #[test]
    fn as_select_stays_deferred_until_the_sql_layer_injects_a_matching_handle() {
        let mut catalog = TempCatalog::new();
        let request = definition("materialized", TempKind::Table, &[]);
        let hash = request.definition_hash.clone();
        catalog.create(request, false).unwrap();
        assert_eq!(
            catalog.resolve("materialized").unwrap().materialization,
            TempMaterialization::Deferred
        );
        let wrong = catalog
            .inject_materialization("materialized", &mdd_types::sha256(b"other"), "h".into())
            .unwrap_err();
        assert_eq!(wrong.details["temp_error"], "definition_changed");
        assert_eq!(
            catalog
                .inject_materialization("materialized", &hash, "handle-1".into())
                .unwrap(),
            TempCatalogChange::Injected {
                name: "materialized".into(),
                kind: TempKind::Table,
                epoch: DecimalU64(2)
            }
        );
        assert_eq!(
            catalog.resolve("materialized").unwrap().materialization,
            TempMaterialization::Injected {
                handle: "handle-1".into()
            }
        );
        let repeated = catalog
            .inject_materialization("materialized", &hash, "handle-2".into())
            .unwrap_err();
        assert_eq!(repeated.details["temp_error"], "already_materialized");
        // A redefinition is a new object: the old handle cannot be reused.
        catalog
            .create(definition("materialized", TempKind::Table, &[]), false)
            .unwrap();
        assert_eq!(
            catalog.resolve("materialized").unwrap().materialization,
            TempMaterialization::Deferred
        );
    }

    #[test]
    fn catalog_is_session_local_and_generations_do_not_leak() {
        let (runtime, sessions) = sessions(2);
        let (first, second) = (&sessions[0], &sessions[1]);
        runtime
            .temp_catalog_create(first, definition("local", TempKind::Table, &[]), false)
            .unwrap();
        assert_eq!(runtime.temp_catalog_epoch(first).unwrap(), DecimalU64(1));
        assert!(
            runtime
                .temp_catalog_resolve(first, "local")
                .unwrap()
                .is_some()
        );
        assert!(
            runtime
                .temp_catalog_resolve(second, "local")
                .unwrap()
                .is_none()
        );
        assert_eq!(runtime.temp_catalog_epoch(second).unwrap(), DecimalU64(0));
        // The same name is free in the other session.
        runtime
            .temp_catalog_create(second, definition("local", TempKind::View, &[]), false)
            .unwrap();
        runtime
            .temp_catalog_drop(first, "local", TempKind::Table, false)
            .unwrap();
        assert!(
            runtime
                .temp_catalog_resolve(first, "local")
                .unwrap()
                .is_none()
        );
        let other = runtime
            .temp_catalog_resolve(second, "local")
            .unwrap()
            .unwrap();
        assert_eq!(other.kind, TempKind::View);
        assert_eq!(runtime.temp_catalog_definitions(second).unwrap().len(), 1);
    }

    #[test]
    fn prepared_query_keeps_its_temp_generation_after_a_redefinition() {
        let (runtime, sessions) = sessions(1);
        let session = &sessions[0];
        runtime
            .temp_catalog_create(session, definition("t", TempKind::Table, &[]), false)
            .unwrap();
        let old_hash = runtime
            .temp_catalog_resolve(session, "t")
            .unwrap()
            .unwrap()
            .definition_hash;
        let query = runtime
            .prepare_query(session, binding(), ResourceLimits::default())
            .unwrap();
        let bound = runtime
            .bind_query_temp(session, &query, &["t".to_owned()])
            .unwrap();
        assert_eq!(bound.catalog_epoch, DecimalU64(1));
        assert_eq!(bound.relations[0].definition_hash, old_hash);
        // Binding is a prepare-time action only.
        runtime.start_query(session, &query, 1).unwrap();
        assert_eq!(
            runtime
                .bind_query_temp(session, &query, &["t".to_owned()])
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );

        runtime
            .temp_catalog_create(session, definition("t", TempKind::View, &[]), false)
            .unwrap();
        let new_hash = runtime
            .temp_catalog_resolve(session, "t")
            .unwrap()
            .unwrap()
            .definition_hash;
        assert_ne!(old_hash, new_hash);
        let verified = runtime.verify_query_temp_binding(&query).unwrap();
        assert_eq!(verified.relations[0].definition_hash, old_hash);
        assert_eq!(verified.relations[0].kind, TempKind::Table);
        assert_eq!(
            runtime
                .query_temp_binding(&query)
                .unwrap()
                .unwrap()
                .relations[0]
                .definition_hash,
            old_hash
        );
        assert_eq!(
            runtime
                .temp_catalog_resolve_at(session, "t", DecimalU64(1))
                .unwrap()
                .unwrap()
                .definition_hash,
            old_hash
        );
        // A new query sees the new generation; it is not an implicit migration of
        // the old query's binding.
        let fresh = runtime
            .prepare_query(session, binding(), ResourceLimits::default())
            .unwrap();
        assert_eq!(
            runtime.query_status(&fresh).unwrap().catalog_epoch,
            DecimalU64(2)
        );
        let fresh_binding = runtime
            .bind_query_temp(session, &fresh, &["t".to_owned()])
            .unwrap();
        assert_eq!(fresh_binding.relations[0].definition_hash, new_hash);
        assert_eq!(fresh_binding.relations[0].kind, TempKind::View);
    }

    #[test]
    fn drop_retains_the_generation_an_existing_query_already_bound() {
        let (runtime, sessions) = sessions(1);
        let session = &sessions[0];
        runtime
            .temp_catalog_create(session, definition("t", TempKind::View, &[]), false)
            .unwrap();
        let query = runtime
            .prepare_query(session, binding(), ResourceLimits::default())
            .unwrap();
        runtime
            .bind_query_temp(session, &query, &["t".to_owned()])
            .unwrap();
        runtime
            .temp_catalog_drop(session, "t", TempKind::View, false)
            .unwrap();
        assert!(
            runtime
                .temp_catalog_resolve(session, "t")
                .unwrap()
                .is_none()
        );
        // The prepared query's generation still resolves; a new generation does not.
        assert!(runtime.verify_query_temp_binding(&query).is_ok());
        let next = runtime
            .prepare_query(session, binding(), ResourceLimits::default())
            .unwrap();
        let error = runtime
            .bind_query_temp(session, &next, &["t".to_owned()])
            .unwrap_err();
        assert_eq!(error.details["temp_error"], "unknown_relation");
    }

    #[test]
    fn binding_a_view_binds_the_tables_behind_it_at_the_query_generation() {
        let (runtime, sessions) = sessions(1);
        let session = &sessions[0];
        runtime
            .temp_catalog_create(session, definition("base", TempKind::Table, &[]), false)
            .unwrap();
        runtime
            .temp_catalog_create(session, definition("mid", TempKind::View, &["base"]), false)
            .unwrap();
        runtime
            .temp_catalog_create(
                session,
                definition("top", TempKind::View, &["mid", "base"]),
                false,
            )
            .unwrap();
        let base_hash = runtime
            .temp_catalog_resolve(session, "base")
            .unwrap()
            .unwrap()
            .definition_hash;
        let query = runtime
            .prepare_query(session, binding(), ResourceLimits::default())
            .unwrap();
        // Only the view the SQL names is requested.
        let bound = runtime
            .bind_query_temp(session, &query, &["top".to_owned()])
            .unwrap();
        let names: Vec<_> = bound.relations.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            ["top", "mid", "base"],
            "dependencies follow, once each"
        );

        // Redefining a table behind the view after prepare must not leak into the
        // stored binding, and the verification must cover it.
        runtime
            .temp_catalog_create(session, definition("base", TempKind::View, &[]), false)
            .unwrap();
        let verified = runtime.verify_query_temp_binding(&query).unwrap();
        let base = verified
            .relations
            .iter()
            .find(|r| r.name == "base")
            .unwrap();
        assert_eq!(base.definition_hash, base_hash);
        assert_eq!(base.kind, TempKind::Table);
    }

    #[test]
    fn a_dependency_missing_at_the_query_generation_names_the_view_that_needs_it() {
        let (runtime, sessions) = sessions(1);
        let session = &sessions[0];
        runtime
            .temp_catalog_create(session, definition("base", TempKind::Table, &[]), false)
            .unwrap();
        runtime
            .temp_catalog_create(session, definition("v", TempKind::View, &["base"]), false)
            .unwrap();
        runtime
            .temp_catalog_drop(session, "base", TempKind::Table, false)
            .unwrap();
        let query = runtime
            .prepare_query(session, binding(), ResourceLimits::default())
            .unwrap();
        let error = runtime
            .bind_query_temp(session, &query, &["v".to_owned()])
            .unwrap_err();
        assert_eq!(error.details["temp_error"], "unknown_relation");
        assert_eq!(error.details["relation"], "base");
        assert_eq!(error.details["required_by"], "v");
        // A failed bind stores nothing.
        assert!(runtime.query_temp_binding(&query).unwrap().is_none());
    }
}
