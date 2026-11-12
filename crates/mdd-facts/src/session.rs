//! One-stop fact session facade.
//!
//! The staged APIs remain authoritative and unchanged: this module only
//! composes them, so every value it hands back is the same immutable fact
//! object the staged constructors produce, with the same coverage semantics.
//!
//! ```no_run
//! # use mdd_facts::session::FactsSession;
//! # fn main() -> Result<(), mdd_types::MddError> {
//! let session = FactsSession::open("app.apk")?;
//! for index in 0..session.dex_count() {
//!     let definitions = session.definitions(index)?;
//!     println!("{}", definitions.definition_coverage() as u8);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Deliberate limits:
//!
//! * `open` captures and validates the inventory only. Fact layers are built
//!   lazily per DEX so opening never pre-builds every relation and never
//!   bypasses the per-layer limits.
//! * No `Completeness::Partial`/`Unknown` value is collapsed into an empty
//!   success; callers still decide whether a layer is usable.
//! * A layer built twice for the same DEX index returns the same `Arc`, so
//!   repeated access never rebuilds. `references()` shares the cached
//!   definition/code leases; `annotations()` still clones `DefinitionFacts`
//!   because it must own one.
use crate::{
    MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    references::{ReferenceFacts, ReferenceLimits},
};
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

/// Aggregated per-layer limits. Each field is forwarded verbatim to the staged
/// constructor it belongs to; no value is reinterpreted or rescaled.
#[derive(Clone, Copy, Debug, Default)]
pub struct FactsLimits {
    pub capture: CaptureLimits,
    pub archive: ArchiveLimits,
    pub strings: StringLimits,
    pub definitions: DefinitionLimits,
    pub code: CodeLimits,
    pub references: ReferenceLimits,
    pub annotations: AnnotationLimits,
}

/// Cached layers for one DEX occurrence.
#[derive(Default)]
struct Layers {
    metadata: Option<Arc<MetadataFacts>>,
    definitions: Option<Arc<DefinitionFacts>>,
    code: Option<Arc<CodeFacts>>,
    references: Option<Arc<ReferenceFacts>>,
    annotations: Option<Arc<AnnotationFacts>>,
}

/// A captured input with its validated archive inventory.
pub struct FactsSession {
    snapshot: Snapshot,
    inventory: ArchiveInventory,
    limits: FactsLimits,
    layers: Vec<Mutex<Layers>>,
}

impl FactsSession {
    /// Capture `path` and build its archive inventory.
    ///
    /// The input kind comes from `InputKind::detect`, so the extension guessing
    /// that every caller previously duplicated lives here once.
    pub fn open(path: impl AsRef<Path>) -> MddResult<Self> {
        Self::open_with(path, FactsLimits::default())
    }
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
        let dex_count = inventory.selected_dexes().len();
        Ok(Self {
            snapshot,
            inventory,
            limits,
            layers: (0..dex_count)
                .map(|_| Mutex::new(Layers::default()))
                .collect(),
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
    /// Number of selected logical DEX occurrences.
    pub fn dex_count(&self) -> usize {
        self.layers.len()
    }
    /// Logical occurrence identity for `index`, matching `selected_dexes()`.
    pub fn occurrence(&self, index: usize) -> MddResult<&str> {
        self.inventory
            .selected_dexes()
            .get(index)
            .map(|dex| dex.dex_occurrence_id.as_str())
            .ok_or_else(|| out_of_range(index))
    }
    fn layers(&self, index: usize) -> MddResult<&Mutex<Layers>> {
        self.layers.get(index).ok_or_else(|| out_of_range(index))
    }
    pub fn metadata(&self, index: usize) -> MddResult<Arc<MetadataFacts>> {
        let mut layers = self.lock(index)?;
        self.metadata_locked(index, &mut layers)
    }
    fn metadata_locked(&self, index: usize, layers: &mut Layers) -> MddResult<Arc<MetadataFacts>> {
        if let Some(facts) = &layers.metadata {
            return Ok(Arc::clone(facts));
        }
        let facts = Arc::new(MetadataFacts::build(
            &self.snapshot,
            &self.inventory,
            index,
            self.limits.strings,
        )?);
        layers.metadata = Some(Arc::clone(&facts));
        Ok(facts)
    }
    pub fn definitions(&self, index: usize) -> MddResult<Arc<DefinitionFacts>> {
        let mut layers = self.lock(index)?;
        self.definitions_locked(index, &mut layers)
    }
    fn definitions_locked(
        &self,
        index: usize,
        layers: &mut Layers,
    ) -> MddResult<Arc<DefinitionFacts>> {
        if let Some(facts) = &layers.definitions {
            return Ok(Arc::clone(facts));
        }
        // Build the metadata through the already-locked view to avoid nesting
        // the same per-DEX mutex, then share that `Arc` instead of cloning the
        // whole string/type/prototype tables.
        let metadata = self.metadata_locked(index, layers)?;
        let facts = Arc::new(DefinitionFacts::build_arc(
            Arc::clone(&metadata),
            self.limits.definitions,
        )?);
        layers.definitions = Some(Arc::clone(&facts));
        Ok(facts)
    }
    pub fn code(&self, index: usize) -> MddResult<Arc<CodeFacts>> {
        let mut layers = self.lock(index)?;
        if let Some(facts) = &layers.code {
            return Ok(Arc::clone(facts));
        }
        let facts = Arc::new(CodeFacts::build_all_code_items(
            &self.snapshot,
            &self.inventory,
            index,
            self.limits.code,
        )?);
        layers.code = Some(Arc::clone(&facts));
        Ok(facts)
    }
    pub fn references(&self, index: usize) -> MddResult<Arc<ReferenceFacts>> {
        let mut layers = self.lock(index)?;
        if let Some(facts) = &layers.references {
            return Ok(Arc::clone(facts));
        }
        let definitions = self.definitions_locked(index, &mut layers)?;
        let code = {
            if let Some(facts) = &layers.code {
                Arc::clone(facts)
            } else {
                let facts = Arc::new(CodeFacts::build_all_code_items(
                    &self.snapshot,
                    &self.inventory,
                    index,
                    self.limits.code,
                )?);
                layers.code = Some(Arc::clone(&facts));
                facts
            }
        };
        // Share the cached definition and code leases instead of cloning them:
        // cloning `CodeFacts` on NewPipe measures ~277 ms and dominates the
        // whole facade call.
        let facts = Arc::new(ReferenceFacts::build_arc(
            Arc::clone(&definitions),
            Arc::clone(&code),
            self.limits.references,
        )?);
        layers.references = Some(Arc::clone(&facts));
        Ok(facts)
    }
    pub fn annotations(&self, index: usize) -> MddResult<Arc<AnnotationFacts>> {
        let mut layers = self.lock(index)?;
        if let Some(facts) = &layers.annotations {
            return Ok(Arc::clone(facts));
        }
        let definitions = self.definitions_locked(index, &mut layers)?;
        // Annotations need an owned `DefinitionFacts`; the clone is ~66 ms on
        // NewPipe, far below the `CodeFacts` clone that `references()` avoids.
        let facts = Arc::new(AnnotationFacts::build(
            (*definitions).clone(),
            self.limits.annotations,
        )?);
        layers.annotations = Some(Arc::clone(&facts));
        Ok(facts)
    }
    fn lock(&self, index: usize) -> MddResult<std::sync::MutexGuard<'_, Layers>> {
        self.layers(index)?.lock().map_err(|_| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.session",
                "layer cache poisoned",
            )
        })
    }
}

fn out_of_range(index: usize) -> MddError {
    MddError::new(
        ErrorCode::InvalidArgument,
        "facts.session",
        "DEX occurrence index outside this session",
    )
    .detail("dex_index", index.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/minimal-035.dex")
    }

    #[test]
    fn session_reuses_each_layer_and_rejects_out_of_range() {
        let session = FactsSession::open(fixture()).unwrap();
        assert_eq!(session.dex_count(), 1);
        let first = session.metadata(0).unwrap();
        let second = session.metadata(0).unwrap();
        assert!(Arc::ptr_eq(&first, &second), "metadata must be cached");

        let definitions = session.definitions(0).unwrap();
        assert!(Arc::ptr_eq(&definitions, &session.definitions(0).unwrap()));
        // The facade must share the cached metadata lease rather than clone the
        // string/type/prototype tables; `references()` already proves this.
        let metadata = session.metadata(0).unwrap();
        assert!(Arc::ptr_eq(&definitions.metadata, &metadata));

        let references = session.references(0).unwrap();
        assert!(Arc::ptr_eq(&references, &session.references(0).unwrap()));
        let error = match session.metadata(1) {
            Ok(_) => panic!("out-of-range metadata must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn occurrence_matches_inventory_order() {
        let session = FactsSession::open(fixture()).unwrap();
        assert_eq!(
            session.occurrence(0).unwrap(),
            session.inventory().selected_dexes()[0].dex_occurrence_id
        );
    }
}
