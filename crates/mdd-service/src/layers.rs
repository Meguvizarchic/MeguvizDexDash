//! The fact layers of one selected DEX, built when something needs them and let go afterwards.
//!
//! A dataset used to build the layers of every DEX at open and keep them for as long as it lived: for an archive of thirty-three
//! DEX that is several gigabytes of objects behind the few hundred megabytes of rows the SQL relations hold. The builder here
//! holds only the inputs (the snapshot and the inventories) and makes the layers of one DEX on request:
//!
//! * for the SQL relations (`OccurrenceLoader`): the provider takes the rows of each DEX from the layers and drops them, and
//!   the builder notes which layers a DEX could not build (`issues`);
//! * for `decode` (`occurrence`): the facts a method or class text is rendered from, built the first time a decode is asked.
//!
//! What a layer contains does not depend on who asks: a DEX whose references or annotations cannot be validated still shows its
//! instructions to `decode`, and gives the SQL relations the structural facts only, with the failing layer named.
use crate::{LayerIssue, decode::Occurrence};
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_facts::{
    DefinitionFacts, MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    references::{ReferenceFacts, ReferenceLimits},
};
use mdd_input::{archive::ArchiveInventory, snapshot::Snapshot};
use mdd_sql::provider::hostlab::{HostLabOccurrenceFacts, LayerNeeds, OccurrenceLoader};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::sync::{Arc, Mutex};

pub(crate) struct LayerBuilder {
    snapshot: Arc<Snapshot>,
    inventories: Arc<Vec<ArchiveInventory>>,
    /// The inventory and the local position in it of each selected DEX, in roster order.
    roster: Vec<(usize, usize)>,
    /// The layers a DEX could not build, by roster position; the last load of a DEX decides.
    issues: Mutex<Vec<(usize, LayerIssue)>>,
}

struct ReleaseOnDrop<'a>(&'a mdd_input::archive::MemberBlob);

impl Drop for ReleaseOnDrop<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// The layers every consumer starts from, and the ones that may fail without taking the DEX away.
struct Built {
    metadata: Arc<MetadataFacts>,
    definitions: Arc<DefinitionFacts>,
    /// The header and opcodes of every code item; the instructions are decoded again from the DEX bytes when they are read,
    /// one code item at a time (by `decode`, and by the reference layer when it takes its sites).
    compact_code: MddResult<Arc<CodeFacts>>,
    annotations: MddResult<Arc<AnnotationFacts>>,
}

impl LayerBuilder {
    pub(crate) fn new(snapshot: Arc<Snapshot>, inventories: Arc<Vec<ArchiveInventory>>) -> Self {
        let roster = inventories
            .iter()
            .enumerate()
            .flat_map(|(inventory, value)| {
                (0..value.selected_dexes().len()).map(move |local| (inventory, local))
            })
            .collect();
        Self {
            snapshot,
            inventories,
            roster,
            issues: Mutex::new(Vec::new()),
        }
    }

    /// The layers a DEX could not build, in roster order.
    pub(crate) fn issues(&self) -> Vec<LayerIssue> {
        let mut issues = self
            .issues
            .lock()
            .map(|issues| issues.clone())
            .unwrap_or_default();
        issues.sort_by_key(|(position, _)| *position);
        issues.into_iter().map(|(_, issue)| issue).collect()
    }

    fn dex(&self, position: usize) -> MddResult<(&ArchiveInventory, usize)> {
        let (inventory, local) = *self.roster.get(position).ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "service.layers",
                "a DEX outside the selected roster was asked for",
            )
            .detail("position", position.to_string())
        })?;
        Ok((&self.inventories[inventory], local))
    }

    /// Metadata and definitions are the base of every relation: without them there is nothing to answer from, so a fault in
    /// them is an error. The code layer is built first and kept on its own, and the annotation layer does not read the code
    /// or the references: a DEX whose references or annotations cannot be validated can still show its instructions, and
    /// `decode` must not lose every method body to a fault in one other layer.
    fn build(&self, position: usize) -> MddResult<Built> {
        let (inventory, local) = self.dex(position)?;
        // The inventory does not hold the DEX: the first layer reads it from the archive and the others share that copy.
        // Whatever the layers need of it they hold themselves, so the inventory lets its copy go when this returns, however
        // it returns; the copy is then freed with the last layer that holds it.
        let _release = ReleaseOnDrop(&inventory.selected_dexes()[local].blob);
        // The code layer reads the DEX bytes and nothing of the metadata, so it is built beside the metadata, definitions
        // and annotation layers: the bytes are read from the archive once (the first to ask reads, the other waits and
        // shares), and the two chains take about as long as the longer. The code layer is built compact: every code item is
        // read and validated, and kept as its header and opcodes; the decoded instructions of the whole DEX (most of a
        // gigabyte for a large one) are never alive together.
        let (chain, compact_code) = std::thread::scope(|scope| {
            let code = scope.spawn(|| {
                CodeFacts::build_all_code_items_compact(
                    &self.snapshot,
                    inventory,
                    local,
                    CodeLimits::default(),
                )
                .map(Arc::new)
            });
            let chain = (|| -> MddResult<_> {
                let metadata = Arc::new(MetadataFacts::build(
                    &self.snapshot,
                    inventory,
                    local,
                    StringLimits::default(),
                )?);
                let definitions = Arc::new(DefinitionFacts::build_arc(
                    Arc::clone(&metadata),
                    DefinitionLimits::default(),
                )?);
                let annotations = AnnotationFacts::build_arc(
                    Arc::clone(&definitions),
                    AnnotationLimits::default(),
                )
                .map(Arc::new);
                Ok((metadata, definitions, annotations))
            })();
            let code = match code.join() {
                Ok(code) => code,
                Err(payload) => std::panic::resume_unwind(payload),
            };
            (chain, code)
        });
        let (metadata, definitions, annotations) = chain?;
        Ok(Built {
            metadata,
            definitions,
            compact_code,
            annotations,
        })
    }

    /// The facts `decode` renders from. The references are not part of them, and the code and annotation layers are `None`
    /// when they could not be built (a method with a body then cannot be decoded, and a text shows no annotations; both say so).
    pub(crate) fn occurrence(&self, position: usize) -> MddResult<Occurrence> {
        let file_id = u32::try_from(position).map_err(|_| {
            MddError::new(ErrorCode::QuotaExceeded, "service", "too many DEX files")
        })?;
        let Built {
            metadata,
            definitions,
            compact_code,
            annotations,
        } = self.build(position)?;
        Ok(Occurrence {
            file_id,
            metadata,
            definitions,
            code: compact_code.ok(),
            annotations: annotations.ok(),
        })
    }

    fn note(&self, position: usize, issue: Option<LayerIssue>) {
        if let Ok(mut issues) = self.issues.lock() {
            issues.retain(|(noted, _)| *noted != position);
            if let Some(issue) = issue {
                issues.push((position, issue));
            }
        }
    }
}

impl OccurrenceLoader for LayerBuilder {
    /// Every layer is built whatever `needs` says: what a relation sees must not depend on which relation asked first, and a
    /// DEX with a layer that fails gives the structural facts to all of them, as it always has.
    fn load(&self, position: usize, _needs: LayerNeeds) -> MddResult<HostLabOccurrenceFacts> {
        let (inventory, local) = self.dex(position)?;
        let occurrence = inventory.selected_dexes()[local].dex_occurrence_id.clone();
        let built = self.build(position)?;
        let Built {
            metadata,
            definitions,
            compact_code,
            annotations,
        } = built;
        let upper = || -> MddResult<_> {
            let compact = Arc::clone(compact_code.as_ref().map_err(Clone::clone)?);
            let references = Arc::new(ReferenceFacts::build_arc(
                Arc::clone(&definitions),
                Arc::clone(&compact),
                ReferenceLimits::default(),
            )?);
            let annotations = Arc::clone(annotations.as_ref().map_err(Clone::clone)?);
            Ok((compact, references, annotations))
        };
        let upper = upper();
        match upper {
            Ok((code, references, annotations)) => {
                self.note(position, None);
                Ok(HostLabOccurrenceFacts::complete(
                    metadata,
                    definitions,
                    code,
                    references,
                    annotations,
                ))
            }
            Err(error) => {
                self.note(
                    position,
                    Some(LayerIssue {
                        dex_occurrence_id: occurrence,
                        layers: "code,references,annotations",
                        error,
                    }),
                );
                Ok(HostLabOccurrenceFacts::structural(metadata, definitions))
            }
        }
    }
}
