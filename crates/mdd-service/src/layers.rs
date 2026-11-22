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
    code::{CodeFacts, CompactCodeRefs},
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
    /// Compact per-DEX validation metadata captured during SQL relation builds for lazy single-DEX decode.
    validated: Vec<Mutex<ValidatedDexLayers>>,
}

#[derive(Clone)]
pub(crate) struct ValidatedCodeMeta {
    pub(crate) declared_code_offsets: Box<[u32]>,
    pub(crate) debug_starts: Box<[u32]>,
}

#[derive(Clone, Default)]
pub(crate) enum LayerValidation<T> {
    #[default]
    Unknown,
    Valid(T),
    Failed,
}

#[derive(Clone, Default)]
struct ValidatedDexLayers {
    code: LayerValidation<ValidatedCodeMeta>,
    annotations: LayerValidation<()>,
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
    /// one code item at a time (by `decode`, or via `compact_refs` when `ReferenceFacts` takes its sites).
    compact_code: MddResult<Arc<CodeFacts>>,
    compact_refs: Option<CompactCodeRefs>,
    annotations: MddResult<Arc<AnnotationFacts>>,
}

impl LayerBuilder {
    pub(crate) fn new(snapshot: Arc<Snapshot>, inventories: Arc<Vec<ArchiveInventory>>) -> Self {
        let roster: Vec<(usize, usize)> = inventories
            .iter()
            .enumerate()
            .flat_map(|(inventory, value)| {
                (0..value.selected_dexes().len()).map(move |local| (inventory, local))
            })
            .collect();
        let validated = (0..roster.len())
            .map(|_| Mutex::new(ValidatedDexLayers::default()))
            .collect();
        Self {
            snapshot,
            inventories,
            roster,
            issues: Mutex::new(Vec::new()),
            validated,
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
        self.build_internal(position, false)
    }

    fn build_internal(&self, position: usize, capture_compact_refs: bool) -> MddResult<Built> {
        let (inventory, local) = self.dex(position)?;
        // The inventory does not hold the DEX: the first layer reads it from the archive and the others share that copy.
        // Whatever the layers need of it they hold themselves, so the inventory lets its copy go when this returns, however
        // it returns; the copy is then freed with the last layer that holds it.
        let _release = ReleaseOnDrop(&inventory.selected_dexes()[local].blob);
        let (chain, (compact_code, compact_refs)) = std::thread::scope(|scope| {
            let code = scope.spawn(|| {
                if capture_compact_refs {
                    match CodeFacts::build_all_code_items_compact_with_refs(
                        &self.snapshot,
                        inventory,
                        local,
                        CodeLimits::default(),
                    ) {
                        Ok((facts, refs)) => (Ok(Arc::new(facts)), Some(refs)),
                        Err(error) => (Err(error), None),
                    }
                } else {
                    (
                        CodeFacts::build_all_code_items_compact(
                            &self.snapshot,
                            inventory,
                            local,
                            CodeLimits::default(),
                        )
                        .map(Arc::new),
                        None,
                    )
                }
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
                let annotations = if capture_compact_refs {
                    Err(MddError::new(
                        ErrorCode::InternalFault,
                        "service.layers",
                        "deferred for parallel loader pass",
                    ))
                } else {
                    AnnotationFacts::build_arc(
                        Arc::clone(&definitions),
                        AnnotationLimits::default(),
                    )
                    .map(Arc::new)
                };
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
            compact_refs,
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
            compact_refs: _,
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

    pub(crate) fn build_base(
        &self,
        position: usize,
    ) -> MddResult<(Arc<MetadataFacts>, Arc<DefinitionFacts>)> {
        let (inventory, local) = self.dex(position)?;
        let _release = ReleaseOnDrop(&inventory.selected_dexes()[local].blob);
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
        Ok((metadata, definitions))
    }

    pub(crate) fn build_compact_code(&self, position: usize) -> MddResult<Arc<CodeFacts>> {
        let (inventory, local) = self.dex(position)?;
        let _release = ReleaseOnDrop(&inventory.selected_dexes()[local].blob);
        CodeFacts::build_all_code_items_compact(
            &self.snapshot,
            inventory,
            local,
            CodeLimits::default(),
        )
        .map(Arc::new)
    }

    pub(crate) fn code_validation(&self, position: usize) -> LayerValidation<ValidatedCodeMeta> {
        self.validated
            .get(position)
            .and_then(|slot| slot.lock().ok().map(|v| v.code.clone()))
            .unwrap_or_default()
    }

    pub(crate) fn annotations_validation(&self, position: usize) -> LayerValidation<()> {
        self.validated
            .get(position)
            .and_then(|slot| slot.lock().ok().map(|v| v.annotations.clone()))
            .unwrap_or_default()
    }

    fn note_validation(
        &self,
        position: usize,
        code: LayerValidation<ValidatedCodeMeta>,
        annotations: LayerValidation<()>,
    ) {
        if let Some(slot) = self.validated.get(position)
            && let Ok(mut guard) = slot.lock()
        {
            *guard = ValidatedDexLayers { code, annotations };
        }
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

fn validate_code_meta(code: &CodeFacts) -> LayerValidation<ValidatedCodeMeta> {
    let Some(starts) = code.debug_starts() else {
        return LayerValidation::Unknown;
    };
    let Some(mut offsets) = code
        .declared_code_item_byte_offsets()
        .iter()
        .map(|d| u32::try_from(d.0).ok())
        .collect::<Option<Vec<u32>>>()
    else {
        return LayerValidation::Unknown;
    };
    let Some(mut debug_starts) = starts
        .iter()
        .map(|&s| u32::try_from(s).ok())
        .collect::<Option<Vec<u32>>>()
    else {
        return LayerValidation::Unknown;
    };
    offsets.sort_unstable();
    debug_starts.sort_unstable();
    LayerValidation::Valid(ValidatedCodeMeta {
        declared_code_offsets: offsets.into_boxed_slice(),
        debug_starts: debug_starts.into_boxed_slice(),
    })
}

impl OccurrenceLoader for LayerBuilder {
    /// Every layer is built whatever `needs` says: what a relation sees must not depend on which relation asked first, and a
    /// DEX with a layer that fails gives the structural facts to all of them, as it always has.
    fn load(&self, position: usize, _needs: LayerNeeds) -> MddResult<HostLabOccurrenceFacts> {
        let (inventory, local) = self.dex(position)?;
        let occurrence = inventory.selected_dexes()[local].dex_occurrence_id.clone();
        let opt_parallel = std::env::var_os("MDD_OPT_PARALLEL_PREPARE").as_deref()
            != Some(std::ffi::OsStr::new("0"));
        let built = self.build_internal(position, opt_parallel)?;
        let Built {
            metadata,
            definitions,
            compact_code,
            compact_refs,
            annotations,
        } = built;
        let code_valid = match &compact_code {
            Ok(code) => validate_code_meta(code),
            Err(_) => LayerValidation::Failed,
        };
        let mut ann_valid = if opt_parallel {
            LayerValidation::Unknown
        } else if annotations.is_ok() {
            LayerValidation::Valid(())
        } else {
            LayerValidation::Failed
        };
        let mut upper = || -> MddResult<_> {
            let built_code = Arc::clone(compact_code.as_ref().map_err(Clone::clone)?);
            if opt_parallel {
                let (references, annotations) = std::thread::scope(|scope| {
                    let ann = scope.spawn(|| {
                        AnnotationFacts::build_arc(
                            Arc::clone(&definitions),
                            AnnotationLimits::default(),
                        )
                        .map(Arc::new)
                    });
                    let refs = match compact_refs {
                        Some(sidecar) => ReferenceFacts::build_arc_with_compact_refs(
                            Arc::clone(&definitions),
                            Arc::clone(&built_code),
                            sidecar,
                            ReferenceLimits::default(),
                        ),
                        None => ReferenceFacts::build_arc(
                            Arc::clone(&definitions),
                            Arc::clone(&built_code),
                            ReferenceLimits::default(),
                        ),
                    }
                    .map(Arc::new);
                    let ann = match ann.join() {
                        Ok(res) => res,
                        Err(payload) => std::panic::resume_unwind(payload),
                    };
                    (refs, ann)
                });
                ann_valid = if annotations.is_ok() {
                    LayerValidation::Valid(())
                } else {
                    LayerValidation::Failed
                };
                return Ok((built_code, references?, annotations?));
            }
            drop(compact_refs);
            let references = Arc::new(ReferenceFacts::build_arc(
                Arc::clone(&definitions),
                Arc::clone(&built_code),
                ReferenceLimits::default(),
            )?);
            let annotations = Arc::clone(annotations.as_ref().map_err(Clone::clone)?);
            Ok((built_code, references, annotations))
        };
        let upper = upper();
        self.note_validation(position, code_valid, ann_valid);
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
