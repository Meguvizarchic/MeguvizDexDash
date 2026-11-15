//! Finding one method of an opened dataset and rendering it as smali.
//!
//! A method is named by its descriptor (`Lpkg/Cls;->name(args)ret`) or by the pair
//! (`file_id`, `method_idx`). A descriptor that is defined in several DEX files of the
//! dataset names none of them: the caller must say which, with `file_id`. A method that
//! is only referred to, never defined, has no body and is not found.
use crate::Dataset;
use mdd_dex::{definitions::MethodBody, instructions::CodeItem};
use mdd_facts::{
    CodeFacts, DefinitionFacts, MetadataFacts,
    smali_required::{MethodView, RenderedMethod, SmaliLimits, render_method},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::{collections::HashMap, sync::Arc};

/// The facts of one DEX of a dataset, kept so a method can be decoded long after the
/// SQL relations were built from them.
pub struct Occurrence {
    pub file_id: u32,
    pub metadata: Arc<MetadataFacts>,
    pub definitions: Arc<DefinitionFacts>,
    /// `None` when the code layer could not be built; a method with a body cannot then
    /// be decoded, and says so.
    pub code: Option<Arc<CodeFacts>>,
}

/// What `select` takes.
#[derive(Clone, Copy, Debug)]
pub enum Selector<'a> {
    Descriptor {
        descriptor: &'a str,
        file_id: Option<u32>,
    },
    Key {
        file_id: u32,
        method_idx: u32,
    },
}

/// Why a method was not produced.
#[derive(Debug)]
pub enum Failure {
    NotFound {
        what: String,
    },
    /// The descriptor is defined in more than one DEX file.
    Ambiguous {
        file_ids: Vec<u32>,
    },
    Error(MddError),
}

impl From<MddError> for Failure {
    fn from(error: MddError) -> Self {
        Self::Error(error)
    }
}

/// A method found, not yet rendered.
#[derive(Clone, Copy, Debug)]
pub struct Located {
    pub file_id: u32,
    pub method_idx: u32,
    /// Position in the occurrence's `method_definitions`.
    definition: usize,
}

/// Per occurrence: defined methods by descriptor, and code items by their byte offset.
pub(crate) struct OccurrenceIndex {
    by_descriptor: HashMap<String, Vec<usize>>,
    by_method_idx: HashMap<u32, usize>,
    code_by_offset: HashMap<u64, usize>,
}

impl OccurrenceIndex {
    pub(crate) fn build(occurrence: &Occurrence) -> Self {
        let defs = occurrence.definitions.definitions();
        let mut by_descriptor: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_method_idx = HashMap::new();
        for (position, definition) in defs.method_definitions.iter().enumerate() {
            by_method_idx.insert(definition.method_idx, position);
            if let Some(reference) = defs.method_references.get(definition.method_idx as usize) {
                by_descriptor
                    .entry(reference.descriptor.clone())
                    .or_default()
                    .push(position);
            }
        }
        let mut code_by_offset = HashMap::new();
        if let Some(code) = &occurrence.code {
            for (ordinal, item) in code.items().iter().enumerate() {
                code_by_offset.insert(item.data().raw_range.byte_offset.0, ordinal);
            }
        }
        Self {
            by_descriptor,
            by_method_idx,
            code_by_offset,
        }
    }
}

fn not_defined(file_id: u32, method_idx: u32) -> Failure {
    Failure::NotFound {
        what: format!(
            "method_idx {method_idx} in file_id {file_id} has no definition (it is only referred to)"
        ),
    }
}

/// Find the method `selector` names.
pub fn select(dataset: &Dataset, selector: Selector<'_>) -> Result<Located, Failure> {
    let occurrences = dataset.occurrences();
    let indexes = dataset.decode_indexes();
    match selector {
        Selector::Key {
            file_id,
            method_idx,
        } => {
            let index = occurrences
                .iter()
                .position(|o| o.file_id == file_id)
                .ok_or_else(|| Failure::NotFound {
                    what: format!("file_id {file_id} is not in this dataset"),
                })?;
            let definition = *indexes[index]
                .by_method_idx
                .get(&method_idx)
                .ok_or_else(|| not_defined(file_id, method_idx))?;
            Ok(Located {
                file_id,
                method_idx,
                definition,
            })
        }
        Selector::Descriptor {
            descriptor,
            file_id,
        } => {
            let mut found = Vec::new();
            for (occurrence, index) in occurrences.iter().zip(indexes) {
                if file_id.is_some_and(|wanted| wanted != occurrence.file_id) {
                    continue;
                }
                for &position in index.by_descriptor.get(descriptor).into_iter().flatten() {
                    found.push((occurrence.file_id, position));
                }
            }
            match found.as_slice() {
                [] => Err(Failure::NotFound {
                    what: format!("method {descriptor} is not defined in this dataset"),
                }),
                [(file_id, position)] => {
                    let occurrence = occurrences
                        .iter()
                        .find(|o| o.file_id == *file_id)
                        .expect("a found file_id belongs to an occurrence");
                    let method_idx = occurrence.definitions.definitions().method_definitions
                        [*position]
                        .method_idx;
                    Ok(Located {
                        file_id: *file_id,
                        method_idx,
                        definition: *position,
                    })
                }
                many => {
                    let mut ids: Vec<u32> = many.iter().map(|(file_id, _)| *file_id).collect();
                    ids.sort_unstable();
                    ids.dedup();
                    if ids.len() == 1 {
                        return Err(Failure::Error(
                            MddError::new(
                                ErrorCode::InvalidInput,
                                "service.decode",
                                "a DEX defines the same method more than once",
                            )
                            .detail("file_id", ids[0].to_string()),
                        ));
                    }
                    Err(Failure::Ambiguous { file_ids: ids })
                }
            }
        }
    }
}

/// A located method, rendered, with the numbers the decode answer carries.
pub struct Decoded {
    pub file_id: u32,
    pub method_idx: u32,
    pub descriptor: String,
    pub access_flags: u32,
    pub rendered: RenderedMethod,
}

/// The facts of a located method: its definition and its code item.
fn code_of<'a>(
    occurrence: &'a Occurrence,
    index: &OccurrenceIndex,
    body: &MethodBody,
) -> Result<Option<&'a CodeItem>, MddError> {
    let MethodBody::Present {
        code_byte_offset, ..
    } = body
    else {
        return Ok(None);
    };
    let code = occurrence.code.as_ref().ok_or_else(|| {
        MddError::new(
            ErrorCode::IncompleteFacts,
            "service.decode",
            "the code layer of this DEX could not be built, so no method body can be shown",
        )
        .detail("file_id", occurrence.file_id.to_string())
    })?;
    let ordinal = *index
        .code_by_offset
        .get(&code_byte_offset.0)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "service.decode",
                "the method's code item is not among the code facts",
            )
            .detail("code_item_byte_offset", code_byte_offset.0.to_string())
        })?;
    Ok(Some(code.items()[ordinal].data()))
}

/// Render the located method.
pub fn render(dataset: &Dataset, located: Located, limits: SmaliLimits) -> MddResult<Decoded> {
    let occurrences = dataset.occurrences();
    let position = occurrences
        .iter()
        .position(|o| o.file_id == located.file_id)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "service.decode",
                "a located file_id vanished",
            )
        })?;
    let occurrence = &occurrences[position];
    let index = &dataset.decode_indexes()[position];
    let definitions = occurrence.definitions.definitions();
    let definition = &definitions.method_definitions[located.definition];
    let code = code_of(occurrence, index, &definition.body)?;
    let view = MethodView {
        metadata: &occurrence.metadata,
        definitions,
        definition,
        code,
    };
    let rendered = render_method(&view, limits)?;
    Ok(Decoded {
        file_id: located.file_id,
        method_idx: located.method_idx,
        descriptor: definitions.method_references[located.method_idx as usize]
            .descriptor
            .clone(),
        access_flags: definition.access_flags,
        rendered,
    })
}
