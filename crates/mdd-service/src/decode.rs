//! Finding one method of an opened dataset and rendering it as smali.
//!
//! A method is named by its descriptor (`Lpkg/Cls;->name(args)ret`) or by the pair
//! (`file_id`, `method_idx`). A descriptor that is defined in several DEX files of the
//! dataset names none of them: the caller must say which, with `file_id`. A method that
//! is only referred to, never defined, has no body and is not found.
use crate::{
    Dataset,
    layers::{LayerBuilder, LayerValidation, ValidatedCodeMeta},
};
use mdd_dex::{
    annotations::AnnotationLimits,
    definitions::MethodBody,
    instructions::{CodeItem, CodeItemDecoder, CodeLimits},
};
use mdd_facts::{
    CodeFacts, DefinitionFacts, MetadataFacts,
    annotations::AnnotationFacts,
    smali::{
        AnnotationIndex, ClassLimits, ClassView, ExtrasReport, FullMethodView, RenderedClass,
        SmaliOptions, render_class, render_method_full,
    },
    smali_required::{MethodView, RenderedMethod, SmaliLimits, method_declaration},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::sync::{Arc, Mutex, OnceLock};

/// The facts of one DEX of a dataset, returned by `Dataset::occurrences`.
pub struct Occurrence {
    pub file_id: u32,
    pub metadata: Arc<MetadataFacts>,
    pub definitions: Arc<DefinitionFacts>,
    /// `None` when the code layer could not be built; a method with a body cannot then
    /// be decoded, and says so.
    pub code: Option<Arc<CodeFacts>>,
    /// `None` when the annotation layer could not be built; a text then shows no annotations
    /// or static values, and its report says so.
    pub annotations: Option<Arc<AnnotationFacts>>,
}

/// Lazily loaded per-DEX decode state: only the target DEX's base facts and the single requested
/// `CodeItem` are parsed and decoded, avoiding loading or indexing all other DEXes in the dataset.
struct AnnotationStore {
    annotations: Option<Arc<AnnotationFacts>>,
}

struct AnnotationLookup {
    annotation_index: Option<AnnotationIndex>,
}

struct CachedAnnotations {
    store: AnnotationStore,
    lookup: AnnotationLookup,
}

static EMPTY_ANNOTATIONS: CachedAnnotations = CachedAnnotations {
    store: AnnotationStore { annotations: None },
    lookup: AnnotationLookup {
        annotation_index: None,
    },
};

pub(crate) struct LazyDexDecode {
    file_id: u32,
    metadata: Arc<MetadataFacts>,
    definitions: Arc<DefinitionFacts>,
    code_validation: LayerValidation<ValidatedCodeMeta>,
    annotations_validation: LayerValidation<()>,
    decoder: Mutex<Option<CodeItemDecoder<Arc<[u8]>>>>,
    fallback_code: OnceLock<Option<Arc<CodeFacts>>>,
    annotations: OnceLock<CachedAnnotations>,
}

impl LazyDexDecode {
    pub(crate) fn new(
        file_id: u32,
        metadata: Arc<MetadataFacts>,
        definitions: Arc<DefinitionFacts>,
        code_validation: LayerValidation<ValidatedCodeMeta>,
        annotations_validation: LayerValidation<()>,
    ) -> Self {
        Self {
            file_id,
            metadata,
            definitions,
            code_validation,
            annotations_validation,
            decoder: Mutex::new(None),
            fallback_code: OnceLock::new(),
            annotations: OnceLock::new(),
        }
    }

    fn find_method_def_by_idx(&self, method_idx: u32) -> Option<usize> {
        self.definitions
            .definitions()
            .method_definitions
            .iter()
            .position(|def| def.method_idx == method_idx)
    }

    fn find_method_defs_by_descriptor(&self, descriptor: &str) -> Vec<usize> {
        let defs = self.definitions.definitions();
        let mut out = Vec::new();
        for (position, def) in defs.method_definitions.iter().enumerate() {
            if defs
                .method_references
                .get(def.method_idx as usize)
                .is_some_and(|reference| reference.descriptor == descriptor)
            {
                out.push(position);
            }
        }
        out
    }

    fn find_classes_by_descriptor(&self, descriptor: &str) -> Vec<usize> {
        self.definitions
            .definitions()
            .classes
            .iter()
            .enumerate()
            .filter(|(_, class)| class.descriptor == descriptor)
            .map(|(position, _)| position)
            .collect()
    }

    fn class_def_at(&self, class_def_idx: u32) -> Option<usize> {
        let classes = &self.definitions.definitions().classes;
        if let Ok(pos) = usize::try_from(class_def_idx)
            && classes
                .get(pos)
                .is_some_and(|class| class.class_def_idx == class_def_idx)
        {
            return Some(pos);
        }
        classes
            .iter()
            .position(|class| class.class_def_idx == class_def_idx)
    }

    fn code_layer_missing_error(&self) -> MddError {
        MddError::new(
            ErrorCode::IncompleteFacts,
            "service.decode",
            "the code layer of this DEX could not be built, so no method body can be shown",
        )
        .detail("file_id", self.file_id.to_string())
    }

    pub(crate) fn decode_code_item(
        &self,
        layers: &LayerBuilder,
        body: &MethodBody,
        with_debug: bool,
    ) -> MddResult<Option<CodeItem>> {
        let MethodBody::Present {
            code_byte_offset, ..
        } = body
        else {
            return Ok(None);
        };
        match &self.code_validation {
            LayerValidation::Failed => Err(self.code_layer_missing_error()),
            LayerValidation::Valid(meta) => {
                let known = u32::try_from(code_byte_offset.0)
                    .ok()
                    .and_then(|off| meta.declared_code_offsets.binary_search(&off).ok())
                    .is_some();
                if !known {
                    return Err(MddError::new(
                        ErrorCode::IncompleteFacts,
                        "service.decode",
                        "the method's code item is not among the code facts",
                    )
                    .detail("code_item_byte_offset", code_byte_offset.0.to_string()));
                }
                let mut guard = self
                    .decoder
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if guard.is_none() {
                    let starts: Vec<u64> =
                        meta.debug_starts.iter().copied().map(u64::from).collect();
                    *guard = Some(CodeItemDecoder::new(
                        self.metadata.lease(),
                        self.metadata.header().clone(),
                        CodeLimits::default(),
                        &starts,
                    ));
                }
                let decoder = guard.as_mut().expect("initialized decoder");
                let item = if with_debug {
                    decoder.decode(code_byte_offset.0)?
                } else {
                    decoder.decode_instructions(code_byte_offset.0)?
                };
                Ok(Some(item))
            }
            LayerValidation::Unknown => {
                let code = self
                    .fallback_code
                    .get_or_init(|| layers.build_compact_code(self.file_id as usize).ok())
                    .as_ref()
                    .ok_or_else(|| self.code_layer_missing_error())?;
                let ordinal = code
                    .items()
                    .iter()
                    .position(|item| item.data().raw_range.byte_offset.0 == code_byte_offset.0)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::IncompleteFacts,
                            "service.decode",
                            "the method's code item is not among the code facts",
                        )
                        .detail("code_item_byte_offset", code_byte_offset.0.to_string())
                    })?;
                Ok(Some(code.decoded_item(ordinal)?.into_owned()))
            }
        }
    }

    pub(crate) fn method_positions_for_class(&self, class_def_idx: u32) -> Vec<usize> {
        let defs = self.definitions.definitions();
        let mut positions: Vec<usize> = defs
            .method_definitions
            .iter()
            .enumerate()
            .filter(|(_, def)| def.class_def_idx == class_def_idx)
            .map(|(position, _)| position)
            .collect();
        if positions.len() > 1 {
            positions.sort_by_key(|&position| defs.method_definitions[position].method_idx);
        }
        positions
    }

    fn annotations_parts(&self, skip: bool) -> (&AnnotationStore, &AnnotationLookup) {
        if skip || matches!(self.annotations_validation, LayerValidation::Failed) {
            return (&EMPTY_ANNOTATIONS.store, &EMPTY_ANNOTATIONS.lookup);
        }
        let cached = self.annotations.get_or_init(|| {
            match AnnotationFacts::build_arc(
                Arc::clone(&self.definitions),
                AnnotationLimits::default(),
            ) {
                Ok(facts) => {
                    let facts = Arc::new(facts);
                    let index = AnnotationIndex::build(&facts);
                    CachedAnnotations {
                        store: AnnotationStore {
                            annotations: Some(facts),
                        },
                        lookup: AnnotationLookup {
                            annotation_index: Some(index),
                        },
                    }
                }
                Err(_) => CachedAnnotations {
                    store: AnnotationStore { annotations: None },
                    lookup: AnnotationLookup {
                        annotation_index: None,
                    },
                },
            }
        });
        (&cached.store, &cached.lookup)
    }
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

/// A located method, not yet rendered.
#[derive(Clone, Copy, Debug)]
pub struct Located {
    pub file_id: u32,
    pub method_idx: u32,
    /// Position in the occurrence's `method_definitions`.
    definition: usize,
}

/// The message of the error that a `method_offset` past the last method raises.
pub const METHOD_OFFSET_PAST_END: &str = "method_offset exceeds total_methods";

/// A class found in one DEX of the dataset, not yet listed.
#[derive(Clone, Copy, Debug)]
pub struct LocatedClass {
    pub file_id: u32,
    /// Position in the occurrence's `definitions.classes`.
    class: usize,
}

/// The methods one class defines, counted in `method_idx` order.
#[derive(Clone, Debug)]
pub struct ClassPage {
    pub file_id: u32,
    pub class_def_idx: u32,
    pub descriptor: String,
    pub access_flags: u32,
    pub superclass: Option<String>,
    /// The source file name; a name that is not well-formed UTF-16 is shown with replacement
    /// characters here, and exactly in the class text.
    pub source_file: Option<String>,
    pub interfaces: Vec<String>,
    pub static_fields: u32,
    pub instance_fields: u32,
    pub total_methods: u64,
    /// The `method_offset` this page starts at.
    pub method_offset: u64,
    /// The methods of the page, at most `method_limit` of them.
    pub methods: Vec<Located>,
}

fn resolve_duplicate_or_ambiguous(file_ids: &[u32], duplicate_message: &str) -> Failure {
    let mut ids: Vec<u32> = file_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() == 1 {
        return Failure::Error(
            MddError::new(ErrorCode::InvalidInput, "service.decode", duplicate_message)
                .detail("file_id", ids[0].to_string()),
        );
    }
    Failure::Ambiguous { file_ids: ids }
}

fn dex_file_range(dex_count: usize, file_id: Option<u32>) -> std::ops::Range<u32> {
    match file_id {
        Some(wanted) if (wanted as usize) < dex_count => wanted..wanted + 1,
        Some(_) => 0..0,
        None => 0..(dex_count as u32),
    }
}

/// Find the class `descriptor` names. A descriptor defined in several DEX files names none of
/// them: say which with `file_id`.
pub fn select_class(
    dataset: &Dataset,
    descriptor: &str,
    file_id: Option<u32>,
) -> Result<LocatedClass, Failure> {
    if !dataset.has_decode_layers() {
        return Err(Failure::NotFound {
            what: "class is not defined in the selected DEX".to_owned(),
        });
    }
    let mut found = Vec::new();
    if let Some(matches) = dataset
        .hostlab_provider()
        .and_then(|provider| provider.find_defined_classes_by_descriptor(descriptor, file_id))
    {
        match matches.as_slice() {
            [] => {}
            [(fid, class_def_idx)] => {
                let dex = dataset.decode_dex(*fid)?;
                let class = dex.class_def_at(*class_def_idx).ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "service.decode",
                        "a located class disappeared from DEX definitions",
                    )
                })?;
                found.push((*fid, class));
            }
            many => {
                for &(fid, _) in many {
                    found.push((fid, 0));
                }
            }
        }
    } else {
        for fid in dex_file_range(dataset.dex_count(), file_id) {
            let dex = dataset.decode_dex(fid)?;
            for class in dex.find_classes_by_descriptor(descriptor) {
                found.push((fid, class));
            }
        }
    }
    match found.as_slice() {
        [] => Err(Failure::NotFound {
            what: "class is not defined in the selected DEX".to_owned(),
        }),
        [(file_id, class)] => Ok(LocatedClass {
            file_id: *file_id,
            class: *class,
        }),
        many => {
            let ids: Vec<u32> = many.iter().map(|(fid, _)| *fid).collect();
            Err(resolve_duplicate_or_ambiguous(
                &ids,
                "a DEX defines the same class more than once",
            ))
        }
    }
}

/// One page of a class's methods: `limit` methods from `offset`, or fewer at the end. An
/// offset past the number of methods is an error; one equal to it is an empty last page.
pub fn class_page(
    dataset: &Dataset,
    class: LocatedClass,
    offset: u64,
    limit: u64,
) -> MddResult<ClassPage> {
    let dex = dataset.decode_dex(class.file_id)?;
    let definitions = dex.definitions.definitions();
    let class_def = &definitions.classes[class.class];
    let all = dex.method_positions_for_class(class_def.class_def_idx);
    let total = all.len() as u64;
    if offset > total {
        return Err(MddError::new(
            ErrorCode::InvalidArgument,
            "service.decode",
            METHOD_OFFSET_PAST_END,
        )
        .detail("method_offset", offset.to_string())
        .detail("total_methods", total.to_string()));
    }
    // `offset <= total <= usize::MAX`
    let start = offset as usize;
    let end = start.saturating_add(usize::try_from(limit).unwrap_or(usize::MAX));
    let methods = all[start..end.min(all.len())]
        .iter()
        .map(|&definition| Located {
            file_id: class.file_id,
            method_idx: definitions.method_definitions[definition].method_idx,
            definition,
        })
        .collect();
    let mut interfaces: Vec<_> = definitions
        .interfaces
        .iter()
        .filter(|row| row.class_def_idx == class_def.class_def_idx)
        .collect();
    interfaces.sort_by_key(|row| row.ordinal);
    Ok(ClassPage {
        file_id: class.file_id,
        class_def_idx: class_def.class_def_idx,
        descriptor: class_def.descriptor.clone(),
        access_flags: class_def.access_flags,
        superclass: class_def.superclass_descriptor.clone(),
        source_file: class_def
            .source_file
            .as_ref()
            .map(|text| String::from_utf16_lossy(&text.utf16_units)),
        interfaces: interfaces
            .iter()
            .map(|row| row.interface_descriptor.clone())
            .collect(),
        static_fields: class_def.static_fields_count,
        instance_fields: class_def.instance_fields_count,
        total_methods: total,
        method_offset: offset,
        methods,
    })
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
    match selector {
        Selector::Key {
            file_id,
            method_idx,
        } => {
            if !dataset.has_decode_layers() || (file_id as usize) >= dataset.dex_count() {
                return Err(Failure::NotFound {
                    what: format!("file_id {file_id} is not in this dataset"),
                });
            }
            let dex = dataset.decode_dex(file_id)?;
            let definition = dex
                .find_method_def_by_idx(method_idx)
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
            if !dataset.has_decode_layers() {
                return Err(Failure::NotFound {
                    what: format!("method {descriptor} is not defined in this dataset"),
                });
            }
            let mut found = Vec::new();
            if let Some(matches) = dataset.hostlab_provider().and_then(|provider| {
                provider.find_defined_methods_by_descriptor(descriptor, file_id)
            }) {
                match matches.as_slice() {
                    [] => {}
                    [(fid, midx)] => {
                        let dex = dataset.decode_dex(*fid)?;
                        let position = dex
                            .find_method_def_by_idx(*midx)
                            .ok_or_else(|| not_defined(*fid, *midx))?;
                        found.push((*fid, position));
                    }
                    many => {
                        for &(fid, _) in many {
                            found.push((fid, 0));
                        }
                    }
                }
            } else {
                for fid in dex_file_range(dataset.dex_count(), file_id) {
                    let dex = dataset.decode_dex(fid)?;
                    for position in dex.find_method_defs_by_descriptor(descriptor) {
                        found.push((fid, position));
                    }
                }
            }
            match found.as_slice() {
                [] => Err(Failure::NotFound {
                    what: format!("method {descriptor} is not defined in this dataset"),
                }),
                [(file_id, position)] => {
                    let dex = dataset.decode_dex(*file_id)?;
                    let method_idx =
                        dex.definitions.definitions().method_definitions[*position].method_idx;
                    Ok(Located {
                        file_id: *file_id,
                        method_idx,
                        definition: *position,
                    })
                }
                many => {
                    let ids: Vec<u32> = many.iter().map(|(fid, _)| *fid).collect();
                    Err(resolve_duplicate_or_ambiguous(
                        &ids,
                        "a DEX defines the same method more than once",
                    ))
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
    /// What the text leaves out, and why (debug events at no instruction, annotation slots
    /// that cannot be placed, a missing annotation layer).
    pub report: ExtrasReport,
}

/// What a located method is, without its text: a method row of a class summary.
#[derive(Clone, Debug)]
pub struct Summary {
    pub file_id: u32,
    pub method_idx: u32,
    pub descriptor: String,
    pub access_flags: u32,
    pub declaration: String,
    pub registers: Option<u16>,
    pub code_units: Option<u32>,
    pub try_count: Option<u16>,
}

/// The facts of the located method that need no text. A method without a body has `None`
/// for registers, code units and tries, as opposed to a body that is empty.
pub fn summarize(dataset: &Dataset, located: Located) -> MddResult<Summary> {
    let layers = dataset.layers().ok_or_else(|| {
        MddError::new(
            ErrorCode::InternalFault,
            "service.decode",
            "a located file_id vanished",
        )
    })?;
    let dex = dataset.decode_dex(located.file_id)?;
    let definitions = dex.definitions.definitions();
    let definition = &definitions.method_definitions[located.definition];
    let reference = &definitions.method_references[located.method_idx as usize];
    let code_item = dex.decode_code_item(layers, &definition.body, false)?;
    let code = code_item.as_ref();
    Ok(Summary {
        file_id: located.file_id,
        method_idx: located.method_idx,
        descriptor: reference.descriptor.clone(),
        access_flags: definition.access_flags,
        declaration: method_declaration(reference, definition.access_flags),
        registers: code.map(|c| c.registers_size),
        code_units: code.map(|c| c.insns_size_code_units),
        try_count: code
            .map(|c| {
                u16::try_from(c.tries.len()).map_err(|_| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "service.decode",
                        "a code item has too many tries",
                    )
                })
            })
            .transpose()?,
    })
}

/// Render the located method.
pub fn render(dataset: &Dataset, located: Located, limits: SmaliLimits) -> MddResult<Decoded> {
    let layers = dataset.layers().ok_or_else(|| {
        MddError::new(
            ErrorCode::InternalFault,
            "service.decode",
            "a located file_id vanished",
        )
    })?;
    let dex = dataset.decode_dex(located.file_id)?;
    let definitions = dex.definitions.definitions();
    let definition = &definitions.method_definitions[located.definition];
    let decoded = dex.decode_code_item(layers, &definition.body, true)?;
    let class_def = dex
        .class_def_at(definition.class_def_idx)
        .map(|pos| &definitions.classes[pos]);
    let skip_annotations = matches!(dex.annotations_validation, LayerValidation::Valid(()))
        && class_def.is_some_and(|c| c.annotations_byte_offset.is_none());
    let options = if skip_annotations {
        SmaliOptions {
            annotations: false,
            parameters: true,
            debug: true,
        }
    } else {
        SmaliOptions::default()
    };
    let (occurrence, index) = dex.annotations_parts(skip_annotations);
    let view = FullMethodView {
        method: MethodView {
            metadata: &dex.metadata,
            definitions,
            definition,
            code: decoded.as_ref(),
        },
        annotations: occurrence
            .annotations
            .as_deref()
            .zip(index.annotation_index.as_ref()),
    };
    let full = render_method_full(&view, limits, options)?;
    Ok(Decoded {
        file_id: located.file_id,
        method_idx: located.method_idx,
        descriptor: definitions.method_references[located.method_idx as usize]
            .descriptor
            .clone(),
        access_flags: definition.access_flags,
        rendered: full.rendered,
        report: full.report,
    })
}

/// The text of a class without its methods: declaration, superclass, source file, interfaces,
/// class annotations and fields with their initial values.
pub fn render_class_text(dataset: &Dataset, class: LocatedClass) -> MddResult<RenderedClass> {
    let dex = dataset.decode_dex(class.file_id)?;
    let definitions = dex.definitions.definitions();
    let (occurrence, index) = dex.annotations_parts(false);
    let view = ClassView {
        metadata: &dex.metadata,
        definitions,
        class: &definitions.classes[class.class],
        annotations: occurrence
            .annotations
            .as_deref()
            .zip(index.annotation_index.as_ref()),
    };
    render_class(&view, ClassLimits::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dialect, InputRequest};
    use mdd_facts::smali_required::{MethodExtras, render_method_with};
    use mdd_session::ResourceLimits;
    use mdd_sql::control::SqlLimits;
    use std::path::PathBuf;

    const F: &str = "Ldecode/K;->f(IJLjava/lang/String;)V";
    const PING: &str = "Ldecode/Marker;->ping()V";

    fn class_dataset() -> Dataset {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/decode/generated/decode-class.dex");
        Dataset::open(
            &[InputRequest { path, kind: None }],
            Dialect::DexSql010,
            ResourceLimits::default(),
            SqlLimits::default(),
        )
        .expect("the fixture opens")
    }

    /// The method rendered with the lines a caller adds, through the hook and nothing else.
    fn with_extras(
        dataset: &Dataset,
        descriptor: &str,
        extras: &MethodExtras,
    ) -> MddResult<RenderedMethod> {
        let located = select(
            dataset,
            Selector::Descriptor {
                descriptor,
                file_id: None,
            },
        )
        .expect("the method is defined");
        let dex = dataset.decode_dex(located.file_id)?;
        let definitions = dex.definitions.definitions();
        let definition = &definitions.method_definitions[located.definition];
        let decoded = dex.decode_code_item(dataset.layers().unwrap(), &definition.body, true)?;
        let view = MethodView {
            metadata: &dex.metadata,
            definitions,
            definition,
            code: decoded.as_ref(),
        };
        render_method_with(&view, SmaliLimits::default(), extras)
    }

    fn lines(at: &[(u32, &str)]) -> std::collections::BTreeMap<u32, Vec<String>> {
        at.iter()
            .map(|(address, line)| (*address, vec![(*line).to_owned()]))
            .collect()
    }

    #[test]
    fn lines_given_to_the_renderer_go_where_they_were_asked() {
        let dataset = class_dataset();
        let plain = with_extras(&dataset, F, &MethodExtras::default()).unwrap();
        let extras = MethodExtras {
            header: vec!["    HEADER".to_owned()],
            // 0 is the first instruction, 1 the second (a two-unit one), 8 the end of the code
            at_address: lines(&[(0, "    FIRST"), (1, "    SECOND"), (8, "    END")]),
        };
        let shown = with_extras(&dataset, F, &extras).unwrap().text;
        assert!(shown.contains("    .registers 6\n    HEADER\n\n    FIRST\n    const/4 v0, 0x1\n    SECOND\n    const-string v1, \"x\"\n"), "{shown}");
        assert!(
            shown.ends_with("    return-void\n    END\n.end method\n"),
            "{shown}"
        );
        // taking the added lines away gives the instruction text back, byte for byte
        let without: String = shown
            .lines()
            .filter(|line| !["    HEADER", "    FIRST", "    SECOND", "    END"].contains(line))
            .map(|line| format!("{line}\n"))
            .collect();
        assert_eq!(without, plain.text);
    }

    #[test]
    fn a_line_for_an_address_where_no_instruction_starts_is_refused_not_dropped() {
        let dataset = class_dataset();
        // 2 is the second unit of the const-string at 1; 4 is inside the invoke at 3..=5; 9 is past the code
        for address in [2u32, 4, 5, 9] {
            let extras = MethodExtras {
                header: Vec::new(),
                at_address: lines(&[(address, "    LOST")]),
            };
            let error = with_extras(&dataset, F, &extras).expect_err(&format!("address {address}"));
            assert_eq!(error.code, ErrorCode::InternalFault, "address {address}");
        }
        // one good address beside a bad one is still a refusal: the count of placed lines must match
        let extras = MethodExtras {
            header: Vec::new(),
            at_address: lines(&[(0, "    OK"), (2, "    LOST")]),
        };
        assert!(with_extras(&dataset, F, &extras).is_err());
    }

    #[test]
    fn a_method_without_code_takes_header_lines_and_no_address_lines() {
        let dataset = class_dataset();
        let header = MethodExtras {
            header: vec!["    NOTE".to_owned()],
            at_address: Default::default(),
        };
        assert_eq!(
            with_extras(&dataset, PING, &header).unwrap().text,
            ".method public abstract ping()V\n    NOTE\n.end method\n"
        );
        let address = MethodExtras {
            header: Vec::new(),
            at_address: lines(&[(0, "    LOST")]),
        };
        assert!(with_extras(&dataset, PING, &address).is_err());
    }

    #[test]
    fn a_class_pages_its_methods_in_method_idx_order_and_the_end_is_an_empty_page() {
        let dataset = class_dataset();
        let class = select_class(&dataset, "Ldecode/K;", None).expect("K is defined");
        let all = class_page(&dataset, class, 0, 50).unwrap();
        assert_eq!(all.total_methods, 6);
        let indexes: Vec<u32> = all.methods.iter().map(|m| m.method_idx).collect();
        assert!(
            indexes.windows(2).all(|pair| pair[0] < pair[1]),
            "{indexes:?}"
        );
        let tail = class_page(&dataset, class, 4, 50).unwrap();
        assert_eq!(tail.methods.len(), 2);
        assert_eq!(tail.methods[0].method_idx, indexes[4]);
        let end = class_page(&dataset, class, 6, 50).unwrap();
        assert!(end.methods.is_empty());
        let past = class_page(&dataset, class, 7, 50).unwrap_err();
        assert_eq!(past.message, METHOD_OFFSET_PAST_END);
        assert_eq!(class_page(&dataset, class, 0, 1).unwrap().methods.len(), 1);
    }

    #[test]
    fn a_class_that_is_only_referred_to_or_not_there_is_not_found() {
        let dataset = class_dataset();
        for descriptor in ["Ljava/lang/Object;", "Lnope/N;", "decode.K"] {
            assert!(matches!(
                select_class(&dataset, descriptor, None),
                Err(Failure::NotFound { .. })
            ));
        }
        assert!(matches!(
            select_class(&dataset, "Ldecode/K;", Some(3)),
            Err(Failure::NotFound { .. })
        ));
    }

    #[test]
    fn multi_dex_lazy_decode_loads_only_target_dex_and_matches_full_occurrence() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let dataset = Dataset::open(
            &[
                InputRequest {
                    path: base.join("decode/generated/decode-class.dex"),
                    kind: None,
                },
                InputRequest {
                    path: base.join("references/generated/classic-035.dex"),
                    kind: None,
                },
            ],
            Dialect::DexSql011,
            ResourceLimits::default(),
            SqlLimits::default(),
        )
        .expect("multi-dex dataset opens");

        // Missing descriptor is rejected directly via HostLabSqlProvider without loading any DEX.
        assert!(matches!(
            select(
                &dataset,
                Selector::Descriptor {
                    descriptor: "Lno/Such;->missing()V",
                    file_id: None,
                },
            ),
            Err(Failure::NotFound { .. })
        ));
        assert!(matches!(
            select_class(&dataset, "Lno/Such;", None),
            Err(Failure::NotFound { .. })
        ));
        assert_eq!(dataset.loaded_decode_dex_count(), 0);

        // Selecting and decoding one method/class on DEX 0 loads ONLY DEX 0, leaving DEX 1 untouched.
        let located = select(
            &dataset,
            Selector::Descriptor {
                descriptor: F,
                file_id: None,
            },
        )
        .expect("method F exists in DEX 0");
        assert_eq!(located.file_id, 0);
        assert_eq!(dataset.loaded_decode_dex_count(), 1);

        let lazy_decoded = render(&dataset, located, SmaliLimits::default()).unwrap();
        let lazy_summary = summarize(&dataset, located).unwrap();
        let class_loc = select_class(&dataset, "Ldecode/K;", None).unwrap();
        let lazy_page = class_page(&dataset, class_loc, 0, 50).unwrap();
        let lazy_class = render_class_text(&dataset, class_loc).unwrap();
        assert_eq!(dataset.loaded_decode_dex_count(), 1);
        assert_eq!(lazy_page.total_methods, 6);
        assert_eq!(lazy_summary.descriptor, F);

        // Verify byte-for-byte equivalence against full Occurrence + CodeFacts::decoded_item rendering.
        let occurrences = dataset.occurrences().unwrap();
        let occ = &occurrences[0];
        let defs = occ.definitions.definitions();
        let def = &defs.method_definitions[located.definition];
        let full_code = match &def.body {
            MethodBody::Present {
                code_byte_offset, ..
            } => {
                let code_facts = occ.code.as_ref().unwrap();
                let ordinal = code_facts
                    .items()
                    .iter()
                    .position(|item| item.data().raw_range.byte_offset.0 == code_byte_offset.0)
                    .unwrap();
                Some(code_facts.decoded_item(ordinal).unwrap().into_owned())
            }
            MethodBody::Abstract | MethodBody::Native => None,
        };
        let ann_idx = occ.annotations.as_deref().map(AnnotationIndex::build);
        let expected_full = render_method_full(
            &FullMethodView {
                method: MethodView {
                    metadata: &occ.metadata,
                    definitions: defs,
                    definition: def,
                    code: full_code.as_ref(),
                },
                annotations: occ.annotations.as_deref().zip(ann_idx.as_ref()),
            },
            SmaliLimits::default(),
            SmaliOptions::default(),
        )
        .unwrap();
        assert_eq!(lazy_decoded.rendered.text, expected_full.rendered.text);
        assert_eq!(lazy_decoded.report, expected_full.report);

        let expected_class = render_class(
            &ClassView {
                metadata: &occ.metadata,
                definitions: defs,
                class: &defs.classes[class_loc.class],
                annotations: occ.annotations.as_deref().zip(ann_idx.as_ref()),
            },
            ClassLimits::default(),
        )
        .unwrap();
        assert_eq!(lazy_class, expected_class);
    }
}
