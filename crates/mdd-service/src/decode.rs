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
    DexHeader, DexRange, MapItem, TableInfo,
    annotations::AnnotationLimits,
    checked_reader::CheckedReader,
    definitions::{MethodBody, MethodReference},
    instructions::{
        CatchHandler, CodeItem, CodeItemDecoder, CodeLimits, DebugAddressScope, DebugEvent,
        Payload, PayloadData, ReferenceKind, ReferenceOperand, TryItem,
    },
    strings::{DexText, StringLimits, decode_mutf8, read_uleb128},
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
use mdd_input::archive::MemberBlob;
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Write as _,
    sync::{Arc, Mutex, OnceLock},
};

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
    fast_path: bool,
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
            fast_path: false,
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
            if !dataset.is_decode_dex_initialized(file_id) {
                match fast_locate_method(dataset, file_id, method_idx)? {
                    FastLocate::Found => {
                        return Ok(Located {
                            file_id,
                            method_idx,
                            definition: 0,
                            fast_path: true,
                        });
                    }
                    FastLocate::NotDefined => return Err(not_defined(file_id, method_idx)),
                    FastLocate::Fallback => {}
                }
            }
            let dex = dataset.decode_dex(file_id)?;
            let definition = dex
                .find_method_def_by_idx(method_idx)
                .ok_or_else(|| not_defined(file_id, method_idx))?;
            Ok(Located {
                file_id,
                method_idx,
                definition,
                fast_path: false,
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
                        fast_path: false,
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

fn build_summary(
    file_id: u32,
    method_idx: u32,
    reference: &MethodReference,
    access_flags: u32,
    code: Option<&CodeItem>,
) -> MddResult<Summary> {
    Ok(Summary {
        file_id,
        method_idx,
        descriptor: reference.descriptor.clone(),
        access_flags,
        declaration: method_declaration(reference, access_flags),
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
    if located.fast_path
        && !dataset.is_decode_dex_initialized(located.file_id)
        && let Some(summary) =
            fast_summarize_method(dataset, layers, located.file_id, located.method_idx)?
    {
        return Ok(summary);
    }
    let dex = dataset.decode_dex(located.file_id)?;
    let definitions = dex.definitions.definitions();
    let def_pos = if located.fast_path {
        dex.find_method_def_by_idx(located.method_idx)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "service.decode",
                    "a located method disappeared from DEX definitions",
                )
            })?
    } else {
        located.definition
    };
    let definition = &definitions.method_definitions[def_pos];
    let reference = &definitions.method_references[located.method_idx as usize];
    let code_item = dex.decode_code_item(layers, &definition.body, false)?;
    build_summary(
        located.file_id,
        located.method_idx,
        reference,
        definition.access_flags,
        code_item.as_ref(),
    )
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
    if located.fast_path
        && !dataset.is_decode_dex_initialized(located.file_id)
        && let Some(decoded) =
            fast_render_method(dataset, layers, located.file_id, located.method_idx, limits)?
    {
        return Ok(decoded);
    }
    let dex = dataset.decode_dex(located.file_id)?;
    let definitions = dex.definitions.definitions();
    let def_pos = if located.fast_path {
        dex.find_method_def_by_idx(located.method_idx)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "service.decode",
                    "a located method disappeared from DEX definitions",
                )
            })?
    } else {
        located.definition
    };
    let definition = &definitions.method_definitions[def_pos];
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

// ---- Single-method fast path --------------------------------------------------

/// Holds a DEX member lease across consecutive single-method calls so an unheld spilled
/// archive member is decompressed and verified at most once, releasing when dropped if this
/// guard opened the lease.
pub struct DexLeaseGuard<'a> {
    blob: &'a MemberBlob,
    bytes: Arc<[u8]>,
    release_on_drop: bool,
}

impl DexLeaseGuard<'_> {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn arc_bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }
}

impl Drop for DexLeaseGuard<'_> {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.blob.release();
        }
    }
}

/// Pin the raw DEX bytes of `file_id` for the duration of a single-method operation when
/// `LazyDexDecode` has not yet been initialized for `file_id`.
pub fn pin_dex_lease(dataset: &Dataset, file_id: u32) -> Option<DexLeaseGuard<'_>> {
    if dataset.is_decode_dex_initialized(file_id) {
        return None;
    }
    let candidate = dataset.dex_candidate(file_id)?;
    let release_on_drop = candidate.blob.held_lease().is_none();
    let bytes = candidate.blob.try_lease().ok()?;
    Some(DexLeaseGuard {
        blob: &candidate.blob,
        bytes,
        release_on_drop,
    })
}

fn map_item_name(kind: u16) -> Option<&'static str> {
    Some(match kind {
        0x0000 => "header",
        0x0001 => "string_ids",
        0x0002 => "type_ids",
        0x0003 => "proto_ids",
        0x0004 => "field_ids",
        0x0005 => "method_ids",
        0x0006 => "class_defs",
        0x0007 => "call_site_ids",
        0x0008 => "method_handles",
        0x1000 => "map_list",
        0x1001 => "type_list",
        0x1002 => "annotation_set_ref_list",
        0x1003 => "annotation_set",
        0x2000 => "class_data",
        0x2001 => "code",
        0x2002 => "string_data",
        0x2003 => "debug_info",
        0x2004 => "annotation",
        0x2005 => "encoded_array",
        0x2006 => "annotations_directory",
        0xf000 => "hiddenapi_class_data",
        _ => return None,
    })
}

struct FastDexLayout {
    header: DexHeader,
    file_size: u64,
    string_ids_count: u32,
    string_ids_off: u64,
    type_ids_count: u32,
    type_ids_off: u64,
    proto_ids_count: u32,
    proto_ids_off: u64,
    field_ids_count: u32,
    field_ids_off: u64,
    method_ids_count: u32,
    method_ids_off: u64,
    class_defs_count: u32,
    class_defs_off: u64,
}

impl FastDexLayout {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let reader = CheckedReader::new(bytes);
        let magic = reader.range(0, 8).ok()?;
        if &magic[..4] != b"dex\n" || magic[7] != 0 {
            return None;
        }
        let version = match &magic[4..7] {
            b"035" => "035",
            b"037" => "037",
            b"038" => "038",
            b"039" => "039",
            b"040" => "040",
            _ => return None,
        };
        reader.range(0, 112).ok()?;
        if reader.u32(40).ok()? != 0x1234_5678 {
            return None;
        }
        let file_size = u64::from(reader.u32(32).ok()?);
        if file_size != reader.len() || reader.u32(36).ok()? != 112 {
            return None;
        }
        let data_size = reader.u32(104).ok()?;
        let data_off = reader.u32(108).ok()?;
        if data_size == 0
            || data_off < 112
            || !data_off.is_multiple_of(4)
            || !data_size.is_multiple_of(4)
        {
            return None;
        }
        reader
            .range(u64::from(data_off), u64::from(data_size))
            .ok()?;
        let data_end = u64::from(data_off).checked_add(u64::from(data_size))?;

        let table_span = |header_off: u64, stride: u64| -> Option<(u32, u64)> {
            let count = reader.u32(header_off).ok()?;
            let off = reader.u32(header_off + 4).ok()?;
            if count == 0 {
                if off != 0 {
                    return None;
                }
                return Some((0, 0));
            }
            if !off.is_multiple_of(4) {
                return None;
            }
            let start = u64::from(off);
            reader.array(start, u64::from(count), stride).ok()?;
            if start.checked_add(u64::from(count).checked_mul(stride)?)? > u64::from(data_off) {
                return None;
            }
            Some((count, start))
        };

        let (string_ids_count, string_ids_off) = table_span(56, 4)?;
        let (type_ids_count, type_ids_off) = table_span(64, 4)?;
        let (proto_ids_count, proto_ids_off) = table_span(72, 12)?;
        let (field_ids_count, field_ids_off) = table_span(80, 8)?;
        let (method_ids_count, method_ids_off) = table_span(88, 8)?;
        let (class_defs_count, class_defs_off) = table_span(96, 32)?;
        if type_ids_count > 65535 || proto_ids_count > 65535 {
            return None;
        }

        let map_off = reader.u32(52).ok()?;
        if !map_off.is_multiple_of(4)
            || map_off < data_off
            || u64::from(map_off).checked_add(4)? > data_end
        {
            return None;
        }
        let map_count = reader.u32(u64::from(map_off)).ok()?;
        if map_count == 0 || map_count > 21 {
            return None;
        }
        let map_len = 4u64.checked_add(u64::from(map_count) * 12)?;
        if u64::from(map_off).checked_add(map_len)? > data_end {
            return None;
        }
        let mut map = Vec::with_capacity(map_count as usize);
        for ordinal in 0..map_count {
            let at = u64::from(map_off) + 4 + u64::from(ordinal) * 12;
            let type_code = reader.u16(at).ok()?;
            let count = reader.u32(at + 4).ok()?;
            let byte_offset = reader.u32(at + 8).ok()?;
            let name = map_item_name(type_code)?;
            if u64::from(byte_offset) > file_size {
                return None;
            }
            map.push(MapItem {
                type_code,
                name: name.to_owned(),
                count,
                byte_offset: DecimalU64(u64::from(byte_offset)),
            });
        }

        let tables = [
            ("string_ids", string_ids_count, string_ids_off, 4u64),
            ("type_ids", type_ids_count, type_ids_off, 4),
            ("proto_ids", proto_ids_count, proto_ids_off, 12),
            ("field_ids", field_ids_count, field_ids_off, 8),
            ("method_ids", method_ids_count, method_ids_off, 8),
            ("class_defs", class_defs_count, class_defs_off, 32),
        ]
        .into_iter()
        .map(|(name, count, offset, stride)| TableInfo {
            name: name.to_owned(),
            count,
            range: DexRange {
                byte_offset: DecimalU64(offset),
                byte_length: DecimalU64(u64::from(count) * stride),
            },
        })
        .collect();

        let header = DexHeader {
            version: version.to_owned(),
            file_size: DecimalU64(file_size),
            header_range: DexRange {
                byte_offset: DecimalU64(0),
                byte_length: DecimalU64(112),
            },
            data_range: DexRange {
                byte_offset: DecimalU64(u64::from(data_off)),
                byte_length: DecimalU64(u64::from(data_size)),
            },
            link_range: None,
            endian: "little".to_owned(),
            declared_checksum: 0,
            checksum_verified: true,
            declared_signature_sha1: String::new(),
            signature_verified: true,
            tables,
            map,
            validated_scope: String::new(),
            full_dex_validation_complete: true,
        };

        Some(Self {
            header,
            file_size,
            string_ids_count,
            string_ids_off,
            type_ids_count,
            type_ids_off,
            proto_ids_count,
            proto_ids_off,
            field_ids_count,
            field_ids_off,
            method_ids_count,
            method_ids_off,
            class_defs_count,
            class_defs_off,
        })
    }
}

struct FastMethodEntry {
    access_flags: u32,
    body: MethodBody,
    annotations_off: u32,
}

enum FastMethodMatch {
    Found(FastMethodEntry),
    NotDefined,
    Fallback,
}

enum FastLocate {
    Found,
    NotDefined,
    Fallback,
}

fn lease_for_fast_path<'a>(
    dataset: &'a Dataset,
    layers: &'a LayerBuilder,
    file_id: u32,
) -> MddResult<Option<(DexLeaseGuard<'a>, ValidatedCodeMeta, LayerValidation<()>)>> {
    let Ok(position) = usize::try_from(file_id) else {
        return Ok(None);
    };
    let LayerValidation::Valid(meta) = layers.code_validation(position) else {
        return Ok(None);
    };
    let annotations_validation = layers.annotations_validation(position);
    if matches!(annotations_validation, LayerValidation::Unknown) {
        return Ok(None);
    }
    let Some(candidate) = dataset.dex_candidate(file_id) else {
        return Ok(None);
    };
    let release_on_drop = candidate.blob.held_lease().is_none();
    let bytes = candidate.blob.try_lease()?;
    Ok(Some((
        DexLeaseGuard {
            blob: &candidate.blob,
            bytes,
            release_on_drop,
        },
        meta,
        annotations_validation,
    )))
}

fn read_uleb_cursor(bytes: &[u8], cursor: &mut u64, end: u64) -> Option<u32> {
    let (value, len) = read_uleb128(bytes, *cursor, end).ok()?;
    *cursor = cursor.checked_add(len)?;
    Some(value)
}

fn find_method_entry(
    layout: &FastDexLayout,
    bytes: &[u8],
    target_method_idx: u32,
) -> FastMethodMatch {
    if target_method_idx >= layout.method_ids_count {
        return FastMethodMatch::NotDefined;
    }
    let reader = CheckedReader::new(bytes);
    let Ok(class_idx) = reader.u16(layout.method_ids_off + u64::from(target_method_idx) * 8) else {
        return FastMethodMatch::Fallback;
    };
    let wanted_class = u32::from(class_idx);
    let mut found_class_def: Option<(u32, u32)> = None;
    for i in 0..layout.class_defs_count {
        let at = layout.class_defs_off + u64::from(i) * 32;
        let Ok(def_class_idx) = reader.u32(at) else {
            return FastMethodMatch::Fallback;
        };
        if def_class_idx == wanted_class {
            if found_class_def.is_some() {
                return FastMethodMatch::Fallback;
            }
            let Ok(annotations_off) = reader.u32(at + 20) else {
                return FastMethodMatch::Fallback;
            };
            let Ok(class_data_off) = reader.u32(at + 24) else {
                return FastMethodMatch::Fallback;
            };
            found_class_def = Some((annotations_off, class_data_off));
        }
    }
    let Some((annotations_off, class_data_off)) = found_class_def else {
        return FastMethodMatch::NotDefined;
    };
    if class_data_off == 0 {
        return FastMethodMatch::NotDefined;
    }

    let mut cursor = u64::from(class_data_off);
    let end = layout.file_size;
    let Some(static_fields) = read_uleb_cursor(bytes, &mut cursor, end) else {
        return FastMethodMatch::Fallback;
    };
    let Some(instance_fields) = read_uleb_cursor(bytes, &mut cursor, end) else {
        return FastMethodMatch::Fallback;
    };
    let Some(direct_methods) = read_uleb_cursor(bytes, &mut cursor, end) else {
        return FastMethodMatch::Fallback;
    };
    let Some(virtual_methods) = read_uleb_cursor(bytes, &mut cursor, end) else {
        return FastMethodMatch::Fallback;
    };
    let field_ulebs = (u64::from(static_fields) + u64::from(instance_fields)) * 2;
    for _ in 0..field_ulebs {
        if read_uleb_cursor(bytes, &mut cursor, end).is_none() {
            return FastMethodMatch::Fallback;
        }
    }

    for (is_direct, count) in [(true, direct_methods), (false, virtual_methods)] {
        let mut prev = 0u32;
        for ordinal in 0..count {
            let Some(delta) = read_uleb_cursor(bytes, &mut cursor, end) else {
                return FastMethodMatch::Fallback;
            };
            let Some(flags) = read_uleb_cursor(bytes, &mut cursor, end) else {
                return FastMethodMatch::Fallback;
            };
            let Some(code_off) = read_uleb_cursor(bytes, &mut cursor, end) else {
                return FastMethodMatch::Fallback;
            };
            if ordinal > 0 && delta == 0 {
                return FastMethodMatch::Fallback;
            }
            let Some(midx) = prev.checked_add(delta) else {
                return FastMethodMatch::Fallback;
            };
            prev = midx;
            if midx == target_method_idx {
                if (flags & (8 | 2 | 0x10000) != 0) != is_direct {
                    return FastMethodMatch::Fallback;
                }
                let is_abstract = flags & 0x400 != 0;
                let is_native = flags & 0x100 != 0;
                if (is_abstract && is_native)
                    || ((is_abstract || is_native) && code_off != 0)
                    || (!(is_abstract || is_native) && code_off == 0)
                {
                    return FastMethodMatch::Fallback;
                }
                let body = if is_abstract {
                    MethodBody::Abstract
                } else if is_native {
                    MethodBody::Native
                } else {
                    if !code_off.is_multiple_of(4) {
                        return FastMethodMatch::Fallback;
                    }
                    MethodBody::Present {
                        code_byte_offset: DecimalU64(u64::from(code_off)),
                        declared_insns_size: 0,
                    }
                };
                return FastMethodMatch::Found(FastMethodEntry {
                    access_flags: flags,
                    body,
                    annotations_off,
                });
            }
        }
    }
    FastMethodMatch::NotDefined
}

fn fast_locate_method(dataset: &Dataset, file_id: u32, method_idx: u32) -> MddResult<FastLocate> {
    let Some(layers) = dataset.layers() else {
        return Ok(FastLocate::Fallback);
    };
    let Some((guard, _meta, _ann)) = lease_for_fast_path(dataset, layers, file_id)? else {
        return Ok(FastLocate::Fallback);
    };
    let Some(layout) = FastDexLayout::parse(guard.bytes()) else {
        return Ok(FastLocate::Fallback);
    };
    Ok(
        match find_method_entry(&layout, guard.bytes(), method_idx) {
            FastMethodMatch::Found(_) => FastLocate::Found,
            FastMethodMatch::NotDefined => FastLocate::NotDefined,
            FastMethodMatch::Fallback => FastLocate::Fallback,
        },
    )
}

fn method_has_annotations(
    bytes: &[u8],
    annotations_off: u32,
    target_method_idx: u32,
) -> Option<bool> {
    if annotations_off == 0 {
        return Some(false);
    }
    if !annotations_off.is_multiple_of(4) {
        return None;
    }
    let reader = CheckedReader::new(bytes);
    let at = u64::from(annotations_off);
    reader.range(at, 16).ok()?;
    let fields_size = u64::from(reader.u32(at + 4).ok()?);
    let methods_size = u64::from(reader.u32(at + 8).ok()?);
    let parameters_size = u64::from(reader.u32(at + 12).ok()?);
    let entries_bytes = fields_size
        .checked_add(methods_size)?
        .checked_add(parameters_size)?
        .checked_mul(8)?;
    reader.range(at + 16, entries_bytes).ok()?;
    let mut cursor = at + 16 + fields_size * 8;
    for _ in 0..methods_size {
        if reader.u32(cursor).ok()? == target_method_idx {
            return Some(true);
        }
        cursor += 8;
    }
    for _ in 0..parameters_size {
        if reader.u32(cursor).ok()? == target_method_idx {
            return Some(true);
        }
        cursor += 8;
    }
    Some(false)
}

fn decode_fast_code_item(
    guard: &DexLeaseGuard<'_>,
    layout: &FastDexLayout,
    meta: &ValidatedCodeMeta,
    body: &MethodBody,
    with_debug: bool,
) -> MddResult<Option<CodeItem>> {
    let MethodBody::Present {
        code_byte_offset, ..
    } = body
    else {
        return Ok(None);
    };
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
    let starts: Vec<u64> = if with_debug {
        meta.debug_starts.iter().copied().map(u64::from).collect()
    } else {
        Vec::new()
    };
    let mut decoder = CodeItemDecoder::new(
        guard.arc_bytes(),
        layout.header.clone(),
        CodeLimits::default(),
        &starts,
    );
    let item = if with_debug {
        decoder.decode(code_byte_offset.0)?
    } else {
        decoder.decode_instructions(code_byte_offset.0)?
    };
    Ok(Some(item))
}

struct FastPools<'a> {
    bytes: &'a [u8],
    reader: CheckedReader<'a>,
    layout: &'a FastDexLayout,
    strings: HashMap<u32, DexText>,
    types: HashMap<u32, String>,
    protos: HashMap<u32, (String, String, Vec<String>)>,
    fields: HashMap<u32, String>,
    methods: HashMap<u32, MethodReference>,
}

impl<'a> FastPools<'a> {
    fn new(bytes: &'a [u8], layout: &'a FastDexLayout) -> Self {
        Self {
            bytes,
            reader: CheckedReader::new(bytes),
            layout,
            strings: HashMap::new(),
            types: HashMap::new(),
            protos: HashMap::new(),
            fields: HashMap::new(),
            methods: HashMap::new(),
        }
    }

    fn dex_text(&mut self, string_idx: u32) -> Option<&DexText> {
        if !self.strings.contains_key(&string_idx) {
            if string_idx >= self.layout.string_ids_count {
                return None;
            }
            let off = u64::from(
                self.reader
                    .u32(self.layout.string_ids_off + u64::from(string_idx) * 4)
                    .ok()?,
            );
            let end = self.layout.file_size;
            let (declared, prefix_len) = read_uleb128(self.bytes, off, end).ok()?;
            let (text, _) = decode_mutf8(
                self.bytes,
                off + prefix_len,
                end,
                declared,
                StringLimits::default().max_string_bytes,
            )
            .ok()?;
            self.strings.insert(string_idx, text);
        }
        self.strings.get(&string_idx)
    }

    fn string_literal(&mut self, string_idx: u32) -> Option<String> {
        let text = self.dex_text(string_idx)?;
        let mut out = String::new();
        push_string_literal_fast(&mut out, &text.utf16_units);
        Some(out)
    }

    fn type_descriptor(&mut self, type_idx: u32) -> Option<String> {
        if let Some(cached) = self.types.get(&type_idx) {
            return Some(cached.clone());
        }
        if type_idx >= self.layout.type_ids_count {
            return None;
        }
        let string_idx = self
            .reader
            .u32(self.layout.type_ids_off + u64::from(type_idx) * 4)
            .ok()?;
        let desc = self.dex_text(string_idx)?.strict_utf8().ok()?;
        self.types.insert(type_idx, desc.clone());
        Some(desc)
    }

    fn proto_parts(&mut self, proto_idx: u32) -> Option<(String, String, Vec<String>)> {
        if let Some(cached) = self.protos.get(&proto_idx) {
            return Some(cached.clone());
        }
        if proto_idx >= self.layout.proto_ids_count {
            return None;
        }
        let at = self.layout.proto_ids_off + u64::from(proto_idx) * 12;
        let return_type_idx = self.reader.u32(at + 4).ok()?;
        let parameters_off = self.reader.u32(at + 8).ok()?;
        let ret = self.type_descriptor(return_type_idx)?;
        let mut params = Vec::new();
        if parameters_off != 0 {
            let list_off = u64::from(parameters_off);
            if !list_off.is_multiple_of(4) {
                return None;
            }
            let count = self.reader.u32(list_off).ok()?;
            let list_len = u64::from(count).checked_mul(2)?;
            self.reader.range(list_off + 4, list_len).ok()?;
            let capacity = usize::try_from(count).ok()?;
            params.reserve(capacity);
            for i in 0..count {
                let tidx = u32::from(self.reader.u16(list_off + 4 + u64::from(i) * 2).ok()?);
                params.push(self.type_descriptor(tidx)?);
            }
        }
        let mut descriptor = String::from("(");
        for param in &params {
            descriptor.push_str(param);
        }
        descriptor.push(')');
        descriptor.push_str(&ret);
        let value = (descriptor, ret, params);
        self.protos.insert(proto_idx, value.clone());
        Some(value)
    }

    fn field_descriptor(&mut self, field_idx: u32) -> Option<String> {
        if let Some(cached) = self.fields.get(&field_idx) {
            return Some(cached.clone());
        }
        if field_idx >= self.layout.field_ids_count {
            return None;
        }
        let at = self.layout.field_ids_off + u64::from(field_idx) * 8;
        let class_idx = u32::from(self.reader.u16(at).ok()?);
        let type_idx = u32::from(self.reader.u16(at + 2).ok()?);
        let name_idx = self.reader.u32(at + 4).ok()?;
        let owner = self.type_descriptor(class_idx)?;
        let ty = self.type_descriptor(type_idx)?;
        let name = self.dex_text(name_idx)?.strict_utf8().ok()?;
        let formatted = format!("{owner}->{name}:{ty}");
        self.fields.insert(field_idx, formatted.clone());
        Some(formatted)
    }

    fn method_reference(&mut self, method_idx: u32) -> Option<MethodReference> {
        if let Some(cached) = self.methods.get(&method_idx) {
            return Some(cached.clone());
        }
        if method_idx >= self.layout.method_ids_count {
            return None;
        }
        let at = self.layout.method_ids_off + u64::from(method_idx) * 8;
        let class_idx = u32::from(self.reader.u16(at).ok()?);
        let proto_idx = u32::from(self.reader.u16(at + 2).ok()?);
        let name_idx = self.reader.u32(at + 4).ok()?;
        let owner = self.type_descriptor(class_idx)?;
        let name = self.dex_text(name_idx)?.strict_utf8().ok()?;
        let (proto_desc, ret, params) = self.proto_parts(proto_idx)?;
        let mut descriptor = String::with_capacity(owner.len() + name.len() + proto_desc.len() + 2);
        descriptor.push_str(&owner);
        descriptor.push_str("->");
        descriptor.push_str(&name);
        descriptor.push_str(&proto_desc);
        let reference = MethodReference {
            method_idx,
            class_idx,
            proto_idx,
            name_idx,
            class_descriptor: owner,
            method_name: name,
            descriptor,
            return_descriptor: ret,
            parameter_descriptors: params,
            encoded_range: DexRange {
                byte_offset: DecimalU64(at),
                byte_length: DecimalU64(8),
            },
        };
        self.methods.insert(method_idx, reference.clone());
        Some(reference)
    }
}

fn smali_fault(message: &str) -> MddError {
    MddError::new(ErrorCode::InternalFault, "facts.smali", message)
}

fn smali_too_large(limit: u64) -> MddError {
    MddError::new(
        ErrorCode::QuotaExceeded,
        "facts.smali",
        "the rendered text is over the byte budget",
    )
    .detail("budget", "max_text_bytes")
    .detail("limit", limit.to_string())
}

fn hex_signed_fast(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{value:x}")
    }
}

fn push_string_literal_fast(out: &mut String, units: &[u16]) {
    out.push('"');
    for &unit in units {
        match unit {
            0x22 => out.push_str("\\\""),
            0x27 => out.push_str("\\'"),
            0x5c => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0a => out.push_str("\\n"),
            0x0c => out.push_str("\\f"),
            0x0d => out.push_str("\\r"),
            0x20..=0x7e => out.push(char::from(unit as u8)),
            other => {
                let _ = write!(out, "\\u{other:04x}");
            }
        }
    }
    out.push('"');
}

fn format_fast_register(number: u16, first_parameter: u16) -> String {
    if number >= first_parameter {
        format!("p{}", number - first_parameter)
    } else {
        format!("v{number}")
    }
}

fn fast_debug_line(
    event: &DebugEvent,
    pools: &mut FastPools<'_>,
    first_parameter: u16,
) -> MddResult<Option<String>> {
    let need_register = || {
        event
            .register
            .ok_or_else(|| smali_fault("a debug event that names a register has none"))
    };
    let line = match event.opcode {
        0..=2 => return Ok(None),
        3 | 4 => {
            let reg = format_fast_register(need_register()?, first_parameter);
            let name = match event.name_idx {
                Some(index) => pools.string_literal(index).ok_or_else(|| {
                    smali_fault("an annotation value names a string the facts do not hold")
                })?,
                None => "null".to_owned(),
            };
            let ty = match event.type_idx {
                Some(index) => pools
                    .type_descriptor(index)
                    .ok_or_else(|| smali_fault("a local names a type the facts do not hold"))?,
                None => "null".to_owned(),
            };
            let mut line = format!(".local {reg}, {name}:{ty}");
            if let Some(index) = event.signature_idx {
                let sig = pools.string_literal(index).ok_or_else(|| {
                    smali_fault("an annotation value names a string the facts do not hold")
                })?;
                line.push_str(", ");
                line.push_str(&sig);
            }
            line
        }
        5 => format!(
            ".end local {}",
            format_fast_register(need_register()?, first_parameter)
        ),
        6 => format!(
            ".restart local {}",
            format_fast_register(need_register()?, first_parameter)
        ),
        7 => ".prologue".to_owned(),
        8 => ".epilogue".to_owned(),
        9 => match event.file_idx {
            Some(index) => {
                let name = pools.string_literal(index).ok_or_else(|| {
                    smali_fault("an annotation value names a string the facts do not hold")
                })?;
                format!(".source {name}")
            }
            None => ".source null".to_owned(),
        },
        _ => match event.source_line {
            Some(line) if event.source_line_usable => format!(".line {}", line.0),
            _ => return Ok(Some(String::new())),
        },
    };
    Ok(Some(line))
}

struct FastExtras {
    header: Vec<String>,
    at_address: BTreeMap<u32, Vec<String>>,
}

fn build_fast_extras(
    reference: &MethodReference,
    access_flags: u32,
    code: Option<&CodeItem>,
    pools: &mut FastPools<'_>,
    annotation_layer_missing: bool,
) -> MddResult<(FastExtras, ExtrasReport)> {
    let mut header = Vec::new();
    let mut at_address: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut report = ExtrasReport {
        annotation_layer_missing,
        ..ExtrasReport::default()
    };

    let is_static = access_flags & 0x8 != 0;
    let mut next_reg = u32::from(!is_static);
    let param_names = code
        .and_then(|c| c.debug_info.as_ref())
        .map(|d| &d.parameter_name_indices);
    for (position, descriptor) in reference.parameter_descriptors.iter().enumerate() {
        if let Some(index) = param_names.and_then(|names| names.get(position).copied().flatten()) {
            let lit = pools.string_literal(index).ok_or_else(|| {
                smali_fault("an annotation value names a string the facts do not hold")
            })?;
            header.push(format!("    .param p{next_reg}, {lit}"));
        }
        next_reg += if descriptor == "J" || descriptor == "D" {
            2
        } else {
            1
        };
    }

    if let Some(code) = code
        && let Some(debug) = code.debug_info.as_ref()
    {
        let instruction_starts: BTreeSet<u32> = code
            .instructions
            .iter()
            .map(|i| i.code_unit_offset)
            .collect();
        let first_parameter = code.registers_size.saturating_sub(code.ins_size);
        for event in debug.events.iter() {
            let Some(line) = fast_debug_line(&event, pools, first_parameter)? else {
                continue;
            };
            if line.is_empty() {
                report.positions_not_source_lines += 1;
                continue;
            }
            let key = match event.code_item_address_scope {
                DebugAddressScope::InsideCodeUnits
                    if instruction_starts.contains(&event.address_code_units) =>
                {
                    event.address_code_units
                }
                DebugAddressScope::AtCodeEnd => code.insns_size_code_units,
                _ => {
                    report.debug_events_unplaced += 1;
                    continue;
                }
            };
            at_address
                .entry(key)
                .or_default()
                .push(format!("    {line}"));
        }
    }

    Ok((FastExtras { header, at_address }, report))
}

fn fast_goto_or_cond(opcode: u8) -> &'static str {
    match opcode {
        0x28..=0x2a => "goto_",
        _ => "cond_",
    }
}

fn fast_payload_label_prefix(data: &PayloadData) -> &'static str {
    match data {
        PayloadData::PackedSwitch { .. } => "pswitch_data_",
        PayloadData::SparseSwitch { .. } => "sswitch_data_",
        PayloadData::FillArray { .. } => "array_",
    }
}

fn fast_handler_of(code: &CodeItem, relative: u16) -> MddResult<&CatchHandler> {
    code.handlers
        .iter()
        .find(|h| h.relative_byte_offset == u32::from(relative))
        .ok_or_else(|| smali_fault("a try item names a handler that is not there"))
}

fn fast_collect_labels(code: &CodeItem) -> MddResult<BTreeMap<u32, BTreeSet<String>>> {
    let mut at: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    let mut add = |address: u32, prefix: &str| {
        at.entry(address)
            .or_default()
            .insert(format!("{prefix}{address:x}"));
    };
    for instruction in &code.instructions {
        if let Some(target) = instruction.branch_target_code_units {
            add(target, fast_goto_or_cond(instruction.opcode));
        }
    }
    for payload in &code.payloads {
        add(
            payload.code_unit_offset,
            fast_payload_label_prefix(&payload.data),
        );
    }
    for switch in &code.switch_targets {
        let owner = code
            .instructions
            .iter()
            .find(|i| i.code_unit_offset == switch.instruction_code_unit_offset)
            .ok_or_else(|| smali_fault("a switch table names an instruction that is not there"))?;
        let prefix = match owner.opcode {
            0x2b => "pswitch_",
            0x2c => "sswitch_",
            _ => {
                return Err(smali_fault(
                    "a switch table belongs to an instruction that is not a switch",
                ));
            }
        };
        for target in &switch.target_code_units {
            add(*target, prefix);
        }
    }
    for item in &code.tries {
        add(item.start_code_unit, "try_start_");
        add(
            item.start_code_unit + u32::from(item.code_unit_count),
            "try_end_",
        );
        let handler = fast_handler_of(code, item.handler_relative_byte_offset)?;
        for pair in &handler.typed_catches {
            add(pair.address_code_units, "catch_");
        }
        if let Some(address) = handler.catch_all_address_code_units {
            add(address, "catchall_");
        }
    }
    Ok(at)
}

fn fast_reference_text(pools: &mut FastPools<'_>, operand: &ReferenceOperand) -> MddResult<String> {
    let index = operand.local_index;
    let missing = |what: &str| {
        smali_fault(&format!(
            "an instruction refers to a {what} the facts do not hold"
        ))
    };
    Ok(match operand.kind {
        ReferenceKind::String => pools
            .string_literal(index)
            .ok_or_else(|| missing("string"))?,
        ReferenceKind::Type => pools
            .type_descriptor(index)
            .ok_or_else(|| missing("type"))?,
        ReferenceKind::Field => pools
            .field_descriptor(index)
            .ok_or_else(|| missing("field"))?,
        ReferenceKind::Method => pools
            .method_reference(index)
            .map(|m| m.descriptor.clone())
            .ok_or_else(|| missing("method"))?,
        ReferenceKind::Prototype => pools
            .proto_parts(index)
            .map(|(desc, _, _)| desc)
            .ok_or_else(|| missing("prototype"))?,
        ReferenceKind::CallSite => format!("call_site_{index}"),
        ReferenceKind::MethodHandle => format!("method_handle_{index}"),
    })
}

fn fast_operands(
    pools: &mut FastPools<'_>,
    instruction: &mdd_dex::instructions::Instruction,
    first_parameter: u16,
) -> MddResult<String> {
    let reg = |slot: usize| -> MddResult<String> {
        instruction
            .registers
            .iter()
            .nth(slot)
            .map(|r| format_fast_register(r, first_parameter))
            .ok_or_else(|| smali_fault("an instruction has fewer registers than its format says"))
    };
    let register_list = || -> String {
        match &instruction.register_range {
            Some(range) if range.word_count == 0 => "{}".to_owned(),
            Some(range) => format!(
                "{{{} .. {}}}",
                format_fast_register(range.first, first_parameter),
                format_fast_register(
                    range.first.saturating_add(range.word_count - 1),
                    first_parameter
                )
            ),
            None => format!(
                "{{{}}}",
                instruction
                    .registers
                    .iter()
                    .map(|r| format_fast_register(r, first_parameter))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    };
    let literal = || -> MddResult<String> {
        let literal = instruction
            .literal
            .as_ref()
            .ok_or_else(|| smali_fault("an instruction has no literal its format needs"))?;
        let mut text = hex_signed_fast(literal.signed_decimal.as_i64());
        if instruction.mnemonic.starts_with("const-wide") {
            text.push('L');
        }
        Ok(text)
    };
    let branch = || -> MddResult<String> {
        let target = instruction
            .branch_target_code_units
            .ok_or_else(|| smali_fault("a branch has no target"))?;
        Ok(format!(
            ":{}{target:x}",
            fast_goto_or_cond(instruction.opcode)
        ))
    };
    let first_reference = |pools: &mut FastPools<'_>| -> MddResult<String> {
        fast_reference_text(
            pools,
            instruction
                .references
                .first()
                .ok_or_else(|| smali_fault("an instruction has no reference its format needs"))?,
        )
    };
    let second_reference = |pools: &mut FastPools<'_>| -> MddResult<String> {
        fast_reference_text(
            pools,
            instruction
                .references
                .get(1)
                .ok_or_else(|| smali_fault("a polymorphic call has no prototype"))?,
        )
    };
    let payload_target = || -> MddResult<String> {
        let target = instruction
            .payload_target_code_units
            .ok_or_else(|| smali_fault("a payload instruction has no payload"))?;
        let prefix = match instruction.opcode {
            0x26 => "array_",
            0x2b => "pswitch_data_",
            _ => "sswitch_data_",
        };
        Ok(format!(":{prefix}{target:x}"))
    };
    Ok(match &*instruction.format {
        "10x" => String::new(),
        "12x" | "22x" | "32x" => format!("{}, {}", reg(0)?, reg(1)?),
        "11n" | "21s" | "21h" | "31i" | "51l" => format!("{}, {}", reg(0)?, literal()?),
        "11x" => reg(0)?,
        "10t" | "20t" | "30t" => branch()?,
        "21t" => format!("{}, {}", reg(0)?, branch()?),
        "21c" | "31c" => format!("{}, {}", reg(0)?, first_reference(pools)?),
        "23x" => format!("{}, {}, {}", reg(0)?, reg(1)?, reg(2)?),
        "22b" | "22s" => format!("{}, {}, {}", reg(0)?, reg(1)?, literal()?),
        "22t" => format!("{}, {}, {}", reg(0)?, reg(1)?, branch()?),
        "22c" => format!("{}, {}, {}", reg(0)?, reg(1)?, first_reference(pools)?),
        "31t" => format!("{}, {}", reg(0)?, payload_target()?),
        "35c" | "3rc" => format!("{}, {}", register_list(), first_reference(pools)?),
        "45cc" | "4rcc" => format!(
            "{}, {}, {}",
            register_list(),
            first_reference(pools)?,
            second_reference(pools)?
        ),
        other => {
            return Err(
                smali_fault("an instruction has a format the renderer does not know")
                    .detail("format", other.to_owned()),
            );
        }
    })
}

fn fast_array_element(bytes: &[u8], width: usize) -> String {
    let mut raw = [0u8; 8];
    raw[..width].copy_from_slice(bytes);
    let value = match width {
        1 => i64::from(raw[0] as i8),
        2 => i64::from(i16::from_le_bytes([raw[0], raw[1]])),
        4 => i64::from(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])),
        _ => i64::from_le_bytes(raw),
    };
    let suffix = match width {
        1 => "t",
        2 => "s",
        8 => "L",
        _ => "",
    };
    format!("{}{suffix}", hex_signed_fast(value))
}

fn write_fast_payload(
    out: &mut String,
    payload: &Payload,
    code: &CodeItem,
    bytes: &[u8],
) -> MddResult<()> {
    match &payload.data {
        PayloadData::PackedSwitch { first_key, .. } => {
            let table = code
                .switch_targets
                .iter()
                .find(|s| s.payload_code_unit_offset == payload.code_unit_offset);
            let _ = writeln!(
                out,
                "    .packed-switch {}",
                hex_signed_fast(i64::from(*first_key))
            );
            if let Some(table) = table {
                for target in &table.target_code_units {
                    let _ = writeln!(out, "        :pswitch_{target:x}");
                }
            }
            out.push_str("    .end packed-switch\n");
        }
        PayloadData::SparseSwitch { keys, .. } => {
            let table = code
                .switch_targets
                .iter()
                .find(|s| s.payload_code_unit_offset == payload.code_unit_offset);
            out.push_str("    .sparse-switch\n");
            if let Some(table) = table {
                for (key, target) in keys.iter().zip(&table.target_code_units) {
                    let _ = writeln!(
                        out,
                        "        {} -> :sswitch_{target:x}",
                        hex_signed_fast(i64::from(*key))
                    );
                }
            }
            out.push_str("    .end sparse-switch\n");
        }
        PayloadData::FillArray {
            element_width_bytes,
            element_count,
            data_range,
        } => {
            let width = usize::from(*element_width_bytes);
            if !matches!(width, 1 | 2 | 4 | 8) {
                return Err(smali_fault("an array payload has an invalid element width"));
            }
            let start = usize::try_from(data_range.byte_offset.0)
                .map_err(|_| smali_fault("an array payload lies outside the file"))?;
            let length = usize::try_from(data_range.byte_length.0)
                .map_err(|_| smali_fault("an array payload lies outside the file"))?;
            let data = start
                .checked_add(length)
                .and_then(|end| bytes.get(start..end))
                .ok_or_else(|| smali_fault("an array payload lies outside the file"))?;
            let _ = writeln!(out, "    .array-data {width}");
            for chunk in data.chunks_exact(width).take(*element_count as usize) {
                let _ = writeln!(out, "        {}", fast_array_element(chunk, width));
            }
            out.push_str("    .end array-data\n");
        }
    }
    Ok(())
}

fn write_fast_catches(
    text: &mut String,
    pools: &mut FastPools<'_>,
    code: &CodeItem,
    item: &TryItem,
) -> MddResult<()> {
    let start = item.start_code_unit;
    let end = start + u32::from(item.code_unit_count);
    let handler = fast_handler_of(code, item.handler_relative_byte_offset)?;
    for pair in &handler.typed_catches {
        let descriptor = pools
            .type_descriptor(pair.type_idx)
            .ok_or_else(|| smali_fault("a catch names a type the facts do not hold"))?;
        let _ = writeln!(
            text,
            "    .catch {descriptor} {{:try_start_{start:x} .. :try_end_{end:x}}} :catch_{:x}",
            pair.address_code_units
        );
    }
    if let Some(address) = handler.catch_all_address_code_units {
        let _ = writeln!(
            text,
            "    .catchall {{:try_start_{start:x} .. :try_end_{end:x}}} :catchall_{address:x}"
        );
    }
    Ok(())
}

fn render_fast_smali(
    reference: &MethodReference,
    entry: &FastMethodEntry,
    code: Option<&CodeItem>,
    pools: &mut FastPools<'_>,
    extras: &FastExtras,
    limits: SmaliLimits,
) -> MddResult<RenderedMethod> {
    let declaration = method_declaration(reference, entry.access_flags);
    let mut text = String::new();
    text.push_str(&declaration);
    text.push('\n');
    let has_body = matches!(entry.body, MethodBody::Present { .. });
    let Some(code) = code.filter(|_| has_body) else {
        if has_body {
            return Err(smali_fault("a method with a body was given no code"));
        }
        if !extras.at_address.is_empty() {
            return Err(smali_fault(
                "a method without code was given lines for a code address",
            ));
        }
        for line in &extras.header {
            text.push_str(line);
            text.push('\n');
        }
        text.push_str(".end method\n");
        return Ok(RenderedMethod {
            declaration,
            text,
            registers: None,
            code_units: None,
            try_count: None,
        });
    };
    let first_parameter = code
        .registers_size
        .checked_sub(code.ins_size)
        .ok_or_else(|| smali_fault("a code item has more incoming than total registers"))?;
    let _ = writeln!(text, "    .registers {}", code.registers_size);
    for line in &extras.header {
        text.push_str(line);
        text.push('\n');
    }
    text.push('\n');

    let labels = fast_collect_labels(code)?;
    let mut instructions = code.instructions.iter().peekable();
    let mut payloads = code.payloads.iter().peekable();
    let mut pending = labels.iter().peekable();
    let end_address = code.insns_size_code_units;
    let mut placed = 0usize;
    loop {
        let next_instruction = instructions.peek().map(|i| i.code_unit_offset);
        let next_payload = payloads.peek().map(|p| p.code_unit_offset);
        let address = match (next_instruction, next_payload) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => end_address,
        };
        while let Some((at, names)) = pending.next_if(|(at, _)| **at <= address) {
            if *at < address {
                return Err(smali_fault(
                    "a label points into the middle of an instruction",
                ));
            }
            for name in names {
                let _ = writeln!(text, "    :{name}");
            }
        }
        for item in &code.tries {
            if item.start_code_unit + u32::from(item.code_unit_count) == address {
                write_fast_catches(&mut text, pools, code, item)?;
            }
        }
        if (next_instruction == Some(address) || address == end_address)
            && let Some(lines) = extras.at_address.get(&address)
        {
            for line in lines {
                text.push_str(line);
                text.push('\n');
            }
            placed += 1;
        }
        if text.len() as u64 > limits.max_text_bytes {
            return Err(smali_too_large(limits.max_text_bytes));
        }
        if address == end_address && next_instruction.is_none() && next_payload.is_none() {
            break;
        }
        if next_instruction == Some(address) {
            let instruction = instructions.next().expect("peeked");
            let rendered = fast_operands(pools, instruction, first_parameter)?;
            if rendered.is_empty() {
                let _ = writeln!(text, "    {}", instruction.mnemonic);
            } else {
                let _ = writeln!(text, "    {} {rendered}", instruction.mnemonic);
            }
        } else {
            let payload = payloads.next().expect("peeked");
            write_fast_payload(&mut text, payload, code, pools.bytes)?;
        }
    }
    if pending.next().is_some() {
        return Err(smali_fault("a label points past the end of the code"));
    }
    if placed != extras.at_address.len() {
        return Err(smali_fault(
            "lines were given for a code address that is not where an instruction starts or the code ends",
        ));
    }
    text.push_str(".end method\n");
    if text.len() as u64 > limits.max_text_bytes {
        return Err(smali_too_large(limits.max_text_bytes));
    }
    Ok(RenderedMethod {
        declaration,
        text,
        registers: Some(code.registers_size),
        code_units: Some(code.insns_size_code_units),
        try_count: Some(
            u16::try_from(code.tries.len())
                .map_err(|_| smali_fault("a code item has too many tries"))?,
        ),
    })
}

fn fast_summarize_method(
    dataset: &Dataset,
    layers: &LayerBuilder,
    file_id: u32,
    method_idx: u32,
) -> MddResult<Option<Summary>> {
    let Some((guard, meta, _ann)) = lease_for_fast_path(dataset, layers, file_id)? else {
        return Ok(None);
    };
    let Some(layout) = FastDexLayout::parse(guard.bytes()) else {
        return Ok(None);
    };
    let FastMethodMatch::Found(entry) = find_method_entry(&layout, guard.bytes(), method_idx)
    else {
        return Ok(None);
    };
    let mut pools = FastPools::new(guard.bytes(), &layout);
    let Some(reference) = pools.method_reference(method_idx) else {
        return Ok(None);
    };
    let code_item = decode_fast_code_item(&guard, &layout, &meta, &entry.body, false)?;
    build_summary(
        file_id,
        method_idx,
        &reference,
        entry.access_flags,
        code_item.as_ref(),
    )
    .map(Some)
}

fn fast_render_method(
    dataset: &Dataset,
    layers: &LayerBuilder,
    file_id: u32,
    method_idx: u32,
    limits: SmaliLimits,
) -> MddResult<Option<Decoded>> {
    let Some((guard, meta, annotations_validation)) =
        lease_for_fast_path(dataset, layers, file_id)?
    else {
        return Ok(None);
    };
    let Some(layout) = FastDexLayout::parse(guard.bytes()) else {
        return Ok(None);
    };
    let FastMethodMatch::Found(entry) = find_method_entry(&layout, guard.bytes(), method_idx)
    else {
        return Ok(None);
    };
    let annotation_layer_missing = match annotations_validation {
        LayerValidation::Valid(()) => {
            match method_has_annotations(guard.bytes(), entry.annotations_off, method_idx) {
                None | Some(true) => return Ok(None),
                Some(false) => false,
            }
        }
        LayerValidation::Failed => true,
        LayerValidation::Unknown => return Ok(None),
    };
    let mut pools = FastPools::new(guard.bytes(), &layout);
    let Some(reference) = pools.method_reference(method_idx) else {
        return Ok(None);
    };
    let code_item = decode_fast_code_item(&guard, &layout, &meta, &entry.body, true)?;
    let (extras, report) = build_fast_extras(
        &reference,
        entry.access_flags,
        code_item.as_ref(),
        &mut pools,
        annotation_layer_missing,
    )?;
    let rendered = render_fast_smali(
        &reference,
        &entry,
        code_item.as_ref(),
        &mut pools,
        &extras,
        limits,
    )?;
    Ok(Some(Decoded {
        file_id,
        method_idx,
        descriptor: reference.descriptor,
        access_flags: entry.access_flags,
        rendered,
        report,
    }))
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

    fn open_decode_fixture(relative: &str) -> Dataset {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        Dataset::open(
            &[InputRequest { path, kind: None }],
            Dialect::DexSql011,
            ResourceLimits::default(),
            SqlLimits::default(),
        )
        .expect("fixture opens")
    }

    fn assert_single_method_matches_lazy(
        fast_ds: &Dataset,
        lazy_ds: &Dataset,
        file_id: u32,
        method_idx: u32,
        context: &str,
    ) {
        let fast_loc = select(
            fast_ds,
            Selector::Key {
                file_id,
                method_idx,
            },
        )
        .unwrap_or_else(|e| panic!("{context} fast select({file_id}, {method_idx}) failed: {e:?}"));
        let lazy_loc = select(
            lazy_ds,
            Selector::Key {
                file_id,
                method_idx,
            },
        )
        .unwrap_or_else(|e| panic!("{context} lazy select({file_id}, {method_idx}) failed: {e:?}"));

        match (summarize(fast_ds, fast_loc), summarize(lazy_ds, lazy_loc)) {
            (Ok(fast), Ok(lazy)) => {
                assert_eq!(fast.file_id, lazy.file_id, "{context}");
                assert_eq!(fast.method_idx, lazy.method_idx, "{context}");
                assert_eq!(fast.descriptor, lazy.descriptor, "{context}");
                assert_eq!(fast.access_flags, lazy.access_flags, "{context}");
                assert_eq!(fast.declaration, lazy.declaration, "{context}");
                assert_eq!(fast.registers, lazy.registers, "{context}");
                assert_eq!(fast.code_units, lazy.code_units, "{context}");
                assert_eq!(fast.try_count, lazy.try_count, "{context}");
            }
            (Err(fast), Err(lazy)) => {
                assert_eq!(fast.code, lazy.code, "{context}");
                assert_eq!(fast.stage, lazy.stage, "{context}");
                assert_eq!(fast.message, lazy.message, "{context}");
            }
            (fast, lazy) => panic!("{context} summarize parity mismatch: {fast:?} vs {lazy:?}"),
        }

        match (
            render(fast_ds, fast_loc, SmaliLimits::default()),
            render(lazy_ds, lazy_loc, SmaliLimits::default()),
        ) {
            (Ok(fast), Ok(lazy)) => {
                assert_eq!(fast.file_id, lazy.file_id, "{context}");
                assert_eq!(fast.method_idx, lazy.method_idx, "{context}");
                assert_eq!(fast.descriptor, lazy.descriptor, "{context}");
                assert_eq!(fast.access_flags, lazy.access_flags, "{context}");
                assert_eq!(fast.rendered, lazy.rendered, "{context}");
                assert_eq!(fast.report, lazy.report, "{context}");
            }
            (Err(fast), Err(lazy)) => {
                assert_eq!(fast.code, lazy.code, "{context}");
                assert_eq!(fast.stage, lazy.stage, "{context}");
                assert_eq!(fast.message, lazy.message, "{context}");
            }
            (_fast, _lazy) => panic!("{context} render parity mismatch"),
        }
    }

    fn verify_fixture_differential(relative: &str) -> (usize, usize) {
        let lazy_ds = open_decode_fixture(relative);
        let _ = lazy_ds.decode_dex(0).expect("lazy decode initializes");
        assert_eq!(lazy_ds.loaded_decode_dex_count(), 1);

        let occurrences = lazy_ds.occurrences().expect("occurrences build");
        let occ = &occurrences[0];
        let defs = occ.definitions.definitions();
        let ann_idx = occ.annotations.as_deref().map(AnnotationIndex::build);

        let mut unannotated = Vec::new();
        let mut annotated = Vec::new();
        let mut defined_indices = std::collections::HashSet::new();
        for def in &defs.method_definitions {
            defined_indices.insert(def.method_idx);
            let param_count = defs.method_references[def.method_idx as usize]
                .parameter_descriptors
                .len();
            let has_ann = ann_idx.as_ref().is_some_and(|idx| {
                idx.method_set(def.class_def_idx, def.method_idx).is_some()
                    || idx
                        .parameter_slots(def.class_def_idx, def.method_idx, param_count)
                        .is_some()
            });
            if has_ann {
                annotated.push(def.method_idx);
            } else {
                unannotated.push(def.method_idx);
            }
        }

        let fast_ds = open_decode_fixture(relative);
        assert_eq!(fast_ds.loaded_decode_dex_count(), 0);
        let code_valid = matches!(
            fast_ds.layers().unwrap().code_validation(0),
            LayerValidation::Valid(_)
        );

        for &method_idx in &unannotated {
            let label = format!("{relative}#method_idx={method_idx}");
            assert_single_method_matches_lazy(&fast_ds, &lazy_ds, 0, method_idx, &label);
        }
        if code_valid {
            assert_eq!(
                fast_ds.loaded_decode_dex_count(),
                0,
                "{relative}: unannotated methods must not initialize LazyDexDecode"
            );
        }

        // Verify referenced-only and out-of-range method_idx stay NotFound without loading LazyDexDecode.
        assert!(matches!(
            select(
                &fast_ds,
                Selector::Key {
                    file_id: 0,
                    method_idx: u32::MAX,
                },
            ),
            Err(Failure::NotFound { .. })
        ));
        for method_idx in 0..defs.method_references.len() as u32 {
            if !defined_indices.contains(&method_idx) {
                assert!(matches!(
                    select(
                        &fast_ds,
                        Selector::Key {
                            file_id: 0,
                            method_idx,
                        },
                    ),
                    Err(Failure::NotFound { .. })
                ));
            }
        }
        if code_valid {
            assert_eq!(
                fast_ds.loaded_decode_dex_count(),
                0,
                "{relative}: undefined method_idx checks must not initialize LazyDexDecode"
            );
        }

        for &method_idx in &annotated {
            let label = format!("{relative}#annotated_method_idx={method_idx}");
            assert_single_method_matches_lazy(&fast_ds, &lazy_ds, 0, method_idx, &label);
        }
        if !annotated.is_empty() {
            assert_eq!(
                fast_ds.loaded_decode_dex_count(),
                1,
                "{relative}: annotated methods must fall back cleanly to LazyDexDecode"
            );
        }
        (unannotated.len(), annotated.len())
    }

    #[test]
    fn single_method_fast_path_matches_lazy_decode_across_all_decode_fixtures() {
        for relative in [
            "tests/fixtures/decode/generated/decode-all.dex",
            "tests/fixtures/decode/generated/decode-v035.dex",
            "tests/fixtures/decode/generated/decode-bad-invoke.dex",
            "tests/fixtures/decode/generated/decode-class.dex",
        ] {
            let (unannotated, _) = verify_fixture_differential(relative);
            assert!(
                unannotated > 0,
                "{relative} should exercise unannotated fast-path methods"
            );
        }
    }

    #[test]
    fn single_method_fast_path_falls_back_when_annotations_exist() {
        let (_, annotated) =
            verify_fixture_differential("tests/fixtures/annotations/generated/annotations-038.dex");
        assert!(
            annotated > 0,
            "annotations-038.dex must exercise annotated fallback"
        );
    }
}
