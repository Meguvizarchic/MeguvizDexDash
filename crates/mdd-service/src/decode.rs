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
    annotations::AnnotationFacts,
    smali::{
        AnnotationIndex, ClassLimits, ClassView, ExtrasReport, FullMethodView, RenderedClass,
        SmaliOptions, render_class, render_method_full,
    },
    smali_required::{MethodView, RenderedMethod, SmaliLimits, method_declaration},
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
    /// `None` when the annotation layer could not be built; a text then shows no annotations
    /// or static values, and its report says so.
    pub annotations: Option<Arc<AnnotationFacts>>,
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

/// Per occurrence: defined methods by descriptor, defined classes by descriptor and their
/// methods in method-index order, and code items by their byte offset.
pub(crate) struct OccurrenceIndex {
    by_descriptor: HashMap<String, Vec<usize>>,
    by_method_idx: HashMap<u32, usize>,
    code_by_offset: HashMap<u64, usize>,
    /// Class descriptor to the positions in `definitions.classes` that define it.
    classes_by_descriptor: HashMap<String, Vec<usize>>,
    /// `class_def_idx` to the positions in `method_definitions` of that class, ordered by
    /// `method_idx` (the order `method_offset` counts in).
    class_methods: HashMap<u32, Vec<usize>>,
    /// Which annotation set each owner has; `None` when the annotation layer is not built.
    annotation_index: Option<AnnotationIndex>,
}

impl OccurrenceIndex {
    pub(crate) fn build(occurrence: &Occurrence) -> Self {
        let defs = occurrence.definitions.definitions();
        let mut by_descriptor: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_method_idx = HashMap::new();
        let mut class_methods: HashMap<u32, Vec<usize>> = HashMap::new();
        for (position, definition) in defs.method_definitions.iter().enumerate() {
            by_method_idx.insert(definition.method_idx, position);
            class_methods
                .entry(definition.class_def_idx)
                .or_default()
                .push(position);
            if let Some(reference) = defs.method_references.get(definition.method_idx as usize) {
                by_descriptor
                    .entry(reference.descriptor.clone())
                    .or_default()
                    .push(position);
            }
        }
        for positions in class_methods.values_mut() {
            positions.sort_by_key(|&position| defs.method_definitions[position].method_idx);
        }
        let mut classes_by_descriptor: HashMap<String, Vec<usize>> = HashMap::new();
        for (position, class) in defs.classes.iter().enumerate() {
            classes_by_descriptor
                .entry(class.descriptor.clone())
                .or_default()
                .push(position);
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
            classes_by_descriptor,
            class_methods,
            annotation_index: occurrence
                .annotations
                .as_deref()
                .map(AnnotationIndex::build),
        }
    }
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

/// Find the class `descriptor` names. A descriptor defined in several DEX files names none of
/// them: say which with `file_id`.
pub fn select_class(
    dataset: &Dataset,
    descriptor: &str,
    file_id: Option<u32>,
) -> Result<LocatedClass, Failure> {
    let occurrences = dataset.occurrences();
    let indexes = dataset.decode_indexes();
    let mut found = Vec::new();
    for (occurrence, index) in occurrences.iter().zip(indexes) {
        if file_id.is_some_and(|wanted| wanted != occurrence.file_id) {
            continue;
        }
        for &class in index
            .classes_by_descriptor
            .get(descriptor)
            .into_iter()
            .flatten()
        {
            found.push((occurrence.file_id, class));
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
            let mut ids: Vec<u32> = many.iter().map(|(file_id, _)| *file_id).collect();
            ids.sort_unstable();
            ids.dedup();
            if ids.len() == 1 {
                return Err(Failure::Error(
                    MddError::new(
                        ErrorCode::InvalidInput,
                        "service.decode",
                        "a DEX defines the same class more than once",
                    )
                    .detail("file_id", ids[0].to_string()),
                ));
            }
            Err(Failure::Ambiguous { file_ids: ids })
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
    let occurrences = dataset.occurrences();
    let position = occurrences
        .iter()
        .position(|o| o.file_id == class.file_id)
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
    let class_def = &definitions.classes[class.class];
    let all = index
        .class_methods
        .get(&class_def.class_def_idx)
        .map_or(&[][..], Vec::as_slice);
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
    /// What the text leaves out, and why (debug events at no instruction, annotation slots
    /// that cannot be placed, a missing annotation layer).
    pub report: ExtrasReport,
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
    let reference = &definitions.method_references[located.method_idx as usize];
    let code = code_of(occurrence, index, &definition.body)?;
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
    let view = FullMethodView {
        method: MethodView {
            metadata: &occurrence.metadata,
            definitions,
            definition,
            code,
        },
        annotations: occurrence
            .annotations
            .as_deref()
            .zip(index.annotation_index.as_ref()),
    };
    let full = render_method_full(&view, limits, SmaliOptions::default())?;
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
    let occurrences = dataset.occurrences();
    let position = occurrences
        .iter()
        .position(|o| o.file_id == class.file_id)
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
    let view = ClassView {
        metadata: &occurrence.metadata,
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
        let occurrences = dataset.occurrences();
        let position = occurrences
            .iter()
            .position(|o| o.file_id == located.file_id)
            .unwrap();
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
}
