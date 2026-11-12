//! The seventeen HostLab contract relation names, served from validated facts.
//!
//! `conformance/manifests/relations.json` marks exactly seventeen relations
//! `required_by_hostlab`. The `native_*` relations in [`super::metadata`] are
//! physical projections with their own shapes; this module registers the
//! contract names and contract column order on top of the same immutable fact
//! layers. Constructing a provider admits nothing: it only makes a relation
//! name answerable for one snapshot generation.
//!
//! Coordinates are not invented here. `file_id` and `string_pool_id` come from
//! [`mdd_facts::indexes::SelectedScope::occurrence_pool_coordinates`], whose
//! ordinal is the selected-DEX roster position. Two independent A0 observations
//! pin that convention with the frozen `dexsql-windows-amd64.exe`
//! (`sha256:f354ebcf…`):
//!
//! * archive order, not numeric member order: `member-policy.apk` stores
//!   `classes10.dex` before `classes2.dex`, and A0 returns `file_id` 0 for
//!   `classes10.dex` and 1 for `classes2.dex`;
//! * a scrambled twelve-member archive returns the ZIP enumeration order, and
//!   two byte-identical occurrences (`duplicate-content.apk`) still receive
//!   distinct pool ids 0 and 1.
//!
//! `source_path` and `entry_name` are provenance owned by the snapshot/archive
//! layers, so the caller passes them per selected occurrence. Both contract
//! columns are `nullable: false`; when a provenance value is absent (a non
//! UTF-8 input path or a non-UTF-8 archive member name) the `dex_files`
//! relation fails with `INCOMPLETE_FACTS` naming the column instead of emitting
//! NULL, empty text, or a guessed spelling.
use super::*;
use crate::{quota, values::SqlText};
use mdd_facts::{
    MetadataFacts,
    annotations::AnnotationFacts,
    code::{CodeFacts, MethodCodeFactViews, MethodCodeViewLimits},
    coverage::{CoverageLedger, CoverageRequest},
    definitions::DefinitionFacts,
    indexes::{FactView, SelectedScope},
    references::ReferenceFacts,
    session::FactsSession,
};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError};

/// Upper bound on selected occurrences accepted by [`HostLabSqlProvider::from_scope`].
/// Same order of magnitude as the selected-roster cap in `mdd-facts`.
const MAX_HOSTLAB_OCCURRENCES: u64 = 1_000_000;

/// One contract relation name. The enum is the whole registration surface:
/// every variant maps to exactly one contract name and one column array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostLabRelation {
    DexFiles,
    Strings,
    Types,
    Methods,
    Classes,
    ClassInterfaces,
    ClassFields,
    ClassMethods,
    CodeItems,
    AnnotationDirectoryEntries,
    AnnotationSetEntries,
    Annotations,
    AnnotationElements,
    MethodStrings,
    MethodCalls,
    MethodFieldAccesses,
    MethodUsedTypes,
}

impl HostLabRelation {
    /// All seventeen contract names in `relations.json` order.
    pub const ALL: [Self; 17] = [
        Self::DexFiles,
        Self::Strings,
        Self::Types,
        Self::Methods,
        Self::Classes,
        Self::ClassInterfaces,
        Self::ClassFields,
        Self::ClassMethods,
        Self::CodeItems,
        Self::AnnotationDirectoryEntries,
        Self::AnnotationSetEntries,
        Self::Annotations,
        Self::AnnotationElements,
        Self::MethodStrings,
        Self::MethodCalls,
        Self::MethodFieldAccesses,
        Self::MethodUsedTypes,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::DexFiles => "dex_files",
            Self::Strings => "strings",
            Self::Types => "types",
            Self::Methods => "methods",
            Self::Classes => "classes",
            Self::ClassInterfaces => "class_interfaces",
            Self::ClassFields => "class_fields",
            Self::ClassMethods => "class_methods",
            Self::CodeItems => "code_items",
            Self::AnnotationDirectoryEntries => "annotation_directory_entries",
            Self::AnnotationSetEntries => "annotation_set_entries",
            Self::Annotations => "annotations",
            Self::AnnotationElements => "annotation_elements",
            Self::MethodStrings => "method_strings",
            Self::MethodCalls => "method_calls",
            Self::MethodFieldAccesses => "method_field_accesses",
            Self::MethodUsedTypes => "method_used_types",
        }
    }

    /// Register a contract name. Only the exact contract spelling is accepted;
    /// the `native_*` aliases stay on their own providers.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|relation| relation.name() == name)
    }

    /// Contract columns in `relations.json` order: `(name, carrier type, nullable)`.
    pub fn columns(self) -> &'static [(&'static str, SqlType, bool)] {
        match self {
            Self::DexFiles => DEX_FILES_COLUMNS,
            Self::Strings => STRINGS_COLUMNS,
            Self::Types => TYPES_COLUMNS,
            Self::Methods => METHODS_COLUMNS,
            Self::Classes => CLASSES_COLUMNS,
            Self::ClassInterfaces => CLASS_INTERFACES_COLUMNS,
            Self::ClassFields => CLASS_FIELDS_COLUMNS,
            Self::ClassMethods => CLASS_METHODS_COLUMNS,
            Self::CodeItems => CODE_ITEMS_COLUMNS,
            Self::AnnotationDirectoryEntries => ANNOTATION_DIRECTORY_ENTRIES_COLUMNS,
            Self::AnnotationSetEntries => ANNOTATION_SET_ENTRIES_COLUMNS,
            Self::Annotations => ANNOTATIONS_COLUMNS,
            Self::AnnotationElements => ANNOTATION_ELEMENTS_COLUMNS,
            Self::MethodStrings => METHOD_STRINGS_COLUMNS,
            Self::MethodCalls => METHOD_CALLS_COLUMNS,
            Self::MethodFieldAccesses => METHOD_FIELD_ACCESSES_COLUMNS,
            Self::MethodUsedTypes => METHOD_USED_TYPES_COLUMNS,
        }
    }

    /// Fact layers this relation reads. Reported to the bridge so a caller can
    /// see why a relation is gated; the provider additionally refuses to serve
    /// a relation whose layer was not attached.
    pub fn required_layers(self) -> Vec<FactLayer> {
        match self {
            Self::DexFiles | Self::Strings | Self::Types => vec![FactLayer::Metadata],
            Self::Methods => vec![
                FactLayer::Metadata,
                FactLayer::Structure,
                FactLayer::CodeLayout,
            ],
            Self::Classes | Self::ClassInterfaces | Self::ClassFields | Self::ClassMethods => {
                vec![FactLayer::Metadata, FactLayer::Structure]
            }
            Self::CodeItems => vec![
                FactLayer::Metadata,
                FactLayer::Structure,
                FactLayer::CodeLayout,
            ],
            Self::AnnotationDirectoryEntries
            | Self::AnnotationSetEntries
            | Self::Annotations
            | Self::AnnotationElements => vec![
                FactLayer::Metadata,
                FactLayer::Structure,
                FactLayer::Annotations,
            ],
            Self::MethodStrings
            | Self::MethodCalls
            | Self::MethodFieldAccesses
            | Self::MethodUsedTypes => vec![
                FactLayer::Metadata,
                FactLayer::Structure,
                FactLayer::CodeLayout,
                FactLayer::References,
            ],
        }
    }
}

const DEX_FILES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("string_pool_id", SqlType::U64, false),
    ("source_path", SqlType::Text, false),
    ("entry_name", SqlType::Text, false),
    ("byte_len", SqlType::U64, false),
    ("dex_version", SqlType::Text, false),
    ("checksum", SqlType::U64, false),
    ("signature_hex", SqlType::Text, false),
    ("file_size", SqlType::U64, false),
    ("header_size", SqlType::U64, false),
    ("endian_tag", SqlType::U64, false),
    ("link_size", SqlType::U64, false),
    ("link_off", SqlType::U64, false),
    ("map_off", SqlType::U64, false),
    ("string_count", SqlType::U64, false),
    ("string_ids_off", SqlType::U64, false),
    ("type_count", SqlType::U64, false),
    ("type_ids_off", SqlType::U64, false),
    ("proto_count", SqlType::U64, false),
    ("proto_ids_off", SqlType::U64, false),
    ("field_count", SqlType::U64, false),
    ("field_ids_off", SqlType::U64, false),
    ("method_count", SqlType::U64, false),
    ("method_ids_off", SqlType::U64, false),
    ("class_count", SqlType::U64, false),
    ("class_defs_off", SqlType::U64, false),
    ("data_size", SqlType::U64, false),
    ("data_off", SqlType::U64, false),
];
const STRINGS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("string_pool_id", SqlType::U64, false),
    ("string_idx", SqlType::U64, false),
    ("value", SqlType::Text, false),
];
const TYPES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("type_idx", SqlType::U64, false),
    ("descriptor", SqlType::Text, false),
    ("java_name", SqlType::Text, false),
];
const METHODS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("class_descriptor", SqlType::Text, false),
    ("proto_idx", SqlType::U64, false),
    ("name", SqlType::Text, false),
    ("descriptor", SqlType::Text, false),
    ("return_descriptor", SqlType::Text, false),
    ("param_count", SqlType::U64, false),
    ("param_descriptors", SqlType::Text, false),
    ("access_flags", SqlType::U64, true),
    ("opcode_count", SqlType::U64, true),
    ("opcode_hex", SqlType::Text, true),
    ("method_kind", SqlType::Text, true),
];
const CLASSES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_def_idx", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("descriptor", SqlType::Text, false),
    ("access_flags", SqlType::U64, false),
    ("superclass_descriptor", SqlType::Text, true),
    ("interface_count", SqlType::U64, false),
    ("source_file", SqlType::Text, true),
];
const CLASS_INTERFACES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("interface_type_idx", SqlType::U64, false),
    ("interface_descriptor", SqlType::Text, false),
];
const CLASS_FIELDS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("class_descriptor", SqlType::Text, false),
    ("field_idx", SqlType::U64, false),
    ("field_name", SqlType::Text, false),
    ("field_descriptor", SqlType::Text, false),
    ("kind", SqlType::Text, false),
    ("access_flags", SqlType::U64, false),
];
const CLASS_METHODS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("class_descriptor", SqlType::Text, false),
    ("method_idx", SqlType::U64, false),
    ("method_name", SqlType::Text, false),
    ("method_descriptor", SqlType::Text, false),
    ("kind", SqlType::Text, false),
    ("access_flags", SqlType::U64, false),
];
const CODE_ITEMS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("code_off", SqlType::U64, false),
    ("registers_size", SqlType::U64, false),
    ("ins_size", SqlType::U64, false),
    ("outs_size", SqlType::U64, false),
    ("tries_size", SqlType::U64, false),
    ("debug_info_off", SqlType::U64, false),
    ("insns_size", SqlType::U64, false),
    ("insns_off", SqlType::U64, false),
    ("tries_off", SqlType::U64, true),
    ("handlers_off", SqlType::U64, true),
];
const ANNOTATION_DIRECTORY_ENTRIES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("annotations_off", SqlType::U64, false),
    ("entry_kind", SqlType::Text, false),
    ("entry_idx", SqlType::U64, false),
    ("annotation_set_off", SqlType::U64, true),
    ("annotation_set_ref_list_off", SqlType::U64, true),
];
const ANNOTATION_SET_ENTRIES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("annotation_set_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("annotation_off", SqlType::U64, false),
];
const ANNOTATIONS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("annotation_off", SqlType::U64, false),
    ("visibility", SqlType::U64, false),
    ("type_idx", SqlType::U64, false),
    ("element_count", SqlType::U64, false),
];
const ANNOTATION_ELEMENTS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("annotation_off", SqlType::U64, false),
    ("depth", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("name_idx", SqlType::U64, true),
    ("value_off", SqlType::U64, false),
    ("value_end_off", SqlType::U64, false),
    ("value_kind", SqlType::Text, false),
    ("value_index", SqlType::U64, true),
    ("value_i64", SqlType::I64, true),
    ("value_f64", SqlType::F64, true),
];
const METHOD_STRINGS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("method", SqlType::Text, false),
    ("method_class", SqlType::Text, false),
    ("method_name", SqlType::Text, false),
    ("value", SqlType::Text, false),
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("string_idx", SqlType::U64, false),
];
const METHOD_CALLS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("method", SqlType::Text, false),
    ("method_class", SqlType::Text, false),
    ("method_name", SqlType::Text, false),
    ("callee", SqlType::Text, false),
    ("callee_class", SqlType::Text, false),
    ("callee_name", SqlType::Text, false),
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("callee_method_idx", SqlType::U64, false),
];
const METHOD_FIELD_ACCESSES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("method", SqlType::Text, false),
    ("method_class", SqlType::Text, false),
    ("method_name", SqlType::Text, false),
    ("field", SqlType::Text, false),
    ("field_class", SqlType::Text, false),
    ("field_name", SqlType::Text, false),
    ("field_type", SqlType::Text, false),
    ("using_type", SqlType::Text, true),
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("field_idx", SqlType::U64, false),
];
const METHOD_USED_TYPES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("method", SqlType::Text, false),
    ("method_class", SqlType::Text, false),
    ("method_name", SqlType::Text, false),
    ("type_descriptor", SqlType::Text, false),
    ("type_name", SqlType::Text, false),
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("type_idx", SqlType::U64, false),
];

/// The two `dex_files` provenance columns of one selected occurrence.
///
/// Both values are owned by the snapshot and archive layers and are resolved by
/// [`SelectedScope::dex_file_provenance`]; this struct only carries them into the
/// SQL projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostLabProvenance {
    pub source_path: String,
    pub entry_name: String,
}

/// Provenance resolution failures are contract gaps, not NULLs.
///
/// `dex_files.source_path` and `dex_files.entry_name` are `nullable: false`, so
/// an occurrence whose captured path or archive member name has no lossless
/// UTF-8 form can never be answered truthfully. The upstream resolver reports
/// that as `UNSUPPORTED_QUERY`; this provider re-states it as
/// `INCOMPLETE_FACTS` naming the column and keeps the original code, reason and
/// identity details. Empty text is not substituted because an empty path/member
/// is a different value from an unavailable one.
fn provenance_gap(occurrence: &HostLabOccurrence, column: &str, cause: MddError) -> MddError {
    MddError::new(
        ErrorCode::IncompleteFacts,
        "sql.hostlab.provenance",
        "dex_files provenance is not representable for this occurrence",
    )
    .detail("column", column.to_owned())
    .detail("nullable_contract", "false")
    .detail(
        "resolution",
        "fail_closed; no NULL and no empty placeholder",
    )
    .detail("cause_code", cause.code.to_string())
    .detail("cause_message", cause.message.clone())
    .detail(
        "cause_reason",
        cause.details.get("reason").cloned().unwrap_or_default(),
    )
    .detail(
        "dex_occurrence_id",
        occurrence.source().dex_occurrence_id.clone(),
    )
    .detail("member_id", occurrence.source().member_id.clone())
    .detail(
        "source_occurrence_id",
        occurrence.source().source_occurrence_id.clone(),
    )
}

/// Fact layers for one selected DEX occurrence.
pub struct HostLabOccurrenceFacts {
    metadata: Arc<MetadataFacts>,
    definitions: Option<Arc<DefinitionFacts>>,
    code: Option<Arc<CodeFacts>>,
    references: Option<Arc<ReferenceFacts>>,
    annotations: Option<Arc<AnnotationFacts>>,
}

impl HostLabOccurrenceFacts {
    pub fn structural(metadata: Arc<MetadataFacts>, definitions: Arc<DefinitionFacts>) -> Self {
        Self {
            metadata,
            definitions: Some(definitions),
            code: None,
            references: None,
            annotations: None,
        }
    }

    pub fn complete(
        metadata: Arc<MetadataFacts>,
        definitions: Arc<DefinitionFacts>,
        code: Arc<CodeFacts>,
        references: Arc<ReferenceFacts>,
        annotations: Arc<AnnotationFacts>,
    ) -> Self {
        Self {
            metadata,
            definitions: Some(definitions),
            code: Some(code),
            references: Some(references),
            annotations: Some(annotations),
        }
    }

    /// Build the requested layers from one cached session occurrence. Layers are
    /// requested in dependency order so the session reuses its own `Arc`s.
    pub fn from_session(
        session: &FactsSession,
        index: usize,
        code: bool,
        references: bool,
        annotations: bool,
    ) -> MddResult<Self> {
        let metadata = session.metadata(index)?;
        let definitions = session.definitions(index)?;
        let code_facts = if code || references {
            Some(session.code(index)?)
        } else {
            None
        };
        let reference_facts = if references {
            Some(session.references(index)?)
        } else {
            None
        };
        let annotation_facts = if annotations {
            Some(session.annotations(index)?)
        } else {
            None
        };
        Ok(Self {
            metadata,
            definitions: Some(definitions),
            code: code_facts,
            references: reference_facts,
            annotations: annotation_facts,
        })
    }

    pub fn metadata(&self) -> &Arc<MetadataFacts> {
        &self.metadata
    }
}

/// One selected DEX occurrence with its validated coordinates.
struct HostLabOccurrence {
    facts: HostLabOccurrenceFacts,
    /// Resolved `source_path`/`entry_name`, or the preserved reason they cannot
    /// be represented. `dex_files` needs both; no other relation reads them.
    provenance: Result<HostLabProvenance, MddError>,
    /// Selected-DEX roster position, confirmed against the scope coordinate
    /// source. The contract `file_id` and `string_pool_id` are both this value
    /// for every observed sample; they stay separate fields so a future rule
    /// can split them without reshaping the rows.
    file_id: u32,
    string_pool_id: u32,
}

impl HostLabOccurrence {
    fn source(&self) -> &mdd_facts::metadata::MetadataSource {
        self.facts.metadata.source()
    }

    fn definitions(&self) -> MddResult<&DefinitionFacts> {
        self.facts.definitions.as_deref().ok_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "sql.hostlab",
                "definition facts are not attached to this occurrence",
            )
            .detail("required_layer", "structure")
            .detail("dex_occurrence_id", self.source().dex_occurrence_id.clone())
        })
    }

    fn code(&self) -> MddResult<&CodeFacts> {
        self.facts.code.as_deref().ok_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "sql.hostlab",
                "code-layout facts are not attached to this occurrence",
            )
            .detail("required_layer", "code_layout")
            .detail("dex_occurrence_id", self.source().dex_occurrence_id.clone())
        })
    }

    fn references(&self) -> MddResult<&ReferenceFacts> {
        self.facts.references.as_deref().ok_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "sql.hostlab",
                "reference facts are not attached to this occurrence",
            )
            .detail("required_layer", "references")
            .detail("dex_occurrence_id", self.source().dex_occurrence_id.clone())
        })
    }

    fn annotations(&self) -> MddResult<&AnnotationFacts> {
        let annotations = self.facts.annotations.as_deref().ok_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "sql.hostlab",
                "annotation facts are not attached to this occurrence",
            )
            .detail("required_layer", "annotations")
            .detail("dex_occurrence_id", self.source().dex_occurrence_id.clone())
        })?;
        if annotations.annotation_coverage() != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "sql.hostlab",
                "complete annotation facts are required",
            )
            .detail("dex_occurrence_id", self.source().dex_occurrence_id.clone()));
        }
        Ok(annotations)
    }
}

/// Contract-name provider over one immutable snapshot generation.
pub struct HostLabSqlProvider {
    binding: SqlBinding,
    occurrences: Vec<HostLabOccurrence>,
    /// The selected scope the coverage ledger is bound to.
    scope: SelectedScope,
    /// One coverage verdict per contract relation, computed on first use. The
    /// ledger is immutable once the provider exists, so a verdict (including a
    /// refusal) never changes and is not recomputed for every scan.
    coverage: [std::sync::OnceLock<Result<(), MddError>>; HostLabRelation::ALL.len()],
}

impl HostLabSqlProvider {
    /// Bind the contract relation names to an explicit selected scope.
    ///
    /// `facts` must be in selected-roster order. The scope supplies the
    /// DEX/metadata pairing, the pool coordinate and the provenance text, so no
    /// second numbering or path convention is introduced here. A provenance
    /// value that the snapshot/archive layers cannot represent losslessly is
    /// retained as a deferred gap: registration and schema still succeed, and
    /// only `dex_files` fails, naming the column.
    pub fn from_scope(
        scope: &SelectedScope,
        facts: Vec<HostLabOccurrenceFacts>,
        epoch: DecimalU64,
    ) -> MddResult<Self> {
        if !scope.roster_complete() {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "sql.hostlab",
                "selected DEX roster is incomplete",
            ));
        }
        let count = scope.dexes().len();
        if count == 0 {
            return Err(invalid("HOSTLAB_SCOPE_HAS_NO_DEX"));
        }
        if facts.len() != count {
            return Err(
                invalid("HOSTLAB_SCOPE_ARITY").detail("selected_dex_count", count.to_string())
            );
        }
        if u64::try_from(count).unwrap_or(u64::MAX) > MAX_HOSTLAB_OCCURRENCES {
            return Err(quota("HOSTLAB_SCOPE_TOO_LARGE"));
        }
        let metadata: Vec<&MetadataFacts> = facts.iter().map(|f| f.metadata.as_ref()).collect();
        // Validate the supplied fact order against the scope roster before
        // moving anything: `metadata_rows` pairs every selected DEX with the
        // metadata built from that same occurrence, and the pool coordinates
        // must describe the same roster in the same order.
        let ordinals: Vec<u32> = {
            let rows = scope.metadata_rows(&metadata, MAX_HOSTLAB_OCCURRENCES)?;
            let coordinates =
                scope.occurrence_pool_coordinates(&metadata, MAX_HOSTLAB_OCCURRENCES)?;
            if rows.len() != count || coordinates.rows.len() != count {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "sql.hostlab",
                    "selected DEX metadata is incomplete",
                ));
            }
            for (((selected, projected), returned), coordinate) in
                rows.iter().zip(facts.iter()).zip(coordinates.rows.iter())
            {
                if selected.dex_occurrence_id != projected.source().dex_occurrence_id
                    || !std::ptr::eq(*projected, returned.metadata.as_ref())
                    || coordinate.dex.dex_occurrence_id != selected.dex_occurrence_id
                {
                    return Err(invalid("HOSTLAB_SCOPE_METADATA_MISMATCH"));
                }
            }
            coordinates
                .rows
                .iter()
                .map(|row| row.occurrence_pool_ordinal)
                .collect()
        };
        let mut occurrences = Vec::new();
        occurrences
            .try_reserve_exact(count)
            .map_err(|_| quota("HOSTLAB_OCCURRENCE_ALLOCATION"))?;
        for (position, (occurrence_fact, ordinal)) in facts.into_iter().zip(ordinals).enumerate() {
            // A non-dense or reordered coordinate would silently renumber every
            // JOIN key, so it is checked instead of being trusted.
            if usize::try_from(ordinal).ok() != Some(position) {
                return Err(invalid("HOSTLAB_NON_DENSE_POOL_COORDINATE"));
            }
            // The scope owns provenance resolution; a failure is preserved so
            // `dex_files` can report the exact column and cause later.
            let provenance = scope
                .dex_file_provenance(&scope.dexes()[position])
                .map(|resolved| HostLabProvenance {
                    source_path: resolved.source_path,
                    entry_name: resolved.entry_name,
                });
            occurrences.push(HostLabOccurrence {
                facts: occurrence_fact,
                provenance,
                file_id: ordinal,
                string_pool_id: ordinal,
            });
        }
        let snapshot_id = occurrences
            .first()
            .ok_or_else(|| invalid("HOSTLAB_SCOPE_HAS_NO_DEX"))?
            .source()
            .snapshot_id
            .clone();
        for occurrence in &occurrences {
            if occurrence.source().snapshot_id != snapshot_id {
                return Err(invalid("HOSTLAB_SCOPE_SNAPSHOT_MISMATCH"));
            }
        }
        Ok(Self {
            binding: SqlBinding {
                provider_identity: mdd_types::opaque_id("sql-hostlab-provider")?,
                snapshot_id,
                catalog_epoch: epoch,
            },
            occurrences,
            scope: scope.clone(),
            coverage: std::array::from_fn(|_| std::sync::OnceLock::new()),
        })
    }

    pub fn occurrence_count(&self) -> usize {
        self.occurrences.len()
    }

    fn relation(name: HostLabRelation) -> SqlRelation {
        SqlRelation {
            name: name.name().to_owned(),
            columns: name
                .columns()
                .iter()
                .map(|(name, data_type, nullable)| SqlColumn {
                    id: (*name).into(),
                    name: (*name).into(),
                    data_type: *data_type,
                    nullable: *nullable,
                })
                .collect(),
            required_layers: name.required_layers(),
            estimated_rows: None,
        }
    }

    /// Estimated row counts where a fact layer already holds the answer, so no
    /// extra scan is needed during optimizer setup.
    ///
    /// A relation whose layer is not attached reports `None` instead of failing:
    /// schema publication must not require every optional layer, otherwise a
    /// metadata-only provider could not even answer `dex_files`. The hard gate
    /// stays in [`Self::require_layer`], which runs when the relation is opened.
    fn estimated_rows(&self, relation: HostLabRelation) -> MddResult<Option<u64>> {
        let mut total = 0u64;
        for occurrence in &self.occurrences {
            let add =
                |value: usize| u64::try_from(value).map_err(|_| quota("HOSTLAB_ROW_OVERFLOW"));
            let count = match relation {
                HostLabRelation::DexFiles => 1,
                HostLabRelation::Strings => add(occurrence.facts.metadata.strings().len())?,
                HostLabRelation::Types => add(occurrence.facts.metadata.types().len())?,
                HostLabRelation::Methods
                    if occurrence.facts.definitions.is_some()
                        && occurrence.facts.code.is_some() =>
                {
                    add(occurrence
                        .definitions()?
                        .definitions()
                        .method_references
                        .len())?
                }
                HostLabRelation::Classes if occurrence.facts.definitions.is_some() => {
                    add(occurrence.definitions()?.definitions().classes.len())?
                }
                HostLabRelation::ClassInterfaces if occurrence.facts.definitions.is_some() => {
                    add(occurrence.definitions()?.definitions().interfaces.len())?
                }
                HostLabRelation::ClassFields if occurrence.facts.definitions.is_some() => {
                    add(occurrence
                        .definitions()?
                        .definitions()
                        .field_definitions
                        .len())?
                }
                HostLabRelation::ClassMethods if occurrence.facts.definitions.is_some() => {
                    add(occurrence
                        .definitions()?
                        .definitions()
                        .method_definitions
                        .len())?
                }
                HostLabRelation::CodeItems if occurrence.facts.code.is_some() => {
                    add(occurrence.code()?.items().len())?
                }
                HostLabRelation::AnnotationDirectoryEntries
                    if occurrence.facts.annotations.is_some() =>
                {
                    let data = occurrence.annotations()?.data();
                    // Every directory binding contributes one row per entry.
                    let entries =
                        data.directory_bindings
                            .iter()
                            .try_fold(0usize, |total, binding| {
                                let rows = data
                                    .directories
                                    .iter()
                                    .find(|item| item.byte_offset == binding.directory_byte_offset)
                                    .map_or(1usize, |item| {
                                        1usize.saturating_add(item.entries.len())
                                    });
                                total.checked_add(rows)
                            });
                    add(entries.ok_or_else(|| quota("HOSTLAB_ROW_OVERFLOW"))?)?
                }
                HostLabRelation::AnnotationSetEntries if occurrence.facts.annotations.is_some() => {
                    let data = occurrence.annotations()?.data();
                    let entries = data.sets.iter().try_fold(0usize, |total, set| {
                        total.checked_add(set.annotation_offsets.len())
                    });
                    add(entries.ok_or_else(|| quota("HOSTLAB_ROW_OVERFLOW"))?)?
                }
                HostLabRelation::Annotations if occurrence.facts.annotations.is_some() => {
                    add(occurrence.annotations()?.data().annotation_items.len())?
                }
                HostLabRelation::AnnotationElements if occurrence.facts.annotations.is_some() => {
                    add(occurrence.annotations()?.data().values.len())?
                }
                HostLabRelation::MethodStrings
                | HostLabRelation::MethodCalls
                | HostLabRelation::MethodFieldAccesses
                | HostLabRelation::MethodUsedTypes
                    if occurrence.facts.references.is_some() =>
                {
                    // Upper bound: the filtered projection never exceeds all sites.
                    add(occurrence.references()?.sites().len())?
                }
                // The layer is not attached, so no estimate is claimed.
                _ => return Ok(None),
            };
            total = total
                .checked_add(count)
                .ok_or_else(|| quota("HOSTLAB_ROW_OVERFLOW"))?;
        }
        Ok(Some(total))
    }

    /// Project one occurrence. Rows are materialized per occurrence so peak
    /// memory follows one DEX, not the whole selected roster.
    fn occurrence_rows(
        &self,
        relation: HostLabRelation,
        occurrence: &HostLabOccurrence,
        control: &SqlControl,
    ) -> MddResult<Vec<SqlRow>> {
        let file_id = occurrence.file_id;
        let pool_id = occurrence.string_pool_id;
        match relation {
            HostLabRelation::DexFiles => {
                let row = occurrence
                    .facts
                    .metadata
                    .dex_file_rows(file_id, pool_id)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "sql.hostlab",
                            "dex_file_rows returned no row for one occurrence",
                        )
                    })?;
                // `source_path`/`entry_name` are snapshot/archive provenance.
                // The contract marks both NOT NULL, so an unavailable value is
                // an explicit gap, never a NULL or an empty placeholder.
                let provenance = occurrence
                    .provenance
                    .as_ref()
                    .map_err(|error| provenance_gap(occurrence, "source_path", error.clone()))?;
                control.work(200)?;
                Ok(vec![vec![
                    number(u64::from(row.file_id)),
                    number(u64::from(row.string_pool_id)),
                    text(&provenance.source_path),
                    text(&provenance.entry_name),
                    number(row.byte_len),
                    text(&row.dex_version),
                    number(u64::from(row.checksum)),
                    text(&row.signature_hex),
                    number(u64::from(row.file_size)),
                    number(u64::from(row.header_size)),
                    number(u64::from(row.endian_tag)),
                    number(u64::from(row.link_size)),
                    number(u64::from(row.link_off)),
                    number(u64::from(row.map_off)),
                    number(u64::from(row.string_count)),
                    number(u64::from(row.string_ids_off)),
                    number(u64::from(row.type_count)),
                    number(u64::from(row.type_ids_off)),
                    number(u64::from(row.proto_count)),
                    number(u64::from(row.proto_ids_off)),
                    number(u64::from(row.field_count)),
                    number(u64::from(row.field_ids_off)),
                    number(u64::from(row.method_count)),
                    number(u64::from(row.method_ids_off)),
                    number(u64::from(row.class_count)),
                    number(u64::from(row.class_defs_off)),
                    number(u64::from(row.data_size)),
                    number(u64::from(row.data_off)),
                ]])
            }
            HostLabRelation::Strings => {
                let rows = occurrence.facts.metadata.string_rows(file_id, pool_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.string_pool_id)),
                            number(u64::from(row.string_idx)),
                            text(&row.value),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::Types => {
                let rows = occurrence.facts.metadata.type_rows(file_id)?;
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.type_idx)),
                            text(&row.descriptor),
                            text(&row.java_name),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::Methods => {
                // The fact layer owns the full 14-column `methods` projection,
                // including the opcode and parameter-descriptor tokenizers, so
                // this provider maps rows instead of re-deriving them.
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.method_rows(file_id)?;
                control.work(192u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.class_idx)),
                            text(&row.class_descriptor),
                            number(u64::from(row.proto_idx)),
                            text(&row.name),
                            text(&row.descriptor),
                            text(&row.return_descriptor),
                            number(u64::from(row.param_count)),
                            text(&row.param_descriptors),
                            row.access_flags
                                .map_or(SqlValue::Null, |v| number(u64::from(v))),
                            row.opcode_count
                                .map_or(SqlValue::Null, |v| number(u64::from(v))),
                            row.opcode_hex.as_deref().map_or(SqlValue::Null, text),
                            row.method_kind.as_deref().map_or(SqlValue::Null, text),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::Classes => {
                let rows = occurrence.definitions()?.class_rows(file_id)?;
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_def_idx)),
                            number(u64::from(row.class_idx)),
                            text(&row.descriptor),
                            number(u64::from(row.access_flags)),
                            row.superclass_descriptor
                                .as_deref()
                                .map_or(SqlValue::Null, text),
                            number(u64::from(row.interface_count)),
                            row.source_file.as_deref().map_or(SqlValue::Null, text),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::ClassInterfaces => {
                let rows = occurrence.definitions()?.class_interface_rows(file_id);
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.ordinal)),
                            number(u64::from(row.interface_type_idx)),
                            text(&row.interface_descriptor),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::ClassFields => {
                let rows = occurrence.definitions()?.class_field_rows(file_id);
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            text(&row.class_descriptor),
                            number(u64::from(row.field_idx)),
                            text(&row.field_name),
                            text(&row.field_descriptor),
                            text(&row.kind),
                            number(u64::from(row.access_flags)),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::ClassMethods => {
                let rows = occurrence.definitions()?.class_method_rows(file_id);
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            text(&row.class_descriptor),
                            number(u64::from(row.method_idx)),
                            text(&row.method_name),
                            text(&row.method_descriptor),
                            text(&row.kind),
                            number(u64::from(row.access_flags)),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::CodeItems => {
                let definitions = occurrence.definitions()?;
                let code = occurrence.code()?;
                let views =
                    MethodCodeFactViews::build(definitions, code, MethodCodeViewLimits::default())?;
                let rows = views.code_item_rows(file_id)?;
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.code_off)),
                            number(u64::from(row.registers_size)),
                            number(u64::from(row.ins_size)),
                            number(u64::from(row.outs_size)),
                            number(u64::from(row.tries_size)),
                            number(u64::from(row.debug_info_off)),
                            number(u64::from(row.insns_size)),
                            number(u64::from(row.insns_off)),
                            row.tries_off
                                .map_or(SqlValue::Null, |v| number(u64::from(v))),
                            row.handlers_off
                                .map_or(SqlValue::Null, |v| number(u64::from(v))),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::AnnotationDirectoryEntries => {
                let rows = occurrence.annotations()?.directory_entry_rows(file_id);
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.annotations_off)),
                            text(&row.entry_kind),
                            number(u64::from(row.entry_idx)),
                            row.annotation_set_off
                                .map_or(SqlValue::Null, |v| number(u64::from(v))),
                            row.annotation_set_ref_list_off
                                .map_or(SqlValue::Null, |v| number(u64::from(v))),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::AnnotationSetEntries => {
                let rows = occurrence.annotations()?.reachable_set_entry_rows(file_id);
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.annotation_set_off)),
                            number(u64::from(row.ordinal)),
                            number(u64::from(row.annotation_off)),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::Annotations => {
                let rows = occurrence.annotations()?.reachable_annotation_rows(file_id);
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.annotation_off)),
                            number(u64::from(row.visibility)),
                            number(u64::from(row.type_idx)),
                            number(u64::from(row.element_count)),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::AnnotationElements => {
                let rows = occurrence.annotations()?.reachable_element_rows(file_id);
                control.work(128u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        // The contract `value_i64` is Int64; the fact layer keeps
                        // the exact canonical decimal string, which is parsed here
                        // instead of being re-encoded through a lossy carrier.
                        let value_i64 = match row.value_i64.as_deref() {
                            None => Ok(SqlValue::Null),
                            Some(text) => text.parse::<i64>().map_or_else(
                                |_| {
                                    Err(MddError::new(
                                        ErrorCode::InternalFault,
                                        "sql.hostlab",
                                        "encoded integer value is not a canonical i64 decimal",
                                    )
                                    .detail("value", text.to_owned()))
                                },
                                |value| Ok(SqlValue::I64(mdd_query::ir::Signed64(value))),
                            ),
                        }?;
                        let value_f64 = row.value_f64.map_or(SqlValue::Null, |value| {
                            // Widen the exact encoded float into the contract's
                            // Float64 carrier; the 32-bit case is exactly
                            // representable in binary64.
                            SqlValue::F64(DecimalU64(value.as_f64().to_bits()))
                        });
                        Ok(vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.annotation_off)),
                            number(u64::from(row.depth)),
                            number(u64::from(row.ordinal)),
                            row.name_idx
                                .map_or(SqlValue::Null, |v| number(u64::from(v))),
                            number(u64::from(row.value_off)),
                            number(u64::from(row.value_end_off)),
                            text(&row.value_kind),
                            row.value_index
                                .map_or(SqlValue::Null, |v| number(u64::from(v))),
                            value_i64,
                            value_f64,
                        ])
                    })
                    .collect::<MddResult<Vec<_>>>()?)
            }
            HostLabRelation::MethodStrings => {
                let rows = occurrence.references()?.method_string_rows(file_id)?;
                control.work(128u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            text(&row.method),
                            text(&row.method_class),
                            text(&row.method_name),
                            text(&row.value),
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.string_idx)),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::MethodCalls => {
                let rows = occurrence.references()?.method_call_rows(file_id)?;
                control.work(160u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            text(&row.method),
                            text(&row.method_class),
                            text(&row.method_name),
                            text(&row.callee),
                            text(&row.callee_class),
                            text(&row.callee_name),
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.callee_method_idx)),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::MethodFieldAccesses => {
                let rows = occurrence.references()?.method_field_rows(file_id)?;
                control.work(192u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            text(&row.method),
                            text(&row.method_class),
                            text(&row.method_name),
                            text(&row.field),
                            text(&row.field_class),
                            text(&row.field_name),
                            text(&row.field_type),
                            row.using_type.as_deref().map_or(SqlValue::Null, text),
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.field_idx)),
                        ]
                    })
                    .collect())
            }
            HostLabRelation::MethodUsedTypes => {
                let rows = occurrence.references()?.method_type_rows(file_id)?;
                control.work(160u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            text(&row.method),
                            text(&row.method_class),
                            text(&row.method_name),
                            text(&row.type_descriptor),
                            text(&row.type_name),
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.type_idx)),
                        ]
                    })
                    .collect())
            }
        }
    }

    /// Require the coverage ledger to prove every frozen column of `relation`
    /// for the whole selected scope.
    ///
    /// [`Self::require_layer`] only checks each layer's own completeness flag.
    /// The ledger additionally answers per column: a column whose owning
    /// provider rejects it, a non-scalar text projection, or a parameter
    /// position that the encoded slots do not prove is `Unknown` and blocks the
    /// whole relation instead of returning rows that look complete. This is the
    /// production path that fills `required_columns`.
    fn require_coverage(&self, relation: HostLabRelation) -> MddResult<()> {
        let slot = HostLabRelation::ALL
            .iter()
            .position(|candidate| *candidate == relation)
            .ok_or_else(|| invalid("UNKNOWN_HOSTLAB_RELATION"))?;
        self.coverage[slot]
            .get_or_init(|| self.evaluate_coverage(relation))
            .clone()
    }

    fn evaluate_coverage(&self, relation: HostLabRelation) -> MddResult<()> {
        let views: Vec<FactView<'_>> = self
            .occurrences
            .iter()
            .map(|occurrence| {
                let mut view = FactView::unbuilt(occurrence.source().dex_occurrence_id.clone())
                    .with_metadata(occurrence.facts.metadata.as_ref());
                if let Some(definitions) = occurrence.facts.definitions.as_deref() {
                    view = view.with_definitions(definitions);
                }
                if let Some(code) = occurrence.facts.code.as_deref() {
                    view = view.with_code(code);
                }
                if let Some(annotations) = occurrence.facts.annotations.as_deref() {
                    view = view.with_annotations(annotations);
                }
                if let Some(references) = occurrence.facts.references.as_deref() {
                    view = view.with_references(references);
                }
                view
            })
            .collect();
        let ledger = CoverageLedger::new(self.scope.clone(), &views)?;
        let request = CoverageRequest::for_relations(&self.scope, &[relation.name()])?;
        let report = ledger.evaluate(&request)?;
        report.require_complete().map_err(|error| {
            // The ledger's own error does not say which column stopped it; name
            // the first blocking issues so a refusal is diagnosable.
            let first = report
                .issues
                .iter()
                .filter(|issue| issue.blocking)
                .take(3)
                .map(|issue| {
                    format!(
                        "{}.{}: {}",
                        issue.layer,
                        issue.column.as_deref().unwrap_or("*"),
                        issue.reason
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            error
                .detail("relation", relation.name())
                .detail("first_blocking_issues", first)
        })
    }

    /// Fail closed when a relation's fact layer is absent or incomplete.
    fn require_layer(&self, relation: HostLabRelation) -> MddResult<()> {
        for occurrence in &self.occurrences {
            let complete = match relation {
                HostLabRelation::DexFiles | HostLabRelation::Strings | HostLabRelation::Types => {
                    occurrence.facts.metadata.metadata_coverage() == Completeness::Complete
                }
                HostLabRelation::Classes
                | HostLabRelation::ClassInterfaces
                | HostLabRelation::ClassFields
                | HostLabRelation::ClassMethods => {
                    let definitions = occurrence.definitions()?;
                    definitions.definition_coverage() == Completeness::Complete
                        && definitions.metadata().metadata_coverage() == Completeness::Complete
                }
                HostLabRelation::Methods | HostLabRelation::CodeItems => {
                    let definitions = occurrence.definitions()?;
                    let code = occurrence.code()?;
                    definitions.definition_coverage() == Completeness::Complete
                        && definitions.metadata().metadata_coverage() == Completeness::Complete
                        && code.code_layout_coverage() == Completeness::Complete
                }
                HostLabRelation::AnnotationDirectoryEntries
                | HostLabRelation::AnnotationSetEntries
                | HostLabRelation::Annotations
                | HostLabRelation::AnnotationElements => {
                    occurrence.annotations()?;
                    true
                }
                HostLabRelation::MethodStrings
                | HostLabRelation::MethodCalls
                | HostLabRelation::MethodFieldAccesses
                | HostLabRelation::MethodUsedTypes => {
                    occurrence.references()?.require_complete()?;
                    true
                }
            };
            if !complete {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "sql.hostlab",
                    "required fact layer is incomplete",
                )
                .detail("relation", relation.name())
                .detail(
                    "dex_occurrence_id",
                    occurrence.source().dex_occurrence_id.clone(),
                ));
            }
        }
        Ok(())
    }
}

fn number(value: u64) -> SqlValue {
    SqlValue::U64(DecimalU64(value))
}

fn text(value: &str) -> SqlValue {
    SqlValue::Text(SqlText::from_utf8(value))
}

struct HostLabCursor {
    provider: Arc<HostLabSqlProvider>,
    relation: HostLabRelation,
    occurrence: usize,
    rows: std::vec::IntoIter<SqlRow>,
    control: SqlControl,
}

impl SqlFactCursor for HostLabCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        loop {
            if let Some(row) = self.rows.next() {
                self.control.checkpoint(1, true)?;
                return Ok(Some(row));
            }
            let Some(occurrence) = self.provider.occurrences.get(self.occurrence) else {
                return Ok(None);
            };
            self.occurrence += 1;
            self.rows = self
                .provider
                .occurrence_rows(self.relation, occurrence, &self.control)?
                .into_iter();
        }
    }
}

impl SqlFactProvider for HostLabSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }

    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        let mut relations = Vec::new();
        relations
            .try_reserve_exact(HostLabRelation::ALL.len())
            .map_err(|_| quota("HOSTLAB_RELATION_ALLOCATION"))?;
        for relation in HostLabRelation::ALL {
            let mut projected = Self::relation(relation);
            projected.estimated_rows = self.estimated_rows(relation)?.map(DecimalU64);
            relations.push(projected);
        }
        Ok(relations)
    }

    fn require_relation(&self, relation: &str) -> MddResult<()> {
        let relation = HostLabRelation::parse(relation).ok_or_else(|| {
            invalid("UNKNOWN_HOSTLAB_RELATION").detail("relation", relation.to_owned())
        })?;
        self.require_layer(relation)?;
        self.require_coverage(relation)
    }

    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        let relation = HostLabRelation::parse(relation).ok_or_else(|| {
            invalid("UNKNOWN_HOSTLAB_RELATION").detail("relation", relation.to_owned())
        })?;
        self.require_layer(relation)?;
        self.require_coverage(relation)?;
        Ok(Box::new(HostLabCursor {
            provider: self,
            relation,
            occurrence: 0,
            rows: Vec::new().into_iter(),
            control,
        }))
    }
}

#[cfg(test)]
mod temp_tests;
#[cfg(test)]
mod tests;
