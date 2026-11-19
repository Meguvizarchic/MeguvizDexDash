//! The public relations beyond the seventeen HostLab contract names (MDD-070), served from the same validated
//! fact layers.
//!
//! A relation is registered here only when its rows are produced from validated facts and have been compared with
//! the recorded answers of the reference engine (`conformance/relations/public_relations_diff.py`). Together with
//! the seventeen contract relations they are the fifty-six relations of the frozen manifest, and a unit test holds
//! the registry to that list: a relation that is not registered is not advertised, not described and not
//! answerable, so a client never meets an empty table that stands for a missing one.
//!
//! The coverage ledger of `mdd-facts` proves the seventeen contract relations column by column. These relations are
//! gated by the completeness of the layers that build them (`required_layers`), checked for every selected DEX
//! before a cursor opens; a layer that is absent or incomplete is a refusal naming the relation and the layer.
use super::*;
use mdd_facts::code::{MethodCodeFactViews, MethodCodeViewLimits};

/// One public relation that is not among the seventeen HostLab contract names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicRelation {
    MapItems,
    IdItems,
    TypeIds,
    TypeLists,
    TypeListEntries,
    ProtoIds,
    Protos,
    ProtoParams,
    FieldIds,
    Fields,
    MethodIds,
    ClassDefs,
    ClassDataItems,
    MethodOpcodes,
    ClassDataMethods,
    TryItems,
    CatchHandlers,
    MethodRefs,
    MethodNumbers,
    MethodUsingNumbers,
    AnnotationDirectories,
    AnnotationSets,
    AnnotationSetRefLists,
    AnnotationSetRefs,
    AnnotationValues,
    AnnotationElementsResolved,
    MethodHandles,
    CallSites,
    CallSiteArgs,
    EncodedArrays,
    EncodedArrayValues,
    EncodedArrayOwners,
    ClassStaticValues,
    HiddenapiFlags,
    DebugInfo,
    DebugParameters,
    DebugPositions,
    DebugLocals,
    DebugOpcodes,
}

impl PublicRelation {
    /// The registered public relations.
    pub const ALL: [Self; 39] = [
        Self::MapItems,
        Self::IdItems,
        Self::TypeIds,
        Self::TypeLists,
        Self::TypeListEntries,
        Self::ProtoIds,
        Self::Protos,
        Self::ProtoParams,
        Self::FieldIds,
        Self::Fields,
        Self::MethodIds,
        Self::MethodOpcodes,
        Self::ClassDataMethods,
        Self::ClassDefs,
        Self::ClassDataItems,
        Self::TryItems,
        Self::CatchHandlers,
        Self::MethodRefs,
        Self::MethodNumbers,
        Self::MethodUsingNumbers,
        Self::AnnotationDirectories,
        Self::AnnotationSets,
        Self::AnnotationSetRefLists,
        Self::AnnotationSetRefs,
        Self::AnnotationValues,
        Self::AnnotationElementsResolved,
        Self::MethodHandles,
        Self::CallSites,
        Self::CallSiteArgs,
        Self::EncodedArrays,
        Self::EncodedArrayValues,
        Self::EncodedArrayOwners,
        Self::ClassStaticValues,
        Self::HiddenapiFlags,
        Self::DebugInfo,
        Self::DebugParameters,
        Self::DebugPositions,
        Self::DebugLocals,
        Self::DebugOpcodes,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::MapItems => "map_items",
            Self::IdItems => "id_items",
            Self::TypeIds => "type_ids",
            Self::TypeLists => "type_lists",
            Self::TypeListEntries => "type_list_entries",
            Self::ProtoIds => "proto_ids",
            Self::Protos => "protos",
            Self::ProtoParams => "proto_params",
            Self::FieldIds => "field_ids",
            Self::Fields => "fields",
            Self::MethodIds => "method_ids",
            Self::ClassDefs => "class_defs",
            Self::ClassDataItems => "class_data_items",
            Self::MethodOpcodes => "method_opcodes",
            Self::ClassDataMethods => "class_data_methods",
            Self::TryItems => "try_items",
            Self::CatchHandlers => "catch_handlers",
            Self::MethodRefs => "method_refs",
            Self::MethodNumbers => "method_numbers",
            Self::MethodUsingNumbers => "method_using_numbers",
            Self::AnnotationDirectories => "annotation_directories",
            Self::AnnotationSets => "annotation_sets",
            Self::AnnotationSetRefLists => "annotation_set_ref_lists",
            Self::AnnotationSetRefs => "annotation_set_refs",
            Self::AnnotationValues => "annotation_values",
            Self::AnnotationElementsResolved => "annotation_elements_resolved",
            Self::MethodHandles => "method_handles",
            Self::CallSites => "call_sites",
            Self::CallSiteArgs => "call_site_args",
            Self::EncodedArrays => "encoded_arrays",
            Self::EncodedArrayValues => "encoded_array_values",
            Self::EncodedArrayOwners => "encoded_array_owners",
            Self::ClassStaticValues => "class_static_values",
            Self::HiddenapiFlags => "hiddenapi_flags",
            Self::DebugInfo => "debug_info",
            Self::DebugParameters => "debug_parameters",
            Self::DebugPositions => "debug_positions",
            Self::DebugLocals => "debug_locals",
            Self::DebugOpcodes => "debug_opcodes",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|relation| relation.name() == name)
    }

    pub fn columns(self) -> &'static [(&'static str, SqlType, bool)] {
        match self {
            Self::MapItems => MAP_ITEMS_COLUMNS,
            Self::IdItems => ID_ITEMS_COLUMNS,
            Self::TypeIds => TYPE_IDS_COLUMNS,
            Self::TypeLists => TYPE_LISTS_COLUMNS,
            Self::TypeListEntries => TYPE_LIST_ENTRIES_COLUMNS,
            Self::ProtoIds => PROTO_IDS_COLUMNS,
            Self::Protos => PROTOS_COLUMNS,
            Self::ProtoParams => PROTO_PARAMS_COLUMNS,
            Self::FieldIds => FIELD_IDS_COLUMNS,
            Self::Fields => FIELDS_COLUMNS,
            Self::MethodIds => METHOD_IDS_COLUMNS,
            Self::ClassDefs => CLASS_DEFS_COLUMNS,
            Self::ClassDataItems => CLASS_DATA_ITEMS_COLUMNS,
            Self::MethodOpcodes => METHOD_OPCODES_COLUMNS,
            Self::ClassDataMethods => CLASS_DATA_METHODS_COLUMNS,
            Self::TryItems => TRY_ITEMS_COLUMNS,
            Self::CatchHandlers => CATCH_HANDLERS_COLUMNS,
            Self::MethodRefs => METHOD_REFS_COLUMNS,
            Self::MethodNumbers => METHOD_NUMBERS_COLUMNS,
            Self::MethodUsingNumbers => METHOD_USING_NUMBERS_COLUMNS,
            Self::AnnotationDirectories => ANNOTATION_DIRECTORIES_COLUMNS,
            Self::AnnotationSets => ANNOTATION_SETS_COLUMNS,
            Self::AnnotationSetRefLists => ANNOTATION_SET_REF_LISTS_COLUMNS,
            Self::AnnotationSetRefs => ANNOTATION_SET_REFS_COLUMNS,
            Self::AnnotationValues => ANNOTATION_VALUES_COLUMNS,
            Self::AnnotationElementsResolved => ANNOTATION_ELEMENTS_RESOLVED_COLUMNS,
            Self::MethodHandles => METHOD_HANDLES_COLUMNS,
            Self::CallSites => CALL_SITES_COLUMNS,
            Self::CallSiteArgs => CALL_SITE_ARGS_COLUMNS,
            Self::EncodedArrays => ENCODED_ARRAYS_COLUMNS,
            Self::EncodedArrayValues => ENCODED_ARRAY_VALUES_COLUMNS,
            Self::EncodedArrayOwners => ENCODED_ARRAY_OWNERS_COLUMNS,
            Self::ClassStaticValues => CLASS_STATIC_VALUES_COLUMNS,
            Self::HiddenapiFlags => HIDDENAPI_FLAGS_COLUMNS,
            Self::DebugInfo => DEBUG_INFO_COLUMNS,
            Self::DebugParameters => DEBUG_PARAMETERS_COLUMNS,
            Self::DebugPositions => DEBUG_POSITIONS_COLUMNS,
            Self::DebugLocals => DEBUG_LOCALS_COLUMNS,
            Self::DebugOpcodes => DEBUG_OPCODES_COLUMNS,
        }
    }

    pub fn required_layers(self) -> Vec<FactLayer> {
        match self {
            Self::MapItems
            | Self::IdItems
            | Self::TypeIds
            | Self::TypeLists
            | Self::TypeListEntries
            | Self::ProtoIds
            | Self::Protos
            | Self::ProtoParams => vec![FactLayer::Metadata],
            Self::FieldIds
            | Self::Fields
            | Self::MethodIds
            | Self::ClassDefs
            | Self::ClassDataItems
            | Self::ClassDataMethods => vec![FactLayer::Metadata, FactLayer::Structure],
            Self::MethodOpcodes
            | Self::DebugInfo
            | Self::DebugParameters
            | Self::DebugPositions
            | Self::DebugLocals
            | Self::DebugOpcodes
            | Self::TryItems
            | Self::CatchHandlers
            | Self::MethodNumbers
            | Self::MethodUsingNumbers => vec![
                FactLayer::Metadata,
                FactLayer::Structure,
                FactLayer::CodeLayout,
            ],
            Self::MethodRefs => vec![
                FactLayer::Metadata,
                FactLayer::Structure,
                FactLayer::CodeLayout,
                FactLayer::References,
            ],
            Self::AnnotationDirectories
            | Self::AnnotationSets
            | Self::AnnotationSetRefLists
            | Self::AnnotationSetRefs
            | Self::AnnotationValues
            | Self::AnnotationElementsResolved
            | Self::CallSites
            | Self::CallSiteArgs
            | Self::EncodedArrays
            | Self::EncodedArrayValues
            | Self::EncodedArrayOwners
            | Self::ClassStaticValues => vec![
                FactLayer::Metadata,
                FactLayer::Structure,
                FactLayer::Annotations,
            ],
            Self::MethodHandles | Self::HiddenapiFlags => {
                vec![FactLayer::Metadata, FactLayer::Structure]
            }
        }
    }
}

const MAP_ITEMS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("type_code", SqlType::U64, false),
    ("size", SqlType::U64, false),
    ("offset", SqlType::U64, false),
];
const ID_ITEMS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("item_type_code", SqlType::U64, false),
    ("idx", SqlType::U64, false),
    ("item_off", SqlType::U64, false),
    ("item_end_off", SqlType::U64, false),
    ("data_off", SqlType::U64, true),
];
const TYPE_IDS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("type_idx", SqlType::U64, false),
    ("descriptor_idx", SqlType::U64, false),
];
const TYPE_LISTS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("type_list_off", SqlType::U64, false),
    ("type_list_end_off", SqlType::U64, false),
    ("size", SqlType::U64, false),
];
const TYPE_LIST_ENTRIES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("type_list_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("type_idx", SqlType::U64, false),
];
const PROTO_IDS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("proto_idx", SqlType::U64, false),
    ("shorty_idx", SqlType::U64, false),
    ("return_type_idx", SqlType::U64, false),
    ("parameters_off", SqlType::U64, false),
];
const PROTOS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("proto_idx", SqlType::U64, false),
    ("shorty_idx", SqlType::U64, false),
    ("shorty", SqlType::Text, false),
    ("return_type_idx", SqlType::U64, false),
    ("return_descriptor", SqlType::Text, false),
    ("parameters_off", SqlType::U64, false),
    ("param_count", SqlType::U64, false),
    ("param_descriptors", SqlType::Text, false),
];
const PROTO_PARAMS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("proto_idx", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("type_idx", SqlType::U64, false),
    ("descriptor", SqlType::Text, false),
];
const FIELD_IDS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("field_idx", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("type_idx", SqlType::U64, false),
    ("name_idx", SqlType::U64, false),
];
const FIELDS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("field_idx", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("class_descriptor", SqlType::Text, false),
    ("type_idx", SqlType::U64, false),
    ("type_descriptor", SqlType::Text, false),
    ("name", SqlType::Text, false),
    ("descriptor", SqlType::Text, false),
];
const METHOD_IDS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("proto_idx", SqlType::U64, false),
    ("name_idx", SqlType::U64, false),
];
const CLASS_DEFS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_def_idx", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("access_flags", SqlType::U64, false),
    ("superclass_idx", SqlType::U64, true),
    ("interfaces_off", SqlType::U64, false),
    ("source_file_idx", SqlType::U64, true),
    ("annotations_off", SqlType::U64, false),
    ("class_data_off", SqlType::U64, false),
    ("static_values_off", SqlType::U64, false),
];
const CLASS_DATA_ITEMS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("class_data_off", SqlType::U64, false),
    ("class_data_end_off", SqlType::U64, false),
    ("static_fields_size", SqlType::U64, false),
    ("instance_fields_size", SqlType::U64, false),
    ("direct_methods_size", SqlType::U64, false),
    ("virtual_methods_size", SqlType::U64, false),
];

const METHOD_OPCODES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("opcode_count", SqlType::U64, true),
    ("opcode_hex", SqlType::Text, true),
];
const CLASS_DATA_METHODS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("access_flags", SqlType::U64, true),
    ("kind", SqlType::Text, true),
];
const TRY_ITEMS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("try_idx", SqlType::U64, false),
    ("start_addr", SqlType::U64, false),
    ("insn_count", SqlType::U64, false),
    ("handler_off", SqlType::U64, false),
];
const CATCH_HANDLERS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("handler_idx", SqlType::U64, false),
    ("handler_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("type_idx", SqlType::U64, true),
    ("addr", SqlType::U64, false),
    ("is_catch_all", SqlType::U64, false),
];
const METHOD_REFS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("index_kind", SqlType::Text, false),
    ("index", SqlType::U64, false),
    ("using_type", SqlType::Text, true),
];
const METHOD_NUMBERS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("opcode", SqlType::U64, false),
    ("number_type", SqlType::Text, false),
    ("long_value", SqlType::I64, false),
    ("double_value", SqlType::F64, true),
];
const METHOD_USING_NUMBERS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("method", SqlType::Text, false),
    ("method_class", SqlType::Text, false),
    ("method_name", SqlType::Text, false),
    ("number_type", SqlType::Text, false),
    ("long_value", SqlType::I64, false),
    ("double_value", SqlType::F64, true),
    ("opcode", SqlType::U64, false),
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
];

const ANNOTATION_DIRECTORIES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("annotations_off", SqlType::U64, false),
    ("class_annotations_off", SqlType::U64, true),
    ("fields_size", SqlType::U64, false),
    ("methods_size", SqlType::U64, false),
    ("parameters_size", SqlType::U64, false),
];
const ANNOTATION_SETS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("annotation_set_off", SqlType::U64, false),
    ("size", SqlType::U64, false),
];
const ANNOTATION_SET_REF_LISTS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("annotation_set_ref_list_off", SqlType::U64, false),
    ("size", SqlType::U64, false),
];
const ANNOTATION_SET_REFS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("annotation_set_ref_list_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("annotation_set_off", SqlType::U64, true),
];
// `owner_kind`, `parameter_idx` and `retention_policy` are computed columns of the reference (its type name is
// "sqlite_dynamic"); here they carry the type of the values they hold.
const ANNOTATION_VALUES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("owner_kind", SqlType::Text, false),
    ("owner_idx", SqlType::U64, false),
    ("owner_descriptor", SqlType::Text, true),
    ("parameter_idx", SqlType::U64, true),
    ("annotation_off", SqlType::U64, false),
    ("annotation_type_idx", SqlType::U64, false),
    ("annotation_descriptor", SqlType::Text, false),
    ("depth", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("name_idx", SqlType::U64, true),
    ("name", SqlType::Text, true),
    ("value_kind", SqlType::Text, false),
    ("value_i64", SqlType::I64, true),
    ("value_f64", SqlType::F64, true),
];
const ANNOTATION_ELEMENTS_RESOLVED_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("owner_kind", SqlType::Text, false),
    ("owner_idx", SqlType::U64, false),
    ("owner", SqlType::Text, true),
    ("parameter_idx", SqlType::U64, true),
    ("annotation", SqlType::Text, false),
    ("visibility", SqlType::U64, false),
    ("element_count", SqlType::U64, false),
    ("annotation_off", SqlType::U64, false),
    ("element_ordinal", SqlType::U64, true),
    ("element_name", SqlType::Text, true),
    ("value_kind", SqlType::Text, true),
    ("value_index", SqlType::U64, true),
    ("value_i64", SqlType::I64, true),
    ("value_f64", SqlType::F64, true),
    ("retention_policy", SqlType::Text, true),
];

const METHOD_HANDLES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_handle_idx", SqlType::U64, false),
    ("method_handle_type", SqlType::U64, false),
    ("member_idx", SqlType::U64, false),
];
const CALL_SITES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("call_site_idx", SqlType::U64, false),
    ("call_site_off", SqlType::U64, false),
    ("value_count", SqlType::U64, false),
    ("method_handle_idx", SqlType::U64, true),
    ("method_name_idx", SqlType::U64, true),
    ("proto_idx", SqlType::U64, true),
];
const CALL_SITE_ARGS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("call_site_idx", SqlType::U64, false),
    ("call_site_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("value_kind", SqlType::Text, false),
    ("value_index", SqlType::U64, true),
    ("value_i64", SqlType::I64, true),
    ("value_f64", SqlType::F64, true),
];
const ENCODED_ARRAYS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("encoded_array_idx", SqlType::U64, false),
    ("encoded_array_off", SqlType::U64, false),
    ("encoded_array_end_off", SqlType::U64, false),
    ("value_count", SqlType::U64, false),
];
const ENCODED_ARRAY_VALUES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("encoded_array_off", SqlType::U64, false),
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
const ENCODED_ARRAY_OWNERS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("encoded_array_off", SqlType::U64, false),
    ("owner_kind", SqlType::Text, false),
    ("owner_idx", SqlType::U64, false),
];
const CLASS_STATIC_VALUES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("static_values_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("field_idx", SqlType::U64, true),
    ("value_kind", SqlType::Text, false),
    ("value_index", SqlType::U64, true),
    ("value_i64", SqlType::I64, true),
    ("value_f64", SqlType::F64, true),
];
const HIDDENAPI_FLAGS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("class_idx", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("member_kind", SqlType::Text, false),
    ("member_idx", SqlType::U64, false),
    ("flag", SqlType::U64, false),
];

const DEBUG_INFO_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("debug_info_off", SqlType::U64, false),
    ("line_start", SqlType::U64, false),
    ("parameters_size", SqlType::U64, false),
];
const DEBUG_PARAMETERS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("debug_info_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("name_idx", SqlType::U64, true),
];
const DEBUG_POSITIONS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("debug_info_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("address", SqlType::U64, false),
    ("line", SqlType::I64, false),
    ("source_file_idx", SqlType::U64, true),
    ("prologue_end", SqlType::U64, false),
    ("epilogue_begin", SqlType::U64, false),
];
const DEBUG_LOCALS_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("debug_info_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("address", SqlType::U64, false),
    ("event", SqlType::Text, false),
    ("register_num", SqlType::U64, false),
    ("name_idx", SqlType::U64, true),
    ("type_idx", SqlType::U64, true),
    ("signature_idx", SqlType::U64, true),
];
const DEBUG_OPCODES_COLUMNS: &[(&str, SqlType, bool)] = &[
    ("file_id", SqlType::U64, false),
    ("method_idx", SqlType::U64, false),
    ("debug_info_off", SqlType::U64, false),
    ("ordinal", SqlType::U64, false),
    ("opcode_off", SqlType::U64, false),
    ("opcode_end_off", SqlType::U64, false),
    ("opcode", SqlType::U64, false),
    ("address", SqlType::U64, false),
    ("line", SqlType::I64, false),
    ("address_diff", SqlType::U64, true),
    ("line_diff", SqlType::I64, true),
    ("register_num", SqlType::U64, true),
    ("name_idx", SqlType::U64, true),
    ("type_idx", SqlType::U64, true),
    ("signature_idx", SqlType::U64, true),
    ("source_file_idx", SqlType::U64, true),
    ("emits_position", SqlType::U64, false),
    ("emits_local", SqlType::U64, false),
];

fn optional(value: Option<u32>) -> SqlValue {
    value.map_or(SqlValue::Null, |value| number(u64::from(value)))
}

fn signed(value: i64) -> SqlValue {
    SqlValue::I64(mdd_query::ir::Signed64(value))
}

/// An encoded integer the fact layer keeps as its canonical decimal text, as the contract's Int64 column.
fn signed_text(value: Option<&str>) -> MddResult<SqlValue> {
    match value {
        None => Ok(SqlValue::Null),
        Some(text) => text.parse::<i64>().map(signed).map_err(|_| {
            MddError::new(
                ErrorCode::InternalFault,
                "sql.hostlab",
                "encoded integer value is not a canonical i64 decimal",
            )
            .detail("value", text.to_owned())
        }),
    }
}

fn float(value: Option<f64>) -> SqlValue {
    value.map_or(SqlValue::Null, |value| {
        SqlValue::F64(DecimalU64(value.to_bits()))
    })
}

impl HostLabSqlProvider {
    /// Fail closed when the layers of a public relation are absent or incomplete.
    pub(super) fn require_public_layer(&self, relation: PublicRelation) -> MddResult<()> {
        // Every refusal names the relation that was asked for, whichever layer stopped it.
        for occurrence in &self.occurrences {
            self.check_public_layer(relation, occurrence)?;
        }
        Ok(())
    }

    /// `require_public_layer` for one occurrence.
    pub(super) fn check_public_layer(
        &self,
        relation: PublicRelation,
        occurrence: &HostLabOccurrence,
    ) -> MddResult<()> {
        let named = |error: MddError| error.detail("relation", relation.name());
        let layers = relation.required_layers();
        {
            if layers.contains(&FactLayer::Metadata)
                && occurrence.facts.metadata.metadata_coverage() != Completeness::Complete
            {
                return Err(incomplete_layer(relation, occurrence, "metadata"));
            }
            if layers.contains(&FactLayer::Structure) {
                let definitions = occurrence.definitions().map_err(named)?;
                if definitions.definition_coverage() != Completeness::Complete {
                    return Err(incomplete_layer(relation, occurrence, "structure"));
                }
            }
            if layers.contains(&FactLayer::CodeLayout) {
                let code = occurrence.code().map_err(named)?;
                if code.code_layout_coverage() != Completeness::Complete {
                    return Err(incomplete_layer(relation, occurrence, "code_layout"));
                }
            }
            if layers.contains(&FactLayer::References) {
                occurrence
                    .references()
                    .and_then(|references| references.require_complete())
                    .map_err(named)?;
            }
            if layers.contains(&FactLayer::Annotations) {
                occurrence.annotations().map_err(named)?;
            }
        }
        Ok(())
    }

    /// Project one occurrence of a public relation.
    pub(super) fn public_occurrence_rows(
        &self,
        relation: PublicRelation,
        occurrence: &HostLabOccurrence,
        control: &SqlControl,
    ) -> MddResult<Vec<SqlRow>> {
        let file_id = occurrence.file_id;
        let metadata = &occurrence.facts.metadata;
        match relation {
            PublicRelation::MapItems => {
                let rows = metadata.map_item_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.ordinal)),
                            number(u64::from(row.type_code)),
                            number(u64::from(row.size)),
                            number(row.offset),
                        ]
                    })
                    .collect())
            }
            PublicRelation::IdItems => {
                let rows = metadata.id_item_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.item_type_code)),
                            number(u64::from(row.idx)),
                            number(row.item_off),
                            number(row.item_end_off),
                            optional(row.data_off),
                        ]
                    })
                    .collect())
            }
            PublicRelation::TypeIds => {
                let rows = metadata.type_id_rows(file_id)?;
                control.work(32u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.type_idx)),
                            number(u64::from(row.descriptor_idx)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::TypeLists => {
                let rows = metadata.type_list_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(row.type_list_off),
                            number(row.type_list_end_off),
                            number(u64::from(row.size)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::TypeListEntries => {
                let rows = metadata.type_list_entry_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(row.type_list_off),
                            number(u64::from(row.ordinal)),
                            number(u64::from(row.type_idx)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::ProtoIds => {
                let rows = metadata.proto_id_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.proto_idx)),
                            number(u64::from(row.shorty_idx)),
                            number(u64::from(row.return_type_idx)),
                            number(u64::from(row.parameters_off)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::Protos => {
                let rows = metadata.proto_rows(file_id)?;
                control.work(128u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.proto_idx)),
                            number(u64::from(row.shorty_idx)),
                            text(&row.shorty),
                            number(u64::from(row.return_type_idx)),
                            text(&row.return_descriptor),
                            number(u64::from(row.parameters_off)),
                            number(u64::from(row.param_count)),
                            text(&row.param_descriptors),
                        ]
                    })
                    .collect())
            }
            PublicRelation::ProtoParams => {
                let rows = metadata.proto_param_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.proto_idx)),
                            number(u64::from(row.ordinal)),
                            number(u64::from(row.type_idx)),
                            text(&row.descriptor),
                        ]
                    })
                    .collect())
            }
            PublicRelation::FieldIds => {
                let rows = occurrence.definitions()?.field_id_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.field_idx)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.type_idx)),
                            number(u64::from(row.name_idx)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::Fields => {
                let rows = occurrence.definitions()?.field_rows(file_id)?;
                control.work(128u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.field_idx)),
                            number(u64::from(row.class_idx)),
                            text(&row.class_descriptor),
                            number(u64::from(row.type_idx)),
                            text(&row.type_descriptor),
                            text(&row.name),
                            text(&row.descriptor),
                        ]
                    })
                    .collect())
            }
            PublicRelation::MethodIds => {
                let rows = occurrence.definitions()?.method_id_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.proto_idx)),
                            number(u64::from(row.name_idx)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::ClassDefs => {
                let rows = occurrence.definitions()?.class_def_rows(file_id)?;
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_def_idx)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.access_flags)),
                            optional(row.superclass_idx),
                            number(u64::from(row.interfaces_off)),
                            optional(row.source_file_idx),
                            number(u64::from(row.annotations_off)),
                            number(u64::from(row.class_data_off)),
                            number(u64::from(row.static_values_off)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::ClassDataItems => {
                let rows = occurrence.definitions()?.class_data_item_rows(file_id)?;
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(row.class_data_off),
                            number(row.class_data_end_off),
                            number(u64::from(row.static_fields_size)),
                            number(u64::from(row.instance_fields_size)),
                            number(u64::from(row.direct_methods_size)),
                            number(u64::from(row.virtual_methods_size)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::MethodOpcodes => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.method_opcode_rows(file_id)?;
                control.work(160u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            optional(row.opcode_count),
                            row.opcode_hex.as_deref().map_or(SqlValue::Null, text),
                        ]
                    })
                    .collect())
            }
            PublicRelation::ClassDataMethods => {
                let rows = occurrence.definitions()?.class_data_method_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.access_flags)),
                            text(row.kind),
                        ]
                    })
                    .collect())
            }
            PublicRelation::TryItems => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.try_item_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.try_idx)),
                            number(u64::from(row.start_addr)),
                            number(u64::from(row.insn_count)),
                            number(u64::from(row.handler_off)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::CatchHandlers => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.catch_handler_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.handler_idx)),
                            number(u64::from(row.handler_off)),
                            number(u64::from(row.ordinal)),
                            optional(row.type_idx),
                            number(u64::from(row.addr)),
                            number(u64::from(row.is_catch_all)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::MethodRefs => {
                let rows = occurrence.references()?.method_ref_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.method_idx)),
                            text(row.index_kind),
                            number(u64::from(row.index)),
                            row.using_type.map_or(SqlValue::Null, text),
                        ]
                    })
                    .collect())
            }
            PublicRelation::MethodNumbers => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.method_number_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.opcode)),
                            text(row.number_type),
                            signed(row.long_value),
                            float(row.double_value),
                        ]
                    })
                    .collect())
            }
            PublicRelation::MethodUsingNumbers => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.method_using_number_rows(file_id)?;
                control.work(160u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            text(&row.method),
                            text(&row.method_class),
                            text(&row.method_name),
                            text(row.number_type),
                            signed(row.long_value),
                            float(row.double_value),
                            number(u64::from(row.opcode)),
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.method_idx)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::AnnotationDirectories => {
                let rows = occurrence.annotations()?.public_directory_rows(file_id)?;
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.annotations_off)),
                            optional(row.class_annotations_off),
                            number(u64::from(row.fields_size)),
                            number(u64::from(row.methods_size)),
                            number(u64::from(row.parameters_size)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::AnnotationSets => {
                let rows = occurrence.annotations()?.public_set_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.annotation_set_off)),
                            number(u64::from(row.size)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::AnnotationSetRefLists => {
                let rows = occurrence.annotations()?.public_ref_list_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.annotation_set_ref_list_off)),
                            number(u64::from(row.size)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::AnnotationSetRefs => {
                let rows = occurrence.annotations()?.public_set_ref_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.annotation_set_ref_list_off)),
                            number(u64::from(row.ordinal)),
                            optional(row.annotation_set_off),
                        ]
                    })
                    .collect())
            }
            PublicRelation::AnnotationValues => {
                let rows = occurrence.annotations()?.annotation_value_rows(file_id)?;
                control.work(192u64.saturating_mul(rows.len() as u64))?;
                rows.into_iter()
                    .map(|row| {
                        Ok(vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            text(row.owner_kind),
                            number(u64::from(row.owner_idx)),
                            text(&row.owner_descriptor),
                            optional(row.parameter_idx),
                            number(u64::from(row.annotation_off)),
                            number(u64::from(row.annotation_type_idx)),
                            text(&row.annotation_descriptor),
                            number(u64::from(row.depth)),
                            number(u64::from(row.ordinal)),
                            optional(row.name_idx),
                            row.name.as_deref().map_or(SqlValue::Null, text),
                            text(row.value_kind),
                            signed_text(row.value_i64.as_deref())?,
                            float(row.value_f64),
                        ])
                    })
                    .collect()
            }
            PublicRelation::AnnotationElementsResolved => {
                let rows = occurrence
                    .annotations()?
                    .annotation_element_resolved_rows(file_id)?;
                control.work(192u64.saturating_mul(rows.len() as u64))?;
                rows.into_iter()
                    .map(|row| {
                        Ok(vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            text(row.owner_kind),
                            number(u64::from(row.owner_idx)),
                            text(&row.owner),
                            optional(row.parameter_idx),
                            text(&row.annotation),
                            number(u64::from(row.visibility)),
                            number(u64::from(row.element_count)),
                            number(u64::from(row.annotation_off)),
                            optional(row.element_ordinal),
                            row.element_name.as_deref().map_or(SqlValue::Null, text),
                            row.value_kind.map_or(SqlValue::Null, text),
                            optional(row.value_index),
                            signed_text(row.value_i64.as_deref())?,
                            float(row.value_f64),
                            row.retention_policy.map_or(SqlValue::Null, text),
                        ])
                    })
                    .collect()
            }
            PublicRelation::MethodHandles => {
                let rows = occurrence.definitions()?.method_handle_rows(file_id)?;
                control.work(48u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_handle_idx)),
                            number(u64::from(row.method_handle_type)),
                            number(u64::from(row.member_idx)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::CallSites => {
                let rows = occurrence.annotations()?.call_site_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.call_site_idx)),
                            number(u64::from(row.call_site_off)),
                            number(u64::from(row.value_count)),
                            optional(row.method_handle_idx),
                            optional(row.method_name_idx),
                            optional(row.proto_idx),
                        ]
                    })
                    .collect())
            }
            PublicRelation::CallSiteArgs => {
                let rows = occurrence.annotations()?.call_site_arg_rows(file_id)?;
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                rows.into_iter()
                    .map(|row| {
                        Ok(vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.call_site_idx)),
                            number(u64::from(row.call_site_off)),
                            number(u64::from(row.ordinal)),
                            text(row.value_kind),
                            optional(row.value_index),
                            signed_text(row.value_i64.as_deref())?,
                            float(row.value_f64),
                        ])
                    })
                    .collect()
            }
            PublicRelation::EncodedArrays => {
                let rows = occurrence.annotations()?.encoded_array_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.encoded_array_idx)),
                            number(u64::from(row.encoded_array_off)),
                            number(row.encoded_array_end_off),
                            number(u64::from(row.value_count)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::EncodedArrayValues => {
                let rows = occurrence
                    .annotations()?
                    .encoded_array_value_rows(file_id)?;
                control.work(128u64.saturating_mul(rows.len() as u64))?;
                rows.into_iter()
                    .map(|row| {
                        Ok(vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.encoded_array_off)),
                            number(u64::from(row.depth)),
                            number(u64::from(row.ordinal)),
                            optional(row.name_idx),
                            number(row.value_off),
                            number(row.value_end_off),
                            text(row.value_kind),
                            optional(row.value_index),
                            signed_text(row.value_i64.as_deref())?,
                            float(row.value_f64),
                        ])
                    })
                    .collect()
            }
            PublicRelation::EncodedArrayOwners => {
                let rows = occurrence
                    .annotations()?
                    .encoded_array_owner_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.encoded_array_off)),
                            text(row.owner_kind),
                            number(u64::from(row.owner_idx)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::ClassStaticValues => {
                let rows = occurrence.annotations()?.class_static_value_rows(file_id)?;
                control.work(112u64.saturating_mul(rows.len() as u64))?;
                rows.into_iter()
                    .map(|row| {
                        Ok(vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.static_values_off)),
                            number(u64::from(row.ordinal)),
                            optional(row.field_idx),
                            text(row.value_kind),
                            optional(row.value_index),
                            signed_text(row.value_i64.as_deref())?,
                            float(row.value_f64),
                        ])
                    })
                    .collect()
            }
            PublicRelation::HiddenapiFlags => {
                let rows = occurrence.definitions()?.hiddenapi_flag_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.class_idx)),
                            number(u64::from(row.ordinal)),
                            text(row.member_kind),
                            number(u64::from(row.member_idx)),
                            number(u64::from(row.flag)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::DebugInfo => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.debug_info_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.debug_info_off)),
                            number(u64::from(row.line_start)),
                            number(u64::from(row.parameters_size)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::DebugParameters => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.debug_parameter_rows(file_id)?;
                control.work(64u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.debug_info_off)),
                            number(u64::from(row.ordinal)),
                            optional(row.name_idx),
                        ]
                    })
                    .collect())
            }
            PublicRelation::DebugPositions => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.debug_position_rows(file_id)?;
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.debug_info_off)),
                            number(u64::from(row.ordinal)),
                            number(u64::from(row.address)),
                            signed(row.line),
                            optional(row.source_file_idx),
                            number(u64::from(row.prologue_end)),
                            number(u64::from(row.epilogue_begin)),
                        ]
                    })
                    .collect())
            }
            PublicRelation::DebugLocals => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.debug_local_rows(file_id)?;
                control.work(96u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.debug_info_off)),
                            number(u64::from(row.ordinal)),
                            number(u64::from(row.address)),
                            text(row.event),
                            number(u64::from(row.register_num)),
                            optional(row.name_idx),
                            optional(row.type_idx),
                            optional(row.signature_idx),
                        ]
                    })
                    .collect())
            }
            PublicRelation::DebugOpcodes => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                let rows = views.debug_opcode_rows(file_id)?;
                control.work(160u64.saturating_mul(rows.len() as u64))?;
                Ok(rows
                    .into_iter()
                    .map(|row| {
                        vec![
                            number(u64::from(row.file_id)),
                            number(u64::from(row.method_idx)),
                            number(u64::from(row.debug_info_off)),
                            number(u64::from(row.ordinal)),
                            number(row.opcode_off),
                            number(row.opcode_end_off),
                            number(u64::from(row.opcode)),
                            number(u64::from(row.address)),
                            signed(row.line),
                            optional(row.address_diff),
                            row.line_diff.map_or(SqlValue::Null, signed),
                            optional(row.register_num),
                            optional(row.name_idx),
                            optional(row.type_idx),
                            optional(row.signature_idx),
                            optional(row.source_file_idx),
                            number(u64::from(row.emits_position)),
                            number(u64::from(row.emits_local)),
                        ]
                    })
                    .collect())
            }
        }
    }
}

fn incomplete_layer(
    relation: PublicRelation,
    occurrence: &HostLabOccurrence,
    layer: &'static str,
) -> MddError {
    MddError::new(
        ErrorCode::IncompleteFacts,
        "sql.hostlab",
        "required fact layer is incomplete",
    )
    .detail("relation", relation.name())
    .detail("required_layer", layer)
    .detail(
        "dex_occurrence_id",
        occurrence.source().dex_occurrence_id.clone(),
    )
}
