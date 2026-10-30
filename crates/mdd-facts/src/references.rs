//! Exact encoded operand sites. Runtime dispatch and definition lookup are separate.
use crate::{
    code::CodeFacts,
    definitions::DefinitionFacts,
    metadata::{EntityKind, EntityRef, MetadataSource, StringFact, StringPoolIdentity, TypeFact},
};
use mdd_dex::{
    DexRange,
    annotations::{
        AnnotationLimits, EncodedArraySection, EncodedKind, MethodHandleSection,
        MethodHandleTarget, read_encoded_array_section, read_method_handle_section,
    },
    definitions::{FieldReference, MethodBody, MethodReference},
    instructions::{InvokeKind, ReferenceKind},
};
use mdd_input::{
    archive::{ArchiveInventory, DexSelection},
    snapshot::Snapshot,
};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError, MddResult};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug)]
pub struct ReferenceLimits {
    pub max_callers: u64,
    pub max_sites: u64,
    pub max_expanded_code_units: u64,
    pub max_fact_bytes: u64,
    pub max_projection_bytes: u64,
    pub max_lookup_candidates: u64,
}
impl Default for ReferenceLimits {
    fn default() -> Self {
        Self {
            max_callers: 4_000_000,
            max_sites: 16_000_000,
            max_expanded_code_units: 256 * 1024 * 1024,
            max_fact_bytes: 512 * 1024 * 1024,
            max_projection_bytes: 512 * 1024 * 1024,
            max_lookup_candidates: 1_000_000,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    String,
    Type,
    Field,
    Method,
    Prototype,
    CallSite,
    MethodHandle,
}
impl TargetKind {
    fn from_operand(value: &ReferenceKind) -> Self {
        match value {
            ReferenceKind::String => Self::String,
            ReferenceKind::Type => Self::Type,
            ReferenceKind::Field => Self::Field,
            ReferenceKind::Method => Self::Method,
            ReferenceKind::Prototype => Self::Prototype,
            ReferenceKind::CallSite => Self::CallSite,
            ReferenceKind::MethodHandle => Self::MethodHandle,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReferenceTargetId {
    pub snapshot_id: String,
    pub dex_occurrence_id: String,
    pub kind: TargetKind,
    pub local_index: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReferenceSiteId {
    pub caller_method_definition: EntityRef,
    pub code_unit_pc: u32,
    pub operand_ordinal: u32,
    pub operand_kind: TargetKind,
}
/// Local coordinates are valid only together with ReferenceFacts.source().
#[derive(Clone, Debug, Serialize)]
pub struct LocalReferenceSite {
    pub site_ordinal: u32,
    pub caller_method_idx: u32,
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub code_item_byte_offset: DecimalU64,
    pub code_unit_pc: u32,
    pub instruction_ordinal: u32,
    pub operand_ordinal: u32,
    pub target_kind: TargetKind,
    pub target_local_index: u32,
    pub opcode: u8,
    pub mnemonic: String,
    pub invoke_kind: Option<InvokeKind>,
    pub instruction_range: DexRange,
    pub operand_range: DexRange,
}
/// One encoded string operand with its exact same-occurrence caller and text fact.
/// UTF-16 units and original MUTF-8 bytes are available from `string.data.text`;
/// the borrowed site retains its caller, PC, operand ordinal and raw ranges.
pub struct StringReferenceSite<'a> {
    pub source: &'a MetadataSource,
    pub string_pool: &'a StringPoolIdentity,
    pub site: &'a LocalReferenceSite,
    pub caller: &'a MethodReference,
    pub string: &'a StringFact,
}

/// Bounds total site visits across both linear scans, not bytes or process RSS.
#[derive(Clone, Copy, Debug)]
pub struct StringReferenceViewLimits {
    pub max_scanned_sites: u64,
    pub max_result_sites: u64,
}
impl Default for StringReferenceViewLimits {
    fn default() -> Self {
        Self {
            max_scanned_sites: 32_000_000,
            max_result_sites: 16_000_000,
        }
    }
}

/// Encoded operand categories whose target facts have same-occurrence identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamedReferenceKind {
    Method,
    Field,
    Type,
}
impl NamedReferenceKind {
    fn target_kind(self) -> TargetKind {
        match self {
            Self::Method => TargetKind::Method,
            Self::Field => TargetKind::Field,
            Self::Type => TargetKind::Type,
        }
    }
}
/// An encoded target only; runtime dispatch, resolution and field access are separate facts.
pub enum NamedReferenceTarget<'a> {
    Method(&'a MethodReference),
    Field(&'a FieldReference),
    Type(&'a TypeFact),
}
pub struct NamedReferenceSite<'a> {
    pub source: &'a MetadataSource,
    pub site: &'a LocalReferenceSite,
    pub caller: &'a MethodReference,
    pub target: NamedReferenceTarget<'a>,
}
/// Bounds total site visits across both linear scans, not bytes or process RSS.
#[derive(Clone, Copy, Debug)]
pub struct NamedReferenceViewLimits {
    pub max_scanned_sites: u64,
    pub max_result_sites: u64,
}
impl Default for NamedReferenceViewLimits {
    fn default() -> Self {
        Self {
            max_scanned_sites: 32_000_000,
            max_result_sites: 16_000_000,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ScopedReferenceSite {
    pub id: ReferenceSiteId,
    pub target: ReferenceTargetId,
    pub location: LocalReferenceSite,
}
#[derive(Clone, Debug, Serialize)]
pub struct DynamicCallSite {
    pub site_ordinal: u32,
    pub call_site_idx: u32,
    pub bootstrap_method_handle_idx: u32,
    pub bootstrap_target_kind: EncodedKind,
    pub bootstrap_target_index: u32,
    pub method_type_idx: u32,
    pub name_string_idx: u32,
    pub runtime_target_status: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct ReferenceCoverage {
    pub required_layer_scope: String,
    pub facts: Completeness,
    pub code_projection_scope: String,
    pub defined_methods: u32,
    pub no_body_methods: u32,
    pub decoded_callers: u32,
    pub missing_method_indices: Vec<u32>,
    pub unowned_physical_code_items: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReferenceMatches {
    pub sites: Vec<ReferenceSiteId>,
    pub coverage: Completeness,
    pub absence_proven_within_encoded_operand_scope: bool,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct ReferenceUsage {
    pub callers: u64,
    pub sites: u64,
    pub expanded_code_units: u64,
    pub fact_bytes: u64,
    pub index_postings: u64,
}
#[derive(Clone, Serialize)]
/// Validated reference facts expose immutable source/coverage and site getters.
/// ```compile_fail
/// fn forge(mut facts: mdd_facts::references::ReferenceFacts) { facts.sites.clear(); }
/// ```
pub struct ReferenceFacts {
    definitions: DefinitionFacts,
    code: CodeFacts,
    sites: Vec<LocalReferenceSite>,
    dynamic_calls: Vec<DynamicCallSite>,
    target_index: BTreeMap<(TargetKind, u32), Vec<u32>>,
    coverage: ReferenceCoverage,
    arrays: Option<EncodedArraySection>,
    handles: Option<MethodHandleSection>,
    limits: ReferenceLimitsView,
    usage: ReferenceUsage,
}
#[derive(Clone, Copy, Serialize)]
struct ReferenceLimitsView {
    max_projection_bytes: u64,
    max_lookup_candidates: u64,
}
struct Budget {
    limits: ReferenceLimits,
    usage: ReferenceUsage,
}
impl Budget {
    fn bytes(&mut self, n: u64) -> MddResult<()> {
        self.usage.fact_bytes = self
            .usage
            .fact_bytes
            .checked_add(n)
            .ok_or_else(|| quota("REFERENCE_BYTE_BUDGET"))?;
        if self.usage.fact_bytes > self.limits.max_fact_bytes {
            return Err(quota("REFERENCE_BYTE_BUDGET"));
        }
        Ok(())
    }
    fn caller(&mut self, units: u64) -> MddResult<()> {
        self.usage.callers += 1;
        if self.usage.callers > self.limits.max_callers {
            return Err(quota("REFERENCE_CALLER_BUDGET"));
        }
        self.usage.expanded_code_units = self
            .usage
            .expanded_code_units
            .checked_add(units)
            .ok_or_else(|| quota("REFERENCE_EXPANSION_BUDGET"))?;
        if self.usage.expanded_code_units > self.limits.max_expanded_code_units {
            return Err(quota("REFERENCE_EXPANSION_BUDGET"));
        }
        self.bytes(16)
    }
    fn site(&mut self, name_bytes: usize) -> MddResult<()> {
        self.usage.sites += 1;
        if self.usage.sites > self.limits.max_sites {
            return Err(quota("REFERENCE_SITE_BUDGET"));
        }
        self.bytes(std::mem::size_of::<LocalReferenceSite>() as u64 + 4 + name_bytes as u64)
    }
}
fn failure(reason: &str) -> MddError {
    MddError::new(ErrorCode::InvalidInput, "facts.references", reason).detail("reason", reason)
}
fn quota(reason: &str) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "facts.references", reason).detail("reason", reason)
}
fn same_source(a: &MetadataSource, b: &MetadataSource) -> bool {
    a.snapshot_id == b.snapshot_id
        && a.dex_occurrence_id == b.dex_occurrence_id
        && a.content_id == b.content_id
        && a.member_id == b.member_id
        && a.source_occurrence_id == b.source_occurrence_id
        && a.physical_dex_id == b.physical_dex_id
}
fn argument_words(definitions: &DefinitionFacts, proto_idx: u32) -> MddResult<u32> {
    let proto = definitions
        .metadata()
        .prototypes()
        .get(proto_idx as usize)
        .ok_or_else(|| failure("REFERENCE_PROTO_INDEX"))?;
    proto
        .data
        .parameter_type_indices
        .iter()
        .try_fold(0u32, |n, index| {
            let ty = definitions
                .metadata()
                .types()
                .get(*index as usize)
                .ok_or_else(|| failure("REFERENCE_TYPE_INDEX"))?;
            n.checked_add(if matches!(ty.data.shape.shorty, 'J' | 'D') {
                2
            } else {
                1
            })
            .ok_or_else(|| failure("REFERENCE_PARAMETER_WORD_OVERFLOW"))
        })
}
fn type_name(descriptor: &str) -> String {
    let dimensions = descriptor.bytes().take_while(|byte| *byte == b'[').count();
    let rest = &descriptor[dimensions..];
    let base = match rest {
        "V" => "void".into(),
        "Z" => "boolean".into(),
        "B" => "byte".into(),
        "S" => "short".into(),
        "C" => "char".into(),
        "I" => "int".into(),
        "J" => "long".into(),
        "F" => "float".into(),
        "D" => "double".into(),
        _ => rest
            .strip_prefix('L')
            .and_then(|value| value.strip_suffix(';'))
            .unwrap_or(rest)
            .replace('/', "."),
    };
    base + &"[]".repeat(dimensions)
}

impl ReferenceFacts {
    pub fn build(
        definitions: DefinitionFacts,
        code: CodeFacts,
        limits: ReferenceLimits,
    ) -> MddResult<Self> {
        if limits.max_sites > u64::from(u32::MAX) || limits.max_callers > u64::from(u32::MAX) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.references",
                "reference IDs exceed supported local index width",
            ));
        }
        let source = definitions.metadata().source();
        let bind = |error: MddError| {
            error
                .detail("snapshot_id", source.snapshot_id.clone())
                .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
                .detail("content_id", source.content_id.clone())
                .detail("member_id", source.member_id.clone())
        };
        if !same_source(source, code.source()) {
            return Err(bind(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.references",
                "definition and code facts do not belong to the same immutable occurrence",
            )));
        }
        if definitions.definition_coverage() != Completeness::Complete
            || code.code_layout_coverage() != Completeness::Complete
        {
            return Err(bind(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.references",
                "validated definition and code scopes are required",
            )));
        }
        let mut budget = Budget {
            limits,
            usage: ReferenceUsage::default(),
        };
        let mut by_code = BTreeMap::new();
        for (index, item) in code.items().iter().enumerate() {
            by_code
                .entry(item.data().raw_range.byte_offset.0)
                .or_insert(index);
        }
        let mut missing = Vec::new();
        let mut callers = Vec::new();
        let mut used_code = BTreeSet::new();
        let mut all_owned_code = BTreeSet::new();
        let mut no_body = 0u32;
        for method in &definitions.definitions().method_definitions {
            let MethodBody::Present {
                code_byte_offset, ..
            } = method.body
            else {
                no_body += 1;
                continue;
            };
            if !code.known_code_item_start(code_byte_offset.0) {
                return Err(bind(
                    failure("METHOD_BODY_NOT_CODE_ITEM_START")
                        .detail("method_idx", u64::from(method.method_idx))
                        .detail("byte_offset", code_byte_offset.0.to_string()),
                ));
            }
            all_owned_code.insert(code_byte_offset.0);
            let Some(index) = by_code.get(&code_byte_offset.0).copied() else {
                budget.bytes(4).map_err(bind)?;
                missing.push(method.method_idx);
                continue;
            };
            let item = code.items()[index].data();
            let reference =
                &definitions.definitions().method_references[method.method_idx as usize];
            let expected = argument_words(&definitions, reference.proto_idx)
                .map_err(bind)?
                .checked_add(u32::from(method.access_flags & 8 == 0))
                .ok_or_else(|| bind(failure("CALLER_PARAMETER_WORD_OVERFLOW")))?;
            if expected != u32::from(item.ins_size) {
                return Err(bind(
                    failure("CALLER_INS_SIZE_MISMATCH")
                        .detail(
                            "byte_offset",
                            (item.raw_range.byte_offset.0 + 2).to_string(),
                        )
                        .detail("byte_length", "2")
                        .detail("method_idx", u64::from(method.method_idx))
                        .detail("expected_words", u64::from(expected))
                        .detail("encoded_words", u64::from(item.ins_size)),
                ));
            }
            budget
                .caller(u64::from(item.insns_size_code_units))
                .map_err(bind)?;
            callers.push((
                method.method_idx,
                method.class_def_idx,
                method.class_idx,
                index,
            ));
            used_code.insert(index);
        }
        let needs_arrays = used_code.iter().any(|index| {
            code.items()[*index]
                .data()
                .instructions
                .iter()
                .any(|instruction| {
                    instruction
                        .references
                        .iter()
                        .any(|reference| reference.kind == ReferenceKind::CallSite)
                })
        });
        let needs_handles = used_code.iter().any(|index| {
            code.items()[*index]
                .data()
                .instructions
                .iter()
                .any(|instruction| {
                    instruction
                        .references
                        .iter()
                        .any(|reference| reference.kind == ReferenceKind::MethodHandle)
                })
        });
        let helper_limits = AnnotationLimits {
            max_decoded_bytes: limits
                .max_fact_bytes
                .saturating_sub(budget.usage.fact_bytes),
            ..AnnotationLimits::default()
        };
        let arrays = if needs_arrays {
            let value = read_encoded_array_section(
                definitions.bytes(),
                definitions.metadata().header(),
                definitions.metadata(),
                definitions.definitions(),
                helper_limits,
            )
            .map_err(bind)?;
            budget.bytes(value.usage.decoded_bytes).map_err(bind)?;
            Some(value)
        } else {
            None
        };
        let handles = if needs_handles && !needs_arrays {
            let value = read_method_handle_section(
                definitions.bytes(),
                definitions.metadata().header(),
                definitions.definitions(),
                helper_limits,
            )
            .map_err(bind)?;
            budget.bytes(value.usage.decoded_bytes).map_err(bind)?;
            Some(value)
        } else {
            None
        };
        let call_sites: BTreeMap<_, _> = arrays
            .as_ref()
            .map(|section| {
                section
                    .call_site_arrays
                    .iter()
                    .map(|item| (item.call_site_idx, item))
                    .collect()
            })
            .unwrap_or_default();
        let mut sites = Vec::new();
        let mut dynamic_calls = Vec::new();
        let mut target_index: BTreeMap<(TargetKind, u32), Vec<u32>> = BTreeMap::new();
        for (method_idx, class_def_idx, class_idx, code_index) in callers.iter().copied() {
            let item = code.items()[code_index].data();
            for instruction in &item.instructions {
                if let Some(invoke) = &instruction.invoke_kind {
                    let target = instruction
                        .references
                        .first()
                        .ok_or_else(|| bind(failure("INVOKE_REFERENCE_MISSING")))?;
                    let expected = match invoke {
                        InvokeKind::Custom | InvokeKind::CustomRange => {
                            let call = call_sites.get(&target.local_index).ok_or_else(|| {
                                bind(MddError::new(
                                    ErrorCode::IncompleteFacts,
                                    "facts.references",
                                    "required call-site metadata is unavailable",
                                ))
                            })?;
                            argument_words(&definitions, call.method_type_idx).map_err(bind)?
                        }
                        InvokeKind::Polymorphic | InvokeKind::PolymorphicRange => {
                            let proto = instruction
                                .references
                                .iter()
                                .find(|value| value.kind == ReferenceKind::Prototype)
                                .ok_or_else(|| bind(failure("POLYMORPHIC_PROTO_MISSING")))?;
                            argument_words(&definitions, proto.local_index)
                                .map_err(bind)?
                                .checked_add(1)
                                .ok_or_else(|| bind(failure("INVOKE_WORD_OVERFLOW")))?
                        }
                        _ => {
                            let method = definitions
                                .definitions()
                                .method_references
                                .get(target.local_index as usize)
                                .ok_or_else(|| bind(failure("INVOKE_METHOD_INDEX")))?;
                            argument_words(&definitions, method.proto_idx)
                                .map_err(bind)?
                                .checked_add(u32::from(
                                    !instruction.mnemonic.starts_with("invoke-static"),
                                ))
                                .ok_or_else(|| bind(failure("INVOKE_WORD_OVERFLOW")))?
                        }
                    };
                    let actual = instruction
                        .register_range
                        .as_ref()
                        .map_or(instruction.registers.len() as u32, |range| {
                            u32::from(range.word_count)
                        });
                    if actual != expected {
                        return Err(bind(
                            failure("INVOKE_ARGUMENT_WORD_MISMATCH")
                                .detail(
                                    "byte_offset",
                                    instruction.raw_range.byte_offset.0.to_string(),
                                )
                                .detail(
                                    "byte_length",
                                    instruction.raw_range.byte_length.0.to_string(),
                                )
                                .detail("method_idx", u64::from(method_idx))
                                .detail("code_unit_pc", u64::from(instruction.code_unit_offset))
                                .detail("expected_words", u64::from(expected))
                                .detail("encoded_words", u64::from(actual)),
                        ));
                    }
                }
                for (ordinal, reference) in instruction.references.iter().enumerate() {
                    budget.site(instruction.mnemonic.len()).map_err(bind)?;
                    let start = reference.raw_range.byte_offset.0;
                    let length = reference.raw_range.byte_length.0;
                    let end = start
                        .checked_add(length)
                        .ok_or_else(|| bind(failure("OPERAND_RANGE_OVERFLOW")))?;
                    if start < instruction.raw_range.byte_offset.0
                        || end
                            > instruction.raw_range.byte_offset.0
                                + instruction.raw_range.byte_length.0
                    {
                        return Err(bind(MddError::new(
                            ErrorCode::InternalFault,
                            "facts.references",
                            "operand range is outside checked instruction",
                        )));
                    }
                    let raw = mdd_dex::checked_reader::CheckedReader::new(definitions.bytes())
                        .range(start, length)
                        .map_err(bind)?;
                    let encoded = match raw.len() {
                        2 => u32::from(u16::from_le_bytes([raw[0], raw[1]])),
                        4 => u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                        _ => {
                            return Err(bind(MddError::new(
                                ErrorCode::InternalFault,
                                "facts.references",
                                "checked operand index width is neither16 nor32",
                            )));
                        }
                    };
                    if encoded != reference.local_index {
                        return Err(bind(
                            MddError::new(
                                ErrorCode::InternalFault,
                                "facts.references",
                                "checked operand index does not match held source range",
                            )
                            .detail("byte_offset", start.to_string()),
                        ));
                    }
                    let site_ordinal = sites.len() as u32;
                    let kind = TargetKind::from_operand(&reference.kind);
                    if !target_index.contains_key(&(kind, reference.local_index)) {
                        budget.bytes(64).map_err(bind)?;
                    }
                    target_index
                        .entry((kind, reference.local_index))
                        .or_default()
                        .push(site_ordinal);
                    budget.usage.index_postings += 1;
                    sites.push(LocalReferenceSite {
                        site_ordinal,
                        caller_method_idx: method_idx,
                        class_def_idx,
                        class_idx,
                        code_item_byte_offset: item.raw_range.byte_offset,
                        code_unit_pc: instruction.code_unit_offset,
                        instruction_ordinal: instruction.instruction_ordinal,
                        operand_ordinal: ordinal as u32,
                        target_kind: kind,
                        target_local_index: reference.local_index,
                        opcode: instruction.opcode,
                        mnemonic: instruction.mnemonic.clone(),
                        invoke_kind: instruction.invoke_kind.clone(),
                        instruction_range: instruction.raw_range.clone(),
                        operand_range: reference.raw_range.clone(),
                    });
                    if kind == TargetKind::CallSite {
                        let call = call_sites[&reference.local_index];
                        let section = arrays.as_ref().ok_or_else(|| {
                            bind(MddError::new(
                                ErrorCode::IncompleteFacts,
                                "facts.references",
                                "call-site arrays not built",
                            ))
                        })?;
                        let handle = section
                            .method_handles
                            .get(call.bootstrap_method_handle_idx as usize)
                            .ok_or_else(|| bind(failure("BOOTSTRAP_HANDLE_INDEX")))?;
                        budget
                            .bytes(std::mem::size_of::<DynamicCallSite>() as u64 + 32)
                            .map_err(bind)?;
                        dynamic_calls.push(DynamicCallSite{site_ordinal,call_site_idx:call.call_site_idx,bootstrap_method_handle_idx:call.bootstrap_method_handle_idx,bootstrap_target_kind:handle.target_kind,bootstrap_target_index:handle.target_index,method_type_idx:call.method_type_idx,name_string_idx:call.name_string_idx,runtime_target_status:"unknown_dynamic_target; bootstrap reference is not the runtime callee"});
                    }
                }
            }
        }
        let coverage = ReferenceCoverage {
            required_layer_scope:
                "encoded operands in all declared method definitions of this bound DEX occurrence; not runtime dispatch".into(),
            facts: if missing.is_empty() {
                Completeness::Complete
            } else {
                Completeness::Partial
            },
            code_projection_scope: code.scope().to_owned(),
            defined_methods: definitions.definitions().method_definitions.len() as u32,
            no_body_methods: no_body,
            decoded_callers: callers.len() as u32,
            missing_method_indices: missing,
            unowned_physical_code_items: code
                .declared_code_item_byte_offsets()
                .iter()
                .filter(|offset| !all_owned_code.contains(&offset.0))
                .count() as u32,
        };
        Ok(Self {
            definitions,
            code,
            sites,
            dynamic_calls,
            target_index,
            coverage,
            arrays,
            handles,
            limits: ReferenceLimitsView {
                max_projection_bytes: limits.max_projection_bytes,
                max_lookup_candidates: limits.max_lookup_candidates,
            },
            usage: budget.usage,
        })
    }
    pub fn source(&self) -> &MetadataSource {
        self.definitions.metadata().source()
    }
    pub fn definitions(&self) -> &DefinitionFacts {
        &self.definitions
    }
    pub fn code(&self) -> &CodeFacts {
        &self.code
    }
    pub fn sites(&self) -> &[LocalReferenceSite] {
        &self.sites
    }
    /// Borrow all encoded string sites without converting their text to UTF-8.
    /// Complete reference coverage is required before an empty result can be
    /// interpreted as absence; each physical operand occurrence is retained.
    pub fn string_reference_sites(
        &self,
        limits: StringReferenceViewLimits,
    ) -> MddResult<impl Iterator<Item = MddResult<StringReferenceSite<'_>>> + '_> {
        self.require_complete()?;
        let visits = u64::try_from(self.sites.len())
            .ok()
            .and_then(|count| count.checked_mul(2))
            .ok_or_else(|| quota("STRING_REFERENCE_SCAN_BUDGET"))?;
        if visits > limits.max_scanned_sites {
            return Err(quota("STRING_REFERENCE_SCAN_BUDGET"));
        }
        let matches = u64::try_from(
            self.sites
                .iter()
                .filter(|site| site.target_kind == TargetKind::String)
                .count(),
        )
        .map_err(|_| quota("STRING_REFERENCE_RESULT_BUDGET"))?;
        if matches > limits.max_result_sites {
            return Err(quota("STRING_REFERENCE_RESULT_BUDGET"));
        }
        Ok(self
            .sites
            .iter()
            .filter(|site| site.target_kind == TargetKind::String)
            .map(move |site| {
                let inconsistent = || {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.references.string_view",
                        "validated string reference identity is inconsistent",
                    )
                };
                let metadata = self.definitions.metadata();
                let caller = self
                    .definitions
                    .definitions()
                    .method_references
                    .get(site.caller_method_idx as usize)
                    .filter(|caller| caller.method_idx == site.caller_method_idx)
                    .ok_or_else(inconsistent)?;
                let string = metadata
                    .strings()
                    .get(site.target_local_index as usize)
                    .filter(|string| {
                        string.data.string_idx == site.target_local_index
                            && string.entity.kind == EntityKind::String
                            && string.entity.local_index == site.target_local_index
                            && string.entity.snapshot_id == self.source().snapshot_id
                            && string.entity.dex_occurrence_id == self.source().dex_occurrence_id
                            && string.string_pool_id == metadata.string_pool().string_pool_id
                    })
                    .ok_or_else(inconsistent)?;
                Ok(StringReferenceSite {
                    source: self.source(),
                    string_pool: metadata.string_pool(),
                    site,
                    caller,
                    string,
                })
            }))
    }
    /// Borrow every selected encoded operand without deduplicating occurrences.
    /// Incomplete reference coverage is an error even when no sites are observed.
    pub fn named_reference_sites(
        &self,
        kind: NamedReferenceKind,
        limits: NamedReferenceViewLimits,
    ) -> MddResult<impl Iterator<Item = MddResult<NamedReferenceSite<'_>>> + '_> {
        self.require_complete()?;
        let visits = u64::try_from(self.sites.len())
            .ok()
            .and_then(|count| count.checked_mul(2))
            .ok_or_else(|| quota("NAMED_REFERENCE_SCAN_BUDGET"))?;
        if visits > limits.max_scanned_sites {
            return Err(quota("NAMED_REFERENCE_SCAN_BUDGET"));
        }
        let target_kind = kind.target_kind();
        let matches = u64::try_from(
            self.sites
                .iter()
                .filter(|site| site.target_kind == target_kind)
                .count(),
        )
        .map_err(|_| quota("NAMED_REFERENCE_RESULT_BUDGET"))?;
        if matches > limits.max_result_sites {
            return Err(quota("NAMED_REFERENCE_RESULT_BUDGET"));
        }
        Ok(self
            .sites
            .iter()
            .filter(move |site| site.target_kind == target_kind)
            .map(move |site| {
                let inconsistent = || {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.references.named_view",
                        "validated reference identity is inconsistent",
                    )
                };
                let definitions = self.definitions.definitions();
                let metadata = self.definitions.metadata();
                let caller = definitions
                    .method_references
                    .get(site.caller_method_idx as usize)
                    .filter(|caller| caller.method_idx == site.caller_method_idx)
                    .ok_or_else(inconsistent)?;
                let target = match kind {
                    NamedReferenceKind::Method => NamedReferenceTarget::Method(
                        definitions
                            .method_references
                            .get(site.target_local_index as usize)
                            .filter(|target| target.method_idx == site.target_local_index)
                            .ok_or_else(inconsistent)?,
                    ),
                    NamedReferenceKind::Field => NamedReferenceTarget::Field(
                        definitions
                            .field_references
                            .get(site.target_local_index as usize)
                            .filter(|target| target.field_idx == site.target_local_index)
                            .ok_or_else(inconsistent)?,
                    ),
                    NamedReferenceKind::Type => NamedReferenceTarget::Type(
                        metadata
                            .types()
                            .get(site.target_local_index as usize)
                            .filter(|target| {
                                target.data.type_idx == site.target_local_index
                                    && target.entity.kind == EntityKind::Type
                                    && target.entity.local_index == site.target_local_index
                                    && target.entity.snapshot_id == self.source().snapshot_id
                                    && target.entity.dex_occurrence_id
                                        == self.source().dex_occurrence_id
                            })
                            .ok_or_else(inconsistent)?,
                    ),
                };
                Ok(NamedReferenceSite {
                    source: self.source(),
                    site,
                    caller,
                    target,
                })
            }))
    }
    pub fn dynamic_calls(&self) -> &[DynamicCallSite] {
        &self.dynamic_calls
    }
    pub fn coverage(&self) -> &ReferenceCoverage {
        &self.coverage
    }
    pub fn usage(&self) -> &ReferenceUsage {
        &self.usage
    }
    pub fn call_site_metadata(&self) -> Option<&EncodedArraySection> {
        self.arrays.as_ref()
    }
    pub fn method_handle_metadata(&self) -> Option<&[MethodHandleTarget]> {
        self.arrays
            .as_ref()
            .map(|section| section.method_handles.as_slice())
            .or_else(|| {
                self.handles
                    .as_ref()
                    .map(|section| section.targets.as_slice())
            })
    }
    pub fn require_complete(&self) -> MddResult<()> {
        if self.coverage.facts != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.references",
                "some genuine method bodies are outside the provided code projection",
            )
            .detail(
                "missing_method_count",
                self.coverage.missing_method_indices.len().to_string(),
            )
            .detail("required_layer", "references"));
        }
        Ok(())
    }
    pub fn target_id(&self, kind: TargetKind, index: u32) -> MddResult<ReferenceTargetId> {
        let valid = match kind {
            TargetKind::String => self
                .definitions
                .metadata()
                .strings()
                .get(index as usize)
                .is_some(),
            TargetKind::Type => self
                .definitions
                .metadata()
                .types()
                .get(index as usize)
                .is_some(),
            TargetKind::Field => self
                .definitions
                .definitions()
                .field_references
                .get(index as usize)
                .is_some(),
            TargetKind::Method => self
                .definitions
                .definitions()
                .method_references
                .get(index as usize)
                .is_some(),
            TargetKind::Prototype => self
                .definitions
                .metadata()
                .prototypes()
                .get(index as usize)
                .is_some(),
            TargetKind::CallSite | TargetKind::MethodHandle => self
                .definitions
                .metadata()
                .header()
                .map
                .iter()
                .find(|item| item.type_code == if kind == TargetKind::CallSite { 7 } else { 8 })
                .is_some_and(|item| index < item.count),
        };
        if !valid {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.references",
                "target index outside bound occurrence",
            ));
        }
        Ok(ReferenceTargetId {
            snapshot_id: self.source().snapshot_id.clone(),
            dex_occurrence_id: self.source().dex_occurrence_id.clone(),
            kind,
            local_index: index,
        })
    }
    pub fn site_id(&self, ordinal: u32) -> MddResult<ReferenceSiteId> {
        let site = self.sites.get(ordinal as usize).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.references",
                "site ordinal outside facts",
            )
        })?;
        Ok(ReferenceSiteId {
            caller_method_definition: self
                .definitions
                .entity(EntityKind::MethodDefinition, site.caller_method_idx)?,
            code_unit_pc: site.code_unit_pc,
            operand_ordinal: site.operand_ordinal,
            operand_kind: site.target_kind,
        })
    }
    pub fn scoped_site(&self, ordinal: u32) -> MddResult<ScopedReferenceSite> {
        let site = self.sites.get(ordinal as usize).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.references",
                "site ordinal outside facts",
            )
        })?;
        Ok(ScopedReferenceSite {
            id: self.site_id(ordinal)?,
            target: self.target_id(site.target_kind, site.target_local_index)?,
            location: site.clone(),
        })
    }
    pub fn raw_operand(&self, ordinal: u32) -> MddResult<&[u8]> {
        let site = self.sites.get(ordinal as usize).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.references",
                "site ordinal outside facts",
            )
        })?;
        mdd_dex::checked_reader::CheckedReader::new(self.definitions.bytes()).range(
            site.operand_range.byte_offset.0,
            site.operand_range.byte_length.0,
        )
    }
    fn matches(&self, target: &ReferenceTargetId, indexed: bool) -> MddResult<ReferenceMatches> {
        if target.snapshot_id != self.source().snapshot_id
            || target.dex_occurrence_id != self.source().dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.references",
                "target identity belongs to another source occurrence",
            ));
        }
        self.target_id(target.kind, target.local_index)?;
        let ordinals = if indexed {
            let matches = self
                .target_index
                .get(&(target.kind, target.local_index))
                .map_or(&[][..], Vec::as_slice);
            if matches.len() as u64 > self.limits.max_lookup_candidates {
                return Err(quota("REFERENCE_MATCH_BUDGET"));
            }
            matches.to_vec()
        } else {
            let mut matches = Vec::new();
            for site in &self.sites {
                if site.target_kind == target.kind && site.target_local_index == target.local_index
                {
                    if matches.len() as u64 >= self.limits.max_lookup_candidates {
                        return Err(quota("REFERENCE_MATCH_BUDGET"));
                    }
                    matches.push(site.site_ordinal);
                }
            }
            matches
        };
        if ordinals.len() as u64 > self.limits.max_lookup_candidates {
            return Err(quota("REFERENCE_MATCH_BUDGET"));
        }
        let estimated = ordinals.len() as u64
            * (self.source().snapshot_id.len()
                + self.source().dex_occurrence_id.len()
                + std::mem::size_of::<ReferenceSiteId>()) as u64;
        if estimated > self.limits.max_projection_bytes {
            return Err(quota("REFERENCE_MATCH_BYTE_BUDGET"));
        }
        let sites = ordinals
            .iter()
            .map(|ordinal| self.site_id(*ordinal))
            .collect::<MddResult<Vec<_>>>()?;
        Ok(ReferenceMatches {
            absence_proven_within_encoded_operand_scope: sites.is_empty()
                && self.coverage.facts == Completeness::Complete,
            sites,
            coverage: self.coverage.facts,
        })
    }
    pub fn find_target_indexed(&self, target: &ReferenceTargetId) -> MddResult<ReferenceMatches> {
        self.matches(target, true)
    }
    pub fn find_target_scalar(&self, target: &ReferenceTargetId) -> MddResult<ReferenceMatches> {
        self.matches(target, false)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct MethodSymbol {
    pub owner: String,
    pub name: String,
    pub prototype: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct FieldSymbol {
    pub owner: String,
    pub name: String,
    pub field_type: String,
}
#[derive(Clone, Copy, Debug)]
pub struct DefinitionSearchLimits {
    pub max_definitions: u64,
    pub max_bytes: u64,
    pub max_candidates: u64,
}
impl Default for DefinitionSearchLimits {
    fn default() -> Self {
        Self {
            max_definitions: 4_000_000,
            max_bytes: 512 * 1024 * 1024,
            max_candidates: 1_000_000,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DefinitionSearchScope {
    Unbuilt,
    WithinProvidedFacts {
        dex_occurrences: Vec<String>,
    },
    CompleteSelectedInputs {
        snapshot_content_key: String,
        dex_occurrences: Vec<String>,
        source_selection_policies: Vec<String>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DefinitionCandidate {
    pub definition: EntityRef,
    pub class_definition: EntityRef,
    pub body_state: Option<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionResolutionState {
    NotBuilt,
    NoDefinitionInProvidedFacts,
    NoDefinitionInSelectedInputs,
    OneDefinitionInScope,
    AmbiguousDefinitionsInScope,
}
#[derive(Clone, Debug, Serialize)]
pub struct DefinitionResolution {
    pub state: DefinitionResolutionState,
    pub candidates: Vec<DefinitionCandidate>,
    pub scope: DefinitionSearchScope,
    pub search_scope_covers_selected_inputs: bool,
    pub absence_proven_in_selected_inputs: bool,
    pub runtime_resolution: String,
}
pub struct DefinitionWorld<'a> {
    facts: Vec<&'a DefinitionFacts>,
    snapshot_id: String,
    scope: DefinitionSearchScope,
    methods: BTreeMap<MethodSymbol, Vec<DefinitionCandidate>>,
    fields: BTreeMap<FieldSymbol, Vec<DefinitionCandidate>>,
    limits: DefinitionSearchLimits,
}
fn method_symbol(facts: &DefinitionFacts, index: u32) -> MddResult<MethodSymbol> {
    let method = facts
        .definitions()
        .method_references
        .get(index as usize)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.definition_search",
                "method reference index outside occurrence",
            )
        })?;
    Ok(MethodSymbol {
        owner: method.class_descriptor.clone(),
        name: method.method_name.clone(),
        prototype: facts.metadata().prototypes()[method.proto_idx as usize]
            .data
            .descriptor
            .clone(),
    })
}
fn field_symbol(facts: &DefinitionFacts, index: u32) -> MddResult<FieldSymbol> {
    let field = facts
        .definitions()
        .field_references
        .get(index as usize)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.definition_search",
                "field reference index outside occurrence",
            )
        })?;
    Ok(FieldSymbol {
        owner: field.class_descriptor.clone(),
        name: field.field_name.clone(),
        field_type: field.type_descriptor.clone(),
    })
}
impl<'a> DefinitionWorld<'a> {
    pub fn unbuilt(snapshot: &Snapshot) -> Self {
        Self {
            facts: Vec::new(),
            snapshot_id: snapshot.manifest().snapshot_id.clone(),
            scope: DefinitionSearchScope::Unbuilt,
            methods: BTreeMap::new(),
            fields: BTreeMap::new(),
            limits: DefinitionSearchLimits::default(),
        }
    }
    pub fn from_provided(
        facts: &[&'a DefinitionFacts],
        limits: DefinitionSearchLimits,
    ) -> MddResult<Self> {
        let first = facts.first().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.definition_search",
                "provided-facts scope requires a bound occurrence; use unbuilt for missing facts",
            )
        })?;
        let occurrences = facts
            .iter()
            .map(|fact| fact.metadata().source().dex_occurrence_id.clone())
            .collect();
        Self::build(
            facts,
            first.metadata().source().snapshot_id.clone(),
            DefinitionSearchScope::WithinProvidedFacts {
                dex_occurrences: occurrences,
            },
            limits,
        )
    }
    pub fn from_complete_selected_inputs(
        snapshot: &Snapshot,
        inventories: &[&ArchiveInventory],
        facts: &[&'a DefinitionFacts],
        limits: DefinitionSearchLimits,
    ) -> MddResult<Self> {
        if inventories.len() != snapshot.manifest().sources.len() {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.definition_search",
                "one complete inventory is required for every captured source",
            )
            .detail("required_layer", "input_inventory"));
        }
        let captured: BTreeMap<_, _> = snapshot
            .manifest()
            .sources
            .iter()
            .map(|source| (source.occurrence_id.as_str(), source.content_id.as_str()))
            .collect();
        let mut seen = BTreeSet::new();
        let mut expected = BTreeMap::new();
        let mut policies = Vec::new();
        for inventory in inventories {
            let manifest = inventory.manifest();
            if captured
                .get(manifest.source_occurrence_id.as_str())
                .copied()
                != Some(manifest.source_content_id.as_str())
                || !seen.insert(manifest.source_occurrence_id.as_str())
            {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.definition_search",
                    "inventory does not belong to this snapshot or is repeated",
                ));
            }
            if !manifest.directory_complete || !manifest.selected_dex_bytes_complete {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.definition_search",
                    "input inventory or requested DEX bytes incomplete",
                ));
            }
            let policy = match manifest.selection {
                DexSelection::TopLevelClasses => "top-level-classes-v1",
                DexSelection::AllDexMembers => "all-dex-members-v1",
                DexSelection::ResourcesOnly => {
                    return Err(MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.definition_search",
                        "resource-only inventory cannot prove a DEX definition world",
                    ));
                }
            };
            policies.push(format!("{}:{policy}", manifest.source_occurrence_id));
            for dex in inventory.selected_dexes() {
                if expected
                    .insert(dex.dex_occurrence_id.as_str(), dex.blob.content_id.as_str())
                    .is_some()
                {
                    return Err(MddError::new(
                        ErrorCode::InvalidArgument,
                        "facts.definition_search",
                        "duplicate DEX occurrence in complete inventory",
                    ));
                }
            }
        }
        let mut provided = BTreeSet::new();
        for fact in facts {
            let source = fact.metadata().source();
            if source.snapshot_id != snapshot.manifest().snapshot_id
                || expected.get(source.dex_occurrence_id.as_str()).copied()
                    != Some(source.content_id.as_str())
                || !provided.insert(source.dex_occurrence_id.as_str())
            {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.definition_search",
                    "definition facts do not exactly belong to selected snapshot occurrences",
                ));
            }
        }
        if provided.len() != expected.len() {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.definition_search",
                "selected DEX occurrences still lack complete definition facts",
            )
            .detail("expected_dex_occurrences", expected.len().to_string())
            .detail("provided_dex_occurrences", provided.len().to_string()));
        }
        let scope = DefinitionSearchScope::CompleteSelectedInputs {
            snapshot_content_key: snapshot.manifest().snapshot_content_key.clone(),
            dex_occurrences: expected.keys().map(|value| (*value).to_owned()).collect(),
            source_selection_policies: policies,
        };
        Self::build(
            facts,
            snapshot.manifest().snapshot_id.clone(),
            scope,
            limits,
        )
    }
    fn build(
        facts: &[&'a DefinitionFacts],
        snapshot_id: String,
        scope: DefinitionSearchScope,
        limits: DefinitionSearchLimits,
    ) -> MddResult<Self> {
        let mut methods: BTreeMap<MethodSymbol, Vec<DefinitionCandidate>> = BTreeMap::new();
        let mut fields: BTreeMap<FieldSymbol, Vec<DefinitionCandidate>> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut rows = 0u64;
        let mut bytes = 0u64;
        for fact in facts {
            let source = fact.metadata().source();
            if source.snapshot_id != snapshot_id || !seen.insert(source.dex_occurrence_id.as_str())
            {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.definition_search",
                    "definition world cannot mix snapshots or repeat the same occurrence",
                ));
            }
            if fact.definition_coverage() != Completeness::Complete {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.definition_search",
                    "definition scope is incomplete",
                ));
            }
            let identity = (source.snapshot_id.len() + source.dex_occurrence_id.len()) as u64;
            for definition in &fact.definitions().method_definitions {
                let key = method_symbol(fact, definition.method_idx)?;
                rows += 1;
                bytes = bytes
                    .checked_add(
                        2 * identity
                            + 128
                            + (key.owner.len() + key.name.len() + key.prototype.len()) as u64,
                    )
                    .ok_or_else(|| quota("DEFINITION_SEARCH_BYTE_BUDGET"))?;
                if rows > limits.max_definitions || bytes > limits.max_bytes {
                    return Err(quota("DEFINITION_SEARCH_BUILD_BUDGET"));
                }
                methods.entry(key).or_default().push(DefinitionCandidate {
                    definition: fact.entity(EntityKind::MethodDefinition, definition.method_idx)?,
                    class_definition: fact
                        .entity(EntityKind::ClassDefinition, definition.class_def_idx)?,
                    body_state: Some(definition.body.state().into()),
                });
            }
            for definition in &fact.definitions().field_definitions {
                let key = field_symbol(fact, definition.field_idx)?;
                rows += 1;
                bytes = bytes
                    .checked_add(
                        2 * identity
                            + 128
                            + (key.owner.len() + key.name.len() + key.field_type.len()) as u64,
                    )
                    .ok_or_else(|| quota("DEFINITION_SEARCH_BYTE_BUDGET"))?;
                if rows > limits.max_definitions || bytes > limits.max_bytes {
                    return Err(quota("DEFINITION_SEARCH_BUILD_BUDGET"));
                }
                fields.entry(key).or_default().push(DefinitionCandidate {
                    definition: fact.entity(EntityKind::FieldDefinition, definition.field_idx)?,
                    class_definition: fact
                        .entity(EntityKind::ClassDefinition, definition.class_def_idx)?,
                    body_state: None,
                });
            }
        }
        Ok(Self {
            facts: facts.to_vec(),
            snapshot_id,
            scope,
            methods,
            fields,
            limits,
        })
    }
    pub fn scope(&self) -> &DefinitionSearchScope {
        &self.scope
    }
    fn resolution(
        &self,
        mut candidates: Vec<DefinitionCandidate>,
    ) -> MddResult<DefinitionResolution> {
        if candidates.len() as u64 > self.limits.max_candidates {
            return Err(quota("DEFINITION_SEARCH_CANDIDATE_BUDGET"));
        }
        candidates.sort_by(|left, right| {
            (
                &left.definition.dex_occurrence_id,
                left.definition.local_index,
            )
                .cmp(&(
                    &right.definition.dex_occurrence_id,
                    right.definition.local_index,
                ))
        });
        let complete = matches!(
            self.scope,
            DefinitionSearchScope::CompleteSelectedInputs { .. }
        );
        let state = if matches!(self.scope, DefinitionSearchScope::Unbuilt) {
            DefinitionResolutionState::NotBuilt
        } else {
            match candidates.len() {
                0 => {
                    if complete {
                        DefinitionResolutionState::NoDefinitionInSelectedInputs
                    } else {
                        DefinitionResolutionState::NoDefinitionInProvidedFacts
                    }
                }
                1 => DefinitionResolutionState::OneDefinitionInScope,
                _ => DefinitionResolutionState::AmbiguousDefinitionsInScope,
            }
        };
        Ok(DefinitionResolution{absence_proven_in_selected_inputs:candidates.is_empty()&&complete,candidates,state,scope:self.scope.clone(),search_scope_covers_selected_inputs:complete,runtime_resolution:"not_inferred; exact encoded owner/name/type/prototype declaration lookup only; inheritance, member linkage, dispatch and runtime classpath are not resolved".into()})
    }
    fn check_source(&self, facts: &DefinitionFacts) -> MddResult<()> {
        if facts.metadata().source().snapshot_id != self.snapshot_id {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.definition_search",
                "reference belongs to a different snapshot",
            ));
        }
        Ok(())
    }
    pub fn resolve_method_reference(
        &self,
        facts: &DefinitionFacts,
        method_idx: u32,
    ) -> MddResult<DefinitionResolution> {
        self.check_source(facts)?;
        let key = method_symbol(facts, method_idx)?;
        let matches = self.methods.get(&key).map_or(&[][..], Vec::as_slice);
        if matches.len() as u64 > self.limits.max_candidates {
            return Err(quota("DEFINITION_SEARCH_CANDIDATE_BUDGET"));
        }
        self.resolution(matches.to_vec())
    }
    pub fn resolve_field_reference(
        &self,
        facts: &DefinitionFacts,
        field_idx: u32,
    ) -> MddResult<DefinitionResolution> {
        self.check_source(facts)?;
        let key = field_symbol(facts, field_idx)?;
        let matches = self.fields.get(&key).map_or(&[][..], Vec::as_slice);
        if matches.len() as u64 > self.limits.max_candidates {
            return Err(quota("DEFINITION_SEARCH_CANDIDATE_BUDGET"));
        }
        self.resolution(matches.to_vec())
    }
    pub fn resolve_method_scalar(
        &self,
        facts: &DefinitionFacts,
        method_idx: u32,
    ) -> MddResult<DefinitionResolution> {
        self.check_source(facts)?;
        let expected = facts
            .definitions()
            .method_references
            .get(method_idx as usize)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.definition_search",
                    "method index out of range",
                )
            })?;
        let proto = &facts.metadata().prototypes()[expected.proto_idx as usize]
            .data
            .descriptor;
        let mut candidates = Vec::new();
        for fact in &self.facts {
            for definition in &fact.definitions().method_definitions {
                let method = &fact.definitions().method_references[definition.method_idx as usize];
                if method.class_descriptor == expected.class_descriptor
                    && method.method_name == expected.method_name
                    && fact.metadata().prototypes()[method.proto_idx as usize]
                        .data
                        .descriptor
                        == *proto
                {
                    candidates.push(DefinitionCandidate {
                        definition: fact
                            .entity(EntityKind::MethodDefinition, definition.method_idx)?,
                        class_definition: fact
                            .entity(EntityKind::ClassDefinition, definition.class_def_idx)?,
                        body_state: Some(definition.body.state().into()),
                    });
                    if candidates.len() as u64 > self.limits.max_candidates {
                        return Err(quota("DEFINITION_SEARCH_CANDIDATE_BUDGET"));
                    }
                }
            }
        }
        self.resolution(candidates)
    }
    pub fn resolve_field_scalar(
        &self,
        facts: &DefinitionFacts,
        field_idx: u32,
    ) -> MddResult<DefinitionResolution> {
        self.check_source(facts)?;
        let expected = facts
            .definitions()
            .field_references
            .get(field_idx as usize)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.definition_search",
                    "field index out of range",
                )
            })?;
        let mut candidates = Vec::new();
        for fact in &self.facts {
            for definition in &fact.definitions().field_definitions {
                let field = &fact.definitions().field_references[definition.field_idx as usize];
                if field.class_descriptor == expected.class_descriptor
                    && field.field_name == expected.field_name
                    && field.type_descriptor == expected.type_descriptor
                {
                    candidates.push(DefinitionCandidate {
                        definition: fact
                            .entity(EntityKind::FieldDefinition, definition.field_idx)?,
                        class_definition: fact
                            .entity(EntityKind::ClassDefinition, definition.class_def_idx)?,
                        body_state: None,
                    });
                    if candidates.len() as u64 > self.limits.max_candidates {
                        return Err(quota("DEFINITION_SEARCH_CANDIDATE_BUDGET"));
                    }
                }
            }
        }
        self.resolution(candidates)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MethodStringRow {
    pub method: String,
    pub method_class: String,
    pub method_name: String,
    pub value: String,
    pub file_id: u32,
    pub class_idx: u32,
    pub method_idx: u32,
    pub string_idx: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct MethodCallRow {
    pub method: String,
    pub method_class: String,
    pub method_name: String,
    pub callee: String,
    pub callee_class: String,
    pub callee_name: String,
    pub file_id: u32,
    pub class_idx: u32,
    pub method_idx: u32,
    pub callee_method_idx: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct MethodFieldRow {
    pub method: String,
    pub method_class: String,
    pub method_name: String,
    pub field: String,
    pub field_class: String,
    pub field_name: String,
    pub field_type: String,
    pub using_type: Option<String>,
    pub file_id: u32,
    pub class_idx: u32,
    pub method_idx: u32,
    pub field_idx: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct MethodTypeRow {
    pub method: String,
    pub method_class: String,
    pub method_name: String,
    pub type_descriptor: String,
    pub type_name: String,
    pub file_id: u32,
    pub class_idx: u32,
    pub method_idx: u32,
    pub type_idx: u32,
}
#[derive(Clone, Copy, Debug)]
pub enum ReferenceRelation {
    MethodStrings,
    MethodCalls,
    MethodFieldAccesses,
    MethodUsedTypes,
}
struct ProjectionBudget {
    remaining: u64,
}
impl ProjectionBudget {
    fn row<T>(&mut self) -> MddResult<()> {
        self.remaining = self
            .remaining
            .checked_sub(std::mem::size_of::<T>() as u64)
            .ok_or_else(|| quota("REFERENCE_PROJECTION_BYTE_BUDGET"))?;
        Ok(())
    }
    fn text(&mut self, values: &[&str]) -> MddResult<()> {
        let bytes = values
            .iter()
            .try_fold(0u64, |sum, value| sum.checked_add(value.len() as u64))
            .ok_or_else(|| quota("REFERENCE_PROJECTION_BYTE_BUDGET"))?;
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| quota("REFERENCE_PROJECTION_BYTE_BUDGET"))?;
        Ok(())
    }
}
impl ReferenceFacts {
    pub fn require_relation_columns(
        &self,
        relation: ReferenceRelation,
        columns: &[&str],
    ) -> MddResult<()> {
        self.require_complete()?;
        let allowed: &[&str] = match relation {
            ReferenceRelation::MethodStrings => &[
                "method",
                "method_class",
                "method_name",
                "value",
                "file_id",
                "class_idx",
                "method_idx",
                "string_idx",
            ],
            ReferenceRelation::MethodCalls => &[
                "method",
                "method_class",
                "method_name",
                "callee",
                "callee_class",
                "callee_name",
                "file_id",
                "class_idx",
                "method_idx",
                "callee_method_idx",
            ],
            ReferenceRelation::MethodFieldAccesses => &[
                "method",
                "method_class",
                "method_name",
                "field",
                "field_class",
                "field_name",
                "field_type",
                "using_type",
                "file_id",
                "class_idx",
                "method_idx",
                "field_idx",
            ],
            ReferenceRelation::MethodUsedTypes => &[
                "method",
                "method_class",
                "method_name",
                "type_descriptor",
                "type_name",
                "file_id",
                "class_idx",
                "method_idx",
                "type_idx",
            ],
        };
        for column in columns {
            if *column != "*" && !allowed.contains(column) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.references.projection",
                    "unknown reference relation column",
                )
                .detail("column", (*column).to_owned()));
            }
        }
        Ok(())
    }
    pub fn method_string_rows(&self, file_id: u32) -> MddResult<Vec<MethodStringRow>> {
        self.require_complete()?;
        let mut budget = ProjectionBudget {
            remaining: self.limits.max_projection_bytes,
        };
        let mut rows = Vec::new();
        let mut texts: BTreeMap<u32, String> = BTreeMap::new();
        for site in self
            .sites
            .iter()
            .filter(|site| site.target_kind == TargetKind::String)
        {
            let caller =
                &self.definitions.definitions().method_references[site.caller_method_idx as usize];
            if let std::collections::btree_map::Entry::Vacant(entry) =
                texts.entry(site.target_local_index)
            {
                let item =
                    &self.definitions.metadata().strings()[site.target_local_index as usize].data;
                let text=item.text.strict_utf8().map_err(|_|MddError::new(ErrorCode::UnsupportedQuery,"facts.references.projection","plain UTF8 relation cannot losslessly represent a legal non-scalar DEX string").detail("reason","NON_SCALAR_TEXT_PROJECTION").detail("string_idx",u64::from(site.target_local_index)).detail("snapshot_id",self.source().snapshot_id.clone()).detail("dex_occurrence_id",self.source().dex_occurrence_id.clone()).detail("string_pool_id",self.definitions.metadata().string_pool().string_pool_id.clone()).detail("byte_offset",item.text.raw_range.byte_offset.0.to_string()))?;
                budget.text(&[&text])?;
                entry.insert(text);
            }
            let text = &texts[&site.target_local_index];
            budget.text(&[
                &caller.descriptor,
                &caller.class_descriptor,
                &caller.method_name,
                text,
            ])?;
            budget.row::<MethodStringRow>()?;
            rows.push(MethodStringRow {
                method: caller.descriptor.clone(),
                method_class: caller.class_descriptor.clone(),
                method_name: caller.method_name.clone(),
                value: text.clone(),
                file_id,
                class_idx: site.class_idx,
                method_idx: site.caller_method_idx,
                string_idx: site.target_local_index,
            });
        }
        Ok(rows)
    }
    pub fn method_call_rows(&self, file_id: u32) -> MddResult<Vec<MethodCallRow>> {
        self.require_complete()?;
        let mut budget = ProjectionBudget {
            remaining: self.limits.max_projection_bytes,
        };
        let mut rows = Vec::new();
        for site in self
            .sites
            .iter()
            .filter(|site| site.target_kind == TargetKind::Method && site.invoke_kind.is_some())
        {
            let caller =
                &self.definitions.definitions().method_references[site.caller_method_idx as usize];
            let target =
                &self.definitions.definitions().method_references[site.target_local_index as usize];
            budget.text(&[
                &caller.descriptor,
                &caller.class_descriptor,
                &caller.method_name,
                &target.descriptor,
                &target.class_descriptor,
                &target.method_name,
            ])?;
            budget.row::<MethodCallRow>()?;
            rows.push(MethodCallRow {
                method: caller.descriptor.clone(),
                method_class: caller.class_descriptor.clone(),
                method_name: caller.method_name.clone(),
                callee: target.descriptor.clone(),
                callee_class: target.class_descriptor.clone(),
                callee_name: target.method_name.clone(),
                file_id,
                class_idx: site.class_idx,
                method_idx: site.caller_method_idx,
                callee_method_idx: site.target_local_index,
            });
        }
        Ok(rows)
    }
    pub fn method_field_rows(&self, file_id: u32) -> MddResult<Vec<MethodFieldRow>> {
        self.require_complete()?;
        let mut budget = ProjectionBudget {
            remaining: self.limits.max_projection_bytes,
        };
        let mut rows = Vec::new();
        for site in self
            .sites
            .iter()
            .filter(|site| site.target_kind == TargetKind::Field)
        {
            let caller =
                &self.definitions.definitions().method_references[site.caller_method_idx as usize];
            let target =
                &self.definitions.definitions().field_references[site.target_local_index as usize];
            let using = if site.mnemonic.starts_with("iget") || site.mnemonic.starts_with("sget") {
                Some("get".to_owned())
            } else if site.mnemonic.starts_with("iput") || site.mnemonic.starts_with("sput") {
                Some("put".to_owned())
            } else {
                None
            };
            budget.text(&[
                &caller.descriptor,
                &caller.class_descriptor,
                &caller.method_name,
                &target.descriptor,
                &target.class_descriptor,
                &target.field_name,
                &target.type_descriptor,
            ])?;
            budget.row::<MethodFieldRow>()?;
            budget.text(&[using.as_deref().unwrap_or("")])?;
            rows.push(MethodFieldRow {
                method: caller.descriptor.clone(),
                method_class: caller.class_descriptor.clone(),
                method_name: caller.method_name.clone(),
                field: target.descriptor.clone(),
                field_class: target.class_descriptor.clone(),
                field_name: target.field_name.clone(),
                field_type: target.type_descriptor.clone(),
                using_type: using,
                file_id,
                class_idx: site.class_idx,
                method_idx: site.caller_method_idx,
                field_idx: site.target_local_index,
            });
        }
        Ok(rows)
    }
    pub fn method_type_rows(&self, file_id: u32) -> MddResult<Vec<MethodTypeRow>> {
        self.require_complete()?;
        let mut budget = ProjectionBudget {
            remaining: self.limits.max_projection_bytes,
        };
        let mut rows = Vec::new();
        for site in self
            .sites
            .iter()
            .filter(|site| site.target_kind == TargetKind::Type)
        {
            let caller =
                &self.definitions.definitions().method_references[site.caller_method_idx as usize];
            let target =
                &self.definitions.metadata().types()[site.target_local_index as usize].data;
            let name = type_name(&target.descriptor);
            budget.text(&[
                &caller.descriptor,
                &caller.class_descriptor,
                &caller.method_name,
                &target.descriptor,
                &name,
            ])?;
            budget.row::<MethodTypeRow>()?;
            rows.push(MethodTypeRow {
                method: caller.descriptor.clone(),
                method_class: caller.class_descriptor.clone(),
                method_name: caller.method_name.clone(),
                type_descriptor: target.descriptor.clone(),
                type_name: name,
                file_id,
                class_idx: site.class_idx,
                method_idx: site.caller_method_idx,
                type_idx: site.target_local_index,
            });
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetadataFacts;
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
    use mdd_input::{
        archive::{ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec},
    };
    use serde_json::Value;
    use std::path::PathBuf;

    struct Setup {
        snapshot: Snapshot,
        inventories: Vec<ArchiveInventory>,
        definitions: Vec<DefinitionFacts>,
        code: Vec<CodeFacts>,
    }
    fn setup(case: &str, count: usize) -> MddResult<Setup> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated")
            .join(format!("{case}.dex"));
        let specs = (0..count)
            .map(|_| InputSpec {
                path: path.clone(),
                kind: InputKind::RawDex,
                expected_sha256: None,
            })
            .collect::<Vec<_>>();
        let snapshot = Snapshot::capture(&specs, CaptureLimits::default())?;
        let mut inventories = Vec::new();
        let mut definitions = Vec::new();
        let mut code = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )?;
            let metadata = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())?;
            definitions.push(DefinitionFacts::build(
                metadata,
                DefinitionLimits::default(),
            )?);
            code.push(CodeFacts::build_all_code_items(
                &snapshot,
                &inventory,
                0,
                CodeLimits::default(),
            )?);
            inventories.push(inventory);
        }
        Ok(Setup {
            snapshot,
            inventories,
            definitions,
            code,
        })
    }
    fn build(case: &str, limits: ReferenceLimits) -> MddResult<ReferenceFacts> {
        let data = setup(case, 1)?;
        ReferenceFacts::build(data.definitions[0].clone(), data.code[0].clone(), limits)
    }
    fn canonical(rows: &Value) -> Vec<String> {
        let mut values = rows
            .as_array()
            .unwrap()
            .iter()
            .map(|row| serde_json::to_string(row).unwrap())
            .collect::<Vec<_>>();
        values.sort();
        values
    }

    #[test]
    fn borrowed_string_sites_preserve_nonscalar_bytes_occurrences_and_coverage() {
        let data = setup("nonscalar-string-035", 2).unwrap();
        let mut occurrences = Vec::new();
        for ordinal in 0..2 {
            let facts = ReferenceFacts::build(
                data.definitions[ordinal].clone(),
                data.code[ordinal].clone(),
                ReferenceLimits::default(),
            )
            .unwrap();
            let sites = facts
                .string_reference_sites(StringReferenceViewLimits::default())
                .unwrap()
                .collect::<MddResult<Vec<_>>>()
                .unwrap();
            let expected = facts
                .sites()
                .iter()
                .filter(|site| site.target_kind == TargetKind::String)
                .count();
            assert!(expected > 0);
            assert_eq!(sites.len(), expected);
            for view in sites {
                assert_eq!(
                    view.source.snapshot_id,
                    data.snapshot.manifest().snapshot_id
                );
                assert_eq!(view.site.target_kind, TargetKind::String);
                assert_eq!(view.site.caller_method_idx, view.caller.method_idx);
                assert_eq!(view.site.target_local_index, view.string.data.string_idx);
                assert_eq!(view.string.data.text.utf16_units, [0xd800]);
                assert_eq!(view.string.data.text.raw_mutf8, [0xed, 0xa0, 0x80]);
                assert_eq!(view.string_pool.string_pool_id, view.string.string_pool_id);
                assert_eq!(
                    facts.raw_operand(view.site.site_ordinal).unwrap().len() as u64,
                    view.site.operand_range.byte_length.0
                );
            }
            assert_eq!(
                facts
                    .string_reference_sites(StringReferenceViewLimits {
                        max_scanned_sites: 0,
                        ..StringReferenceViewLimits::default()
                    })
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
            let visits = (facts.sites().len() as u64) * 2;
            assert_eq!(
                facts
                    .string_reference_sites(StringReferenceViewLimits {
                        max_scanned_sites: visits - 1,
                        ..StringReferenceViewLimits::default()
                    })
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
            assert_eq!(
                facts
                    .string_reference_sites(StringReferenceViewLimits {
                        max_scanned_sites: visits,
                        ..StringReferenceViewLimits::default()
                    })
                    .unwrap()
                    .count(),
                expected
            );
            assert_eq!(
                facts
                    .string_reference_sites(StringReferenceViewLimits {
                        max_result_sites: 0,
                        ..StringReferenceViewLimits::default()
                    })
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
            occurrences.push(facts.source().dex_occurrence_id.clone());
        }
        assert_ne!(occurrences[0], occurrences[1]);

        let partial = CodeFacts::build_offsets(
            &data.snapshot,
            &data.inventories[0],
            0,
            &[],
            CodeLimits::default(),
        )
        .unwrap();
        let facts = ReferenceFacts::build(
            data.definitions[0].clone(),
            partial,
            ReferenceLimits::default(),
        )
        .unwrap();
        assert_eq!(facts.coverage().facts, Completeness::Partial);
        assert_eq!(
            facts
                .string_reference_sites(StringReferenceViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
    }

    #[test]
    fn borrowed_named_sites_preserve_target_kind_occurrences_and_coverage() {
        let data = setup("shared-code-035", 2).unwrap();
        let mut occurrences = Vec::new();
        for ordinal in 0..2 {
            let facts = ReferenceFacts::build(
                data.definitions[ordinal].clone(),
                data.code[ordinal].clone(),
                ReferenceLimits::default(),
            )
            .unwrap();
            for (kind, expected) in [
                (NamedReferenceKind::Method, 8),
                (NamedReferenceKind::Field, 4),
                (NamedReferenceKind::Type, 4),
            ] {
                let views = facts
                    .named_reference_sites(kind, NamedReferenceViewLimits::default())
                    .unwrap()
                    .collect::<MddResult<Vec<_>>>()
                    .unwrap();
                assert_eq!(views.len(), expected, "{kind:?}");
                let mut site_ids = BTreeSet::new();
                for view in views {
                    assert_eq!(
                        view.source.snapshot_id,
                        data.snapshot.manifest().snapshot_id
                    );
                    assert_eq!(
                        view.source.dex_occurrence_id,
                        facts.source().dex_occurrence_id
                    );
                    assert_eq!(view.site.caller_method_idx, view.caller.method_idx);
                    assert_eq!(view.site.target_kind, kind.target_kind());
                    match view.target {
                        NamedReferenceTarget::Method(target) => {
                            assert_eq!(kind, NamedReferenceKind::Method);
                            assert_eq!(target.method_idx, view.site.target_local_index);
                        }
                        NamedReferenceTarget::Field(target) => {
                            assert_eq!(kind, NamedReferenceKind::Field);
                            assert_eq!(target.field_idx, view.site.target_local_index);
                        }
                        NamedReferenceTarget::Type(target) => {
                            assert_eq!(kind, NamedReferenceKind::Type);
                            assert_eq!(target.data.type_idx, view.site.target_local_index);
                            assert_eq!(
                                target.entity.dex_occurrence_id,
                                view.source.dex_occurrence_id
                            );
                        }
                    }
                    assert_eq!(
                        facts.raw_operand(view.site.site_ordinal).unwrap().len() as u64,
                        view.site.operand_range.byte_length.0
                    );
                    site_ids.insert(
                        serde_json::to_string(&facts.site_id(view.site.site_ordinal).unwrap())
                            .unwrap(),
                    );
                }
                assert_eq!(site_ids.len(), expected, "{kind:?}");
                let visits = (facts.sites().len() as u64) * 2;
                assert_eq!(
                    facts
                        .named_reference_sites(
                            kind,
                            NamedReferenceViewLimits {
                                max_scanned_sites: visits - 1,
                                ..NamedReferenceViewLimits::default()
                            },
                        )
                        .err()
                        .unwrap()
                        .code,
                    ErrorCode::QuotaExceeded
                );
                assert_eq!(
                    facts
                        .named_reference_sites(
                            kind,
                            NamedReferenceViewLimits {
                                max_result_sites: 0,
                                ..NamedReferenceViewLimits::default()
                            },
                        )
                        .err()
                        .unwrap()
                        .code,
                    ErrorCode::QuotaExceeded
                );
            }
            occurrences.push(facts.source().dex_occurrence_id.clone());
        }
        assert_ne!(occurrences[0], occurrences[1]);

        let partial = CodeFacts::build_offsets(
            &data.snapshot,
            &data.inventories[0],
            0,
            &[],
            CodeLimits::default(),
        )
        .unwrap();
        let facts = ReferenceFacts::build(
            data.definitions[0].clone(),
            partial,
            ReferenceLimits::default(),
        )
        .unwrap();
        for kind in [
            NamedReferenceKind::Method,
            NamedReferenceKind::Field,
            NamedReferenceKind::Type,
        ] {
            assert_eq!(
                facts
                    .named_reference_sites(kind, NamedReferenceViewLimits::default())
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::IncompleteFacts
            );
        }
    }
    fn target_method(facts: &DefinitionFacts, name: &str) -> u32 {
        facts
            .definitions()
            .method_references
            .iter()
            .find(|method| method.method_name == name)
            .unwrap()
            .method_idx
    }

    #[test]
    fn all_hand_fixtures_match_independent_sites_ranges_and_complete_rows() {
        let oracle: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/references/oracle-results.json"
        ))
        .unwrap();
        let mut accepted = 0;
        let mut rejected = 0;
        for reference in oracle["results"].as_array().unwrap() {
            let case = PathBuf::from(reference["path"].as_str().unwrap())
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let result = build(&case, ReferenceLimits::default());
            if reference["status"] == "invalid" {
                let error = result
                    .err()
                    .unwrap_or_else(|| panic!("invalid fixture accepted: {case}"));
                assert_eq!(error.code, ErrorCode::InvalidInput, "{case}: {error}");
                rejected += 1;
                continue;
            }
            let facts = result.unwrap_or_else(|error| panic!("{case}: {error}"));
            facts.require_complete().unwrap();
            accepted += 1;
            assert_eq!(
                facts.sites().len(),
                reference["sites"].as_array().unwrap().len(),
                "{case}"
            );
            let mut ids = BTreeSet::new();
            for (site, expected) in facts
                .sites()
                .iter()
                .zip(reference["sites"].as_array().unwrap())
            {
                assert_eq!(
                    u64::from(site.caller_method_idx),
                    expected["caller_method_idx"].as_u64().unwrap()
                );
                assert_eq!(
                    u64::from(site.code_unit_pc),
                    expected["pc"].as_u64().unwrap()
                );
                assert_eq!(
                    u64::from(site.operand_ordinal),
                    expected["operand_ordinal"].as_u64().unwrap()
                );
                assert_eq!(
                    serde_json::to_value(site.target_kind).unwrap(),
                    expected["kind"]
                );
                assert_eq!(
                    u64::from(site.target_local_index),
                    expected["index"].as_u64().unwrap()
                );
                assert_eq!(
                    site.operand_range.byte_offset.0,
                    expected["byte_offset"].as_u64().unwrap()
                );
                assert_eq!(
                    site.operand_range.byte_length.0,
                    expected["byte_length"].as_u64().unwrap()
                );
                let raw = facts.raw_operand(site.site_ordinal).unwrap();
                let actual = if raw.len() == 4 {
                    u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
                } else {
                    u32::from(u16::from_le_bytes([raw[0], raw[1]]))
                };
                assert_eq!(actual, site.target_local_index);
                ids.insert(
                    serde_json::to_string(&facts.site_id(site.site_ordinal).unwrap()).unwrap(),
                );
                let target = facts
                    .target_id(site.target_kind, site.target_local_index)
                    .unwrap();
                assert_eq!(
                    facts.find_target_indexed(&target).unwrap(),
                    facts.find_target_scalar(&target).unwrap()
                );
            }
            assert_eq!(
                ids.len(),
                facts.sites().len(),
                "each caller/PC/operand identity must remain distinct"
            );
            if reference["plain_scalar_string_projection"] == true {
                assert_eq!(
                    canonical(&serde_json::to_value(facts.method_string_rows(0).unwrap()).unwrap()),
                    canonical(&reference["relations"]["method_strings"]),
                    "{case} strings"
                );
            } else {
                assert_eq!(
                    facts.method_string_rows(0).err().unwrap().code,
                    ErrorCode::UnsupportedQuery
                );
                let index = facts
                    .sites()
                    .iter()
                    .find(|site| site.target_kind == TargetKind::String)
                    .unwrap()
                    .target_local_index;
                assert_eq!(
                    facts.definitions().metadata().strings()[index as usize]
                        .data
                        .text
                        .utf16_units,
                    [0xd800]
                );
            }
            for (name, rows) in [
                (
                    "method_calls",
                    serde_json::to_value(facts.method_call_rows(0).unwrap()).unwrap(),
                ),
                (
                    "method_field_accesses",
                    serde_json::to_value(facts.method_field_rows(0).unwrap()).unwrap(),
                ),
                (
                    "method_used_types",
                    serde_json::to_value(facts.method_type_rows(0).unwrap()).unwrap(),
                ),
            ] {
                assert_eq!(
                    canonical(&rows),
                    canonical(&reference["relations"][name]),
                    "{case} {name}"
                );
            }
            assert_eq!(
                facts.dynamic_calls().len(),
                reference["dynamic_calls"].as_array().unwrap().len()
            );
            assert_eq!(
                facts.coverage().unowned_physical_code_items as usize,
                reference["unowned_code_offsets"].as_array().unwrap().len()
            );
        }
        assert_eq!((accepted, rejected), (11, 7));
    }

    #[test]
    fn shared_code_expands_callers_without_counting_projection_duplicates_or_fake_callers() {
        let shared = build("shared-code-035", ReferenceLimits::default()).unwrap();
        assert_eq!(shared.sites().len(), 20);
        assert_eq!(shared.method_call_rows(0).unwrap().len(), 8);
        assert_eq!(shared.coverage().no_body_methods, 1);
        let orphan = build("orphan-code-035", ReferenceLimits::default()).unwrap();
        assert_eq!(orphan.coverage().unowned_physical_code_items, 1);
        assert_eq!(orphan.sites().len(), 10);
        let data = setup("classic-035", 1).unwrap();
        let offsets = data.code[0]
            .declared_code_item_byte_offsets()
            .iter()
            .map(|offset| offset.0 as u32)
            .collect::<Vec<_>>();
        let projected = CodeFacts::build_offsets(
            &data.snapshot,
            &data.inventories[0],
            0,
            &[offsets[0], offsets[0], offsets[1]],
            CodeLimits::default(),
        )
        .unwrap();
        let facts = ReferenceFacts::build(
            data.definitions[0].clone(),
            projected,
            ReferenceLimits::default(),
        )
        .unwrap();
        assert_eq!(facts.sites().len(), 10);
        facts.require_complete().unwrap();
    }

    #[test]
    fn partial_or_missing_code_never_becomes_complete_empty_rows() {
        let data = setup("classic-035", 1).unwrap();
        let target = data.definitions[0]
            .definitions()
            .method_definitions
            .iter()
            .find(|method| {
                data.definitions[0].definitions().method_references[method.method_idx as usize]
                    .method_name
                    == "target"
            })
            .unwrap();
        let MethodBody::Present {
            code_byte_offset, ..
        } = target.body
        else {
            panic!("target body")
        };
        let code = CodeFacts::build_offsets(
            &data.snapshot,
            &data.inventories[0],
            0,
            &[code_byte_offset.0 as u32],
            CodeLimits::default(),
        )
        .unwrap();
        let facts = ReferenceFacts::build(
            data.definitions[0].clone(),
            code,
            ReferenceLimits::default(),
        )
        .unwrap();
        assert_eq!(facts.coverage().facts, Completeness::Partial);
        assert!(facts.sites().is_empty());
        assert_eq!(
            facts.require_complete().err().unwrap().code,
            ErrorCode::IncompleteFacts
        );
        assert_eq!(
            facts.method_call_rows(0).err().unwrap().code,
            ErrorCode::IncompleteFacts
        );
        let index = facts
            .definitions()
            .metadata()
            .strings()
            .iter()
            .find(|item| item.data.text.strict_utf8().ok().as_deref() == Some("repeat"))
            .unwrap()
            .data
            .string_idx;
        let target = facts.target_id(TargetKind::String, index).unwrap();
        let matches = facts.find_target_indexed(&target).unwrap();
        assert!(matches.sites.is_empty());
        assert_eq!(matches.coverage, Completeness::Partial);
        assert!(!matches.absence_proven_within_encoded_operand_scope);
    }

    #[test]
    fn source_and_snapshot_guards_reject_local_id_cross_joins() {
        let data = setup("classic-035", 2).unwrap();
        assert_eq!(
            ReferenceFacts::build(
                data.definitions[0].clone(),
                data.code[1].clone(),
                ReferenceLimits::default()
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::InvalidArgument
        );
        let a = ReferenceFacts::build(
            data.definitions[0].clone(),
            data.code[0].clone(),
            ReferenceLimits::default(),
        )
        .unwrap();
        let b = ReferenceFacts::build(
            data.definitions[1].clone(),
            data.code[1].clone(),
            ReferenceLimits::default(),
        )
        .unwrap();
        assert_ne!(a.site_id(0).unwrap(), b.site_id(0).unwrap());
        assert_eq!(a.source().snapshot_id, b.source().snapshot_id);
        let foreign = b
            .target_id(TargetKind::String, b.sites()[0].target_local_index)
            .unwrap();
        assert_eq!(
            a.find_target_indexed(&foreign).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn ordinary_scope_does_not_consume_unrelated_annotations_and_custom_does_not_fake_callee() {
        let ordinary = build(
            "ordinary-unrelated-bad-annotation",
            ReferenceLimits::default(),
        )
        .unwrap();
        assert!(ordinary.call_site_metadata().is_none());
        assert!(ordinary.method_handle_metadata().is_none());
        assert_eq!(ordinary.method_call_rows(0).unwrap().len(), 4);
        let custom = build("poly-custom-038", ReferenceLimits::default()).unwrap();
        assert_eq!(custom.dynamic_calls().len(), 2);
        assert_eq!(custom.method_call_rows(0).unwrap().len(), 6);
        assert!(custom.dynamic_calls().iter().all(|call| {
            call.runtime_target_status
                .contains("unknown_dynamic_target")
        }));
        assert!(
            custom
                .method_call_rows(0)
                .unwrap()
                .iter()
                .all(|row| row.callee_name != "bootstrap")
        );
        let handles = build("handles-039", ReferenceLimits::default()).unwrap();
        assert_eq!(handles.method_handle_metadata().unwrap().len(), 2);
        assert_eq!(handles.method_call_rows(0).unwrap().len(), 4);
        assert_eq!(handles.method_field_rows(0).unwrap().len(), 2);
    }

    #[test]
    fn index_and_scalar_definition_search_keep_world_scope_external_and_ambiguity() {
        let data = setup("defined-field-035", 2).unwrap();
        let facts = vec![&data.definitions[0], &data.definitions[1]];
        let inventories = data.inventories.iter().collect::<Vec<_>>();
        let complete = DefinitionWorld::from_complete_selected_inputs(
            &data.snapshot,
            &inventories,
            &facts,
            DefinitionSearchLimits::default(),
        )
        .unwrap();
        let provided =
            DefinitionWorld::from_provided(&facts[..1], DefinitionSearchLimits::default()).unwrap();
        let unbuilt = DefinitionWorld::unbuilt(&data.snapshot);
        for method in &data.definitions[0].definitions().method_references {
            let indexed = complete
                .resolve_method_reference(&data.definitions[0], method.method_idx)
                .unwrap();
            let scalar = complete
                .resolve_method_scalar(&data.definitions[0], method.method_idx)
                .unwrap();
            assert_eq!(
                serde_json::to_value(indexed).unwrap(),
                serde_json::to_value(scalar).unwrap()
            );
        }
        for field in &data.definitions[0].definitions().field_references {
            assert_eq!(
                serde_json::to_value(
                    complete
                        .resolve_field_reference(&data.definitions[0], field.field_idx)
                        .unwrap()
                )
                .unwrap(),
                serde_json::to_value(
                    complete
                        .resolve_field_scalar(&data.definitions[0], field.field_idx)
                        .unwrap()
                )
                .unwrap()
            );
        }
        let target = target_method(&data.definitions[0], "target");
        let ambiguous = complete
            .resolve_method_reference(&data.definitions[0], target)
            .unwrap();
        assert_eq!(
            ambiguous.state,
            DefinitionResolutionState::AmbiguousDefinitionsInScope
        );
        assert_eq!(ambiguous.candidates.len(), 2);
        assert_ne!(
            ambiguous.candidates[0].definition,
            ambiguous.candidates[1].definition
        );
        let one = provided
            .resolve_method_reference(&data.definitions[0], target)
            .unwrap();
        assert_eq!(one.state, DefinitionResolutionState::OneDefinitionInScope);
        assert!(!one.search_scope_covers_selected_inputs);
        let external = target_method(&data.definitions[0], "external");
        let unknown = provided
            .resolve_method_reference(&data.definitions[0], external)
            .unwrap();
        assert_eq!(
            unknown.state,
            DefinitionResolutionState::NoDefinitionInProvidedFacts
        );
        assert!(!unknown.absence_proven_in_selected_inputs);
        let absent = complete
            .resolve_method_reference(&data.definitions[0], external)
            .unwrap();
        assert_eq!(
            absent.state,
            DefinitionResolutionState::NoDefinitionInSelectedInputs
        );
        assert!(absent.absence_proven_in_selected_inputs);
        assert!(absent.runtime_resolution.contains("not_inferred"));
        assert_eq!(
            unbuilt
                .resolve_method_reference(&data.definitions[0], target)
                .unwrap()
                .state,
            DefinitionResolutionState::NotBuilt
        );
        assert_eq!(
            DefinitionWorld::from_complete_selected_inputs(
                &data.snapshot,
                &inventories,
                &facts[..1],
                DefinitionSearchLimits::default()
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::IncompleteFacts
        );
        let foreign = setup("classic-035", 1).unwrap();
        assert_eq!(
            complete
                .resolve_method_reference(&foreign.definitions[0], 0)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            DefinitionWorld::from_provided(
                &[facts[0], &foreign.definitions[0]],
                DefinitionSearchLimits::default()
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn caller_site_expansion_query_and_search_budgets_fail_before_partial_success() {
        for limits in [
            ReferenceLimits {
                max_callers: 0,
                ..ReferenceLimits::default()
            },
            ReferenceLimits {
                max_sites: 0,
                ..ReferenceLimits::default()
            },
            ReferenceLimits {
                max_expanded_code_units: 0,
                ..ReferenceLimits::default()
            },
            ReferenceLimits {
                max_fact_bytes: 0,
                ..ReferenceLimits::default()
            },
        ] {
            assert_eq!(
                build("shared-code-035", limits).err().unwrap().code,
                ErrorCode::QuotaExceeded
            );
        }
        let facts = build(
            "classic-035",
            ReferenceLimits {
                max_lookup_candidates: 0,
                ..ReferenceLimits::default()
            },
        )
        .unwrap();
        let target = facts
            .target_id(
                facts.sites()[0].target_kind,
                facts.sites()[0].target_local_index,
            )
            .unwrap();
        assert_eq!(
            facts.find_target_indexed(&target).err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts.find_target_scalar(&target).err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
        let facts = build(
            "classic-035",
            ReferenceLimits {
                max_projection_bytes: 0,
                ..ReferenceLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            facts.method_call_rows(0).err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
        let data = setup("classic-035", 1).unwrap();
        assert_eq!(
            DefinitionWorld::from_provided(
                &[&data.definitions[0]],
                DefinitionSearchLimits {
                    max_definitions: 0,
                    ..DefinitionSearchLimits::default()
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
    }

    #[test]
    fn physical_invalid_body_is_not_downgraded_to_unbuilt_partial_scope() {
        let data = setup("bad-body-interior-pointer", 1).unwrap();
        let projected = CodeFacts::build_offsets(
            &data.snapshot,
            &data.inventories[0],
            0,
            &[],
            CodeLimits::default(),
        )
        .unwrap();
        let error = ReferenceFacts::build(
            data.definitions[0].clone(),
            projected,
            ReferenceLimits::default(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(error.details["reason"], "METHOD_BODY_NOT_CODE_ITEM_START");
    }

    #[test]
    fn custom_narrow_metadata_scope_and_definition_candidate_budget_are_explicit() {
        let custom = build(
            "poly-custom-unrelated-bad-annotation",
            ReferenceLimits::default(),
        )
        .unwrap();
        assert_eq!(custom.dynamic_calls().len(), 2);
        assert!(custom.call_site_metadata().is_some());
        custom.require_complete().unwrap();
        let data = setup("classic-035", 2).unwrap();
        let world = DefinitionWorld::from_provided(
            &[&data.definitions[0], &data.definitions[1]],
            DefinitionSearchLimits {
                max_candidates: 1,
                ..DefinitionSearchLimits::default()
            },
        )
        .unwrap();
        let index = target_method(&data.definitions[0], "target");
        assert_eq!(
            world
                .resolve_method_reference(&data.definitions[0], index)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            world
                .resolve_method_scalar(&data.definitions[0], index)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
}
