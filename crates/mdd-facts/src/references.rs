//! Exact encoded operand sites. Runtime dispatch and definition lookup are separate.
use crate::{
    code::CodeFacts,
    definitions::DefinitionFacts,
    metadata::{
        EntityKind, EntityRef, MetadataSource, SharedId, StringFact, StringPoolIdentity, TypeFact,
    },
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
use std::sync::Arc;

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
    pub snapshot_id: SharedId,
    pub dex_occurrence_id: SharedId,
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
    pub mnemonic: &'static str,
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
/// One encoded invocation operand. This does not resolve runtime dispatch.
pub struct MethodCallSite<'a> {
    pub source: &'a MetadataSource,
    pub site: &'a LocalReferenceSite,
    pub caller: &'a MethodReference,
    pub callee: &'a MethodReference,
}
/// An encoded invoke-custom occurrence and its bootstrap metadata. The
/// bootstrap target is not the dynamically resolved runtime callee.
pub struct DynamicCallReferenceSite<'a> {
    pub source: &'a MetadataSource,
    pub site: &'a LocalReferenceSite,
    pub caller: &'a MethodReference,
    pub dynamic: &'a DynamicCallSite,
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
    definitions: Arc<DefinitionFacts>,
    code: Arc<CodeFacts>,
    sites: Vec<LocalReferenceSite>,
    dynamic_calls: Vec<DynamicCallSite>,
    target_index: TargetIndex,
    coverage: ReferenceCoverage,
    arrays: Option<EncodedArraySection>,
    handles: Option<MethodHandleSection>,
    limits: ReferenceLimitsView,
    usage: ReferenceUsage,
}

/// Compressed-sparse-row posting index: `keys` is sorted by `(kind, local_index)`
/// and `offsets[i]..offsets[i + 1]` slices `postings` for `keys[i]`.
///
/// One contiguous allocation per array replaces one `BTreeMap` node plus one
/// heap `Vec` per distinct target. Postings stay in ascending site order
/// because they are appended in site construction order, so lookups return the
/// same ordinal sequence as the previous per-target `Vec`.
///
/// Serialization is derived from the same key/value pairs in the same key
/// order as the previous `BTreeMap<(TargetKind, u32), Vec<u32>>`; the wire shape
/// is therefore identical, including the fact that serde_json rejects tuple
/// keys before writing anything.
#[derive(Clone, Debug)]
struct TargetIndex {
    keys: Vec<(TargetKind, u32)>,
    offsets: Vec<u32>,
    postings: Vec<u32>,
}

impl TargetIndex {
    /// Build CSR arrays from the validated site list.
    ///
    /// `distinct` must hold exactly the keys present in `sites`; it iterates in
    /// key order, which becomes the CSR key order. Two passes over `sites`
    /// scatter each posting into its key's slot. Sites are visited in ascending
    /// `site_ordinal` order, so every posting list stays ascending.
    fn from_sites(
        sites: &[LocalReferenceSite],
        distinct: &BTreeSet<(TargetKind, u32)>,
    ) -> MddResult<Self> {
        let keys = distinct.iter().copied().collect::<Vec<_>>();
        let mut offsets = vec![0u32; keys.len() + 1];
        for site in sites {
            let position = keys
                .binary_search(&(site.target_kind, site.target_local_index))
                .map_err(|_| failure("REFERENCE_INDEX_KEY_MISSING"))?;
            offsets[position + 1] += 1;
        }
        for position in 0..keys.len() {
            offsets[position + 1] = offsets[position]
                .checked_add(offsets[position + 1])
                .ok_or_else(|| failure("REFERENCE_INDEX_OFFSET_OVERFLOW"))?;
        }
        let mut cursor = offsets[..keys.len()].to_vec();
        let mut postings = vec![0u32; sites.len()];
        for site in sites {
            let position = keys
                .binary_search(&(site.target_kind, site.target_local_index))
                .map_err(|_| failure("REFERENCE_INDEX_KEY_MISSING"))?;
            let slot = &mut cursor[position];
            postings[*slot as usize] = site.site_ordinal;
            *slot += 1;
        }
        debug_assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        debug_assert_eq!(offsets.len(), keys.len() + 1);
        Ok(Self {
            keys,
            offsets,
            postings,
        })
    }

    fn postings(&self, kind: TargetKind, local_index: u32) -> &[u32] {
        let Ok(position) = self.keys.binary_search(&(kind, local_index)) else {
            return &[];
        };
        let start = self.offsets[position] as usize;
        let end = self.offsets[position + 1] as usize;
        &self.postings[start..end]
    }

    #[cfg(test)]
    fn target_count(&self) -> usize {
        self.keys.len()
    }
}

impl Serialize for TargetIndex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.keys.len()))?;
        for (position, key) in self.keys.iter().enumerate() {
            let start = self.offsets[position] as usize;
            let end = self.offsets[position + 1] as usize;
            map.serialize_entry(key, &self.postings[start..end])?;
        }
        map.end()
    }
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
/// The Java-style name of a type descriptor (`Ljava/lang/String;` is `java.lang.String`, `[I` is `int[]`), which the
/// type-use relation carries beside the descriptor.
pub fn type_name(descriptor: &str) -> String {
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
        Self::build_arc(Arc::new(definitions), Arc::new(code), limits)
    }

    /// Build from shared leases so a facade can publish the same definition and
    /// code facts to several consumers without deep-copying them.
    pub fn build_arc(
        definitions: Arc<DefinitionFacts>,
        code: Arc<CodeFacts>,
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
        // The sites are read out of the decoded instructions. A compact value does not hold them: its items are
        // decoded again, one caller at a time, from the DEX bytes it leases (`CodeItemReader::instructions`), and
        // let go as soon as their sites are taken. The result is the one the full value gives.
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
        // One pass over the used code items instead of two: the two predicates
        // share the same traversal, and stopping once both are true keeps the
        // short-circuit behaviour of the previous separate `any` calls.
        let mut needs_arrays = false;
        let mut needs_handles = false;
        for index in &used_code {
            let item = &code.items()[*index];
            needs_arrays |= item.names_call_site();
            needs_handles |= item.names_method_handle();
            if needs_arrays && needs_handles {
                break;
            }
        }
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
        let mut distinct_targets = BTreeSet::new();
        let mut reader = code.reader();
        for (method_idx, class_def_idx, class_idx, code_index) in callers.iter().copied() {
            let item = reader.instructions(code_index).map_err(bind)?;
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
                    // One set insertion replaces the previous `contains_key`
                    // plus `entry` pair, and keeps the 64-byte charge on the
                    // first posting of each distinct target.
                    if distinct_targets.insert((kind, reference.local_index)) {
                        budget.bytes(64).map_err(bind)?;
                    }
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
                        mnemonic: mdd_dex::instructions::opcode_mnemonic(instruction.opcode),
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
        drop(reader);
        let target_index = TargetIndex::from_sites(&sites, &distinct_targets).map_err(bind)?;
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
    /// The same facts reading `code` instead of the code facts they were built from, which must be the compact copy
    /// of them (`CodeFacts::compacted`): same occurrence, same code items at the same offsets. The sites were read
    /// out of the decoded instructions when the facts were built, so nothing here changes; what is released is the
    /// decoded instructions and debug programs of every code item, once no other holder keeps the full value.
    pub fn with_code(mut self, code: Arc<CodeFacts>) -> MddResult<Self> {
        let refuse = |message: &'static str| {
            MddError::new(ErrorCode::InvalidArgument, "facts.references", message)
        };
        if !code.is_compact() {
            return Err(refuse("with_code takes the compact copy of the code facts"));
        }
        if !same_source(self.definitions.metadata().source(), code.source())
            || code.items().len() != self.code.items().len()
            || code
                .items()
                .iter()
                .zip(self.code.items())
                .any(|(left, right)| {
                    left.data().raw_range.byte_offset.0 != right.data().raw_range.byte_offset.0
                })
        {
            return Err(refuse(
                "the code facts are not the compact copy of the ones these references were built from",
            ));
        }
        self.code = code;
        Ok(self)
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
    /// Borrow method invocation sites in encoded order without deduplicating.
    /// Complete reference facts are required even for a zero-row result.
    /// Logical site visits are bounded across the count and iteration passes;
    /// this does not bound caller-owned output or allocator overhead.
    pub fn method_call_sites(
        &self,
        limits: NamedReferenceViewLimits,
    ) -> MddResult<impl Iterator<Item = MddResult<MethodCallSite<'_>>> + '_> {
        self.require_complete()?;
        let visits = u64::try_from(self.sites.len())
            .ok()
            .and_then(|count| count.checked_mul(2))
            .ok_or_else(|| quota("METHOD_CALL_SITE_SCAN_BUDGET"))?;
        if visits > limits.max_scanned_sites {
            return Err(quota("METHOD_CALL_SITE_SCAN_BUDGET"));
        }
        let is_call = |site: &LocalReferenceSite| {
            site.target_kind == TargetKind::Method && site.invoke_kind.is_some()
        };
        let count = u64::try_from(self.sites.iter().filter(|site| is_call(site)).count())
            .map_err(|_| quota("METHOD_CALL_SITE_RESULT_BUDGET"))?;
        if count > limits.max_result_sites {
            return Err(quota("METHOD_CALL_SITE_RESULT_BUDGET"));
        }
        Ok(self
            .sites
            .iter()
            .filter(move |site| is_call(site))
            .map(move |site| {
                let inconsistent = || {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.references.method_calls",
                        "validated method call identity is inconsistent",
                    )
                };
                let methods = &self.definitions.definitions().method_references;
                let caller = methods
                    .get(site.caller_method_idx as usize)
                    .filter(|value| value.method_idx == site.caller_method_idx)
                    .ok_or_else(inconsistent)?;
                let callee = methods
                    .get(site.target_local_index as usize)
                    .filter(|value| value.method_idx == site.target_local_index)
                    .ok_or_else(inconsistent)?;
                Ok(MethodCallSite {
                    source: self.source(),
                    site,
                    caller,
                    callee,
                })
            }))
    }
    pub fn dynamic_calls(&self) -> &[DynamicCallSite] {
        &self.dynamic_calls
    }
    /// Borrow every encoded invoke-custom occurrence in site order. This is
    /// not a resolved call graph; the runtime target remains unknown. Scanning
    /// is bounded by `sites.len() + 2 * dynamic_calls.len()` logical visits,
    /// including the validation and returned iteration passes, not CPU or RSS.
    pub fn dynamic_call_reference_sites(
        &self,
        limits: NamedReferenceViewLimits,
    ) -> MddResult<impl Iterator<Item = MddResult<DynamicCallReferenceSite<'_>>> + '_> {
        self.require_complete()?;
        let dynamic_count = u64::try_from(self.dynamic_calls.len())
            .map_err(|_| quota("DYNAMIC_CALL_SITE_RESULT_BUDGET"))?;
        let visits = u64::try_from(self.sites.len())
            .ok()
            .and_then(|n| dynamic_count.checked_mul(2).and_then(|d| n.checked_add(d)))
            .ok_or_else(|| quota("DYNAMIC_CALL_SITE_SCAN_BUDGET"))?;
        if visits > limits.max_scanned_sites {
            return Err(quota("DYNAMIC_CALL_SITE_SCAN_BUDGET"));
        }
        if dynamic_count > limits.max_result_sites {
            return Err(quota("DYNAMIC_CALL_SITE_RESULT_BUDGET"));
        }
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.references.dynamic_calls",
                "validated dynamic call identity is inconsistent",
            )
        };
        let encoded_count = u64::try_from(
            self.sites
                .iter()
                .filter(|site| site.target_kind == TargetKind::CallSite)
                .count(),
        )
        .map_err(|_| inconsistent())?;
        if encoded_count != dynamic_count
            || self
                .dynamic_calls
                .windows(2)
                .any(|pair| pair[0].site_ordinal >= pair[1].site_ordinal)
        {
            return Err(inconsistent());
        }
        Ok(self.dynamic_calls.iter().map(move |dynamic| {
            let site = self
                .sites
                .get(dynamic.site_ordinal as usize)
                .filter(|site| {
                    site.site_ordinal == dynamic.site_ordinal
                        && site.target_kind == TargetKind::CallSite
                        && site.target_local_index == dynamic.call_site_idx
                        && matches!(
                            site.invoke_kind,
                            Some(InvokeKind::Custom | InvokeKind::CustomRange)
                        )
                })
                .ok_or_else(inconsistent)?;
            let caller = self
                .definitions
                .definitions()
                .method_references
                .get(site.caller_method_idx as usize)
                .filter(|caller| caller.method_idx == site.caller_method_idx)
                .ok_or_else(inconsistent)?;
            Ok(DynamicCallReferenceSite {
                source: self.source(),
                site,
                caller,
                dynamic,
            })
        }))
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
    /// Resolve one exact encoded operand site within this complete DEX occurrence.
    /// `None` proves absence only within these complete encoded reference facts;
    /// it does not infer runtime dispatch or absence in other occurrences.
    /// `max_site_entries` limits the number of site entries examined, not CPU,
    /// memory, or the definition identity validation performed before the scan.
    pub fn site_by_id(
        &self,
        identity: &ReferenceSiteId,
        max_site_entries: u64,
    ) -> MddResult<Option<&LocalReferenceSite>> {
        self.require_complete()?;
        let caller = &identity.caller_method_definition;
        if caller.snapshot_id != self.source().snapshot_id
            || caller.dex_occurrence_id != self.source().dex_occurrence_id
            || caller.kind != EntityKind::MethodDefinition
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.references",
                "site caller belongs to another occurrence or entity kind",
            ));
        }
        self.definitions
            .entity(EntityKind::MethodDefinition, caller.local_index)?;
        if u64::try_from(self.sites.len()).map_err(|_| quota("SITE_ID_SCAN_BUDGET"))?
            > max_site_entries
        {
            return Err(quota("SITE_ID_SCAN_BUDGET"));
        }
        let mut found = None;
        for site in &self.sites {
            if site.caller_method_idx == caller.local_index
                && site.code_unit_pc == identity.code_unit_pc
                && site.operand_ordinal == identity.operand_ordinal
                && site.target_kind == identity.operand_kind
                && found.replace(site).is_some()
            {
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "facts.references",
                    "duplicate encoded site identity in validated facts",
                ));
            }
        }
        Ok(found)
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
            let matches = self.target_index.postings(target.kind, target.local_index);
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
            .map(|fact| fact.metadata().source().dex_occurrence_id.to_string())
            .collect();
        Self::build(
            facts,
            first.metadata().source().snapshot_id.to_string(),
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
/// The columns of a `method_strings` row that come from the facts, borrowed from them; the caller adds the file.
#[derive(Clone, Copy, Debug)]
pub struct MethodStringRef<'a> {
    pub method: &'a str,
    pub method_class: &'a str,
    pub method_name: &'a str,
    pub value: &'a str,
    pub class_idx: u32,
    pub method_idx: u32,
    pub string_idx: u32,
}
/// The columns of a `method_calls` row that come from the facts, borrowed from them.
#[derive(Clone, Copy, Debug)]
pub struct MethodCallRef<'a> {
    pub method: &'a str,
    pub method_class: &'a str,
    pub method_name: &'a str,
    pub callee: &'a str,
    pub callee_class: &'a str,
    pub callee_name: &'a str,
    pub class_idx: u32,
    pub method_idx: u32,
    pub callee_method_idx: u32,
}
/// The columns of a `method_field_accesses` row that come from the facts, borrowed from them.
#[derive(Clone, Copy, Debug)]
pub struct MethodFieldRef<'a> {
    pub method: &'a str,
    pub method_class: &'a str,
    pub method_name: &'a str,
    pub field: &'a str,
    pub field_class: &'a str,
    pub field_name: &'a str,
    pub field_type: &'a str,
    pub using_type: Option<&'a str>,
    pub class_idx: u32,
    pub method_idx: u32,
    pub field_idx: u32,
}
/// The columns of a `method_used_types` row that come from the facts, borrowed from them.
#[derive(Clone, Copy, Debug)]
pub struct MethodTypeRef<'a> {
    pub method: &'a str,
    pub method_class: &'a str,
    pub method_name: &'a str,
    pub type_descriptor: &'a str,
    pub type_name: &'a str,
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
    /// The string-use sites as rows, each handed to `each` as it is made and not kept: a caller that stores the rows
    /// somewhere else holds one of them at a time, not all of a DEX. Refused and budgeted as `method_string_rows` is.
    pub fn for_each_method_string(
        &self,
        each: &mut dyn FnMut(&MethodStringRef<'_>) -> MddResult<()>,
    ) -> MddResult<()> {
        self.for_each_method_string_with_policy(crate::coverage::NonScalarTextPolicy::Reject, each)
    }

    /// As [`Self::for_each_method_string`], with an explicit policy for legal non-scalar strings.
    pub fn for_each_method_string_with_policy(
        &self,
        policy: crate::coverage::NonScalarTextPolicy,
        each: &mut dyn FnMut(&MethodStringRef<'_>) -> MddResult<()>,
    ) -> MddResult<()> {
        self.require_complete()?;
        let mut budget = ProjectionBudget {
            remaining: self.limits.max_projection_bytes,
        };
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
                let text = policy.project_dex_text(&item.text).ok_or_else(|| {
                    MddError::new(
                        ErrorCode::UnsupportedQuery,
                        "facts.references.projection",
                        "plain UTF8 relation cannot losslessly represent a legal non-scalar DEX string",
                    )
                    .detail("reason", "NON_SCALAR_TEXT_PROJECTION")
                    .detail("string_idx", u64::from(site.target_local_index))
                    .detail("snapshot_id", self.source().snapshot_id.clone())
                    .detail("dex_occurrence_id", self.source().dex_occurrence_id.clone())
                    .detail(
                        "string_pool_id",
                        self.definitions.metadata().string_pool().string_pool_id.clone(),
                    )
                    .detail(
                        "byte_offset",
                        item.text.raw_range.byte_offset.0.to_string(),
                    )
                })?;
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
            each(&MethodStringRef {
                method: &caller.descriptor,
                method_class: &caller.class_descriptor,
                method_name: &caller.method_name,
                value: text,
                class_idx: site.class_idx,
                method_idx: site.caller_method_idx,
                string_idx: site.target_local_index,
            })?;
        }
        Ok(())
    }
    pub fn method_string_rows(&self, file_id: u32) -> MddResult<Vec<MethodStringRow>> {
        self.method_string_rows_with_policy(file_id, crate::coverage::NonScalarTextPolicy::Reject)
    }

    pub fn method_string_rows_with_policy(
        &self,
        file_id: u32,
        policy: crate::coverage::NonScalarTextPolicy,
    ) -> MddResult<Vec<MethodStringRow>> {
        let mut rows = Vec::new();
        self.for_each_method_string_with_policy(policy, &mut |row| {
            rows.push(MethodStringRow {
                method: row.method.to_owned(),
                method_class: row.method_class.to_owned(),
                method_name: row.method_name.to_owned(),
                value: row.value.to_owned(),
                file_id,
                class_idx: row.class_idx,
                method_idx: row.method_idx,
                string_idx: row.string_idx,
            });
            Ok(())
        })?;
        Ok(rows)
    }
    /// The call sites as rows, handed to `each` one at a time (see `for_each_method_string`).
    pub fn for_each_method_call(
        &self,
        each: &mut dyn FnMut(&MethodCallRef<'_>) -> MddResult<()>,
    ) -> MddResult<()> {
        self.require_complete()?;
        let mut budget = ProjectionBudget {
            remaining: self.limits.max_projection_bytes,
        };
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
            each(&MethodCallRef {
                method: &caller.descriptor,
                method_class: &caller.class_descriptor,
                method_name: &caller.method_name,
                callee: &target.descriptor,
                callee_class: &target.class_descriptor,
                callee_name: &target.method_name,
                class_idx: site.class_idx,
                method_idx: site.caller_method_idx,
                callee_method_idx: site.target_local_index,
            })?;
        }
        Ok(())
    }
    pub fn method_call_rows(&self, file_id: u32) -> MddResult<Vec<MethodCallRow>> {
        let mut rows = Vec::new();
        self.for_each_method_call(&mut |row| {
            rows.push(MethodCallRow {
                method: row.method.to_owned(),
                method_class: row.method_class.to_owned(),
                method_name: row.method_name.to_owned(),
                callee: row.callee.to_owned(),
                callee_class: row.callee_class.to_owned(),
                callee_name: row.callee_name.to_owned(),
                file_id,
                class_idx: row.class_idx,
                method_idx: row.method_idx,
                callee_method_idx: row.callee_method_idx,
            });
            Ok(())
        })?;
        Ok(rows)
    }
    /// The field-access sites as rows, handed to `each` one at a time (see `for_each_method_string`).
    pub fn for_each_method_field(
        &self,
        each: &mut dyn FnMut(&MethodFieldRef<'_>) -> MddResult<()>,
    ) -> MddResult<()> {
        self.require_complete()?;
        let mut budget = ProjectionBudget {
            remaining: self.limits.max_projection_bytes,
        };
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
                Some("get")
            } else if site.mnemonic.starts_with("iput") || site.mnemonic.starts_with("sput") {
                Some("put")
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
            budget.text(&[using.unwrap_or("")])?;
            each(&MethodFieldRef {
                method: &caller.descriptor,
                method_class: &caller.class_descriptor,
                method_name: &caller.method_name,
                field: &target.descriptor,
                field_class: &target.class_descriptor,
                field_name: &target.field_name,
                field_type: &target.type_descriptor,
                using_type: using,
                class_idx: site.class_idx,
                method_idx: site.caller_method_idx,
                field_idx: site.target_local_index,
            })?;
        }
        Ok(())
    }
    pub fn method_field_rows(&self, file_id: u32) -> MddResult<Vec<MethodFieldRow>> {
        let mut rows = Vec::new();
        self.for_each_method_field(&mut |row| {
            rows.push(MethodFieldRow {
                method: row.method.to_owned(),
                method_class: row.method_class.to_owned(),
                method_name: row.method_name.to_owned(),
                field: row.field.to_owned(),
                field_class: row.field_class.to_owned(),
                field_name: row.field_name.to_owned(),
                field_type: row.field_type.to_owned(),
                using_type: row.using_type.map(str::to_owned),
                file_id,
                class_idx: row.class_idx,
                method_idx: row.method_idx,
                field_idx: row.field_idx,
            });
            Ok(())
        })?;
        Ok(rows)
    }
    /// The type-use sites as rows, handed to `each` one at a time (see `for_each_method_string`).
    pub fn for_each_method_type(
        &self,
        each: &mut dyn FnMut(&MethodTypeRef<'_>) -> MddResult<()>,
    ) -> MddResult<()> {
        self.require_complete()?;
        let mut budget = ProjectionBudget {
            remaining: self.limits.max_projection_bytes,
        };
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
            each(&MethodTypeRef {
                method: &caller.descriptor,
                method_class: &caller.class_descriptor,
                method_name: &caller.method_name,
                type_descriptor: &target.descriptor,
                type_name: &name,
                class_idx: site.class_idx,
                method_idx: site.caller_method_idx,
                type_idx: site.target_local_index,
            })?;
        }
        Ok(())
    }
    pub fn method_type_rows(&self, file_id: u32) -> MddResult<Vec<MethodTypeRow>> {
        let mut rows = Vec::new();
        self.for_each_method_type(&mut |row| {
            rows.push(MethodTypeRow {
                method: row.method.to_owned(),
                method_class: row.method_class.to_owned(),
                method_name: row.method_name.to_owned(),
                type_descriptor: row.type_descriptor.to_owned(),
                type_name: row.type_name.to_owned(),
                file_id,
                class_idx: row.class_idx,
                method_idx: row.method_idx,
                type_idx: row.type_idx,
            });
            Ok(())
        })?;
        Ok(rows)
    }
}

#[cfg(test)]
#[path = "references_tests.rs"]
mod tests;
