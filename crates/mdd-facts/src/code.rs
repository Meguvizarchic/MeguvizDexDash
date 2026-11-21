//! Snapshot-bound code layout facts; method ownership is a separate definition layer.
use crate::{
    MetadataSource,
    definitions::{DefinitionFacts, MethodFactView, MethodFactViews, MethodViewLimits},
    metadata::EntityRef,
};
use mdd_dex::{
    definitions::MethodBody,
    instructions::{
        CodeItem, CodeItemDecoder, CodeLimits, CodeSection, DebugPolicy, ReferenceKind,
        read_code_offsets, read_code_section_streaming, read_code_section_with_debug_starts,
    },
    validate_header,
};
use mdd_input::{archive::ArchiveInventory, snapshot::Snapshot};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::{borrow::Cow, sync::Arc};

#[derive(Clone, Serialize)]
pub struct CodeFact {
    pub(crate) code_item_id: String,
    pub(crate) data: CodeItem,
    /// The opcode of every ordinary instruction, in code-unit order: the one piece of the decoded
    /// instructions the `methods` relation reads (`opcode_count`, `opcode_hex`). Kept for every fact so that
    /// a compact fact answers it without decoding.
    #[serde(skip)]
    pub(crate) opcodes: Box<[u8]>,
    /// Which tables of the DEX the item's instructions read besides the ones every reference reads, as the
    /// `NAMES_*` bits: kept for every fact, so the reference layer can tell what it needs to load before it decodes
    /// any instruction of a compact one.
    #[serde(skip)]
    pub(crate) reference_kinds: u8,
}

/// An instruction of the item names a call site (`invoke-custom`).
const NAMES_CALL_SITE: u8 = 1;
/// An instruction of the item names a method handle.
const NAMES_METHOD_HANDLE: u8 = 2;

fn reference_kinds_of(item: &CodeItem) -> u8 {
    let mut kinds = 0;
    for instruction in &item.instructions {
        for reference in &instruction.references {
            match reference.kind {
                ReferenceKind::CallSite => kinds |= NAMES_CALL_SITE,
                ReferenceKind::MethodHandle => kinds |= NAMES_METHOD_HANDLE,
                _ => {}
            }
        }
    }
    kinds
}

impl CodeFact {
    /// An instruction of the item names a call site, so the reference layer reads the DEX's call-site arrays for it.
    pub fn names_call_site(&self) -> bool {
        self.reference_kinds & NAMES_CALL_SITE != 0
    }
    /// An instruction of the item names a method handle.
    pub fn names_method_handle(&self) -> bool {
        self.reference_kinds & NAMES_METHOD_HANDLE != 0
    }

    pub fn code_item_id(&self) -> &str {
        &self.code_item_id
    }
    /// The code item. On a fact of a compact `CodeFacts` (see `CodeFacts::compacted`) this is the header view:
    /// `instructions`, `payloads`, `switch_targets` and `debug_info` are empty. Anything that reads those must get
    /// the item from `CodeFacts::decoded_item` or a `CodeItemReader`, which give the same item on either kind.
    pub fn data(&self) -> &CodeItem {
        &self.data
    }
    /// The opcode of every ordinary instruction, in order. Equal to the opcodes of `data().instructions` on a
    /// full fact, and available on a compact one.
    pub fn opcodes(&self) -> &[u8] {
        &self.opcodes
    }
}

/// The part of a code item that is not derived from its instruction words or debug program: what a compact
/// fact keeps. Listed field by field so that a field added to `CodeItem` stops compiling here until it is
/// placed on one side or the other.
fn header_view(item: &CodeItem) -> CodeItem {
    let CodeItem {
        raw_range,
        insns_range,
        registers_size,
        ins_size,
        outs_size,
        insns_size_code_units,
        debug_info_byte_offset,
        instructions: _,
        payloads: _,
        switch_targets: _,
        tries,
        handlers,
        debug_info: _,
        validation_scope,
        full_art_verification_complete,
    } = item;
    CodeItem {
        raw_range: raw_range.clone(),
        insns_range: insns_range.clone(),
        registers_size: *registers_size,
        ins_size: *ins_size,
        outs_size: *outs_size,
        insns_size_code_units: *insns_size_code_units,
        debug_info_byte_offset: *debug_info_byte_offset,
        instructions: Vec::new(),
        payloads: Vec::new(),
        switch_targets: Vec::new(),
        tries: tries.clone(),
        handlers: handlers.clone(),
        debug_info: None,
        validation_scope: validation_scope.clone(),
        full_art_verification_complete: *full_art_verification_complete,
    }
}

fn bind_source(source: &MetadataSource, error: MddError) -> MddError {
    error
        .detail("source_binding", "snapshot_member_lease")
        .detail("snapshot_id", source.snapshot_id.clone())
        .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
        .detail("member_id", source.member_id.clone())
        .detail("content_id", source.content_id.clone())
}

/// `header_view` of an item that is not needed any more: the parts it keeps are moved, not copied.
fn into_header_view(item: CodeItem) -> CodeItem {
    let CodeItem {
        raw_range,
        insns_range,
        registers_size,
        ins_size,
        outs_size,
        insns_size_code_units,
        debug_info_byte_offset,
        instructions: _,
        payloads: _,
        switch_targets: _,
        tries,
        handlers,
        debug_info: _,
        validation_scope,
        full_art_verification_complete,
    } = item;
    CodeItem {
        raw_range,
        insns_range,
        registers_size,
        ins_size,
        outs_size,
        insns_size_code_units,
        debug_info_byte_offset,
        instructions: Vec::new(),
        payloads: Vec::new(),
        switch_targets: Vec::new(),
        tries,
        handlers,
        debug_info: None,
        validation_scope,
        full_art_verification_complete,
    }
}

/// Immutable validated encoded facts; source-position semantics remain separate.
/// ```compile_fail
/// # use mdd_facts::code::CodeFacts;
/// fn forge(facts: &mut CodeFacts) { facts.items.clear(); }
/// ```
#[derive(Clone, Serialize)]
pub struct CodeFacts {
    pub(crate) source: MetadataSource,
    pub(crate) scope: String,
    pub(crate) debug_policy: DebugPolicy,
    pub(crate) declared_map_code_item_count: u32,
    pub(crate) declared_code_item_byte_offsets: Vec<DecimalU64>,
    pub(crate) requested_code_byte_offsets: Vec<DecimalU64>,
    pub(crate) items: Vec<CodeFact>,
    pub(crate) code_layout_coverage: Completeness,
    pub(crate) method_ownership_built: bool,
    pub(crate) references_built: bool,
    pub(crate) source_positions_built: bool,
    pub(crate) full_dex_validation_complete: bool,
    /// The DEX bytes the items were read from (see `MetadataFacts`).
    #[serde(skip)]
    bytes: Arc<[u8]>,
    /// The limits the items were decoded under; a later decode of one item uses the same ones.
    #[serde(skip)]
    limits: CodeLimits,
    /// Where the DEX's debug programs start, from the same section read. Present for a complete build; a
    /// scoped build (`build_offsets`) does not keep it and cannot be compacted.
    #[serde(skip)]
    debug_starts: Option<Arc<[u64]>>,
    /// True for the result of `compacted`: the items hold headers and opcodes, not decoded instructions.
    #[serde(skip)]
    compact: bool,
}

impl CodeFacts {
    pub fn build_all_code_items(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        limits: CodeLimits,
    ) -> MddResult<Self> {
        Self::build(snapshot, inventory, dex_index, None, limits)
    }

    pub fn build_offsets(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        offsets: &[u32],
        limits: CodeLimits,
    ) -> MddResult<Self> {
        Self::build(snapshot, inventory, dex_index, Some(offsets), limits)
    }

    /// The source of the DEX and its validated header, after the checks that tie the inventory to the snapshot and the
    /// held bytes to the identity they were captured under. Every error after the source is known carries it.
    fn prepare(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
    ) -> MddResult<(MetadataSource, Arc<[u8]>, mdd_dex::DexHeader)> {
        let source_entry = snapshot
            .manifest()
            .sources
            .iter()
            .find(|source| {
                source.occurrence_id == inventory.manifest().source_occurrence_id
                    && source.content_id == inventory.manifest().source_content_id
            })
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.code",
                    "inventory does not belong to snapshot",
                )
            })?;
        let candidate = inventory.selected_dexes().get(dex_index).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "DEX occurrence index outside inventory",
            )
        })?;
        let source = MetadataSource {
            snapshot_id: snapshot.manifest().snapshot_id.as_str().into(),
            dex_occurrence_id: candidate.dex_occurrence_id.as_str().into(),
            physical_dex_id: candidate.physical_dex_id.clone(),
            member_id: candidate.blob.identity.member_id.clone(),
            source_occurrence_id: source_entry.occurrence_id.clone(),
            content_id: candidate.blob.content_id.clone(),
        };
        if candidate.logical_header_byte_offset.0 != 0
            || candidate.blob.identity.source_occurrence_id != source_entry.occurrence_id
        {
            return Err(bind_source(
                &source,
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.code",
                    "unsupported logical offset or mismatched source",
                ),
            ));
        }
        let bytes = candidate
            .blob
            .try_lease()
            .map_err(|error| bind_source(&source, error))?;
        if content_id(&bytes) != source.content_id {
            return Err(bind_source(
                &source,
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.code",
                    "held bytes differ from content identity",
                ),
            ));
        }
        let header = validate_header(&bytes).map_err(|error| bind_source(&source, error))?;
        Ok((source, bytes, header))
    }

    fn build(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        offsets: Option<&[u32]>,
        limits: CodeLimits,
    ) -> MddResult<Self> {
        let (source, bytes, header) = Self::prepare(snapshot, inventory, dex_index)?;
        let (section, debug_starts): (CodeSection, Option<Arc<[u64]>>) = match offsets {
            None => read_code_section_with_debug_starts(&bytes, &header, limits)
                .map(|(section, starts)| (section, Some(Arc::from(starts)))),
            Some(offsets) => {
                read_code_offsets(&bytes, &header, offsets, limits).map(|section| (section, None))
            }
        }
        .map_err(|error| bind_source(&source, error))?;
        let items = section
            .items
            .into_iter()
            .map(|data| CodeFact {
                code_item_id: format!(
                    "{}:code-byte:{}",
                    source.dex_occurrence_id, data.raw_range.byte_offset.0
                ),
                opcodes: data.instructions.iter().map(|i| i.opcode).collect(),
                reference_kinds: reference_kinds_of(&data),
                data,
            })
            .collect();
        Ok(Self {
            source,
            scope: section.scope,
            debug_policy: limits.debug_policy,
            declared_map_code_item_count: section.declared_code_item_count,
            declared_code_item_byte_offsets: section.declared_code_item_byte_offsets,
            requested_code_byte_offsets: offsets
                .unwrap_or(&[])
                .iter()
                .map(|n| DecimalU64(u64::from(*n)))
                .collect(),
            items,
            code_layout_coverage: Completeness::Complete,
            method_ownership_built: false,
            references_built: false,
            source_positions_built: false,
            full_dex_validation_complete: false,
            bytes,
            limits,
            debug_starts,
            compact: false,
        })
    }

    /// The compact facts of every code item (`build_all_code_items` and then `compacted`), without the full ones in
    /// between: each item is read and validated by the same walk, kept as its header and opcodes, and let go. Equal to
    /// what the two steps give, error for error; the difference is that the decoded instructions of the whole section
    /// are never alive together, which for a large DEX is most of a gigabyte.
    pub fn build_all_code_items_compact(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        limits: CodeLimits,
    ) -> MddResult<Self> {
        let (source, bytes, header) = Self::prepare(snapshot, inventory, dex_index)?;
        let mut items = Vec::new();
        let (section, debug_starts) =
            read_code_section_streaming(&bytes, &header, limits, |data| {
                items.push(CodeFact {
                    code_item_id: format!(
                        "{}:code-byte:{}",
                        source.dex_occurrence_id, data.raw_range.byte_offset.0
                    ),
                    opcodes: data.instructions.iter().map(|i| i.opcode).collect(),
                    reference_kinds: reference_kinds_of(&data),
                    data: into_header_view(data),
                });
                Ok(())
            })
            .map_err(|error| bind_source(&source, error))?;
        Ok(Self {
            source,
            scope: section.scope,
            debug_policy: limits.debug_policy,
            declared_map_code_item_count: section.declared_code_item_count,
            declared_code_item_byte_offsets: section.declared_code_item_byte_offsets,
            requested_code_byte_offsets: Vec::new(),
            items,
            code_layout_coverage: Completeness::Complete,
            method_ownership_built: false,
            references_built: false,
            source_positions_built: false,
            full_dex_validation_complete: false,
            bytes,
            limits,
            debug_starts: Some(Arc::from(debug_starts)),
            compact: true,
        })
    }

    /// The same facts with the decoded instructions, payloads, switch tables and debug programs dropped from every
    /// item: what is left is the header of each item, its tries and handlers, and its opcode bytes. They are
    /// 20-25 times smaller, and the dropped parts come back, equal field for field, from `decoded_item` or a
    /// `CodeItemReader`, which decode that one item again from the DEX bytes this value keeps leasing.
    ///
    /// Build, validation and coverage are unchanged: the instructions were decoded and checked when `self` was built.
    /// Only a complete build can be compacted (a scoped one does not keep what a later decode needs), and a compact
    /// value cannot be compacted again.
    pub fn compacted(&self) -> MddResult<Self> {
        let refuse = |message: &'static str| {
            MddError::new(ErrorCode::InvalidArgument, "facts.code", message)
        };
        if self.compact {
            return Err(refuse("code facts are already compact"));
        }
        if self.debug_starts.is_none() || !self.requested_code_byte_offsets.is_empty() {
            return Err(refuse("only a complete code section can be compacted"));
        }
        let items = self
            .items
            .iter()
            .map(|fact| CodeFact {
                code_item_id: fact.code_item_id.clone(),
                data: header_view(&fact.data),
                opcodes: fact.opcodes.clone(),
                reference_kinds: fact.reference_kinds,
            })
            .collect();
        Ok(Self {
            source: self.source.clone(),
            scope: self.scope.clone(),
            debug_policy: self.debug_policy,
            declared_map_code_item_count: self.declared_map_code_item_count,
            declared_code_item_byte_offsets: self.declared_code_item_byte_offsets.clone(),
            requested_code_byte_offsets: self.requested_code_byte_offsets.clone(),
            items,
            code_layout_coverage: self.code_layout_coverage,
            method_ownership_built: self.method_ownership_built,
            references_built: self.references_built,
            source_positions_built: self.source_positions_built,
            full_dex_validation_complete: self.full_dex_validation_complete,
            bytes: Arc::clone(&self.bytes),
            limits: self.limits,
            debug_starts: self.debug_starts.clone(),
            compact: true,
        })
    }

    /// True when the items hold headers and opcodes only (see `compacted`).
    pub fn is_compact(&self) -> bool {
        self.compact
    }

    /// The code item with its instructions, payloads, switch tables and debug program: borrowed from a full value,
    /// decoded again from the DEX bytes for a compact one. Equal either way. For many items of one DEX, a
    /// `CodeItemReader` keeps the decoder between calls.
    pub fn decoded_item(&self, ordinal: usize) -> MddResult<Cow<'_, CodeItem>> {
        self.reader().get(ordinal)
    }

    /// Reads decoded items, remembering the decoder (and the debug programs it has decoded) between calls.
    pub fn reader(&self) -> CodeItemReader<'_> {
        CodeItemReader {
            facts: self,
            decoder: None,
        }
    }

    pub fn lease(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }

    pub fn source(&self) -> &MetadataSource {
        &self.source
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn debug_policy(&self) -> DebugPolicy {
        self.debug_policy
    }
    pub fn declared_map_code_item_count(&self) -> u32 {
        self.declared_map_code_item_count
    }
    pub fn declared_code_item_byte_offsets(&self) -> &[DecimalU64] {
        &self.declared_code_item_byte_offsets
    }
    pub fn known_code_item_start(&self, offset: u64) -> bool {
        self.declared_code_item_byte_offsets
            .binary_search_by_key(&offset, |item| item.0)
            .is_ok()
    }
    pub fn requested_code_byte_offsets(&self) -> &[DecimalU64] {
        &self.requested_code_byte_offsets
    }
    pub fn items(&self) -> &[CodeFact] {
        &self.items
    }
    pub fn code_layout_coverage(&self) -> Completeness {
        self.code_layout_coverage
    }
    pub fn method_ownership_built(&self) -> bool {
        self.method_ownership_built
    }
    pub fn references_built(&self) -> bool {
        self.references_built
    }
    pub fn source_positions_built(&self) -> bool {
        self.source_positions_built
    }
    pub fn full_dex_validation_complete(&self) -> bool {
        self.full_dex_validation_complete
    }

    fn bytes_in(&self, range: &mdd_dex::DexRange) -> MddResult<&[u8]> {
        mdd_dex::checked_reader::CheckedReader::new(&self.bytes)
            .range(range.byte_offset.0, range.byte_length.0)
    }

    pub fn raw_insns(&self, ordinal: usize) -> MddResult<&[u8]> {
        let item = self.items.get(ordinal).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "code ordinal outside scope",
            )
        })?;
        self.bytes_in(&item.data.insns_range)
    }

    pub fn raw_code_item(&self, ordinal: usize) -> MddResult<&[u8]> {
        let item = self.items.get(ordinal).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "code ordinal outside scope",
            )
        })?;
        self.bytes_in(&item.data.raw_range)
    }
}

/// Decoded code items of one `CodeFacts`, with the decoder kept between calls. See `CodeFacts::reader`.
/// Dropping it releases whatever debug programs it decoded.
pub struct CodeItemReader<'a> {
    facts: &'a CodeFacts,
    decoder: Option<CodeItemDecoder<Arc<[u8]>>>,
}

impl<'a> CodeItemReader<'a> {
    pub fn get(&mut self, ordinal: usize) -> MddResult<Cow<'a, CodeItem>> {
        let facts = self.facts;
        let fact = facts.items.get(ordinal).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "code ordinal outside scope",
            )
        })?;
        self.fact(fact)
    }

    /// The decoded item of a fact of these code facts (the fact a `MethodCodeBody::Present` carries).
    pub fn fact(&mut self, fact: &'a CodeFact) -> MddResult<Cow<'a, CodeItem>> {
        self.item_of(fact, true)
    }

    /// As `get`, with the instructions, payloads and switch tables but without the debug program: `debug_info` is
    /// `None` on a compact value. For a reader of the instructions, which then does not decode the debug programs or
    /// keep them. A full value hands out its own item, which has its program.
    pub fn instructions(&mut self, ordinal: usize) -> MddResult<Cow<'a, CodeItem>> {
        let facts = self.facts;
        let fact = facts.items.get(ordinal).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "code ordinal outside scope",
            )
        })?;
        self.item_of(fact, false)
    }

    fn item_of(&mut self, fact: &'a CodeFact, debug: bool) -> MddResult<Cow<'a, CodeItem>> {
        let facts = self.facts;
        if !facts.compact {
            return Ok(Cow::Borrowed(&fact.data));
        }
        if self.decoder.is_none() {
            let starts = facts.debug_starts.as_ref().ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.code",
                    "compact code facts lost their debug program starts",
                )
            })?;
            let lease = Arc::clone(&facts.bytes);
            let header = validate_header(&lease)?;
            self.decoder = Some(CodeItemDecoder::new(lease, header, facts.limits, starts));
        }
        let decoder = self.decoder.as_mut().ok_or_else(|| {
            MddError::new(ErrorCode::InternalFault, "facts.code", "decoder missing")
        })?;
        let offset = fact.data.raw_range.byte_offset.0;
        let mut item = if debug {
            decoder.decode(offset)?
        } else {
            decoder.decode_instructions(offset)?
        };
        // The retained header was read together with the whole section; keep it as the one source of truth for
        // the fields that are not derived from the instruction words.
        item.validation_scope
            .clone_from(&fact.data.validation_scope);
        Ok(Cow::Owned(item))
    }
}

/// Logical join limits. These are not an allocator or process RSS bound.
#[derive(Clone, Copy, Debug)]
pub struct MethodCodeViewLimits {
    pub methods: MethodViewLimits,
    pub max_code_items: u64,
    pub max_code_index_bytes: u64,
}
impl Default for MethodCodeViewLimits {
    fn default() -> Self {
        Self {
            methods: MethodViewLimits::default(),
            max_code_items: 4_000_000,
            max_code_index_bytes: 256 * 1024 * 1024,
        }
    }
}

/// These variants distinguish a reference from actual definitions without bodies.
/// `Present` contains exact validated code facts, not a legacy opcode projection.
pub enum MethodCodeBody<'a> {
    ReferenceOnly,
    Native,
    Abstract,
    Present {
        code: &'a CodeFact,
        raw_insns: &'a [u8],
    },
}

/// Logical limits for a single opcode text projection; not an RSS bound.
#[derive(Clone, Copy, Debug)]
pub struct OpcodeTextLimits {
    pub max_opcodes: u64,
    pub max_text_bytes: u64,
}
impl Default for OpcodeTextLimits {
    fn default() -> Self {
        Self {
            max_opcodes: 4_000_000,
            max_text_bytes: 12_000_000,
        }
    }
}

/// Exact ordinary-instruction count and lower-case hexadecimal text, in order.
/// The underlying `MethodCodeBody` retains the specific definition/body state.
#[derive(Debug, Eq, PartialEq)]
pub struct OpcodeText {
    pub count: u32,
    pub text: String,
}

impl MethodCodeBody<'_> {
    /// Iterates decoded ordinary-instruction opcode bytes in code-unit order.
    /// Payloads are separately represented by `CodeItem::payloads` and are not
    /// instructions. The original body variant still distinguishes native,
    /// abstract and present-empty; a reference has no defined opcode sequence.
    /// This is not a legacy hexadecimal rendering or a profile qualification.
    pub fn decoded_opcode_bytes(&self) -> Option<impl ExactSizeIterator<Item = u8> + '_> {
        let opcodes: &[u8] = match self {
            Self::ReferenceOnly => return None,
            Self::Native | Self::Abstract => &[],
            Self::Present { code, .. } => code.opcodes(),
        };
        Some(opcodes.iter().copied())
    }

    /// Render ordinary opcodes as two lower-case hex digits separated by a
    /// single space. Reference-only methods return None; native, abstract and
    /// present-empty definitions return a zero count and empty text. Payload
    /// words are not included. Limits cover logical opcode/text bytes only.
    pub fn opcode_text(&self, limits: OpcodeTextLimits) -> MddResult<Option<OpcodeText>> {
        let Some(opcodes) = self.decoded_opcode_bytes() else {
            return Ok(None);
        };
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.opcode_text",
                "opcode text projection budget exceeded",
            )
        };
        let count = u64::try_from(opcodes.len()).map_err(|_| quota())?;
        let count_u32 = u32::try_from(count).map_err(|_| quota())?;
        let bytes = count
            .checked_mul(3)
            .and_then(|value| {
                if count == 0 {
                    Some(0)
                } else {
                    value.checked_sub(1)
                }
            })
            .ok_or_else(quota)?;
        if count > limits.max_opcodes || bytes > limits.max_text_bytes {
            return Err(quota());
        }
        let mut text = String::new();
        text.try_reserve_exact(usize::try_from(bytes).map_err(|_| quota())?)
            .map_err(|_| quota())?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (ordinal, opcode) in opcodes.enumerate() {
            if ordinal != 0 {
                text.push(' ');
            }
            text.push(char::from(HEX[usize::from(opcode >> 4)]));
            text.push(char::from(HEX[usize::from(opcode & 0x0f)]));
        }
        Ok(Some(OpcodeText {
            count: count_u32,
            text,
        }))
    }
}
pub struct MethodCodeFactView<'a> {
    pub method: MethodFactView<'a>,
    pub body: MethodCodeBody<'a>,
}
pub struct MethodCodeFactViews<'a> {
    methods: MethodFactViews<'a>,
    code: &'a CodeFacts,
    code_index: Vec<usize>,
}
impl<'a> MethodCodeFactViews<'a> {
    /// Decoded items of the code these views were built over: borrowed from full facts, decoded again from the
    /// DEX bytes (keeping the decoder between calls) for compact ones.
    pub(crate) fn code_reader(&self) -> CodeItemReader<'a> {
        self.code.reader()
    }

    /// Bind complete same-occurrence definitions and code layout. A scoped code
    /// projection is accepted only when every present method body is included.
    pub fn build(
        definitions: &'a DefinitionFacts,
        code: &'a CodeFacts,
        limits: MethodCodeViewLimits,
    ) -> MddResult<Self> {
        let source = definitions.metadata().source();
        let actual = code.source();
        if source.snapshot_id != actual.snapshot_id
            || source.dex_occurrence_id != actual.dex_occurrence_id
            || source.physical_dex_id != actual.physical_dex_id
            || source.member_id != actual.member_id
            || source.source_occurrence_id != actual.source_occurrence_id
            || source.content_id != actual.content_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.method_code",
                "definitions and code do not bind the same source generation",
            ));
        }
        if code.code_layout_coverage() != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.method_code",
                "complete code layout for requested items is required",
            ));
        }
        let methods = definitions.method_fact_views(limits.methods)?;
        let count = u64::try_from(code.items().len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.method_code",
                "code index count overflow",
            )
        })?;
        let bytes = count
            .checked_mul(std::mem::size_of::<usize>() as u64)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.method_code",
                    "code index byte overflow",
                )
            })?;
        if count > limits.max_code_items || bytes > limits.max_code_index_bytes {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.method_code",
                "code index budget exceeded",
            ));
        }
        let mut code_index = Vec::new();
        code_index
            .try_reserve_exact(code.items().len())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.method_code",
                    "code index allocation failed",
                )
            })?;
        code_index.extend(0..code.items().len());
        code_index
            .sort_unstable_by_key(|&ordinal| code.items()[ordinal].data().raw_range.byte_offset.0);
        let view = Self {
            methods,
            code,
            code_index,
        };
        // Fail before exposing any rows if a selected projection omitted a real body.
        for method in view.methods.iter() {
            view.body(&method?)?;
        }
        Ok(view)
    }

    fn body(&self, method: &MethodFactView<'a>) -> MddResult<MethodCodeBody<'a>> {
        let Some(definition) = method.definition else {
            return Ok(MethodCodeBody::ReferenceOnly);
        };
        match &definition.body {
            MethodBody::Native => Ok(MethodCodeBody::Native),
            MethodBody::Abstract => Ok(MethodCodeBody::Abstract),
            MethodBody::Present {
                code_byte_offset,
                declared_insns_size,
            } => {
                let at = code_byte_offset.0;
                if !self.code.known_code_item_start(at) {
                    return Err(MddError::new(
                        ErrorCode::InvalidInput,
                        "facts.method_code",
                        "method body is not a physical code item start",
                    )
                    .detail("method_idx", definition.method_idx.to_string())
                    .detail("code_item_byte_offset", at.to_string()));
                }
                let position = self
                    .code_index
                    .binary_search_by_key(&at, |&ordinal| {
                        self.code.items()[ordinal].data().raw_range.byte_offset.0
                    })
                    .map_err(|_| {
                        MddError::new(
                            ErrorCode::IncompleteFacts,
                            "facts.method_code",
                            "method body absent from selected code projection",
                        )
                        .detail("method_idx", definition.method_idx.to_string())
                        .detail("code_item_byte_offset", at.to_string())
                    })?;
                let ordinal = self.code_index[position];
                let code: &'a CodeFacts = self.code;
                let item = &code.items()[ordinal];
                let data = item.data();
                let expected = u64::from(*declared_insns_size) * 2;
                if data.insns_size_code_units != *declared_insns_size
                    || data.insns_range.byte_length.0 != expected
                    || at.checked_add(16) != Some(data.insns_range.byte_offset.0)
                {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "facts.method_code",
                        "definition and code instruction intervals disagree",
                    ));
                }
                let raw_insns = code.raw_insns(ordinal)?;
                Ok(MethodCodeBody::Present {
                    code: item,
                    raw_insns,
                })
            }
        }
    }

    /// Look up a method identity in the already validated source-bound view.
    /// Reference-only, native, abstract and present bodies remain distinct.
    pub fn get(&self, entity: &EntityRef) -> MddResult<MethodCodeFactView<'a>> {
        let method = self.methods.get(entity)?;
        let body = self.body(&method)?;
        Ok(MethodCodeFactView { method, body })
    }

    /// Iterate every method reference in DEX order, including reference-only rows.
    pub fn iter(&self) -> impl Iterator<Item = MddResult<MethodCodeFactView<'a>>> + '_ {
        self.methods.iter().map(|method| {
            let method = method?;
            let body = self.body(&method)?;
            Ok(MethodCodeFactView { method, body })
        })
    }

    /// Gate a requested `code_items` column list before projection.
    pub fn require_relation_columns(
        &self,
        relation: CodeRelation,
        columns: &[&str],
    ) -> MddResult<()> {
        let CodeRelation::CodeItems = relation;
        require_code_item_columns(columns)
    }

    /// Gate a requested `methods` column list for the code-joined projection.
    ///
    /// Unlike [`DefinitionFacts::require_relation_columns`], this gate accepts
    /// `opcode_count`/`opcode_hex` because the code-layout layer is present, and
    /// it accepts `*` because every contract column of `methods` is produced
    /// here.
    pub fn require_method_columns(columns: &[&str]) -> MddResult<()> {
        for column in columns {
            if *column != "*" && !MethodCodeRow::COLUMNS.contains(column) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.method_code",
                    "unknown methods column",
                )
                .detail("column", (*column).to_owned()));
            }
        }
        Ok(())
    }

    /// Project one complete `methods` row per encoded method_id, in DEX order.
    ///
    /// The 12 definition-layer columns keep their reference-only NULLs;
    /// `opcode_count`/`opcode_hex` are the exact decoded ordinary-instruction
    /// count and lower-case hex text of the same occurrence, and are `None`
    /// exactly for a reference-only method. `insns_size` is never used as a
    /// proxy for the opcode count and payload words are never rendered.
    ///
    /// This is the MDD-032 complete legacy `Methods` relation; the tokenizer
    /// shape itself is a compatibility projection, not a native atom.
    pub fn method_rows(&self, file_id: u32) -> MddResult<Vec<MethodCodeRow>> {
        Self::require_method_columns(MethodCodeRow::COLUMNS)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.methods.method_count())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.method_code",
                    "methods row allocation failed",
                )
            })?;
        for view in self.iter() {
            let view = view?;
            let reference = view.method.reference;
            let param_count =
                u32::try_from(reference.parameter_descriptors.len()).map_err(|_| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.method_code",
                        "validated parameter count exceeds UInt32",
                    )
                    .detail("method_idx", u64::from(reference.method_idx))
                })?;
            let (opcode_count, opcode_hex) =
                match view.body.opcode_text(OpcodeTextLimits::default()) {
                    Ok(Some(text)) => (Some(text.count), Some(text.text)),
                    Ok(None) => (None, None),
                    Err(error) => {
                        return Err(error
                            .detail("method_idx", u64::from(reference.method_idx))
                            .detail("column", "opcode_hex"));
                    }
                };
            rows.push(MethodCodeRow {
                file_id,
                method_idx: reference.method_idx,
                class_idx: reference.class_idx,
                class_descriptor: reference.class_descriptor.clone(),
                proto_idx: reference.proto_idx,
                name: reference.method_name.clone(),
                descriptor: reference.descriptor.clone(),
                return_descriptor: reference.return_descriptor.clone(),
                param_count,
                param_descriptors: crate::definitions::parameter_descriptors_text(
                    &reference.parameter_descriptors,
                )?,
                access_flags: view
                    .method
                    .definition
                    .map(|definition| definition.access_flags),
                opcode_count,
                opcode_hex,
                method_kind: view
                    .method
                    .definition
                    .map(|definition| definition.kind.as_str().to_owned()),
            });
        }
        Ok(rows)
    }

    /// The rows of `method_rows`, each handed to `each` as it is made and not kept: a caller that stores the rows somewhere
    /// else holds one at a time, not every row of a DEX with its text. The same rows in the same order, refused as
    /// `method_rows` refuses them; the text of the identity columns is borrowed from the facts, and the two derived texts
    /// (`param_descriptors`, `opcode_hex`) live for the one call of `each`.
    pub fn for_each_method_row(
        &self,
        each: &mut dyn FnMut(&MethodCodeRowRef<'_>) -> MddResult<()>,
    ) -> MddResult<()> {
        Self::require_method_columns(MethodCodeRow::COLUMNS)?;
        for view in self.iter() {
            let view = view?;
            let reference = view.method.reference;
            let param_count =
                u32::try_from(reference.parameter_descriptors.len()).map_err(|_| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.method_code",
                        "validated parameter count exceeds UInt32",
                    )
                    .detail("method_idx", u64::from(reference.method_idx))
                })?;
            let (opcode_count, opcode_hex) =
                match view.body.opcode_text(OpcodeTextLimits::default()) {
                    Ok(Some(text)) => (Some(text.count), Some(text.text)),
                    Ok(None) => (None, None),
                    Err(error) => {
                        return Err(error
                            .detail("method_idx", u64::from(reference.method_idx))
                            .detail("column", "opcode_hex"));
                    }
                };
            let param_descriptors =
                crate::definitions::parameter_descriptors_text(&reference.parameter_descriptors)?;
            each(&MethodCodeRowRef {
                method_idx: reference.method_idx,
                class_idx: reference.class_idx,
                class_descriptor: &reference.class_descriptor,
                proto_idx: reference.proto_idx,
                name: &reference.method_name,
                descriptor: &reference.descriptor,
                return_descriptor: &reference.return_descriptor,
                param_count,
                param_descriptors: &param_descriptors,
                access_flags: view
                    .method
                    .definition
                    .map(|definition| definition.access_flags),
                opcode_count,
                opcode_hex: opcode_hex.as_deref(),
                method_kind: view
                    .method
                    .definition
                    .map(|definition| definition.kind.as_str()),
            })?;
        }
        Ok(())
    }

    /// Project one `code_items` row per method-owned present body, in
    /// `method_idx` order. A physical code item with no declaring method is not
    /// a row of this relation because `method_idx` is NOT NULL; a shared body
    /// expands once per owning method.
    ///
    /// `debug_info_off` projects the encoded header word, so an absent debug
    /// section is the encoded zero offset rather than NULL. `tries_off` and
    /// `handlers_off` are NULL exactly when the encoded try list is empty.
    pub fn code_item_rows(&self, file_id: u32) -> MddResult<Vec<CodeItemRow>> {
        self.require_relation_columns(CodeRelation::CodeItems, CodeItemRow::COLUMNS)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.code.items().len())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.code.projection",
                    "code item row allocation failed",
                )
            })?;
        for view in self.iter() {
            let view = view?;
            let MethodCodeBody::Present { code: item, .. } = view.body else {
                continue;
            };
            let data = item.data();
            let insns_size = data.insns_size_code_units;
            let method_idx = view.method.reference.method_idx;
            let insns_off = u32::try_from(data.insns_range.byte_offset.0).map_err(|_| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.code.projection",
                    "validated insns offset exceeds UInt32",
                )
                .detail("method_idx", u64::from(method_idx))
            })?;
            let tries_size = u32::try_from(data.tries.len()).map_err(|_| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.code.projection",
                    "validated try count exceeds UInt32",
                )
                .detail("method_idx", u64::from(method_idx))
            })?;
            // The encoded instruction array is followed by one alignment word
            // only when its code-unit count is odd; the try block table starts
            // there. This mirrors the raw header layout exactly.
            let tries_off = if tries_size == 0 {
                None
            } else {
                Some(
                    insns_off
                        .checked_add(insns_size.saturating_mul(2))
                        .and_then(|end| end.checked_add(insns_size % 2 * 2))
                        .ok_or_else(|| {
                            MddError::new(
                                ErrorCode::InternalFault,
                                "facts.code.projection",
                                "validated try offset overflow",
                            )
                            .detail("method_idx", u64::from(method_idx))
                        })?,
                )
            };
            let handlers_off = match tries_off {
                Some(offset) => Some(
                    offset
                        .checked_add(tries_size.saturating_mul(8))
                        .ok_or_else(|| {
                            MddError::new(
                                ErrorCode::InternalFault,
                                "facts.code.projection",
                                "validated handler offset overflow",
                            )
                            .detail("method_idx", u64::from(method_idx))
                        })?,
                ),
                None => None,
            };
            rows.push(CodeItemRow {
                file_id,
                method_idx,
                code_off: u32::try_from(data.raw_range.byte_offset.0).map_err(|_| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.code.projection",
                        "validated code offset exceeds UInt32",
                    )
                    .detail("method_idx", u64::from(method_idx))
                })?,
                registers_size: u32::from(data.registers_size),
                ins_size: u32::from(data.ins_size),
                outs_size: u32::from(data.outs_size),
                tries_size,
                debug_info_off: u32::try_from(
                    data.debug_info_byte_offset.map_or(0u64, |value| value.0),
                )
                .map_err(|_| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.code.projection",
                        "validated debug info offset exceeds UInt32",
                    )
                    .detail("method_idx", u64::from(method_idx))
                })?,
                insns_size,
                insns_off,
                tries_off,
                handlers_off,
            });
        }
        Ok(rows)
    }
}

/// Compatibility relation names whose columns the code layer can project.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeRelation {
    CodeItems,
}

/// Gate a requested `code_items` column list without materialising the
/// method/code join. Coverage needs the same rejection contract as
/// [`MethodCodeFactViews::code_item_rows`] without paying for
/// [`MethodCodeFactViews::build`] once per requested column.
pub fn require_code_item_columns(columns: &[&str]) -> MddResult<()> {
    for column in columns {
        if *column != "*" && !CodeItemRow::COLUMNS.contains(column) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code.projection",
                "unknown code_items column",
            )
            .detail("column", (*column).to_owned()));
        }
    }
    Ok(())
}

/// One `code_items` row bound to one method-owned present body.
#[derive(Clone, Debug, Serialize)]
pub struct CodeItemRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub code_off: u32,
    pub registers_size: u32,
    pub ins_size: u32,
    pub outs_size: u32,
    pub tries_size: u32,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub insns_off: u32,
    pub tries_off: Option<u32>,
    pub handlers_off: Option<u32>,
}

impl CodeItemRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &[
        "file_id",
        "method_idx",
        "code_off",
        "registers_size",
        "ins_size",
        "outs_size",
        "tries_size",
        "debug_info_off",
        "insns_size",
        "insns_off",
        "tries_off",
        "handlers_off",
    ];
}

/// One complete 14-column `methods` row: the 12 definition-layer columns plus
/// the two code-layout opcode columns.
///
/// The row exists only when [`MethodCodeFactViews`] was built, so
/// `opcode_count`/`opcode_hex` come from the exact decoded instruction stream
/// of the same occurrence, never from `insns_size`. They are NULL exactly for a
/// reference-only method (no definition body at all); native, abstract and
/// present-empty definitions report `0` and `""`, matching the reference.
/// Payload pseudo-instructions are not counted and are not rendered.
/// A `methods` row (with the opcode columns) without its `file_id`, its text borrowed from the facts or from the call that
/// hands it out: what `for_each_method_row` gives.
#[derive(Clone, Copy, Debug)]
pub struct MethodCodeRowRef<'a> {
    pub method_idx: u32,
    pub class_idx: u32,
    pub class_descriptor: &'a str,
    pub proto_idx: u32,
    pub name: &'a str,
    pub descriptor: &'a str,
    pub return_descriptor: &'a str,
    pub param_count: u32,
    pub param_descriptors: &'a str,
    pub access_flags: Option<u32>,
    pub opcode_count: Option<u32>,
    pub opcode_hex: Option<&'a str>,
    pub method_kind: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MethodCodeRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub class_idx: u32,
    pub class_descriptor: String,
    pub proto_idx: u32,
    pub name: String,
    pub descriptor: String,
    pub return_descriptor: String,
    pub param_count: u32,
    pub param_descriptors: String,
    pub access_flags: Option<u32>,
    pub opcode_count: Option<u32>,
    pub opcode_hex: Option<String>,
    pub method_kind: Option<String>,
}

impl MethodCodeRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &[
        "file_id",
        "method_idx",
        "class_idx",
        "class_descriptor",
        "proto_idx",
        "name",
        "descriptor",
        "return_descriptor",
        "param_count",
        "param_descriptors",
        "access_flags",
        "opcode_count",
        "opcode_hex",
        "method_kind",
    ];
}

#[cfg(test)]
#[path = "code_tests.rs"]
mod tests;
