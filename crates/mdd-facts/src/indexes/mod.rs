//! Snapshot/selected-scope candidate indexes; every candidate is exactly rechecked.
mod columns;
pub mod lazy;
mod scope;
#[cfg(test)]
mod tests;
mod views;
use crate::{
    coverage::{CoverageLedger, CoverageReport, CoverageRequest, FactLayer, InputNeed},
    metadata::{EntityKind, EntityRef},
    references::{
        FieldSymbol, MethodSymbol, ReferenceFacts, ReferenceMatches, ReferenceTargetId, TargetKind,
    },
};
use lazy::{IndexAudit, LazyIndex};
use mdd_dex::annotations::{AnnotationOwnerBinding, EncodedKind, MethodHandleTarget};
use mdd_types::{ErrorCode, MddError, MddResult};
pub use scope::{
    OccurrencePoolCoordinate, ScopedPoolCoordinates, SelectedDex, SelectedInput, SelectedScope,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
pub use views::FactView;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ColumnSpec {
    pub relation: &'static str,
    pub column: &'static str,
    pub data_type: &'static str,
    pub nullable: bool,
    pub assembled_projection: bool,
}
pub fn column_specs() -> &'static [ColumnSpec] {
    columns::COLUMNS
}
#[derive(Clone, Copy, Debug)]
pub struct IndexLimits {
    pub max_entries: u64,
    pub max_index_bytes: u64,
    pub max_result_entries: u64,
    pub max_result_bytes: u64,
    pub max_build_attempts: u64,
    pub build_duration: Option<Duration>,
}
impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_entries: 8_000_000,
            max_index_bytes: 512 * 1024 * 1024,
            max_result_entries: 1_000_000,
            max_result_bytes: 256 * 1024 * 1024,
            max_build_attempts: 32,
            build_duration: None,
        }
    }
}
struct Budget {
    limits: IndexLimits,
    entries: u64,
    bytes: u64,
    started: Instant,
}
impl Budget {
    fn new(limits: IndexLimits) -> Self {
        Self {
            limits,
            entries: 0,
            bytes: 0,
            started: Instant::now(),
        }
    }
    fn charge(&mut self, entries: u64, bytes: u64) -> MddResult<()> {
        if self
            .limits
            .build_duration
            .is_some_and(|duration| self.started.elapsed() >= duration)
        {
            return Err(MddError::new(
                ErrorCode::DeadlineExceeded,
                "facts.index_build",
                "index build deadline reached",
            )
            .detail("budget", "index_build_duration"));
        }
        self.entries = self
            .entries
            .checked_add(entries)
            .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))?;
        if self.entries > self.limits.max_entries {
            return Err(quota("INDEX_ENTRY_BUDGET"));
        }
        if self.bytes > self.limits.max_index_bytes {
            return Err(quota("INDEX_BYTE_BUDGET"));
        }
        Ok(())
    }
}
fn quota(reason: &str) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "facts.index", reason).detail("reason", reason)
}
fn missing_facts(message: &str) -> MddError {
    MddError::new(ErrorCode::IncompleteFacts, "facts.index", message)
}
/// Strings shorter than this deduplicate their code units on the stack
/// instead of allocating a temporary set.
const DEDUP_INLINE_LIMIT: usize = 32;

/// Strings: every string occurrence with its exact UTF-16 units, raw MUTF-8
/// bytes, and the set of code units it contains. Candidates are a superset;
/// callers always recheck with `predicate.matches`.
fn add_strings(
    index: &mut StringIndex,
    budget: &mut Budget,
    view_id: u32,
    metadata: &crate::MetadataFacts,
) -> MddResult<()> {
    for string in metadata.strings() {
        let atom = Atom {
            view: view_id,
            local: string.data.string_idx,
        };
        budget.charge(1, 16)?;
        index.all.push(atom);
        budget.charge(1, 8)?;
        // Deduplicate code units inside one string without a heap BTreeSet:
        // strings are short, so a linear scan over a small stack buffer wins.
        let units = &string.data.text.utf16_units;
        if units.len() <= DEDUP_INLINE_LIMIT {
            let mut seen: [u16; DEDUP_INLINE_LIMIT] = [0; DEDUP_INLINE_LIMIT];
            let mut count = 0usize;
            for unit in units {
                if !seen[..count].contains(unit) {
                    seen[count] = *unit;
                    count += 1;
                    budget.charge(1, 8)?;
                    index.pending_units.push((*unit, atom));
                }
            }
        } else {
            let mut seen = units.to_vec();
            seen.sort_unstable();
            seen.dedup();
            budget.charge(0, seen.len() as u64 * 2)?;
            for unit in seen {
                budget.charge(1, 8)?;
                index.pending_units.push((unit, atom));
            }
        }
    }
    Ok(())
}
/// Definitions: class/field/method names plus direct-owner membership.
fn add_definitions(
    index: &mut DefinitionIndex,
    budget: &mut Budget,
    view_id: u32,
    facts: &crate::definitions::DefinitionFacts,
) -> MddResult<()> {
    let definitions = facts.definitions();
    for class in &definitions.classes {
        let atom = DefinitionAtom {
            view: view_id,
            kind: DefinitionKind::Class,
            local: class.class_def_idx,
        };
        budget.charge(1, class.descriptor.len() as u64 + 24)?;
        index.pending_names.push(atom);
        index.all.push(atom);
    }
    for field in &definitions.field_definitions {
        let reference = &definitions.field_references[field.field_idx as usize];
        let atom = DefinitionAtom {
            view: view_id,
            kind: DefinitionKind::Field,
            local: field.field_idx,
        };
        budget.charge(1, reference.field_name.len() as u64 + 48)?;
        index.pending_names.push(atom);
        index
            .owners
            .entry((view_id, field.class_def_idx, DefinitionKind::Field))
            .or_default()
            .push(atom);
        index.all.push(atom);
    }
    for method in &definitions.method_definitions {
        let reference = &definitions.method_references[method.method_idx as usize];
        let atom = DefinitionAtom {
            view: view_id,
            kind: DefinitionKind::Method,
            local: method.method_idx,
        };
        budget.charge(1, reference.method_name.len() as u64 + 48)?;
        index.pending_names.push(atom);
        index
            .owners
            .entry((view_id, method.class_def_idx, DefinitionKind::Method))
            .or_default()
            .push(atom);
        index.all.push(atom);
    }
    Ok(())
}
/// Encoded method reference symbols (owner, name, prototype), borrowed until
/// the postings are laid out.
fn add_reference_symbols<'m>(
    pairs: &mut Vec<(MethodSymbolKey<'m>, ReferenceAtom)>,
    budget: &mut Budget,
    view_id: u32,
    facts: &'m crate::definitions::DefinitionFacts,
) -> MddResult<()> {
    let definitions = facts.definitions();
    let prototypes = facts.metadata().prototypes();
    pairs
        .try_reserve(definitions.method_references.len())
        .map_err(|_| quota("INDEX_ALLOCATION"))?;
    for reference in &definitions.method_references {
        let prototype = prototypes
            .get(reference.proto_idx as usize)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.index",
                    "validated method reference prototype missing",
                )
            })?;
        budget.charge(
            1,
            (reference.class_descriptor.len()
                + reference.method_name.len()
                + prototype.data.descriptor.len()) as u64
                + 16,
        )?;
        pairs.push((
            (
                reference.class_descriptor.as_str(),
                reference.method_name.as_str(),
                prototype.data.descriptor.as_str(),
            ),
            ReferenceAtom {
                view: view_id,
                local: reference.method_idx,
            },
        ));
    }
    Ok(())
}
/// Encoded field reference symbols (owner, name, type), borrowed until the
/// postings are laid out.
fn add_field_reference_symbols<'m>(
    pairs: &mut Vec<(FieldSymbolKey<'m>, ReferenceAtom)>,
    budget: &mut Budget,
    view_id: u32,
    facts: &'m crate::definitions::DefinitionFacts,
) -> MddResult<()> {
    let references = &facts.definitions().field_references;
    pairs
        .try_reserve(references.len())
        .map_err(|_| quota("INDEX_ALLOCATION"))?;
    for reference in references {
        let bytes = reference
            .class_descriptor
            .len()
            .checked_add(reference.field_name.len())
            .and_then(|v| v.checked_add(reference.type_descriptor.len()))
            .and_then(|v| v.checked_add(16))
            .and_then(|v| u64::try_from(v).ok())
            .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))?;
        budget.charge(1, bytes)?;
        pairs.push((
            (
                reference.class_descriptor.as_str(),
                reference.field_name.as_str(),
                reference.type_descriptor.as_str(),
            ),
            ReferenceAtom {
                view: view_id,
                local: reference.field_idx,
            },
        ));
    }
    Ok(())
}
/// Metadata type descriptors.
fn add_type_references<'m>(
    pairs: &mut Vec<(&'m str, Atom)>,
    budget: &mut Budget,
    view_id: u32,
    metadata: &'m crate::MetadataFacts,
) -> MddResult<()> {
    pairs
        .try_reserve(metadata.types().len())
        .map_err(|_| quota("INDEX_ALLOCATION"))?;
    for dex_type in metadata.types() {
        budget.charge(1, 16)?;
        pairs.push((
            dex_type.data.descriptor.as_str(),
            Atom {
                view: view_id,
                local: dex_type.data.type_idx,
            },
        ));
    }
    Ok(())
}
/// Metadata prototype descriptors.
fn add_prototype_references<'m>(
    pairs: &mut Vec<(&'m str, Atom)>,
    budget: &mut Budget,
    view_id: u32,
    metadata: &'m crate::MetadataFacts,
) -> MddResult<()> {
    pairs
        .try_reserve(metadata.prototypes().len())
        .map_err(|_| quota("INDEX_ALLOCATION"))?;
    for prototype in metadata.prototypes() {
        budget.charge(1, 16)?;
        pairs.push((
            prototype.data.descriptor.as_str(),
            Atom {
                view: view_id,
                local: prototype.data.proto_idx,
            },
        ));
    }
    Ok(())
}
/// Encoded reference sites grouped by their caller method.
fn add_caller_sites(
    pairs: &mut Vec<(Atom, u32)>,
    budget: &mut Budget,
    view_id: u32,
    facts: &ReferenceFacts,
) -> MddResult<()> {
    pairs
        .try_reserve(facts.sites().len())
        .map_err(|_| quota("INDEX_ALLOCATION"))?;
    for (ordinal, site) in facts.sites().iter().enumerate() {
        let ordinal = u32::try_from(ordinal).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
        if site.site_ordinal != ordinal {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "facts.index",
                "validated reference site ordinal is inconsistent",
            ));
        }
        budget.charge(1, 8)?;
        pairs.push((
            Atom {
                view: view_id,
                local: site.caller_method_idx,
            },
            ordinal,
        ));
    }
    Ok(())
}
/// Validated method-handle metadata symbols.
fn add_method_handles(
    index: &mut MethodHandleIndex,
    budget: &mut Budget,
    view_id: u32,
    facts: &ReferenceFacts,
) -> MddResult<()> {
    for handle in handle_metadata(facts)? {
        let target = handle_target(facts, handle)?;
        budget.charge(1, target.bytes()?)?;
        index.symbols.entry(target.owned()).or_default().push(Atom {
            view: view_id,
            local: handle.method_handle_idx,
        });
    }
    Ok(())
}
/// Cache key for a `require`-style coverage request: scope identity plus the
/// exact ordered layer set. Only requests without columns or resource members
/// reach this, so those two dimensions cannot collide.
fn coverage_cache_key(request: &CoverageRequest) -> String {
    let mut key = String::with_capacity(64 + request.required_layers.len() * 20);
    key.push_str(&request.scope_id);
    key.push('|');
    for layer in &request.required_layers {
        key.push_str(match layer {
            FactLayer::Metadata => "m",
            FactLayer::Definitions => "d",
            FactLayer::Structure => "s",
            FactLayer::CodeProjection => "c",
            FactLayer::AllPhysicalCode => "p",
            FactLayer::MethodBindings => "b",
            FactLayer::AllMethodBodies => "a",
            FactLayer::References => "r",
            FactLayer::Annotations => "n",
            FactLayer::PrototypeParameterPositions => "q",
            FactLayer::RawCode => "w",
            FactLayer::SourcePositions => "x",
            FactLayer::DerivedAnalysis => "y",
        });
        key.push(',');
    }
    key
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Utf16Predicate {
    Any,
    Equal(Vec<u16>),
    Prefix(Vec<u16>),
    Contains(Vec<u16>),
}
impl Utf16Predicate {
    pub fn matches(&self, value: &[u16]) -> bool {
        match self {
            Self::Any => true,
            Self::Equal(expected) => value == expected,
            Self::Prefix(prefix) => value.starts_with(prefix),
            Self::Contains(needle) => {
                needle.is_empty() || value.windows(needle.len()).any(|part| part == needle)
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionKind {
    Class,
    Field,
    Method,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Atom {
    view: u32,
    local: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct DefinitionAtom {
    view: u32,
    kind: DefinitionKind,
    local: u32,
}
#[derive(Clone, Copy, Debug)]
struct ReferenceAtom {
    view: u32,
    local: u32,
}
/// Code-unit postings in one flat, immutable table.
///
/// Every UTF-16 code unit is its own bucket, so the table is a fixed-size
/// offset array plus one flat atom array: no per-string temporary set and no
/// tree node per unit. `get` is an O(1) slice index.
struct UnitPostings {
    /// `offsets[u]..offsets[u + 1]` is the posting range for code unit `u`.
    offsets: Vec<u32>,
    atoms: Vec<Atom>,
}
impl UnitPostings {
    fn empty() -> Self {
        Self {
            offsets: vec![0; usize::from(u16::MAX) + 2],
            atoms: Vec::new(),
        }
    }
    fn get(&self, unit: u16) -> &[Atom] {
        let start = self.offsets[usize::from(unit)] as usize;
        let end = self.offsets[usize::from(unit) + 1] as usize;
        &self.atoms[start..end]
    }
    /// Build the flat table from `(code unit, atom)` pairs in one counting
    /// pass: no comparison sort and no per-string temporary allocation.
    fn from_pairs(pairs: Vec<(u16, Atom)>, budget: &mut Budget) -> MddResult<Self> {
        let mut counts = vec![0u32; usize::from(u16::MAX) + 1];
        for (unit, _) in &pairs {
            let slot = &mut counts[usize::from(*unit)];
            *slot = slot
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
        }
        let mut offsets = vec![0u32; usize::from(u16::MAX) + 2];
        let mut running = 0u32;
        for (index, count) in counts.iter().enumerate() {
            offsets[index] = running;
            running = running
                .checked_add(*count)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
        }
        offsets[usize::from(u16::MAX) + 1] = running;
        budget.charge(0, offsets.len() as u64 * 4 + pairs.len() as u64 * 8)?;
        let mut cursor = offsets.clone();
        let mut atoms = vec![Atom { view: 0, local: 0 }; pairs.len()];
        for (unit, atom) in pairs {
            let slot = &mut cursor[usize::from(unit)];
            atoms[*slot as usize] = atom;
            *slot += 1;
        }
        Ok(Self { offsets, atoms })
    }
}
/// Distinct keys with their postings, stored as one sorted key array plus one
/// flat posting array.
///
/// A `BTreeMap<Vec<u16>, Vec<Atom>>` clones the key for every occurrence and
/// pays a tree node per insert. Here the traversal only records atoms; `finish`
/// sorts them by the referenced text and clones each *distinct* key exactly
/// once. `get` is a binary search, and prefix scans are a partition point.
struct Utf16Postings {
    keys: Vec<Vec<u16>>,
    /// `offsets[i]..offsets[i + 1]` is the posting range for `keys[i]`.
    offsets: Vec<u32>,
    atoms: Vec<Atom>,
}
impl Utf16Postings {
    fn empty() -> Self {
        Self {
            keys: Vec::new(),
            offsets: Vec::new(),
            atoms: Vec::new(),
        }
    }
    fn get(&self, key: &[u16]) -> &[Atom] {
        match self
            .keys
            .binary_search_by(|probe| probe.as_slice().cmp(key))
        {
            Ok(index) => {
                &self.atoms[self.offsets[index] as usize..self.offsets[index + 1] as usize]
            }
            Err(_) => &[],
        }
    }
    /// All postings whose key starts with `prefix`, in key order.
    fn prefix(&self, prefix: &[u16]) -> impl Iterator<Item = &[Atom]> {
        let start = self.keys.partition_point(|key| key.as_slice() < prefix);
        self.keys[start..]
            .iter()
            .take_while(move |key| key.starts_with(prefix))
            .enumerate()
            .map(move |(offset, _)| {
                let index = start + offset;
                &self.atoms[self.offsets[index] as usize..self.offsets[index + 1] as usize]
            })
    }
}
struct RawPostings {
    keys: Vec<Vec<u8>>,
    offsets: Vec<u32>,
    atoms: Vec<Atom>,
}
impl RawPostings {
    fn empty() -> Self {
        Self {
            keys: Vec::new(),
            offsets: Vec::new(),
            atoms: Vec::new(),
        }
    }
    fn get(&self, key: &[u8]) -> &[Atom] {
        match self
            .keys
            .binary_search_by(|probe| probe.as_slice().cmp(key))
        {
            Ok(index) => {
                &self.atoms[self.offsets[index] as usize..self.offsets[index + 1] as usize]
            }
            Err(_) => &[],
        }
    }
}
struct StringIndex {
    all: Vec<Atom>,
    utf16: Utf16Postings,
    raw: RawPostings,
    units: UnitPostings,
    /// `(code unit, atom)` pairs accumulated during the traversal; the flat
    /// `units` table is built from them once, at `finish`.
    pending_units: Vec<(u16, Atom)>,
}
impl StringIndex {
    fn empty() -> Self {
        Self {
            all: Vec::new(),
            utf16: Utf16Postings::empty(),
            raw: RawPostings::empty(),
            units: UnitPostings::empty(),
            pending_units: Vec::new(),
        }
    }
    fn finish(&mut self, views: &[FactView<'_>], budget: &mut Budget) -> MddResult<()> {
        self.units = UnitPostings::from_pairs(std::mem::take(&mut self.pending_units), budget)?;
        // Sort atom handles by the text they point at, then clone one key per
        // distinct value. `sort_by` is stable, so postings keep traversal order.
        let mut by_utf16 = self
            .all
            .iter()
            .map(|atom| {
                Ok((
                    string_text(views, *atom)?.data.text.utf16_units.as_slice(),
                    *atom,
                ))
            })
            .collect::<MddResult<Vec<_>>>()?;
        by_utf16.sort_by(|left, right| left.0.cmp(right.0));
        let mut utf16 = Utf16Postings::empty();
        let mut start = 0usize;
        while start < by_utf16.len() {
            let mut end = start + 1;
            while end < by_utf16.len() && by_utf16[end].0 == by_utf16[start].0 {
                end += 1;
            }
            let key = by_utf16[start].0;
            budget.charge(0, key.len() as u64 * 2 + 64)?;
            utf16.keys.push(key.to_vec());
            utf16.offsets.push(utf16.atoms.len() as u32);
            utf16
                .atoms
                .extend(by_utf16[start..end].iter().map(|(_, atom)| *atom));
            start = end;
        }
        utf16.offsets.push(utf16.atoms.len() as u32);
        self.utf16 = utf16;

        let mut by_raw = self
            .all
            .iter()
            .map(|atom| {
                Ok((
                    string_text(views, *atom)?.data.text.raw_mutf8.as_slice(),
                    *atom,
                ))
            })
            .collect::<MddResult<Vec<_>>>()?;
        by_raw.sort_by(|left, right| left.0.cmp(right.0));
        let mut raw = RawPostings::empty();
        let mut start = 0usize;
        while start < by_raw.len() {
            let mut end = start + 1;
            while end < by_raw.len() && by_raw[end].0 == by_raw[start].0 {
                end += 1;
            }
            let key = by_raw[start].0;
            budget.charge(0, key.len() as u64 + 64)?;
            raw.keys.push(key.to_vec());
            raw.offsets.push(raw.atoms.len() as u32);
            raw.atoms
                .extend(by_raw[start..end].iter().map(|(_, atom)| *atom));
            start = end;
        }
        raw.offsets.push(raw.atoms.len() as u32);
        self.raw = raw;
        Ok(())
    }
}
/// Resolve one string atom to its validated text.
fn string_text<'v>(
    views: &'v [FactView<'_>],
    atom: Atom,
) -> MddResult<&'v crate::metadata::StringFact> {
    views
        .get(atom.view as usize)
        .and_then(|view| view.metadata)
        .and_then(|metadata| metadata.strings().get(atom.local as usize))
        .ok_or_else(|| missing_facts("metadata missing"))
}
/// Definition name postings keyed by `(kind, UTF-16 name)`, stored sorted with
/// one cloned key per distinct name rather than one clone per definition.
struct DefinitionNamePostings {
    /// Sorted by `(kind, name)`.
    keys: Vec<(DefinitionKind, Vec<u16>)>,
    /// `offsets[i]..offsets[i + 1]` is the posting range for `keys[i]`.
    offsets: Vec<u32>,
    atoms: Vec<DefinitionAtom>,
}
impl DefinitionNamePostings {
    fn empty() -> Self {
        Self {
            keys: Vec::new(),
            offsets: Vec::new(),
            atoms: Vec::new(),
        }
    }
    fn get(&self, kind: DefinitionKind, name: &[u16]) -> &[DefinitionAtom] {
        match self.keys.binary_search_by(|(probe_kind, probe_name)| {
            probe_kind
                .cmp(&kind)
                .then_with(|| probe_name.as_slice().cmp(name))
        }) {
            Ok(index) => {
                &self.atoms[self.offsets[index] as usize..self.offsets[index + 1] as usize]
            }
            Err(_) => &[],
        }
    }
    /// Postings for `kind` whose name starts with `prefix`, in name order.
    fn prefix(
        &self,
        kind: DefinitionKind,
        prefix: &[u16],
    ) -> impl Iterator<Item = &[DefinitionAtom]> {
        let start = self.keys.partition_point(|(probe_kind, probe_name)| {
            (*probe_kind, probe_name.as_slice()) < (kind, prefix)
        });
        self.keys[start..]
            .iter()
            .take_while(move |(probe_kind, probe_name)| {
                *probe_kind == kind && probe_name.starts_with(prefix)
            })
            .enumerate()
            .map(move |(offset, _)| {
                let index = start + offset;
                &self.atoms[self.offsets[index] as usize..self.offsets[index + 1] as usize]
            })
    }
}
struct DefinitionIndex {
    names: DefinitionNamePostings,
    owners: BTreeMap<(u32, u32, DefinitionKind), Vec<DefinitionAtom>>,
    all: Vec<DefinitionAtom>,
    /// Atoms collected during the traversal. Names are resolved from the fact
    /// views in `finish`, so no UTF-16 key is allocated until a distinct name
    /// is emitted.
    pending_names: Vec<DefinitionAtom>,
}
/// Ordering used for definition-name postings.
///
/// This must be the **UTF-16 code-unit** order, because the postings are
/// searched with `[u16]` comparisons. `&str` comparison is UTF-8 byte order,
/// which disagrees once supplementary-plane characters are involved: UTF-16
/// spells them as surrogates `D800-DFFF`, which sort *after* `E000-FFFF` in
/// code-unit order but compare differently as UTF-8 bytes.
fn cmp_definition_name(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

impl DefinitionIndex {
    fn empty() -> Self {
        Self {
            names: DefinitionNamePostings::empty(),
            owners: BTreeMap::new(),
            all: Vec::new(),
            pending_names: Vec::new(),
        }
    }
    fn finish(&mut self, views: &[FactView<'_>], budget: &mut Budget) -> MddResult<()> {
        let mut pending = std::mem::take(&mut self.pending_names);
        // Sort by (kind, name, atom); the comparator borrows the validated name
        // straight out of the fact views, so sorting allocates nothing.
        let mut keyed = pending
            .iter()
            .map(|atom| Ok((*atom, definition_name_str(views, *atom)?)))
            .collect::<MddResult<Vec<_>>>()?;
        keyed.sort_by(|left, right| {
            left.0
                .kind
                .cmp(&right.0.kind)
                // The key array is searched with UTF-16 code-unit ordering, so
                // the sort must use that same order. `&str` comparison is UTF-8
                // byte order, which differs once supplementary-plane
                // characters are involved (UTF-16 uses surrogates D800-DFFF,
                // which sort *after* E000-FFFF in code-unit order but compare
                // differently as UTF-8 bytes). Sorting one way and searching
                // the other made valid names containing supplementary
                // characters unfindable and produced a false "absence proven".
                .then_with(|| cmp_definition_name(left.1, right.1))
                .then_with(|| left.0.cmp(&right.0))
        });
        let mut names = DefinitionNamePostings::empty();
        let mut start = 0usize;
        while start < keyed.len() {
            let mut end = start + 1;
            while end < keyed.len()
                && keyed[end].0.kind == keyed[start].0.kind
                && keyed[end].1 == keyed[start].1
            {
                end += 1;
            }
            // Encode UTF-16 exactly once, for the distinct name only.
            let name = keyed[start].1.encode_utf16().collect::<Vec<_>>();
            budget.charge(0, name.len() as u64 * 2 + 24)?;
            names.keys.push((keyed[start].0.kind, name));
            names.offsets.push(names.atoms.len() as u32);
            names
                .atoms
                .extend(keyed[start..end].iter().map(|(atom, _)| *atom));
            start = end;
        }
        names.offsets.push(names.atoms.len() as u32);
        self.names = names;
        pending.clear();
        Ok(())
    }
}
/// Resolve a definition atom to its validated name text.
fn definition_name_str<'v>(views: &'v [FactView<'_>], atom: DefinitionAtom) -> MddResult<&'v str> {
    let facts = views
        .get(atom.view as usize)
        .and_then(|view| view.definitions)
        .ok_or_else(|| missing_facts("definitions missing"))?;
    let definitions = facts.definitions();
    let name = match atom.kind {
        DefinitionKind::Class => {
            &definitions
                .classes
                .get(atom.local as usize)
                .ok_or_else(|| missing_facts("class definition missing"))?
                .descriptor
        }
        DefinitionKind::Field => {
            &definitions
                .field_references
                .get(atom.local as usize)
                .ok_or_else(|| missing_facts("field definition missing"))?
                .field_name
        }
        DefinitionKind::Method => {
            &definitions
                .method_references
                .get(atom.local as usize)
                .ok_or_else(|| missing_facts("method definition missing"))?
                .method_name
        }
    };
    Ok(name.as_str())
}
/// Encoded method symbols with postings. Sorting borrowed `(owner, name,
/// prototype)` triples first means each distinct symbol is cloned exactly once
/// instead of once per reference occurrence.
struct ReferenceSymbolIndex {
    /// Sorted by `(owner, name, prototype)`.
    keys: Vec<MethodSymbol>,
    offsets: Vec<u32>,
    atoms: Vec<ReferenceAtom>,
}
impl ReferenceSymbolIndex {
    fn get(&self, symbol: &MethodSymbol) -> &[ReferenceAtom] {
        match self.keys.binary_search(symbol) {
            Ok(index) => {
                &self.atoms[self.offsets[index] as usize..self.offsets[index + 1] as usize]
            }
            Err(_) => &[],
        }
    }
    fn from_pairs(
        mut pairs: Vec<(MethodSymbolKey<'_>, ReferenceAtom)>,
        budget: &mut Budget,
    ) -> MddResult<Self> {
        pairs.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut keys = Vec::new();
        let mut offsets = Vec::new();
        let mut atoms = Vec::with_capacity(pairs.len());
        let mut start = 0usize;
        while start < pairs.len() {
            let mut end = start + 1;
            while end < pairs.len() && pairs[end].0 == pairs[start].0 {
                end += 1;
            }
            let (owner, name, prototype) = pairs[start].0;
            budget.charge(0, (owner.len() + name.len() + prototype.len()) as u64 + 16)?;
            keys.push(MethodSymbol {
                owner: owner.to_owned(),
                name: name.to_owned(),
                prototype: prototype.to_owned(),
            });
            offsets.push(atoms.len() as u32);
            atoms.extend(pairs[start..end].iter().map(|(_, atom)| *atom));
            start = end;
        }
        offsets.push(atoms.len() as u32);
        Ok(Self {
            keys,
            offsets,
            atoms,
        })
    }
}
/// Borrowed method symbol, used only to sort and group before cloning keys.
type MethodSymbolKey<'m> = (&'m str, &'m str, &'m str);
/// Encoded field symbols with postings; same grouping strategy as methods.
struct FieldReferenceSymbolIndex {
    /// Sorted by `(owner, name, field_type)`.
    keys: Vec<FieldSymbol>,
    offsets: Vec<u32>,
    atoms: Vec<ReferenceAtom>,
}
impl FieldReferenceSymbolIndex {
    fn get(&self, symbol: &FieldSymbol) -> &[ReferenceAtom] {
        match self.keys.binary_search(symbol) {
            Ok(index) => {
                &self.atoms[self.offsets[index] as usize..self.offsets[index + 1] as usize]
            }
            Err(_) => &[],
        }
    }
    fn from_pairs(
        mut pairs: Vec<(FieldSymbolKey<'_>, ReferenceAtom)>,
        budget: &mut Budget,
    ) -> MddResult<Self> {
        pairs.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut keys = Vec::new();
        let mut offsets = Vec::new();
        let mut atoms = Vec::with_capacity(pairs.len());
        let mut start = 0usize;
        while start < pairs.len() {
            let mut end = start + 1;
            while end < pairs.len() && pairs[end].0 == pairs[start].0 {
                end += 1;
            }
            let (owner, name, field_type) = pairs[start].0;
            budget.charge(0, (owner.len() + name.len() + field_type.len()) as u64 + 16)?;
            keys.push(FieldSymbol {
                owner: owner.to_owned(),
                name: name.to_owned(),
                field_type: field_type.to_owned(),
            });
            offsets.push(atoms.len() as u32);
            atoms.extend(pairs[start..end].iter().map(|(_, atom)| *atom));
            start = end;
        }
        offsets.push(atoms.len() as u32);
        Ok(Self {
            keys,
            offsets,
            atoms,
        })
    }
}
/// Borrowed field symbol, used only to sort and group before cloning keys.
type FieldSymbolKey<'m> = (&'m str, &'m str, &'m str);
/// Descriptor string postings, stored sorted with one cloned key per distinct
/// descriptor. Cloning per occurrence costs one `String` allocation per type or
/// prototype in every selected DEX.
struct DescriptorPostings {
    keys: Vec<String>,
    offsets: Vec<u32>,
    atoms: Vec<Atom>,
}
impl DescriptorPostings {
    fn get(&self, descriptor: &str) -> &[Atom] {
        match self
            .keys
            .binary_search_by(|probe| probe.as_str().cmp(descriptor))
        {
            Ok(index) => {
                &self.atoms[self.offsets[index] as usize..self.offsets[index + 1] as usize]
            }
            Err(_) => &[],
        }
    }
    /// Group `(descriptor, atom)` pairs; `pairs` is sorted in place first.
    fn from_pairs(mut pairs: Vec<(&str, Atom)>, budget: &mut Budget) -> MddResult<Self> {
        pairs.sort_unstable_by(|left, right| left.0.cmp(right.0));
        let mut keys = Vec::new();
        let mut offsets = Vec::new();
        let mut atoms = Vec::with_capacity(pairs.len());
        let mut start = 0usize;
        while start < pairs.len() {
            let mut end = start + 1;
            while end < pairs.len() && pairs[end].0 == pairs[start].0 {
                end += 1;
            }
            let key = pairs[start].0;
            budget.charge(0, key.len() as u64 + 64)?;
            keys.push(key.to_owned());
            offsets.push(atoms.len() as u32);
            atoms.extend(pairs[start..end].iter().map(|(_, atom)| *atom));
            start = end;
        }
        offsets.push(atoms.len() as u32);
        Ok(Self {
            keys,
            offsets,
            atoms,
        })
    }
}
struct TypeReferenceIndex {
    descriptors: DescriptorPostings,
}
impl TypeReferenceIndex {}
struct PrototypeReferenceIndex {
    descriptors: DescriptorPostings,
}
impl PrototypeReferenceIndex {}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(tag = "target_kind", rename_all = "snake_case")]
pub enum MethodHandleSymbol {
    Field {
        handle_kind: u16,
        target: FieldSymbol,
    },
    Method {
        handle_kind: u16,
        target: MethodSymbol,
    },
}
/// Exact bytes of one validated call-site array, bound to its complete DEX content.
/// This key deliberately does not assert semantic equality between different DEX files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CallSiteEncodedKey {
    snapshot_id: String,
    dex_content_id: String,
    encoded_array: Vec<u8>,
}
impl CallSiteEncodedKey {
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
    pub fn dex_content_id(&self) -> &str {
        &self.dex_content_id
    }
    pub fn encoded_array(&self) -> &[u8] {
        &self.encoded_array
    }
}
struct MethodHandleIndex {
    symbols: BTreeMap<MethodHandleSymbol, Vec<Atom>>,
}
impl MethodHandleIndex {
    fn empty() -> Self {
        Self {
            symbols: BTreeMap::new(),
        }
    }
}
/// Caller-method atoms with their site ordinals, stored as one sorted key
/// array plus one flat ordinal array. There is one entry per encoded site, so
/// a tree node and a key clone per site is the dominant build cost otherwise.
struct CallerSiteIndex {
    /// Sorted `(view, caller method local index)`.
    keys: Vec<Atom>,
    /// `offsets[i]..offsets[i + 1]` is the ordinal range for `keys[i]`.
    offsets: Vec<u32>,
    ordinals: Vec<u32>,
}
impl CallerSiteIndex {
    fn get(&self, key: Atom) -> &[u32] {
        match self.keys.binary_search(&key) {
            Ok(index) => {
                &self.ordinals[self.offsets[index] as usize..self.offsets[index + 1] as usize]
            }
            Err(_) => &[],
        }
    }
    /// Group `(key, ordinal)` pairs; `pairs` is consumed and sorted in place.
    fn from_pairs(mut pairs: Vec<(Atom, u32)>, budget: &mut Budget) -> MddResult<Self> {
        pairs.sort_unstable();
        budget.charge(0, pairs.len() as u64 * 8)?;
        let mut keys = Vec::new();
        let mut offsets = Vec::new();
        let mut ordinals = Vec::with_capacity(pairs.len());
        let mut start = 0usize;
        while start < pairs.len() {
            let mut end = start + 1;
            while end < pairs.len() && pairs[end].0 == pairs[start].0 {
                end += 1;
            }
            keys.push(pairs[start].0);
            offsets.push(ordinals.len() as u32);
            ordinals.extend(pairs[start..end].iter().map(|(_, ordinal)| *ordinal));
            start = end;
        }
        offsets.push(ordinals.len() as u32);
        Ok(Self {
            keys,
            offsets,
            ordinals,
        })
    }
}
#[derive(Clone, Copy, Debug)]
struct AnnotationOwnerAtom {
    view: u32,
    owner: u32,
    item: u32,
    set: u32,
    ordinal: u32,
}
struct AnnotationTypeIndex {
    owners: BTreeMap<Vec<u16>, Vec<AnnotationOwnerAtom>>,
}
impl AnnotationTypeIndex {
    fn empty() -> Self {
        Self {
            owners: BTreeMap::new(),
        }
    }
}
/// An encoded owner-to-annotation occurrence, not an inferred runtime annotation.
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationOwnerMatch {
    pub dex_occurrence_id: String,
    pub annotation_byte_offset: u32,
    pub annotation_set_byte_offset: u32,
    pub set_ordinal: u32,
    pub owner: AnnotationOwnerBinding,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationOwnerMatches {
    pub snapshot_id: String,
    pub scope_id: String,
    pub index_attempt: Option<IndexAudit>,
    pub access_path: &'static str,
    pub candidate_count: u64,
    pub matches: Vec<AnnotationOwnerMatch>,
    /// No matching encoded owner association was found in the selected scope.
    /// This does not assert complete prototype parameter positions or runtime annotations.
    pub absence_proven_within_selected_scope: bool,
    pub covers_all_captured_sources: bool,
    pub coverage: CoverageReport,
}
fn annotation_inconsistent() -> MddError {
    MddError::new(
        ErrorCode::InternalFault,
        "facts.annotation_index",
        "validated annotation owner facts are inconsistent",
    )
}
enum HandleTargetRef<'a> {
    Field {
        kind: u16,
        owner: &'a str,
        name: &'a str,
        field_type: &'a str,
    },
    Method {
        kind: u16,
        owner: &'a str,
        name: &'a str,
        prototype: &'a str,
    },
}
impl HandleTargetRef<'_> {
    fn bytes(&self) -> MddResult<u64> {
        let (owner, name, signature) = match self {
            Self::Field {
                owner,
                name,
                field_type,
                ..
            } => (*owner, *name, *field_type),
            Self::Method {
                owner,
                name,
                prototype,
                ..
            } => (*owner, *name, *prototype),
        };
        owner
            .len()
            .checked_add(name.len())
            .and_then(|n| n.checked_add(signature.len()))
            .and_then(|n| n.checked_add(80))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))
    }
    fn owned(&self) -> MethodHandleSymbol {
        match self {
            Self::Field {
                kind,
                owner,
                name,
                field_type,
            } => MethodHandleSymbol::Field {
                handle_kind: *kind,
                target: FieldSymbol {
                    owner: (*owner).into(),
                    name: (*name).into(),
                    field_type: (*field_type).into(),
                },
            },
            Self::Method {
                kind,
                owner,
                name,
                prototype,
            } => MethodHandleSymbol::Method {
                handle_kind: *kind,
                target: MethodSymbol {
                    owner: (*owner).into(),
                    name: (*name).into(),
                    prototype: (*prototype).into(),
                },
            },
        }
    }
    fn matches(&self, other: &MethodHandleSymbol) -> bool {
        match (self, other) {
            (
                Self::Field {
                    kind,
                    owner,
                    name,
                    field_type,
                },
                MethodHandleSymbol::Field {
                    handle_kind,
                    target,
                },
            ) => {
                kind == handle_kind
                    && *owner == target.owner
                    && *name == target.name
                    && *field_type == target.field_type
            }
            (
                Self::Method {
                    kind,
                    owner,
                    name,
                    prototype,
                },
                MethodHandleSymbol::Method {
                    handle_kind,
                    target,
                },
            ) => {
                kind == handle_kind
                    && *owner == target.owner
                    && *name == target.name
                    && *prototype == target.prototype
            }
            _ => false,
        }
    }
}
fn handle_target<'a>(
    facts: &'a ReferenceFacts,
    handle: &MethodHandleTarget,
) -> MddResult<HandleTargetRef<'a>> {
    let definitions = facts.definitions().definitions();
    let malformed = || {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.index",
            "validated method handle target missing or inconsistent",
        )
    };
    match handle.target_kind {
        EncodedKind::Field if handle.handle_kind <= 3 => {
            let field = definitions
                .field_references
                .get(handle.target_index as usize)
                .ok_or_else(malformed)?;
            Ok(HandleTargetRef::Field {
                kind: handle.handle_kind,
                owner: &field.class_descriptor,
                name: &field.field_name,
                field_type: &field.type_descriptor,
            })
        }
        EncodedKind::Method if (4..=8).contains(&handle.handle_kind) => {
            let method = definitions
                .method_references
                .get(handle.target_index as usize)
                .ok_or_else(malformed)?;
            let proto = facts
                .definitions()
                .metadata()
                .prototypes()
                .get(method.proto_idx as usize)
                .ok_or_else(malformed)?;
            Ok(HandleTargetRef::Method {
                kind: handle.handle_kind,
                owner: &method.class_descriptor,
                name: &method.method_name,
                prototype: &proto.data.descriptor,
            })
        }
        _ => Err(malformed()),
    }
}
fn handle_metadata(facts: &ReferenceFacts) -> MddResult<&[MethodHandleTarget]> {
    if let Some(handles) = facts.method_handle_metadata() {
        return Ok(handles);
    }
    if facts
        .sites()
        .iter()
        .any(|site| site.target_kind == TargetKind::MethodHandle)
    {
        return Err(MddError::new(
            ErrorCode::IncompleteFacts,
            "facts.index",
            "method handle operands lack metadata",
        ));
    }
    Ok(&[])
}
fn call_site_array_bytes(facts: &ReferenceFacts, local: u32) -> MddResult<&[u8]> {
    let missing = || {
        MddError::new(
            ErrorCode::IncompleteFacts,
            "facts.index",
            "call-site encoded arrays are not built",
        )
    };
    let broken = || {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.index",
            "validated call-site encoded array is inconsistent",
        )
    };
    let section = facts.call_site_metadata().ok_or_else(missing)?;
    let binding = section
        .call_site_arrays
        .get(local as usize)
        .filter(|v| v.call_site_idx == local)
        .ok_or_else(broken)?;
    let array = section
        .arrays
        .get(binding.encoded_array_index as usize)
        .ok_or_else(broken)?;
    if array.byte_offset != binding.encoded_array_byte_offset
        || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
        || array.elements.len() < 3
    {
        return Err(broken());
    }
    let start = usize::try_from(array.encoded_range.byte_offset.0).map_err(|_| broken())?;
    let length = usize::try_from(array.encoded_range.byte_length.0).map_err(|_| broken())?;
    let end = start.checked_add(length).ok_or_else(broken)?;
    facts
        .definitions()
        .bytes()
        .get(start..end)
        .ok_or_else(broken)
}
#[derive(Clone, Copy)]
enum ReferenceResultKind {
    Method,
    Field,
    String,
    RawString,
    Type,
    Prototype,
    MethodHandle,
    CallSiteBytes,
    Caller,
}
#[derive(Clone, Copy)]
enum StringReferencePredicate<'a> {
    Utf16(&'a [u16]),
    RawMutf8(&'a [u8]),
}
#[derive(Clone, Debug, Serialize)]
pub struct IndexMatches {
    pub scope_id: String,
    pub snapshot_id: String,
    pub index_attempt: Option<IndexAudit>,
    pub access_path: String,
    pub candidate_count: u64,
    pub exact_match_count: u64,
    pub entities: Vec<EntityRef>,
    pub absence_proven_within_selected_scope: bool,
    pub covers_all_captured_sources: bool,
    pub coverage: CoverageReport,
}
#[derive(Clone, Debug, Serialize)]
pub struct ReferenceIndexMatches {
    pub snapshot_id: String,
    pub scope_id: String,
    pub index_attempt: Option<IndexAudit>,
    pub access_path: String,
    pub candidate_reference_count: u64,
    pub sites: Vec<crate::references::ReferenceSiteId>,
    pub absence_proven_within_selected_encoded_scope: bool,
    pub covers_all_captured_sources: bool,
    pub runtime_resolution: &'static str,
    pub coverage: CoverageReport,
}
pub struct SnapshotFactIndex<'a> {
    scope: SelectedScope,
    views: Vec<FactView<'a>>,
    by_occurrence: BTreeMap<String, u32>,
    ledger: CoverageLedger<'a>,
    /// Number of times `CoverageLedger::evaluate` actually ran for this instance.
    /// The ledger is immutable once built, so repeat requests are answered from
    /// `coverage_cache`; this counter makes that observable.
    ledger_evaluations: std::sync::atomic::AtomicU64,
    /// Number of full `self.views` traversals performed by index construction.
    /// One pass per index before batching; one pass for the whole batch after.
    index_traversals: std::sync::atomic::AtomicU64,
    coverage_cache: std::sync::Mutex<BTreeMap<String, CoverageReport>>,
    limits: IndexLimits,
    strings: LazyIndex<StringIndex>,
    definitions: LazyIndex<DefinitionIndex>,
    reference_symbols: LazyIndex<ReferenceSymbolIndex>,
    field_reference_symbols: LazyIndex<FieldReferenceSymbolIndex>,
    type_references: LazyIndex<TypeReferenceIndex>,
    prototype_references: LazyIndex<PrototypeReferenceIndex>,
    method_handles: LazyIndex<MethodHandleIndex>,
    caller_sites: LazyIndex<CallerSiteIndex>,
    annotation_types: LazyIndex<AnnotationTypeIndex>,
}

impl<'a> SnapshotFactIndex<'a> {
    pub fn new(
        scope: SelectedScope,
        views: &[FactView<'a>],
        limits: IndexLimits,
    ) -> MddResult<Self> {
        let ledger = CoverageLedger::new(scope.clone(), views)?;
        let mut ordered = Vec::new();
        let mut by_occurrence = BTreeMap::new();
        for dex in scope.dexes() {
            if let Some(view) = views
                .iter()
                .find(|view| view.occurrence() == dex.dex_occurrence_id)
            {
                view.validate(&scope)?;
                by_occurrence.insert(dex.dex_occurrence_id.clone(), ordered.len() as u32);
                ordered.push(view.clone());
            }
        }
        Ok(Self {
            strings: LazyIndex::new(
                scope.scope_id(),
                "strings-utf16-raw-candidates-v1",
                limits.max_build_attempts,
            )?,
            definitions: LazyIndex::new(
                scope.scope_id(),
                "definitions-owner-candidates-v1",
                limits.max_build_attempts,
            )?,
            reference_symbols: LazyIndex::new(
                scope.scope_id(),
                "encoded-reference-symbol-candidates-v1",
                limits.max_build_attempts,
            )?,
            field_reference_symbols: LazyIndex::new(
                scope.scope_id(),
                "encoded-field-reference-symbol-candidates-v1",
                limits.max_build_attempts,
            )?,
            type_references: LazyIndex::new(
                scope.scope_id(),
                "encoded-type-reference-descriptor-candidates-v1",
                limits.max_build_attempts,
            )?,
            prototype_references: LazyIndex::new(
                scope.scope_id(),
                "encoded-prototype-reference-descriptor-candidates-v1",
                limits.max_build_attempts,
            )?,
            method_handles: LazyIndex::new(
                scope.scope_id(),
                "encoded-method-handle-symbol-candidates-v1",
                limits.max_build_attempts,
            )?,
            caller_sites: LazyIndex::new(
                scope.scope_id(),
                "encoded-caller-site-candidates-v1",
                limits.max_build_attempts,
            )?,
            annotation_types: LazyIndex::new(
                scope.scope_id(),
                "annotation-type-owner-candidates-v1",
                limits.max_build_attempts,
            )?,
            scope,
            views: ordered,
            by_occurrence,
            ledger,
            ledger_evaluations: std::sync::atomic::AtomicU64::new(0),
            index_traversals: std::sync::atomic::AtomicU64::new(0),
            coverage_cache: std::sync::Mutex::new(BTreeMap::new()),
            limits,
        })
    }
    pub fn scope(&self) -> &SelectedScope {
        &self.scope
    }
    /// Development instrument: how many `CoverageLedger::evaluate` calls ran.
    /// This is a monotonic counter, not part of any serialized contract.
    pub fn coverage_evaluations(&self) -> u64 {
        self.ledger_evaluations
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Development instrument: how many full `views` passes index building did.
    /// This is a monotonic counter, not part of any serialized contract.
    pub fn index_traversals(&self) -> u64 {
        self.index_traversals
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    fn note_traversal(&self) {
        self.index_traversals
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn coverage(&self, request: &CoverageRequest) -> MddResult<CoverageReport> {
        // The ledger is immutable once `new` returns, so an identical request
        // always yields an identical report. Only the `require`-style requests
        // (scope + layer set, no columns or resource members) are cached: those
        // are the ones every build and every query entry point repeats.
        let cacheable = request.required_columns.is_empty()
            && request.required_resource_members.is_empty()
            && request.input == InputNeed::ValidatedStandardDex
            && request.scope_id == self.scope.scope_id();
        let key = cacheable.then(|| coverage_cache_key(request));
        if let Some(key) = &key
            && let Ok(cache) = self.coverage_cache.lock()
            && let Some(report) = cache.get(key)
        {
            return Ok(report.clone());
        }
        self.ledger_evaluations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let report = self.ledger.evaluate(request)?;
        if let Some(key) = key
            && let Ok(mut cache) = self.coverage_cache.lock()
        {
            cache.insert(key, report.clone());
        }
        Ok(report)
    }
    /// Relation-scoped coverage for this bound scope: every frozen column of
    /// `relations` must be provable, including the fact layers that own them.
    ///
    /// This is the production path that actually fills
    /// `required_columns` — [`CoverageRequest::for_scope`] deliberately leaves
    /// it empty, so a layer-only requirement never silently claims column
    /// projectability. The report is returned, not enforced: callers decide
    /// whether `Unknown` blocks them, and `require_complete` carries the
    /// provider's own error when it does.
    pub fn coverage_for_relations(&self, relations: &[&str]) -> MddResult<CoverageReport> {
        let request = CoverageRequest::for_relations(&self.scope, relations)?;
        self.coverage(&request)
    }
    pub fn audits(&self) -> MddResult<Vec<IndexAudit>> {
        Ok(vec![
            self.strings.audit()?,
            self.definitions.audit()?,
            self.reference_symbols.audit()?,
            self.field_reference_symbols.audit()?,
            self.type_references.audit()?,
            self.prototype_references.audit()?,
            self.method_handles.audit()?,
            self.caller_sites.audit()?,
            self.annotation_types.audit()?,
        ])
    }
    fn require(&self, layer: FactLayer) -> MddResult<CoverageReport> {
        let report = self.coverage(&CoverageRequest::for_scope(&self.scope, &[layer]))?;
        report.require_complete()?;
        Ok(report)
    }
    fn metadata(&self, view: u32) -> MddResult<&crate::MetadataFacts> {
        self.views
            .get(view as usize)
            .and_then(|view| view.metadata)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "metadata not built",
                )
            })
    }
    fn definition_facts(&self, view: u32) -> MddResult<&crate::definitions::DefinitionFacts> {
        self.views
            .get(view as usize)
            .and_then(|view| view.definitions)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "definitions not built",
                )
            })
    }
    fn string_entity(&self, atom: Atom) -> MddResult<EntityRef> {
        self.metadata(atom.view)?
            .entity(EntityKind::String, atom.local)
    }
    fn definition_entity(&self, atom: DefinitionAtom) -> MddResult<EntityRef> {
        self.definition_facts(atom.view)?.entity(
            match atom.kind {
                DefinitionKind::Class => EntityKind::ClassDefinition,
                DefinitionKind::Field => EntityKind::FieldDefinition,
                DefinitionKind::Method => EntityKind::MethodDefinition,
            },
            atom.local,
        )
    }
    fn result(
        &self,
        mut entities: Vec<EntityRef>,
        candidates: usize,
        path: &str,
        audit: Option<IndexAudit>,
        coverage: CoverageReport,
    ) -> MddResult<IndexMatches> {
        let bytes = entities
            .iter()
            .try_fold(0u64, |sum, entity| {
                sum.checked_add(
                    (entity.snapshot_id.len()
                        + entity.dex_occurrence_id.len()
                        + std::mem::size_of::<EntityRef>()) as u64,
                )
            })
            .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
        if entities.len() as u64 > self.limits.max_result_entries
            || bytes > self.limits.max_result_bytes
        {
            return Err(quota("INDEX_RESULT_BUDGET"));
        }
        entities.sort_by_key(|entity| {
            (
                self.by_occurrence[&entity.dex_occurrence_id],
                entity.local_index,
            )
        });
        Ok(IndexMatches {
            scope_id: self.scope.scope_id().into(),
            snapshot_id: self.scope.snapshot_id().into(),
            index_attempt: audit,
            access_path: path.into(),
            candidate_count: candidates as u64,
            exact_match_count: entities.len() as u64,
            absence_proven_within_selected_scope: entities.is_empty()
                && coverage.input == mdd_types::Completeness::Complete
                && coverage.facts == mdd_types::Completeness::Complete,
            covers_all_captured_sources: self.scope.covers_all_captured_sources(),
            entities,
            coverage,
        })
    }
    fn check_predicate(predicate: &Utf16Predicate) -> MddResult<()> {
        let length = match predicate {
            Utf16Predicate::Any => 0,
            Utf16Predicate::Equal(v) | Utf16Predicate::Prefix(v) | Utf16Predicate::Contains(v) => {
                v.len()
            }
        };
        if length > 1_000_000 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        Ok(())
    }
    fn append_entity(
        &self,
        result: &mut Vec<EntityRef>,
        bytes: &mut u64,
        view: u32,
        make: impl FnOnce() -> MddResult<EntityRef>,
    ) -> MddResult<()> {
        let cost = (self.scope.snapshot_id().len()
            + self.views[view as usize].occurrence().len()
            + std::mem::size_of::<EntityRef>()) as u64;
        *bytes = bytes
            .checked_add(cost)
            .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
        if result.len() as u64 >= self.limits.max_result_entries
            || *bytes > self.limits.max_result_bytes
        {
            return Err(quota("INDEX_RESULT_BUDGET"));
        }
        result
            .try_reserve(1)
            .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
        result.push(make()?);
        Ok(())
    }
    fn build_strings(&self) -> MddResult<StringIndex> {
        self.note_traversal();
        self.require(FactLayer::Metadata)?;
        let mut index = StringIndex::empty();
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let metadata = view
                .metadata
                .ok_or_else(|| missing_facts("metadata missing"))?;
            add_strings(&mut index, &mut budget, view_id as u32, metadata)?;
        }
        index.finish(&self.views, &mut budget)?;
        Ok(index)
    }
    fn string_candidates<'b>(
        index: &'b StringIndex,
        predicate: &'b Utf16Predicate,
    ) -> Box<dyn Iterator<Item = Atom> + 'b> {
        match predicate {
            Utf16Predicate::Any => Box::new(index.all.iter().copied()),
            Utf16Predicate::Equal(value) => Box::new(index.utf16.get(value).iter().copied()),
            Utf16Predicate::Prefix(prefix) => {
                Box::new(index.utf16.prefix(prefix).flatten().copied())
            }
            Utf16Predicate::Contains(value) => match value.first() {
                None => Box::new(index.all.iter().copied()),
                Some(unit) => Box::new(index.units.get(*unit).iter().copied()),
            },
        }
    }
    pub fn strings_indexed(&self, predicate: &Utf16Predicate) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Metadata)?;
        let index = self.strings.get_or_build(|| self.build_strings())?;
        let candidates = Self::string_candidates(&index, predicate);
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        let mut candidate_count = 0;
        for atom in candidates {
            candidate_count += 1;
            let text = &self.metadata(atom.view)?.strings()[atom.local as usize]
                .data
                .text;
            if predicate.matches(&text.utf16_units) {
                self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                    self.string_entity(atom)
                })?;
            }
        }
        self.result(
            entities,
            candidate_count,
            "utf16_candidate_then_exact_residual",
            Some(self.strings.audit()?),
            coverage,
        )
    }
    pub fn strings_scalar(&self, predicate: &Utf16Predicate) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Metadata)?;
        let mut entities = Vec::new();
        let mut candidates = 0;
        let mut result_bytes = 0;
        for (view, entry) in self.views.iter().enumerate() {
            for string in entry
                .metadata
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "metadata missing",
                    )
                })?
                .strings()
            {
                candidates += 1;
                if predicate.matches(&string.data.text.utf16_units) {
                    self.append_entity(&mut entities, &mut result_bytes, view as u32, || {
                        self.string_entity(Atom {
                            view: view as u32,
                            local: string.data.string_idx,
                        })
                    })?;
                }
            }
        }
        self.result(
            entities,
            candidates,
            "scalar_full_string_scan",
            None,
            coverage,
        )
    }
    pub fn strings_raw_mutf8(&self, raw: &[u8]) -> MddResult<IndexMatches> {
        if raw.len() > 16 * 1024 * 1024 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::Metadata)?;
        let index = self.strings.get_or_build(|| self.build_strings())?;
        let candidates = index.raw.get(raw);
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        for atom in candidates {
            if self.metadata(atom.view)?.strings()[atom.local as usize]
                .data
                .text
                .raw_mutf8
                == raw
            {
                self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                    self.string_entity(*atom)
                })?;
            }
        }
        self.result(
            entities,
            candidates.len(),
            "raw_mutf8_exact",
            Some(self.strings.audit()?),
            coverage,
        )
    }
    pub fn retry_string_index(&self) -> MddResult<IndexAudit> {
        self.strings.retry_failed(|| self.build_strings())?;
        self.strings.audit()
    }
    fn build_definitions(&self) -> MddResult<DefinitionIndex> {
        self.note_traversal();
        self.require(FactLayer::Definitions)?;
        let mut index = DefinitionIndex::empty();
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let facts = view
                .definitions
                .ok_or_else(|| missing_facts("definitions missing"))?;
            add_definitions(&mut index, &mut budget, view_id as u32, facts)?;
        }
        index.finish(&self.views, &mut budget)?;
        Ok(index)
    }
    fn definition_name(&self, atom: DefinitionAtom) -> MddResult<Vec<u16>> {
        let facts = self.definition_facts(atom.view)?;
        Ok(match atom.kind {
            DefinitionKind::Class => facts.definitions().classes[atom.local as usize]
                .descriptor
                .encode_utf16()
                .collect(),
            DefinitionKind::Field => facts.definitions().field_references[atom.local as usize]
                .field_name
                .encode_utf16()
                .collect(),
            DefinitionKind::Method => facts.definitions().method_references[atom.local as usize]
                .method_name
                .encode_utf16()
                .collect(),
        })
    }
    /// Exact class descriptor lookup tied to the selected snapshot and coverage.
    /// Empty matches only prove absence within the complete selected scope;
    /// `covers_all_captured_sources` separately states whether it covers all inputs.
    pub fn classes_exact(&self, descriptor: &[u16]) -> MddResult<IndexMatches> {
        let predicate = Self::class_exact_predicate(descriptor)?;
        self.definition_names(DefinitionKind::Class, &predicate)
    }
    /// Independent scalar path for the same selected-scope class lookup.
    pub fn classes_exact_scalar(&self, descriptor: &[u16]) -> MddResult<IndexMatches> {
        let predicate = Self::class_exact_predicate(descriptor)?;
        self.definition_names_scalar(DefinitionKind::Class, &predicate)
    }
    fn class_exact_predicate(descriptor: &[u16]) -> MddResult<Utf16Predicate> {
        if descriptor.len() > 1_000_000 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let mut units = Vec::new();
        units
            .try_reserve_exact(descriptor.len())
            .map_err(|_| quota("INDEX_PREDICATE_ALLOCATION"))?;
        units.extend_from_slice(descriptor);
        Ok(Utf16Predicate::Equal(units))
    }

    pub fn definition_names(
        &self,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Definitions)?;
        let index = self.definitions.get_or_build(|| self.build_definitions())?;
        let candidates: Box<dyn Iterator<Item = DefinitionAtom> + '_> = match predicate {
            Utf16Predicate::Equal(name) => Box::new(index.names.get(kind, name).iter().copied()),
            Utf16Predicate::Prefix(prefix) => {
                Box::new(index.names.prefix(kind, prefix).flatten().copied())
            }
            _ => Box::new(index.all.iter().filter(|atom| atom.kind == kind).copied()),
        };
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        let mut candidate_count = 0;
        for atom in candidates {
            candidate_count += 1;
            if predicate.matches(&self.definition_name(atom)?) {
                self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                    self.definition_entity(atom)
                })?;
            }
        }
        self.result(
            entities,
            candidate_count,
            "definition_name_candidates_then_exact",
            Some(self.definitions.audit()?),
            coverage,
        )
    }
    pub fn definition_names_scalar(
        &self,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Definitions)?;
        let mut entities = Vec::new();
        let mut candidates = 0;
        let mut result_bytes = 0;
        for (view, entry) in self.views.iter().enumerate() {
            let facts = entry.definitions.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "definitions missing",
                )
            })?;
            let mut visit = |local| -> MddResult<()> {
                let atom = DefinitionAtom {
                    view: view as u32,
                    kind,
                    local,
                };
                candidates += 1;
                if predicate.matches(&self.definition_name(atom)?) {
                    self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                        self.definition_entity(atom)
                    })?;
                }
                Ok(())
            };
            match kind {
                DefinitionKind::Class => {
                    for item in &facts.definitions().classes {
                        visit(item.class_def_idx)?;
                    }
                }
                DefinitionKind::Field => {
                    for item in &facts.definitions().field_definitions {
                        visit(item.field_idx)?;
                    }
                }
                DefinitionKind::Method => {
                    for item in &facts.definitions().method_definitions {
                        visit(item.method_idx)?;
                    }
                }
            }
        }
        self.result(
            entities,
            candidates,
            "scalar_full_definition_scan",
            None,
            coverage,
        )
    }
    pub fn owner_members(
        &self,
        owner: &EntityRef,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Definitions)?;
        if owner.snapshot_id != self.scope.snapshot_id()
            || owner.kind != EntityKind::ClassDefinition
            || kind == DefinitionKind::Class
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "owner must be a class definition in this scope and member kind field/method",
            ));
        }
        let view = *self
            .by_occurrence
            .get(&owner.dex_occurrence_id)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index",
                    "owner occurrence outside selection",
                )
            })?;
        self.definition_facts(view)?
            .entity(EntityKind::ClassDefinition, owner.local_index)?;
        let index = self.definitions.get_or_build(|| self.build_definitions())?;
        let candidates = index
            .owners
            .get(&(view, owner.local_index, kind))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        for atom in candidates {
            if predicate.matches(&self.definition_name(*atom)?) {
                self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                    self.definition_entity(*atom)
                })?;
            }
        }
        self.result(
            entities,
            candidates.len(),
            "owner_candidates_then_exact",
            Some(self.definitions.audit()?),
            coverage,
        )
    }
    /// Find directly declared fields or methods for an exact class descriptor across the selected occurrences.
    /// Duplicate definitions are retained and inheritance or runtime resolution is not inferred.
    pub fn owner_members_by_descriptor(
        &self,
        descriptor: &str,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        self.owner_members_descriptor_impl(descriptor, kind, predicate, false)
    }
    /// Full scan independent of the lazy owner index.
    pub fn owner_members_by_descriptor_scalar(
        &self,
        descriptor: &str,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        self.owner_members_descriptor_impl(descriptor, kind, predicate, true)
    }
    fn owner_members_descriptor_impl(
        &self,
        descriptor: &str,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
        scalar: bool,
    ) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        if kind == DefinitionKind::Class {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "member kind must be field or method",
            ));
        }
        if descriptor.encode_utf16().take(1_000_001).count() > 1_000_000 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::Definitions)?;
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        let mut candidates = 0usize;
        if scalar {
            for (view, entry) in self.views.iter().enumerate() {
                let facts = entry.definitions.ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "definitions missing",
                    )
                })?;
                let view = u32::try_from(view).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
                for class in facts
                    .definitions()
                    .classes
                    .iter()
                    .filter(|class| class.descriptor == descriptor)
                {
                    let members: Box<dyn Iterator<Item = u32> + '_> = match kind {
                        DefinitionKind::Field => Box::new(
                            facts
                                .definitions()
                                .field_definitions
                                .iter()
                                .filter(move |item| item.class_def_idx == class.class_def_idx)
                                .map(|item| item.field_idx),
                        ),
                        DefinitionKind::Method => Box::new(
                            facts
                                .definitions()
                                .method_definitions
                                .iter()
                                .filter(move |item| item.class_def_idx == class.class_def_idx)
                                .map(|item| item.method_idx),
                        ),
                        DefinitionKind::Class => unreachable!(),
                    };
                    for local in members {
                        candidates = candidates
                            .checked_add(1)
                            .ok_or_else(|| quota("INDEX_RESULT_ENTRY_BUDGET"))?;
                        let atom = DefinitionAtom { view, kind, local };
                        if predicate.matches(&self.definition_name(atom)?) {
                            self.append_entity(&mut entities, &mut result_bytes, view, || {
                                self.definition_entity(atom)
                            })?;
                        }
                    }
                }
            }
        } else {
            let index = self.definitions.get_or_build(|| self.build_definitions())?;
            let name = descriptor.encode_utf16().collect::<Vec<_>>();
            for owner in index.names.get(DefinitionKind::Class, &name) {
                let facts = self.definition_facts(owner.view)?;
                let class = facts
                    .definitions()
                    .classes
                    .get(owner.local as usize)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "facts.index",
                            "class candidate missing",
                        )
                    })?;
                if class.descriptor != descriptor {
                    continue;
                }
                for atom in index
                    .owners
                    .get(&(owner.view, owner.local, kind))
                    .into_iter()
                    .flatten()
                {
                    candidates = candidates
                        .checked_add(1)
                        .ok_or_else(|| quota("INDEX_RESULT_ENTRY_BUDGET"))?;
                    let member_class = match kind {
                        DefinitionKind::Field => facts
                            .definitions()
                            .field_references
                            .get(atom.local as usize)
                            .map(|member| member.class_idx),
                        DefinitionKind::Method => facts
                            .definitions()
                            .method_references
                            .get(atom.local as usize)
                            .map(|member| member.class_idx),
                        DefinitionKind::Class => unreachable!(),
                    }
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "facts.index",
                            "member candidate missing",
                        )
                    })?;
                    if member_class == class.class_idx
                        && predicate.matches(&self.definition_name(*atom)?)
                    {
                        self.append_entity(&mut entities, &mut result_bytes, owner.view, || {
                            self.definition_entity(*atom)
                        })?;
                    }
                }
            }
        }
        self.result(
            entities,
            candidates,
            if scalar {
                "scalar_class_descriptor_and_direct_members"
            } else {
                "class_descriptor_and_owner_candidates_then_exact"
            },
            if scalar {
                None
            } else {
                Some(self.definitions.audit()?)
            },
            coverage,
        )
    }
    pub fn retry_definition_index(&self) -> MddResult<IndexAudit> {
        self.definitions.retry_failed(|| self.build_definitions())?;
        self.definitions.audit()
    }
    fn annotation_descriptor(&self, atom: AnnotationOwnerAtom) -> MddResult<&[u16]> {
        let view = self
            .views
            .get(atom.view as usize)
            .ok_or_else(annotation_inconsistent)?;
        let facts = view.annotations.ok_or_else(annotation_inconsistent)?;
        let item = facts
            .data()
            .annotation_items
            .get(atom.item as usize)
            .ok_or_else(annotation_inconsistent)?;
        let metadata = facts.definitions().metadata();
        let ty = metadata
            .types()
            .get(item.type_idx as usize)
            .ok_or_else(annotation_inconsistent)?;
        if ty.entity.local_index != item.type_idx {
            return Err(annotation_inconsistent());
        }
        let text = metadata
            .strings()
            .get(ty.descriptor_string.local_index as usize)
            .ok_or_else(annotation_inconsistent)?;
        if text.entity != ty.descriptor_string {
            return Err(annotation_inconsistent());
        }
        Ok(&text.data.text.utf16_units)
    }

    // Logical visit/temporary-map limits only; neither allocator RSS nor CPU time is bounded.
    fn walk_annotation_owners(
        &self,
        budget: &mut Budget,
        mut visit: impl FnMut(AnnotationOwnerAtom, &mut Budget) -> MddResult<()>,
    ) -> MddResult<()> {
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let facts = view
                .annotations
                .ok_or_else(|| missing_facts("annotations not built"))?;
            let data = facts.data();
            let view_id = u32::try_from(view_id).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
            let mut sets = BTreeMap::new();
            for (index, item) in data.sets.iter().enumerate() {
                budget.charge(1, 48)?;
                let index = u32::try_from(index).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
                if item.encoded_range.byte_offset.0 != u64::from(item.byte_offset)
                    || sets.insert(item.byte_offset, index).is_some()
                {
                    return Err(annotation_inconsistent());
                }
            }
            let mut items = BTreeMap::new();
            for (index, item) in data.annotation_items.iter().enumerate() {
                budget.charge(1, 48)?;
                let index = u32::try_from(index).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
                if item.encoded_range.byte_offset.0 != u64::from(item.byte_offset)
                    || items.insert(item.byte_offset, index).is_some()
                {
                    return Err(annotation_inconsistent());
                }
            }
            for (owner_id, owner) in data.owner_bindings.iter().enumerate() {
                budget.charge(1, 0)?;
                let Some(offset) = owner.annotation_set_offset else {
                    continue;
                };
                let set_index = *sets.get(&offset).ok_or_else(annotation_inconsistent)?;
                let set = data
                    .sets
                    .get(set_index as usize)
                    .ok_or_else(annotation_inconsistent)?;
                let owner_id = u32::try_from(owner_id).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
                for (ordinal, offset) in set.annotation_offsets.iter().enumerate() {
                    budget.charge(1, 0)?;
                    let atom = AnnotationOwnerAtom {
                        view: view_id,
                        owner: owner_id,
                        item: *items.get(offset).ok_or_else(annotation_inconsistent)?,
                        set: set_index,
                        ordinal: u32::try_from(ordinal).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?,
                    };
                    visit(atom, budget)?;
                }
            }
        }
        Ok(())
    }

    fn build_annotation_types(&self) -> MddResult<AnnotationTypeIndex> {
        self.note_traversal();
        self.require(FactLayer::Annotations)?;
        let mut index = AnnotationTypeIndex::empty();
        let mut budget = Budget::new(self.limits);
        self.walk_annotation_owners(&mut budget, |atom, budget| {
            let key = self.annotation_descriptor(atom)?;
            if !index.owners.contains_key(key) {
                let bytes = u64::try_from(key.len())
                    .ok()
                    .and_then(|n| n.checked_mul(2))
                    .and_then(|n| n.checked_add(64))
                    .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))?;
                budget.charge(0, bytes)?;
            }
            budget.charge(1, std::mem::size_of::<AnnotationOwnerAtom>() as u64)?;
            if let Some(postings) = index.owners.get_mut(key) {
                postings
                    .try_reserve(1)
                    .map_err(|_| quota("INDEX_ALLOCATION"))?;
                postings.push(atom);
            } else {
                index.owners.insert(key.to_vec(), vec![atom]);
            }
            Ok(())
        })?;
        Ok(index)
    }

    fn annotation_owner_match(&self, atom: AnnotationOwnerAtom) -> MddResult<AnnotationOwnerMatch> {
        let view = self
            .views
            .get(atom.view as usize)
            .ok_or_else(annotation_inconsistent)?;
        let facts = view.annotations.ok_or_else(annotation_inconsistent)?;
        let data = facts.data();
        let owner = data
            .owner_bindings
            .get(atom.owner as usize)
            .ok_or_else(annotation_inconsistent)?;
        let item = data
            .annotation_items
            .get(atom.item as usize)
            .ok_or_else(annotation_inconsistent)?;
        let offset = owner
            .annotation_set_offset
            .ok_or_else(annotation_inconsistent)?;
        // Recheck every posting, including ordinal and physical identity, against immutable facts.
        let set = data
            .sets
            .get(atom.set as usize)
            .ok_or_else(annotation_inconsistent)?;
        if set.byte_offset != offset
            || set.annotation_offsets.get(atom.ordinal as usize) != Some(&item.byte_offset)
        {
            return Err(annotation_inconsistent());
        }
        Ok(AnnotationOwnerMatch {
            dex_occurrence_id: view.occurrence().to_owned(),
            annotation_byte_offset: item.byte_offset,
            annotation_set_byte_offset: offset,
            set_ordinal: atom.ordinal,
            owner: owner.clone(),
        })
    }

    fn annotation_owner_result(
        &self,
        descriptor: &[u16],
        scalar: bool,
    ) -> MddResult<AnnotationOwnerMatches> {
        if descriptor.len() > 1_000_000 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::Annotations)?;
        let mut matches = Vec::new();
        let mut bytes = 0u64;
        let mut candidates = 0u64;
        let mut append = |atom: AnnotationOwnerAtom| -> MddResult<()> {
            candidates = candidates
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_RESULT_BUDGET"))?;
            if self.annotation_descriptor(atom)? != descriptor {
                return Ok(());
            }
            let view = self
                .views
                .get(atom.view as usize)
                .ok_or_else(annotation_inconsistent)?;
            let cost = u64::try_from(view.occurrence().len())
                .ok()
                .and_then(|v| v.checked_add(std::mem::size_of::<AnnotationOwnerMatch>() as u64))
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            bytes = bytes
                .checked_add(cost)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if matches.len() as u64 >= self.limits.max_result_entries
                || bytes > self.limits.max_result_bytes
            {
                return Err(quota("INDEX_RESULT_BUDGET"));
            }
            matches
                .try_reserve(1)
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            matches.push(self.annotation_owner_match(atom)?);
            Ok(())
        };
        if scalar {
            let mut budget = Budget::new(self.limits);
            self.walk_annotation_owners(&mut budget, |atom, _| append(atom))?;
        } else {
            let index = self
                .annotation_types
                .get_or_build(|| self.build_annotation_types())?;
            let mut budget = Budget::new(self.limits);
            budget.charge(0, 0)?;
            if let Some(atoms) = index.owners.get(descriptor) {
                for atom in atoms {
                    budget.charge(1, 0)?;
                    append(*atom)?;
                }
            }
        }
        Ok(AnnotationOwnerMatches {
            snapshot_id: self.scope.snapshot_id().into(),
            scope_id: self.scope.scope_id().into(),
            index_attempt: if scalar {
                None
            } else {
                Some(self.annotation_types.audit()?)
            },
            access_path: if scalar {
                "scalar_annotation_owner_scan"
            } else {
                "annotation_type_candidates_then_exact"
            },
            candidate_count: candidates,
            absence_proven_within_selected_scope: matches.is_empty(),
            covers_all_captured_sources: self.scope.covers_all_captured_sources(),
            matches,
            coverage,
        })
    }
    /// Exact UTF-16 type descriptor, over encoded owner occurrences only.
    pub fn annotation_owners_by_type(
        &self,
        descriptor: &[u16],
    ) -> MddResult<AnnotationOwnerMatches> {
        self.annotation_owner_result(descriptor, false)
    }
    pub fn annotation_owners_by_type_scalar(
        &self,
        descriptor: &[u16],
    ) -> MddResult<AnnotationOwnerMatches> {
        self.annotation_owner_result(descriptor, true)
    }
    pub fn retry_annotation_type_index(&self) -> MddResult<IndexAudit> {
        self.annotation_types
            .retry_failed(|| self.build_annotation_types())?;
        self.annotation_types.audit()
    }
    pub fn retry_reference_symbol_index(&self) -> MddResult<IndexAudit> {
        self.reference_symbols
            .retry_failed(|| self.build_reference_symbols())?;
        self.reference_symbols.audit()
    }
    pub fn retry_field_reference_symbol_index(&self) -> MddResult<IndexAudit> {
        self.field_reference_symbols
            .retry_failed(|| self.build_field_reference_symbols())?;
        self.field_reference_symbols.audit()
    }
    pub fn retry_type_reference_index(&self) -> MddResult<IndexAudit> {
        self.type_references
            .retry_failed(|| self.build_type_references())?;
        self.type_references.audit()
    }
    pub fn retry_prototype_reference_index(&self) -> MddResult<IndexAudit> {
        self.prototype_references
            .retry_failed(|| self.build_prototype_references())?;
        self.prototype_references.audit()
    }
    pub fn retry_method_handle_index(&self) -> MddResult<IndexAudit> {
        self.method_handles
            .retry_failed(|| self.build_method_handles())?;
        self.method_handles.audit()
    }
    pub fn retry_caller_site_index(&self) -> MddResult<IndexAudit> {
        self.caller_sites
            .retry_failed(|| self.build_caller_sites())?;
        self.caller_sites.audit()
    }
    fn build_caller_sites(&self) -> MddResult<CallerSiteIndex> {
        self.note_traversal();
        self.require(FactLayer::References)?;
        let mut pairs = Vec::new();
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let facts = view
                .references
                .ok_or_else(|| missing_facts("references missing"))?;
            add_caller_sites(&mut pairs, &mut budget, view_id as u32, facts)?;
        }
        CallerSiteIndex::from_pairs(pairs, &mut budget)
    }
    fn build_method_handles(&self) -> MddResult<MethodHandleIndex> {
        self.note_traversal();
        self.require(FactLayer::References)?;
        let mut index = MethodHandleIndex::empty();
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let facts = view
                .references
                .ok_or_else(|| missing_facts("references missing"))?;
            add_method_handles(&mut index, &mut budget, view_id as u32, facts)?;
        }
        Ok(index)
    }
    fn build_prototype_references(&self) -> MddResult<PrototypeReferenceIndex> {
        self.note_traversal();
        self.require(FactLayer::Metadata)?;
        let mut pairs = Vec::new();
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let metadata = view
                .metadata
                .ok_or_else(|| missing_facts("metadata missing"))?;
            add_prototype_references(&mut pairs, &mut budget, view_id as u32, metadata)?;
        }
        Ok(PrototypeReferenceIndex {
            descriptors: DescriptorPostings::from_pairs(pairs, &mut budget)?,
        })
    }
    fn build_type_references(&self) -> MddResult<TypeReferenceIndex> {
        self.note_traversal();
        self.require(FactLayer::Metadata)?;
        let mut pairs = Vec::new();
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let metadata = view
                .metadata
                .ok_or_else(|| missing_facts("metadata missing"))?;
            add_type_references(&mut pairs, &mut budget, view_id as u32, metadata)?;
        }
        Ok(TypeReferenceIndex {
            descriptors: DescriptorPostings::from_pairs(pairs, &mut budget)?,
        })
    }
    fn build_field_reference_symbols(&self) -> MddResult<FieldReferenceSymbolIndex> {
        self.note_traversal();
        self.require(FactLayer::Definitions)?;
        let mut pairs = Vec::new();
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let facts = view
                .definitions
                .ok_or_else(|| missing_facts("definitions missing"))?;
            add_field_reference_symbols(&mut pairs, &mut budget, view_id as u32, facts)?;
        }
        FieldReferenceSymbolIndex::from_pairs(pairs, &mut budget)
    }
    fn build_reference_symbols(&self) -> MddResult<ReferenceSymbolIndex> {
        self.note_traversal();
        self.require(FactLayer::Definitions)?;
        let mut pairs = Vec::new();
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let facts = view
                .definitions
                .ok_or_else(|| missing_facts("definitions missing"))?;
            add_reference_symbols(&mut pairs, &mut budget, view_id as u32, facts)?;
        }
        ReferenceSymbolIndex::from_pairs(pairs, &mut budget)
    }
    pub fn references_local(&self, target: &ReferenceTargetId) -> MddResult<ReferenceMatches> {
        self.require(FactLayer::References)?;
        let view = *self
            .by_occurrence
            .get(&target.dex_occurrence_id)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index",
                    "reference target outside selected occurrences",
                )
            })?;
        let matches = self.views[view as usize]
            .references
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "references not built",
                )
            })?
            .find_target_indexed(target)?;
        self.check_site_budget(&matches.sites)?;
        Ok(matches)
    }
    fn check_site_budget(&self, sites: &[crate::references::ReferenceSiteId]) -> MddResult<()> {
        let bytes = Self::site_bytes(sites)?;
        if sites.len() as u64 > self.limits.max_result_entries
            || bytes > self.limits.max_result_bytes
        {
            return Err(quota("INDEX_RESULT_BUDGET"));
        }
        Ok(())
    }
    fn site_bytes(sites: &[crate::references::ReferenceSiteId]) -> MddResult<u64> {
        sites
            .iter()
            .try_fold(0u64, |sum, site| {
                sum.checked_add(
                    (std::mem::size_of::<crate::references::ReferenceSiteId>()
                        + site.caller_method_definition.snapshot_id.len()
                        + site.caller_method_definition.dex_occurrence_id.len())
                        as u64,
                )
            })
            .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))
    }
    fn reference_result(
        &self,
        mut sites: Vec<crate::references::ReferenceSiteId>,
        candidates: u64,
        scalar: bool,
        kind: ReferenceResultKind,
        coverage: CoverageReport,
    ) -> MddResult<ReferenceIndexMatches> {
        self.check_site_budget(&sites)?;
        sites.sort_by_key(|site| {
            (
                self.by_occurrence[&site.caller_method_definition.dex_occurrence_id],
                site.caller_method_definition.local_index,
                site.code_unit_pc,
                site.operand_ordinal,
            )
        });
        Ok(ReferenceIndexMatches {
            snapshot_id: self.scope.snapshot_id().into(),
            scope_id: self.scope.scope_id().into(),
            index_attempt: match (scalar, kind) {
                (true, _) => None,
                (false, ReferenceResultKind::Method) => Some(self.reference_symbols.audit()?),
                (false, ReferenceResultKind::Field) => Some(self.field_reference_symbols.audit()?),
                (false, ReferenceResultKind::String | ReferenceResultKind::RawString) => {
                    Some(self.strings.audit()?)
                }
                (false, ReferenceResultKind::Type) => Some(self.type_references.audit()?),
                (false, ReferenceResultKind::Prototype) => Some(self.prototype_references.audit()?),
                (false, ReferenceResultKind::MethodHandle) => Some(self.method_handles.audit()?),
                (false, ReferenceResultKind::CallSiteBytes) => None,
                (false, ReferenceResultKind::Caller) => Some(self.caller_sites.audit()?),
            },
            access_path: match (scalar, kind) {
                (true, ReferenceResultKind::Method) => {
                    "scalar_encoded_method_refs_then_scalar_sites"
                }
                (false, ReferenceResultKind::Method) => {
                    "method_symbol_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::Field) => "scalar_encoded_field_refs_then_scalar_sites",
                (false, ReferenceResultKind::Field) => {
                    "field_symbol_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::String) => "scalar_utf16_strings_then_scalar_sites",
                (false, ReferenceResultKind::String) => {
                    "utf16_string_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::RawString) => {
                    "scalar_raw_mutf8_strings_then_scalar_sites"
                }
                (false, ReferenceResultKind::RawString) => {
                    "raw_mutf8_string_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::Type) => "scalar_type_descriptors_then_scalar_sites",
                (false, ReferenceResultKind::Type) => {
                    "type_descriptor_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::Prototype) => {
                    "scalar_prototype_descriptors_then_scalar_sites"
                }
                (false, ReferenceResultKind::Prototype) => {
                    "prototype_descriptor_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::MethodHandle) => {
                    "scalar_method_handles_then_scalar_sites"
                }
                (false, ReferenceResultKind::MethodHandle) => {
                    "method_handle_symbol_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::CallSiteBytes) => {
                    "same_dex_content_callsite_bytes_then_scalar_sites"
                }
                (false, ReferenceResultKind::CallSiteBytes) => {
                    "same_dex_content_callsite_bytes_then_existing_postings"
                }
                (true, ReferenceResultKind::Caller) => "scalar_caller_and_encoded_sites",
                (false, ReferenceResultKind::Caller) => {
                    "caller_candidates_then_exact_encoded_sites"
                }
            }
            .into(),
            candidate_reference_count: candidates,
            absence_proven_within_selected_encoded_scope: sites.is_empty(),
            covers_all_captured_sources: self.scope.covers_all_captured_sources(),
            runtime_resolution: match kind {
                ReferenceResultKind::Field => {
                    "encoded_field_operands_only;runtime_resolution_not_inferred"
                }
                ReferenceResultKind::Method => {
                    "encoded_method_operands_only;runtime_dispatch_not_inferred"
                }
                ReferenceResultKind::String | ReferenceResultKind::RawString => {
                    "encoded_string_operands_only;runtime_values_not_inferred"
                }
                ReferenceResultKind::Type => {
                    "encoded_type_operands_only;runtime_resolution_not_inferred"
                }
                ReferenceResultKind::Prototype => {
                    "encoded_prototype_operands_only;runtime_dispatch_not_inferred"
                }
                ReferenceResultKind::MethodHandle => {
                    "encoded_method_handle_operands_only;no_implied_call_or_field_access"
                }
                ReferenceResultKind::CallSiteBytes => {
                    "same_dex_content_and_encoded_array_bytes_only;dynamic_target_not_inferred"
                }
                ReferenceResultKind::Caller => {
                    "encoded_operands_only;runtime_resolution_not_inferred"
                }
            },
            sites,
            coverage,
        })
    }
    /// Find encoded operand sites in one same-occurrence method definition.
    /// A method operand remains an encoded reference, not inferred runtime dispatch.
    pub fn references_from_method(
        &self,
        caller: &EntityRef,
        kind: Option<TargetKind>,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_from_method_impl(caller, kind, false)
    }
    /// Full scalar site scan, independent of the caller index.
    pub fn references_from_method_scalar(
        &self,
        caller: &EntityRef,
        kind: Option<TargetKind>,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_from_method_impl(caller, kind, true)
    }
    fn references_from_method_impl(
        &self,
        caller: &EntityRef,
        kind: Option<TargetKind>,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if caller.snapshot_id != self.scope.snapshot_id()
            || caller.kind != EntityKind::MethodDefinition
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "caller is a foreign snapshot or not a method definition",
            ));
        }
        let coverage = self.require(FactLayer::References)?;
        let view = *self
            .by_occurrence
            .get(&caller.dex_occurrence_id)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index",
                    "caller outside selected occurrences",
                )
            })?;
        let facts = self.views[view as usize].references.ok_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.index",
                "references missing",
            )
        })?;
        if facts.source().snapshot_id != caller.snapshot_id
            || facts.source().dex_occurrence_id != caller.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "foreign caller identity",
            ));
        }
        let mut scan = Budget::new(self.limits);
        scan.charge(0, 0)?;
        let mut found = false;
        for definition in &facts.definitions().definitions().method_definitions {
            scan.charge(1, 0)?;
            if definition.method_idx == caller.local_index {
                found = true;
                break;
            }
        }
        if !found {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "method definition does not exist in this occurrence",
            ));
        }
        let index = if scalar {
            None
        } else {
            Some(
                self.caller_sites
                    .get_or_build(|| self.build_caller_sites())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = u32> + '_> = if let Some(index) = &index {
            Box::new(
                index
                    .get(Atom {
                        view,
                        local: caller.local_index,
                    })
                    .iter()
                    .copied(),
            )
        } else {
            Box::new((0..facts.sites().len()).map(|ordinal| ordinal as u32))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for ordinal in candidates {
            scan.charge(1, 0)?;
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let site = facts
                .sites()
                .get(ordinal as usize)
                .filter(|site| site.site_ordinal == ordinal)
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.index",
                        "caller candidate site missing",
                    )
                })?;
            if site.caller_method_idx != caller.local_index
                || kind.is_some_and(|kind| site.target_kind != kind)
            {
                continue;
            }
            let cost = std::mem::size_of::<crate::references::ReferenceSiteId>()
                .checked_add(caller.snapshot_id.len())
                .and_then(|size| size.checked_add(caller.dex_occurrence_id.len()))
                .and_then(|size| u64::try_from(size).ok())
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            result_bytes = result_bytes
                .checked_add(cost)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result.len() as u64 >= self.limits.max_result_entries
                || result_bytes > self.limits.max_result_bytes
            {
                return Err(quota("INDEX_RESULT_BUDGET"));
            }
            result
                .try_reserve(1)
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.push(crate::references::ReferenceSiteId {
                caller_method_definition: caller.clone(),
                code_unit_pc: site.code_unit_pc,
                operand_ordinal: site.operand_ordinal,
                operand_kind: site.target_kind,
            });
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Caller,
            coverage,
        )
    }
    /// Capture full call-site encoded-array bytes with the validated DEX content identity.
    /// The key is a byte identity within identical DEX content, not cross-DEX semantic equality.
    pub fn call_site_encoded_key(
        &self,
        target: &ReferenceTargetId,
    ) -> MddResult<CallSiteEncodedKey> {
        self.require(FactLayer::References)?;
        if target.snapshot_id != self.scope.snapshot_id() || target.kind != TargetKind::CallSite {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "foreign snapshot or non-call-site target",
            ));
        }
        let view = *self
            .by_occurrence
            .get(&target.dex_occurrence_id)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index",
                    "reference target outside selected occurrences",
                )
            })?;
        let facts = self.views[view as usize].references.ok_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.index",
                "references missing",
            )
        })?;
        if facts.target_id(TargetKind::CallSite, target.local_index)? != *target {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "foreign call-site target",
            ));
        }
        let bytes = call_site_array_bytes(facts, target.local_index)?;
        let needed = u64::try_from(bytes.len())
            .ok()
            .and_then(|n| n.checked_add(facts.source().content_id.len() as u64))
            .and_then(|n| n.checked_add(facts.source().snapshot_id.len() as u64))
            .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
        if needed > self.limits.max_result_bytes {
            return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
        }
        let mut encoded_array = Vec::new();
        encoded_array
            .try_reserve_exact(bytes.len())
            .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
        encoded_array.extend_from_slice(bytes);
        Ok(CallSiteEncodedKey {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_content_id: facts.source().content_id.clone(),
            encoded_array,
        })
    }
    /// Search complete encoded operands with the same DEX content and full array bytes.
    /// The source-local references within the byte array are never equated across different DEX contents.
    pub fn references_to_call_site_encoded_key(
        &self,
        key: &CallSiteEncodedKey,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_call_site_encoded(key, false)
    }
    pub fn references_to_call_site_encoded_key_scalar(
        &self,
        key: &CallSiteEncodedKey,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_call_site_encoded(key, true)
    }
    fn references_to_call_site_encoded(
        &self,
        key: &CallSiteEncodedKey,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if key.snapshot_id != self.scope.snapshot_id() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "call-site key belongs to a different snapshot",
            ));
        }
        let coverage = self.require(FactLayer::References)?;
        if u64::try_from(key.encoded_array.len()).map_or(true, |n| n > self.limits.max_result_bytes)
        {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let mut scan = Budget::new(self.limits);
        scan.charge(0, 0)?;
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidates = 0u64;
        for entry in &self.views {
            let facts = entry.references.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "references missing",
                )
            })?;
            if facts.source().content_id != key.dex_content_id {
                continue;
            }
            let Some(section) = facts.call_site_metadata() else {
                if facts
                    .sites()
                    .iter()
                    .any(|site| site.target_kind == TargetKind::CallSite)
                {
                    return Err(MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "call-site operand metadata missing",
                    ));
                }
                continue;
            };
            for binding in &section.call_site_arrays {
                scan.charge(1, 0)?;
                candidates = candidates
                    .checked_add(1)
                    .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
                let bytes = call_site_array_bytes(facts, binding.call_site_idx)?;
                if bytes.len() != key.encoded_array.len() {
                    continue;
                }
                let mut equal = true;
                for (a, b) in bytes.chunks(4096).zip(key.encoded_array.chunks(4096)) {
                    scan.charge(0, a.len() as u64)?;
                    if a != b {
                        equal = false;
                        break;
                    }
                }
                if !equal {
                    continue;
                }
                let target = facts.target_id(TargetKind::CallSite, binding.call_site_idx)?;
                let matches = if scalar {
                    facts.find_target_scalar(&target)?
                } else {
                    facts.find_target_indexed(&target)?
                };
                if result
                    .len()
                    .checked_add(matches.sites.len())
                    .and_then(|n| u64::try_from(n).ok())
                    .is_none_or(|n| n > self.limits.max_result_entries)
                {
                    return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
                }
                self.check_site_budget(&matches.sites)?;
                result_bytes = result_bytes
                    .checked_add(Self::site_bytes(&matches.sites)?)
                    .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
                if result_bytes > self.limits.max_result_bytes {
                    return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
                }
                result
                    .try_reserve(matches.sites.len())
                    .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
                result.extend(matches.sites);
            }
        }
        self.reference_result(
            result,
            candidates,
            scalar,
            ReferenceResultKind::CallSiteBytes,
            coverage,
        )
    }

    /// Find encoded method-handle operand sites by handle kind and complete target symbol.
    /// Handle constants do not imply a call, field access, or runtime resolution.
    pub fn references_to_method_handle_symbol(
        &self,
        symbol: &MethodHandleSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_method_handle(symbol, false)
    }
    /// Scan immutable method-handle metadata and operand facts without the candidate index.
    pub fn references_to_method_handle_symbol_scalar(
        &self,
        symbol: &MethodHandleSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_method_handle(symbol, true)
    }
    fn references_to_method_handle(
        &self,
        symbol: &MethodHandleSymbol,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        let (kind, size, is_field) = match symbol {
            MethodHandleSymbol::Field {
                handle_kind,
                target,
            } => (
                *handle_kind,
                target
                    .owner
                    .len()
                    .saturating_add(target.name.len())
                    .saturating_add(target.field_type.len()),
                true,
            ),
            MethodHandleSymbol::Method {
                handle_kind,
                target,
            } => (
                *handle_kind,
                target
                    .owner
                    .len()
                    .saturating_add(target.name.len())
                    .saturating_add(target.prototype.len()),
                false,
            ),
        };
        if size > 16 * 1024 * 1024 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        if (is_field && kind > 3) || (!is_field && !(4..=8).contains(&kind)) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "invalid method-handle kind for target",
            ));
        }
        let coverage = self.require(FactLayer::References)?;
        // Metadata may legitimately be unbuilt when there are no handle operands;
        // a missing table in the presence of an operand remains an error.
        for entry in &self.views {
            let facts = entry.references.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "references missing",
                )
            })?;
            handle_metadata(facts)?;
        }
        let index = if scalar {
            None
        } else {
            Some(
                self.method_handles
                    .get_or_build(|| self.build_method_handles())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = Atom> + '_> = if let Some(index) = &index {
            Box::new(index.symbols.get(symbol).into_iter().flatten().copied())
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.references.into_iter().flat_map(move |facts| {
                    facts
                        .method_handle_metadata()
                        .into_iter()
                        .flatten()
                        .map(move |handle| Atom {
                            view: view as u32,
                            local: handle.method_handle_idx,
                        })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let facts = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let handle = handle_metadata(facts)?
                .get(candidate.local as usize)
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.index",
                        "method-handle candidate missing",
                    )
                })?;
            if !handle_target(facts, handle)?.matches(symbol) {
                continue;
            }
            let target = facts.target_id(TargetKind::MethodHandle, candidate.local)?;
            let matches = if scalar {
                facts.find_target_scalar(&target)?
            } else {
                facts.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::MethodHandle,
            coverage,
        )
    }

    /// Search exact encoded type operands by DEX descriptor across selected occurrences.
    /// This does not infer runtime class resolution, inheritance, or assignability.
    pub fn references_to_type_descriptor(
        &self,
        descriptor: &str,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_type(descriptor, false)
    }
    /// Full metadata and encoded-site scan independent of the lazy type index.
    pub fn references_to_type_descriptor_scalar(
        &self,
        descriptor: &str,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_type(descriptor, true)
    }
    fn references_to_type(
        &self,
        descriptor: &str,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if descriptor.len() > 16 * 1024 * 1024 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        self.require(FactLayer::Metadata)?;
        let index = if scalar {
            None
        } else {
            Some(
                self.type_references
                    .get_or_build(|| self.build_type_references())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = Atom> + '_> = if let Some(index) = &index {
            Box::new(index.descriptors.get(descriptor).iter().copied())
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.metadata.into_iter().flat_map(move |metadata| {
                    metadata.types().iter().map(move |dex_type| Atom {
                        view: view as u32,
                        local: dex_type.data.type_idx,
                    })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let dex_type = &refs.definitions().metadata().types()[candidate.local as usize];
            if dex_type.data.descriptor != descriptor {
                continue;
            }
            let target = refs.target_id(TargetKind::Type, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Type,
            coverage,
        )
    }

    /// Search exact encoded prototype operands by DEX descriptor across selected occurrences.
    /// This does not infer runtime dispatch or call resolution.
    pub fn references_to_prototype_descriptor(
        &self,
        descriptor: &str,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_prototype(descriptor, false)
    }
    /// Full metadata and encoded-site scan independent of the lazy prototype index.
    pub fn references_to_prototype_descriptor_scalar(
        &self,
        descriptor: &str,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_prototype(descriptor, true)
    }
    fn references_to_prototype(
        &self,
        descriptor: &str,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if descriptor.len() > 16 * 1024 * 1024 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        self.require(FactLayer::Metadata)?;
        let index = if scalar {
            None
        } else {
            Some(
                self.prototype_references
                    .get_or_build(|| self.build_prototype_references())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = Atom> + '_> = if let Some(index) = &index {
            Box::new(index.descriptors.get(descriptor).iter().copied())
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.metadata.into_iter().flat_map(move |metadata| {
                    metadata.prototypes().iter().map(move |prototype| Atom {
                        view: view as u32,
                        local: prototype.data.proto_idx,
                    })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let prototype = &refs.definitions().metadata().prototypes()[candidate.local as usize];
            if prototype.data.descriptor != descriptor {
                continue;
            }
            let target = refs.target_id(TargetKind::Prototype, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Prototype,
            coverage,
        )
    }

    /// Search encoded string operand sites by exact UTF-16 code units across selected occurrences.
    /// Raw MUTF-8 byte equality is a separate predicate and is not implied by this query.
    pub fn references_to_string_utf16(&self, value: &[u16]) -> MddResult<ReferenceIndexMatches> {
        self.references_to_string(StringReferencePredicate::Utf16(value), false)
    }
    /// Scan immutable string and reference facts without using the lazy candidate index.
    pub fn references_to_string_utf16_scalar(
        &self,
        value: &[u16],
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_string(StringReferencePredicate::Utf16(value), true)
    }
    /// Search encoded string operands using the exact MUTF-8 payload bytes.
    /// The bytes exclude the terminating zero and the encoded UTF-16 length.
    /// This does not imply a runtime string value or Unicode normalization.
    pub fn references_to_string_raw_mutf8(&self, value: &[u8]) -> MddResult<ReferenceIndexMatches> {
        self.references_to_string(StringReferencePredicate::RawMutf8(value), false)
    }
    /// Scan immutable strings and encoded reference sites without the candidate index.
    pub fn references_to_string_raw_mutf8_scalar(
        &self,
        value: &[u8],
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_string(StringReferencePredicate::RawMutf8(value), true)
    }
    fn references_to_string(
        &self,
        value: StringReferencePredicate<'_>,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if match value {
            StringReferencePredicate::Utf16(units) => units.len() > 1_000_000,
            StringReferencePredicate::RawMutf8(bytes) => bytes.len() > 16 * 1024 * 1024,
        } {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        self.require(FactLayer::Metadata)?;
        let index = if scalar {
            None
        } else {
            Some(self.strings.get_or_build(|| self.build_strings())?)
        };
        let candidates: Box<dyn Iterator<Item = Atom> + '_> = if let Some(index) = &index {
            match value {
                StringReferencePredicate::Utf16(units) => {
                    Box::new(index.utf16.get(units).iter().copied())
                }
                StringReferencePredicate::RawMutf8(bytes) => {
                    Box::new(index.raw.get(bytes).iter().copied())
                }
            }
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.metadata.into_iter().flat_map(move |metadata| {
                    metadata.strings().iter().map(move |string| Atom {
                        view: view as u32,
                        local: string.data.string_idx,
                    })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let string = &refs.definitions().metadata().strings()[candidate.local as usize];
            let exact = match value {
                StringReferencePredicate::Utf16(units) => string.data.text.utf16_units == units,
                StringReferencePredicate::RawMutf8(bytes) => string.data.text.raw_mutf8 == bytes,
            };
            if !exact {
                continue;
            }
            let target = refs.target_id(TargetKind::String, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            match value {
                StringReferencePredicate::Utf16(_) => ReferenceResultKind::String,
                StringReferencePredicate::RawMutf8(_) => ReferenceResultKind::RawString,
            },
            coverage,
        )
    }

    /// Search encoded field operand sites in each selected DEX occurrence.
    /// This matches reference symbols exactly; it does not infer runtime resolution.
    pub fn references_to_field_symbol(
        &self,
        symbol: &FieldSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_field(symbol, false)
    }
    /// Independent full scan of encoded field references and sites, without the lazy index.
    pub fn references_to_field_symbol_scalar(
        &self,
        symbol: &FieldSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_field(symbol, true)
    }
    fn references_to_field(
        &self,
        symbol: &FieldSymbol,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if symbol
            .owner
            .len()
            .saturating_add(symbol.name.len())
            .saturating_add(symbol.field_type.len())
            > 16 * 1024 * 1024
        {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        let index = if scalar {
            None
        } else {
            Some(
                self.field_reference_symbols
                    .get_or_build(|| self.build_field_reference_symbols())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = ReferenceAtom> + '_> = if let Some(index) = &index {
            Box::new(index.get(symbol).iter().copied())
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.definitions.into_iter().flat_map(move |defs| {
                    defs.definitions()
                        .field_references
                        .iter()
                        .map(move |reference| ReferenceAtom {
                            view: view as u32,
                            local: reference.field_idx,
                        })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let reference =
                &refs.definitions().definitions().field_references[candidate.local as usize];
            if reference.class_descriptor != symbol.owner
                || reference.field_name != symbol.name
                || reference.type_descriptor != symbol.field_type
            {
                continue;
            }
            let target = refs.target_id(TargetKind::Field, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Field,
            coverage,
        )
    }

    pub fn references_to_method_symbol(
        &self,
        symbol: &MethodSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_symbol(symbol, false)
    }
    pub fn references_to_method_symbol_scalar(
        &self,
        symbol: &MethodSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_symbol(symbol, true)
    }
    fn references_to_symbol(
        &self,
        symbol: &MethodSymbol,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if symbol
            .owner
            .len()
            .saturating_add(symbol.name.len())
            .saturating_add(symbol.prototype.len())
            > 16 * 1024 * 1024
        {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        // The scalar path scans immutable definition/reference facts and does not
        // consult candidate postings or a cached index failure.
        let index = if scalar {
            None
        } else {
            Some(
                self.reference_symbols
                    .get_or_build(|| self.build_reference_symbols())?,
            )
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let candidates: Box<dyn Iterator<Item = ReferenceAtom> + '_> = if let Some(index) = &index {
            Box::new(index.get(symbol).iter().copied())
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.definitions.into_iter().flat_map(move |defs| {
                    defs.definitions()
                        .method_references
                        .iter()
                        .map(move |reference| ReferenceAtom {
                            view: view as u32,
                            local: reference.method_idx,
                        })
                })
            }))
        };
        let mut candidate_count = 0;
        for candidate in candidates {
            candidate_count += 1;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let reference =
                &refs.definitions().definitions().method_references[candidate.local as usize];
            if reference.class_descriptor != symbol.owner
                || reference.method_name != symbol.name
                || refs.definitions().metadata().prototypes()[reference.proto_idx as usize]
                    .data
                    .descriptor
                    != symbol.prototype
            {
                continue;
            }
            let target = refs.target_id(TargetKind::Method, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result.len() as u64 + matches.sites.len() as u64 > self.limits.max_result_entries {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            // Charge the combined result before copying another source's sites.
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Method,
            coverage,
        )
    }
}
