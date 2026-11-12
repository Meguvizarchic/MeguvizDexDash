//! HostLab `native_surface` migration: family surface records and raw byte fingerprints.
//!
//! The reference implementation issues three per-file SQL queries per DEX
//! (`classes`, `class_fields`, `class_methods`), a `code_items` range query, and
//! then re-opens the APK by path to hash resources. This module derives the same
//! records from the already-built snapshot-bound facts with one linear pass per
//! layer, reads raw instruction bytes from the same captured DEX lease, and
//! hashes resource members through the captured inventory. It never re-reads an
//! input path, so the DEX bytes and the resource bytes always belong to one
//! snapshot generation.
//!
//! Deliberate boundaries:
//!
//! * Business family prefixes are supplied by the caller through
//!   [`FamilyClassifier`]. The generic core carries no BIL package name.
//! * Only the fields the reference derives from class/field/method definitions
//!   plus raw instruction bytes are produced. The invoke-edge, protocol and
//!   page-matrix fields need the reference layer and are reported as unproduced
//!   instead of being guessed.
//! * `profile_admitted` stays `false`: this is a record-level provider, not an
//!   admitted HostLab replacement.
use crate::definitions::DefinitionFacts;
use mdd_dex::definitions::MethodBody;
use mdd_input::archive::ArchiveInventory;
use mdd_types::{Completeness, ErrorCode, MddError, MddResult, sha256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The reference gate: one DEX larger than this is refused before hashing.
pub const MAX_FINGERPRINT_DEX_BYTES: u64 = 128 * 1024 * 1024;

/// Caller-supplied family classification, mirroring the reference `W.family`.
///
/// The reference first applies a case-insensitive `LIKE` superset filter and then
/// gates every row with the exact, case-sensitive Python classifier. Because the
/// SQL filter is a strict superset, the classifier alone decides membership; this
/// trait therefore exposes only the authoritative classifier.
pub trait FamilyClassifier {
    /// Return the reference family key for one class descriptor, or `None`.
    fn family(&self, class_descriptor: &str) -> Option<String>;
    /// Every statically known family key, including keys with no class in this
    /// input. The reference summary emits a row for each of them.
    fn known_families(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Logical work limits. These bound visits and hashed bytes, not process RSS.
#[derive(Clone, Copy, Debug)]
pub struct SurfaceLimits {
    /// Refuse one DEX above this many bytes (reference 128 MiB gate).
    pub max_dex_bytes: u64,
    /// Family class records per DEX.
    pub max_family_classes: u64,
    /// Family field plus method entries per DEX.
    pub max_family_members: u64,
    /// Total instruction bytes hashed per DEX.
    pub max_digest_bytes: u64,
    /// Resource members hashed for one input.
    pub max_resource_members: u64,
    /// Total decompressed resource bytes hashed for one input.
    pub max_resource_bytes: u64,
}

impl Default for SurfaceLimits {
    fn default() -> Self {
        Self {
            max_dex_bytes: MAX_FINGERPRINT_DEX_BYTES,
            max_family_classes: 4_000_000,
            max_family_members: 64_000_000,
            max_digest_bytes: 2 * 1024 * 1024 * 1024,
            max_resource_members: 1_000_000,
            max_resource_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// One selected DEX occurrence placed in the reference numeric `file_id` order.
///
/// The reference sorts archive member names by the integer formed from their
/// digits (`classes.dex` counts as 1) and then reports the position in that
/// order, which is not the archive order for ten or more DEX files.
#[derive(Clone, Debug, Serialize)]
pub struct SurfaceDexFile {
    pub file_id: u32,
    pub dex_index: usize,
    pub dex_occurrence_id: String,
    pub member_name: Option<String>,
}

/// One family class record, field-compatible with the reference `class_records`.
#[derive(Clone, Debug, Serialize)]
pub struct SurfaceClassRecord {
    pub file_id: u32,
    pub family: String,
    pub class: String,
    pub superclass: Option<String>,
    /// `(field name, field type descriptor)`, sorted by the reference tuple order.
    pub fields: Vec<(String, String)>,
    /// `(method name, "(params)return")`, sorted by the reference tuple order.
    pub methods: Vec<(String, String)>,
    pub method_bodies_sha256: String,
    pub compose_signatures: Vec<String>,
}

/// Records for one DEX occurrence plus the work actually performed.
#[derive(Clone, Debug, Serialize)]
pub struct SurfaceDexScan {
    pub file_id: u32,
    pub records: Vec<SurfaceClassRecord>,
    pub family_classes: u64,
    pub family_fields: u64,
    pub family_methods: u64,
    pub hashed_code_bytes: u64,
}

/// One reference `families` row, restricted to the fields derivable from records.
#[derive(Clone, Debug, Serialize)]
pub struct SurfaceFamilySummary {
    pub classes: u64,
    pub compose_methods: u64,
    pub fingerprint: String,
    pub runtime_enabled: &'static str,
    pub module_coverage: &'static str,
}

/// Record-level surface report.
#[derive(Clone, Debug, Serialize)]
pub struct SurfaceReport {
    pub scope: &'static str,
    pub dex_files: Vec<SurfaceDexFile>,
    pub class_records: Vec<SurfaceClassRecord>,
    pub families: BTreeMap<String, SurfaceFamilySummary>,
    pub unknown_families: Vec<String>,
    pub resource_fingerprints: BTreeMap<String, String>,
    /// Resource members whose archive name is not valid UTF-8. The reference
    /// would still emit a cp437-decoded key; this count keeps the difference
    /// visible instead of silently dropping it.
    pub resource_members_skipped_non_utf8: u64,
    /// Fields the reference emits that this provider does not produce.
    pub unproduced_fields: Vec<&'static str>,
    /// Never `true`: no HostLab qualification is claimed here.
    pub profile_admitted: bool,
}

/// Resource fingerprints bound to the captured inventory.
#[derive(Clone, Debug, Serialize)]
pub struct SurfaceResources {
    pub fingerprints: BTreeMap<String, String>,
    pub members_hashed: u64,
    pub bytes_hashed: u64,
    /// Members whose archive name is not valid UTF-8. The reference decodes such
    /// names with cp437 or replacement and would still emit a key; this provider
    /// reports the count instead of inventing a spelling.
    pub members_skipped_non_utf8: u64,
}

fn failure(code: ErrorCode, reason: &str) -> MddError {
    MddError::new(code, "facts.surface", reason)
}

fn unsupported(reason: &str) -> MddError {
    failure(ErrorCode::UnsupportedCapability, reason)
}

/// Reproduce the reference ordinal: `int(re.sub(r"\D", "", name) or 1)`.
///
/// `classes.dex` has no digits and therefore counts as 1, so it precedes
/// `classes2.dex`; `classes10.dex` counts as 10 and sorts after `classes9.dex`,
/// which is why the reported `file_id` is not the archive order.
pub fn numeric_dex_ordinal(member_name: &str) -> MddResult<u128> {
    let digits: String = member_name.chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return Ok(1);
    }
    digits.parse::<u128>().map_err(|_| {
        unsupported("DEX file ordinal is not representable")
            .detail("member_name", member_name.to_owned())
    })
}

/// Place every selected DEX in the reference numeric `file_id` order.
///
/// Refuses the two conditions the reference treats as unadmitted: a synthetic
/// `#N` logical DEX member (DEX 041) and two members whose digit strings denote
/// the same ordinal.
pub fn dex_file_order(inventory: &ArchiveInventory) -> MddResult<Vec<SurfaceDexFile>> {
    let mut rows = Vec::new();
    rows.try_reserve_exact(inventory.selected_dexes().len())
        .map_err(|_| {
            failure(
                ErrorCode::QuotaExceeded,
                "DEX file ordering allocation failed",
            )
        })?;
    for (dex_index, candidate) in inventory.selected_dexes().iter().enumerate() {
        let member_name = candidate.blob.identity.name_utf8.clone();
        let label = member_name.as_deref().unwrap_or_default();
        if label.contains('#') {
            return Err(
                unsupported("DEX 041 container fingerprint equivalence is not admitted")
                    .detail("member_name", label.to_owned()),
            );
        }
        let numeric = numeric_dex_ordinal(label)?;
        rows.push((numeric, dex_index, member_name));
    }
    rows.sort_by_key(|row| row.0);
    if rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(unsupported(
            "ambiguous numeric DEX ordering in fingerprint input",
        ));
    }
    let mut ordered = Vec::with_capacity(rows.len());
    for (file_id, (_, dex_index, member_name)) in rows.into_iter().enumerate() {
        let file_id = u32::try_from(file_id).map_err(|_| {
            failure(
                ErrorCode::QuotaExceeded,
                "DEX file ordinal exceeds the report width",
            )
        })?;
        ordered.push(SurfaceDexFile {
            file_id,
            dex_index,
            dex_occurrence_id: inventory.selected_dexes()[dex_index]
                .dex_occurrence_id
                .clone(),
            member_name,
        });
    }
    Ok(ordered)
}

/// One method awaiting ordering and digest.
struct PendingMethod {
    name: String,
    proto: String,
    /// The reference's legacy fingerprint sort key: parameters joined by one space.
    spaced: String,
    /// `(insns byte offset, insns byte length)` inside the captured DEX.
    insns: Option<(usize, usize)>,
}

/// Reproduce `native_surface.legacy_body_order` exactly.
///
/// The reference sorts fingerprint inputs by a prototype whose parameters are
/// joined with single spaces, because that was the legacy bytecode fingerprint
/// ordering. A prototype the regex could not fully tokenise was refused rather
/// than approximated, and so is it here.
pub fn legacy_body_order(proto: &str) -> MddResult<String> {
    let body = proto
        .strip_prefix('(')
        .ok_or_else(|| unsupported("method prototype is not a parenthesised prototype"))?;
    let (parameters, result) = body.split_once(')').ok_or_else(|| {
        unsupported("method prototype cannot preserve the legacy bytecode fingerprint ordering")
    })?;
    let mut tokens: Vec<&str> = Vec::new();
    let bytes = parameters.as_bytes();
    let mut at = 0usize;
    while at < bytes.len() {
        let start = at;
        while bytes.get(at) == Some(&b'[') {
            at += 1;
        }
        match bytes.get(at) {
            Some(b'Z' | b'B' | b'S' | b'C' | b'I' | b'J' | b'F' | b'D') => at += 1,
            Some(b'L') => {
                let name_start = at + 1;
                let semi = parameters[name_start..].find(';').ok_or_else(|| {
                    unsupported(
                        "method prototype cannot preserve the legacy bytecode fingerprint ordering",
                    )
                })?;
                if semi == 0 {
                    return Err(unsupported(
                        "method prototype cannot preserve the legacy bytecode fingerprint ordering",
                    ));
                }
                at = name_start + semi + 1;
            }
            _ => {
                return Err(unsupported(
                    "method prototype cannot preserve the legacy bytecode fingerprint ordering",
                ));
            }
        }
        tokens.push(&parameters[start..at]);
    }
    Ok(format!("({}){}", tokens.join(" "), result))
}

/// Build the record-level surface for one DEX occurrence.
///
/// One pass over class definitions, one over field definitions, one over method
/// definitions, then one sort and one digest pass per family record. No query is
/// issued per file and no table is re-scanned per record.
pub fn scan_dex(
    definitions: &DefinitionFacts,
    classifier: &dyn FamilyClassifier,
    file_id: u32,
    limits: SurfaceLimits,
) -> MddResult<SurfaceDexScan> {
    let metadata = definitions.metadata();
    let source = metadata.source();
    let bind = |error: MddError| {
        error
            .detail("file_id", file_id.to_string())
            .detail("snapshot_id", source.snapshot_id.clone())
            .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
    };
    if definitions.definition_coverage() != Completeness::Complete
        || metadata.metadata_coverage() != Completeness::Complete
    {
        return Err(bind(failure(
            ErrorCode::IncompleteFacts,
            "complete metadata and definitions are required",
        )));
    }
    // `MetadataFacts::build` already proved that these held bytes hash to
    // `source.content_id`; re-hashing the whole DEX here would add a second full
    // pass without adding any binding.
    let bytes = metadata.lease();
    if bytes.len() as u64 > limits.max_dex_bytes {
        return Err(bind(unsupported(
            "single DEX fingerprint input exceeds admitted memory budget",
        )));
    }
    let version = metadata.header().version.as_str();
    if !matches!(version, "035" | "036" | "037" | "038" | "039" | "040") {
        return Err(bind(
            unsupported("native raw-code fingerprint DEX version is not admitted")
                .detail("dex_version", version.to_owned()),
        ));
    }

    let dex = definitions.definitions();
    let mut records: Vec<SurfaceClassRecord> = Vec::new();
    let mut slots: Vec<Option<usize>> = vec![None; dex.classes.len()];
    let mut seen_classes: BTreeSet<&str> = BTreeSet::new();
    let mut class_budget = 0u64;

    // Pass 1: class definitions, in class_def_idx order.
    for class in &dex.classes {
        let Some(family) = classifier.family(&class.descriptor) else {
            continue;
        };
        class_budget += 1;
        if class_budget > limits.max_family_classes {
            return Err(bind(
                failure(
                    ErrorCode::QuotaExceeded,
                    "family class record budget exceeded",
                )
                .detail("limit", limits.max_family_classes.to_string()),
            ));
        }
        if !seen_classes.insert(class.descriptor.as_str()) {
            return Err(bind(unsupported(
                "duplicate class definition in native surface scan",
            )));
        }
        let slot = slots.get_mut(class.class_def_idx as usize).ok_or_else(|| {
            bind(failure(
                ErrorCode::InternalFault,
                "validated class definition index is outside the class table",
            ))
        })?;
        *slot = Some(records.len());
        records.push(SurfaceClassRecord {
            file_id,
            family,
            class: class.descriptor.clone(),
            superclass: class.superclass_descriptor.clone(),
            fields: Vec::new(),
            methods: Vec::new(),
            method_bodies_sha256: String::new(),
            compose_signatures: Vec::new(),
        });
    }

    let mut member_budget = 0u64;
    let member_limit = |count: u64, current: &mut u64| -> MddResult<()> {
        *current = current
            .checked_add(count)
            .ok_or_else(|| failure(ErrorCode::QuotaExceeded, "family member budget overflow"))?;
        if *current > limits.max_family_members {
            return Err(
                failure(ErrorCode::QuotaExceeded, "family member budget exceeded")
                    .detail("limit", limits.max_family_members.to_string()),
            );
        }
        Ok(())
    };

    // Pass 2: field definitions, in class_def_idx order, joined to their field-id row.
    for definition in &dex.field_definitions {
        let Some(record) = slots
            .get(definition.class_def_idx as usize)
            .copied()
            .flatten()
        else {
            continue;
        };
        let reference = dex
            .field_references
            .get(definition.field_idx as usize)
            .filter(|reference| reference.field_idx == definition.field_idx)
            .ok_or_else(|| {
                bind(failure(
                    ErrorCode::InternalFault,
                    "validated field definition has no matching field reference",
                ))
            })?;
        member_limit(1, &mut member_budget).map_err(bind)?;
        records[record].fields.push((
            reference.field_name.clone(),
            reference.type_descriptor.clone(),
        ));
    }

    // Pass 3: method definitions, in class_def_idx order, joined to their method-id row.
    let mut pending: Vec<Option<Vec<PendingMethod>>> = Vec::with_capacity(records.len());
    pending.resize_with(records.len(), || None);
    let mut seen_methods: BTreeSet<(usize, &str, &str)> = BTreeSet::new();
    let mut method_count = 0u64;
    for definition in &dex.method_definitions {
        let Some(record) = slots
            .get(definition.class_def_idx as usize)
            .copied()
            .flatten()
        else {
            continue;
        };
        let reference = dex
            .method_references
            .get(definition.method_idx as usize)
            .filter(|reference| reference.method_idx == definition.method_idx)
            .ok_or_else(|| {
                bind(failure(
                    ErrorCode::InternalFault,
                    "validated method definition has no matching method reference",
                ))
            })?;
        let prototype = metadata
            .prototypes()
            .get(reference.proto_idx as usize)
            .filter(|item| item.data.proto_idx == reference.proto_idx)
            .map(|item| item.data.descriptor.as_str())
            .ok_or_else(|| {
                bind(failure(
                    ErrorCode::InternalFault,
                    "validated method prototype is missing",
                ))
            })?;
        if !seen_methods.insert((record, reference.method_name.as_str(), prototype)) {
            return Err(bind(unsupported(
                "duplicate method definition in native surface scan",
            )));
        }
        let insns = match &definition.body {
            MethodBody::Present {
                code_byte_offset,
                declared_insns_size,
            } => {
                let start = code_byte_offset
                    .0
                    .checked_add(16)
                    .ok_or_else(|| bind(code_interval_error("native code interval overflow")))?;
                let length = u64::from(*declared_insns_size) * 2;
                let end = start
                    .checked_add(length)
                    .ok_or_else(|| bind(code_interval_error("native code interval overflow")))?;
                if !start.is_multiple_of(2) || end > bytes.len() as u64 {
                    return Err(bind(code_interval_error(
                        "native code interval is outside the verified DEX",
                    )));
                }
                let start = usize::try_from(start).map_err(|_| {
                    bind(code_interval_error("native code offset is not addressable"))
                })?;
                let length = usize::try_from(length).map_err(|_| {
                    bind(code_interval_error("native code length is not addressable"))
                })?;
                Some((start, length))
            }
            MethodBody::Abstract | MethodBody::Native => None,
        };
        member_limit(1, &mut member_budget).map_err(bind)?;
        method_count += 1;
        let spaced = legacy_body_order(prototype).map_err(bind)?;
        pending[record]
            .get_or_insert_with(Vec::new)
            .push(PendingMethod {
                name: reference.method_name.clone(),
                proto: prototype.to_owned(),
                spaced,
                insns,
            });
    }

    // Finalise each record: sort members, then hash the raw instruction bytes in
    // the legacy spaced-prototype order.
    let mut hashed_code_bytes = 0u64;
    let mut field_count = 0u64;
    for (index, record) in records.iter_mut().enumerate() {
        record.fields.sort();
        field_count += record.fields.len() as u64;
        let methods = pending[index].take().unwrap_or_default();
        let mut pairs: Vec<(String, String)> = methods
            .iter()
            .map(|method| (method.name.clone(), method.proto.clone()))
            .collect();
        pairs.sort();
        record.compose_signatures = pairs
            .iter()
            .filter(|(_, proto)| proto.contains("Landroidx/compose/runtime/Composer;"))
            .map(|(name, proto)| format!("{name}{proto}"))
            .collect();
        record.methods = pairs;

        let mut order: Vec<usize> = (0..methods.len()).collect();
        order.sort_by(|left, right| {
            let a = &methods[*left];
            let b = &methods[*right];
            (a.name.as_str(), a.spaced.as_str()).cmp(&(b.name.as_str(), b.spaced.as_str()))
        });
        let mut digest = Sha256::new();
        for position in order {
            let method = &methods[position];
            digest.update(method.name.as_bytes());
            digest.update(method.proto.as_bytes());
            if let Some((start, length)) = method.insns {
                hashed_code_bytes =
                    hashed_code_bytes
                        .checked_add(length as u64)
                        .ok_or_else(|| {
                            bind(failure(
                                ErrorCode::QuotaExceeded,
                                "hashed instruction byte counter overflow",
                            ))
                        })?;
                if hashed_code_bytes > limits.max_digest_bytes {
                    return Err(bind(
                        failure(
                            ErrorCode::QuotaExceeded,
                            "instruction byte digest budget exceeded",
                        )
                        .detail("limit", limits.max_digest_bytes.to_string()),
                    ));
                }
                let end = start + length;
                digest.update(&bytes[start..end]);
            }
        }
        record.method_bodies_sha256 = hex(&digest.finalize());
    }

    Ok(SurfaceDexScan {
        file_id,
        family_classes: records.len() as u64,
        family_fields: field_count,
        family_methods: method_count,
        hashed_code_bytes,
        records,
    })
}

fn code_interval_error(reason: &str) -> MddError {
    failure(ErrorCode::InvalidInput, reason)
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0xf)]));
    }
    text
}

/// Hash every `resources.arsc` and `res/*.xml` member through the captured inventory.
///
/// The reference re-opens the APK path after the DEX scan and hashes the members
/// again. Reading through the inventory keeps both fingerprints on one snapshot
/// generation and rejects a member whose held bytes disagree with its identity.
pub fn resource_fingerprints(
    inventory: &ArchiveInventory,
    limits: SurfaceLimits,
) -> MddResult<SurfaceResources> {
    let mut fingerprints = BTreeMap::new();
    let mut members_hashed = 0u64;
    let mut bytes_hashed = 0u64;
    let mut members_skipped_non_utf8 = 0u64;
    for member in &inventory.manifest().members {
        if member.is_directory {
            continue;
        }
        let raw = member.raw_name.as_slice();
        let selected =
            raw == b"resources.arsc" || (raw.starts_with(b"res/") && raw.ends_with(b".xml"));
        if !selected {
            continue;
        }
        let Some(name) = member.name_utf8.clone() else {
            members_skipped_non_utf8 += 1;
            continue;
        };
        members_hashed += 1;
        if members_hashed > limits.max_resource_members {
            return Err(failure(
                ErrorCode::QuotaExceeded,
                "resource fingerprint member budget exceeded",
            )
            .detail("limit", limits.max_resource_members.to_string()));
        }
        let blob = inventory.read_member(&member.member_id)?;
        let length = blob.bytes().len() as u64;
        bytes_hashed = bytes_hashed.checked_add(length).ok_or_else(|| {
            failure(
                ErrorCode::QuotaExceeded,
                "resource fingerprint byte counter overflow",
            )
        })?;
        if bytes_hashed > limits.max_resource_bytes {
            return Err(failure(
                ErrorCode::QuotaExceeded,
                "resource fingerprint byte budget exceeded",
            )
            .detail("limit", limits.max_resource_bytes.to_string()));
        }
        let digest = sha256(blob.bytes());
        if blob.content_id != format!("sha256:{digest}") {
            return Err(failure(
                ErrorCode::InternalFault,
                "held resource bytes disagree with their content identity",
            )
            .detail("member_id", member.member_id.clone()));
        }
        // A duplicate archive name keeps the last value, as the reference dict does.
        fingerprints.insert(name, digest);
    }
    Ok(SurfaceResources {
        fingerprints,
        members_hashed,
        bytes_hashed,
        members_skipped_non_utf8,
    })
}

/// Assemble the reference-shaped report from per-DEX scans.
///
/// `scans` must be in ascending `file_id` order, which is what
/// [`dex_file_order`] plus [`scan_dex`] produce.
pub fn build_report(
    scans: &[SurfaceDexScan],
    classifier: &dyn FamilyClassifier,
    resources: SurfaceResources,
) -> MddResult<SurfaceReport> {
    if scans
        .windows(2)
        .any(|pair| pair[0].file_id >= pair[1].file_id)
    {
        return Err(failure(
            ErrorCode::InvalidArgument,
            "surface scans are not in ascending file order",
        ));
    }
    let known = classifier.known_families();
    let known_set: BTreeSet<&str> = known.iter().map(String::as_str).collect();
    let mut groups: BTreeMap<String, Vec<&SurfaceClassRecord>> =
        known.iter().map(|key| (key.clone(), Vec::new())).collect();
    let mut class_records = Vec::new();
    for scan in scans {
        for record in &scan.records {
            groups
                .entry(record.family.clone())
                .or_default()
                .push(record);
            class_records.push(record.clone());
        }
    }
    let mut families = BTreeMap::new();
    for (key, members) in &mut groups {
        let compose_methods = members
            .iter()
            .map(|record| record.compose_signatures.len() as u64)
            .sum();
        members.sort_by(|left, right| {
            (left.class.as_str(), left.file_id).cmp(&(right.class.as_str(), right.file_id))
        });
        families.insert(
            key.clone(),
            SurfaceFamilySummary {
                classes: members.len() as u64,
                compose_methods,
                fingerprint: family_fingerprint(members),
                runtime_enabled: "unknown",
                module_coverage: "requires_installer_review",
            },
        );
    }
    let unknown_families = groups
        .keys()
        .filter(|key| !known_set.contains(key.as_str()))
        .cloned()
        .collect();
    Ok(SurfaceReport {
        scope: "family-class-method-surface-and-raw-byte-fingerprints-v1",
        dex_files: Vec::new(),
        class_records,
        families,
        unknown_families,
        resource_fingerprints: resources.fingerprints,
        resource_members_skipped_non_utf8: resources.members_skipped_non_utf8,
        unproduced_fields: vec![
            "families.*.external_invoke_edges",
            "families.*.evidence",
            "invoke_edges",
            "protocol_definitions",
            "protocol_paths",
            "protocol_twins",
            "unregistered_protocols",
            "unclassified_protocol_callers",
            "page_path_matrix",
        ],
        profile_admitted: false,
    })
}

/// `sha256(json.dumps(sorted(members, key=(class, file_id)), sort_keys=True))`
/// with CPython's default separators and `ensure_ascii=True` escaping.
fn family_fingerprint(members: &[&SurfaceClassRecord]) -> String {
    let mut text = String::from("[");
    for (position, record) in members.iter().enumerate() {
        if position > 0 {
            text.push_str(", ");
        }
        push_record_json(&mut text, record);
    }
    text.push(']');
    sha256(text.as_bytes())
}

/// One record with the reference's `sort_keys=True` key order.
fn push_record_json(out: &mut String, record: &SurfaceClassRecord) {
    out.push_str("{\"class\": ");
    push_json_string(out, &record.class);
    out.push_str(", \"compose_signatures\": [");
    for (position, signature) in record.compose_signatures.iter().enumerate() {
        if position > 0 {
            out.push_str(", ");
        }
        push_json_string(out, signature);
    }
    out.push_str("], \"family\": ");
    push_json_string(out, &record.family);
    out.push_str(", \"fields\": [");
    push_pairs_json(out, &record.fields);
    out.push_str("], \"file_id\": ");
    out.push_str(&record.file_id.to_string());
    out.push_str(", \"method_bodies_sha256\": ");
    push_json_string(out, &record.method_bodies_sha256);
    out.push_str(", \"methods\": [");
    push_pairs_json(out, &record.methods);
    out.push_str("], \"superclass\": ");
    match &record.superclass {
        None => out.push_str("null"),
        Some(value) => push_json_string(out, value),
    }
    out.push('}');
}

fn push_pairs_json(out: &mut String, pairs: &[(String, String)]) {
    for (position, (left, right)) in pairs.iter().enumerate() {
        if position > 0 {
            out.push_str(", ");
        }
        out.push('[');
        push_json_string(out, left);
        out.push_str(", ");
        push_json_string(out, right);
        out.push(']');
    }
}

/// CPython `json.dumps(..., ensure_ascii=True)` string escaping.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            character if (character as u32) < 0x20 => {
                push_u16_escape(out, character as u16);
            }
            character if (character as u32) <= 0x7e => out.push(character),
            character if (character as u32) <= 0xffff => {
                push_u16_escape(out, character as u16);
            }
            character => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    push_u16_escape(out, *unit);
                }
            }
        }
    }
    out.push('"');
}

fn push_u16_escape(out: &mut String, unit: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    for shift in [12, 8, 4, 0] {
        out.push(char::from(HEX[usize::from((unit >> shift) & 0xf)]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetadataFacts;
    use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
    use mdd_input::{
        archive::{ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
    };
    use std::path::PathBuf;

    struct FixtureFamilies;
    impl FamilyClassifier for FixtureFamilies {
        fn family(&self, class_descriptor: &str) -> Option<String> {
            class_descriptor
                .starts_with("Lfixture/")
                .then(|| "fixture".to_owned())
        }
        fn known_families(&self) -> Vec<String> {
            vec!["fixture".to_owned(), "absent".to_owned()]
        }
    }

    fn fixture(name: &str) -> (Snapshot, ArchiveInventory, DefinitionFacts) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(name);
        let kind = if name.ends_with(".apk") {
            InputKind::Apk
        } else {
            InputKind::RawDex
        };
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path,
                kind,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        (snapshot, inventory, definitions)
    }

    #[test]
    fn legacy_body_order_matches_the_reference_spaced_prototypes() {
        assert_eq!(legacy_body_order("()V").unwrap(), "()V");
        assert_eq!(legacy_body_order("(I)V").unwrap(), "(I)V");
        assert_eq!(legacy_body_order("(ILx;)V").unwrap(), "(I Lx;)V");
        assert_eq!(
            legacy_body_order("(I[Ljava/lang/String;)V").unwrap(),
            "(I [Ljava/lang/String;)V"
        );
        assert_eq!(
            legacy_body_order("(Z[B[S[C[I[J[F[D)Lx;").unwrap(),
            "(Z [B [S [C [I [J [F [D)Lx;"
        );
        // The reference splits on the first `)`, so trailing text lands in the
        // result half and is preserved verbatim instead of being rejected.
        assert_eq!(legacy_body_order("(I)V)").unwrap(), "(I)V)");
        for bad in ["(Q)V", "(I", "Lx;->a()V", "(L;)V", "(V)V"] {
            assert!(
                legacy_body_order(bad).is_err(),
                "{bad} must not be approximated"
            );
        }
    }

    #[test]
    fn canonical_json_matches_cpython_ensure_ascii() {
        let mut text = String::new();
        push_json_string(&mut text, "Lfixture/compose/A;");
        assert_eq!(text, "\"Lfixture/compose/A;\"");
        text.clear();
        push_json_string(&mut text, "a\u{7f}b");
        assert_eq!(text, "\"a\\u007fb\"");
        text.clear();
        push_json_string(&mut text, "a\u{1}b");
        assert_eq!(text, "\"a\\u0001b\"");
        text.clear();
        push_json_string(&mut text, "a\u{8}b\u{c}c");
        assert_eq!(text, "\"a\\bb\\fc\"");
        text.clear();
        push_json_string(&mut text, "caf\u{e9}");
        assert_eq!(text, "\"caf\\u00e9\"");
        text.clear();
        push_json_string(&mut text, "a\u{1f600}b");
        assert_eq!(text, "\"a\\ud83d\\ude00b\"");
        text.clear();
        push_json_string(&mut text, "a\"b\\c\td\ne");
        assert_eq!(text, "\"a\\\"b\\\\c\\td\\ne\"");

        let record = SurfaceClassRecord {
            file_id: 3,
            family: "comment_compose".into(),
            class: "Lfixture/compose/A;".into(),
            superclass: Some("Ljava/lang/Object;".into()),
            fields: vec![
                ("a".into(), "I".into()),
                ("b".into(), "Ljava/lang/String;".into()),
            ],
            methods: vec![
                ("a".into(), "()V".into()),
                ("b".into(), "(ILjava/util/List;)Lkotlin/Unit;".into()),
            ],
            method_bodies_sha256: "0".repeat(64),
            compose_signatures: vec!["b(ILjava/util/List;)Lkotlin/Unit;".into()],
        };
        let mut text = String::new();
        push_record_json(&mut text, &record);
        assert_eq!(
            text,
            concat!(
                "{\"class\": \"Lfixture/compose/A;\", \"compose_signatures\": ",
                "[\"b(ILjava/util/List;)Lkotlin/Unit;\"], \"family\": \"comment_compose\", ",
                "\"fields\": [[\"a\", \"I\"], [\"b\", \"Ljava/lang/String;\"]], ",
                "\"file_id\": 3, \"method_bodies_sha256\": \"",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "\", \"methods\": [[\"a\", \"()V\"], ",
                "[\"b\", \"(ILjava/util/List;)Lkotlin/Unit;\"]], ",
                "\"superclass\": \"Ljava/lang/Object;\"}"
            )
        );
    }

    #[test]
    fn empty_family_fingerprint_is_the_cpython_empty_list_digest() {
        assert_eq!(
            family_fingerprint(&[]),
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
    }

    #[test]
    fn structured_fixture_digest_matches_an_independent_python_oracle() {
        // Produced by an independent Python re-implementation of the reference
        // digest over this fixture: sha256(name+proto then raw insns) in legacy
        // spaced-prototype order.
        let (_, _, definitions) = fixture("tests/fixtures/generated/structured-035.dex");
        let scan = scan_dex(&definitions, &FixtureFamilies, 0, SurfaceLimits::default()).unwrap();
        assert_eq!(scan.family_classes, 1);
        assert_eq!(scan.family_fields, 0);
        assert_eq!(scan.family_methods, 4);
        let record = &scan.records[0];
        assert_eq!(record.class, "Lfixture/A;");
        assert_eq!(record.superclass.as_deref(), Some("Ljava/lang/Object;"));
        assert_eq!(
            record.methods,
            vec![
                ("caller".to_owned(), "()V".to_owned()),
                ("nativeNoBody".to_owned(), "()V".to_owned()),
                ("target".to_owned(), "()V".to_owned()),
                ("withTry".to_owned(), "()V".to_owned()),
            ]
        );
        assert_eq!(record.method_bodies_sha256, FIXTURE_DIGEST);
        assert!(record.compose_signatures.is_empty());
        assert_eq!(scan.hashed_code_bytes, (7 + 1 + 4) * 2);
    }

    // `sha256(b"caller()V" + insns(304+16,14) + b"nativeNoBody()V"
    // + b"target()V" + insns(336+16,2) + b"withTry()V" + insns(356+16,8))`.
    // The byte intervals come from an independent struct-level DEX walk.
    const FIXTURE_DIGEST: &str = "58b3a560272e99173f18d481ab8d40e92d72faee125293238e2bc90501d96206";

    #[test]
    fn absent_family_keeps_a_zero_row_and_unknown_family_is_listed() {
        let (_, _, definitions) = fixture("tests/fixtures/generated/structured-035.dex");
        let scan = scan_dex(&definitions, &FixtureFamilies, 0, SurfaceLimits::default()).unwrap();
        let resources = SurfaceResources {
            fingerprints: BTreeMap::new(),
            members_hashed: 0,
            bytes_hashed: 0,
            members_skipped_non_utf8: 0,
        };
        let report = build_report(&[scan], &FixtureFamilies, resources).unwrap();
        assert_eq!(report.families["fixture"].classes, 1);
        assert_eq!(report.families["absent"].classes, 0);
        assert_eq!(
            report.families["absent"].fingerprint,
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
        assert!(report.unknown_families.is_empty());
        assert!(!report.profile_admitted);
        assert_eq!(report.class_records.len(), 1);
    }

    #[test]
    fn dex_file_order_is_numeric_and_rejects_ambiguous_ordinals() {
        let (_, inventory, _) = fixture("tests/fixtures/generated/structured-035.dex");
        let ordered = dex_file_order(&inventory).unwrap();
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].file_id, 0);
        assert_eq!(ordered[0].member_name, None);

        // The reference ordinal is the integer formed from the member's digits,
        // with no digits counting as 1, so lexical archive order is not used.
        assert_eq!(numeric_dex_ordinal("classes.dex").unwrap(), 1);
        assert_eq!(numeric_dex_ordinal("classes2.dex").unwrap(), 2);
        assert_eq!(numeric_dex_ordinal("classes9.dex").unwrap(), 9);
        assert_eq!(numeric_dex_ordinal("classes10.dex").unwrap(), 10);
        assert_eq!(numeric_dex_ordinal("classes33.dex").unwrap(), 33);
        assert_eq!(numeric_dex_ordinal("anything.dex").unwrap(), 1);
        assert_eq!(numeric_dex_ordinal("classes0.dex").unwrap(), 0);
        assert!(
            numeric_dex_ordinal("classes99999999999999999999999999999999999999999.dex").is_err()
        );

        let mut names = vec!["classes10.dex", "classes2.dex", "classes.dex"];
        names.sort_by_key(|name| numeric_dex_ordinal(name).unwrap());
        assert_eq!(names, vec!["classes.dex", "classes2.dex", "classes10.dex"]);
    }

    #[test]
    fn resource_fingerprints_cover_arsc_and_res_xml_only() {
        let (_, inventory, _) = fixture("tests/fixtures/generated/multidex-stored.apk");
        let resources = resource_fingerprints(&inventory, SurfaceLimits::default()).unwrap();
        // The fixture has no resources.arsc and no res/ members.
        assert!(resources.fingerprints.is_empty());
        assert_eq!(resources.members_hashed, 0);
        assert_eq!(resources.members_skipped_non_utf8, 0);
    }
}
