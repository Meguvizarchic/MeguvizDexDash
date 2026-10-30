//! Snapshot-bound raw byte evidence; naming, selection and business ordering live above it.
use crate::{
    code::CodeFacts,
    definitions::DefinitionFacts,
    metadata::{EntityKind, EntityRef, MetadataSource},
};
use mdd_dex::{DexRange, definitions::MethodBody};
use mdd_input::{
    archive::{ArchiveInventory, MemberIdentity},
    manifest::{ManifestDocument, ManifestLimits, parse_manifest},
    snapshot::Snapshot,
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult, content_id, sha256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Copy, Debug)]
pub struct FingerprintLimits {
    pub max_method_records: u64,
    pub max_total_body_bytes: u64,
    pub max_recipe_bytes: u64,
}
impl Default for FingerprintLimits {
    fn default() -> Self {
        Self {
            max_method_records: 1_000_000,
            max_total_body_bytes: 1024 * 1024 * 1024,
            max_recipe_bytes: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawBodyKind {
    Present,
    NativeNoBody,
    AbstractNoBody,
}

#[derive(Clone, Debug, Serialize)]
pub struct MethodByteEvidence {
    pub method: EntityRef,
    pub body_kind: RawBodyKind,
    pub code_item_byte_offset: Option<DecimalU64>,
    pub insns_range: Option<DexRange>,
    pub sha256: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct RawCodeEvidence {
    source: MetadataSource,
    methods: Vec<MethodByteEvidence>,
    #[serde(skip)]
    method_index: BTreeMap<u32, usize>,
    scope: String,
    max_recipe_bytes: DecimalU64,
    max_recipe_parts: DecimalU64,
    #[serde(skip)]
    bytes: Arc<[u8]>,
}

fn error(code: ErrorCode, stage: &str, message: &str) -> MddError {
    MddError::new(code, stage, message)
}

fn checked<'a>(bytes: &'a [u8], range: &DexRange) -> MddResult<&'a [u8]> {
    let end = range
        .byte_offset
        .0
        .checked_add(range.byte_length.0)
        .ok_or_else(|| error(ErrorCode::InvalidInput, "raw.range", "byte range overflow"))?;
    let start = usize::try_from(range.byte_offset.0).map_err(|_| {
        error(
            ErrorCode::InvalidInput,
            "raw.range",
            "byte offset is not addressable",
        )
    })?;
    let end = usize::try_from(end).map_err(|_| {
        error(
            ErrorCode::InvalidInput,
            "raw.range",
            "byte end is not addressable",
        )
    })?;
    bytes.get(start..end).ok_or_else(|| {
        error(
            ErrorCode::InvalidInput,
            "raw.range",
            "raw interval exceeds held blob",
        )
    })
}

impl RawCodeEvidence {
    pub fn build(
        definitions: &DefinitionFacts,
        code: &CodeFacts,
        limits: FingerprintLimits,
    ) -> MddResult<Self> {
        let source = definitions.metadata().source();
        let bind = |failure: MddError| {
            failure
                .detail("snapshot_id", source.snapshot_id.clone())
                .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
                .detail("content_id", source.content_id.clone())
        };
        if source.snapshot_id != code.source().snapshot_id
            || source.dex_occurrence_id != code.source().dex_occurrence_id
            || source.content_id != code.source().content_id
        {
            return Err(bind(error(
                ErrorCode::InvalidArgument,
                "raw.code",
                "definitions/code do not bind the same source generation",
            )));
        }
        if definitions.definition_coverage() != mdd_types::Completeness::Complete
            || code.code_layout_coverage() != mdd_types::Completeness::Complete
        {
            return Err(bind(error(
                ErrorCode::IncompleteFacts,
                "raw.code",
                "complete definition and requested code-layout facts are required",
            )));
        }
        let bytes = code.lease();
        if content_id(&bytes) != source.content_id {
            return Err(bind(error(
                ErrorCode::InternalFault,
                "raw.code",
                "held raw blob identity differs",
            )));
        }
        let count = definitions.definitions().method_definitions.len() as u64;
        if count > limits.max_method_records {
            return Err(bind(
                error(
                    ErrorCode::QuotaExceeded,
                    "raw.code",
                    "method evidence record budget exceeded",
                )
                .detail("budget", "max_method_records")
                .detail("limit", limits.max_method_records.to_string()),
            ));
        }
        let by_offset: BTreeMap<_, _> = code
            .items()
            .iter()
            .map(|item| (item.data().raw_range.byte_offset.0, item.data()))
            .collect();
        let mut methods = Vec::new();
        methods.try_reserve_exact(count as usize).map_err(|_| {
            bind(error(
                ErrorCode::QuotaExceeded,
                "raw.code",
                "method evidence allocation failed",
            ))
        })?;
        let mut method_index = BTreeMap::new();
        let mut total = 0u64;
        for method in &definitions.definitions().method_definitions {
            // The immutable, completely validated definitions are the source
            // of this identity; searching the same collection again per item
            // adds no validation and makes the join quadratic.
            let entity = EntityRef {
                snapshot_id: source.snapshot_id.clone(),
                dex_occurrence_id: source.dex_occurrence_id.clone(),
                kind: EntityKind::MethodDefinition,
                local_index: method.method_idx,
            };
            if method_index
                .insert(method.method_idx, methods.len())
                .is_some()
            {
                return Err(bind(error(
                    ErrorCode::InternalFault,
                    "raw.code",
                    "validated method definition identity is duplicated",
                )));
            }
            let (body_kind, offset, range, digest) = match &method.body {
                MethodBody::Native => (RawBodyKind::NativeNoBody, None, None, None),
                MethodBody::Abstract => (RawBodyKind::AbstractNoBody, None, None, None),
                MethodBody::Present {
                    code_byte_offset,
                    declared_insns_size,
                } => {
                    let at = code_byte_offset.0;
                    if !code.known_code_item_start(at) {
                        return Err(bind(
                            error(
                                ErrorCode::InvalidInput,
                                "raw.code",
                                "method body does not name a physical code_item start",
                            )
                            .detail("method_idx", method.method_idx.to_string())
                            .detail("code_item_byte_offset", at.to_string()),
                        ));
                    }
                    let item = by_offset.get(&at).ok_or_else(|| {
                        bind(
                            error(
                                ErrorCode::IncompleteFacts,
                                "raw.code",
                                "a real method code item is absent from the provided projection",
                            )
                            .detail("method_idx", method.method_idx.to_string())
                            .detail("code_item_byte_offset", at.to_string()),
                        )
                    })?;
                    let expected = u64::from(*declared_insns_size) * 2;
                    if item.insns_size_code_units != *declared_insns_size
                        || item.insns_range.byte_length.0 != expected
                        || item.insns_range.byte_offset.0 != at + 16
                    {
                        return Err(bind(error(
                            ErrorCode::InternalFault,
                            "raw.code",
                            "independently built definition/code raw intervals disagree",
                        )));
                    }
                    total = total.checked_add(expected).ok_or_else(|| {
                        bind(error(
                            ErrorCode::QuotaExceeded,
                            "raw.code",
                            "total raw method bytes overflow",
                        ))
                    })?;
                    if total > limits.max_total_body_bytes {
                        return Err(bind(
                            error(
                                ErrorCode::QuotaExceeded,
                                "raw.code",
                                "raw method byte budget exceeded",
                            )
                            .detail("budget", "max_total_body_bytes")
                            .detail("limit", limits.max_total_body_bytes.to_string()),
                        ));
                    }
                    let raw = checked(&bytes, &item.insns_range).map_err(bind)?;
                    (
                        RawBodyKind::Present,
                        Some(*code_byte_offset),
                        Some(item.insns_range.clone()),
                        Some(sha256(raw)),
                    )
                }
            };
            methods.push(MethodByteEvidence {
                method: entity,
                body_kind,
                code_item_byte_offset: offset,
                insns_range: range,
                sha256: digest,
            });
        }
        Ok(Self {
            source: source.clone(),
            methods,
            method_index,
            scope: "raw-insns-bytes-for-all-defined-methods-v1".into(),
            max_recipe_bytes: DecimalU64(limits.max_recipe_bytes),
            max_recipe_parts: DecimalU64(limits.max_method_records),
            bytes,
        })
    }
    pub fn source(&self) -> &MetadataSource {
        &self.source
    }
    pub fn methods(&self) -> &[MethodByteEvidence] {
        &self.methods
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn raw_method_body(&self, method: &EntityRef) -> MddResult<Option<&[u8]>> {
        if method.snapshot_id != self.source.snapshot_id
            || method.dex_occurrence_id != self.source.dex_occurrence_id
            || method.kind != EntityKind::MethodDefinition
        {
            return Err(error(
                ErrorCode::InvalidArgument,
                "raw.code",
                "method identity belongs to another source or entity kind",
            ));
        }
        let record = self
            .method_index
            .get(&method.local_index)
            .and_then(|ordinal| self.methods.get(*ordinal))
            .ok_or_else(|| {
                error(
                    ErrorCode::InvalidArgument,
                    "raw.code",
                    "method definition is not in the validated scope",
                )
            })?;
        record
            .insns_range
            .as_ref()
            .map(|range| checked(&self.bytes, range))
            .transpose()
    }
    /// The caller supplies the explicit order and prefix bytes. No business sorting is embedded here.
    pub fn ordered_digest(
        &self,
        parts: &[(&EntityRef, &[u8])],
        max_bytes: u64,
    ) -> MddResult<String> {
        let max_bytes = max_bytes.min(self.max_recipe_bytes.0);
        if parts.len() as u64 > self.max_recipe_parts.0 {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "raw.recipe",
                "explicit recipe part budget exceeded",
            ));
        }
        let mut digest = Sha256::new();
        let mut total = 0u64;
        for (method, prefix) in parts {
            let body = self.raw_method_body(method)?.unwrap_or(&[]);
            total = total
                .checked_add(prefix.len() as u64)
                .and_then(|n| n.checked_add(body.len() as u64))
                .ok_or_else(|| {
                    error(
                        ErrorCode::QuotaExceeded,
                        "raw.recipe",
                        "recipe byte counter overflow",
                    )
                })?;
            if total > max_bytes {
                return Err(error(
                    ErrorCode::QuotaExceeded,
                    "raw.recipe",
                    "explicit recipe byte budget exceeded",
                ));
            }
            digest.update(prefix);
            digest.update(body);
        }
        Ok(digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }
}

#[derive(Clone, Serialize)]
pub struct ResourceByteEvidence {
    snapshot_id: String,
    source_content_id: String,
    member: MemberIdentity,
    content_id: String,
    sha256: String,
    byte_length: DecimalU64,
    #[serde(skip)]
    bytes: Arc<[u8]>,
}

#[derive(Clone, Serialize)]
pub struct ManifestByteEvidence {
    resource: ResourceByteEvidence,
    document: ManifestDocument,
}

impl ManifestByteEvidence {
    pub fn build(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        limits: ManifestLimits,
    ) -> MddResult<Self> {
        let matches: Vec<_> = inventory
            .manifest()
            .members
            .iter()
            .filter(|member| member.raw_name == b"AndroidManifest.xml" && !member.is_directory)
            .collect();
        let member = match matches.as_slice() {
            [] => {
                return Err(error(
                    ErrorCode::PartialInput,
                    "manifest",
                    "required AndroidManifest.xml member is missing",
                ));
            }
            [member] => *member,
            _ => {
                return Err(error(
                    ErrorCode::AmbiguousEntity,
                    "manifest",
                    "multiple physical AndroidManifest.xml members require an explicit selection",
                ));
            }
        };
        let resource = ResourceByteEvidence::build(snapshot, inventory, &member.member_id)?;
        let document = parse_manifest(resource.lease(), limits).map_err(|failure| {
            failure
                .detail("snapshot_id", snapshot.manifest().snapshot_id.clone())
                .detail("member_id", member.member_id.clone())
                .detail("content_id", resource.content_id().to_owned())
        })?;
        if content_id(document.bytes()) != resource.content_id() {
            return Err(error(
                ErrorCode::InternalFault,
                "manifest",
                "parsed document and raw fingerprint do not bind identical bytes",
            ));
        }
        Ok(Self { resource, document })
    }
    pub fn resource(&self) -> &ResourceByteEvidence {
        &self.resource
    }
    pub fn document(&self) -> &ManifestDocument {
        &self.document
    }
}

impl ResourceByteEvidence {
    pub fn build(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        member_id: &str,
    ) -> MddResult<Self> {
        let manifest = inventory.manifest();
        if !snapshot.manifest().sources.iter().any(|source| {
            source.occurrence_id == manifest.source_occurrence_id
                && source.content_id == manifest.source_content_id
        }) {
            return Err(error(
                ErrorCode::InvalidArgument,
                "raw.resource",
                "inventory does not belong to snapshot",
            ));
        }
        let blob = inventory.read_member(member_id)?;
        let digest = sha256(blob.bytes());
        if blob.identity.source_occurrence_id != manifest.source_occurrence_id
            || blob.content_id != format!("sha256:{digest}")
        {
            return Err(error(
                ErrorCode::InternalFault,
                "raw.resource",
                "held resource identity mismatch",
            ));
        }
        Ok(Self {
            snapshot_id: snapshot.manifest().snapshot_id.clone(),
            source_content_id: manifest.source_content_id.clone(),
            member: blob.identity.clone(),
            content_id: blob.content_id.clone(),
            sha256: digest,
            byte_length: DecimalU64(blob.bytes().len() as u64),
            bytes: blob.lease(),
        })
    }
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
    pub fn member(&self) -> &MemberIdentity {
        &self.member
    }
    pub fn content_id(&self) -> &str {
        &self.content_id
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn lease(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
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
    use std::{fs, path::PathBuf};

    fn facts(relative: &str) -> (Snapshot, ArchiveInventory, DefinitionFacts, CodeFacts) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path,
                kind: InputKind::RawDex,
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
        let code = CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
            .unwrap();
        (snapshot, inventory, definitions, code)
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn raw_body_bytes_and_explicit_order_match_handwritten_python_digests() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/raw_fingerprints/expected.json"
        ))
        .unwrap();
        let (snapshot, inventory, definitions, code) =
            facts("tests/fixtures/generated/structured-035.dex");
        let evidence =
            RawCodeEvidence::build(&definitions, &code, FingerprintLimits::default()).unwrap();
        let mut prefixes = Vec::new();
        for row in expected["methods"].as_array().unwrap() {
            let id = definitions
                .entity(
                    EntityKind::MethodDefinition,
                    row["method_idx"].as_u64().unwrap() as u32,
                )
                .unwrap();
            let record = evidence
                .methods()
                .iter()
                .find(|record| record.method == id)
                .unwrap();
            assert_eq!(
                serde_json::to_value(record.body_kind).unwrap(),
                row["body_kind"]
            );
            assert_eq!(serde_json::to_value(&record.sha256).unwrap(), row["sha256"]);
            assert_eq!(
                serde_json::to_value(evidence.raw_method_body(&id).unwrap().map(hex)).unwrap(),
                row["raw_hex"]
            );
            prefixes.push((id, row["prefix"].as_str().unwrap().as_bytes().to_vec()));
        }
        let parts: Vec<_> = prefixes
            .iter()
            .map(|(id, prefix)| (id, prefix.as_slice()))
            .collect();
        assert_eq!(
            evidence.ordered_digest(&parts, u64::MAX).unwrap(),
            expected["ordered_recipe_sha256"]
        );
        let reversed: Vec<_> = parts.iter().copied().rev().collect();
        assert_ne!(
            evidence.ordered_digest(&reversed, u64::MAX).unwrap(),
            expected["ordered_recipe_sha256"]
        );
        drop(snapshot);
        drop(inventory);
        drop(definitions);
        drop(code);
        assert_eq!(
            hex(evidence.raw_method_body(&prefixes[0].0).unwrap().unwrap()),
            "7100020000007100020000000e00"
        );
    }

    #[test]
    fn missing_projection_bad_item_source_and_zero_quotas_fail_closed() {
        let (snapshot, inventory, definitions, code) =
            facts("tests/fixtures/generated/structured-035.dex");
        let partial =
            CodeFacts::build_offsets(&snapshot, &inventory, 0, &[304], CodeLimits::default())
                .unwrap();
        assert_eq!(
            RawCodeEvidence::build(&definitions, &partial, FingerprintLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let (_, _, _, foreign) = facts("tests/fixtures/generated/structured-035.dex");
        assert_eq!(
            RawCodeEvidence::build(&definitions, &foreign, FingerprintLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        for limits in [
            FingerprintLimits {
                max_method_records: 0,
                ..FingerprintLimits::default()
            },
            FingerprintLimits {
                max_total_body_bytes: 0,
                ..FingerprintLimits::default()
            },
        ] {
            assert_eq!(
                RawCodeEvidence::build(&definitions, &code, limits)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
        let evidence = RawCodeEvidence::build(
            &definitions,
            &code,
            FingerprintLimits {
                max_recipe_bytes: 0,
                ..FingerprintLimits::default()
            },
        )
        .unwrap();
        let native = definitions.entity(EntityKind::MethodDefinition, 1).unwrap();
        assert_eq!(
            evidence
                .ordered_digest(&[(&native, b"prefix")], u64::MAX)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let (_, _, bad_defs, bad_code) =
            facts("tests/fixtures/raw_fingerprints/bad-code-item-reference.dex");
        assert_eq!(
            RawCodeEvidence::build(&bad_defs, &bad_code, FingerprintLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn present_empty_insns_has_empty_digest_not_absent_body() {
        let (_, _, definitions, code) =
            facts("tests/fixtures/definitions/generated/zero-insns-present.dex");
        let evidence =
            RawCodeEvidence::build(&definitions, &code, FingerprintLimits::default()).unwrap();
        let empty = evidence
            .methods()
            .iter()
            .find(|record| {
                record.body_kind == RawBodyKind::Present
                    && record
                        .insns_range
                        .as_ref()
                        .is_some_and(|range| range.byte_length.0 == 0)
            })
            .unwrap();
        assert_eq!(
            empty.sha256.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            evidence.raw_method_body(&empty.method).unwrap(),
            Some(&[][..])
        );
    }

    #[test]
    fn raw_evidence_keeps_occurrences_shared_bodies_and_unique_definitions() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/shared-code-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut definitions = Vec::new();
        let mut codes = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            definitions
                .push(DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap());
            codes.push(
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                    .unwrap(),
            );
        }
        let left = RawCodeEvidence::build(&definitions[0], &codes[0], FingerprintLimits::default())
            .unwrap();
        let right =
            RawCodeEvidence::build(&definitions[1], &codes[1], FingerprintLimits::default())
                .unwrap();
        assert_eq!(left.methods().len(), right.methods().len());
        assert_ne!(
            left.source().dex_occurrence_id,
            right.source().dex_occurrence_id
        );
        for (a, b) in left.methods().iter().zip(right.methods()) {
            assert_eq!(a.method.local_index, b.method.local_index);
            assert_ne!(a.method.dex_occurrence_id, b.method.dex_occurrence_id);
            assert_eq!(a.body_kind, b.body_kind);
            assert_eq!(a.sha256, b.sha256);
            assert_eq!(
                left.raw_method_body(&a.method).unwrap(),
                right.raw_method_body(&b.method).unwrap()
            );
            assert_eq!(
                left.raw_method_body(&b.method).unwrap_err().code,
                ErrorCode::InvalidArgument
            );
        }
        let shared = left.methods().iter().enumerate().any(|(i, a)| {
            a.code_item_byte_offset.is_some()
                && left.methods()[i + 1..].iter().any(|b| {
                    a.method.local_index != b.method.local_index
                        && a.code_item_byte_offset == b.code_item_byte_offset
                        && a.sha256 == b.sha256
                })
        });
        assert!(
            shared,
            "fixture must contain distinct owners of one code item"
        );

        let mut inconsistent = definitions[0].clone();
        inconsistent
            .definitions
            .method_definitions
            .push(inconsistent.definitions.method_definitions[0].clone());
        assert_eq!(
            RawCodeEvidence::build(&inconsistent, &codes[0], FingerprintLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
    }

    #[test]
    fn resource_fingerprint_is_raw_same_snapshot_and_survives_source_mutation() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/raw_fingerprints/expected.json"
        ))
        .unwrap();
        let dir = std::env::temp_dir().join(mdd_types::opaque_id("raw-resource-test").unwrap());
        fs::create_dir(&dir).unwrap();
        let path = dir.join("input.apk");
        fs::write(
            &path,
            include_bytes!("../../../tests/fixtures/generated/multidex-stored.apk"),
        )
        .unwrap();
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path: path.clone(),
                kind: InputKind::Apk,
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
        let member = inventory
            .manifest()
            .members
            .iter()
            .find(|member| member.raw_name == b"assets/raw.bin")
            .unwrap();
        let evidence =
            ResourceByteEvidence::build(&snapshot, &inventory, &member.member_id).unwrap();
        let manifest =
            ManifestByteEvidence::build(&snapshot, &inventory, ManifestLimits::default()).unwrap();
        assert_eq!(manifest.document().nodes().len(), 1);
        assert_eq!(manifest.document().bytes(), manifest.resource().bytes());
        assert!(Arc::ptr_eq(
            &manifest.document().lease(),
            &manifest.resource().lease()
        ));
        assert_eq!(
            evidence.sha256(),
            expected["resource_sha256"].as_str().unwrap()
        );
        assert_eq!(hex(evidence.bytes()), expected["resource_raw_hex"]);
        let (_, foreign, _, _) = facts("tests/fixtures/generated/structured-035.dex");
        assert_eq!(
            ResourceByteEvidence::build(&snapshot, &foreign, "bad")
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        fs::write(&path, b"new source generation").unwrap();
        fs::rename(&path, dir.join("renamed.apk")).unwrap();
        drop(snapshot);
        drop(inventory);
        assert_eq!(hex(evidence.bytes()), expected["resource_raw_hex"]);
        assert_eq!(manifest.document().bytes(), manifest.resource().bytes());
    }
}
