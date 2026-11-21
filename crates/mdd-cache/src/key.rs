//! Canonical deterministic cache key construction without path or mtime dependence.

use mdd_input::{
    archive::ArchiveInventory,
    snapshot::{CaptureLimits, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult, sha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DEFAULT_CACHE_FORMAT: &str = "mdd-index/1";
pub const DEFAULT_FACT_SCHEMA_VERSION: &str = "mdd.facts.cache.v1";
pub const DEFAULT_PARSER_SEMANTICS_VERSION: &str = "mdd-dex-parser-v1";
pub const DEFAULT_VALIDATOR_POLICY: &str = "standard-le-header-map-fixed-references-v2";
pub const DEFAULT_TEXT_SEMANTICS_VERSION: &str = "mutf8-lossless-utf16-v1";
pub const DEFAULT_INSTRUCTION_SEMANTICS_VERSION: &str = "dalvik-bytecode-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    Standalone,
    Thin,
}

impl CacheMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Thin => "thin",
        }
    }
}

/// Content- and offset-addressed identity of one selected archive member or logical DEX.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberKey {
    pub member_ordinal: u64,
    pub raw_name_hex: String,
    pub content_id: String,
    pub byte_length: u64,
    pub logical_header_offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_dependency_sha256: Option<String>,
}

/// Positional source occurrence binding content identity while preserving multiplicity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceOccurrenceKey {
    pub input_ordinal: u64,
    pub content_id: String,
    pub byte_length: u64,
    pub input_kind: String,
    pub selected_members: Vec<MemberKey>,
}

/// Explicit semantic version tuple covered by the fact cache key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticsIdentity {
    pub cache_format: String,
    pub fact_schema_version: String,
    pub parser_semantics_version: String,
    pub validator_policy: String,
    pub text_semantics_version: String,
    pub instruction_semantics_version: String,
    pub profile: String,
    pub non_scalar_text_policy: String,
    pub selection_policy: String,
    pub provider_identities: BTreeMap<String, String>,
}

impl Default for SemanticsIdentity {
    fn default() -> Self {
        Self {
            cache_format: DEFAULT_CACHE_FORMAT.to_owned(),
            fact_schema_version: DEFAULT_FACT_SCHEMA_VERSION.to_owned(),
            parser_semantics_version: DEFAULT_PARSER_SEMANTICS_VERSION.to_owned(),
            validator_policy: DEFAULT_VALIDATOR_POLICY.to_owned(),
            text_semantics_version: DEFAULT_TEXT_SEMANTICS_VERSION.to_owned(),
            instruction_semantics_version: DEFAULT_INSTRUCTION_SEMANTICS_VERSION.to_owned(),
            profile: "mdd-facts-v1".to_owned(),
            non_scalar_text_policy: "reject".to_owned(),
            selection_policy: "top-level-classes".to_owned(),
            provider_identities: BTreeMap::new(),
        }
    }
}

/// Canonical key spec for persistent fact caches.
///
/// File paths, timestamps (`mtime`/`ctime`), host temp paths, and transient session IDs are
/// deliberately excluded; identical inputs with different occurrence multiplicity produce distinct
/// keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactCacheKeySpec {
    pub semantics: SemanticsIdentity,
    pub occurrences: Vec<SourceOccurrenceKey>,
}

impl FactCacheKeySpec {
    pub fn from_snapshot_and_inventories(
        snapshot: &Snapshot,
        inventories: &[ArchiveInventory],
        semantics: SemanticsIdentity,
    ) -> MddResult<Self> {
        let sources = snapshot.sources();
        if sources.len() != inventories.len() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cache.key",
                "snapshot sources count disagrees with inventories count",
            ));
        }
        let mut occurrences = Vec::with_capacity(sources.len());
        for (source, inventory) in sources.iter().zip(inventories.iter()) {
            let ident = source.identity();
            let inv_manifest = inventory.manifest();
            if ident.occurrence_id != inv_manifest.source_occurrence_id
                || ident.content_id != inv_manifest.source_content_id
            {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "cache.key",
                    "inventory does not match snapshot source occurrence",
                ));
            }
            let selected_members = inventory
                .selected_dexes()
                .iter()
                .enumerate()
                .map(|(ordinal, cand)| {
                    let raw_hex: String = cand
                        .blob
                        .identity
                        .raw_name
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    MemberKey {
                        member_ordinal: cand
                            .blob
                            .identity
                            .archive_member_ordinal
                            .map_or(ordinal as u64, |v| v.0),
                        raw_name_hex: raw_hex,
                        content_id: cand.blob.content_id.clone(),
                        byte_length: cand.blob.len() as u64,
                        logical_header_offset: cand.logical_header_byte_offset.0,
                        container_dependency_sha256: None,
                    }
                })
                .collect();
            occurrences.push(SourceOccurrenceKey {
                input_ordinal: ident.input_ordinal.0,
                content_id: ident.content_id.clone(),
                byte_length: ident.byte_length.0,
                input_kind: ident.input_kind.clone(),
                selected_members,
            });
        }
        Ok(Self {
            semantics,
            occurrences,
        })
    }

    /// Capture paths once and build an authoritative content-addressed key specification without
    /// ever incorporating filesystem path names or mtime into the digest.
    pub fn from_input_specs(
        inputs: &[InputSpec],
        capture_limits: CaptureLimits,
        inventories: &[ArchiveInventory],
        semantics: SemanticsIdentity,
    ) -> MddResult<(Snapshot, Self)> {
        let snapshot = Snapshot::capture(inputs, capture_limits)?;
        let spec = Self::from_snapshot_and_inventories(&snapshot, inventories, semantics)?;
        Ok((snapshot, spec))
    }

    /// Canonical compact byte serialization independent of pretty-printing choices.
    pub fn canonical_bytes(&self) -> MddResult<Vec<u8>> {
        let json = serde_json::to_vec(self).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "cache.key", error.to_string())
        })?;
        let mut out = Vec::with_capacity(16 + json.len());
        out.extend_from_slice(b"mdd-cache-key/1\0");
        out.extend_from_slice(&json);
        Ok(out)
    }

    pub fn canonical_cache_key(&self) -> MddResult<String> {
        let bytes = self.canonical_bytes()?;
        Ok(sha256(&bytes))
    }
}

/// Separate cache key object for rule/evidence/query caches (`docs/02_ARCHITECTURE_AND_CONTRACTS.md` §11.3).
/// Rule/config hashes are bound here and never injected into base DEX fact cache keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCacheKeySpec {
    pub base_fact_cache_key: String,
    pub rule_bundle_sha256: String,
    pub config_sha256: String,
    pub query_semantics_version: String,
    pub scope_id: String,
    pub parameters_digest: String,
}

impl RuleCacheKeySpec {
    pub fn canonical_rule_key(&self) -> MddResult<String> {
        if self.base_fact_cache_key.is_empty()
            || self.rule_bundle_sha256.is_empty()
            || self.config_sha256.is_empty()
            || self.scope_id.is_empty()
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cache.rule_key",
                "rule cache key fields must be nonempty",
            ));
        }
        let json = serde_json::to_vec(self).map_err(|error| {
            MddError::new(
                ErrorCode::InternalFault,
                "cache.rule_key",
                error.to_string(),
            )
        })?;
        let mut out = Vec::with_capacity(16 + json.len());
        out.extend_from_slice(b"mdd-rule-key/1\0");
        out.extend_from_slice(&json);
        Ok(sha256(&out))
    }
}
