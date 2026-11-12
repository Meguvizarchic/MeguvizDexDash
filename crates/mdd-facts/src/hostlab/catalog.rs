//! Adapter payload loader for the HostLab structural audit.
//!
//! The reference audit keeps its business data in
//! `tools/hostlab/analysis/audit_catalog.json` (`lists`) plus literals inside
//! `native_rules.py`. That data names classes of the analysed application, so it
//! is **not** part of this repository: a catalog is loaded from a JSON file the
//! operator supplies, and the rule code only knows the key names below. Tests use [`HostlabCatalog::neutral`], whose
//! values name classes that no fixture contains.
//!
//! The digest of the frozen Java reference travels with the catalog for the same
//! reason the reference checks it: a changed Java rule set invalidates native
//! equivalence. This crate cannot recompute that digest because the Java source
//! is not vendored, so the adapter that supplies the file must keep enforcing it.
//!
//! This crate has no JSON dependency, so the file is read by the caller (see
//! `examples/hostlab_audit.rs`) and handed to [`HostlabCatalog::new`], which does
//! the validation. The file shape the example reads is:
//!
//! ```json
//! { "schema_version": "mdd.hostlab-catalog.v1", "id": "...",
//!   "reference_commit": "<40 hex>", "java_reference_sha256": "<64 hex>",
//!   "lists": { "<key>": ["..."] }, "constants": { "<key>": "..." } }
//! ```
//!
//! [`HostlabCatalog::new`] requires every key in [`REQUIRED_LISTS`] and
//! [`REQUIRED_CONSTANTS`] and accepts no other key, so a typo in a catalog file
//! fails at load time instead of silently turning a rule into `MISSING`.
use mdd_types::{ErrorCode, MddError, MddResult};
use std::collections::BTreeMap;

pub use super::rules::HostlabCatalog;

/// `schema_version` of the file format the example reads.
pub const CATALOG_SCHEMA: &str = "mdd.hostlab-catalog.v1";

/// Lists the rules read, keyed as in the reference `audit_catalog.json`
/// (`run.*` and `teenagers.*` keys come from inline `native_rules.py` literals).
pub const REQUIRED_LISTS: &[&str] = &[
    "auditBottomBar.owners",
    "auditCommentCopy.highOwners",
    "auditCommentCopy.lowOwners",
    "auditCommentData.replyOwners",
    "auditCommentSection.services",
    "auditCommentTopology.detailSetters",
    "auditCommentTopology.replyGetters",
    "auditCommentTopology.replyOwners",
    "auditFullNumber.names",
    "auditFullNumber.owners",
    "auditHomeRecommend.responses",
    "auditHomeTabs.owners",
    "auditHomeTopBar.baseOwners",
    "auditMineComponents.groupOwners",
    "auditMineComponents.itemOwners",
    "auditSplash.names",
    "auditSplash.owners",
    "auditStory.booleanNames",
    "run.blockCandidates",
    "run.qualityCandidates",
    "teenagers.owners",
];

pub const REQUIRED_CONSTANTS: &[&str] = &[
    "block.contextArg",
    "block.resultClass",
    "fullNumber.kotlinOwner",
    "merchandise.owner",
    "playerStatusBar.owner",
];

fn catalog_error(reason: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "hostlab.catalog", reason)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl HostlabCatalog {
    /// A catalog whose every value names a class that no fixture contains, so a
    /// rule run over a fixture reports business verdicts without touching any
    /// application data.
    pub fn neutral(id: &str) -> Self {
        Self::from_parts(
            id.to_owned(),
            "0".repeat(40),
            "0".repeat(64),
            REQUIRED_LISTS
                .iter()
                .map(|key| ((*key).to_owned(), Vec::new()))
                .collect(),
            REQUIRED_CONSTANTS
                .iter()
                .map(|key| {
                    let value = match *key {
                        "block.contextArg" => "android.content.Context".to_owned(),
                        other => format!("synthetic.absent.{}", other.replace('.', "_")),
                    };
                    ((*key).to_owned(), value)
                })
                .collect(),
        )
    }

    /// Validate and build a catalog from already parsed data.
    pub fn new(
        id: String,
        reference_commit: String,
        java_reference_sha256: String,
        lists: BTreeMap<String, Vec<String>>,
        constants: BTreeMap<String, String>,
    ) -> MddResult<Self> {
        if id.is_empty() {
            return Err(catalog_error("catalog id must not be empty"));
        }
        if !is_lower_hex(&reference_commit, 40) || !is_lower_hex(&java_reference_sha256, 64) {
            return Err(catalog_error(
                "reference_commit must be 40 and java_reference_sha256 64 lowercase hex digits",
            ));
        }
        for key in REQUIRED_LISTS {
            if !lists.contains_key(*key) {
                return Err(
                    catalog_error("catalog lacks a list the rules read").detail("list", *key)
                );
            }
        }
        for key in REQUIRED_CONSTANTS {
            if !constants.contains_key(*key) {
                return Err(catalog_error("catalog lacks a constant the rules read")
                    .detail("constant", *key));
            }
        }
        if let Some(extra) = lists
            .keys()
            .find(|key| !REQUIRED_LISTS.contains(&key.as_str()))
        {
            return Err(
                catalog_error("catalog defines a list no rule reads").detail("list", extra.clone())
            );
        }
        if let Some(extra) = constants
            .keys()
            .find(|key| !REQUIRED_CONSTANTS.contains(&key.as_str()))
        {
            return Err(catalog_error("catalog defines a constant no rule reads")
                .detail("constant", extra.clone()));
        }
        Ok(Self::from_parts(
            id,
            reference_commit,
            java_reference_sha256,
            lists,
            constants,
        ))
    }

    pub fn list(&self, key: &str) -> MddResult<Vec<&str>> {
        self.lists
            .get(key)
            .map(|values| values.iter().map(String::as_str).collect())
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "hostlab.catalog",
                    "rule requested a catalog list that this payload does not define",
                )
                .detail("catalog", self.id.clone())
                .detail("list", key.to_owned())
            })
    }

    pub fn constant(&self, key: &str) -> MddResult<&str> {
        self.constants.get(key).map(String::as_str).ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "hostlab.catalog",
                "rule requested a catalog constant that this payload does not define",
            )
            .detail("catalog", self.id.clone())
            .detail("constant", key.to_owned())
        })
    }
}
