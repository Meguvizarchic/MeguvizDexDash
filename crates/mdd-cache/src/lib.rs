//! Versioned persistent fact cache (`mdd-index/1`), CAS storage, and atomic recovery.
//!
//! Persistent cache entries never store raw memory structs, pointers, transient session handles,
//! file paths as strong keys, or partial/incomplete results as complete or negative hits.

pub mod cas;
pub mod dependency_tracking;
pub mod facts_codec;
pub mod format;
pub mod guard;
pub mod key;
pub mod store;

pub use dependency_tracking::{OccurrenceReuseMap, SharedContainerDependency};
pub use facts_codec::{
    CachedCell, CachedFactsPayload, CachedRawCodeMethod, CachedRelationTable,
    NegativeFindingRecord, OccurrenceSummary,
};
pub use format::{
    CACHE_FORMAT_ID, FLAG_STANDALONE_BLOBS, FLAG_THIN_EXTERNAL_CAS, HEADER_BYTES, IndexHeader,
    IndexManifest, SECTION_DESCRIPTOR_BYTES, SectionDescriptor, SectionKind, VerifiedIndex,
};
pub use guard::{PersistEligibility, PersistScopeCheck};
pub use key::{
    CacheMode, FactCacheKeySpec, MemberKey, RuleCacheKeySpec, SemanticsIdentity,
    SourceOccurrenceKey,
};
pub use store::{CacheAccessOutcome, CacheAccessReport, CacheOpenPolicy, CacheStore};
