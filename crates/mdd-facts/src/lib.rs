//! Snapshot-scoped exact facts. Metadata completion never implies complete audit facts.
pub mod annotations;
pub mod code;
pub mod coverage;
pub mod definitions;
pub mod indexes;
pub mod metadata;
pub mod raw_fingerprints;
pub mod references;

pub use mdd_dex::{
    annotations::AnnotationOwnerKind, definitions::MethodBody, instructions::InvokeKind,
};

pub use metadata::{
    EntityKind, EntityRef, MetadataFacts, MetadataSource, PrototypeFact, StringFact,
    StringPoolIdentity, TypeFact,
};
