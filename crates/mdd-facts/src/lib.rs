//! Snapshot-scoped exact facts. Metadata completion never implies complete audit facts.
pub mod annotations;
pub mod code;
pub mod coverage;
pub mod definitions;
pub mod hostlab;
pub mod indexes;
pub mod metadata;
pub mod pipeline;
pub mod raw_fingerprints;
pub mod references;
pub mod session;
pub mod surface;
pub mod threads;

pub use mdd_dex::{
    annotations::AnnotationOwnerKind, definitions::MethodBody, instructions::InvokeKind,
};

pub use session::{FactsLimits, FactsSession};

pub use pipeline::{
    DexFacts, DexStageTimings, FactsPipeline, PipelineConfig, PipelineReport, PipelineSummary,
};

pub use code::CodeFacts;
pub use definitions::DefinitionFacts;
pub use references::ReferenceFacts;

pub use metadata::{
    EntityKind, EntityRef, MetadataFacts, MetadataSource, PrototypeFact, StringFact,
    StringPoolIdentity, TypeFact,
};
