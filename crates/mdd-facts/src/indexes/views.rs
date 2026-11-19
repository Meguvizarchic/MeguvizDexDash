use super::SelectedScope;
use crate::{
    MetadataFacts, annotations::AnnotationFacts, code::CodeFacts, definitions::DefinitionFacts,
    raw_fingerprints::RawCodeEvidence, references::ReferenceFacts,
};
use mdd_types::{ErrorCode, MddError, MddResult};

#[derive(Clone)]
pub struct FactView<'a> {
    pub(crate) occurrence: String,
    pub(crate) metadata: Option<&'a MetadataFacts>,
    pub(crate) definitions: Option<&'a DefinitionFacts>,
    pub(crate) code: Option<&'a CodeFacts>,
    pub(crate) annotations: Option<&'a AnnotationFacts>,
    pub(crate) references: Option<&'a ReferenceFacts>,
    pub(crate) raw_code: Option<&'a RawCodeEvidence>,
}
impl<'a> FactView<'a> {
    pub fn unbuilt(occurrence: impl AsRef<str>) -> Self {
        Self {
            occurrence: occurrence.as_ref().to_owned(),
            metadata: None,
            definitions: None,
            code: None,
            annotations: None,
            references: None,
            raw_code: None,
        }
    }
    pub fn with_metadata(mut self, value: &'a MetadataFacts) -> Self {
        self.metadata = Some(value);
        self
    }
    pub fn with_definitions(mut self, value: &'a DefinitionFacts) -> Self {
        self.metadata = Some(value.metadata());
        self.definitions = Some(value);
        self
    }
    pub fn with_code(mut self, value: &'a CodeFacts) -> Self {
        self.code = Some(value);
        self
    }
    pub fn with_annotations(mut self, value: &'a AnnotationFacts) -> Self {
        self.metadata = Some(value.definitions().metadata());
        self.definitions = Some(value.definitions());
        self.annotations = Some(value);
        self
    }
    pub fn with_references(mut self, value: &'a ReferenceFacts) -> Self {
        self.metadata = Some(value.definitions().metadata());
        self.definitions = Some(value.definitions());
        self.code = Some(value.code());
        self.references = Some(value);
        self
    }
    pub fn with_raw_code(mut self, value: &'a RawCodeEvidence) -> Self {
        self.raw_code = Some(value);
        self
    }
    pub fn occurrence(&self) -> &str {
        &self.occurrence
    }
    pub fn metadata(&self) -> Option<&'a MetadataFacts> {
        self.metadata
    }
    pub fn definitions(&self) -> Option<&'a DefinitionFacts> {
        self.definitions
    }
    pub fn references(&self) -> Option<&'a ReferenceFacts> {
        self.references
    }
    pub fn validate(&self, scope: &SelectedScope) -> MddResult<()> {
        let expected = scope
            .dexes()
            .iter()
            .find(|dex| dex.dex_occurrence_id == self.occurrence)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index_view",
                    "fact view occurrence is outside explicit selected scope",
                )
            })?;
        let sources = [
            self.metadata.map(|v| v.source()),
            self.definitions.map(|v| v.metadata().source()),
            self.code.map(|v| v.source()),
            self.annotations.map(|v| v.source()),
            self.references.map(|v| v.source()),
            self.raw_code.map(|v| v.source()),
        ];
        for source in sources.into_iter().flatten() {
            if source.snapshot_id != scope.snapshot_id()
                || source.dex_occurrence_id != expected.dex_occurrence_id
                || source.content_id != expected.content_id
                || source.member_id != expected.member_id
                || source.source_occurrence_id != expected.source_occurrence_id
            {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index_view",
                    "fact leaves do not bind the same selected snapshot/member generation",
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn standard_header_proven(&self) -> bool {
        self.metadata.is_some()
            || self.definitions.is_some()
            || self.code.is_some()
            || self.annotations.is_some()
            || self.references.is_some()
            || self.raw_code.is_some()
    }
}
