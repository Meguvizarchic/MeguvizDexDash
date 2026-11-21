use super::*;

/// Combines already-built metadata and definitions without copying or ETL.
/// Both sides must describe exactly the same selected DEX occurrences.
pub struct CombinedSqlProvider {
    binding: SqlBinding,
    metadata: Arc<MetadataSqlProvider>,
    definitions: Arc<DefinitionSqlProvider>,
    references: Option<Arc<ReferenceSqlProvider>>,
    code: Option<Arc<CodeSqlProvider>>,
    annotations: Option<Arc<AnnotationSqlProvider>>,
}
impl CombinedSqlProvider {
    pub fn new(
        metadata: Arc<MetadataSqlProvider>,
        definitions: Arc<DefinitionSqlProvider>,
    ) -> MddResult<Self> {
        if metadata.binding.snapshot_id != definitions.binding.snapshot_id
            || metadata.binding.catalog_epoch != definitions.binding.catalog_epoch
        {
            return Err(invalid("COMBINED_PROVIDER_GENERATION"));
        }
        let metadata_sources: BTreeSet<_> = metadata
            .occurrences
            .iter()
            .map(|f| &f.source().dex_occurrence_id)
            .collect();
        let definition_sources: BTreeSet<_> = definitions
            .occurrences
            .iter()
            .map(|f| &f.metadata().source().dex_occurrence_id)
            .collect();
        if metadata_sources != definition_sources {
            return Err(invalid("COMBINED_PROVIDER_SCOPE"));
        }
        Ok(Self {
            binding: SqlBinding {
                provider_identity: opaque_id("sql-combined-provider")?,
                snapshot_id: metadata.binding.snapshot_id.clone(),
                catalog_epoch: metadata.binding.catalog_epoch,
            },
            metadata,
            definitions,
            references: None,
            code: None,
            annotations: None,
        })
    }

    /// Attach complete encoded reference sites for precisely the same selected
    /// occurrences and catalog generation. No legacy call-graph semantics are inferred.
    pub fn with_references(mut self, references: Arc<ReferenceSqlProvider>) -> MddResult<Self> {
        if self.references.is_some() {
            return Err(invalid("COMBINED_PROVIDER_REFERENCES_ALREADY_BOUND"));
        }
        if self.binding.snapshot_id != references.binding.snapshot_id
            || self.binding.catalog_epoch != references.binding.catalog_epoch
        {
            return Err(invalid("COMBINED_PROVIDER_GENERATION"));
        }
        let metadata_sources: BTreeSet<_> = self
            .metadata
            .occurrences
            .iter()
            .map(|facts| &facts.source().dex_occurrence_id)
            .collect();
        let reference_sources: BTreeSet<_> = references
            .occurrences
            .iter()
            .map(|facts| &facts.source().dex_occurrence_id)
            .collect();
        if metadata_sources != reference_sources {
            return Err(invalid("COMBINED_PROVIDER_SCOPE"));
        }
        for facts in &references.occurrences {
            facts.require_complete()?;
        }
        self.references = Some(references);
        Ok(self)
    }

    /// Attach complete physical code items for the same selected occurrences.
    /// Physical items do not by themselves establish method ownership.
    pub fn with_code(mut self, code: Arc<CodeSqlProvider>) -> MddResult<Self> {
        if self.code.is_some() {
            return Err(invalid("COMBINED_PROVIDER_CODE_ALREADY_BOUND"));
        }
        if self.binding.snapshot_id != code.binding.snapshot_id
            || self.binding.catalog_epoch != code.binding.catalog_epoch
        {
            return Err(invalid("COMBINED_PROVIDER_GENERATION"));
        }
        let metadata_sources: BTreeSet<_> = self
            .metadata
            .occurrences
            .iter()
            .map(|facts| &facts.source().dex_occurrence_id)
            .collect();
        let code_sources: BTreeSet<_> = code
            .occurrences
            .iter()
            .map(|facts| &facts.source().dex_occurrence_id)
            .collect();
        if metadata_sources != code_sources {
            return Err(invalid("COMBINED_PROVIDER_SCOPE"));
        }
        self.code = Some(code);
        Ok(self)
    }

    /// Bind encoded annotation facts for exactly the same selected sources.
    pub fn with_annotations(mut self, annotations: Arc<AnnotationSqlProvider>) -> MddResult<Self> {
        if self.annotations.is_some() {
            return Err(invalid("COMBINED_PROVIDER_ANNOTATIONS_ALREADY_BOUND"));
        }
        if self.binding.snapshot_id != annotations.binding.snapshot_id
            || self.binding.catalog_epoch != annotations.binding.catalog_epoch
        {
            return Err(invalid("COMBINED_PROVIDER_GENERATION"));
        }
        let expected: BTreeSet<_> = self
            .metadata
            .occurrences
            .iter()
            .map(|f| &f.source().dex_occurrence_id)
            .collect();
        let actual: BTreeSet<_> = annotations
            .occurrences
            .iter()
            .map(|f| &f.source().dex_occurrence_id)
            .collect();
        if expected != actual {
            return Err(invalid("COMBINED_PROVIDER_SCOPE"));
        }
        self.annotations = Some(annotations);
        Ok(self)
    }
}
impl SqlFactProvider for CombinedSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        let mut relations = self.metadata.relations()?;
        relations.extend(self.definitions.relations()?);
        if let Some(references) = &self.references {
            relations.extend(references.relations()?);
        }
        if let Some(code) = &self.code {
            relations.extend(code.relations()?);
        }
        if let Some(annotations) = &self.annotations {
            relations.extend(annotations.relations()?);
        }
        let mut names = BTreeSet::new();
        if relations
            .iter()
            .any(|r| !names.insert(r.name.to_ascii_lowercase()))
        {
            return Err(invalid("COMBINED_PROVIDER_DUPLICATE_RELATION"));
        }
        Ok(relations)
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        if MetadataRelation::parse(relation).is_ok() {
            self.metadata.require_relation(relation)
        } else if AnnotationRelation::parse(relation).is_some() {
            self.annotations
                .as_ref()
                .ok_or_else(|| invalid("UNKNOWN_ANNOTATION_RELATION"))?
                .require_relation(relation)
        } else if CodeRelation::parse(relation).is_ok() {
            self.code
                .as_ref()
                .ok_or_else(|| invalid("UNKNOWN_CODE_RELATION"))?
                .require_relation(relation)
        } else if is_reference_relation(relation) {
            self.references
                .as_ref()
                .ok_or_else(|| invalid("UNKNOWN_REFERENCE_RELATION"))?
                .require_relation(relation)
        } else {
            self.definitions.require_relation(relation)
        }
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        if MetadataRelation::parse(relation).is_ok() {
            Arc::clone(&self.metadata).open_cursor(relation, control)
        } else if AnnotationRelation::parse(relation).is_some() {
            Arc::clone(
                self.annotations
                    .as_ref()
                    .ok_or_else(|| invalid("UNKNOWN_ANNOTATION_RELATION"))?,
            )
            .open_cursor(relation, control)
        } else if CodeRelation::parse(relation).is_ok() {
            Arc::clone(
                self.code
                    .as_ref()
                    .ok_or_else(|| invalid("UNKNOWN_CODE_RELATION"))?,
            )
            .open_cursor(relation, control)
        } else if is_reference_relation(relation) {
            Arc::clone(
                self.references
                    .as_ref()
                    .ok_or_else(|| invalid("UNKNOWN_REFERENCE_RELATION"))?,
            )
            .open_cursor(relation, control)
        } else {
            Arc::clone(&self.definitions).open_cursor(relation, control)
        }
    }
}
