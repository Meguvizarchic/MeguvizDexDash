use super::*;

pub type DirectoryEntryVisitor<'a> =
    &'a mut dyn FnMut(u32, u32, &str, u32, Option<u32>, Option<u32>) -> MddResult<()>;

impl AnnotationFacts {
    pub fn bytes(&self) -> &[u8] {
        self.definitions.bytes()
    }
    pub fn require_relation_columns(
        &self,
        relation: AnnotationRelation,
        columns: &[&str],
    ) -> MddResult<()> {
        let available: &[&str] = match relation {
            AnnotationRelation::Directories => &[
                "file_id",
                "class_idx",
                "annotations_off",
                "class_annotations_off",
                "fields_size",
                "methods_size",
                "parameters_size",
            ],
            AnnotationRelation::DirectoryEntries => &[
                "file_id",
                "class_idx",
                "annotations_off",
                "entry_kind",
                "entry_idx",
                "annotation_set_off",
                "annotation_set_ref_list_off",
            ],
            AnnotationRelation::SetEntries => {
                &["file_id", "annotation_set_off", "ordinal", "annotation_off"]
            }
            AnnotationRelation::SetRefs => &[
                "file_id",
                "annotation_set_ref_list_off",
                "ordinal",
                "annotation_set_off",
            ],
            AnnotationRelation::Annotations => &[
                "file_id",
                "annotation_off",
                "visibility",
                "type_idx",
                "element_count",
            ],
            AnnotationRelation::Elements => &[
                "file_id",
                "annotation_off",
                "depth",
                "ordinal",
                "name_idx",
                "value_off",
                "value_end_off",
                "value_kind",
                "value_index",
                "value_i64",
                "value_f64",
            ],
        };
        for column in columns {
            if *column != "*" && !available.contains(column) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.annotations",
                    "unknown annotation relation column",
                )
                .detail("column", (*column).to_owned()));
            }
        }
        Ok(())
    }
    pub fn directory_rows(&self, file_id: u32) -> Vec<AnnotationDirectoryRow> {
        let items: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        self.data
            .directory_bindings
            .iter()
            .map(|binding| {
                let item = items[&binding.directory_byte_offset];
                AnnotationDirectoryRow {
                    file_id,
                    class_idx: binding.class_idx,
                    annotations_off: item.byte_offset,
                    class_annotations_off: item.class_annotation_set_offset,
                    fields_size: item.fields_size,
                    methods_size: item.methods_size,
                    parameters_size: item.parameters_size,
                }
            })
            .collect()
    }
    pub fn directory_entry_rows(&self, file_id: u32) -> Vec<AnnotationDirectoryEntryRow> {
        let items: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        self.data
            .directory_bindings
            .iter()
            .flat_map(|binding| {
                items[&binding.directory_byte_offset]
                    .entries
                    .iter()
                    .map(move |entry| AnnotationDirectoryEntryRow {
                        file_id,
                        class_idx: binding.class_idx,
                        annotations_off: binding.directory_byte_offset,
                        entry_kind: match entry.kind {
                            AnnotationOwnerKind::Field => "field",
                            AnnotationOwnerKind::Method => "method",
                            AnnotationOwnerKind::Parameter => "parameter",
                            AnnotationOwnerKind::Class => "class",
                        }
                        .into(),
                        entry_idx: entry.local_index,
                        annotation_set_off: (entry.kind != AnnotationOwnerKind::Parameter)
                            .then_some(entry.target_byte_offset),
                        annotation_set_ref_list_off: (entry.kind == AnnotationOwnerKind::Parameter)
                            .then_some(entry.target_byte_offset),
                    })
            })
            .collect()
    }
    pub fn set_entry_rows(&self, file_id: u32) -> Vec<AnnotationSetEntryRow> {
        self.data
            .sets
            .iter()
            .flat_map(|set| {
                set.annotation_offsets
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, offset)| AnnotationSetEntryRow {
                        file_id,
                        annotation_set_off: set.byte_offset,
                        ordinal: ordinal as u32,
                        annotation_off: *offset,
                    })
            })
            .collect()
    }
    pub fn set_ref_rows(&self, file_id: u32) -> Vec<AnnotationSetRefRow> {
        self.data
            .ref_lists
            .iter()
            .flat_map(|list| {
                list.annotation_set_offsets
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, offset)| AnnotationSetRefRow {
                        file_id,
                        annotation_set_ref_list_off: list.byte_offset,
                        ordinal: ordinal as u32,
                        annotation_set_off: *offset,
                    })
            })
            .collect()
    }
    /// Offsets of the annotation sets and annotation items that a class
    /// annotation directory reaches, directly or through a parameter
    /// reference list.
    ///
    /// The physical row producers above enumerate every legal item in the
    /// section, including legal items that nothing references. The frozen
    /// HostLab backend enumerates only what a class-bound directory reaches, so
    /// the SQL projections use the `reachable_*` producers below. The fact layer
    /// itself keeps the unreferenced items.
    /// Offsets of the parameter reference lists that a class annotation directory names.
    pub(crate) fn reachable_ref_list_offsets(&self) -> BTreeSet<u32> {
        let directories: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        self.data
            .directory_bindings
            .iter()
            .filter_map(|binding| directories.get(&binding.directory_byte_offset))
            .flat_map(|directory| directory.entries.iter())
            .filter(|entry| entry.kind == AnnotationOwnerKind::Parameter)
            .map(|entry| entry.target_byte_offset)
            .collect()
    }
    pub(crate) fn reachable_offsets(&self) -> (BTreeSet<u32>, BTreeSet<u32>) {
        let directories: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        let ref_lists: BTreeMap<_, _> = self
            .data
            .ref_lists
            .iter()
            .map(|list| (list.byte_offset, list))
            .collect();
        let mut sets = BTreeSet::new();
        for binding in &self.data.directory_bindings {
            let Some(directory) = directories.get(&binding.directory_byte_offset) else {
                continue;
            };
            sets.extend(directory.class_annotation_set_offset);
            for entry in &directory.entries {
                if entry.kind == AnnotationOwnerKind::Parameter {
                    if let Some(list) = ref_lists.get(&entry.target_byte_offset) {
                        sets.extend(list.annotation_set_offsets.iter().flatten().copied());
                    }
                } else {
                    sets.insert(entry.target_byte_offset);
                }
            }
        }
        let annotations = self
            .data
            .sets
            .iter()
            .filter(|set| sets.contains(&set.byte_offset))
            .flat_map(|set| set.annotation_offsets.iter().copied())
            .collect();
        (sets, annotations)
    }
    /// `annotation_set_entries` rows of the sets a class directory reaches.
    pub fn reachable_set_entry_rows(&self, file_id: u32) -> Vec<AnnotationSetEntryRow> {
        let (sets, _) = self.reachable_offsets();
        self.set_entry_rows(file_id)
            .into_iter()
            .filter(|row| sets.contains(&row.annotation_set_off))
            .collect()
    }
    /// `annotations` rows of the items a reachable set contains.
    pub fn reachable_annotation_rows(&self, file_id: u32) -> Vec<AnnotationRow> {
        let (_, annotations) = self.reachable_offsets();
        self.annotation_rows(file_id)
            .into_iter()
            .filter(|row| annotations.contains(&row.annotation_off))
            .collect()
    }
    /// `annotation_elements` rows whose root annotation is reachable.
    pub fn reachable_element_rows(&self, file_id: u32) -> Vec<AnnotationElementRow> {
        let (_, annotations) = self.reachable_offsets();
        self.element_rows(file_id)
            .into_iter()
            .filter(|row| annotations.contains(&row.annotation_off))
            .collect()
    }
    pub fn annotation_rows(&self, file_id: u32) -> Vec<AnnotationRow> {
        self.data
            .annotation_items
            .iter()
            .map(|item| AnnotationRow {
                file_id,
                annotation_off: item.byte_offset,
                visibility: u32::from(item.visibility),
                type_idx: item.type_idx,
                element_count: item.elements.len() as u32,
            })
            .collect()
    }
    pub fn element_rows(&self, file_id: u32) -> Vec<AnnotationElementRow> {
        self.data
            .values
            .iter()
            .filter_map(|item| {
                item.annotation_byte_offset
                    .map(|root| AnnotationElementRow {
                        file_id,
                        annotation_off: root,
                        depth: item.depth,
                        ordinal: item.ordinal,
                        name_idx: item.name_idx,
                        value_off: item.encoded_range.byte_offset.0 as u32,
                        value_end_off: (item.encoded_range.byte_offset.0
                            + item.encoded_range.byte_length.0)
                            as u32,
                        value_kind: item.kind.as_str().into(),
                        value_index: item.value_index,
                        value_i64: item.value_i64.clone(),
                        value_f64: item.value_f64,
                    })
            })
            .collect()
    }

    pub fn for_each_directory_entry_row(&self, each: DirectoryEntryVisitor<'_>) -> MddResult<()> {
        let items: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        for binding in &self.data.directory_bindings {
            for entry in &items[&binding.directory_byte_offset].entries {
                let kind = match entry.kind {
                    AnnotationOwnerKind::Field => "field",
                    AnnotationOwnerKind::Method => "method",
                    AnnotationOwnerKind::Parameter => "parameter",
                    AnnotationOwnerKind::Class => "class",
                };
                let set_off = (entry.kind != AnnotationOwnerKind::Parameter)
                    .then_some(entry.target_byte_offset);
                let ref_list_off = (entry.kind == AnnotationOwnerKind::Parameter)
                    .then_some(entry.target_byte_offset);
                each(
                    binding.class_idx,
                    binding.directory_byte_offset,
                    kind,
                    entry.local_index,
                    set_off,
                    ref_list_off,
                )?;
            }
        }
        Ok(())
    }

    pub fn for_each_reachable_set_entry_row(
        &self,
        each: &mut dyn FnMut(u32, u32, u32) -> MddResult<()>,
    ) -> MddResult<()> {
        let (sets, _) = self.reachable_offsets();
        for set in &self.data.sets {
            if !sets.contains(&set.byte_offset) {
                continue;
            }
            for (ordinal, offset) in set.annotation_offsets.iter().enumerate() {
                each(set.byte_offset, ordinal as u32, *offset)?;
            }
        }
        Ok(())
    }

    pub fn for_each_reachable_annotation_row(
        &self,
        each: &mut dyn FnMut(u32, u32, u32, u32) -> MddResult<()>,
    ) -> MddResult<()> {
        let (_, annotations) = self.reachable_offsets();
        for item in &self.data.annotation_items {
            if !annotations.contains(&item.byte_offset) {
                continue;
            }
            each(
                item.byte_offset,
                u32::from(item.visibility),
                item.type_idx,
                item.elements.len() as u32,
            )?;
        }
        Ok(())
    }

    pub fn for_each_reachable_element_row(
        &self,
        each: &mut dyn FnMut(&ReachableElementRef<'_>) -> MddResult<()>,
    ) -> MddResult<()> {
        let (_, annotations) = self.reachable_offsets();
        for item in &self.data.values {
            let Some(root) = item.annotation_byte_offset else {
                continue;
            };
            if !annotations.contains(&root) {
                continue;
            }
            each(&ReachableElementRef {
                annotation_off: root,
                depth: item.depth,
                ordinal: item.ordinal,
                name_idx: item.name_idx,
                value_off: item.encoded_range.byte_offset.0 as u32,
                value_end_off: (item.encoded_range.byte_offset.0 + item.encoded_range.byte_length.0)
                    as u32,
                value_kind: item.kind.as_str(),
                value_index: item.value_index,
                value_i64: item.value_i64.as_deref(),
                value_f64: item.value_f64,
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReachableElementRef<'a> {
    pub annotation_off: u32,
    pub depth: u32,
    pub ordinal: u32,
    pub name_idx: Option<u32>,
    pub value_off: u32,
    pub value_end_off: u32,
    pub value_kind: &'static str,
    pub value_index: Option<u32>,
    pub value_i64: Option<&'a str>,
    pub value_f64: Option<ExactFloat>,
}
