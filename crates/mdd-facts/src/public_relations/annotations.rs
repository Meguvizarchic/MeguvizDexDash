//! The annotation relations beyond the HostLab four: annotation_directories, annotation_sets,
//! annotation_set_ref_lists, annotation_set_refs, annotation_values and annotation_elements_resolved.
//!
//! Like `annotation_set_entries` and `annotations`, they enumerate what a class annotation directory reaches:
//! its class set, the sets of its fields and methods, and the sets of its parameters through their reference
//! lists. Legal items nothing references stay in the fact layer and are not rows of these relations.
//!
//! An *owner* is one thing an annotation set annotates: a class, a field, a method, or one parameter of a method.
//! `annotation_values` and `annotation_elements_resolved` carry one row group per owner and per annotation of its
//! set, so a set that several owners share appears once for each of them.
use super::{row_budget, to_u32};
use crate::annotations::{AnnotationDirectoryRow, AnnotationFacts, AnnotationSetRefRow};
use mdd_dex::annotations::{AnnotationOwnerKind, EncodedValue};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnotationSetRow {
    pub file_id: u32,
    pub annotation_set_off: u32,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnotationSetRefListRow {
    pub file_id: u32,
    pub annotation_set_ref_list_off: u32,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AnnotationValueRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub owner_kind: &'static str,
    pub owner_idx: u32,
    pub owner_descriptor: String,
    pub parameter_idx: Option<u32>,
    pub annotation_off: u32,
    pub annotation_type_idx: u32,
    pub annotation_descriptor: String,
    pub depth: u32,
    pub ordinal: u32,
    pub name_idx: Option<u32>,
    pub name: Option<String>,
    pub value_kind: &'static str,
    pub value_i64: Option<String>,
    pub value_f64: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AnnotationElementResolvedRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub owner_kind: &'static str,
    pub owner_idx: u32,
    pub owner: String,
    pub parameter_idx: Option<u32>,
    pub annotation: String,
    pub visibility: u32,
    pub element_count: u32,
    pub annotation_off: u32,
    pub element_ordinal: Option<u32>,
    pub element_name: Option<String>,
    pub value_kind: Option<&'static str>,
    pub value_index: Option<u32>,
    pub value_i64: Option<String>,
    pub value_f64: Option<f64>,
    pub retention_policy: Option<&'static str>,
}

/// One thing an annotation set annotates.
struct Owner {
    class_idx: u32,
    kind: &'static str,
    idx: u32,
    descriptor: String,
    parameter_idx: Option<u32>,
    set_off: u32,
}

impl AnnotationFacts {
    /// `annotation_directories`: the annotation directory of every class that has one.
    pub fn public_directory_rows(&self, file_id: u32) -> MddResult<Vec<AnnotationDirectoryRow>> {
        let rows = self.directory_rows(file_id);
        row_budget(rows.len(), "annotation_directories")?;
        Ok(rows)
    }

    /// `annotation_sets`: the annotation sets a class directory reaches, in offset order.
    pub fn public_set_rows(&self, file_id: u32) -> MddResult<Vec<AnnotationSetRow>> {
        let (reachable, _) = self.reachable_offsets();
        let data = self.data();
        row_budget(data.sets.len(), "annotation_sets")?;
        data.sets
            .iter()
            .filter(|set| reachable.contains(&set.byte_offset))
            .map(|set| {
                Ok(AnnotationSetRow {
                    file_id,
                    annotation_set_off: set.byte_offset,
                    size: to_u32(set.annotation_offsets.len() as u64, "annotation set size")?,
                })
            })
            .collect()
    }

    /// `annotation_set_ref_lists`: the parameter reference lists a class directory reaches.
    pub fn public_ref_list_rows(&self, file_id: u32) -> MddResult<Vec<AnnotationSetRefListRow>> {
        let reachable = self.reachable_ref_list_offsets();
        let data = self.data();
        row_budget(data.ref_lists.len(), "annotation_set_ref_lists")?;
        data.ref_lists
            .iter()
            .filter(|list| reachable.contains(&list.byte_offset))
            .map(|list| {
                Ok(AnnotationSetRefListRow {
                    file_id,
                    annotation_set_ref_list_off: list.byte_offset,
                    size: to_u32(
                        list.annotation_set_offsets.len() as u64,
                        "annotation set ref list size",
                    )?,
                })
            })
            .collect()
    }

    /// `annotation_set_refs`: the entries of those lists; a parameter without annotations is a NULL set.
    pub fn public_set_ref_rows(&self, file_id: u32) -> MddResult<Vec<AnnotationSetRefRow>> {
        let reachable = self.reachable_ref_list_offsets();
        let rows = self.set_ref_rows(file_id);
        row_budget(rows.len(), "annotation_set_refs")?;
        Ok(rows
            .into_iter()
            .filter(|row| reachable.contains(&row.annotation_set_ref_list_off))
            .collect())
    }

    fn owners(&self) -> MddResult<Vec<Owner>> {
        let data = self.data();
        let definitions = self.definitions().definitions();
        let metadata = self.definitions().metadata();
        let directories: BTreeMap<u32, _> = data
            .directories
            .iter()
            .map(|directory| (directory.byte_offset, directory))
            .collect();
        let ref_lists: BTreeMap<u32, _> = data
            .ref_lists
            .iter()
            .map(|list| (list.byte_offset, list))
            .collect();
        let inconsistent = |what: &'static str| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.public_relations",
                "annotation facts disagree with the definition facts",
            )
            .detail("item", what)
        };
        let mut owners = Vec::new();
        for binding in &data.directory_bindings {
            let directory = directories
                .get(&binding.directory_byte_offset)
                .ok_or_else(|| inconsistent("directory"))?;
            if let Some(set_off) = directory.class_annotation_set_offset {
                let class = metadata
                    .types()
                    .get(binding.class_idx as usize)
                    .ok_or_else(|| inconsistent("class type"))?;
                owners.push(Owner {
                    class_idx: binding.class_idx,
                    kind: "class",
                    idx: binding.class_idx,
                    descriptor: class.data.descriptor.clone(),
                    parameter_idx: None,
                    set_off,
                });
            }
            for entry in &directory.entries {
                match entry.kind {
                    AnnotationOwnerKind::Field => {
                        let field = definitions
                            .field_references
                            .get(entry.local_index as usize)
                            .ok_or_else(|| inconsistent("field"))?;
                        owners.push(Owner {
                            class_idx: binding.class_idx,
                            kind: "field",
                            idx: entry.local_index,
                            descriptor: field.descriptor.clone(),
                            parameter_idx: None,
                            set_off: entry.target_byte_offset,
                        });
                    }
                    AnnotationOwnerKind::Method => {
                        let method = definitions
                            .method_references
                            .get(entry.local_index as usize)
                            .ok_or_else(|| inconsistent("method"))?;
                        owners.push(Owner {
                            class_idx: binding.class_idx,
                            kind: "method",
                            idx: entry.local_index,
                            descriptor: method.descriptor.clone(),
                            parameter_idx: None,
                            set_off: entry.target_byte_offset,
                        });
                    }
                    AnnotationOwnerKind::Parameter => {
                        let method = definitions
                            .method_references
                            .get(entry.local_index as usize)
                            .ok_or_else(|| inconsistent("parameter method"))?;
                        let list = ref_lists
                            .get(&entry.target_byte_offset)
                            .ok_or_else(|| inconsistent("parameter list"))?;
                        for (ordinal, set) in list.annotation_set_offsets.iter().enumerate() {
                            let Some(set_off) = set else { continue };
                            owners.push(Owner {
                                class_idx: binding.class_idx,
                                kind: "parameter",
                                idx: entry.local_index,
                                descriptor: method.descriptor.clone(),
                                parameter_idx: Some(to_u32(ordinal as u64, "parameter position")?),
                                set_off: *set_off,
                            });
                        }
                    }
                    AnnotationOwnerKind::Class => {}
                }
            }
        }
        Ok(owners)
    }

    fn name_text(&self, name_idx: Option<u32>) -> MddResult<Option<String>> {
        let Some(index) = name_idx else {
            return Ok(None);
        };
        let metadata = self.definitions().metadata();
        let string = metadata.strings().get(index as usize).ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.public_relations",
                "an annotation element name lies outside the string table",
            )
            .detail("string_idx", u64::from(index))
        })?;
        string.data.text.strict_utf8().map(Some).map_err(|_| {
            MddError::new(
                ErrorCode::UnsupportedQuery,
                "facts.public_relations",
                "plain UTF8 relation cannot losslessly represent a legal non-scalar DEX string",
            )
            .detail("reason", "NON_SCALAR_TEXT_PROJECTION")
            .detail("string_idx", u64::from(index))
        })
    }

    /// Every annotation of every owner's set, with the value nodes of that annotation.
    fn for_each_owned_annotation(
        &self,
        relation: &'static str,
        mut visit: impl FnMut(
            &Owner,
            u32,
            &mdd_dex::annotations::AnnotationItem,
            &[&EncodedValue],
        ) -> MddResult<()>,
    ) -> MddResult<()> {
        let data = self.data();
        let sets: BTreeMap<u32, _> = data.sets.iter().map(|set| (set.byte_offset, set)).collect();
        let items: BTreeMap<u32, _> = data
            .annotation_items
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        let mut values_of: BTreeMap<u32, Vec<&EncodedValue>> = BTreeMap::new();
        for value in &data.values {
            if let Some(root) = value.annotation_byte_offset {
                values_of.entry(root).or_default().push(value);
            }
        }
        let missing = |what: &'static str| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.public_relations",
                "an annotation owner refers to an item the annotation facts do not hold",
            )
            .detail("item", what)
        };
        let mut visited = 0usize;
        for owner in self.owners()? {
            let set = sets
                .get(&owner.set_off)
                .ok_or_else(|| missing("annotation set"))?;
            for annotation_off in &set.annotation_offsets {
                let item = items
                    .get(annotation_off)
                    .ok_or_else(|| missing("annotation"))?;
                let values = values_of.get(annotation_off).map_or(&[][..], Vec::as_slice);
                visited = visited.saturating_add(values.len().max(1));
                row_budget(visited, relation)?;
                visit(&owner, *annotation_off, item, values)?;
            }
        }
        Ok(())
    }

    fn type_descriptor(&self, type_idx: u32) -> MddResult<String> {
        self.definitions()
            .metadata()
            .types()
            .get(type_idx as usize)
            .map(|fact| fact.data.descriptor.clone())
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.public_relations",
                    "an annotation type lies outside the type table",
                )
                .detail("type_idx", u64::from(type_idx))
            })
    }

    /// `annotation_values`: every value node of every annotation of every owner, nested ones included.
    pub fn annotation_value_rows(&self, file_id: u32) -> MddResult<Vec<AnnotationValueRow>> {
        let mut rows = Vec::new();
        self.for_each_owned_annotation(
            "annotation_values",
            |owner, annotation_off, item, values| {
                let descriptor = self.type_descriptor(item.type_idx)?;
                for value in values {
                    rows.push(AnnotationValueRow {
                        file_id,
                        class_idx: owner.class_idx,
                        owner_kind: owner.kind,
                        owner_idx: owner.idx,
                        owner_descriptor: owner.descriptor.clone(),
                        parameter_idx: owner.parameter_idx,
                        annotation_off,
                        annotation_type_idx: item.type_idx,
                        annotation_descriptor: descriptor.clone(),
                        depth: value.depth,
                        ordinal: value.ordinal,
                        name_idx: value.name_idx,
                        name: self.name_text(value.name_idx)?,
                        value_kind: value.kind.as_str(),
                        value_i64: value.value_i64.clone(),
                        value_f64: value.value_f64.map(|exact| exact.as_f64()),
                    });
                }
                Ok(())
            },
        )?;
        Ok(rows)
    }

    /// `annotation_elements_resolved`: the top-level elements of every annotation of every owner, with the
    /// annotation spelled out. An annotation without elements is one row whose element columns are NULL.
    pub fn annotation_element_resolved_rows(
        &self,
        file_id: u32,
    ) -> MddResult<Vec<AnnotationElementResolvedRow>> {
        let mut rows = Vec::new();
        self.for_each_owned_annotation(
            "annotation_elements_resolved",
            |owner, annotation_off, item, values| {
                let annotation = self.type_descriptor(item.type_idx)?;
                let element_count = to_u32(item.elements.len() as u64, "element count")?;
                let retention = match item.visibility {
                    0 => Some("class"),
                    1 => Some("runtime"),
                    2 => Some("system"),
                    _ => None,
                };
                let base =
                    |element: Option<&EncodedValue>| -> MddResult<AnnotationElementResolvedRow> {
                        Ok(AnnotationElementResolvedRow {
                            file_id,
                            class_idx: owner.class_idx,
                            owner_kind: owner.kind,
                            owner_idx: owner.idx,
                            owner: owner.descriptor.clone(),
                            parameter_idx: owner.parameter_idx,
                            annotation: annotation.clone(),
                            visibility: u32::from(item.visibility),
                            element_count,
                            annotation_off,
                            element_ordinal: element.map(|value| value.ordinal),
                            element_name: match element {
                                Some(value) => self.name_text(value.name_idx)?,
                                None => None,
                            },
                            value_kind: element.map(|value| value.kind.as_str()),
                            value_index: element.and_then(|value| value.value_index),
                            value_i64: element.and_then(|value| value.value_i64.clone()),
                            value_f64: element
                                .and_then(|value| value.value_f64)
                                .map(|exact| exact.as_f64()),
                            retention_policy: retention,
                        })
                    };
                let top: Vec<&&EncodedValue> =
                    values.iter().filter(|value| value.depth == 0).collect();
                if top.is_empty() {
                    rows.push(base(None)?);
                }
                for value in top {
                    rows.push(base(Some(value))?);
                }
                Ok(())
            },
        )?;
        Ok(rows)
    }
}
