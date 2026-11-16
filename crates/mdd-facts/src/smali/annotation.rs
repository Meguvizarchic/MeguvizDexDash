//! Annotation blocks: which annotation sets belong to a class, a field, a method or a method's
//! parameters, and how a set is written.
//!
//! ```text
//! .annotation runtime Lpkg/Name;
//!     element = value
//! .end annotation
//! ```
//!
//! A set is written as its items are stored: in order, each with its visibility word (`build`,
//! `runtime`, `system`) and its elements in stored order (the format sorts them by name). A set
//! that is stored but empty writes nothing, the same as no set; the facts keep the difference.
//!
//! Which parameter an annotation slot belongs to is a fact only when the slots of the method
//! are as many as its prototype has parameters (`parameter_position_in_prototype`); otherwise
//! the slots are not placed and [`ParameterSlots::Unplaced`] says how many were left out.
use super::value::{ValueContext, push_indent};
use crate::annotations::AnnotationFacts;
use mdd_dex::annotations::{AnnotationOwnerKind, DexAnnotations};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::collections::HashMap;

fn fault(message: &str) -> MddError {
    MddError::new(ErrorCode::InternalFault, "facts.smali", message)
}

/// Which annotation set each owner has, by owner identity. Built once per DEX.
#[derive(Debug, Default)]
pub struct AnnotationIndex {
    sets: HashMap<u32, usize>,
    items: HashMap<u32, usize>,
    arrays: HashMap<u32, usize>,
    class_sets: HashMap<u32, u32>,
    field_sets: HashMap<(u32, u32), u32>,
    method_sets: HashMap<(u32, u32), u32>,
    /// Per (class, method): the set offset of each encoded slot, `None` for a zero slot.
    parameter_slots: HashMap<(u32, u32), Vec<Option<u32>>>,
    /// Per (class, method): how many parameters the prototype has, when the facts know it.
    parameter_counts: HashMap<(u32, u32), u32>,
}

/// The parameters of a method that have annotations, or why none can be placed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParameterSlots {
    /// Slot `i` is the set offset of parameter `i` of the prototype.
    Placed(Vec<Option<u32>>),
    /// The method has parameter annotation slots that cannot be tied to prototype positions:
    /// this many slots are not shown.
    Unplaced { slots: usize },
}

impl AnnotationIndex {
    pub fn build(facts: &AnnotationFacts) -> Self {
        let data = facts.data();
        let mut index = Self::default();
        for (position, set) in data.sets.iter().enumerate() {
            index.sets.insert(set.byte_offset, position);
        }
        for (position, item) in data.annotation_items.iter().enumerate() {
            index.items.insert(item.byte_offset, position);
        }
        for (position, array) in data.encoded_arrays.iter().enumerate() {
            index.arrays.insert(array.byte_offset, position);
        }
        for binding in &data.owner_bindings {
            let Some(set) = binding.annotation_set_offset else {
                // A zero slot has no set. Parameter slots still hold their place below.
                if binding.kind == AnnotationOwnerKind::Parameter {
                    let slots = index
                        .parameter_slots
                        .entry((binding.class_def_idx, binding.local_index))
                        .or_default();
                    let ordinal = binding.parameter_ordinal.unwrap_or(0) as usize;
                    if slots.len() <= ordinal {
                        slots.resize(ordinal + 1, None);
                    }
                    if let Some(count) = binding.prototype_parameter_count {
                        index
                            .parameter_counts
                            .insert((binding.class_def_idx, binding.local_index), count);
                    }
                }
                continue;
            };
            match binding.kind {
                AnnotationOwnerKind::Class => {
                    index.class_sets.insert(binding.class_def_idx, set);
                }
                AnnotationOwnerKind::Field => {
                    index
                        .field_sets
                        .insert((binding.class_def_idx, binding.local_index), set);
                }
                AnnotationOwnerKind::Method => {
                    index
                        .method_sets
                        .insert((binding.class_def_idx, binding.local_index), set);
                }
                AnnotationOwnerKind::Parameter => {
                    let key = (binding.class_def_idx, binding.local_index);
                    let slots = index.parameter_slots.entry(key).or_default();
                    let ordinal = binding.parameter_ordinal.unwrap_or(0) as usize;
                    if slots.len() <= ordinal {
                        slots.resize(ordinal + 1, None);
                    }
                    slots[ordinal] = Some(set);
                    if let Some(count) = binding.prototype_parameter_count {
                        index.parameter_counts.insert(key, count);
                    }
                }
            }
        }
        index
    }

    pub fn class_set(&self, class_def_idx: u32) -> Option<u32> {
        self.class_sets.get(&class_def_idx).copied()
    }

    pub fn field_set(&self, class_def_idx: u32, field_idx: u32) -> Option<u32> {
        self.field_sets.get(&(class_def_idx, field_idx)).copied()
    }

    pub fn method_set(&self, class_def_idx: u32, method_idx: u32) -> Option<u32> {
        self.method_sets.get(&(class_def_idx, method_idx)).copied()
    }

    /// The parameter slots of a method whose prototype has `prototype_parameters` parameters.
    /// `None` when the method has no parameter annotation list.
    pub fn parameter_slots(
        &self,
        class_def_idx: u32,
        method_idx: u32,
        prototype_parameters: usize,
    ) -> Option<ParameterSlots> {
        let key = (class_def_idx, method_idx);
        let slots = self.parameter_slots.get(&key)?;
        let encoded = self
            .parameter_counts
            .get(&key)
            .map_or(slots.len(), |count| *count as usize);
        // The slots are as many as the encoded list says; the list says how many, which the
        // trailing zero slots keep even when no set follows them.
        let complete = slots.len() == prototype_parameters && encoded == prototype_parameters;
        Some(if complete {
            ParameterSlots::Placed(slots.clone())
        } else {
            ParameterSlots::Unplaced {
                slots: slots.iter().flatten().count(),
            }
        })
    }

    /// The static values array that a byte offset names.
    pub fn array(&self, byte_offset: u32) -> Option<usize> {
        self.arrays.get(&byte_offset).copied()
    }

    /// Write the blocks of the set at `set_offset`, each at `indent`. Returns how many blocks
    /// were written. An offset that is no set of this DEX is an error.
    pub fn write_set(
        &self,
        out: &mut String,
        data: &DexAnnotations,
        context: &ValueContext<'_>,
        set_offset: u32,
        indent: usize,
    ) -> MddResult<usize> {
        let set = self
            .sets
            .get(&set_offset)
            .map(|position| &data.sets[*position])
            .ok_or_else(|| fault("an annotation set is not among the facts"))?;
        for offset in &set.annotation_offsets {
            let item = self
                .items
                .get(offset)
                .map(|position| &data.annotation_items[*position])
                .ok_or_else(|| fault("an annotation set names an item the facts do not hold"))?;
            let visibility = match item.visibility {
                0 => "build",
                1 => "runtime",
                2 => "system",
                _ => {
                    return Err(fault(
                        "an annotation has a visibility the format does not have",
                    ));
                }
            };
            let descriptor = context
                .metadata
                .types
                .get(item.type_idx as usize)
                .ok_or_else(|| fault("an annotation names a type the facts do not hold"))?
                .data
                .descriptor
                .as_str();
            push_indent(out, indent);
            out.push_str(".annotation ");
            out.push_str(visibility);
            out.push(' ');
            out.push_str(descriptor);
            out.push('\n');
            context.write_elements(out, &item.elements, indent + 4, 0)?;
            push_indent(out, indent);
            out.push_str(".end annotation\n");
        }
        Ok(set.annotation_offsets.len())
    }

    /// The same, one line per output line and without the final newline: the shape
    /// [`smali_required::MethodExtras`] takes.
    pub fn set_lines(
        &self,
        data: &DexAnnotations,
        context: &ValueContext<'_>,
        set_offset: u32,
        indent: usize,
    ) -> MddResult<Vec<String>> {
        let mut text = String::new();
        self.write_set(&mut text, data, context, set_offset, indent)?;
        Ok(text.split_terminator('\n').map(str::to_owned).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_slots_belong_to_parameters_only_when_they_are_as_many() {
        let mut index = AnnotationIndex::default();
        index.parameter_slots.insert((0, 5), vec![Some(100), None]);
        assert_eq!(
            index.parameter_slots(0, 5, 2),
            Some(ParameterSlots::Placed(vec![Some(100), None]))
        );
        // three parameters and two slots: which parameter has the annotation is not a fact
        assert_eq!(
            index.parameter_slots(0, 5, 3),
            Some(ParameterSlots::Unplaced { slots: 1 })
        );
        assert_eq!(
            index.parameter_slots(0, 5, 1),
            Some(ParameterSlots::Unplaced { slots: 1 })
        );
        // another method, another class: nothing
        assert_eq!(index.parameter_slots(0, 6, 2), None);
        assert_eq!(index.parameter_slots(1, 5, 2), None);
    }

    #[test]
    fn owners_are_told_apart_by_class_and_by_kind() {
        let mut index = AnnotationIndex::default();
        index.class_sets.insert(0, 10);
        index.field_sets.insert((0, 3), 20);
        index.method_sets.insert((0, 3), 30);
        assert_eq!(index.class_set(0), Some(10));
        assert_eq!(index.field_set(0, 3), Some(20));
        assert_eq!(index.method_set(0, 3), Some(30));
        assert_eq!(index.class_set(1), None);
        assert_eq!(index.field_set(1, 3), None);
        assert_eq!(index.method_set(0, 4), None);
    }
}
