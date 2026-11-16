//! The text of a class without its methods: declaration, superclass, source file, interfaces,
//! class annotations and fields with their initial values.
//!
//! ```text
//! .class public final Lpkg/K;
//! .super Ljava/lang/Object;
//! .source "K.java"
//!
//! .implements Ljava/lang/Runnable;
//!
//! .annotation runtime Lpkg/A;
//! .end annotation
//!
//! .field public static final A:I = 0x1
//! .field public static b:Ljava/lang/String; = "x"
//!
//! .field private c:I
//! .field private d:I
//!     .annotation runtime Lpkg/B;
//!     .end annotation
//! .end field
//! ```
//!
//! A section appears only when it has lines, and sections are separated by one blank line. The
//! static fields come first in the order the class data stores them, then the instance fields.
//! The *n*-th static field takes the *n*-th value of the class's static-values array; a static
//! field past the end of that array has no value written, which says that the array does not
//! hold one, not that the field is zero. The methods are separate texts (`render_method_full`).
//!
//! Flag words: a class prints `public private protected static final interface abstract
//! synthetic annotation enum` for the bits that are set (`0x20` is not a class flag and prints
//! nothing); a field prints `public private protected static final
//! volatile transient synthetic enum`. A bit without a word does not print; the numeric flags
//! stay in the facts.
use super::{annotation::AnnotationIndex, value::ValueContext};
use crate::{annotations::AnnotationFacts, metadata::MetadataFacts};
use mdd_dex::definitions::{ClassDefinition, DexDefinitions, FieldKind};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::fmt::Write as _;

fn fault(message: &str) -> MddError {
    MddError::new(ErrorCode::InternalFault, "facts.smali", message)
}

const CLASS_WORDS: [(u32, &str); 10] = [
    (0x1, "public"),
    (0x2, "private"),
    (0x4, "protected"),
    (0x8, "static"),
    (0x10, "final"),
    (0x200, "interface"),
    (0x400, "abstract"),
    (0x1000, "synthetic"),
    (0x2000, "annotation"),
    (0x4000, "enum"),
];
const FIELD_WORDS: [(u32, &str); 9] = [
    (0x1, "public"),
    (0x2, "private"),
    (0x4, "protected"),
    (0x8, "static"),
    (0x10, "final"),
    (0x40, "volatile"),
    (0x80, "transient"),
    (0x1000, "synthetic"),
    (0x4000, "enum"),
];

/// The words of a class's access flags.
pub fn class_flag_words(flags: u32) -> Vec<&'static str> {
    CLASS_WORDS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, word)| *word)
        .collect()
}

/// The words of a field's access flags.
pub fn field_flag_words(flags: u32) -> Vec<&'static str> {
    FIELD_WORDS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, word)| *word)
        .collect()
}

/// What a class is, for rendering.
pub struct ClassView<'a> {
    pub metadata: &'a MetadataFacts,
    pub definitions: &'a DexDefinitions,
    pub class: &'a ClassDefinition,
    pub annotations: Option<(&'a AnnotationFacts, &'a AnnotationIndex)>,
}

/// What one rendering may cost.
#[derive(Clone, Copy, Debug)]
pub struct ClassLimits {
    pub max_text_bytes: u64,
}

impl Default for ClassLimits {
    fn default() -> Self {
        Self {
            max_text_bytes: 64 * 1024 * 1024,
        }
    }
}

/// A class rendered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedClass {
    /// The `.class ...` line without its newline.
    pub declaration: String,
    pub text: String,
    pub static_fields: u32,
    pub instance_fields: u32,
    /// Static values the class's array holds; fewer than `static_fields` is allowed.
    pub static_values: u32,
    pub interfaces: u32,
    /// The class has annotations the annotation layer could not supply.
    pub annotation_layer_missing: bool,
}

/// Render the text of a class.
pub fn render_class(view: &ClassView<'_>, limits: ClassLimits) -> MddResult<RenderedClass> {
    let class = view.class;
    let definitions = view.definitions;
    let mut declaration = String::from(".class");
    for word in class_flag_words(class.access_flags) {
        declaration.push(' ');
        declaration.push_str(word);
    }
    declaration.push(' ');
    declaration.push_str(&class.descriptor);
    let mut text = String::new();
    text.push_str(&declaration);
    text.push('\n');
    if let Some(superclass) = &class.superclass_descriptor {
        let _ = writeln!(text, ".super {superclass}");
    }
    if let Some(source) = &class.source_file {
        text.push_str(".source ");
        crate::smali_required::push_string_literal(&mut text, &source.utf16_units);
        text.push('\n');
    }

    let mut interfaces: Vec<_> = definitions
        .interfaces
        .iter()
        .filter(|row| row.class_def_idx == class.class_def_idx)
        .collect();
    interfaces.sort_by_key(|row| row.ordinal);
    if !interfaces.is_empty() {
        text.push('\n');
        for row in &interfaces {
            let _ = writeln!(text, ".implements {}", row.interface_descriptor);
        }
    }

    let annotated = view.annotations;
    if let Some((facts, index)) = annotated
        && let Some(set) = index.class_set(class.class_def_idx)
    {
        let data = facts.data();
        let context = ValueContext {
            metadata: view.metadata,
            definitions,
            values: &data.values,
        };
        let mut blocks = String::new();
        if index.write_set(&mut blocks, data, &context, set, 0)? > 0 {
            text.push('\n');
            text.push_str(&blocks);
        }
    }

    let mut statics: Vec<_> = definitions
        .field_definitions
        .iter()
        .filter(|row| row.class_def_idx == class.class_def_idx && row.kind == FieldKind::Static)
        .collect();
    statics.sort_by_key(|row| row.ordinal);
    let mut instances: Vec<_> = definitions
        .field_definitions
        .iter()
        .filter(|row| row.class_def_idx == class.class_def_idx && row.kind == FieldKind::Instance)
        .collect();
    instances.sort_by_key(|row| row.ordinal);

    // The array of static values, as node ids of the shared value table.
    let (values, array): (&[mdd_dex::annotations::EncodedValue], &[u32]) = match annotated {
        Some((facts, index)) => {
            let data = facts.data();
            let elements = match class.static_values_byte_offset {
                Some(offset) => {
                    let offset = u32::try_from(offset.0)
                        .map_err(|_| fault("a static-values offset is past the file"))?;
                    let position = index.array(offset).ok_or_else(|| {
                        fault("a class names a static-values array the facts do not hold")
                    })?;
                    data.encoded_arrays[position].elements.as_slice()
                }
                None => &[],
            };
            (data.values.as_slice(), elements)
        }
        None => (&[], &[]),
    };
    let annotation_layer_missing = annotated.is_none()
        && (class.annotations_byte_offset.is_some() || class.static_values_byte_offset.is_some());
    let context = ValueContext {
        metadata: view.metadata,
        definitions,
        values,
    };
    for (rows, with_values) in [(&statics, true), (&instances, false)] {
        if rows.is_empty() {
            continue;
        }
        text.push('\n');
        for (position, row) in rows.iter().enumerate() {
            let field = definitions
                .field_references
                .get(row.field_idx as usize)
                .ok_or_else(|| fault("a field definition has no field reference"))?;
            let mut line = String::from(".field");
            for word in field_flag_words(row.access_flags) {
                line.push(' ');
                line.push_str(word);
            }
            let _ = write!(line, " {}:{}", field.field_name, field.type_descriptor);
            if with_values && let Some(node) = array.get(position) {
                line.push_str(" = ");
                context.write(&mut line, *node, 0)?;
            }
            text.push_str(&line);
            text.push('\n');
            if let Some((facts, index)) = annotated
                && let Some(set) = index.field_set(class.class_def_idx, row.field_idx)
            {
                let data = facts.data();
                let field_context = ValueContext {
                    metadata: view.metadata,
                    definitions,
                    values: &data.values,
                };
                let mut blocks = String::new();
                if index.write_set(&mut blocks, data, &field_context, set, 4)? > 0 {
                    text.push_str(&blocks);
                    text.push_str(".end field\n");
                }
            }
            if text.len() as u64 > limits.max_text_bytes {
                return Err(MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.smali",
                    "the rendered text is over the byte budget",
                )
                .detail("budget", "max_text_bytes")
                .detail("limit", limits.max_text_bytes.to_string()));
            }
        }
    }
    Ok(RenderedClass {
        declaration,
        text,
        static_fields: u32::try_from(statics.len()).map_err(|_| fault("too many fields"))?,
        instance_fields: u32::try_from(instances.len()).map_err(|_| fault("too many fields"))?,
        static_values: u32::try_from(array.len()).map_err(|_| fault("too many values"))?,
        interfaces: u32::try_from(interfaces.len()).map_err(|_| fault("too many interfaces"))?,
        annotation_layer_missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_class_prints_the_words_of_its_bits_in_the_prescribed_order_and_not_acc_super() {
        assert_eq!(class_flag_words(0x1 | 0x10 | 0x20), ["public", "final"]);
        assert_eq!(
            class_flag_words(0x1 | 0x200 | 0x400),
            ["public", "interface", "abstract"]
        );
        assert_eq!(
            class_flag_words(0x4000 | 0x2000 | 0x1000 | 0x1),
            ["public", "synthetic", "annotation", "enum"]
        );
        assert!(class_flag_words(0).is_empty());
        assert!(
            class_flag_words(0x20).is_empty(),
            "0x20 is not a class flag"
        );
    }

    #[test]
    fn a_field_prints_its_words_and_volatile_and_transient_are_fields_not_classes() {
        assert_eq!(
            field_flag_words(0x1 | 0x8 | 0x10),
            ["public", "static", "final"]
        );
        assert_eq!(
            field_flag_words(0x2 | 0x40 | 0x80),
            ["private", "volatile", "transient"]
        );
        assert_eq!(field_flag_words(0x4000 | 0x1000), ["synthetic", "enum"]);
        assert!(class_flag_words(0x40 | 0x80).is_empty());
        assert!(field_flag_words(0x20).is_empty());
    }
}
