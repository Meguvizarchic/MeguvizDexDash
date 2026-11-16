//! Encoded values as smali writes them: the elements of annotations and the initial values of
//! static fields.
//!
//! Every value is written from its node in the validated annotation facts and from the pools it
//! indexes; a value that names an index the pools do not hold is an error, never a placeholder.
//!
//! | kind | text |
//! | --- | --- |
//! | boolean, null | `true`, `false`, `null` |
//! | byte, short, int, long | signed hexadecimal, suffix `t`, `s`, none, `L` |
//! | char | the unit in single quotes, escaped like a string |
//! | float, double | the shortest decimal that reads back as the same bits, see [`float_text`]; suffix `f` for float |
//! | string | double quotes, escaped (`smali_required::push_string_literal`) |
//! | type, method type | the descriptor |
//! | field, method | `Lc;->n:t`, `Lc;->n(p)r` |
//! | enum | `.enum Lc;->N:Lc;` |
//! | method handle | `method_handle_<index>` (the handle's target is a fact, not text) |
//! | array | `{}`, or `{`, one element per line one level deeper, `}` |
//! | annotation | `.subannotation Lt;`, one element per line, `.end subannotation` |
//!
//! The text spells the value; it does not keep every bit. A NaN prints as `NaN` whatever its
//! payload, and `-0.0` and `0.0` differ. The exact bits stay in the annotation facts
//! (`float_bits`).
use crate::{metadata::MetadataFacts, smali_required::push_string_literal};
use mdd_dex::{
    annotations::{EncodedKind, EncodedValue},
    definitions::DexDefinitions,
};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::fmt::Write as _;

/// How deep values nest in one text. The facts bound it to 64 already; this is the guard of the
/// writer itself.
const MAX_DEPTH: usize = 256;

fn fault(message: &str) -> MddError {
    MddError::new(ErrorCode::InternalFault, "facts.smali", message)
}

/// What the writer reads: the pools and the node table of one DEX.
pub struct ValueContext<'a> {
    pub metadata: &'a MetadataFacts,
    pub definitions: &'a DexDefinitions,
    /// Indexed by `node_id`.
    pub values: &'a [EncodedValue],
}

fn signed_hex(text: &str) -> MddResult<String> {
    let value: i64 = text
        .parse()
        .map_err(|_| fault("an encoded integer is not a number"))?;
    Ok(crate::smali_required::hex_signed(value))
}

/// The shortest decimal text of a float or double that reads back as the same value, in this
/// shape: plain digits with at least one fractional digit when the decimal exponent is in
/// `-4..16`, otherwise `d.ddde<exp>` (no `+`, no padding). `NaN`, `Infinity` and `-Infinity`
/// are spelled so. The text for a float carries the suffix `f`.
pub fn float_text(bits: u64, width: u8) -> String {
    let (value, suffix) = if width == 32 {
        (f64::from(f32::from_bits(bits as u32)), "f")
    } else {
        (f64::from_bits(bits), "")
    };
    if value.is_nan() {
        return format!("NaN{suffix}");
    }
    if value.is_infinite() {
        return format!("{}Infinity{suffix}", if value < 0.0 { "-" } else { "" });
    }
    // `{:e}` gives the shortest digits that read back as the same value of the type, so a float
    // is formatted as a float: its digits are not those of the same value as a double.
    let scientific = if width == 32 {
        format!("{:e}", f32::from_bits(bits as u32))
    } else {
        format!("{value:e}")
    };
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("a float in scientific form has an exponent");
    let exponent: i32 = exponent.parse().expect("an exponent is a number");
    let (sign, digits) = match mantissa.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", mantissa),
    };
    let digits: String = digits.chars().filter(|c| *c != '.').collect();
    let body = if (-4..16).contains(&exponent) {
        let point = exponent + 1;
        if point <= 0 {
            format!("0.{}{}", "0".repeat((-point) as usize), digits)
        } else if (point as usize) >= digits.len() {
            format!("{}{}.0", digits, "0".repeat(point as usize - digits.len()))
        } else {
            format!(
                "{}.{}",
                &digits[..point as usize],
                &digits[point as usize..]
            )
        }
    } else if digits.len() == 1 {
        format!("{digits}.0e{exponent}")
    } else {
        format!("{}.{}e{exponent}", &digits[..1], &digits[1..])
    };
    format!("{sign}{body}{suffix}")
}

impl ValueContext<'_> {
    fn node(&self, id: u32) -> MddResult<&EncodedValue> {
        self.values
            .get(id as usize)
            .filter(|node| node.node_id == id)
            .ok_or_else(|| fault("an annotation names a value node the facts do not hold"))
    }

    fn type_descriptor(&self, index: u32) -> MddResult<&str> {
        self.metadata
            .types
            .get(index as usize)
            .map(|fact| fact.data.descriptor.as_str())
            .ok_or_else(|| fault("an annotation value names a type the facts do not hold"))
    }

    pub(crate) fn string_literal(&self, index: u32) -> MddResult<String> {
        let string = self
            .metadata
            .strings
            .get(index as usize)
            .ok_or_else(|| fault("an annotation value names a string the facts do not hold"))?;
        let mut out = String::new();
        push_string_literal(&mut out, &string.data.text.utf16_units);
        Ok(out)
    }

    pub(crate) fn name(&self, index: u32) -> MddResult<String> {
        let string =
            self.metadata.strings.get(index as usize).ok_or_else(|| {
                fault("an annotation element names a string the facts do not hold")
            })?;
        Ok(String::from_utf16_lossy(&string.data.text.utf16_units))
    }

    fn index(&self, node: &EncodedValue) -> MddResult<u32> {
        node.value_index
            .ok_or_else(|| fault("an encoded value has no index its kind needs"))
    }

    /// Write one value starting at the cursor; a value of several lines continues at `indent`.
    pub fn write(&self, out: &mut String, id: u32, indent: usize) -> MddResult<()> {
        self.write_at(out, id, indent, 0)
    }

    fn write_at(&self, out: &mut String, id: u32, indent: usize, depth: usize) -> MddResult<()> {
        if depth > MAX_DEPTH {
            return Err(fault("an encoded value nests deeper than the writer reads"));
        }
        let node = self.node(id)?;
        let number = || {
            node.value_i64
                .as_deref()
                .ok_or_else(|| fault("an encoded integer has no value"))
        };
        match node.kind {
            EncodedKind::Boolean => out.push_str(if number()? == "0" { "false" } else { "true" }),
            EncodedKind::Null => out.push_str("null"),
            EncodedKind::Byte => {
                out.push_str(&signed_hex(number()?)?);
                out.push('t');
            }
            EncodedKind::Short => {
                out.push_str(&signed_hex(number()?)?);
                out.push('s');
            }
            EncodedKind::Int => out.push_str(&signed_hex(number()?)?),
            EncodedKind::Long => {
                out.push_str(&signed_hex(number()?)?);
                out.push('L');
            }
            EncodedKind::Char => {
                let unit: u16 = number()?
                    .parse()
                    .map_err(|_| fault("an encoded char is not a code unit"))?;
                let mut quoted = String::new();
                push_string_literal(&mut quoted, &[unit]);
                // the same escapes as a string, between single quotes
                out.push('\'');
                out.push_str(&quoted[1..quoted.len() - 1]);
                out.push('\'');
            }
            EncodedKind::Float | EncodedKind::Double => {
                let bits = node
                    .float_bits
                    .ok_or_else(|| fault("an encoded float has no bits"))?
                    .0;
                let width = node
                    .float_bit_width
                    .ok_or_else(|| fault("an encoded float has no width"))?;
                out.push_str(&float_text(bits, width));
            }
            EncodedKind::String => out.push_str(&self.string_literal(self.index(node)?)?),
            EncodedKind::Type => out.push_str(self.type_descriptor(self.index(node)?)?),
            EncodedKind::MethodType => {
                let index = self.index(node)?;
                let prototype = self
                    .metadata
                    .prototypes
                    .get(index as usize)
                    .ok_or_else(|| {
                        fault("an annotation value names a prototype the facts do not hold")
                    })?;
                out.push_str(&prototype.data.descriptor);
            }
            EncodedKind::MethodHandle => {
                let _ = write!(out, "method_handle_{}", self.index(node)?);
            }
            EncodedKind::Field | EncodedKind::Enum => {
                let index = self.index(node)?;
                let field = self
                    .definitions
                    .field_references
                    .get(index as usize)
                    .ok_or_else(|| {
                        fault("an annotation value names a field the facts do not hold")
                    })?;
                if node.kind == EncodedKind::Enum {
                    out.push_str(".enum ");
                }
                let _ = write!(
                    out,
                    "{}->{}:{}",
                    field.class_descriptor, field.field_name, field.type_descriptor
                );
            }
            EncodedKind::Method => {
                let index = self.index(node)?;
                let method = self
                    .definitions
                    .method_references
                    .get(index as usize)
                    .ok_or_else(|| {
                        fault("an annotation value names a method the facts do not hold")
                    })?;
                let _ = write!(
                    out,
                    "{}->{}({}){}",
                    method.class_descriptor,
                    method.method_name,
                    method.parameter_descriptors.concat(),
                    method.return_descriptor
                );
            }
            EncodedKind::Array => {
                if node.children.is_empty() {
                    out.push_str("{}");
                } else {
                    out.push_str("{\n");
                    let last = node.children.len() - 1;
                    for (position, child) in node.children.iter().enumerate() {
                        push_indent(out, indent + 4);
                        self.write_at(out, *child, indent + 4, depth + 1)?;
                        if position != last {
                            out.push(',');
                        }
                        out.push('\n');
                    }
                    push_indent(out, indent);
                    out.push('}');
                }
            }
            EncodedKind::Annotation => {
                let type_index = self.index(node)?;
                let _ = writeln!(out, ".subannotation {}", self.type_descriptor(type_index)?);
                self.write_elements(out, &node.children, indent + 4, depth + 1)?;
                push_indent(out, indent);
                out.push_str(".end subannotation");
            }
        }
        Ok(())
    }

    /// `name = value` lines, one per element, each at `indent`, each ending in a newline.
    pub fn write_elements(
        &self,
        out: &mut String,
        elements: &[u32],
        indent: usize,
        depth: usize,
    ) -> MddResult<()> {
        for element in elements {
            let node = self.node(*element)?;
            let name = node
                .name_idx
                .ok_or_else(|| fault("an annotation element has no name"))?;
            push_indent(out, indent);
            out.push_str(&self.name(name)?);
            out.push_str(" = ");
            self.write_at(out, *element, indent, depth)?;
            out.push('\n');
        }
        Ok(())
    }
}

pub(crate) fn push_indent(out: &mut String, spaces: usize) {
    for _ in 0..spaces {
        out.push(' ');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(value: f32) -> String {
        float_text(u64::from(value.to_bits()), 32)
    }
    fn d(value: f64) -> String {
        float_text(value.to_bits(), 64)
    }

    #[test]
    fn floats_print_as_their_shortest_reading_with_a_point_and_a_suffix() {
        assert_eq!(f(1.0), "1.0f");
        assert_eq!(f(1.5), "1.5f");
        assert_eq!(f(-0.0), "-0.0f");
        assert_eq!(
            f(0.1),
            "0.1f",
            "0.1 as a float, not as the double it widens to"
        );
        assert_eq!(f(16_777_216.0), "16777216.0f");
        assert_eq!(f(0.000_1), "0.0001f");
        assert_eq!(f(0.000_01), "1.0e-5f");
        assert_eq!(f(1.0e16), "1.0e16f");
        assert_eq!(f(3.4028235e38), "3.4028235e38f");
        assert_eq!(d(0.1), "0.1");
        assert_eq!(d(100.0), "100.0");
        assert_eq!(d(1.0e15), "1000000000000000.0");
        assert_eq!(d(1.0e16), "1.0e16");
        assert_eq!(d(1.2345e-7), "1.2345e-7");
        assert_eq!(d(f64::MAX), "1.7976931348623157e308");
        assert_eq!(d(5e-324), "5.0e-324");
    }

    #[test]
    fn what_is_not_a_number_is_spelled_as_a_word_and_a_payload_is_not_kept() {
        assert_eq!(float_text(0x7fc0_1234, 32), "NaNf");
        assert_eq!(float_text(0x7ff8_0000_0000_0000, 64), "NaN");
        assert_eq!(float_text(0x7f80_0000, 32), "Infinityf");
        assert_eq!(float_text(0xff80_0000, 32), "-Infinityf");
        assert_eq!(float_text(0xfff0_0000_0000_0000, 64), "-Infinity");
    }

    #[test]
    fn a_shortest_reading_reads_back_as_the_same_bits() {
        for bits in [
            1u32,
            0x0080_0000,
            0x3f80_0001,
            0x4b00_0001,
            0x7f7f_ffff,
            0x0000_0001,
        ] {
            let text = f(f32::from_bits(bits));
            let digits = text.trim_end_matches('f');
            assert_eq!(digits.parse::<f32>().unwrap().to_bits(), bits, "{text}");
        }
    }
}
