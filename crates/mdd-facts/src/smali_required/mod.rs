//! Smali text for one method, rendered from validated facts, and its paging.
//!
//! The text is a display of facts already proven elsewhere: instructions come from the
//! code layer (`mdd_dex::instructions`), names from the metadata and definition layers.
//! Nothing here reads the DEX again to decide what an instruction means, and a method is
//! never rendered from guesses: an index the facts cannot resolve is an error, not a
//! placeholder.
//!
//! # Format
//!
//! The one reference output on record (the reference engine's `decode` of a four
//! instruction method, evidence/compatibility/0.1.0) fixes the frame and the common
//! instructions:
//!
//! ```text
//! .method public static foo()V
//!     .registers 1
//!
//!     const-string v0, "needle"
//!     invoke-static {}, Ldemo/B;->bar()V
//!     return-void
//! .end method
//! ```
//!
//! Everything the recording does not show follows the baksmali conventions (default
//! options, hexadecimal code-address labels), and is this crate's own choice until a
//! reference output says otherwise: parameter registers print as `pN`, labels are
//! `:goto_<hex address>`, `:cond_`, `:pswitch_`, `:pswitch_data_`, `:sswitch_`,
//! `:sswitch_data_`, `:array_`, `:try_start_`, `:try_end_`, `:catch_`, `:catchall_`,
//! each directive on its own line. This module writes the *instructions* of a method: the
//! annotations, parameter names and debug directives of the complete format (`mdd.smali.v1`)
//! are added by `crate::smali` through [`MethodExtras`], and the reference's SQL tables remain
//! where those facts are queried. This comment is the specification of the instruction text; the independent
//! renderer in `conformance/decode/oracle.py` and the hand-written texts in
//! `conformance/decode/hand-expected.txt` were written from it, not from this code.
use crate::metadata::MetadataFacts;
use mdd_dex::{
    definitions::{DexDefinitions, MethodDefinition},
    instructions::CodeItem,
};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

mod render;

pub use render::{
    SmaliLimits, access_flag_words, method_declaration, render_method, render_method_with,
};

/// What a method is, for rendering: its definition, its code if it has any, and the
/// pools that name what the instructions refer to.
pub struct MethodView<'a> {
    pub metadata: &'a MetadataFacts,
    pub definitions: &'a DexDefinitions,
    pub definition: &'a MethodDefinition,
    pub code: Option<&'a CodeItem>,
}

/// Lines a caller adds to the text of a method: the annotations, parameter names and debug
/// directives of the complete format (`crate::smali`). This module places them and does not
/// look inside them, so the instruction text is the same with or without them.
///
/// Every line is complete: indented, without its newline.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MethodExtras {
    /// After `.registers N` (after the `.method` line when the method has no code), before
    /// the blank line that precedes the first instruction.
    pub header: Vec<String>,
    /// Before the instruction that starts at the code-unit address (after the labels and
    /// `.catch` lines of that address). The key `insns_size` places lines after the last
    /// instruction. An address where no instruction starts is refused.
    pub at_address: BTreeMap<u32, Vec<String>>,
}

/// One method, rendered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedMethod {
    /// The `.method ...` line without its newline.
    pub declaration: String,
    /// The whole text, every line ending in a newline.
    pub text: String,
    pub registers: Option<u16>,
    pub code_units: Option<u32>,
    pub try_count: Option<u16>,
}

fn fault(message: &str) -> MddError {
    MddError::new(ErrorCode::InternalFault, "facts.smali", message)
}

fn bad_argument(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "facts.smali", message)
}

/// One page of a text, cut on line boundaries or, when a byte budget says so, inside a
/// line but never inside a character.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextPage<'a> {
    pub text: &'a str,
    /// The UTF-8 byte offset the page starts at.
    pub offset: u64,
    /// The byte offset to continue from, `None` when the text ends with this page.
    pub next_offset: Option<u64>,
    /// Zero-based line the page starts in.
    pub start_line: u64,
    /// One past the last line the page touches.
    pub end_line: u64,
    pub starts_mid_line: bool,
    pub ends_mid_line: bool,
    pub total_bytes: u64,
    pub total_lines: u64,
}

/// Take a page of `text` from byte `offset`: at most `max_lines` lines (a line the
/// offset falls inside counts as one) and, when given, at most `max_bytes` bytes.
///
/// The three units are never mixed: `offset`/`max_bytes` are UTF-8 bytes of the text,
/// `max_lines` and the line fields count lines of the text. An offset past the end or
/// inside a character is refused; an offset at the end is an empty final page.
pub fn page_text(
    text: &str,
    offset: u64,
    max_lines: u64,
    max_bytes: Option<u64>,
) -> MddResult<TextPage<'_>> {
    if max_lines == 0 {
        return Err(bad_argument("max_lines must be at least 1"));
    }
    let total = text.len();
    let start = usize::try_from(offset).map_err(|_| bad_argument("OFFSET_OUT_OF_RANGE"))?;
    if start > total {
        return Err(bad_argument("OFFSET_OUT_OF_RANGE")
            .detail("offset", offset.to_string())
            .detail("total_bytes", total.to_string()));
    }
    if !text.is_char_boundary(start) {
        return Err(
            bad_argument("OFFSET_NOT_ON_CHARACTER_BOUNDARY").detail("offset", offset.to_string())
        );
    }
    let bytes = text.as_bytes();
    let newline_count = |slice: &[u8]| slice.iter().filter(|b| **b == b'\n').count() as u64;
    let total_lines =
        newline_count(bytes) + u64::from(!bytes.is_empty() && bytes[total - 1] != b'\n');
    let start_line = newline_count(&bytes[..start]);
    let starts_mid_line = start > 0 && bytes[start - 1] != b'\n';
    let mut end = start;
    let mut taken = 0u64;
    let mut cut_inside_line = false;
    while end < total && taken < max_lines {
        let line_end = bytes[end..]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(total, |at| end + at + 1);
        if let Some(budget) = max_bytes {
            let used = (end - start) as u64;
            let left = budget.saturating_sub(used);
            if (line_end - end) as u64 > left {
                let mut stop = end
                    + usize::try_from(left)
                        .unwrap_or(usize::MAX)
                        .min(line_end - end);
                while stop > end && !text.is_char_boundary(stop) {
                    stop -= 1;
                }
                if stop == end {
                    if taken == 0 {
                        return Err(bad_argument("MAX_BYTES_TOO_SMALL")
                            .detail("max_bytes", budget.to_string()));
                    }
                    break;
                }
                end = stop;
                taken += 1;
                cut_inside_line = true;
                break;
            }
        }
        end = line_end;
        taken += 1;
    }
    let ends_mid_line = cut_inside_line || (end < total && end > 0 && bytes[end - 1] != b'\n');
    Ok(TextPage {
        text: &text[start..end],
        offset,
        next_offset: (end < total).then_some(end as u64),
        start_line,
        end_line: start_line + taken,
        starts_mid_line,
        ends_mid_line,
        total_bytes: total as u64,
        total_lines,
    })
}

/// Collects the labels a method needs, by address, before any line is written, so a
/// label is printed exactly where its address is reached.
#[derive(Default)]
struct Labels {
    at: BTreeMap<u32, BTreeSet<String>>,
}

impl Labels {
    fn add(&mut self, address: u32, prefix: &str) -> String {
        let name = format!("{prefix}{address:x}");
        self.at.entry(address).or_default().insert(name.clone());
        name
    }
}

/// `-0x1` / `0x1f`: a signed value in hexadecimal, the way smali spells literals.
pub(crate) fn hex_signed(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{value:x}")
    }
}

pub(crate) fn push_string_literal(out: &mut String, units: &[u16]) {
    out.push('"');
    for &unit in units {
        match unit {
            0x22 => out.push_str("\\\""),
            0x27 => out.push_str("\\'"),
            0x5c => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0a => out.push_str("\\n"),
            0x0c => out.push_str("\\f"),
            0x0d => out.push_str("\\r"),
            0x20..=0x7e => out.push(char::from(unit as u8)),
            other => {
                let _ = write!(out, "\\u{other:04x}");
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests;
