//! The `context` view of a text: its anchor lines with the zero-based number each has in the
//! full text.
//!
//! The view is derived from the text and from nothing else, so a number in it always names a
//! line of the text it was cut from, and the line after the number is that line, byte for byte.
//! It is a separate text with its own lines and byte offsets: an offset into it never continues
//! the full text, and the full text's offsets never page it.
//!
//! The reference engine (dexsql 0.1.0) writes the same view; a check against its answers for
//! every method of the decode fixture found its anchor lines to be exactly these (see
//! `conformance/decode/a0_replay.py`).

/// The first line of every method context text.
pub const CONTEXT_HEADER: &str =
    "# Original zero-based smali line numbers; labels retain method-relative code-unit offsets.";

/// The lines of a method text that the context view keeps: the method line, the register line,
/// every label (including the case labels inside a switch table) and every exception-table line.
/// The first word of the trimmed line decides, and the words are these:
const METHOD_ANCHORS: [&str; 3] = [".method", ".registers", ".catch"];

/// The lines of a class text that the context view keeps.
const CLASS_ANCHORS: [&str; 5] = [".class", ".super", ".source", ".implements", ".field"];

fn is_anchor(trimmed: &str, words: &[&str]) -> bool {
    trimmed.starts_with(':') || words.iter().any(|word| trimmed.starts_with(word))
}

fn build(header: &str, text: &str, words: &[&str]) -> String {
    let mut out = String::with_capacity(header.len() + 1);
    out.push_str(header);
    out.push('\n');
    for (number, line) in text.split_terminator('\n').enumerate() {
        if is_anchor(line.trim_start(), words) {
            out.push_str("line ");
            out.push_str(&number.to_string());
            out.push_str(": ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The context text of one method's smali text.
pub fn method_context(text: &str) -> String {
    build(CONTEXT_HEADER, text, &METHOD_ANCHORS)
}

/// The context text of a class's smali text (header, interfaces, fields).
pub fn class_context(text: &str) -> String {
    build(CLASS_CONTEXT_HEADER, text, &CLASS_ANCHORS)
}

/// The first line of every class context text.
pub const CLASS_CONTEXT_HEADER: &str = "# Original zero-based smali line numbers of the class text; fields and interfaces are listed with their lines.";

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = ".method public static f()V\n    .registers 2\n\n    :try_start_0\n    invoke-static {}, La;->b()V\n    :try_end_0\n    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0\n    return-void\n    :catch_0\n    .sparse-switch\n        0x1 -> :sswitch_0\n    .end sparse-switch\n.end method\n";

    #[test]
    fn the_view_keeps_the_method_line_registers_labels_and_catch_lines_with_their_numbers() {
        let view = method_context(TEXT);
        assert_eq!(
            view,
            format!(
                "{CONTEXT_HEADER}\nline 0: .method public static f()V\nline 1:     .registers 2\nline 3:     :try_start_0\nline 5:     :try_end_0\nline 6:     .catch Ljava/lang/Exception; {{:try_start_0 .. :try_end_0}} :catch_0\nline 8:     :catch_0\n"
            )
        );
    }

    #[test]
    fn every_numbered_line_is_the_line_of_the_text_it_names_and_instructions_are_never_kept() {
        let lines: Vec<&str> = TEXT.split_terminator('\n').collect();
        for entry in method_context(TEXT).lines().skip(1) {
            let (number, line) = entry
                .strip_prefix("line ")
                .and_then(|rest| rest.split_once(": "))
                .unwrap();
            assert_eq!(lines[number.parse::<usize>().unwrap()], line);
            assert!(!line.trim_start().starts_with("invoke"));
        }
    }

    #[test]
    fn a_case_entry_of_a_sparse_switch_is_not_a_label_line_but_a_packed_one_is() {
        let text = ".method a\n    .packed-switch 0x0\n        :pswitch_0\n    .end packed-switch\n    .sparse-switch\n        0x1 -> :sswitch_0\n    .end sparse-switch\n.end method\n";
        let view = method_context(text);
        assert!(view.contains("line 2:         :pswitch_0\n"));
        assert!(!view.contains("sswitch"));
    }

    #[test]
    fn a_text_without_anchors_still_has_its_header_and_a_missing_final_newline_is_harmless() {
        assert_eq!(method_context(""), format!("{CONTEXT_HEADER}\n"));
        assert_eq!(
            method_context(".method a"),
            format!("{CONTEXT_HEADER}\nline 0: .method a\n")
        );
    }

    #[test]
    fn the_class_view_keeps_the_class_lines_and_fields() {
        let text = ".class public Lp/C;\n.super Ljava/lang/Object;\n\n.field public static a:I = 0x1\n\n.field private b:I\n    .annotation runtime Lx;\n    .end annotation\n.end field\n";
        let view = class_context(text);
        assert!(view.starts_with(CLASS_CONTEXT_HEADER));
        for wanted in [
            "line 0: .class public Lp/C;",
            "line 1: .super Ljava/lang/Object;",
            "line 3: .field public static a:I = 0x1",
            "line 5: .field private b:I",
        ] {
            assert!(view.contains(wanted), "{wanted}");
        }
        assert!(!view.contains("annotation"));
    }
}
