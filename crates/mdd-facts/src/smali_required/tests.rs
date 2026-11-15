use super::*;

const TEXT: &str = ".method a\n    .registers 1\n\n    nop\n.end method\n";

fn lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

#[test]
fn a_page_of_two_lines_starts_at_the_text_and_says_where_to_continue() {
    let page = page_text(TEXT, 0, 2, None).unwrap();
    assert_eq!(page.text, ".method a\n    .registers 1\n");
    assert_eq!(
        (
            page.offset,
            page.next_offset,
            page.start_line,
            page.end_line
        ),
        (0, Some(27), 0, 2)
    );
    assert!(!page.starts_mid_line && !page.ends_mid_line);
    assert_eq!((page.total_bytes, page.total_lines), (TEXT.len() as u64, 5));
}

#[test]
fn the_last_page_has_no_continuation_and_the_whole_text_is_one_page_when_it_fits() {
    let page = page_text(TEXT, 0, 1000, None).unwrap();
    assert_eq!(page.text, TEXT);
    assert_eq!(page.next_offset, None);
    assert_eq!((page.start_line, page.end_line), (0, 5));
}

#[test]
fn offsets_are_bytes_and_line_numbers_are_lines_and_the_two_are_not_mixed() {
    // offset 27 is the start of line 2 (the blank line), not "line 27"
    let page = page_text(TEXT, 27, 1, None).unwrap();
    assert_eq!(page.text, "\n");
    assert_eq!((page.start_line, page.end_line), (2, 3));
    assert_eq!(page.next_offset, Some(28));
    assert!(!page.starts_mid_line);
    // offset 26 is the newline that ends line 1: the page starts inside that line
    let tail = page_text(TEXT, 26, 1, None).unwrap();
    assert_eq!(
        (tail.text, tail.start_line, tail.starts_mid_line),
        ("\n", 1, true)
    );
}

#[test]
fn a_page_may_start_inside_a_line_and_counts_that_line_as_one() {
    let page = page_text(TEXT, 5, 2, None).unwrap();
    assert_eq!(page.text, "od a\n    .registers 1\n");
    assert!(page.starts_mid_line && !page.ends_mid_line);
    assert_eq!((page.start_line, page.end_line), (0, 2));
}

#[test]
fn a_byte_budget_cuts_inside_a_line_and_the_next_page_says_it_starts_there() {
    let first = page_text(TEXT, 0, 1000, Some(4)).unwrap();
    assert_eq!(first.text, ".met");
    assert!(first.ends_mid_line && !first.starts_mid_line);
    assert_eq!((first.next_offset, first.end_line), (Some(4), 1));
    let second = page_text(TEXT, 4, 1000, Some(4)).unwrap();
    assert_eq!(second.text, "hod ");
    assert!(second.starts_mid_line && second.ends_mid_line);
    assert_eq!((second.start_line, second.end_line), (0, 1));
}

#[test]
fn a_budget_that_ends_exactly_on_a_line_boundary_is_not_a_mid_line_cut() {
    let page = page_text(TEXT, 0, 1000, Some(10)).unwrap();
    assert_eq!(page.text, ".method a\n");
    assert!(!page.ends_mid_line);
    assert_eq!(page.next_offset, Some(10));
}

#[test]
fn a_walk_by_any_budget_rebuilds_the_text_without_gaps_or_overlaps() {
    let text = "α\nβγ\nlong line with ünïcode and 中文\n\nend\n";
    for budget in [3, 4, 5, 7, 16, 1000] {
        for max_lines in [1, 2, 1000] {
            let mut rebuilt = String::new();
            let mut offset = 0u64;
            loop {
                let page = page_text(text, offset, max_lines, Some(budget)).unwrap();
                assert!(page.text.len() as u64 <= budget);
                assert_eq!(page.offset, offset);
                rebuilt.push_str(page.text);
                match page.next_offset {
                    Some(next) => {
                        assert_eq!(
                            next,
                            offset + page.text.len() as u64,
                            "{budget} {max_lines}"
                        );
                        offset = next;
                    }
                    None => break,
                }
            }
            assert_eq!(rebuilt, text, "{budget} {max_lines}");
        }
    }
}

#[test]
fn a_cut_never_lands_inside_a_character() {
    // 'é' is two bytes, '中' three
    let text = "é中\n";
    let page = page_text(text, 0, 10, Some(1)).err().unwrap();
    assert_eq!(page.message, "MAX_BYTES_TOO_SMALL");
    assert_eq!(page_text(text, 0, 10, Some(2)).unwrap().text, "é");
    assert_eq!(
        page_text(text, 0, 10, Some(4)).unwrap().text,
        "é",
        "the three bytes of 中 do not fit in two"
    );
    assert_eq!(page_text(text, 0, 10, Some(5)).unwrap().text, "é中");
}

#[test]
fn an_offset_inside_a_character_or_past_the_end_is_refused_and_one_at_the_end_is_empty() {
    let text = "é中\n";
    assert_eq!(
        page_text(text, 1, 10, None).err().unwrap().message,
        "OFFSET_NOT_ON_CHARACTER_BOUNDARY"
    );
    assert_eq!(
        page_text(text, 3, 10, None).err().unwrap().message,
        "OFFSET_NOT_ON_CHARACTER_BOUNDARY"
    );
    assert_eq!(
        page_text(text, 7, 10, None).err().unwrap().message,
        "OFFSET_OUT_OF_RANGE"
    );
    let end = page_text(text, 6, 10, None).unwrap();
    assert_eq!((end.text, end.next_offset), ("", None));
}

#[test]
fn zero_lines_is_refused_and_an_empty_text_is_one_empty_page() {
    assert!(page_text(TEXT, 0, 0, None).is_err());
    let page = page_text("", 0, 5, None).unwrap();
    assert_eq!(
        (page.text, page.next_offset, page.total_lines),
        ("", None, 0)
    );
}

#[test]
fn a_text_that_does_not_end_in_a_newline_counts_its_last_line() {
    let page = page_text("a\nb", 0, 10, None).unwrap();
    assert_eq!(
        (page.total_lines, page.end_line, page.next_offset),
        (2, 2, None)
    );
    assert!(!page.ends_mid_line, "the end of the text is not a cut");
}

#[test]
fn literals_are_signed_hexadecimal() {
    assert_eq!(hex_signed(0), "0x0");
    assert_eq!(hex_signed(255), "0xff");
    assert_eq!(hex_signed(-1), "-0x1");
    assert_eq!(hex_signed(i64::MIN), "-0x8000000000000000");
    assert_eq!(hex_signed(i64::MAX), "0x7fffffffffffffff");
}

#[test]
fn a_string_literal_escapes_what_the_format_escapes_and_nothing_else() {
    let mut out = String::new();
    let units: Vec<u16> = "a\"b'c\\d\n\t\r\u{8}\u{c}é中".encode_utf16().collect();
    push_string_literal(&mut out, &units);
    assert_eq!(out, "\"a\\\"b\\'c\\\\d\\n\\t\\r\\b\\f\\u00e9\\u4e2d\"");
    // a lone surrogate is one unit and is spelled as that unit
    let mut out = String::new();
    push_string_literal(&mut out, &[0x61, 0xd800, 0x62, 0x0000, 0x007f]);
    assert_eq!(out, "\"a\\ud800b\\u0000\\u007f\"");
    // a pair stays two units
    let mut out = String::new();
    let units: Vec<u16> = "😀".encode_utf16().collect();
    push_string_literal(&mut out, &units);
    assert_eq!(out, "\"\\ud83d\\ude00\"");
}

#[test]
fn access_flags_print_in_the_prescribed_order_and_skip_bits_without_a_word() {
    assert_eq!(access_flag_words(0x9), ["public", "static"]);
    assert_eq!(
        access_flag_words(0x1 | 0x20 | 0x100 | 0x8),
        ["public", "static", "synchronized", "native"]
    );
    assert_eq!(access_flag_words(0x10000 | 0x1), ["public", "constructor"]);
    assert!(access_flag_words(0x200).is_empty());
    assert_eq!(access_flag_words(0), Vec::<&str>::new());
    assert_eq!(lines(TEXT).len(), 5);
}
