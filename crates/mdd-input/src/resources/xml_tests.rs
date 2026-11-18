//! Binary XML assembled byte by byte, for the shapes of namespace, escaping and nesting that the
//! fixtures do not have. Each test names the document and the text it must give.
use super::xml::render;
use crate::manifest::{ManifestLimits, parse_xml_resource};
use mdd_types::ErrorCode;
use std::sync::Arc;

const NONE: u32 = 0xffff_ffff;

fn node(kind: u16, line: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = kind.to_le_bytes().to_vec();
    out.extend(16u16.to_le_bytes());
    out.extend(((16 + payload.len()) as u32).to_le_bytes());
    out.extend(line.to_le_bytes());
    out.extend(NONE.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// A string pool, UTF-8 or UTF-16 (the units given as they are, a lone surrogate included).
fn pool(strings: &[Vec<u16>], utf8: bool) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        if utf8 {
            let text = String::from_utf16(s).expect("valid text");
            data.push(s.len() as u8);
            data.push(text.len() as u8);
            data.extend_from_slice(text.as_bytes());
            data.push(0);
        } else {
            data.extend((s.len() as u16).to_le_bytes());
            for unit in s {
                data.extend(unit.to_le_bytes());
            }
            data.extend([0, 0]);
        }
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let start = 28 + 4 * offsets.len();
    let mut out = 1u16.to_le_bytes().to_vec();
    out.extend(28u16.to_le_bytes());
    out.extend(((start + data.len()) as u32).to_le_bytes());
    out.extend(words(&[
        strings.len() as u32,
        0,
        if utf8 { 0x100 } else { 0 },
        start as u32,
        0,
    ]));
    out.extend(words(&offsets));
    out.extend(data);
    out
}

fn document(pool: Vec<u8>, nodes: Vec<Vec<u8>>) -> Vec<u8> {
    let mut body = pool;
    for n in nodes {
        body.extend(n);
    }
    let mut out = 3u16.to_le_bytes().to_vec();
    out.extend(8u16.to_le_bytes());
    out.extend(((8 + body.len()) as u32).to_le_bytes());
    out.extend(body);
    out
}

fn start_ns(prefix: u32, uri: u32) -> Vec<u8> {
    node(0x100, 1, &words(&[prefix, uri]))
}
fn end_ns(prefix: u32, uri: u32) -> Vec<u8> {
    node(0x101, 1, &words(&[prefix, uri]))
}
fn end_element(ns: u32, name: u32) -> Vec<u8> {
    node(0x103, 1, &words(&[ns, name]))
}
fn text(string: u32) -> Vec<u8> {
    let mut payload = words(&[string]);
    payload.extend(8u16.to_le_bytes());
    payload.extend([0, 3]);
    payload.extend(string.to_le_bytes());
    node(0x104, 1, &payload)
}

/// (namespace, name, raw string, type, data)
type Attr = (u32, u32, u32, u8, u32);

fn start_element(ns: u32, name: u32, attrs: &[Attr]) -> Vec<u8> {
    let mut payload = words(&[ns, name]);
    for half in [20u16, 20, attrs.len() as u16, 0, 0, 0] {
        payload.extend(half.to_le_bytes());
    }
    for (ns, name, raw, kind, data) in attrs {
        payload.extend(words(&[*ns, *name, *raw]));
        payload.extend(8u16.to_le_bytes());
        payload.extend([0, *kind]);
        payload.extend(data.to_le_bytes());
    }
    node(0x102, 1, &payload)
}

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn shown(bytes: Vec<u8>) -> Result<String, mdd_types::MddError> {
    let parsed = parse_xml_resource(Arc::from(bytes), ManifestLimits::default())?;
    render(&parsed)
}

const HEADER: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";

/// Pool indexes: 0 "", 1 "urn:d", 2 "urn:p", 3 "p", 4 "root", 5 "a", 6 "v", 7 "child".
fn strings() -> Vec<Vec<u16>> {
    ["", "urn:d", "urn:p", "p", "root", "a", "v", "child"]
        .iter()
        .map(|s| units(s))
        .collect()
}

#[test]
fn a_default_namespace_is_written_without_a_prefix_and_a_prefixed_one_with_it() {
    let nodes = vec![
        start_ns(NONE, 1),
        start_ns(3, 2),
        start_element(1, 4, &[(2, 5, 6, 3, 6)]),
        end_element(1, 4),
        end_ns(3, 2),
        end_ns(NONE, 1),
    ];
    let text = shown(document(pool(&strings(), true), nodes)).unwrap();
    assert_eq!(
        text,
        format!("{HEADER}<root\n  xmlns=\"urn:d\"\n  xmlns:p=\"urn:p\"\n  p:a=\"v\"/>\n")
    );
}

#[test]
fn an_attribute_in_a_namespace_that_only_has_a_default_binding_is_refused() {
    let nodes = vec![
        start_ns(NONE, 1),
        start_element(1, 4, &[(1, 5, 6, 3, 6)]),
        end_element(1, 4),
        end_ns(NONE, 1),
    ];
    let error = shown(document(pool(&strings(), true), nodes)).unwrap_err();
    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
    assert_eq!(error.details["name"], "a");
}

#[test]
fn a_prefix_that_is_rebound_inside_is_not_used_for_the_outer_uri() {
    // pool: ..., "urn:x" 8, "urn:y" 9, "b" 10
    let mut s = strings();
    s.extend(["urn:x", "urn:y", "b"].iter().map(|s| units(s)));
    let nodes = vec![
        start_ns(10, 8), // b -> x
        start_ns(3, 8),  // p -> x
        start_element(NONE, 4, &[]),
        start_ns(3, 9), // p -> y inside, so p no longer names x
        start_element(NONE, 7, &[(8, 5, 6, 3, 6)]),
        end_element(NONE, 7),
        end_ns(3, 9),
        end_element(NONE, 4),
        end_ns(3, 8),
        end_ns(10, 8),
    ];
    let text = shown(document(pool(&s, true), nodes)).unwrap();
    assert!(text.contains("\n    b:a=\"v\"/>"), "{text}");
    assert!(!text.contains("p:a="), "{text}");
}

#[test]
fn two_prefixes_for_one_uri_are_settled_by_the_later_declaration() {
    let mut s = strings();
    s.push(units("q")); // 8
    let nodes = vec![
        start_ns(3, 2), // p -> urn:p
        start_ns(8, 2), // q -> urn:p
        start_element(NONE, 4, &[(2, 5, 6, 3, 6)]),
        end_element(NONE, 4),
        end_ns(8, 2),
        end_ns(3, 2),
    ];
    let text = shown(document(pool(&s, true), nodes)).unwrap();
    assert!(text.contains("q:a=\"v\""), "{text}");
}

#[test]
fn an_attribute_value_is_escaped_and_its_control_characters_are_references() {
    let mut s = strings();
    s.push(units("a\"b&c<d>e'f\n\t\u{1}"));
    let nodes = vec![
        start_element(NONE, 4, &[(NONE, 5, 8, 3, 8)]),
        end_element(NONE, 4),
    ];
    let text = shown(document(pool(&s, true), nodes)).unwrap();
    assert_eq!(
        text,
        format!("{HEADER}<root a=\"a&quot;b&amp;c&lt;d&gt;e&apos;f&#xA;&#x9;&#x1;\"/>\n")
    );
}

#[test]
fn text_nodes_are_indented_escaped_and_make_the_element_open() {
    let mut s = strings();
    s.push(units("x<y&z"));
    let nodes = vec![
        start_element(NONE, 4, &[]),
        start_element(NONE, 7, &[(NONE, 5, NONE, 0x10, 5)]),
        end_element(NONE, 7),
        text(8),
        end_element(NONE, 4),
    ];
    let text = shown(document(pool(&s, true), nodes)).unwrap();
    assert_eq!(
        text,
        format!("{HEADER}<root>\n  <child a=\"5\"/>\n  x&lt;y&amp;z\n</root>\n")
    );
}

#[test]
fn an_element_with_one_attribute_is_on_one_line_with_two_it_is_not() {
    let one = vec![
        start_element(NONE, 4, &[(NONE, 5, NONE, 0x12, NONE)]),
        end_element(NONE, 4),
    ];
    assert_eq!(
        shown(document(pool(&strings(), true), one)).unwrap(),
        format!("{HEADER}<root a=\"true\"/>\n")
    );
    let two = vec![
        start_element(
            NONE,
            4,
            &[(NONE, 5, NONE, 0x10, 1), (NONE, 6, NONE, 0x10, 2)],
        ),
        end_element(NONE, 4),
    ];
    assert_eq!(
        shown(document(pool(&strings(), true), two)).unwrap(),
        format!("{HEADER}<root\n  a=\"1\"\n  v=\"2\"/>\n")
    );
    let none = vec![start_element(NONE, 4, &[]), end_element(NONE, 4)];
    assert_eq!(
        shown(document(pool(&strings(), true), none)).unwrap(),
        format!("{HEADER}<root/>\n")
    );
}

#[test]
fn a_string_with_an_unpaired_surrogate_is_refused_naming_the_attribute() {
    let mut s = strings();
    s.push(vec![0x61, 0xd800, 0x62]);
    let nodes = vec![
        start_element(NONE, 4, &[(NONE, 5, 8, 3, 8)]),
        end_element(NONE, 4),
    ];
    let error = shown(document(pool(&s, false), nodes)).unwrap_err();
    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
    assert_eq!(error.details["attribute"], "a");
}

#[test]
fn only_the_android_namespace_gets_framework_names_for_its_integers() {
    // "urn:android" stands for the platform's namespace only by its exact URI
    let mut s = strings();
    s.push(units("http://schemas.android.com/apk/res/android")); // 8
    s.push(units("protectionLevel")); // 9
    let nodes = vec![
        start_ns(3, 8),
        start_element(NONE, 4, &[(8, 9, NONE, 0x10, 2), (2, 9, NONE, 0x10, 2)]),
        end_element(NONE, 4),
        end_ns(3, 8),
    ];
    // the second attribute is in urn:p, which has no binding: the parser refuses the document
    assert!(shown(document(pool(&s, true), nodes)).is_err());
    let nodes = vec![
        start_ns(3, 8),
        start_ns(NONE, 2),
        start_element(NONE, 4, &[(8, 9, NONE, 0x10, 2), (NONE, 9, NONE, 0x10, 2)]),
        end_element(NONE, 4),
        end_ns(NONE, 2),
        end_ns(3, 8),
    ];
    let text = shown(document(pool(&s, true), nodes)).unwrap();
    assert!(text.contains("p:protectionLevel=\"signature\""), "{text}");
    assert!(text.contains("\n  protectionLevel=\"2\""), "{text}");
}

#[test]
fn a_flag_word_written_as_hex_is_named_like_one_written_as_decimal() {
    let mut s = strings();
    s.push(units("http://schemas.android.com/apk/res/android")); // 8
    s.push(units("protectionLevel")); // 9
    for (kind, expected) in [(0x10u8, "signature"), (0x11, "signature")] {
        let nodes = vec![
            start_ns(3, 8),
            start_element(NONE, 4, &[(8, 9, NONE, kind, 2)]),
            end_element(NONE, 4),
            end_ns(3, 8),
        ];
        let text = shown(document(pool(&s, true), nodes)).unwrap();
        assert!(
            text.contains(&format!("p:protectionLevel=\"{expected}\"")),
            "{text}"
        );
    }
    // typed as a string it is a string, whatever its data word says
    let mut with_text = s.clone();
    with_text.push(units("whatever"));
    let nodes = vec![
        start_ns(3, 8),
        start_element(NONE, 4, &[(8, 9, 10, 3, 10)]),
        end_element(NONE, 4),
        end_ns(3, 8),
    ];
    let text = shown(document(pool(&with_text, true), nodes)).unwrap();
    assert!(text.contains("p:protectionLevel=\"whatever\""), "{text}");
}
