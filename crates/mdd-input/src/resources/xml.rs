//! Android binary XML written back as text, the way the reference engine writes it: the XML
//! declaration, two spaces per level, an element with two or more attributes (namespace
//! declarations count) on one line each, an empty element closed with `/>`.
//!
//! The text is a view. The document it comes from (`ManifestDocument`) keeps the exact
//! pool strings, the typed words and their byte ranges, and this module never replaces
//! information with a guess: a value with an unpaired surrogate is refused, a control
//! character is written as a character reference (the reference drops it), a namespace
//! that cannot be named is refused.
use super::{
    framework,
    value::{ReferenceStyle, data_type, spell},
};
use crate::manifest::{
    ANDROID_NS, ExpandedName, ManifestAttribute, ManifestDocument, ManifestEvent, ManifestValue,
    NamespaceDeclaration, ResourceText, TypedData,
};
use mdd_types::{ErrorCode, MddError, MddResult};

fn refuse(message: &str) -> MddError {
    MddError::new(ErrorCode::UnsupportedCapability, "resources.xml", message)
}

/// An attribute's value as text: a pool string as it is, the framework enums and flags of
/// `framework` by name, any other compiled value as `value::spell` writes it.
pub fn attribute_text(attribute: &ManifestAttribute) -> MddResult<String> {
    let unrepresentable = |what: &str| {
        refuse("an attribute has a value that text cannot carry")
            .detail("attribute", attribute.name.local_name.clone())
            .detail("value_kind", what.to_owned())
    };
    let string = |value: &ResourceText| {
        value
            .text
            .clone()
            .ok_or_else(|| unrepresentable("string with an unpaired surrogate"))
    };
    match &attribute.value {
        ManifestValue::Text { value } => string(value),
        ManifestValue::Compiled {
            data_type: kind,
            raw_data,
            decoded,
        } => {
            if matches!(*kind, data_type::INT_DEC | data_type::INT_HEX)
                && attribute.name.namespace_uri.as_deref() == Some(ANDROID_NS)
                && let Some(name) = framework::named(&attribute.name.local_name, *raw_data)
            {
                return Ok(name);
            }
            match decoded {
                TypedData::String { value, .. } => string(value),
                _ => Ok(spell(*kind, *raw_data, ReferenceStyle::Compact)
                    .expect("only a string has no spelling")),
            }
        }
    }
}

fn escape(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' | '\0'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' => {
                out.push_str(&format!("&#x{:X};", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// `prefix:local` for a name in a namespace, resolved against the declarations in scope.
/// The innermost declaration of the URI whose prefix is not rebound later wins, which
/// also settles a document that binds one URI to two prefixes at once.
fn qualified(
    name: &ExpandedName,
    active: &[&NamespaceDeclaration],
    attribute: bool,
) -> MddResult<String> {
    let Some(uri) = name.namespace_uri.as_deref() else {
        return Ok(name.local_name.clone());
    };
    let visible = |position: usize| {
        let d = active[position];
        !active[position + 1..]
            .iter()
            .any(|later| later.prefix == d.prefix)
    };
    let found = (0..active.len())
        .rev()
        .filter(|position| active[*position].uri == uri && visible(*position))
        .map(|position| active[position].prefix.as_deref())
        .find(|prefix| prefix.is_some() || !attribute);
    match found {
        Some(Some(prefix)) => Ok(format!("{prefix}:{}", name.local_name)),
        Some(None) => Ok(name.local_name.clone()),
        None => Err(
            refuse("a name is in a namespace that has no prefix to write")
                .detail("namespace", uri.to_owned())
                .detail("name", name.local_name.clone()),
        ),
    }
}

/// The document as XML text.
pub fn render(document: &ManifestDocument) -> MddResult<String> {
    let nodes = document.nodes();
    let events = document.events();
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    let mut active: Vec<&NamespaceDeclaration> = Vec::new();
    let mut depth = 0usize;
    let mut position = 0usize;
    while position < events.len() {
        match &events[position] {
            ManifestEvent::NamespaceStart { declaration, .. } => active.push(declaration),
            ManifestEvent::NamespaceEnd { .. } => {
                active.pop();
            }
            ManifestEvent::StartElement { node } => {
                let element = &nodes[*node];
                let empty = matches!(
                    events.get(position + 1),
                    Some(ManifestEvent::EndElement { node: end, .. }) if end == node
                );
                let mut parts: Vec<String> = Vec::new();
                for declaration in &element.namespaces {
                    let mut part = match &declaration.prefix {
                        Some(prefix) => format!("xmlns:{prefix}=\""),
                        None => "xmlns=\"".to_owned(),
                    };
                    escape(&declaration.uri, &mut part);
                    part.push('"');
                    parts.push(part);
                }
                for attribute in &element.attributes {
                    let mut part = qualified(&attribute.name, &active, true)?;
                    part.push_str("=\"");
                    escape(&attribute_text(attribute)?, &mut part);
                    part.push('"');
                    parts.push(part);
                }
                let indent = "  ".repeat(depth);
                out.push_str(&indent);
                out.push('<');
                out.push_str(&qualified(&element.name, &active, false)?);
                match parts.len() {
                    0 => {}
                    1 => {
                        out.push(' ');
                        out.push_str(&parts[0]);
                    }
                    _ => {
                        for part in &parts {
                            out.push('\n');
                            out.push_str(&indent);
                            out.push_str("  ");
                            out.push_str(part);
                        }
                    }
                }
                if empty {
                    out.push_str("/>\n");
                    position += 1;
                } else {
                    out.push_str(">\n");
                    depth += 1;
                }
            }
            ManifestEvent::EndElement { node, .. } => {
                depth = depth.saturating_sub(1);
                out.push_str(&"  ".repeat(depth));
                out.push_str("</");
                out.push_str(&qualified(&nodes[*node].name, &active, false)?);
                out.push_str(">\n");
            }
            ManifestEvent::Text { value, .. } => {
                let text = value
                    .text
                    .as_deref()
                    .ok_or_else(|| refuse("a text node has an unpaired surrogate"))?;
                out.push_str(&"  ".repeat(depth));
                escape(text, &mut out);
                out.push('\n');
            }
        }
        position += 1;
    }
    Ok(out)
}
