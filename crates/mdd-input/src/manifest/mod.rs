//! Bounded Manifest facts over one immutable resource member. Resource strings
//! deliberately do not use the DEX MUTF-8 codec. No ARSC or runtime defaults.
use mdd_types::{ErrorCode, MddError, MddResult};
use serde::Serialize;
use std::sync::Arc;

mod axml;
mod text;

pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

#[derive(Clone, Copy, Debug)]
pub struct ManifestLimits {
    pub max_bytes: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_attributes: usize,
    pub max_strings: usize,
    pub max_string_units: usize,
    pub max_events: usize,
    pub max_work_units: usize,
}
impl Default for ManifestLimits {
    fn default() -> Self {
        Self {
            max_bytes: 16 * 1024 * 1024,
            max_nodes: 100_000,
            max_depth: 256,
            max_attributes: 1_000_000,
            max_strings: 200_000,
            max_string_units: 8 * 1024 * 1024,
            max_events: 400_000,
            max_work_units: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestFormat {
    AndroidBinaryXml,
    Utf8Xml,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Absolute member-byte range in `ManifestDocument::bytes()`, never a DEX,
/// UTF-16 character, rendered XML, or archive-compressed offset.
pub struct ByteRange {
    pub offset: usize,
    pub length: usize,
}

/// A resource UTF-16 string may contain an isolated surrogate. The code units
/// remain exact; `text = None` is not an empty string or replacement decoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceText {
    pub utf16: Vec<u16>,
    pub text: Option<String>,
}
impl ResourceText {
    fn from_str(value: &str) -> Self {
        Self {
            utf16: value.encode_utf16().collect(),
            text: Some(value.to_owned()),
        }
    }
    fn from_units(utf16: Vec<u16>) -> Self {
        let text = String::from_utf16(&utf16).ok();
        Self { utf16, text }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PoolString {
    pub value: ResourceText,
    pub source_range: ByteRange,
    pub encoding: String,
    pub styles: Vec<StyleSpan>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StyleSpan {
    pub name_index: u32,
    pub first_utf16: u32,
    pub last_utf16: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExpandedName {
    pub namespace_uri: Option<String>,
    pub local_name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefixProvenance {
    SourceQName,
    NoNamespace,
    UniqueNamespaceBinding,
    AmbiguousNamespaceBindings,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypedData {
    Null {
        empty: bool,
    },
    UnresolvedReference {
        resource_id: u32,
        attribute: bool,
        dynamic: bool,
    },
    String {
        value: ResourceText,
        string_index: u32,
    },
    FloatBits,
    Dimension {
        unit: u8,
        radix: u8,
    },
    Fraction {
        unit: u8,
        radix: u8,
    },
    IntDecimal {
        signed: i32,
    },
    IntHex,
    Boolean {
        value: bool,
    },
    Color,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "representation", rename_all = "snake_case")]
pub enum ManifestValue {
    Text {
        value: ResourceText,
    },
    Compiled {
        data_type: u8,
        raw_data: u32,
        decoded: TypedData,
    },
}
impl ManifestValue {
    pub fn string(&self) -> Option<&ResourceText> {
        match self {
            Self::Text { value }
            | Self::Compiled {
                decoded: TypedData::String { value, .. },
                ..
            } => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManifestAttribute {
    pub name: ExpandedName,
    pub prefix: Option<String>,
    pub prefix_provenance: PrefixProvenance,
    /// Text XML retains the lexical value (entities included); AXML retains
    /// the optional rawValue pool string. Absence is distinct from empty.
    pub raw_value: Option<ResourceText>,
    pub value: ManifestValue,
    pub resource_id: Option<u32>,
    pub source_range: ByteRange,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NamespaceDeclaration {
    pub prefix: Option<String>,
    pub uri: String,
    pub source_range: ByteRange,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManifestNode {
    pub name: ExpandedName,
    pub prefix: Option<String>,
    pub prefix_provenance: PrefixProvenance,
    pub parent: Option<usize>,
    pub attributes: Vec<ManifestAttribute>,
    pub namespaces: Vec<NamespaceDeclaration>,
    /// Start-tag / START_ELEMENT chunk only, not the entire subtree.
    pub source_range: ByteRange,
    pub line_number: Option<u32>,
}
impl ManifestNode {
    pub fn attribute(
        &self,
        namespace: Option<&str>,
        local_name: &str,
    ) -> Option<&ManifestAttribute> {
        self.attributes.iter().find(|a| {
            a.name.namespace_uri.as_deref() == namespace && a.name.local_name == local_name
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ManifestEvent {
    StartElement {
        node: usize,
    },
    EndElement {
        node: usize,
        source_range: ByteRange,
    },
    NamespaceStart {
        depth: usize,
        declaration: NamespaceDeclaration,
    },
    NamespaceEnd {
        depth: usize,
        declaration: NamespaceDeclaration,
    },
    Text {
        parent: Option<usize>,
        value: ResourceText,
        typed_value: Option<ManifestValue>,
        source_range: ByteRange,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManifestPermission {
    pub node: usize,
    pub kind: String,
    pub name: Option<ManifestValue>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManifestComponent {
    pub node: usize,
    pub kind: String,
    pub name: Option<ManifestValue>,
    pub exported: Option<ManifestValue>,
    pub permission: Option<ManifestValue>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManifestSummary {
    pub package: Option<ManifestValue>,
    pub version_code: Option<ManifestValue>,
    pub version_code_major: Option<ManifestValue>,
    pub version_name: Option<ManifestValue>,
    pub min_sdk_version: Option<ManifestValue>,
    pub target_sdk_version: Option<ManifestValue>,
    pub max_sdk_version: Option<ManifestValue>,
    pub uses_sdk_nodes: Vec<usize>,
    pub sdk_attribute_projection: String,
    pub permissions: Vec<ManifestPermission>,
    pub declared_permissions: Vec<ManifestPermission>,
    pub application_nodes: Vec<usize>,
    pub components: Vec<ManifestComponent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ManifestDocument {
    format: ManifestFormat,
    #[serde(skip)]
    bytes: Arc<[u8]>,
    strings: Vec<PoolString>,
    resource_map: Vec<u32>,
    nodes: Vec<ManifestNode>,
    events: Vec<ManifestEvent>,
    summary: ManifestSummary,
}
impl ManifestDocument {
    pub fn format(&self) -> ManifestFormat {
        self.format
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn lease(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }
    pub fn strings(&self) -> &[PoolString] {
        &self.strings
    }
    pub fn resource_map(&self) -> &[u32] {
        &self.resource_map
    }
    pub fn nodes(&self) -> &[ManifestNode] {
        &self.nodes
    }
    pub fn events(&self) -> &[ManifestEvent] {
        &self.events
    }
    pub fn summary(&self) -> &ManifestSummary {
        &self.summary
    }
}

pub fn parse_manifest(bytes: Arc<[u8]>, limits: ManifestLimits) -> MddResult<ManifestDocument> {
    parse_document(bytes, limits, true)
}

/// Any Android binary XML (a layout, a drawable), read by the same strict parser as the
/// Manifest. The only difference is that its root element is not required to be `<manifest>`;
/// the summary it carries is meaningful for a Manifest only.
pub fn parse_xml_resource(bytes: Arc<[u8]>, limits: ManifestLimits) -> MddResult<ManifestDocument> {
    if !bytes.starts_with(&[3, 0, 8, 0]) {
        return Err(invalid("not Android binary XML"));
    }
    parse_document(bytes, limits, false)
}

/// One `ResStringPool` chunk (the pools of `resources.arsc` have the layout of the binary XML's),
/// read by the same strict reader. `chunk` is the whole chunk from its 8-byte header;
/// `base_offset` is where it starts in the member, for the strings' source ranges.
pub fn parse_string_pool(
    chunk: &[u8],
    base_offset: usize,
    limits: ManifestLimits,
) -> MddResult<Vec<PoolString>> {
    let field = |at: usize, width: usize| {
        chunk
            .get(at..at + width)
            .ok_or_else(|| invalid("string pool chunk is shorter than its header"))
    };
    let kind = u16::from_le_bytes(field(0, 2)?.try_into().expect("two bytes"));
    let header = usize::from(u16::from_le_bytes(
        field(2, 2)?.try_into().expect("two bytes"),
    ));
    let size = u32::from_le_bytes(field(4, 4)?.try_into().expect("four bytes")) as usize;
    if kind != 1 || size != chunk.len() {
        return Err(invalid("not a string pool chunk, or its size is wrong"));
    }
    let mut build = Builder::new(limits);
    axml::pool(chunk, base_offset, header, &mut build)?;
    Ok(build.strings)
}

fn parse_document(
    bytes: Arc<[u8]>,
    limits: ManifestLimits,
    manifest_root: bool,
) -> MddResult<ManifestDocument> {
    if bytes.len() > limits.max_bytes {
        return Err(quota("manifest bytes exceed budget"));
    }
    if bytes.is_empty() {
        return Err(invalid("empty Manifest"));
    }
    let format = if bytes.starts_with(&[3, 0, 8, 0]) {
        ManifestFormat::AndroidBinaryXml
    } else {
        ManifestFormat::Utf8Xml
    };
    let mut build = Builder::new(limits);
    match format {
        ManifestFormat::AndroidBinaryXml => axml::parse(&bytes, &mut build)?,
        ManifestFormat::Utf8Xml => text::parse(&bytes, &mut build)?,
    }
    let root = build
        .nodes
        .first()
        .ok_or_else(|| invalid("Manifest has no root element"))?;
    if manifest_root
        && (root.parent.is_some()
            || root.name.namespace_uri.is_some()
            || root.name.local_name != "manifest")
    {
        return Err(invalid(
            "Manifest root must be the unqualified manifest element",
        ));
    }
    let summary = summarize(&build.nodes);
    Ok(ManifestDocument {
        format,
        bytes,
        strings: build.strings,
        resource_map: build.resource_map,
        nodes: build.nodes,
        events: build.events,
        summary,
    })
}

fn value(node: &ManifestNode, namespace: Option<&str>, name: &str) -> Option<ManifestValue> {
    node.attribute(namespace, name).map(|a| a.value.clone())
}
fn summarize(nodes: &[ManifestNode]) -> ManifestSummary {
    let root = &nodes[0];
    let mut result = ManifestSummary {
        package: value(root, None, "package"),
        version_code: value(root, Some(ANDROID_NS), "versionCode"),
        version_code_major: value(root, Some(ANDROID_NS), "versionCodeMajor"),
        version_name: value(root, Some(ANDROID_NS), "versionName"),
        min_sdk_version: None,
        target_sdk_version: None,
        max_sdk_version: None,
        uses_sdk_nodes: Vec::new(),
        sdk_attribute_projection: "absent".to_owned(),
        permissions: Vec::new(),
        declared_permissions: Vec::new(),
        application_nodes: Vec::new(),
        components: Vec::new(),
    };
    for (id, node) in nodes.iter().enumerate().skip(1) {
        if node.name.namespace_uri.is_some() {
            continue;
        }
        if node.parent == Some(0) {
            match node.name.local_name.as_str() {
                "uses-sdk" => {
                    result.uses_sdk_nodes.push(id);
                    if result.uses_sdk_nodes.len() == 1 {
                        result.sdk_attribute_projection = "single_declaration".to_owned();
                        result.min_sdk_version = value(node, Some(ANDROID_NS), "minSdkVersion");
                        result.target_sdk_version =
                            value(node, Some(ANDROID_NS), "targetSdkVersion");
                        result.max_sdk_version = value(node, Some(ANDROID_NS), "maxSdkVersion");
                    } else {
                        result.sdk_attribute_projection =
                            "ambiguous_multiple_declarations".to_owned();
                        result.min_sdk_version = None;
                        result.target_sdk_version = None;
                        result.max_sdk_version = None;
                    }
                }
                "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                    result.permissions.push(ManifestPermission {
                        node: id,
                        kind: node.name.local_name.clone(),
                        name: value(node, Some(ANDROID_NS), "name"),
                    })
                }
                "permission" | "permission-group" | "permission-tree" => {
                    result.declared_permissions.push(ManifestPermission {
                        node: id,
                        kind: node.name.local_name.clone(),
                        name: value(node, Some(ANDROID_NS), "name"),
                    })
                }
                "application" => result.application_nodes.push(id),
                _ => (),
            }
        }
        if node.parent.is_some_and(|p| {
            nodes[p].parent == Some(0)
                && nodes[p].name.namespace_uri.is_none()
                && nodes[p].name.local_name == "application"
        }) && matches!(
            node.name.local_name.as_str(),
            "activity" | "activity-alias" | "service" | "receiver" | "provider"
        ) {
            result.components.push(ManifestComponent {
                node: id,
                kind: node.name.local_name.clone(),
                name: value(node, Some(ANDROID_NS), "name"),
                exported: value(node, Some(ANDROID_NS), "exported"),
                permission: value(node, Some(ANDROID_NS), "permission"),
            });
        }
    }
    result
}

pub(super) fn invalid(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidInput, "manifest", message)
}
pub(super) fn quota(message: &str) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "manifest", message)
}
pub(super) struct Builder {
    limits: ManifestLimits,
    strings: Vec<PoolString>,
    resource_map: Vec<u32>,
    nodes: Vec<ManifestNode>,
    events: Vec<ManifestEvent>,
    units: usize,
    attributes: usize,
    work: usize,
}
impl Builder {
    fn new(limits: ManifestLimits) -> Self {
        Self {
            limits,
            strings: Vec::new(),
            resource_map: Vec::new(),
            nodes: Vec::new(),
            events: Vec::new(),
            units: 0,
            attributes: 0,
            work: 0,
        }
    }
    fn units(&mut self, count: usize) -> MddResult<()> {
        self.units = self
            .units
            .checked_add(count)
            .ok_or_else(|| quota("string unit sum overflow"))?;
        if self.units > self.limits.max_string_units {
            return Err(quota("decoded string units exceed budget"));
        }
        Ok(())
    }
    fn work(&mut self, count: usize) -> MddResult<()> {
        self.work = self
            .work
            .checked_add(count)
            .ok_or_else(|| quota("Manifest work counter overflow"))?;
        if self.work > self.limits.max_work_units {
            return Err(quota("Manifest namespace work budget exceeded"));
        }
        Ok(())
    }
    fn attributes(&mut self, count: usize) -> MddResult<()> {
        self.attributes = self
            .attributes
            .checked_add(count)
            .ok_or_else(|| quota("attribute sum overflow"))?;
        if self.attributes > self.limits.max_attributes {
            return Err(quota("attributes exceed budget"));
        }
        Ok(())
    }
    fn push(&mut self, node: ManifestNode, depth: usize) -> MddResult<usize> {
        if depth > self.limits.max_depth || self.nodes.len() >= self.limits.max_nodes {
            return Err(quota("Manifest node/depth budget exceeded"));
        }
        if node.parent.is_none() && !self.nodes.is_empty() {
            return Err(invalid("multiple Manifest roots"));
        }
        let id = self.nodes.len();
        self.nodes.push(node);
        self.event(ManifestEvent::StartElement { node: id })?;
        Ok(id)
    }
    fn event(&mut self, event: ManifestEvent) -> MddResult<()> {
        if self.events.len() >= self.limits.max_events {
            return Err(quota("Manifest event budget exceeded"));
        }
        self.events.push(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
