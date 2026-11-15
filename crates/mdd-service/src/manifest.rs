//! The AndroidManifest.xml of an opened archive, presented the way `get_manifest` answers.
//!
//! The parse is `mdd_input::manifest`'s; this module only chooses what to show and how a
//! value is spelled. The spelling follows the reference engine's recorded summary of a
//! public APK (artifacts/mdd-025/manifest/a0): an attribute is `android:name` for the
//! android namespace and `name` without one, integers are decimal text, booleans are
//! `true`/`false`, a reference that was not resolved is `@` and eight lower-case hex
//! digits (`?` for an attribute reference), `installLocation` and `protectionLevel` print
//! their framework enum names. A value of a type the recording does not show is refused,
//! naming the attribute, rather than written some other way.
use crate::Dataset;
use mdd_facts::raw_fingerprints::ResourceByteEvidence;
use mdd_input::manifest::{
    ManifestAttribute, ManifestDocument, ManifestLimits, ManifestNode, ManifestValue, TypedData,
    parse_manifest,
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::Arc};

const ANDROID: &str = mdd_input::manifest::ANDROID_NS;
const PERMISSION_ELEMENTS: [&str; 4] = [
    "permission",
    "uses-permission",
    "uses-permission-sdk-23",
    "uses-permission-sdk-m",
];

fn refuse(code: ErrorCode, message: &str) -> MddError {
    MddError::new(code, "service.manifest", message)
}

/// Why no manifest could be shown.
#[derive(Debug)]
pub enum ManifestFailure {
    /// The input index names no input, or an input that is not an archive.
    NoSuchInput(String),
    /// The archive has no AndroidManifest.xml.
    Missing(String),
    /// The archive has several, and none is chosen for the reader.
    Several(String),
    Error(MddError),
}

impl From<MddError> for ManifestFailure {
    fn from(error: MddError) -> Self {
        Self::Error(error)
    }
}

impl Dataset {
    /// The parsed manifest of the archive input at `input_index`, parsed once.
    pub fn manifest(&self, input_index: usize) -> Result<Arc<ManifestDocument>, ManifestFailure> {
        let archives = self.archive_inputs();
        if !archives.contains(&input_index) {
            return Err(ManifestFailure::NoSuchInput(format!(
                "input_index {input_index} is not an archive of this dataset (archive inputs: {archives:?})"
            )));
        }
        let mut cache = self.manifests.lock().map_err(|_| {
            ManifestFailure::Error(refuse(
                ErrorCode::InternalFault,
                "the manifest cache is poisoned",
            ))
        })?;
        if let Some(found) = cache.get(&input_index) {
            return Ok(Arc::clone(found));
        }
        let inventory = &self.inventories[input_index];
        let members: Vec<_> = inventory
            .manifest()
            .members
            .iter()
            .filter(|member| member.raw_name == b"AndroidManifest.xml")
            .collect();
        let member = match members.as_slice() {
            [one] => *one,
            [] => {
                return Err(ManifestFailure::Missing(
                    "the archive has no AndroidManifest.xml".to_owned(),
                ));
            }
            many => {
                return Err(ManifestFailure::Several(format!(
                    "the archive has {} AndroidManifest.xml entries; none is chosen for the reader",
                    many.len()
                )));
            }
        };
        let evidence = ResourceByteEvidence::build(&self.snapshot, inventory, &member.member_id)?;
        let document = Arc::new(parse_manifest(evidence.lease(), ManifestLimits::default())?);
        cache.insert(input_index, Arc::clone(&document));
        Ok(document)
    }
}

/// What the summary shows of one manifest.
#[derive(Clone, Debug)]
pub struct Summary {
    pub manifest: Map<String, Value>,
    pub application: Option<Map<String, Value>>,
    pub uses_sdk: Option<Map<String, Value>>,
    pub component_counts: Map<String, Value>,
    pub target_sdk: Option<i64>,
    pub permissions: Vec<Value>,
}

fn enum_name(local: &str, raw: u32) -> Option<&'static str> {
    match (local, raw) {
        ("installLocation", 0) => Some("auto"),
        ("installLocation", 1) => Some("internalOnly"),
        ("installLocation", 2) => Some("preferExternal"),
        ("protectionLevel", 0) => Some("normal"),
        ("protectionLevel", 1) => Some("dangerous"),
        ("protectionLevel", 2) => Some("signature"),
        ("protectionLevel", 3) => Some("signatureOrSystem"),
        _ => None,
    }
}

fn present(attribute: &ManifestAttribute) -> MddResult<String> {
    let local = attribute.name.local_name.as_str();
    let unrepresentable = |what: &str| {
        refuse(
            ErrorCode::UnsupportedCapability,
            "an attribute has a value the summary does not present yet",
        )
        .detail("attribute", local.to_owned())
        .detail("value_kind", what.to_owned())
    };
    match &attribute.value {
        ManifestValue::Text { value } => value
            .text
            .clone()
            .ok_or_else(|| unrepresentable("text with an unpaired surrogate")),
        ManifestValue::Compiled {
            raw_data, decoded, ..
        } => {
            if let Some(name) = enum_name(local, *raw_data) {
                return Ok(name.to_owned());
            }
            match decoded {
                TypedData::String { value, .. } => value
                    .text
                    .clone()
                    .ok_or_else(|| unrepresentable("string with an unpaired surrogate")),
                TypedData::IntDecimal { signed } => Ok(signed.to_string()),
                TypedData::IntHex => Ok(format!("0x{raw_data:08x}")),
                TypedData::Boolean { value } => {
                    Ok(if *value { "true" } else { "false" }.to_owned())
                }
                TypedData::UnresolvedReference {
                    resource_id,
                    attribute,
                    ..
                } => Ok(format!(
                    "{}{resource_id:08x}",
                    if *attribute { '?' } else { '@' }
                )),
                TypedData::Null { .. } => Err(unrepresentable("null")),
                TypedData::FloatBits => Err(unrepresentable("float")),
                TypedData::Dimension { .. } => Err(unrepresentable("dimension")),
                TypedData::Fraction { .. } => Err(unrepresentable("fraction")),
                TypedData::Color => Err(unrepresentable("color")),
                TypedData::Unknown => Err(unrepresentable("unknown type")),
            }
        }
    }
}

fn attributes(node: &ManifestNode) -> MddResult<Map<String, Value>> {
    let mut out = Map::new();
    for attribute in &node.attributes {
        let key = match attribute.name.namespace_uri.as_deref() {
            None => attribute.name.local_name.clone(),
            Some(ANDROID) => format!("android:{}", attribute.name.local_name),
            Some(other) => {
                return Err(refuse(
                    ErrorCode::UnsupportedCapability,
                    "an attribute is in a namespace the summary does not name yet",
                )
                .detail("namespace", other.to_owned())
                .detail("attribute", attribute.name.local_name.clone()));
            }
        };
        if out
            .insert(key.clone(), json!(present(attribute)?))
            .is_some()
        {
            return Err(refuse(
                ErrorCode::InvalidInput,
                "an element has the same attribute twice",
            )
            .detail("attribute", key));
        }
    }
    Ok(out)
}

/// The summary of one manifest, whole. Paging the permissions is the caller's.
pub fn summarize(document: &ManifestDocument) -> MddResult<Summary> {
    let nodes = document.nodes();
    let root = nodes
        .first()
        .filter(|node| node.name.namespace_uri.is_none() && node.name.local_name == "manifest")
        .ok_or_else(|| {
            refuse(
                ErrorCode::InvalidInput,
                "the document's root element is not <manifest>",
            )
        })?;
    let summary = document.summary();
    let first_of = |indexes: &[usize]| indexes.first().map(|i| attributes(&nodes[*i])).transpose();
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for component in &summary.components {
        *counts.entry(component.kind.as_str()).or_default() += 1;
    }
    let target_sdk = match summary.target_sdk_version.as_ref() {
        Some(ManifestValue::Compiled {
            decoded: TypedData::IntDecimal { signed },
            ..
        }) => Some(i64::from(*signed)),
        _ => None,
    };
    let mut permissions = Vec::new();
    for node in nodes {
        if node.parent == Some(0)
            && node.name.namespace_uri.is_none()
            && PERMISSION_ELEMENTS.contains(&node.name.local_name.as_str())
        {
            permissions.push(json!({
                "attributes": attributes(node)?,
                "kind": node.name.local_name,
            }));
        }
    }
    Ok(Summary {
        manifest: attributes(root)?,
        application: first_of(&summary.application_nodes)?,
        uses_sdk: first_of(&summary.uses_sdk_nodes)?,
        component_counts: counts
            .into_iter()
            .map(|(k, v)| (k.to_owned(), json!(v)))
            .collect(),
        target_sdk,
        permissions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdd_input::manifest::{ByteRange, ExpandedName, PrefixProvenance, ResourceText};

    fn text(value: &str) -> ResourceText {
        ResourceText {
            utf16: value.encode_utf16().collect(),
            text: Some(value.to_owned()),
        }
    }

    fn attribute(namespace: Option<&str>, name: &str, value: ManifestValue) -> ManifestAttribute {
        ManifestAttribute {
            name: ExpandedName {
                namespace_uri: namespace.map(str::to_owned),
                local_name: name.to_owned(),
            },
            prefix: None,
            prefix_provenance: PrefixProvenance::NoNamespace,
            raw_value: None,
            value,
            resource_id: None,
            source_range: ByteRange {
                offset: 0,
                length: 0,
            },
        }
    }

    fn compiled(raw_data: u32, decoded: TypedData) -> ManifestValue {
        ManifestValue::Compiled {
            data_type: 0,
            raw_data,
            decoded,
        }
    }

    fn shown(name: &str, value: ManifestValue) -> MddResult<String> {
        present(&attribute(Some(ANDROID), name, value))
    }

    #[test]
    fn framework_enums_print_their_names_and_only_for_their_attributes() {
        let int = |signed: i32| compiled(signed as u32, TypedData::IntDecimal { signed });
        for (raw, name) in [(0, "auto"), (1, "internalOnly"), (2, "preferExternal")] {
            assert_eq!(shown("installLocation", int(raw)).unwrap(), name);
        }
        for (raw, name) in [
            (0, "normal"),
            (1, "dangerous"),
            (2, "signature"),
            (3, "signatureOrSystem"),
        ] {
            assert_eq!(shown("protectionLevel", int(raw)).unwrap(), name);
        }
        // outside the table, or under another name, the number is a number
        assert_eq!(shown("installLocation", int(3)).unwrap(), "3");
        assert_eq!(shown("versionCode", int(2)).unwrap(), "2");
    }

    #[test]
    fn values_are_spelled_as_the_recording_spells_them() {
        let reference = |resource_id, attribute| {
            compiled(
                resource_id,
                TypedData::UnresolvedReference {
                    resource_id,
                    attribute,
                    dynamic: false,
                },
            )
        };
        assert_eq!(
            shown("icon", reference(0x7f10_0002, false)).unwrap(),
            "@7f100002"
        );
        assert_eq!(
            shown("theme", reference(0x0101_0000, true)).unwrap(),
            "?01010000"
        );
        assert_eq!(
            shown(
                "n",
                compiled(0xffff_ffff, TypedData::IntDecimal { signed: -1 })
            )
            .unwrap(),
            "-1"
        );
        assert_eq!(
            shown("n", compiled(0xa, TypedData::IntHex)).unwrap(),
            "0x0000000a"
        );
        assert_eq!(
            shown(
                "flag",
                compiled(0xffff_ffff, TypedData::Boolean { value: true })
            )
            .unwrap(),
            "true"
        );
        assert_eq!(
            shown("flag", compiled(0, TypedData::Boolean { value: false })).unwrap(),
            "false"
        );
        let string = compiled(
            0,
            TypedData::String {
                value: text("example.test"),
                string_index: 0,
            },
        );
        assert_eq!(shown("package", string).unwrap(), "example.test");
        assert_eq!(
            shown(
                "label",
                ManifestValue::Text {
                    value: text("plain")
                }
            )
            .unwrap(),
            "plain"
        );
    }

    #[test]
    fn a_value_the_recording_does_not_show_is_refused_naming_the_attribute_and_kind() {
        for (decoded, kind) in [
            (TypedData::FloatBits, "float"),
            (TypedData::Dimension { unit: 0, radix: 0 }, "dimension"),
            (TypedData::Fraction { unit: 0, radix: 0 }, "fraction"),
            (TypedData::Color, "color"),
            (TypedData::Null { empty: true }, "null"),
            (TypedData::Unknown, "unknown type"),
        ] {
            let error = shown("ratio", compiled(5, decoded)).unwrap_err();
            assert_eq!(error.code, ErrorCode::UnsupportedCapability);
            assert_eq!(error.details["attribute"], "ratio");
            assert_eq!(error.details["value_kind"], kind);
        }
        let lone = ResourceText {
            utf16: vec![0xd800],
            text: None,
        };
        let error = shown(
            "label",
            compiled(
                0,
                TypedData::String {
                    value: lone,
                    string_index: 0,
                },
            ),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedCapability);
    }

    fn node(attributes: Vec<ManifestAttribute>) -> ManifestNode {
        ManifestNode {
            name: ExpandedName {
                namespace_uri: None,
                local_name: "application".to_owned(),
            },
            prefix: None,
            prefix_provenance: PrefixProvenance::NoNamespace,
            parent: Some(0),
            attributes,
            namespaces: Vec::new(),
            source_range: ByteRange {
                offset: 0,
                length: 0,
            },
            line_number: None,
        }
    }

    #[test]
    fn attribute_keys_carry_android_only_for_the_android_namespace() {
        let string = |s: &str| ManifestValue::Text { value: text(s) };
        let map = attributes(&node(vec![
            attribute(Some(ANDROID), "name", string("a")),
            attribute(None, "package", string("b")),
        ]))
        .unwrap();
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        assert_eq!(keys, ["android:name", "package"]);
        assert_eq!(map["android:name"], "a");
    }

    #[test]
    fn another_namespace_and_a_repeated_attribute_are_refused() {
        let string = |s: &str| ManifestValue::Text { value: text(s) };
        let other =
            attributes(&node(vec![attribute(Some("urn:other"), "x", string("1"))])).unwrap_err();
        assert_eq!(other.code, ErrorCode::UnsupportedCapability);
        assert_eq!(other.details["namespace"], "urn:other");
        let twice = attributes(&node(vec![
            attribute(None, "x", string("1")),
            attribute(None, "x", string("2")),
        ]))
        .unwrap_err();
        assert_eq!(twice.code, ErrorCode::InvalidInput);
        assert_eq!(twice.details["attribute"], "x");
    }
}
