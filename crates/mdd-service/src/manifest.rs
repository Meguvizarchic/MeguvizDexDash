//! The AndroidManifest.xml of an opened archive, presented the way `get_manifest` answers.
//!
//! The parse is `mdd_input::manifest`'s; this module only chooses what to show. How a value is
//! spelled is `mdd_input::resources::xml::attribute_text`'s, the same function the XML view
//! uses, so the summary and the XML never spell one value two ways: integers are decimal text,
//! booleans `true`/`false`, a reference `@` and eight lower-case hex digits (`?` for an attribute
//! reference), floats, dimensions, fractions and colours as the reference engine writes them,
//! `installLocation`, `launchMode` and `protectionLevel` by their framework names. A value that
//! text cannot carry (an unpaired surrogate) is refused, naming the attribute.
use crate::Dataset;
use mdd_facts::raw_fingerprints::ResourceByteEvidence;
use mdd_input::{
    manifest::{
        ManifestAttribute, ManifestDocument, ManifestLimits, ManifestNode, ManifestValue,
        TypedData, parse_manifest,
    },
    resources::xml::attribute_text,
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

impl Dataset {
    /// The Manifest as XML text, rendered once. A Manifest the XML view cannot carry (a value
    /// with an unpaired surrogate) is refused with the attribute named.
    pub fn manifest_xml(&self, input_index: usize) -> Result<Arc<str>, ManifestFailure> {
        let document = self.manifest(input_index)?;
        let mut cache = self.resources.lock().map_err(|_| {
            ManifestFailure::Error(refuse(
                ErrorCode::InternalFault,
                "the resource cache is poisoned",
            ))
        })?;
        if let Some(text) = cache.manifest_xml.get(&input_index) {
            return Ok(Arc::clone(text));
        }
        let text: Arc<str> = Arc::from(mdd_input::resources::xml::render(&document)?);
        cache.manifest_xml.insert(input_index, Arc::clone(&text));
        Ok(text)
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

/// The key an attribute has in a map: `android:name` for the android namespace whatever
/// prefix the document gave it, `name` without a namespace, `prefix:name` in another namespace
/// with one prefix to name it, `{uri}name` when no single prefix does.
fn attribute_key(attribute: &ManifestAttribute) -> String {
    match attribute.name.namespace_uri.as_deref() {
        None => attribute.name.local_name.clone(),
        Some(ANDROID) => format!("android:{}", attribute.name.local_name),
        Some(uri) => match attribute.prefix.as_deref() {
            Some(prefix) if !prefix.is_empty() => {
                format!("{prefix}:{}", attribute.name.local_name)
            }
            _ => format!("{{{uri}}}{}", attribute.name.local_name),
        },
    }
}

fn attributes(node: &ManifestNode) -> MddResult<Map<String, Value>> {
    let mut out = Map::new();
    for attribute in &node.attributes {
        let key = attribute_key(attribute);
        if out
            .insert(key.clone(), json!(attribute_text(attribute)?))
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

// ---- components ---------------------------------------------------------------

/// Why a component is, or is not, exported: the manifest says so, or the platform's default
/// decides (the reasons the reference engine names), or the manifest's value cannot be told.
const REASON_EXPLICIT: &str = "explicit";
const REASON_FILTER_DEFAULT: &str = "intent_filter_default";
const REASON_PROVIDER_DEFAULT: &str = "provider_target_sdk_default";
const REASON_REQUIRED: &str = "explicit_exported_required_or_target_sdk_unknown";
const REASON_NOT_A_BOOLEAN: &str = "exported_value_not_resolvable_here";

/// What the manifest alone says about the components. It is not a claim of runtime access.
pub const EXPORTED_ASSUMPTION: &str =
    "Android API 17+; manifest configuration only, excluding runtime state and permission checks";

/// One component, with the two fields the tool filters by kept beside the row.
#[derive(Clone, Debug)]
pub struct Component {
    pub kind: String,
    pub exported: Option<bool>,
    pub row: Value,
}

#[derive(Clone, Debug)]
pub struct Components {
    pub target_sdk: Option<i64>,
    pub components: Vec<Component>,
}

/// A boolean attribute: its value when the manifest states one, `None` when it points at a
/// resource this document cannot resolve.
fn boolean(attribute: &ManifestAttribute) -> Option<bool> {
    match &attribute.value {
        ManifestValue::Compiled {
            raw_data, decoded, ..
        } => match decoded {
            TypedData::Boolean { value } => Some(*value),
            TypedData::IntDecimal { .. } | TypedData::IntHex => Some(*raw_data != 0),
            _ => None,
        },
        ManifestValue::Text { value } => match value.text.as_deref() {
            Some("true") => Some(true),
            Some("false") => Some(false),
            _ => None,
        },
    }
}

/// A class name as the manifest writes it, made absolute against the package: `.Main` and `Main`
/// are in the package, a name with a dot inside is already absolute.
fn absolute(package: Option<&str>, name: &str) -> String {
    match package {
        Some(package) if name.starts_with('.') => format!("{package}{name}"),
        Some(package) if !name.contains('.') => format!("{package}.{name}"),
        _ => name.to_owned(),
    }
}

fn android_text(node: &ManifestNode, name: &str) -> MddResult<Option<String>> {
    node.attribute(Some(ANDROID), name)
        .map(attribute_text)
        .transpose()
}

/// The exported state of a component and why: the manifest's own word, else the default the
/// platform gives it at this target SDK.
fn exported_state(
    kind: &str,
    node: &ManifestNode,
    has_filter: bool,
    target_sdk: Option<i64>,
) -> (Option<bool>, &'static str) {
    if let Some(attribute) = node.attribute(Some(ANDROID), "exported") {
        return match boolean(attribute) {
            Some(value) => (Some(value), REASON_EXPLICIT),
            None => (None, REASON_NOT_A_BOOLEAN),
        };
    }
    if kind == "provider" {
        return match target_sdk {
            Some(sdk) => (Some(sdk < 17), REASON_PROVIDER_DEFAULT),
            None => (None, REASON_REQUIRED),
        };
    }
    if !has_filter {
        return (Some(false), REASON_FILTER_DEFAULT);
    }
    match target_sdk {
        Some(sdk) if sdk < 31 => (Some(true), REASON_FILTER_DEFAULT),
        _ => (None, REASON_REQUIRED),
    }
}

/// Every component of the application, in document order, with its intent filters, metadata and
/// the exported state the manifest gives it.
pub fn components(document: &ManifestDocument) -> MddResult<Components> {
    let nodes = document.nodes();
    let summary = document.summary();
    let target_sdk = match summary.target_sdk_version.as_ref() {
        Some(ManifestValue::Compiled {
            decoded: TypedData::IntDecimal { signed },
            ..
        }) => Some(i64::from(*signed)),
        _ => None,
    };
    let package = nodes
        .first()
        .and_then(|root| root.attribute(None, "package"))
        .map(attribute_text)
        .transpose()?;
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        if let Some(parent) = node.parent {
            children[parent].push(index);
        }
    }
    let direct = |parent: usize, name: &'static str| {
        children[parent]
            .iter()
            .map(|i| (*i, &nodes[*i]))
            .filter(move |(_, n)| n.name.namespace_uri.is_none() && n.name.local_name == name)
    };
    let mut out = Vec::new();
    for component in &summary.components {
        let node = &nodes[component.node];
        let name = android_text(node, "name")?.map(|n| absolute(package.as_deref(), &n));
        let mut filters = Vec::new();
        let mut launcher = false;
        for (filter_index, filter) in direct(component.node, "intent-filter") {
            let named = |element: &'static str| -> MddResult<Vec<String>> {
                direct(filter_index, element)
                    .filter_map(|(_, n)| android_text(n, "name").transpose())
                    .collect()
            };
            let actions = named("action")?;
            let categories = named("category")?;
            launcher |= actions.iter().any(|a| a == "android.intent.action.MAIN")
                && categories
                    .iter()
                    .any(|c| c == "android.intent.category.LAUNCHER");
            let data = direct(filter_index, "data")
                .map(|(_, n)| attributes(n))
                .collect::<MddResult<Vec<_>>>()?;
            filters.push(json!({
                "actions": actions,
                "attributes": attributes(filter)?,
                "categories": categories,
                "data": data,
            }));
        }
        let metadata = direct(component.node, "meta-data")
            .map(|(_, n)| attributes(n))
            .collect::<MddResult<Vec<_>>>()?;
        let (exported, reason) =
            exported_state(&component.kind, node, !filters.is_empty(), target_sdk);
        let enabled = node
            .attribute(Some(ANDROID), "enabled")
            .map_or(Some(true), boolean);
        let target_activity = if component.kind == "activity-alias" {
            android_text(node, "targetActivity")?.map(|n| absolute(package.as_deref(), &n))
        } else {
            None
        };
        out.push(Component {
            kind: component.kind.clone(),
            exported,
            row: json!({
                "attributes": attributes(node)?,
                "descriptor": name.as_ref().map(|n| format!("L{};", n.replace('.', "/"))),
                "enabled": enabled,
                "exported": exported,
                "exported_reason": reason,
                "intent_filters": filters,
                "kind": component.kind,
                "launcher_intent": launcher,
                "metadata": metadata,
                "name": name,
                "target_activity": target_activity,
            }),
        });
    }
    Ok(Components {
        target_sdk,
        components: out,
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

    fn attribute(
        namespace: Option<&str>,
        prefix: Option<&str>,
        name: &str,
        value: ManifestValue,
    ) -> ManifestAttribute {
        ManifestAttribute {
            name: ExpandedName {
                namespace_uri: namespace.map(str::to_owned),
                local_name: name.to_owned(),
            },
            prefix: prefix.map(str::to_owned),
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

    fn string(s: &str) -> ManifestValue {
        ManifestValue::Text { value: text(s) }
    }

    #[test]
    fn keys_name_the_android_namespace_whatever_its_prefix_and_any_other_by_its_own() {
        let map = attributes(&node(vec![
            attribute(Some(ANDROID), Some("a"), "name", string("n")),
            attribute(None, None, "package", string("p")),
            attribute(Some("urn:other"), Some("o"), "x", string("1")),
            attribute(Some("urn:other"), None, "y", string("2")),
        ]))
        .unwrap();
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        // a JSON object keeps its keys sorted
        assert_eq!(keys, ["android:name", "o:x", "package", "{urn:other}y"]);
        assert_eq!(map["android:name"], "n");
    }

    #[test]
    fn a_repeated_attribute_is_refused_naming_it() {
        let twice = attributes(&node(vec![
            attribute(None, None, "x", string("1")),
            attribute(None, None, "x", string("2")),
        ]))
        .unwrap_err();
        assert_eq!(twice.code, ErrorCode::InvalidInput);
        assert_eq!(twice.details["attribute"], "x");
    }

    #[test]
    fn a_value_text_cannot_carry_is_refused_naming_the_attribute_and_kind() {
        let lone = ManifestValue::Text {
            value: ResourceText {
                utf16: vec![0xd800],
                text: None,
            },
        };
        let error = attributes(&node(vec![attribute(None, None, "label", lone)])).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedCapability);
        assert_eq!(error.details["attribute"], "label");
    }
}
