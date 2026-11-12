//! Structural graph over one [`NativeSession`].
//!
//! This is the native counterpart of the frozen `native_graph.Graph`. The
//! reference implementation loads class headers and members lazily by owner
//! name and only follows the superclass chain when collecting members; this
//! module keeps that behaviour, including the difference between
//! `methods(inherited = true)` (superclass chain only) and `subclass()` (the
//! full superclass/interface closure).
//!
//! A class descriptor that occurs in more than one selected DEX occurrence is
//! rejected rather than resolved to the first match: the reference audit
//! raises `UnsupportedAudit` in that case, and choosing one occurrence would
//! silently invent an answer.
use super::{ClassSite, NativeSession};
use crate::definitions::DefinitionFacts;
use mdd_dex::definitions::ClassDefinition;
use mdd_types::{ErrorCode, MddError, MddResult};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

/// Erased Java type rendered for rule predicates and audit detail.
///
/// Generic arguments are intentionally empty in this skeleton: erased
/// prototype descriptors carry no type arguments, and the frozen reference
/// only obtains them from `dalvik.annotation.Signature`, which the graph does
/// not interpret yet.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TypeRef {
    pub raw: String,
}

impl TypeRef {
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl std::fmt::Display for TypeRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.raw)
    }
}

/// One defined method in one occurrence, with erased prototype types.
#[derive(Clone, Debug)]
pub struct MethodInfo {
    pub owner: String,
    pub name: String,
    /// Exact descriptor tail, e.g. `(Ljava/lang/String;)V`.
    pub proto: String,
    pub args: Vec<TypeRef>,
    pub result: TypeRef,
    pub access_flags: u32,
    pub dex_ordinal: u32,
    pub class_def_idx: u32,
    pub method_idx: u32,
}

impl MethodInfo {
    pub fn is_static(&self) -> bool {
        self.access_flags & 0x8 != 0
    }
    pub fn is_abstract(&self) -> bool {
        self.access_flags & 0x400 != 0
    }
    /// `owner#name(proto)` in the reference `refs()` form.
    pub fn reference(&self) -> String {
        format!("{}#{}{}", self.owner, self.name, self.proto)
    }
    /// `owner` plus `name(proto)`, the reference `refs()` tuple identity.
    pub fn signature_key(&self) -> (String, String) {
        (self.owner.clone(), format!("{}{}", self.name, self.proto))
    }
}

/// One defined field in one occurrence.
#[derive(Clone, Debug)]
pub struct FieldInfo {
    pub owner: String,
    pub name: String,
    pub field_type: TypeRef,
    /// Exact type descriptor, e.g. `Ljava/util/List;`.
    pub type_descriptor: String,
    pub access_flags: u32,
    pub dex_ordinal: u32,
    pub class_def_idx: u32,
    pub field_idx: u32,
}

impl FieldInfo {
    pub fn is_static(&self) -> bool {
        self.access_flags & 0x8 != 0
    }
}

/// Validated class header for one occurrence.
#[derive(Clone, Debug)]
pub struct ClassNode {
    pub descriptor: String,
    /// Dotted name, matching the reference `Graph` node key.
    pub name: String,
    pub access_flags: u32,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub dex_ordinal: u32,
    pub class_def_idx: u32,
}

/// Graph over a prepared session.
///
/// Header lookups are cached because every rule repeatedly asks for the same
/// catalog owners. Member lists are rebuilt per call: this mirrors the
/// reference's per-owner lazy load without keeping a second owned copy of
/// every class in the process.
pub struct Graph<'a> {
    session: &'a NativeSession,
    headers: RefCell<BTreeMap<String, Option<ClassNode>>>,
}

impl<'a> Graph<'a> {
    pub fn new(session: &'a NativeSession) -> Self {
        Self {
            session,
            headers: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn session(&self) -> &'a NativeSession {
        self.session
    }

    /// Resolve one class header by dotted name.
    ///
    /// `None` means the descriptor is absent from every selected occurrence.
    /// A descriptor present in two occurrences is an unsupported ambiguity.
    pub fn class(&self, name: &str) -> MddResult<Option<ClassNode>> {
        if let Some(cached) = self.headers.borrow().get(name) {
            return Ok(cached.clone());
        }
        let descriptor = descriptor_of(name);
        let node = match self.session.class_sites(&descriptor) {
            None => None,
            Some(sites) => {
                if sites.len() > 1 {
                    return Err(MddError::new(
                        ErrorCode::UnsupportedCapability,
                        "hostlab.graph",
                        "duplicate class definitions in native structural audit",
                    )
                    .detail("class", name.to_owned())
                    .detail("occurrences", sites.len().to_string()));
                }
                Some(self.build_node(sites[0])?)
            }
        };
        self.headers
            .borrow_mut()
            .insert(name.to_owned(), node.clone());
        Ok(node)
    }

    fn build_node(&self, site: ClassSite) -> MddResult<ClassNode> {
        let state = self.session.occurrence_state(site.dex_ordinal)?;
        let definitions = state.definitions().ok_or_else(not_prepared)?;
        let class = definitions
            .definitions()
            .classes
            .get(site.class_def_idx as usize)
            .filter(|class| class.class_def_idx == site.class_def_idx)
            .ok_or_else(inconsistent)?;
        Ok(ClassNode {
            descriptor: class.descriptor.clone(),
            name: dotted(&class.descriptor)?,
            access_flags: class.access_flags,
            superclass: match &class.superclass_descriptor {
                Some(value) => Some(dotted(value)?),
                None => None,
            },
            interfaces: class_interfaces(definitions, class)?
                .iter()
                .map(|value| dotted(value))
                .collect::<MddResult<Vec<_>>>()?,
            dex_ordinal: site.dex_ordinal,
            class_def_idx: site.class_def_idx,
        })
    }

    /// Defined fields of one exact owner, in encoded order (static then instance).
    pub fn fields(&self, owner: &str) -> MddResult<Vec<FieldInfo>> {
        let Some(node) = self.class(owner)? else {
            return Ok(Vec::new());
        };
        let definitions = self.definitions_of(&node)?;
        let definitions = definitions.definitions();
        let (start, end) = owned_range(&definitions.field_definitions, node.class_def_idx);
        let class_idx = definitions
            .classes
            .get(node.class_def_idx as usize)
            .filter(|class| class.class_def_idx == node.class_def_idx)
            .map(|class| class.class_idx)
            .ok_or_else(inconsistent)?;
        let mut result = Vec::with_capacity(end - start);
        for definition in &definitions.field_definitions[start..end] {
            let reference = definitions
                .field_references
                .get(definition.field_idx as usize)
                .filter(|reference| reference.field_idx == definition.field_idx)
                .ok_or_else(inconsistent)?;
            if reference.class_descriptor != node.descriptor || definition.class_idx != class_idx {
                return Err(inconsistent());
            }
            result.push(FieldInfo {
                owner: node.name.clone(),
                name: reference.field_name.clone(),
                field_type: TypeRef::new(dotted(&reference.type_descriptor)?),
                type_descriptor: reference.type_descriptor.clone(),
                access_flags: definition.access_flags,
                dex_ordinal: node.dex_ordinal,
                class_def_idx: node.class_def_idx,
                field_idx: definition.field_idx,
            });
        }
        Ok(result)
    }

    /// Methods of the given owners.
    ///
    /// With `inherited`, each owner contributes its own methods followed by
    /// its superclass chain, exactly like the reference implementation. The
    /// chain is walked by name only and stops on a cycle; interfaces are not
    /// included here, matching the reference's asymmetric hierarchy use.
    pub fn methods(&self, owners: &[&str], inherited: bool) -> MddResult<Vec<MethodInfo>> {
        let mut result = Vec::new();
        for owner in owners {
            let mut current = Some((*owner).to_owned());
            let mut seen = BTreeSet::new();
            while let Some(name) = current {
                if !seen.insert(name.clone()) {
                    break;
                }
                result.extend(self.owner_methods(&name)?);
                current = if inherited {
                    self.class(&name)?.and_then(|node| node.superclass)
                } else {
                    None
                };
            }
        }
        Ok(result)
    }

    fn owner_methods(&self, owner: &str) -> MddResult<Vec<MethodInfo>> {
        let Some(node) = self.class(owner)? else {
            return Ok(Vec::new());
        };
        let definitions = self.definitions_of(&node)?;
        let definitions = definitions.definitions();
        let (start, end) = owned_range(&definitions.method_definitions, node.class_def_idx);
        let class_idx = definitions
            .classes
            .get(node.class_def_idx as usize)
            .filter(|class| class.class_def_idx == node.class_def_idx)
            .map(|class| class.class_idx)
            .ok_or_else(inconsistent)?;
        let mut result = Vec::with_capacity(end - start);
        for definition in &definitions.method_definitions[start..end] {
            let reference = definitions
                .method_references
                .get(definition.method_idx as usize)
                .filter(|reference| reference.method_idx == definition.method_idx)
                .ok_or_else(inconsistent)?;
            if reference.class_descriptor != node.descriptor || definition.class_idx != class_idx {
                return Err(inconsistent());
            }
            let proto = format!(
                "({}){}",
                reference.parameter_descriptors.concat(),
                reference.return_descriptor
            );
            let args = reference
                .parameter_descriptors
                .iter()
                .map(|value| dotted(value).map(TypeRef::new))
                .collect::<MddResult<Vec<_>>>()?;
            result.push(MethodInfo {
                owner: node.name.clone(),
                name: reference.method_name.clone(),
                proto,
                args,
                result: TypeRef::new(dotted(&reference.return_descriptor)?),
                access_flags: definition.access_flags,
                dex_ordinal: node.dex_ordinal,
                class_def_idx: node.class_def_idx,
                method_idx: definition.method_idx,
            });
        }
        Ok(result)
    }

    fn definitions_of(&self, node: &ClassNode) -> MddResult<&'a DefinitionFacts> {
        let state = self.session.occurrence_state(node.dex_ordinal)?;
        state.definitions().ok_or_else(not_prepared)
    }

    /// Every method of every owner that defines at least one method whose
    /// return descriptor equals `result_descriptor`.
    ///
    /// This reproduces the frozen reference `Graph.discover`: the SQL selects
    /// only *distinct owner descriptors*, then the whole owner is loaded, so
    /// non-matching methods of a matching owner are returned as well. Owners
    /// are ordered by exact descriptor string, as `ORDER BY m.class_descriptor`
    /// does, and the result keeps definition order inside each owner.
    pub fn discover(&self, result_descriptor: &str) -> MddResult<Vec<MethodInfo>> {
        let mut owners = BTreeSet::new();
        for state in self.session.occurrences() {
            let definitions = state.definitions().ok_or_else(not_prepared)?;
            for definition in &definitions.definitions().method_definitions {
                let reference = definitions
                    .definitions()
                    .method_references
                    .get(definition.method_idx as usize)
                    .ok_or_else(inconsistent)?;
                if reference.return_descriptor == result_descriptor {
                    owners.insert(reference.class_descriptor.clone());
                }
            }
        }
        let mut result = Vec::new();
        for descriptor in owners {
            result.extend(self.owner_methods(&dotted(&descriptor)?)?);
        }
        Ok(result)
    }

    /// Subclass/interface closure test, replicating the reference shortcuts:
    /// any `android.view.*`, `android.widget.*` or `android.webkit.*` name is
    /// already a `View`, and any `android.app.*Activity` is already an
    /// `Activity`; those platform classes are usually not in the APK.
    pub fn subclass(&self, child: &str, expected: &str) -> MddResult<bool> {
        if child == expected || platform_match(child, expected) {
            return Ok(true);
        }
        let mut pending = vec![child.to_owned()];
        let mut seen = BTreeSet::new();
        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            if name == expected || platform_match(&name, expected) {
                return Ok(true);
            }
            let Some(node) = self.class(&name)? else {
                continue;
            };
            if let Some(superclass) = node.superclass {
                pending.push(superclass);
            }
            pending.extend(node.interfaces);
        }
        Ok(false)
    }

    /// Instance method with this name and no arguments, inherited allowed.
    pub fn has(&self, owner: &str, name: &str) -> MddResult<bool> {
        Ok(self
            .methods(&[owner], true)?
            .iter()
            .any(|method| method.name == name && !method.is_static() && method.args.is_empty()))
    }
}

fn not_prepared() -> MddError {
    MddError::new(
        ErrorCode::IncompleteFacts,
        "hostlab.graph",
        "definitions are not prepared",
    )
}

fn inconsistent() -> MddError {
    MddError::new(
        ErrorCode::InternalFault,
        "hostlab.graph",
        "validated class/member ownership is inconsistent",
    )
}

fn platform_match(name: &str, expected: &str) -> bool {
    match expected {
        "android.view.View" => {
            name.starts_with("android.view.")
                || name.starts_with("android.widget.")
                || name.starts_with("android.webkit.")
        }
        "android.app.Activity" => name.starts_with("android.app.") && name.ends_with("Activity"),
        _ => false,
    }
}

/// Half-open position range of the definitions owned by `class_def_idx`.
///
/// Definition tables are validated to be ordered by `class_def_idx`, so this
/// is one binary search instead of a full scan per owner.
fn owned_range<T>(items: &[T], class_def_idx: u32) -> (usize, usize)
where
    T: OwnedByClass,
{
    let start = items.partition_point(|item| item.class_def_idx() < class_def_idx);
    let end = items.partition_point(|item| item.class_def_idx() <= class_def_idx);
    (start, end)
}

trait OwnedByClass {
    fn class_def_idx(&self) -> u32;
}

impl OwnedByClass for mdd_dex::definitions::FieldDefinition {
    fn class_def_idx(&self) -> u32 {
        self.class_def_idx
    }
}

impl OwnedByClass for mdd_dex::definitions::MethodDefinition {
    fn class_def_idx(&self) -> u32 {
        self.class_def_idx
    }
}

fn class_interfaces(
    definitions: &DefinitionFacts,
    class: &ClassDefinition,
) -> MddResult<Vec<String>> {
    let interfaces = &definitions.definitions().interfaces;
    let start = interfaces.partition_point(|item| item.class_def_idx < class.class_def_idx);
    let end = interfaces.partition_point(|item| item.class_def_idx <= class.class_def_idx);
    let mut result = Vec::with_capacity(end - start);
    for (offset, interface) in interfaces[start..end].iter().enumerate() {
        if interface.class_idx != class.class_idx
            || u32::try_from(offset).ok() != Some(interface.ordinal)
        {
            return Err(inconsistent());
        }
        result.push(interface.interface_descriptor.clone());
    }
    Ok(result)
}

/// Dotted class name to the exact JVM descriptor.
pub fn descriptor_of(name: &str) -> String {
    format!("L{};", name.replace('.', "/"))
}

/// Descriptor to the reference dotted form, including arrays and primitives.
///
/// This intentionally accepts only shapes that the DEX type table has already
/// validated; an unexpected descriptor is an error instead of a guess.
pub fn dotted(descriptor: &str) -> MddResult<String> {
    let dimensions = descriptor.len() - descriptor.trim_start_matches('[').len();
    let base = &descriptor[dimensions..];
    let mut value = match base {
        "V" => "void".to_owned(),
        "Z" => "boolean".to_owned(),
        "B" => "byte".to_owned(),
        "S" => "short".to_owned(),
        "C" => "char".to_owned(),
        "I" => "int".to_owned(),
        "J" => "long".to_owned(),
        "F" => "float".to_owned(),
        "D" => "double".to_owned(),
        _ => {
            let name = base
                .strip_prefix('L')
                .and_then(|value| value.strip_suffix(';'))
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InvalidInput,
                        "hostlab.graph",
                        "type descriptor has no supported shape",
                    )
                    .detail("descriptor", descriptor.to_owned())
                })?;
            name.replace('/', ".")
        }
    };
    for _ in 0..dimensions {
        value.push_str("[]");
    }
    Ok(value)
}
