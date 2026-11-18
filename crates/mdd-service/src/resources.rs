//! The members and the resource table of an opened archive, as the resource tools read them.
//!
//! Every byte served here comes through `ResourceByteEvidence`: read from the dataset's own
//! snapshot, its size and CRC checked by the archive reader, its SHA-256 and identity kept
//! beside it. A member is never re-opened from the path it was captured from. What is built
//! from bytes (a rendered XML, a parsed table) is cached per dataset, so paging through one
//! resource renders it once.
use crate::Dataset;
use mdd_facts::raw_fingerprints::ResourceByteEvidence;
pub use mdd_input::resources::{
    query::{Filter, Row},
    value::{data_type, type_label},
};
use mdd_input::{
    manifest::{ManifestLimits, parse_xml_resource},
    resources::{
        arsc::{ResourceTable, TableLimits},
        xml,
    },
};
use mdd_types::{ErrorCode, MddError};
use std::{collections::HashMap, sync::Arc};

/// The most bytes of one member the resource tools will serve or parse, the reference
/// engine's `max_resource_bytes`.
pub const MAX_RESOURCE_BYTES: u64 = 64 * 1024 * 1024;

/// Whether a member of this declared size may be served.
fn within_cap(declared: u64) -> bool {
    declared <= MAX_RESOURCE_BYTES
}

/// Why a resource could not be served.
#[derive(Debug)]
pub enum ResourceFailure {
    /// The input index names no input, or one that is not an archive.
    NoSuchInput(String),
    /// The archive has no member of that name.
    NotFound(String),
    /// The name is a directory entry.
    Directory(String),
    /// Several members have that name, and none is chosen for the reader.
    Several(String),
    /// The member is Android binary XML that does not parse.
    InvalidXml(MddError),
    /// `resources.arsc` does not parse as a resource table.
    InvalidTable(MddError),
    Error(MddError),
}

impl From<MddError> for ResourceFailure {
    fn from(error: MddError) -> Self {
        Self::Error(error)
    }
}

impl From<crate::manifest::ManifestFailure> for ResourceFailure {
    fn from(failure: crate::manifest::ManifestFailure) -> Self {
        use crate::manifest::ManifestFailure as M;
        match failure {
            M::NoSuchInput(message) => Self::NoSuchInput(message),
            M::Missing(message) => Self::NotFound(message),
            M::Several(message) => Self::Several(message),
            M::Error(error) => Self::Error(error),
        }
    }
}

/// One archive member, listed.
#[derive(Clone, Debug)]
pub struct ResourceFile {
    /// The member's position in the central directory.
    pub entry_index: u64,
    /// The name; for a name that is not UTF-8, its lossy reading (see `raw_name_hex`).
    pub name: String,
    /// The exact name bytes in hex, present only when `name` is not exact.
    pub raw_name_hex: Option<String>,
    pub bytes: u64,
    pub compressed_bytes: u64,
    pub crc32: u32,
    pub directory: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    /// Android binary XML, shown as XML text.
    AndroidXml,
    /// Bytes that are valid UTF-8, shown as they are.
    Text,
    /// Anything else, or anything read as hex.
    Binary,
}

/// A member's bytes with what they were read as.
#[derive(Clone)]
pub struct Resource {
    pub evidence: ResourceByteEvidence,
    pub kind: ResourceKind,
    /// The text of an `AndroidXml` or `Text` resource.
    pub text: Option<Arc<str>>,
}

/// A parsed `resources.arsc` with the bytes it was parsed from.
pub struct TableHandle {
    pub table: ResourceTable,
    pub evidence: ResourceByteEvidence,
}

#[derive(Default)]
pub(crate) struct ResourceCache {
    tables: HashMap<usize, Arc<TableHandle>>,
    last: Option<((usize, String, bool), Arc<Resource>)>,
    pub(crate) manifest_xml: HashMap<usize, Arc<str>>,
}

fn refuse(code: ErrorCode, message: &str) -> MddError {
    MddError::new(code, "service.resources", message)
}

impl Dataset {
    fn require_archive(&self, input_index: usize) -> Result<(), ResourceFailure> {
        let archives = self.archive_inputs();
        if archives.contains(&input_index) {
            return Ok(());
        }
        Err(ResourceFailure::NoSuchInput(format!(
            "input_index {input_index} is not an archive of this dataset (archive inputs: {archives:?})"
        )))
    }

    fn cache(&self) -> Result<std::sync::MutexGuard<'_, ResourceCache>, ResourceFailure> {
        self.resources.lock().map_err(|_| {
            ResourceFailure::Error(refuse(
                ErrorCode::InternalFault,
                "the resource cache is poisoned",
            ))
        })
    }

    /// Every member of the archive at `input_index`, directory entries included, in name order
    /// (the central directory's order breaks a tie between equal names).
    pub fn resource_files(&self, input_index: usize) -> Result<Vec<ResourceFile>, ResourceFailure> {
        self.require_archive(input_index)?;
        let mut files: Vec<(Vec<u8>, ResourceFile)> = self.inventories[input_index]
            .manifest()
            .members
            .iter()
            .map(|member| {
                let exact = member.name_utf8.clone();
                (
                    member.raw_name.clone(),
                    ResourceFile {
                        entry_index: member.archive_member_ordinal.map_or(0, |o| o.0),
                        name: exact.clone().unwrap_or_else(|| {
                            String::from_utf8_lossy(&member.raw_name).into_owned()
                        }),
                        raw_name_hex: exact
                            .is_none()
                            .then(|| member.raw_name.iter().map(|b| format!("{b:02x}")).collect()),
                        bytes: member.declared_size.0,
                        compressed_bytes: member.compressed_size.0,
                        crc32: member.crc32.unwrap_or(0),
                        directory: member.is_directory,
                    },
                )
            })
            .collect();
        files.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.entry_index.cmp(&b.1.entry_index)));
        Ok(files.into_iter().map(|(_, file)| file).collect())
    }

    /// The bytes of the member called `name`, and how they read: with `hex`, always as binary;
    /// otherwise binary XML as XML text, UTF-8 as text, anything else as binary.
    pub fn resource(
        &self,
        input_index: usize,
        name: &str,
        hex: bool,
    ) -> Result<Arc<Resource>, ResourceFailure> {
        self.require_archive(input_index)?;
        let key = (input_index, name.to_owned(), hex);
        if let Some((cached, resource)) = self.cache()?.last.as_ref()
            && *cached == key
        {
            return Ok(Arc::clone(resource));
        }
        let inventory = &self.inventories[input_index];
        let members: Vec<_> = inventory
            .manifest()
            .members
            .iter()
            .filter(|member| member.raw_name == name.as_bytes())
            .collect();
        let member = match members.as_slice() {
            [one] => *one,
            [] => {
                return Err(ResourceFailure::NotFound(format!(
                    "archive entry not found: {name}"
                )));
            }
            many => {
                return Err(ResourceFailure::Several(format!(
                    "the archive has {} entries named {name}; none is chosen for the reader",
                    many.len()
                )));
            }
        };
        if member.is_directory {
            return Err(ResourceFailure::Directory(
                "entry is a directory".to_owned(),
            ));
        }
        if !within_cap(member.declared_size.0) {
            return Err(ResourceFailure::Error(
                refuse(
                    ErrorCode::QuotaExceeded,
                    "the resource is larger than the resource budget",
                )
                .detail("budget", "max_resource_bytes")
                .detail("limit", MAX_RESOURCE_BYTES.to_string())
                .detail("observed", member.declared_size.0.to_string()),
            ));
        }
        let evidence = ResourceByteEvidence::build(&self.snapshot, inventory, &member.member_id)?;
        let (kind, text) = if hex {
            (ResourceKind::Binary, None)
        } else if evidence.bytes().starts_with(&[3, 0, 8, 0]) {
            let document = parse_xml_resource(evidence.lease(), ManifestLimits::default())
                .map_err(ResourceFailure::InvalidXml)?;
            let rendered = xml::render(&document).map_err(ResourceFailure::InvalidXml)?;
            (ResourceKind::AndroidXml, Some(Arc::<str>::from(rendered)))
        } else if let Ok(text) = std::str::from_utf8(evidence.bytes()) {
            (ResourceKind::Text, Some(Arc::<str>::from(text)))
        } else {
            (ResourceKind::Binary, None)
        };
        let resource = Arc::new(Resource {
            evidence,
            kind,
            text,
        });
        self.cache()?.last = Some((key, Arc::clone(&resource)));
        Ok(resource)
    }

    /// The parsed `resources.arsc` of the archive at `input_index`, parsed once.
    pub fn resource_table(&self, input_index: usize) -> Result<Arc<TableHandle>, ResourceFailure> {
        self.require_archive(input_index)?;
        if let Some(handle) = self.cache()?.tables.get(&input_index) {
            return Ok(Arc::clone(handle));
        }
        let resource = self.resource(input_index, "resources.arsc", true)?;
        let table = ResourceTable::parse(resource.evidence.bytes(), TableLimits::default())
            .map_err(ResourceFailure::InvalidTable)?;
        let handle = Arc::new(TableHandle {
            table,
            evidence: resource.evidence.clone(),
        });
        self.cache()?
            .tables
            .insert(input_index, Arc::clone(&handle));
        Ok(handle)
    }
}

#[cfg(test)]
#[path = "components_tests.rs"]
mod components_tests;
#[cfg(test)]
#[path = "resources_tests.rs"]
mod resources_tests;
