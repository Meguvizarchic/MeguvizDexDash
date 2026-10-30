//! Snapshot-bound code layout facts; method ownership is a separate definition layer.
use crate::{
    MetadataSource,
    definitions::{DefinitionFacts, MethodFactView, MethodFactViews, MethodViewLimits},
};
use mdd_dex::{
    definitions::MethodBody,
    instructions::{
        CodeItem, CodeLimits, CodeSection, DebugPolicy, read_code_offsets, read_code_section,
    },
    validate_header,
};
use mdd_input::{
    archive::{ArchiveInventory, MemberBlob},
    snapshot::Snapshot,
};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone, Serialize)]
pub struct CodeFact {
    pub(crate) code_item_id: String,
    pub(crate) data: CodeItem,
}

impl CodeFact {
    pub fn code_item_id(&self) -> &str {
        &self.code_item_id
    }
    pub fn data(&self) -> &CodeItem {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetadataFacts;
    use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
    use mdd_input::{
        archive::{ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec},
    };
    use std::fs;

    #[test]
    fn method_code_views_bind_exact_source_and_distinguish_body_states() {
        fn build(
            name: &str,
        ) -> (
            Snapshot,
            Vec<ArchiveInventory>,
            Vec<DefinitionFacts>,
            Vec<CodeFacts>,
        ) {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/definitions/generated")
                .join(name);
            let input = InputSpec {
                path,
                kind: InputKind::RawDex,
                expected_sha256: None,
            };
            let snapshot =
                Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
            let inventories: Vec<_> = snapshot
                .sources()
                .iter()
                .map(|source| {
                    ArchiveInventory::build(
                        source,
                        InventoryPolicy::default(),
                        ArchiveLimits::default(),
                    )
                    .unwrap()
                })
                .collect();
            let definitions = inventories
                .iter()
                .map(|inventory| {
                    let metadata =
                        MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default())
                            .unwrap();
                    DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap()
                })
                .collect();
            let code = inventories
                .iter()
                .map(|inventory| {
                    CodeFacts::build_all_code_items(&snapshot, inventory, 0, CodeLimits::default())
                        .unwrap()
                })
                .collect();
            (snapshot, inventories, definitions, code)
        }
        let (snapshot, inventories, definitions, codes) = build("definitions-035.dex");
        for ordinal in 0..2 {
            let view = MethodCodeFactViews::build(
                &definitions[ordinal],
                &codes[ordinal],
                MethodCodeViewLimits::default(),
            )
            .unwrap();
            let rows = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
            assert_eq!(
                rows.len(),
                definitions[ordinal].definitions().method_references.len()
            );
            assert!(rows.iter().all(|row| row.method.source.dex_occurrence_id
                == codes[ordinal].source().dex_occurrence_id));
            assert!(matches!(
                rows.iter()
                    .find(|r| r.method.reference.method_name == "externalCall")
                    .unwrap()
                    .body,
                MethodCodeBody::ReferenceOnly
            ));
            assert!(matches!(
                rows.iter()
                    .find(|r| r.method.reference.method_name == "nativeCall")
                    .unwrap()
                    .body,
                MethodCodeBody::Native
            ));
            assert!(matches!(
                rows.iter()
                    .find(|r| r.method.reference.method_name == "abstractCall")
                    .unwrap()
                    .body,
                MethodCodeBody::Abstract
            ));
            let present = rows
                .iter()
                .find(|r| r.method.reference.method_name == "virtualCall")
                .unwrap();
            let MethodCodeBody::Present { code, raw_insns } = &present.body else {
                panic!("present body lost")
            };
            assert_eq!(
                raw_insns.len() as u64,
                code.data().insns_range.byte_length.0
            );
            assert_eq!(*raw_insns, &[0x0e, 0]);
        }
        assert_ne!(
            codes[0].source().dex_occurrence_id,
            codes[1].source().dex_occurrence_id
        );
        assert_eq!(
            MethodCodeFactViews::build(&definitions[0], &codes[1], MethodCodeViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let projection =
            CodeFacts::build_offsets(&snapshot, &inventories[0], 0, &[], CodeLimits::default())
                .unwrap();
        assert_eq!(
            MethodCodeFactViews::build(
                &definitions[0],
                &projection,
                MethodCodeViewLimits::default()
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::IncompleteFacts
        );
        let mut partial = codes[0].clone();
        partial.code_layout_coverage = Completeness::Partial;
        assert_eq!(
            MethodCodeFactViews::build(&definitions[0], &partial, MethodCodeViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut wrong_start = definitions[0].clone();
        let method = wrong_start
            .definitions
            .method_definitions
            .iter_mut()
            .find(|method| matches!(method.body, MethodBody::Present { .. }))
            .unwrap();
        let MethodBody::Present {
            code_byte_offset, ..
        } = &mut method.body
        else {
            unreachable!()
        };
        *code_byte_offset = DecimalU64(1);
        assert_eq!(
            MethodCodeFactViews::build(&wrong_start, &codes[0], MethodCodeViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidInput
        );
        for limits in [
            MethodCodeViewLimits {
                max_code_items: 0,
                ..MethodCodeViewLimits::default()
            },
            MethodCodeViewLimits {
                max_code_index_bytes: 0,
                ..MethodCodeViewLimits::default()
            },
        ] {
            assert_eq!(
                MethodCodeFactViews::build(&definitions[0], &codes[0], limits)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
        let (_, _, zero_definitions, zero_codes) = build("zero-insns-present.dex");
        let zero = MethodCodeFactViews::build(
            &zero_definitions[0],
            &zero_codes[0],
            MethodCodeViewLimits::default(),
        )
        .unwrap();
        let empty = zero
            .iter()
            .find_map(|row| {
                let row = row.unwrap();
                (row.method.reference.method_name == "privateCall").then_some(row)
            })
            .unwrap();
        assert!(matches!(
            empty.body,
            MethodCodeBody::Present { raw_insns: [], .. }
        ));
    }

    #[test]
    fn all_hand_fixtures_match_independent_python_oracle_fields_and_raw_bytes() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/instructions/expected-results.json"
        ))
        .unwrap();
        let mut accepted = 0;
        let mut rejected = 0;
        for record in expected["results"].as_array().unwrap() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/instructions/generated")
                .join(record["path"].as_str().unwrap());
            let snapshot = Snapshot::capture(
                &[InputSpec {
                    path,
                    kind: InputKind::RawDex,
                    expected_sha256: None,
                }],
                CaptureLimits::default(),
            )
            .unwrap();
            let inventory = ArchiveInventory::build(
                &snapshot.sources()[0],
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let result =
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default());
            if record["status"] == "expected_invalid" {
                assert!(result.is_err(), "{}", record["path"]);
                rejected += 1;
                continue;
            }
            let facts = result.unwrap_or_else(|error| panic!("{}: {error}", record["path"]));
            accepted += 1;
            let rows = record["items"].as_array().unwrap();
            assert_eq!(facts.items.len(), rows.len());
            for (ordinal, (native, reference)) in facts.items.iter().zip(rows).enumerate() {
                let hex =
                    |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                assert_eq!(
                    native.data.raw_range.byte_offset.0,
                    reference["offset"].as_u64().unwrap()
                );
                assert_eq!(
                    hex(facts.raw_insns(ordinal).unwrap()),
                    reference["insns_bytes"].as_str().unwrap()
                );
                assert_eq!(
                    hex(facts.raw_code_item(ordinal).unwrap()),
                    reference["code_bytes"].as_str().unwrap()
                );
                if let Some(payload) = reference.get("payload") {
                    match &native.data.payloads[0].data {
                        mdd_dex::instructions::PayloadData::PackedSwitch {
                            first_key,
                            relative_targets,
                        } => {
                            assert_eq!(serde_json::json!(first_key), payload["first_key"]);
                            assert_eq!(serde_json::json!(relative_targets), payload["targets"]);
                        }
                        mdd_dex::instructions::PayloadData::SparseSwitch {
                            keys,
                            relative_targets,
                        } => {
                            assert_eq!(serde_json::json!(keys), payload["keys"]);
                            assert_eq!(serde_json::json!(relative_targets), payload["targets"]);
                        }
                        mdd_dex::instructions::PayloadData::FillArray {
                            element_width_bytes,
                            element_count,
                            data_range,
                        } => {
                            assert_eq!(serde_json::json!(element_width_bytes), payload["width"]);
                            assert_eq!(serde_json::json!(element_count), payload["count"]);
                            assert_eq!(
                                serde_json::json!(facts.bytes_in(data_range).unwrap()),
                                payload["bytes"]
                            );
                        }
                    }
                }
                let tries: Vec<_> = native
                    .data
                    .tries
                    .iter()
                    .map(|item| {
                        serde_json::json!([
                            item.start_code_unit,
                            item.code_unit_count,
                            item.handler_relative_byte_offset
                        ])
                    })
                    .collect();
                assert_eq!(serde_json::json!(tries), reference["tries"]);
                let handlers:Vec<_>=native.data.handlers.iter().map(|item|serde_json::json!({
                    "relative":item.relative_byte_offset,"typed":item.typed_catches.iter().map(|p|[p.type_idx,p.address_code_units]).collect::<Vec<_>>(),
                    "catch_all":item.catch_all_address_code_units})).collect();
                assert_eq!(serde_json::json!(handlers), reference["handlers"]);
                if let Some(debug) = reference.get("debug") {
                    let native = native.data.debug_info.as_ref().unwrap();
                    let positions: Vec<_> = native
                        .events
                        .iter()
                        .filter(|e| e.emits_position)
                        .map(|e| {
                            serde_json::json!([
                                e.address_code_units,
                                e.encoded_line_decimal.parse::<i64>().unwrap()
                            ])
                        })
                        .collect();
                    assert_eq!(serde_json::json!(positions), debug["positions"]);
                    let view: Vec<_> = native
                        .method_positions()
                        .map(|e| {
                            serde_json::json!([
                                e.address_code_units,
                                e.encoded_line_decimal.parse::<i64>().unwrap()
                            ])
                        })
                        .collect();
                    assert_eq!(serde_json::json!(view), debug["applicable_positions"]);
                    let source: Vec<_> = native
                        .usable_source_positions()
                        .map(|e| {
                            serde_json::json!([e.address_code_units, e.source_line.unwrap().0])
                        })
                        .collect();
                    assert_eq!(serde_json::json!(source), debug["usable_source_positions"]);
                    assert_eq!(
                        serde_json::json!(native.representation),
                        debug["representation"]
                    );
                    assert_eq!(
                        serde_json::json!(
                            native.events.iter().map(|e| e.opcode).collect::<Vec<_>>()
                        ),
                        debug["operations"]
                    );
                }
            }
        }
        assert_eq!((accepted, rejected), (20, 5));
    }

    #[test]
    fn raw_code_retains_exact_member_lease_scope_and_occurrence_after_source_changes() {
        let directory = std::env::temp_dir().join(mdd_types::opaque_id("code-facts-test").unwrap());
        fs::create_dir(&directory).unwrap();
        let path = directory.join("input.dex");
        let original = include_bytes!(
            "../../../tests/fixtures/instructions/generated/unreferenced-two-code.dex"
        );
        fs::write(&path, original).unwrap();
        let spec = InputSpec {
            path: path.clone(),
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot = Snapshot::capture(&[spec.clone(), spec], CaptureLimits::default()).unwrap();
        let left = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let right = ArchiveInventory::build(
            &snapshot.sources()[1],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let facts =
            CodeFacts::build_all_code_items(&snapshot, &left, 0, CodeLimits::default()).unwrap();
        let other =
            CodeFacts::build_all_code_items(&snapshot, &right, 0, CodeLimits::default()).unwrap();
        assert_eq!(facts.items.len(), 2);
        assert_ne!(facts.items[0].code_item_id, other.items[0].code_item_id);
        assert!(Arc::ptr_eq(
            &facts.lease(),
            &left.selected_dexes()[0].blob.lease()
        ));
        assert_eq!(facts.raw_insns(0).unwrap(), &[0x0e, 0]);
        let scoped =
            CodeFacts::build_offsets(&snapshot, &left, 0, &[132, 112, 132], CodeLimits::default())
                .unwrap();
        assert_eq!(scoped.items.len(), 3);
        assert!(scoped.scope.starts_with("explicit-code-offsets"));
        assert_eq!(
            scoped.declared_code_item_byte_offsets(),
            &[DecimalU64(112), DecimalU64(132)]
        );
        assert!(scoped.known_code_item_start(132));
        assert!(!scoped.known_code_item_start(113));
        assert!(!facts.references_built);
        assert!(!facts.method_ownership_built);
        assert!(!facts.full_dex_validation_complete);
        fs::write(&path, b"changed external source").unwrap();
        fs::rename(&path, directory.join("renamed.dex")).unwrap();
        drop(snapshot);
        drop(left);
        drop(right);
        assert_eq!(facts.raw_insns(1).unwrap(), &[0x0e, 0]);
        assert_eq!(facts.lease().as_ref(), original);
        assert_eq!(
            other.raw_code_item(0).unwrap(),
            facts.raw_code_item(0).unwrap()
        );
    }
}

/// Immutable validated encoded facts; source-position semantics remain separate.
/// ```compile_fail
/// # use mdd_facts::code::CodeFacts;
/// fn forge(facts: &mut CodeFacts) { facts.items.clear(); }
/// ```
#[derive(Clone, Serialize)]
pub struct CodeFacts {
    pub(crate) source: MetadataSource,
    pub(crate) scope: String,
    pub(crate) debug_policy: DebugPolicy,
    pub(crate) declared_map_code_item_count: u32,
    pub(crate) declared_code_item_byte_offsets: Vec<DecimalU64>,
    pub(crate) requested_code_byte_offsets: Vec<DecimalU64>,
    pub(crate) items: Vec<CodeFact>,
    pub(crate) code_layout_coverage: Completeness,
    pub(crate) method_ownership_built: bool,
    pub(crate) references_built: bool,
    pub(crate) source_positions_built: bool,
    pub(crate) full_dex_validation_complete: bool,
    #[serde(skip)]
    blob: MemberBlob,
}

impl CodeFacts {
    pub fn build_all_code_items(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        limits: CodeLimits,
    ) -> MddResult<Self> {
        Self::build(snapshot, inventory, dex_index, None, limits)
    }

    pub fn build_offsets(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        offsets: &[u32],
        limits: CodeLimits,
    ) -> MddResult<Self> {
        Self::build(snapshot, inventory, dex_index, Some(offsets), limits)
    }

    fn build(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        offsets: Option<&[u32]>,
        limits: CodeLimits,
    ) -> MddResult<Self> {
        let source_entry = snapshot
            .manifest()
            .sources
            .iter()
            .find(|source| {
                source.occurrence_id == inventory.manifest().source_occurrence_id
                    && source.content_id == inventory.manifest().source_content_id
            })
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.code",
                    "inventory does not belong to snapshot",
                )
            })?;
        let candidate = inventory.selected_dexes().get(dex_index).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "DEX occurrence index outside inventory",
            )
        })?;
        let source = MetadataSource {
            snapshot_id: snapshot.manifest().snapshot_id.clone(),
            dex_occurrence_id: candidate.dex_occurrence_id.clone(),
            physical_dex_id: candidate.physical_dex_id.clone(),
            member_id: candidate.blob.identity.member_id.clone(),
            source_occurrence_id: source_entry.occurrence_id.clone(),
            content_id: candidate.blob.content_id.clone(),
        };
        let bind = |error: MddError| {
            error
                .detail("source_binding", "snapshot_member_lease")
                .detail("snapshot_id", source.snapshot_id.clone())
                .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
                .detail("member_id", source.member_id.clone())
                .detail("content_id", source.content_id.clone())
        };
        if candidate.logical_header_byte_offset.0 != 0
            || candidate.blob.identity.source_occurrence_id != source_entry.occurrence_id
        {
            return Err(bind(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "unsupported logical offset or mismatched source",
            )));
        }
        if content_id(candidate.blob.bytes()) != source.content_id {
            return Err(bind(MddError::new(
                ErrorCode::InternalFault,
                "facts.code",
                "held bytes differ from content identity",
            )));
        }
        let header = validate_header(candidate.blob.bytes()).map_err(bind)?;
        let section: CodeSection = match offsets {
            None => read_code_section(candidate.blob.bytes(), &header, limits),
            Some(offsets) => read_code_offsets(candidate.blob.bytes(), &header, offsets, limits),
        }
        .map_err(bind)?;
        let items = section
            .items
            .into_iter()
            .map(|data| CodeFact {
                code_item_id: format!(
                    "{}:code-byte:{}",
                    source.dex_occurrence_id, data.raw_range.byte_offset.0
                ),
                data,
            })
            .collect();
        Ok(Self {
            source,
            scope: section.scope,
            debug_policy: limits.debug_policy,
            declared_map_code_item_count: section.declared_code_item_count,
            declared_code_item_byte_offsets: section.declared_code_item_byte_offsets,
            requested_code_byte_offsets: offsets
                .unwrap_or(&[])
                .iter()
                .map(|n| DecimalU64(u64::from(*n)))
                .collect(),
            items,
            code_layout_coverage: Completeness::Complete,
            method_ownership_built: false,
            references_built: false,
            source_positions_built: false,
            full_dex_validation_complete: false,
            blob: candidate.blob.clone(),
        })
    }

    pub fn lease(&self) -> Arc<[u8]> {
        self.blob.lease()
    }

    pub fn source(&self) -> &MetadataSource {
        &self.source
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn debug_policy(&self) -> DebugPolicy {
        self.debug_policy
    }
    pub fn declared_map_code_item_count(&self) -> u32 {
        self.declared_map_code_item_count
    }
    pub fn declared_code_item_byte_offsets(&self) -> &[DecimalU64] {
        &self.declared_code_item_byte_offsets
    }
    pub fn known_code_item_start(&self, offset: u64) -> bool {
        self.declared_code_item_byte_offsets
            .binary_search_by_key(&offset, |item| item.0)
            .is_ok()
    }
    pub fn requested_code_byte_offsets(&self) -> &[DecimalU64] {
        &self.requested_code_byte_offsets
    }
    pub fn items(&self) -> &[CodeFact] {
        &self.items
    }
    pub fn code_layout_coverage(&self) -> Completeness {
        self.code_layout_coverage
    }
    pub fn method_ownership_built(&self) -> bool {
        self.method_ownership_built
    }
    pub fn references_built(&self) -> bool {
        self.references_built
    }
    pub fn source_positions_built(&self) -> bool {
        self.source_positions_built
    }
    pub fn full_dex_validation_complete(&self) -> bool {
        self.full_dex_validation_complete
    }

    fn bytes_in(&self, range: &mdd_dex::DexRange) -> MddResult<&[u8]> {
        mdd_dex::checked_reader::CheckedReader::new(self.blob.bytes())
            .range(range.byte_offset.0, range.byte_length.0)
    }

    pub fn raw_insns(&self, ordinal: usize) -> MddResult<&[u8]> {
        let item = self.items.get(ordinal).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "code ordinal outside scope",
            )
        })?;
        self.bytes_in(&item.data.insns_range)
    }

    pub fn raw_code_item(&self, ordinal: usize) -> MddResult<&[u8]> {
        let item = self.items.get(ordinal).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.code",
                "code ordinal outside scope",
            )
        })?;
        self.bytes_in(&item.data.raw_range)
    }
}

/// Logical join limits. These are not an allocator or process RSS bound.
#[derive(Clone, Copy, Debug)]
pub struct MethodCodeViewLimits {
    pub methods: MethodViewLimits,
    pub max_code_items: u64,
    pub max_code_index_bytes: u64,
}
impl Default for MethodCodeViewLimits {
    fn default() -> Self {
        Self {
            methods: MethodViewLimits::default(),
            max_code_items: 4_000_000,
            max_code_index_bytes: 256 * 1024 * 1024,
        }
    }
}

/// These variants distinguish a reference from actual definitions without bodies.
/// `Present` contains exact validated code facts, not a legacy opcode projection.
pub enum MethodCodeBody<'a> {
    ReferenceOnly,
    Native,
    Abstract,
    Present {
        code: &'a CodeFact,
        raw_insns: &'a [u8],
    },
}
pub struct MethodCodeFactView<'a> {
    pub method: MethodFactView<'a>,
    pub body: MethodCodeBody<'a>,
}
pub struct MethodCodeFactViews<'a> {
    methods: MethodFactViews<'a>,
    code: &'a CodeFacts,
    code_index: Vec<usize>,
}
impl<'a> MethodCodeFactViews<'a> {
    /// Bind complete same-occurrence definitions and code layout. A scoped code
    /// projection is accepted only when every present method body is included.
    pub fn build(
        definitions: &'a DefinitionFacts,
        code: &'a CodeFacts,
        limits: MethodCodeViewLimits,
    ) -> MddResult<Self> {
        let source = definitions.metadata().source();
        let actual = code.source();
        if source.snapshot_id != actual.snapshot_id
            || source.dex_occurrence_id != actual.dex_occurrence_id
            || source.physical_dex_id != actual.physical_dex_id
            || source.member_id != actual.member_id
            || source.source_occurrence_id != actual.source_occurrence_id
            || source.content_id != actual.content_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.method_code",
                "definitions and code do not bind the same source generation",
            ));
        }
        if code.code_layout_coverage() != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.method_code",
                "complete code layout for requested items is required",
            ));
        }
        let methods = definitions.method_fact_views(limits.methods)?;
        let count = u64::try_from(code.items().len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.method_code",
                "code index count overflow",
            )
        })?;
        let bytes = count
            .checked_mul(std::mem::size_of::<usize>() as u64)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.method_code",
                    "code index byte overflow",
                )
            })?;
        if count > limits.max_code_items || bytes > limits.max_code_index_bytes {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.method_code",
                "code index budget exceeded",
            ));
        }
        let mut code_index = Vec::new();
        code_index
            .try_reserve_exact(code.items().len())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.method_code",
                    "code index allocation failed",
                )
            })?;
        code_index.extend(0..code.items().len());
        code_index
            .sort_unstable_by_key(|&ordinal| code.items()[ordinal].data().raw_range.byte_offset.0);
        let view = Self {
            methods,
            code,
            code_index,
        };
        // Fail before exposing any rows if a selected projection omitted a real body.
        for method in view.methods.iter() {
            view.body(&method?)?;
        }
        Ok(view)
    }

    fn body(&self, method: &MethodFactView<'a>) -> MddResult<MethodCodeBody<'a>> {
        let Some(definition) = method.definition else {
            return Ok(MethodCodeBody::ReferenceOnly);
        };
        match &definition.body {
            MethodBody::Native => Ok(MethodCodeBody::Native),
            MethodBody::Abstract => Ok(MethodCodeBody::Abstract),
            MethodBody::Present {
                code_byte_offset,
                declared_insns_size,
            } => {
                let at = code_byte_offset.0;
                if !self.code.known_code_item_start(at) {
                    return Err(MddError::new(
                        ErrorCode::InvalidInput,
                        "facts.method_code",
                        "method body is not a physical code item start",
                    )
                    .detail("method_idx", definition.method_idx.to_string())
                    .detail("code_item_byte_offset", at.to_string()));
                }
                let position = self
                    .code_index
                    .binary_search_by_key(&at, |&ordinal| {
                        self.code.items()[ordinal].data().raw_range.byte_offset.0
                    })
                    .map_err(|_| {
                        MddError::new(
                            ErrorCode::IncompleteFacts,
                            "facts.method_code",
                            "method body absent from selected code projection",
                        )
                        .detail("method_idx", definition.method_idx.to_string())
                        .detail("code_item_byte_offset", at.to_string())
                    })?;
                let ordinal = self.code_index[position];
                let code: &'a CodeFacts = self.code;
                let item = &code.items()[ordinal];
                let data = item.data();
                let expected = u64::from(*declared_insns_size) * 2;
                if data.insns_size_code_units != *declared_insns_size
                    || data.insns_range.byte_length.0 != expected
                    || at.checked_add(16) != Some(data.insns_range.byte_offset.0)
                {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "facts.method_code",
                        "definition and code instruction intervals disagree",
                    ));
                }
                let raw_insns = code.raw_insns(ordinal)?;
                Ok(MethodCodeBody::Present {
                    code: item,
                    raw_insns,
                })
            }
        }
    }

    /// Iterate every method reference in DEX order, including reference-only rows.
    pub fn iter(&self) -> impl Iterator<Item = MddResult<MethodCodeFactView<'a>>> + '_ {
        self.methods.iter().map(|method| {
            let method = method?;
            let body = self.body(&method)?;
            Ok(MethodCodeFactView { method, body })
        })
    }
}
