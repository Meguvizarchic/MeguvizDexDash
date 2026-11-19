//! Budgeted operation-boundary adapters. Legacy low-level readers keep their independent limits.
use super::*;
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, DexSelection, InventoryPolicy, MemberBlob},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use std::{collections::BTreeSet, fs};
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct BudgetedSnapshot {
    snapshot: Arc<Snapshot>,
    _resident: Reservation,
}
impl BudgetedSnapshot {
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn admitted_resident_bytes(&self) -> u64 {
        self._resident.amount()
    }
}
pub fn capture(
    pool: &BudgetPool,
    inputs: &[InputSpec],
    requested: CaptureLimits,
) -> MddResult<BudgetedSnapshot> {
    pool.checkpoint()?;
    if inputs.is_empty() {
        return Err(invalid("empty capture request"));
    }
    if inputs.len() > requested.max_sources {
        return Err(MddError::new(
            ErrorCode::QuotaExceeded,
            "capture.admission",
            "source count exceeds requested limit",
        )
        .detail("budget", "max_sources")
        .detail("limit", requested.max_sources.to_string())
        .detail("observed", inputs.len().to_string()));
    }
    let mut total = 0u64;
    let mut names = 0u64;
    for input in inputs {
        pool.checkpoint()?;
        let size = fs::metadata(&input.path)
            .map_err(|e| {
                MddError::new(ErrorCode::InvalidInput, "capture.admission", e.to_string())
            })?
            .len();
        total = total.checked_add(size).ok_or_else(|| {
            exceeded(
                Resource::InputBytes,
                requested.max_input_bytes,
                "overflow",
                &pool.owner,
            )
        })?;
        names = names
            .checked_add(input.path.as_os_str().len() as u64 * 4)
            .ok_or_else(|| invalid("capture path size overflow"))?;
    }
    let limit = pool
        .remaining(Resource::InputBytes)?
        .min(requested.max_input_bytes);
    if total > limit {
        return Err(exceeded(Resource::InputBytes, limit, total, &pool.owner));
    }
    let metadata = (inputs.len() as u64 + 1)
        .checked_mul(4096)
        .and_then(|n| n.checked_add(names))
        .ok_or_else(|| invalid("capture metadata bound overflow"))?;
    let resident_upper = total
        .checked_add(metadata)
        .ok_or_else(|| invalid("capture resident overflow"))?;
    let workspace_upper = total
        .checked_mul(3)
        .and_then(|n| n.checked_add(metadata))
        .and_then(|n| n.checked_add(65536))
        .ok_or_else(|| invalid("capture workspace overflow"))?;
    let mut resident = pool.reserve(Resource::InputResidentBytes, resident_upper)?;
    let workspace = pool.reserve(Resource::BuildWorkspaceBytes, workspace_upper)?;
    let admission = pool.admit(Resource::InputBytes, total)?;
    let snapshot = Snapshot::capture(
        inputs,
        CaptureLimits {
            max_input_bytes: total,
            max_sources: requested.max_sources,
        },
    )?;
    let mut unique = BTreeSet::new();
    let mut retained = metadata;
    for source in snapshot.sources() {
        let lease = source.lease();
        if unique.insert(Arc::as_ptr(&lease) as *const u8 as usize) {
            retained = retained
                .checked_add(source.bytes().len() as u64)
                .ok_or_else(|| invalid("retained input overflow"))?;
        }
    }
    admission.commit(snapshot.manifest().captured_input_bytes.0)?;
    resident.shrink(retained)?;
    drop(workspace);
    Ok(BudgetedSnapshot {
        snapshot: Arc::new(snapshot),
        _resident: resident,
    })
}
struct InventoryOwner {
    inventory: ArchiveInventory,
    source: BudgetedSnapshot,
    _resident: Reservation,
    pool: BudgetPool,
}
#[derive(Clone)]
pub struct BudgetedInventory {
    owner: Arc<InventoryOwner>,
    cache: Arc<Mutex<BTreeMap<String, BudgetedMember>>>,
}
#[derive(Clone)]
pub struct BudgetedMember {
    blob: MemberBlob,
    _owner: Arc<InventoryOwner>,
    _resident: Option<Reservation>,
}
impl BudgetedMember {
    pub fn blob(&self) -> &MemberBlob {
        &self.blob
    }
    pub fn bytes(&self) -> Arc<[u8]> {
        self.blob.lease()
    }
}
impl BudgetedInventory {
    /// Borrowing this view does not automatically budget arbitrary legacy lazy read_member calls.
    /// Published runtime paths must retain this owner and use member() for resource reads.
    pub fn inventory(&self) -> &ArchiveInventory {
        &self.owner.inventory
    }
    pub fn source(&self) -> &BudgetedSnapshot {
        &self.owner.source
    }
    pub fn member(&self, member_id: &str) -> MddResult<BudgetedMember> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| fault("member cache mutex poisoned"))?;
        if let Some(member) = cache.get(member_id) {
            return Ok(member.clone());
        }
        let member = self
            .owner
            .inventory
            .manifest()
            .members
            .iter()
            .find(|m| m.member_id == member_id)
            .ok_or_else(|| invalid("member outside budgeted inventory"))?;
        let selected = self
            .owner
            .inventory
            .selected_dexes()
            .iter()
            .any(|d| d.blob.identity.member_id == member_id);
        let pool = &self.owner.pool;
        let (memory, workspace, admission) = if selected {
            (None, None, None)
        } else {
            pool.check_individual(Resource::MemberUncompressedBytes, member.declared_size.0)?;
            let memory = pool.reserve(Resource::ArchiveResidentBytes, member.declared_size.0)?;
            let workspace = pool.reserve(
                Resource::BuildWorkspaceBytes,
                member
                    .declared_size
                    .0
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(65536))
                    .ok_or_else(|| invalid("member workspace overflow"))?,
            )?;
            let admission = pool.admit(Resource::UncompressedBytes, member.declared_size.0)?;
            (Some(memory), Some(workspace), Some(admission))
        };
        let blob = self.owner.inventory.read_member(member_id)?;
        if let Some(admission) = admission {
            admission.commit(blob.len() as u64)?;
        }
        drop(workspace);
        let result = BudgetedMember {
            blob,
            _owner: Arc::clone(&self.owner),
            _resident: memory,
        };
        cache.insert(member_id.into(), result.clone());
        Ok(result)
    }
}
pub fn inventory(
    pool: &BudgetPool,
    source: BudgetedSnapshot,
    input_ordinal: usize,
    policy: InventoryPolicy,
    requested: ArchiveLimits,
    metadata_workspace_upper: u64,
) -> MddResult<BudgetedInventory> {
    let _source_admission = source._resident.borrow_for(pool)?;
    pool.checkpoint()?;
    let captured = source
        .snapshot
        .sources()
        .get(input_ordinal)
        .ok_or_else(|| invalid("input ordinal outside snapshot"))?;
    if metadata_workspace_upper < 4096 {
        return Err(invalid(
            "inventory metadata workspace upper bound below minimum",
        ));
    }
    let workspace = pool.reserve(Resource::BuildWorkspaceBytes, metadata_workspace_upper)?;
    let limits = ArchiveLimits {
        max_members: requested
            .max_members
            .min(usize::try_from(pool.remaining(Resource::ArchiveMembers)?).unwrap_or(usize::MAX))
            .min((metadata_workspace_upper / 4096) as usize),
        max_directory_bytes: requested
            .max_directory_bytes
            .min(metadata_workspace_upper / 16),
        max_member_bytes: requested
            .max_member_bytes
            .min(pool.limit(Resource::MemberUncompressedBytes)?),
        max_total_uncompressed_bytes: requested
            .max_total_uncompressed_bytes
            .min(pool.remaining(Resource::UncompressedBytes)?),
    };
    let (member_count, selected_bytes, archive) = match captured.kind() {
        InputKind::RawDex => (1, captured.bytes().len() as u64, false),
        InputKind::Apk => {
            let preview = ArchiveInventory::build(
                captured,
                InventoryPolicy {
                    dex_selection: DexSelection::ResourcesOnly,
                    require_dex: false,
                    ..policy
                },
                limits,
            )?;
            let mut bytes = 0u64;
            for member in &preview.manifest().members {
                if policy.selects(&member.raw_name) {
                    bytes = bytes.checked_add(member.declared_size.0).ok_or_else(|| {
                        exceeded(
                            Resource::UncompressedBytes,
                            limits.max_total_uncompressed_bytes,
                            "overflow",
                            &pool.owner,
                        )
                    })?;
                }
            }
            (preview.manifest().members.len() as u64, bytes, true)
        }
    };
    let members = pool.admit(Resource::ArchiveMembers, member_count)?;
    let data_resident = if archive { selected_bytes } else { 0 };
    let resident = pool.reserve(
        Resource::ArchiveResidentBytes,
        data_resident
            .checked_add(metadata_workspace_upper)
            .ok_or_else(|| invalid("inventory resident overflow"))?,
    )?;
    let decode = pool.reserve(
        Resource::BuildWorkspaceBytes,
        data_resident
            .checked_mul(2)
            .ok_or_else(|| invalid("inventory decode workspace overflow"))?,
    )?;
    let admitted = pool.admit(Resource::UncompressedBytes, selected_bytes)?;
    let result = ArchiveInventory::build(captured, policy, limits)?;
    let actual = result
        .selected_dexes()
        .iter()
        .try_fold(0u64, |n, d| n.checked_add(d.blob.len() as u64))
        .ok_or_else(|| invalid("selected member total overflow"))?;
    admitted.commit(actual)?;
    members.commit(result.manifest().members.len() as u64)?;
    drop(decode);
    drop(workspace);
    Ok(BudgetedInventory {
        owner: Arc::new(InventoryOwner {
            inventory: result,
            source,
            _resident: resident,
            pool: pool.clone(),
        }),
        cache: Arc::new(Mutex::new(BTreeMap::new())),
    })
}

#[derive(Clone, Copy, Debug)]
pub struct FactBounds {
    pub max_rows: u64,
    pub workspace_bytes: u64,
    pub ready_bytes: u64,
    pub text_bytes: u64,
}
pub struct FactBuildLimits {
    pub strings: StringLimits,
    pub definitions: DefinitionLimits,
}
pub struct BudgetedFacts<T> {
    facts: T,
    _source: BudgetedInventory,
    _resident: Reservation,
}
impl<T> BudgetedFacts<T> {
    pub fn facts(&self) -> &T {
        &self.facts
    }
}
/// The trusted producer receives strict parser limits, is called only after all upper
/// bounds are admitted, and must report its actual logical element count before publication.
/// Ready/workspace bounds are conservative declared reservations, not measured heap/RSS.
pub fn build_facts<T>(
    pool: &BudgetPool,
    source: BudgetedInventory,
    bounds: FactBounds,
    build: impl FnOnce(&BudgetedInventory, FactBuildLimits) -> MddResult<(T, u64)>,
) -> MddResult<BudgetedFacts<T>> {
    let _input_admission = source.owner.source._resident.borrow_for(pool)?;
    let _archive_admission = source.owner._resident.borrow_for(pool)?;
    let workspace = pool.reserve(Resource::BuildWorkspaceBytes, bounds.workspace_bytes)?;
    let ready = pool.reserve(Resource::ReadyFactsBytes, bounds.ready_bytes)?;
    let rows = pool.admit(Resource::FactRows, bounds.max_rows)?;
    let limits = FactBuildLimits {
        strings: StringLimits {
            max_strings: u32::try_from(bounds.max_rows).unwrap_or(u32::MAX),
            max_string_bytes: bounds.text_bytes,
            max_total_code_units: bounds.text_bytes / 2,
        },
        definitions: DefinitionLimits {
            max_rows: bounds.max_rows,
            max_text_bytes: bounds.text_bytes,
        },
    };
    let (facts, actual_rows) = build(&source, limits)?;
    rows.commit(actual_rows)?;
    drop(workspace);
    Ok(BudgetedFacts {
        facts,
        _source: source,
        _resident: ready,
    })
}
