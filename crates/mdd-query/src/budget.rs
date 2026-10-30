//! Hierarchical logical budgets and RAII-owned resident/queue reservations, never RSS claims.
use mdd_session::cancellation::{DeliveryBudgetDeadline, QueryCancellation};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Condvar, Mutex, Weak},
    time::{Duration, Instant},
};
pub mod imports;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    InputBytes,
    InputResidentBytes,
    ArchiveResidentBytes,
    ResidentBytes,
    ArchiveMembers,
    MemberUncompressedBytes,
    UncompressedBytes,
    FactRows,
    BuildWorkspaceBytes,
    ReadyFactsBytes,
    QueryWorkspaceBytes,
    QueryWorkBytes,
    OutputBytes,
    QueueBytes,
    QueueItems,
    Cursors,
    SpoolBytes,
    Threads,
    QuerySteps,
}
pub const RESOURCES: [Resource; 19] = [
    Resource::InputBytes,
    Resource::InputResidentBytes,
    Resource::ArchiveResidentBytes,
    Resource::ResidentBytes,
    Resource::ArchiveMembers,
    Resource::MemberUncompressedBytes,
    Resource::UncompressedBytes,
    Resource::FactRows,
    Resource::BuildWorkspaceBytes,
    Resource::ReadyFactsBytes,
    Resource::QueryWorkspaceBytes,
    Resource::QueryWorkBytes,
    Resource::OutputBytes,
    Resource::QueueBytes,
    Resource::QueueItems,
    Resource::Cursors,
    Resource::SpoolBytes,
    Resource::Threads,
    Resource::QuerySteps,
];
impl Resource {
    fn resident(self) -> bool {
        matches!(
            self,
            Self::InputResidentBytes
                | Self::ArchiveResidentBytes
                | Self::ResidentBytes
                | Self::BuildWorkspaceBytes
                | Self::ReadyFactsBytes
                | Self::QueryWorkspaceBytes
                | Self::QueueBytes
                | Self::QueueItems
                | Self::Cursors
                | Self::SpoolBytes
                | Self::Threads
        )
    }
    fn physical_memory(self) -> bool {
        matches!(
            self,
            Self::InputResidentBytes
                | Self::ArchiveResidentBytes
                | Self::BuildWorkspaceBytes
                | Self::ReadyFactsBytes
                | Self::QueryWorkspaceBytes
        )
    }
}
#[derive(Clone, Debug)]
pub struct BudgetLimits {
    values: BTreeMap<Resource, u64>,
    soft_deadline_ms: u64,
    hard_deadline_ms: u64,
}
impl Serialize for BudgetLimits {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("BudgetLimits", 5)?;
        let values: BTreeMap<Resource, DecimalU64> = self
            .values
            .iter()
            .map(|(kind, value)| (*kind, DecimalU64(*value)))
            .collect();
        state.serialize_field("values", &values)?;
        state.serialize_field("soft_deadline_ms", &DecimalU64(self.soft_deadline_ms))?;
        state.serialize_field("hard_deadline_ms", &DecimalU64(self.hard_deadline_ms))?;
        state.serialize_field("max_owner_records", &DecimalU64(10000))?;
        state.serialize_field("max_live_reservations", &DecimalU64(10000))?;
        state.end()
    }
}
impl Default for BudgetLimits {
    fn default() -> Self {
        let mut values = BTreeMap::new();
        for resource in RESOURCES {
            values.insert(
                resource,
                match resource {
                    Resource::ArchiveMembers => 1_000_000,
                    Resource::FactRows => 16_000_000,
                    Resource::QueueItems => 16,
                    Resource::Cursors => 64,
                    Resource::Threads => 2,
                    Resource::QuerySteps => 1_000_000,
                    Resource::InputBytes | Resource::UncompressedBytes => 1024 * 1024 * 1024,
                    Resource::MemberUncompressedBytes => 512 * 1024 * 1024,
                    Resource::ReadyFactsBytes => 256 * 1024 * 1024,
                    Resource::InputResidentBytes | Resource::ArchiveResidentBytes => {
                        512 * 1024 * 1024
                    }
                    Resource::ResidentBytes => 1024 * 1024 * 1024,
                    Resource::QueueBytes => 8 * 1024 * 1024,
                    _ => 64 * 1024 * 1024,
                },
            );
        }
        Self {
            values,
            soft_deadline_ms: 60_000,
            hard_deadline_ms: 90_000,
        }
    }
}
impl BudgetLimits {
    pub fn with(mut self, resource: Resource, limit: u64) -> Self {
        self.values.insert(resource, limit);
        self
    }
    pub fn deadlines(mut self, soft_ms: u64, hard_ms: u64) -> MddResult<Self> {
        if hard_ms < soft_ms {
            return Err(invalid("hard deadline precedes soft deadline"));
        }
        self.soft_deadline_ms = soft_ms;
        self.hard_deadline_ms = hard_ms;
        Ok(self)
    }
    pub fn limit(&self, resource: Resource) -> u64 {
        self.values[&resource]
    }
    fn restricted(&self, requested: &Self) -> Self {
        let mut result = requested.clone();
        for resource in RESOURCES {
            result.values.insert(
                resource,
                self.limit(resource).min(requested.limit(resource)),
            );
        }
        result.soft_deadline_ms = self.soft_deadline_ms.min(requested.soft_deadline_ms);
        result.hard_deadline_ms = self.hard_deadline_ms.min(requested.hard_deadline_ms);
        result
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    Global,
    Worker,
    Session,
    Query,
}
impl BudgetScope {
    fn ordinal(self) -> u8 {
        match self {
            Self::Global => 0,
            Self::Worker => 1,
            Self::Session => 2,
            Self::Query => 3,
        }
    }
}
struct Node {
    parent: Option<String>,
    scope: BudgetScope,
    limits: BudgetLimits,
    used: BTreeMap<Resource, u64>,
    soft: Instant,
    hard: Instant,
    started: Instant,
}
struct Shared {
    ticket: u64,
    weak: Weak<ReservationInner>,
}
struct State {
    nodes: BTreeMap<String, Node>,
    shared: BTreeMap<(String, String, Resource), Shared>,
    next: u64,
    fault: Option<MddError>,
    live_reservations: usize,
}
#[derive(Clone)]
pub struct BudgetPool {
    state: Arc<Mutex<State>>,
    owner: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct BudgetUsage {
    pub owner: String,
    pub scope: BudgetScope,
    pub used: BTreeMap<Resource, DecimalU64>,
    pub effective_limits: BudgetLimits,
}
fn invalid(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "budget", message)
}
fn fault(message: &str) -> MddError {
    MddError::new(ErrorCode::InternalFault, "budget", message)
}
fn exceeded(resource: Resource, limit: u64, observed: impl ToString, owner: &str) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "budget", "budget exhausted")
        .detail(
            "budget",
            serde_json::to_value(resource).expect("enum serializes"),
        )
        .detail("limit", limit.to_string())
        .detail("observed", observed.to_string())
        .detail("owner", owner)
}
impl BudgetPool {
    pub fn global(owner: String, limits: BudgetLimits) -> MddResult<Self> {
        if owner.is_empty() {
            return Err(invalid("empty budget owner"));
        }
        let now = Instant::now();
        let soft = now
            .checked_add(Duration::from_millis(limits.soft_deadline_ms))
            .ok_or_else(|| invalid("deadline overflow"))?;
        let hard = now
            .checked_add(Duration::from_millis(limits.hard_deadline_ms))
            .ok_or_else(|| invalid("deadline overflow"))?;
        let node = Node {
            parent: None,
            scope: BudgetScope::Global,
            limits,
            used: BTreeMap::new(),
            soft,
            hard,
            started: now,
        };
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                nodes: BTreeMap::from([(owner.clone(), node)]),
                shared: BTreeMap::new(),
                next: 0,
                fault: None,
                live_reservations: 0,
            })),
            owner,
        })
    }
    fn lock(&self) -> MddResult<std::sync::MutexGuard<'_, State>> {
        let state = self
            .state
            .lock()
            .map_err(|_| fault("budget mutex poisoned"))?;
        if let Some(error) = &state.fault {
            return Err(error.clone());
        }
        Ok(state)
    }
    pub fn child(
        &self,
        owner: String,
        scope: BudgetScope,
        requested: BudgetLimits,
    ) -> MddResult<Self> {
        let mut state = self.lock()?;
        let parent = &state.nodes[&self.owner];
        if owner.is_empty()
            || owner.len() > 256
            || state.nodes.contains_key(&owner)
            || scope.ordinal() != parent.scope.ordinal() + 1
        {
            return Err(invalid("invalid budget hierarchy or owner"));
        }
        if state.nodes.len() >= 10000 {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "budget",
                "budget owner registry lifetime capacity exhausted",
            )
            .detail("budget", "budget_owners")
            .detail("limit", "10000")
            .detail("observed", (state.nodes.len() + 1).to_string()));
        }
        let limits = parent.limits.restricted(&requested);
        let now = Instant::now();
        let soft = parent.soft.min(
            now.checked_add(Duration::from_millis(limits.soft_deadline_ms))
                .ok_or_else(|| invalid("deadline overflow"))?,
        );
        let hard = parent.hard.min(
            now.checked_add(Duration::from_millis(limits.hard_deadline_ms))
                .ok_or_else(|| invalid("deadline overflow"))?,
        );
        state.nodes.insert(
            owner.clone(),
            Node {
                parent: Some(self.owner.clone()),
                scope,
                limits,
                used: BTreeMap::new(),
                soft,
                hard,
                started: now,
            },
        );
        Ok(Self {
            state: Arc::clone(&self.state),
            owner,
        })
    }
    pub fn checkpoint(&self) -> MddResult<()> {
        let state = self.lock()?;
        let node = &state.nodes[&self.owner];
        let now = Instant::now();
        if now >= node.soft {
            let hard = now >= node.hard;
            return Err(MddError::new(
                ErrorCode::DeadlineExceeded,
                "budget",
                "query deadline reached",
            )
            .detail("deadline_kind", if hard { "hard" } else { "soft" })
            .detail(
                "budget",
                if hard {
                    "hard_deadline_ms"
                } else {
                    "soft_deadline_ms"
                },
            )
            .detail(
                "limit",
                (if hard { node.hard } else { node.soft })
                    .saturating_duration_since(node.started)
                    .as_millis()
                    .to_string(),
            )
            .detail(
                "observed",
                now.saturating_duration_since(node.started)
                    .as_millis()
                    .to_string(),
            )
            .detail("owner", self.owner.clone())
            .detail("supervisor_termination_required", hard));
        }
        Ok(())
    }
    pub fn hard_deadline_due(&self) -> MddResult<bool> {
        Ok(Instant::now() >= self.lock()?.nodes[&self.owner].hard)
    }
    /// Copy the immutable absolute deadlines without holding the budget lock
    /// while the lifecycle lock is acquired for final delivery.
    pub(crate) fn delivery_deadline(&self) -> MddResult<DeliveryBudgetDeadline> {
        let (started, soft, hard) = {
            let state = self.lock()?;
            let node = &state.nodes[&self.owner];
            (node.started, node.soft, node.hard)
        };
        DeliveryBudgetDeadline::new(started, soft, hard, self.owner.clone())
    }
    pub fn limit(&self, resource: Resource) -> MddResult<u64> {
        Ok(self.lock()?.nodes[&self.owner].limits.limit(resource))
    }
    pub fn check_individual(&self, resource: Resource, bytes: u64) -> MddResult<()> {
        self.checkpoint()?;
        let limit = self.limit(resource)?;
        if bytes > limit {
            Err(exceeded(resource, limit, bytes, &self.owner))
        } else {
            Ok(())
        }
    }
    pub fn remaining(&self, resource: Resource) -> MddResult<u64> {
        let state = self.lock()?;
        Ok(Self::ancestors(&state, &self.owner)
            .iter()
            .map(|owner| {
                let node = &state.nodes[owner];
                node.limits
                    .limit(resource)
                    .saturating_sub(node.used.get(&resource).copied().unwrap_or(0))
            })
            .min()
            .unwrap_or(0))
    }
    /// Check one cumulative charge against all current ancestors without committing it.
    /// A subsequent charge still rechecks atomically because siblings may change usage.
    pub(crate) fn check_cumulative(&self, resource: Resource, amount: u64) -> MddResult<()> {
        self.checkpoint()?;
        if resource.resident() || resource == Resource::MemberUncompressedBytes {
            return Err(invalid("resource requires reservation or per-member check"));
        }
        let state = self.lock()?;
        for owner in Self::ancestors(&state, &self.owner) {
            let node = &state.nodes[&owner];
            let limit = node.limits.limit(resource);
            let value = node
                .used
                .get(&resource)
                .copied()
                .unwrap_or(0)
                .checked_add(amount)
                .ok_or_else(|| exceeded(resource, limit, "overflow", &owner))?;
            if value > limit {
                return Err(exceeded(resource, limit, value, &owner));
            }
        }
        Ok(())
    }
    pub fn accepts_owner(&self, owner: &BudgetPool) -> MddResult<bool> {
        if !Arc::ptr_eq(&self.state, &owner.state) {
            return Ok(false);
        }
        let state = self.lock()?;
        Ok(Self::ancestors(&state, &self.owner).contains(&owner.owner))
    }
    fn ancestors(state: &State, owner: &str) -> Vec<String> {
        let mut keys = Vec::new();
        let mut next = Some(owner.to_owned());
        while let Some(key) = next {
            next = state.nodes[&key].parent.clone();
            keys.push(key);
        }
        keys
    }
    fn add(state: &mut State, owner: &str, resource: Resource, amount: u64) -> MddResult<()> {
        let charges = if resource.physical_memory() {
            vec![(resource, amount), (Resource::ResidentBytes, amount)]
        } else {
            vec![(resource, amount)]
        };
        let ancestors = Self::ancestors(state, owner);
        let mut totals = Vec::new();
        for key in &ancestors {
            let node = &state.nodes[key];
            for (resource, amount) in &charges {
                let value = node
                    .used
                    .get(resource)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(*amount);
                let limit = node.limits.limit(*resource);
                let value = value.ok_or_else(|| exceeded(*resource, limit, "overflow", key))?;
                if value > limit {
                    return Err(exceeded(*resource, limit, value, key));
                }
                totals.push((key.clone(), *resource, value));
            }
        }
        for (key, resource, total) in totals {
            state
                .nodes
                .get_mut(&key)
                .unwrap()
                .used
                .insert(resource, total);
        }
        Ok(())
    }
    pub fn charge(&self, resource: Resource, amount: u64) -> MddResult<()> {
        self.checkpoint()?;
        if resource.resident() || resource == Resource::MemberUncompressedBytes {
            return Err(invalid("resource requires reservation or per-member check"));
        }
        let mut state = self.lock()?;
        Self::add(&mut state, &self.owner, resource, amount)
    }
    pub fn admit(&self, resource: Resource, maximum: u64) -> MddResult<Admission> {
        self.charge(resource, maximum)?;
        Ok(Admission {
            pool: self.clone(),
            resource,
            maximum,
        })
    }
    pub fn reserve(&self, resource: Resource, amount: u64) -> MddResult<Reservation> {
        self.reserve_inner(resource, amount, None, None)
    }
    pub fn reserve_arc<T: ?Sized + Send + Sync + 'static>(
        &self,
        allocation: &Arc<T>,
        resource: Resource,
        amount: u64,
    ) -> MddResult<Reservation> {
        let key = format!("arc:{:p}", Arc::as_ptr(allocation));
        self.reserve_inner(
            resource,
            amount,
            Some(key),
            Some(Box::new(Arc::clone(allocation))),
        )
    }
    fn reserve_inner(
        &self,
        resource: Resource,
        amount: u64,
        allocation: Option<String>,
        keeper: Option<Box<dyn KeepAlive>>,
    ) -> MddResult<Reservation> {
        self.checkpoint()?;
        if !resource.resident() {
            return Err(invalid("resource is cumulative, not resident"));
        }
        let mut state = self.lock()?;
        let shared_key = allocation.map(|key| (self.owner.clone(), key, resource));
        if let Some(key) = &shared_key
            && let Some(existing) = state.shared.get(key).and_then(|v| v.weak.upgrade())
        {
            if existing.amount != amount {
                return Err(invalid("shared allocation size changed"));
            }
            return Ok(Reservation(existing));
        }
        let ticket = state.next;
        if state.live_reservations >= 10000 {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "budget",
                "live reservation metadata capacity exhausted",
            )
            .detail("budget", "live_reservations")
            .detail("limit", "10000")
            .detail("observed", (state.live_reservations + 1).to_string()));
        }
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| fault("reservation ticket overflow"))?;
        Self::add(&mut state, &self.owner, resource, amount)?;
        state.live_reservations += 1;
        let value = Arc::new(ReservationInner {
            pool: self.clone(),
            resource,
            amount,
            ticket,
            shared_key: shared_key.clone(),
            _allocation: keeper,
        });
        if let Some(key) = shared_key {
            state.shared.insert(
                key,
                Shared {
                    ticket,
                    weak: Arc::downgrade(&value),
                },
            );
        }
        Ok(Reservation(value))
    }
    pub fn usage(&self) -> MddResult<BudgetUsage> {
        let state = self.lock()?;
        let node = &state.nodes[&self.owner];
        Ok(BudgetUsage {
            owner: self.owner.clone(),
            scope: node.scope,
            used: node
                .used
                .iter()
                .map(|(k, v)| (*k, DecimalU64(*v)))
                .collect(),
            effective_limits: node.limits.clone(),
        })
    }
}
/// A failed attempt conservatively retains its admitted maximum when exact consumed work is unknown.
pub struct Admission {
    pool: BudgetPool,
    resource: Resource,
    maximum: u64,
}
impl Admission {
    pub fn commit(self, actual: u64) -> MddResult<()> {
        if actual > self.maximum {
            return Err(fault("producer exceeded admitted cumulative upper bound"));
        }
        let mut state = self.pool.lock()?;
        release(&mut state, &self.pool, self.resource, self.maximum - actual)
    }
}
struct ReservationInner {
    pool: BudgetPool,
    resource: Resource,
    amount: u64,
    ticket: u64,
    shared_key: Option<(String, String, Resource)>,
    _allocation: Option<Box<dyn KeepAlive>>,
}
trait KeepAlive: Send + Sync {}
impl<T: Send + Sync> KeepAlive for T {}
fn release(state: &mut State, pool: &BudgetPool, resource: Resource, amount: u64) -> MddResult<()> {
    let resources = if resource.physical_memory() {
        vec![resource, Resource::ResidentBytes]
    } else {
        vec![resource]
    };
    let mut totals = Vec::new();
    for owner in BudgetPool::ancestors(state, &pool.owner) {
        for resource in &resources {
            let used = state.nodes[&owner].used.get(resource).copied().unwrap_or(0);
            let Some(remaining) = used.checked_sub(amount) else {
                let error = state
                    .fault
                    .get_or_insert_with(|| fault("reservation accounting underflow"));
                return Err(error.clone());
            };
            totals.push((owner.clone(), *resource, remaining));
        }
    }
    for (owner, resource, remaining) in totals {
        state
            .nodes
            .get_mut(&owner)
            .unwrap()
            .used
            .insert(resource, remaining);
    }
    Ok(())
}
impl Drop for ReservationInner {
    fn drop(&mut self) {
        if let Ok(mut state) = self.pool.state.lock() {
            if let Some(count) = state.live_reservations.checked_sub(1) {
                state.live_reservations = count;
            } else {
                state
                    .fault
                    .get_or_insert_with(|| fault("reservation metadata count underflow"));
            }
            if let Err(error) = release(&mut state, &self.pool, self.resource, self.amount) {
                state.fault.get_or_insert(error);
            }
            if let Some(key) = &self.shared_key
                && state
                    .shared
                    .get(key)
                    .is_some_and(|v| v.ticket == self.ticket)
            {
                state.shared.remove(key);
            }
        }
    }
}
#[derive(Clone)]
pub struct Reservation(Arc<ReservationInner>);
impl Reservation {
    pub fn amount(&self) -> u64 {
        self.0.amount
    }
    pub fn shrink(&mut self, amount: u64) -> MddResult<()> {
        let inner = Arc::get_mut(&mut self.0)
            .ok_or_else(|| invalid("cannot resize published/shared reservation"))?;
        if amount > inner.amount {
            return Err(invalid("cannot grow reservation via shrink"));
        }
        {
            let mut state = inner.pool.lock()?;
            release(
                &mut state,
                &inner.pool,
                inner.resource,
                inner.amount - amount,
            )?;
        }
        inner.amount = amount;
        Ok(())
    }
    pub fn borrow_for(&self, query: &BudgetPool) -> MddResult<Self> {
        // This is a per-object admission check. Physical bytes remain charged once to
        // the allocation owner; it does not claim query-total resident accounting.
        if !query.accepts_owner(&self.0.pool)? {
            return Err(invalid(
                "shared reservation belongs to another budget tree or non-ancestor owner",
            ));
        }
        query.check_individual(self.0.resource, self.0.amount)?;
        if self.0.resource.physical_memory() {
            query.check_individual(Resource::ResidentBytes, self.0.amount)?;
        }
        Ok(self.clone())
    }
}

#[derive(Clone)]
pub struct RuntimeBudget {
    pool: BudgetPool,
    cancel: QueryCancellation,
}
impl RuntimeBudget {
    pub fn new(pool: BudgetPool, cancel: QueryCancellation) -> MddResult<Self> {
        let session = cancel.session_id()?;
        let worker = cancel.worker_owner_id()?;
        let state = pool.lock()?;
        let ancestors = BudgetPool::ancestors(&state, &pool.owner);
        if state.nodes[&pool.owner].scope != BudgetScope::Query
            || pool.owner != cancel.query_handle().id()
            || !ancestors
                .iter()
                .any(|owner| state.nodes[owner].scope == BudgetScope::Session && *owner == session)
            || !ancestors
                .iter()
                .any(|owner| state.nodes[owner].scope == BudgetScope::Worker && *owner == worker)
        {
            return Err(invalid("runtime budget/query owner mismatch"));
        }
        drop(state);
        Ok(Self { pool, cancel })
    }
    pub fn pool(&self) -> &BudgetPool {
        &self.pool
    }
    pub fn cancellation(&self) -> &QueryCancellation {
        &self.cancel
    }
    pub fn stop(&self, error: MddError) -> MddError {
        match self.cancel.fail(error.clone()) {
            Ok(status) => status.error.unwrap_or(error),
            Err(failure) => failure,
        }
    }
    pub fn checkpoint(&self) -> MddResult<()> {
        let deadline = self
            .pool
            .delivery_deadline()
            .map_err(|error| self.stop(error))?;
        self.cancel.checkpoint_with_budget(&deadline)
    }
    pub fn charge(&self, resource: Resource, amount: u64) -> MddResult<()> {
        self.checkpoint()?;
        self.pool
            .charge(resource, amount)
            .map_err(|error| self.stop(error))
    }
}

pub struct Budgeted<T> {
    payload: T,
    _memory: Reservation,
    acknowledgement: Option<PacketAcknowledgement>,
}
impl<T> Budgeted<T> {
    pub fn payload(&self) -> &T {
        &self.payload
    }
    /// Confirm this packet only after the consumer has processed its payload.
    pub fn acknowledge(mut self) -> MddResult<()> {
        let mut ack = self
            .acknowledgement
            .take()
            .ok_or_else(|| invalid("queue has no query-bound delivery tracking"))?;
        let mut state = match ack.tracker.state.lock() {
            Ok(state) => state,
            Err(_) => {
                let error = fault("delivery tracking mutex poisoned");
                return Err(match ack.tracker.cancel.fail(error.clone()) {
                    Ok(status) => status.error.unwrap_or(error),
                    Err(failure) => failure,
                });
            }
        };
        if state.abandoned || ack.sequence != state.acknowledged {
            state.abandoned = true;
            drop(state);
            let error = invalid("delivery acknowledgement out of order or abandoned");
            let _ = ack.tracker.cancel.fail(error.clone());
            return Err(error);
        }
        let Some(next) = state.acknowledged.checked_add(1) else {
            drop(state);
            let error = fault("delivery acknowledgement overflow");
            return Err(match ack.tracker.cancel.fail(error.clone()) {
                Ok(status) => status.error.unwrap_or(error),
                Err(failure) => failure,
            });
        };
        state.acknowledged = next;
        ack.confirmed = true;
        Ok(())
    }
}
struct DeliveryState {
    sent: u64,
    acknowledged: u64,
    end_seen: bool,
    end_error: Option<MddError>,
    abandoned: bool,
}
pub(crate) struct DeliveryTracker {
    state: Mutex<DeliveryState>,
    cancel: QueryCancellation,
    cursor: mdd_session::CursorHandle,
}
struct PacketAcknowledgement {
    tracker: Arc<DeliveryTracker>,
    sequence: u64,
    confirmed: bool,
}
impl Drop for PacketAcknowledgement {
    fn drop(&mut self) {
        if !self.confirmed {
            if let Ok(mut state) = self.tracker.state.lock() {
                state.abandoned = true;
            }
            let _ = self
                .tracker
                .cancel
                .abandon_delivery_cursor(&self.tracker.cursor);
            let _ = self.tracker.cancel.fail(MddError::new(
                ErrorCode::Cancelled,
                "queue.delivery",
                "consumer dropped an unacknowledged packet",
            ));
        }
    }
}
struct Entry<T> {
    packet: Budgeted<T>,
    _queued: Reservation,
    _item: Reservation,
}
struct QueueState<T> {
    entries: VecDeque<Entry<T>>,
    terminal: Option<MddResult<()>>,
    senders: usize,
    bound_sends_in_flight: usize,
    bound_producer_active: bool,
    receiver_closed: bool,
    end_delivered: bool,
    receipt_issued: bool,
}
struct Channel<T> {
    state: Mutex<QueueState<T>>,
    changed: Condvar,
    pool: BudgetPool,
    cancel: Option<QueryCancellation>,
    capacity: usize,
    delivery: Option<Arc<DeliveryTracker>>,
}
struct BoundSendGuard<T> {
    channel: Arc<Channel<T>>,
}
/// Exclusive query producer capability. Its fields are private so only the
/// queue can issue or complete it; dropping an armed lease fails the query.
pub(crate) struct BoundProducerLease<T> {
    channel: Arc<Channel<T>>,
    active: bool,
    armed: bool,
}
pub struct BoundedSender<T>(Arc<Channel<T>>);
pub struct BoundedReceiver<T>(Arc<Channel<T>>);
pub enum QueueEvent<T> {
    Data(Budgeted<T>),
    End(MddResult<()>),
}
pub fn bounded_channel<T>(
    pool: BudgetPool,
    cancel: Option<QueryCancellation>,
    capacity: usize,
) -> MddResult<(BoundedSender<T>, BoundedReceiver<T>)> {
    if capacity == 0 {
        return Err(invalid("invalid queue capacity"));
    }
    let max = pool.limit(Resource::QueueItems)?;
    if capacity as u64 > max {
        return Err(exceeded(Resource::QueueItems, max, capacity, &pool.owner));
    }
    let delivery = if let Some(token) = &cancel {
        RuntimeBudget::new(pool.clone(), token.clone())?;
        let cursor = token.open_delivery_cursor()?;
        Some(Arc::new(DeliveryTracker {
            state: Mutex::new(DeliveryState {
                sent: 0,
                acknowledged: 0,
                end_seen: false,
                end_error: None,
                abandoned: false,
            }),
            cancel: token.clone(),
            cursor,
        }))
    } else {
        None
    };
    let channel = Arc::new(Channel {
        state: Mutex::new(QueueState {
            entries: VecDeque::new(),
            terminal: None,
            senders: 1,
            bound_sends_in_flight: 0,
            bound_producer_active: false,
            receiver_closed: false,
            end_delivered: false,
            receipt_issued: false,
        }),
        changed: Condvar::new(),
        pool,
        cancel,
        capacity,
        delivery,
    });
    Ok((
        BoundedSender(Arc::clone(&channel)),
        BoundedReceiver(channel),
    ))
}
impl<T> Channel<T> {
    fn checkpoint(&self) -> MddResult<()> {
        if let Some(cancel) = &self.cancel {
            let deadline = self
                .pool
                .delivery_deadline()
                .map_err(|error| self.bound_query_failure(error))?;
            cancel.checkpoint_with_budget(&deadline)
        } else {
            self.pool.checkpoint()
        }
    }
    fn protocol_fault(&self, error: MddError) -> MddError {
        if let Some(tracker) = &self.delivery {
            if let Ok(mut state) = tracker.state.lock() {
                state.abandoned = true;
            }
            let _ = tracker.cancel.fail(error.clone());
        }
        error
    }
    fn bound_query_failure(&self, error: MddError) -> MddError {
        match &self.cancel {
            Some(cancel) => match cancel.fail(error.clone()) {
                Ok(status) => status.error.unwrap_or(error),
                Err(failure) => failure,
            },
            None => error,
        }
    }
    fn bound_send_failure(&self, error: MddError) -> MddError {
        let Some(cancel) = &self.cancel else {
            return error;
        };
        // Serialize against finish(): a bound queue must not publish an Ok End
        // after an unrecoverable send error. Preserve an earlier error terminal.
        let mut queue = match self.state.lock() {
            Ok(queue) => queue,
            Err(_) => {
                return match cancel.fail(error.clone()) {
                    Ok(status) => status.error.unwrap_or(error),
                    Err(failure) => failure,
                };
            }
        };
        let candidate = match queue.terminal.as_ref() {
            Some(Err(previous)) => previous.clone(),
            _ => error,
        };
        let first = match cancel.fail(candidate.clone()) {
            Ok(status) => status.error.unwrap_or(candidate),
            Err(failure) => failure,
        };
        if !queue.end_delivered && !queue.receiver_closed {
            queue.terminal = Some(Err(first.clone()));
            self.changed.notify_all();
        }
        first
    }
}
impl<T> Drop for BoundSendGuard<T> {
    fn drop(&mut self) {
        let failure = match self.channel.state.lock() {
            Ok(mut queue) => match queue.bound_sends_in_flight.checked_sub(1) {
                Some(remaining) => {
                    queue.bound_sends_in_flight = remaining;
                    self.channel.changed.notify_all();
                    None
                }
                None => Some(fault("bound send count underflow")),
            },
            Err(_) => Some(fault("queue mutex poisoned")),
        };
        if let Some(error) = failure {
            let _ = self.channel.bound_send_failure(error);
        }
    }
}
impl<T> BoundProducerLease<T> {
    pub(crate) fn arm(&mut self) {
        self.armed = true;
    }
}
impl<T> Drop for BoundProducerLease<T> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut queue = match self.channel.state.lock() {
            Ok(queue) => queue,
            Err(_) => {
                if self.armed {
                    let _ = self
                        .channel
                        .bound_query_failure(fault("queue mutex poisoned"));
                }
                return;
            }
        };
        queue.bound_producer_active = false;
        if self.armed {
            let error = match queue.terminal.as_ref() {
                Some(Err(previous)) => previous.clone(),
                _ => MddError::new(
                    ErrorCode::WorkerLost,
                    "queue.producer",
                    "query producer dropped before its terminal",
                ),
            };
            let first = self.channel.bound_query_failure(error);
            if !queue.end_delivered && !queue.receiver_closed {
                queue.terminal = Some(Err(first));
            }
        }
        self.channel.changed.notify_all();
    }
}
impl<T> BoundedSender<T> {
    pub(crate) fn claim_producer(&self) -> MddResult<BoundProducerLease<T>> {
        let tracker = self
            .0
            .delivery
            .as_ref()
            .ok_or_else(|| invalid("producer needs a bound queue"))?;
        let mut queue = self
            .0
            .state
            .lock()
            .map_err(|_| fault("queue mutex poisoned"))?;
        if queue.bound_producer_active
            || queue.bound_sends_in_flight != 0
            || queue.receiver_closed
            || queue.end_delivered
            || queue.terminal.is_some()
            || !queue.entries.is_empty()
        {
            return Err(invalid("bound queue is not available for a producer"));
        }
        let delivery = tracker
            .state
            .lock()
            .map_err(|_| fault("delivery tracking mutex poisoned"))?;
        if delivery.sent != 0
            || delivery.acknowledged != 0
            || delivery.end_seen
            || delivery.abandoned
        {
            return Err(invalid("bound queue has prior delivery state"));
        }
        drop(delivery);
        queue.bound_producer_active = true;
        Ok(BoundProducerLease {
            channel: Arc::clone(&self.0),
            active: true,
            armed: false,
        })
    }
    fn begin_bound_send(
        &self,
        producer: Option<&BoundProducerLease<T>>,
    ) -> MddResult<Option<BoundSendGuard<T>>> {
        if self.0.delivery.is_none() {
            return if producer.is_some() {
                Err(invalid("producer lease cannot use an unbound queue"))
            } else {
                Ok(None)
            };
        }
        let mut queue = self
            .0
            .state
            .lock()
            .map_err(|_| fault("queue mutex poisoned"))?;
        if queue.bound_producer_active {
            if !producer.is_some_and(|lease| {
                lease.active && lease.armed && Arc::ptr_eq(&lease.channel, &self.0)
            }) {
                return Err(invalid("bound queue has an exclusive producer"));
            }
        } else if producer.is_some() {
            return Err(invalid("bound producer lease is not active"));
        }
        queue.bound_sends_in_flight = queue
            .bound_sends_in_flight
            .checked_add(1)
            .ok_or_else(|| fault("bound send count overflow"))?;
        Ok(Some(BoundSendGuard {
            channel: Arc::clone(&self.0),
        }))
    }
    pub(crate) fn matches_runtime(&self, runtime: &RuntimeBudget) -> bool {
        self.0.delivery.as_ref().is_some_and(|tracker| {
            Arc::ptr_eq(&self.0.pool.state, &runtime.pool.state)
                && self.0.pool.owner == runtime.pool.owner
                && tracker.cancel.query_handle() == runtime.cancel.query_handle()
        })
    }
    pub fn try_clone(&self) -> MddResult<Self> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| fault("queue mutex poisoned"))?;
        state.senders = state
            .senders
            .checked_add(1)
            .ok_or_else(|| fault("sender count overflow"))?;
        Ok(Self(Arc::clone(&self.0)))
    }
    pub fn send(&self, payload: T, bytes: u64) -> MddResult<()> {
        let _send = match self.begin_bound_send(None) {
            Ok(guard) => guard,
            Err(error) if error.code == ErrorCode::InvalidArgument => return Err(error),
            Err(error) => return Err(self.0.bound_send_failure(error)),
        };
        self.send_with_resident_bytes(payload, bytes, bytes)
            .map_err(|error| self.0.bound_send_failure(error))
    }
    /// Queue occupancy and the owned payload's logical resident estimate are distinct.
    pub(crate) fn send_with_resident_bytes(
        &self,
        payload: T,
        wire_bytes: u64,
        resident_bytes: u64,
    ) -> MddResult<()> {
        self.0
            .pool
            .check_individual(Resource::QueueBytes, wire_bytes)?;
        let memory = self.reserve_payload(resident_bytes)?;
        self.send_reserved(payload, wire_bytes, memory)
    }
    pub(crate) fn reserve_payload(&self, resident_bytes: u64) -> MddResult<Reservation> {
        self.0
            .pool
            .check_individual(Resource::QueryWorkspaceBytes, resident_bytes)?;
        self.0
            .pool
            .reserve(Resource::QueryWorkspaceBytes, resident_bytes)
    }
    pub(crate) fn send_reserved(
        &self,
        payload: T,
        wire_bytes: u64,
        memory: Reservation,
    ) -> MddResult<()> {
        self.send_reserved_checked(payload, wire_bytes, memory, None)
    }
    pub(crate) fn send_reserved_produced(
        &self,
        payload: T,
        wire_bytes: u64,
        memory: Reservation,
        producer: &BoundProducerLease<T>,
    ) -> MddResult<()> {
        self.send_reserved_checked(payload, wire_bytes, memory, Some(producer))
    }
    fn send_reserved_checked(
        &self,
        payload: T,
        wire_bytes: u64,
        memory: Reservation,
        producer: Option<&BoundProducerLease<T>>,
    ) -> MddResult<()> {
        let _send = self.begin_bound_send(producer)?;
        self.send_reserved_inner(payload, wire_bytes, memory)
            .map_err(|error| self.0.bound_query_failure(error))
    }
    fn send_reserved_inner(
        &self,
        payload: T,
        wire_bytes: u64,
        memory: Reservation,
    ) -> MddResult<()> {
        self.0
            .pool
            .check_individual(Resource::QueueBytes, wire_bytes)?;
        if memory.0.resource != Resource::QueryWorkspaceBytes
            || !Arc::ptr_eq(&memory.0.pool.state, &self.0.pool.state)
            || memory.0.pool.owner != self.0.pool.owner
        {
            return Err(invalid("payload reservation belongs to another budget"));
        }
        // Pending senders own live payload memory even while there is no queue slot.
        let mut payload = Some(Budgeted {
            payload,
            _memory: memory,
            acknowledgement: None,
        });
        loop {
            self.0.checkpoint()?;
            let mut state = self
                .0
                .state
                .lock()
                .map_err(|_| fault("queue mutex poisoned"))?;
            if state.receiver_closed {
                return Err(MddError::new(
                    ErrorCode::Cancelled,
                    "queue",
                    "consumer closed before complete delivery",
                ));
            }
            if state.terminal.is_some() || state.end_delivered {
                drop(state);
                return Err(self.0.protocol_fault(invalid("send after terminal")));
            }
            if state.entries.len() < self.0.capacity {
                let reservations = (|| {
                    let queued = self.0.pool.reserve(Resource::QueueBytes, wire_bytes)?;
                    let item = self.0.pool.reserve(Resource::QueueItems, 1)?;
                    Ok::<_, MddError>((queued, item))
                })();
                match reservations {
                    Ok((queued, item)) => {
                        if let Some(tracker) = &self.0.delivery {
                            let mut delivery = tracker
                                .state
                                .lock()
                                .map_err(|_| fault("delivery tracking mutex poisoned"))?;
                            if delivery.abandoned {
                                return Err(invalid("delivery is abandoned"));
                            }
                            let sequence = delivery.sent;
                            delivery.sent = delivery
                                .sent
                                .checked_add(1)
                                .ok_or_else(|| fault("delivery packet count overflow"))?;
                            payload.as_mut().unwrap().acknowledgement =
                                Some(PacketAcknowledgement {
                                    tracker: Arc::clone(tracker),
                                    sequence,
                                    confirmed: false,
                                });
                        }
                        state.entries.push_back(Entry {
                            packet: payload.take().unwrap(),
                            _queued: queued,
                            _item: item,
                        });
                        self.0.changed.notify_all();
                        return Ok(());
                    }
                    Err(error) if error.code == ErrorCode::QuotaExceeded => (),
                    Err(error) => return Err(error),
                }
            }
            drop(
                self.0
                    .changed
                    .wait_timeout(state, Duration::from_millis(5))
                    .map_err(|_| fault("queue mutex poisoned"))?,
            );
        }
    }
    pub fn finish(&self, result: MddResult<()>) -> MddResult<()> {
        self.finish_checked(result, None)
    }
    pub(crate) fn finish_produced(
        &self,
        producer: &mut BoundProducerLease<T>,
        result: MddResult<()>,
    ) -> MddResult<()> {
        self.finish_checked(result, Some(producer))
    }
    fn finish_checked(
        &self,
        mut result: MddResult<()>,
        producer: Option<&mut BoundProducerLease<T>>,
    ) -> MddResult<()> {
        let owned = if let Some(lease) = producer.as_ref() {
            if !lease.active
                || !Arc::ptr_eq(&lease.channel, &self.0)
                || (result.is_ok() && !lease.armed)
            {
                return Err(invalid("producer lease does not own this queue"));
            }
            true
        } else {
            false
        };
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| fault("queue mutex poisoned"))?;
        if state.terminal.is_some() || state.end_delivered {
            drop(state);
            return Err(self.0.protocol_fault(invalid("duplicate queue terminal")));
        }
        if state.receiver_closed {
            return Err(MddError::new(
                ErrorCode::Cancelled,
                "queue",
                "consumer closed",
            ));
        }
        if owned && !state.bound_producer_active {
            return Err(invalid("bound producer lease is not active"));
        }
        if state.bound_producer_active && !owned && result.is_ok() {
            return Err(invalid("bound queue has an active producer"));
        }
        if self.0.delivery.is_some() && result.is_ok() && state.bound_sends_in_flight != 0 {
            return Err(invalid("bound queue has sends in flight"));
        }
        if result.is_ok()
            && let Err(error) = self.0.checkpoint()
        {
            // An owned producer still needs to publish its explicit error End
            // and construct the corresponding failure envelope. External
            // senders have no producer lease, so publish their error here.
            if !owned {
                state.terminal = Some(Err(error.clone()));
                self.0.changed.notify_all();
            }
            return Err(error);
        }
        if let (Some(cancel), Err(error)) = (&self.0.cancel, &result) {
            let status = cancel.fail(error.clone())?;
            result = Err(status.error.unwrap_or_else(|| error.clone()));
        }
        state.terminal = Some(result);
        if let Some(lease) = producer {
            state.bound_producer_active = false;
            lease.active = false;
        }
        self.0.changed.notify_all();
        Ok(())
    }
}
impl<T> Drop for BoundedSender<T> {
    fn drop(&mut self) {
        let mut lost = None;
        if let Ok(mut state) = self.0.state.lock() {
            state.senders -= 1;
            if state.senders == 0 && state.terminal.is_none() && !state.end_delivered {
                let error = MddError::new(
                    ErrorCode::WorkerLost,
                    "queue",
                    "producer dropped without terminal",
                );
                state.terminal = Some(Err(error.clone()));
                lost = Some(error);
            }
            self.0.changed.notify_all();
        }
        if let (Some(cancel), Some(error)) = (&self.0.cancel, lost) {
            let _ = cancel.fail(error);
        }
    }
}
impl<T> BoundedReceiver<T> {
    pub fn receive(&mut self) -> MddResult<QueueEvent<T>> {
        loop {
            let mut state = self
                .0
                .state
                .lock()
                .map_err(|_| fault("queue mutex poisoned"))?;
            if let Some(entry) = state.entries.pop_front() {
                self.0.changed.notify_all();
                return Ok(QueueEvent::Data(entry.packet));
            }
            if state.end_delivered {
                drop(state);
                return Err(self.0.protocol_fault(invalid("read after queue terminal")));
            }
            if let Some(mut end) = state.terminal.take() {
                // An unbound queue has no later delivery receipt at which to
                // recheck its budget. Confirm the deadline when the consumer
                // actually receives a successful End, while retaining any
                // error already published by the producer. Bound queues use
                // their query receipt for the final delivery decision.
                if end.is_ok()
                    && self.0.delivery.is_none()
                    && let Err(error) = self.0.checkpoint()
                {
                    end = Err(error);
                }
                state.end_delivered = true;
                if let Some(tracker) = &self.0.delivery {
                    let mut delivery = tracker.state.lock().map_err(|_| {
                        self.0
                            .bound_query_failure(fault("delivery tracking mutex poisoned"))
                    })?;
                    delivery.end_seen = true;
                    delivery.end_error = end.as_ref().err().cloned();
                }
                return Ok(QueueEvent::End(end));
            }
            drop(state);
            self.0.checkpoint()?;
            let state = self
                .0
                .state
                .lock()
                .map_err(|_| fault("queue mutex poisoned"))?;
            drop(
                self.0
                    .changed
                    .wait_timeout(state, Duration::from_millis(5))
                    .map_err(|_| fault("queue mutex poisoned"))?,
            );
        }
    }
}
impl<T> Drop for BoundedReceiver<T> {
    fn drop(&mut self) {
        let mut receipt_issued = false;
        if let Ok(mut state) = self.0.state.lock() {
            state.receiver_closed = true;
            state.entries.clear();
            receipt_issued = state.receipt_issued;
            self.0.changed.notify_all();
        }
        if !receipt_issued
            && let Some(cancel) = &self.0.cancel
            && !cancel.status().is_ok_and(|s| s.delivery_complete)
        {
            if let Some(tracker) = &self.0.delivery {
                if let Ok(mut state) = tracker.state.lock() {
                    state.abandoned = true;
                }
                let _ = cancel.abandon_delivery_cursor(&tracker.cursor);
            }
            let _ = cancel.cancel();
        }
    }
}

/// Proof can only be obtained from the bound receiver after explicit End and every packet ack.
pub struct QueueDeliveryReceipt {
    pub(crate) tracker: Arc<DeliveryTracker>,
    consumed: bool,
}
impl<T> BoundedReceiver<T> {
    pub fn into_delivery_receipt(self) -> MddResult<QueueDeliveryReceipt> {
        let tracker = self
            .0
            .delivery
            .as_ref()
            .ok_or_else(|| invalid("unbound queue cannot confirm query delivery"))?
            .clone();
        {
            let mut queue = self
                .0
                .state
                .lock()
                .map_err(|_| fault("queue mutex poisoned"))?;
            let state = tracker.state.lock().map_err(|_| {
                self.0
                    .bound_query_failure(fault("delivery tracking mutex poisoned"))
            })?;
            if !state.end_seen
                || state.abandoned
                || state.sent != state.acknowledged
                || !queue.entries.is_empty()
                || queue.receipt_issued
            {
                return Err(invalid(
                    "queue delivery requires acknowledged packets and explicit End",
                ));
            }
            queue.receipt_issued = true;
        }
        Ok(QueueDeliveryReceipt {
            tracker,
            consumed: false,
        })
    }
}
impl QueueDeliveryReceipt {
    pub(crate) fn matches<T>(
        &self,
        sender: &BoundedSender<T>,
        runtime: &RuntimeBudget,
        expected: u64,
        error: Option<&MddError>,
    ) -> MddResult<bool> {
        let Some(other) = &sender.0.delivery else {
            return Ok(false);
        };
        let state = self
            .tracker
            .state
            .lock()
            .map_err(|_| fault("delivery tracking mutex poisoned"))?;
        let same_error = match (state.end_error.as_ref(), error) {
            (None, None) => true,
            (Some(actual), Some(expected)) => {
                actual.code == expected.code
                    && actual.stage == expected.stage
                    && actual.message == expected.message
                    && actual.retryable == expected.retryable
                    && actual.details == expected.details
            }
            _ => false,
        };
        Ok(!self.consumed
            && Arc::ptr_eq(&self.tracker, other)
            && Arc::ptr_eq(&sender.0.pool.state, &runtime.pool.state)
            && sender.0.pool.owner == runtime.pool.owner
            && self.tracker.cancel.query_handle() == runtime.cancel.query_handle()
            && state.end_seen
            && !state.abandoned
            && state.sent == expected
            && state.acknowledged == expected
            && same_error)
    }
    #[cfg(test)]
    pub(crate) fn finish_cursor(&mut self) -> MddResult<()> {
        self.tracker
            .cancel
            .finish_delivery_cursor(&self.tracker.cursor)?;
        self.consumed = true;
        Ok(())
    }
    pub(crate) fn finish_cursor_with_budget(
        &mut self,
        deadline: &DeliveryBudgetDeadline,
    ) -> MddResult<()> {
        self.tracker
            .cancel
            .finish_delivery_cursor_with_budget(&self.tracker.cursor, deadline)?;
        self.consumed = true;
        Ok(())
    }
    pub(crate) fn finish_failed(&mut self) -> MddResult<()> {
        self.tracker
            .cancel
            .abandon_delivery_cursor(&self.tracker.cursor)?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for QueueDeliveryReceipt {
    fn drop(&mut self) {
        if !self.consumed {
            let _ = self
                .tracker
                .cancel
                .abandon_delivery_cursor(&self.tracker.cursor);
            let _ = self.tracker.cancel.cancel();
        }
    }
}
