//! Generation-tagged handles.
//!
//! A handle is a 64-bit value, not an address: `kind (8) | generation (32) | index (24)`.
//! Every use is checked against the table, so a forged, stale, already released or
//! wrong-kind handle yields `INVALID_HANDLE` instead of touching memory. The slot of
//! a released handle is reused with a higher generation, so an old value cannot
//! reach the new occupant. Zero is never a valid handle.
//!
//! Objects are `Arc`s. Taking one out of the table clones the `Arc` under the lock
//! and uses it after the lock is gone, so a long call never holds the table and a
//! concurrent release cannot free an object that a call is still using.
use crate::{
    engine::{BatchObj, PreparedObj, QueryObj, SessionObj, SnapshotObj, TerminalObj},
    error::{SdkError, SdkResult},
};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Snapshot = 1,
    Session = 2,
    Prepared = 3,
    Query = 4,
    Event = 5,
    Batch = 6,
    Error = 7,
}

impl Kind {
    fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits {
            1 => Self::Snapshot,
            2 => Self::Session,
            3 => Self::Prepared,
            4 => Self::Query,
            5 => Self::Event,
            6 => Self::Batch,
            7 => Self::Error,
            _ => return None,
        })
    }
}

/// What an event carries. A batch event owns one reference to its batch, taken when
/// the event is created and dropped when the event is.
pub enum EventKind {
    Batch(u64),
    Terminal(Arc<TerminalObj>),
}

pub struct EventObj {
    pub kind: EventKind,
}

impl Drop for EventObj {
    fn drop(&mut self) {
        if let EventKind::Batch(handle) = self.kind {
            let _ = registry().release_pinned(handle, Kind::Batch);
        }
    }
}

pub struct ErrorObj {
    pub status: u32,
    pub json: String,
}

#[derive(Clone)]
enum Object {
    Snapshot(Arc<SnapshotObj>),
    Session(Arc<SessionObj>),
    Prepared(Arc<PreparedObj>),
    Query(Arc<QueryObj>),
    Event(Arc<EventObj>),
    Batch(Arc<BatchObj>),
    Error(Arc<ErrorObj>),
}

struct Entry {
    object: Object,
    refs: u32,
    /// References held by the library itself (an event holds its batch). The caller can
    /// release only what it retained on top of these.
    pinned: u32,
}

struct Slot {
    generation: u32,
    entry: Option<Entry>,
}

#[derive(Default)]
struct Table {
    slots: Vec<Slot>,
    free: Vec<u32>,
}

const INDEX_BITS: u32 = 24;
const MAX_SLOTS: usize = (1 << INDEX_BITS) - 1;

fn encode(kind: Kind, generation: u32, index: u32) -> u64 {
    (u64::from(kind as u8) << 56) | (u64::from(generation) << INDEX_BITS) | u64::from(index)
}

fn decode(handle: u64) -> Option<(Kind, u32, u32)> {
    let kind = Kind::from_bits(u8::try_from(handle >> 56).ok()?)?;
    let generation = u32::try_from((handle >> INDEX_BITS) & 0xFFFF_FFFF).ok()?;
    let index = u32::try_from(handle & ((1 << INDEX_BITS) - 1)).ok()?;
    Some((kind, generation, index))
}

fn kind_of(object: &Object) -> Kind {
    match object {
        Object::Snapshot(_) => Kind::Snapshot,
        Object::Session(_) => Kind::Session,
        Object::Prepared(_) => Kind::Prepared,
        Object::Query(_) => Kind::Query,
        Object::Event(_) => Kind::Event,
        Object::Batch(_) => Kind::Batch,
        Object::Error(_) => Kind::Error,
    }
}

pub struct Registry {
    table: Mutex<Table>,
}

pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        table: Mutex::new(Table::default()),
    })
}

fn stale(kind: Kind) -> SdkError {
    SdkError::handle(format!("not a live {kind:?} handle"))
}

impl Registry {
    fn insert(&self, object: Object) -> SdkResult<u64> {
        let kind = kind_of(&object);
        let mut table = self
            .table
            .lock()
            .map_err(|_| SdkError::fault("handle table poisoned"))?;
        let index = match table.free.pop() {
            Some(index) => index,
            None => {
                if table.slots.len() >= MAX_SLOTS {
                    return Err(SdkError::new(
                        crate::error::Status::QuotaExceeded,
                        "QUOTA_EXCEEDED",
                        "ffi",
                        "too many live handles",
                    ));
                }
                table.slots.push(Slot {
                    generation: 0,
                    entry: None,
                });
                u32::try_from(table.slots.len() - 1)
                    .map_err(|_| SdkError::fault("handle index overflow"))?
            }
        };
        let slot = &mut table.slots[index as usize];
        // Generation zero is never issued, so a zeroed value cannot match a slot.
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.entry = Some(Entry {
            object,
            refs: 1,
            pinned: 0,
        });
        Ok(encode(kind, slot.generation, index))
    }

    fn lookup(&self, handle: u64, want: Kind) -> SdkResult<Object> {
        let (kind, generation, index) = decode(handle).ok_or_else(|| stale(want))?;
        if kind != want {
            return Err(stale(want));
        }
        let table = self
            .table
            .lock()
            .map_err(|_| SdkError::fault("handle table poisoned"))?;
        let slot = table.slots.get(index as usize).ok_or_else(|| stale(want))?;
        match &slot.entry {
            Some(entry) if slot.generation == generation => Ok(entry.object.clone()),
            _ => Err(stale(want)),
        }
    }

    pub fn retain(&self, handle: u64, want: Kind) -> SdkResult<()> {
        let (kind, generation, index) = decode(handle).ok_or_else(|| stale(want))?;
        if kind != want {
            return Err(stale(want));
        }
        let mut table = self
            .table
            .lock()
            .map_err(|_| SdkError::fault("handle table poisoned"))?;
        let slot = table
            .slots
            .get_mut(index as usize)
            .ok_or_else(|| stale(want))?;
        match &mut slot.entry {
            Some(entry) if slot.generation == generation => {
                entry.refs = entry
                    .refs
                    .checked_add(1)
                    .ok_or_else(|| SdkError::fault("reference count overflow"))?;
                Ok(())
            }
            _ => Err(stale(want)),
        }
    }

    /// Mark the one reference a new object starts with as the library's own. From then
    /// on the caller's `release` is refused until the caller has retained its own.
    pub fn pin(&self, handle: u64, want: Kind) -> SdkResult<()> {
        let (kind, generation, index) = decode(handle).ok_or_else(|| stale(want))?;
        if kind != want {
            return Err(stale(want));
        }
        let mut table = self
            .table
            .lock()
            .map_err(|_| SdkError::fault("handle table poisoned"))?;
        let slot = table
            .slots
            .get_mut(index as usize)
            .ok_or_else(|| stale(want))?;
        match &mut slot.entry {
            Some(entry) if slot.generation == generation => {
                entry.pinned += 1;
                Ok(())
            }
            _ => Err(stale(want)),
        }
    }

    /// The caller's release: refused while only the library's own references remain.
    pub fn release(&self, handle: u64, want: Kind) -> SdkResult<()> {
        self.release_ref(handle, want, false)
    }

    /// The library giving back a reference it pinned.
    pub fn release_pinned(&self, handle: u64, want: Kind) -> SdkResult<()> {
        self.release_ref(handle, want, true)
    }

    /// Drop one reference. The object is destroyed, outside the table lock, when the
    /// last one goes. A second release of the same handle is `INVALID_HANDLE`.
    fn release_ref(&self, handle: u64, want: Kind, internal: bool) -> SdkResult<()> {
        let (kind, generation, index) = decode(handle).ok_or_else(|| stale(want))?;
        if kind != want {
            return Err(stale(want));
        }
        let removed = {
            let mut table = self
                .table
                .lock()
                .map_err(|_| SdkError::fault("handle table poisoned"))?;
            let slot = table
                .slots
                .get_mut(index as usize)
                .ok_or_else(|| stale(want))?;
            let gone = match &mut slot.entry {
                Some(entry) if slot.generation == generation => {
                    if internal {
                        entry.pinned = entry.pinned.saturating_sub(1);
                    } else if entry.refs <= entry.pinned {
                        return Err(SdkError::handle(
                            "this handle is borrowed from its event; retain it before releasing it",
                        ));
                    }
                    entry.refs -= 1;
                    entry.refs == 0
                }
                _ => return Err(stale(want)),
            };
            if gone {
                let entry = slot.entry.take();
                table.free.push(index);
                entry
            } else {
                None
            }
        };
        drop(removed);
        Ok(())
    }

    pub fn live_handles(&self) -> usize {
        self.table
            .lock()
            .map(|table| {
                table
                    .slots
                    .iter()
                    .filter(|slot| slot.entry.is_some())
                    .count()
            })
            .unwrap_or(usize::MAX)
    }

    pub fn insert_snapshot(&self, object: Arc<SnapshotObj>) -> SdkResult<u64> {
        self.insert(Object::Snapshot(object))
    }

    pub fn insert_session(&self, object: Arc<SessionObj>) -> SdkResult<u64> {
        self.insert(Object::Session(object))
    }

    pub fn insert_prepared(&self, object: Arc<PreparedObj>) -> SdkResult<u64> {
        self.insert(Object::Prepared(object))
    }

    pub fn insert_query(&self, object: Arc<QueryObj>) -> SdkResult<u64> {
        self.insert(Object::Query(object))
    }

    pub fn insert_event(&self, object: Arc<EventObj>) -> SdkResult<u64> {
        self.insert(Object::Event(object))
    }

    pub fn insert_batch(&self, object: Arc<BatchObj>) -> SdkResult<u64> {
        self.insert(Object::Batch(object))
    }

    pub fn insert_error(&self, object: Arc<ErrorObj>) -> SdkResult<u64> {
        self.insert(Object::Error(object))
    }

    pub fn snapshot(&self, handle: u64) -> SdkResult<Arc<SnapshotObj>> {
        match self.lookup(handle, Kind::Snapshot)? {
            Object::Snapshot(object) => Ok(object),
            _ => Err(stale(Kind::Snapshot)),
        }
    }

    pub fn session(&self, handle: u64) -> SdkResult<Arc<SessionObj>> {
        match self.lookup(handle, Kind::Session)? {
            Object::Session(object) => Ok(object),
            _ => Err(stale(Kind::Session)),
        }
    }

    pub fn prepared(&self, handle: u64) -> SdkResult<Arc<PreparedObj>> {
        match self.lookup(handle, Kind::Prepared)? {
            Object::Prepared(object) => Ok(object),
            _ => Err(stale(Kind::Prepared)),
        }
    }

    pub fn query(&self, handle: u64) -> SdkResult<Arc<QueryObj>> {
        match self.lookup(handle, Kind::Query)? {
            Object::Query(object) => Ok(object),
            _ => Err(stale(Kind::Query)),
        }
    }

    pub fn event(&self, handle: u64) -> SdkResult<Arc<EventObj>> {
        match self.lookup(handle, Kind::Event)? {
            Object::Event(object) => Ok(object),
            _ => Err(stale(Kind::Event)),
        }
    }

    pub fn batch(&self, handle: u64) -> SdkResult<Arc<BatchObj>> {
        match self.lookup(handle, Kind::Batch)? {
            Object::Batch(object) => Ok(object),
            _ => Err(stale(Kind::Batch)),
        }
    }

    pub fn error(&self, handle: u64) -> SdkResult<Arc<ErrorObj>> {
        match self.lookup(handle, Kind::Error)? {
            Object::Error(object) => Ok(object),
            _ => Err(stale(Kind::Error)),
        }
    }
}
