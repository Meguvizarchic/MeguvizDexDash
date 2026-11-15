//! ABI status codes and the structured error behind them.
//!
//! Every exported function returns a `u32` status. Zero is success; anything else
//! is one of the stable values below, and the call also yields an error object that
//! carries the exact engine code (`QUOTA_EXCEEDED`, ...), the stage, a message and
//! detail fields. The numeric status is for branching in C; the string code is for
//! logs and for the Python exception class. A successful call is not a successful
//! query: the verdict of a query is in its terminal envelope.
use mdd_types::{ErrorCode, MddError};
use serde_json::{Map, Value, json};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Ok = 0,
    InvalidArgument = 1,
    /// Forged, stale, already released or wrong-kind handle.
    InvalidHandle = 2,
    Closed = 3,
    /// Another thread is inside `next` on the same query.
    Busy = 4,
    /// The previous batch has not been acknowledged and fully released.
    OutstandingBatch = 5,
    Cancelled = 6,
    DeadlineExceeded = 7,
    QuotaExceeded = 8,
    Unsupported = 9,
    IncompleteFacts = 10,
    InvalidInput = 11,
    AbiMismatch = 12,
    InternalFault = 13,
}

/// Maps the engine's error codes onto the stable ABI statuses. The exact engine
/// code always travels in the error object, so this table may be coarser.
pub fn status_for(code: &ErrorCode) -> Status {
    match code {
        ErrorCode::UnsupportedCapability | ErrorCode::UnsupportedQuery => Status::Unsupported,
        ErrorCode::InvalidArgument | ErrorCode::InvalidCursor | ErrorCode::AmbiguousEntity => {
            Status::InvalidArgument
        }
        ErrorCode::InvalidInput | ErrorCode::PartialInput | ErrorCode::SourceChanged => {
            Status::InvalidInput
        }
        ErrorCode::IncompleteFacts => Status::IncompleteFacts,
        ErrorCode::QuotaExceeded => Status::QuotaExceeded,
        ErrorCode::DeadlineExceeded => Status::DeadlineExceeded,
        ErrorCode::Cancelled => Status::Cancelled,
        ErrorCode::SnapshotClosed => Status::Closed,
        ErrorCode::UnavailableBackend
        | ErrorCode::StaleCache
        | ErrorCode::CacheCorrupt
        | ErrorCode::InternalFault
        | ErrorCode::WorkerLost => Status::InternalFault,
    }
}

#[derive(Clone, Debug)]
pub struct SdkError {
    pub status: Status,
    /// Exact engine code, or an ABI-level code such as `INVALID_HANDLE`.
    pub code: String,
    pub stage: String,
    pub message: String,
    pub retryable: bool,
    pub details: Map<String, Value>,
}

impl SdkError {
    pub fn new(status: Status, code: &str, stage: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.to_owned(),
            stage: stage.to_owned(),
            message: message.into(),
            retryable: false,
            details: Map::new(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(Status::InvalidArgument, "INVALID_ARGUMENT", "ffi", message)
    }

    pub fn handle(message: impl Into<String>) -> Self {
        Self::new(Status::InvalidHandle, "INVALID_HANDLE", "ffi", message)
    }

    pub fn closed(what: &str) -> Self {
        Self::new(
            Status::Closed,
            "SNAPSHOT_CLOSED",
            "ffi",
            format!("the {what} is closed"),
        )
    }

    pub fn fault(message: impl Into<String>) -> Self {
        Self::new(Status::InternalFault, "INTERNAL_FAULT", "ffi", message)
    }

    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_owned(), value.into());
        self
    }

    pub fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    pub fn to_json(&self) -> String {
        json!({
            "status": self.status as u32,
            "code": self.code,
            "stage": self.stage,
            "message": self.message,
            "retryable": self.retryable,
            "details": self.details,
        })
        .to_string()
    }
}

impl From<MddError> for SdkError {
    fn from(error: MddError) -> Self {
        Self {
            status: status_for(&error.code),
            code: error.code.to_string(),
            stage: error.stage,
            message: error.message,
            retryable: error.retryable,
            details: error.details,
        }
    }
}

pub type SdkResult<T> = Result<T, SdkError>;
