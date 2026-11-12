//! Read-only SQLite access to immutable, generation-bound providers.
//! Dialect conformance is separate from bridge availability.
mod bridge;
pub mod control;
pub mod dialects;
pub mod provider;
pub mod runtime;
pub mod temp;
pub mod values;
pub mod virtual_tables;
pub mod window;
pub use bridge::{PreparedSql, SqlBridge, SqlResult};
#[cfg(test)]
mod join_tests;
#[cfg(test)]
mod runtime_tests;

use mdd_types::{ErrorCode, MddError};

pub(crate) fn invalid(reason: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "sql", reason)
}
pub(crate) fn quota(reason: &str) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "sql", reason)
}

pub(crate) fn sqlite_error(error: rusqlite::Error) -> MddError {
    if let rusqlite::Error::UserFunctionError(inner) = &error
        && let Some(error) = inner.downcast_ref::<MddError>()
    {
        return error.clone();
    }
    if let rusqlite::Error::SqliteFailure(code, _) = &error {
        use rusqlite::ErrorCode as Code;
        let mapped = match code.code {
            Code::OutOfMemory | Code::TooBig | Code::DiskFull => ErrorCode::QuotaExceeded,
            Code::DatabaseBusy
            | Code::DatabaseLocked
            | Code::CannotOpen
            | Code::SystemIoFailure
            | Code::NoLargeFileSupport => ErrorCode::UnavailableBackend,
            Code::InternalMalfunction
            | Code::DatabaseCorrupt
            | Code::NotADatabase
            | Code::ApiMisuse
            | Code::OperationInterrupted
            | Code::SchemaChanged => ErrorCode::InternalFault,
            _ => ErrorCode::InvalidArgument,
        };
        return MddError::new(mapped, "sql.sqlite", error.to_string())
            .detail("sqlite_extended_code", code.extended_code)
            .detail("sqlite_code", format!("{:?}", code.code));
    }
    MddError::new(ErrorCode::InvalidArgument, "sql.sqlite", error.to_string())
}
