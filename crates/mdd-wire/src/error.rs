//! Protocol failures. Every failure has a stable code so the conformance cases can
//! name it, and none of them is ever an empty successful result.
use mdd_types::{ErrorCode, MddError};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireErrorKind {
    BadMagic,
    UnsupportedVersion,
    BadHeaderLength,
    UnknownFrameKind,
    UnknownRequiredFlag,
    FrameTooLarge,
    TruncatedHeader,
    TruncatedBody,
    MalformedBody,
    NegotiationFailed,
    BadStreamId,
    UnexpectedFrame,
    SequenceGap,
    SchemaInvalid,
    RowShapeMismatch,
    CellTypeMismatch,
    CellTooLarge,
    BatchTooLarge,
    BufferQuota,
    CreditExceeded,
    CountMismatch,
    DigestMismatch,
    FrameAfterTerminal,
    Disconnected,
    Cancelled,
    DeadlineExceeded,
    PeerError,
    ChannelNotDedicated,
    McpStdoutViolation,
    Io,
}

impl WireErrorKind {
    /// Stable spelling used by the conformance cases and by error details.
    pub fn code(self) -> &'static str {
        match self {
            Self::BadMagic => "bad_magic",
            Self::UnsupportedVersion => "unsupported_version",
            Self::BadHeaderLength => "bad_header_length",
            Self::UnknownFrameKind => "unknown_frame_kind",
            Self::UnknownRequiredFlag => "unknown_required_flag",
            Self::FrameTooLarge => "frame_too_large",
            Self::TruncatedHeader => "truncated_header",
            Self::TruncatedBody => "truncated_body",
            Self::MalformedBody => "malformed_body",
            Self::NegotiationFailed => "negotiation_failed",
            Self::BadStreamId => "bad_stream_id",
            Self::UnexpectedFrame => "unexpected_frame",
            Self::SequenceGap => "sequence_gap",
            Self::SchemaInvalid => "schema_invalid",
            Self::RowShapeMismatch => "row_shape_mismatch",
            Self::CellTypeMismatch => "cell_type_mismatch",
            Self::CellTooLarge => "cell_too_large",
            Self::BatchTooLarge => "batch_too_large",
            Self::BufferQuota => "buffer_quota",
            Self::CreditExceeded => "credit_exceeded",
            Self::CountMismatch => "count_mismatch",
            Self::DigestMismatch => "digest_mismatch",
            Self::FrameAfterTerminal => "frame_after_terminal",
            Self::Disconnected => "disconnected",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::PeerError => "peer_error",
            Self::ChannelNotDedicated => "channel_not_dedicated",
            Self::McpStdoutViolation => "mcp_stdout_violation",
            Self::Io => "io",
        }
    }

    fn error_code(self) -> ErrorCode {
        match self {
            // A peer that vanished mid-frame is a lost worker like one that vanished
            // between frames.
            Self::Disconnected | Self::TruncatedHeader | Self::TruncatedBody => {
                ErrorCode::WorkerLost
            }
            Self::Cancelled => ErrorCode::Cancelled,
            Self::DeadlineExceeded => ErrorCode::DeadlineExceeded,
            Self::FrameTooLarge
            | Self::CellTooLarge
            | Self::BatchTooLarge
            | Self::BufferQuota
            | Self::CreditExceeded => ErrorCode::QuotaExceeded,
            _ => ErrorCode::InternalFault,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireError {
    pub kind: WireErrorKind,
    pub message: String,
}

impl WireError {
    pub fn new(kind: WireErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The error as the engine-wide error type. A peer that broke the protocol is
    /// an internal fault of the worker channel, a vanished peer is `WORKER_LOST`,
    /// and a limit is `QUOTA_EXCEEDED`; none of them is ever a fallback code.
    pub fn to_mdd(&self) -> MddError {
        MddError::new(self.kind.error_code(), "wire", self.message.clone())
            .detail("wire_error", self.kind.code())
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.code(), self.message)
    }
}

impl std::error::Error for WireError {}

pub type WireResult<T> = Result<T, WireError>;

pub(crate) fn malformed(message: impl Into<String>) -> WireError {
    WireError::new(WireErrorKind::MalformedBody, message)
}
