//! `mdd-wire/1`: framing, negotiation, typed JSON batches and the verification
//! state machine for the local worker channel.
//!
//! This crate knows nothing about sessions, queries or the engine's budgets. It
//! turns bytes into verified, typed results and refuses everything else. It is
//! never used on MCP stdout (see [`channel`]).
pub mod cell;
pub mod channel;
pub mod credit;
pub mod error;
pub mod frame;
pub mod stream;

pub use cell::{Cell, ColumnType};
pub use channel::{ChannelKind, check_mcp_stdout_message};
pub use credit::{Credit, CreditGate, CreditLedger};
pub use error::{WireError, WireErrorKind, WireResult};
pub use frame::{
    Agreed, Frame, FrameKind, FrameReader, FrameWriter, HEADER_BYTES, Header, Hello, MAGIC, MAJOR,
    MIN_FRAME_BYTES, MINOR, negotiate,
};
pub use stream::{
    Column, Completed, Failure, PeerError, ProducerStream, ResponseStream, Schema, StreamDigest,
    StreamLimits,
};
