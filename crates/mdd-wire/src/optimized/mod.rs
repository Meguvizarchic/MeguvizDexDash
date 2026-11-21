//! Fast, toggleable wire batch encoding and optional binary column-major framing (`MDD-061`).

pub mod batch_codec;
pub mod columns_v1;

pub use batch_codec::{BatchJsonWriter, wire_direct_json_enabled};
pub use columns_v1::{COLUMNS_V1_MAGIC, ColumnsV1Batch, ColumnsV1Cell};
