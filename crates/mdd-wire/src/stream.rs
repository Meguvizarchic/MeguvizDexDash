//! One response stream: Schema, consecutive Batches, then exactly one terminal.
//!
//! The producer side builds frame bodies and keeps the running counts and
//! integrity digest; the consumer side ([`ResponseStream`]) checks every frame
//! against the schema and the sequence, buffers rows only within a quota, and
//! hands them out from [`ResponseStream::finish`] *only* when the End frame's row
//! count, batch count and digest equal what was actually received. Receiving
//! batches is not completing: a stream that ends without End, ends with an Error,
//! or repeats a terminal is never an empty or short success.
use crate::cell::{Cell, ColumnType, cell_type_error, decimal_field, hex};
use crate::credit::{Credit, CreditLedger};
use crate::error::{WireError, WireErrorKind, WireResult, malformed};
use crate::frame::{Frame, FrameKind};
use mdd_types::{ErrorCode, MddError, sha256};
use serde_json::{Map, Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamLimits {
    /// Largest frame body; normally the negotiated `max_frame_bytes`.
    pub max_body_bytes: u64,
    pub max_rows_per_batch: u64,
    /// Hard limit for one cell's variable-length payload.
    pub max_cell_bytes: usize,
    /// Total body bytes the consumer buffers before the terminal arrives.
    pub max_buffered_bytes: u64,
    /// Refuse batches that exceed the credit the consumer granted.
    pub enforce_credit: bool,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 4 * 1024 * 1024,
            max_rows_per_batch: 65_536,
            max_cell_bytes: 1024 * 1024,
            max_buffered_bytes: 64 * 1024 * 1024,
            enforce_credit: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Column {
    pub ordinal: u32,
    /// Identity of the column; `name` is display only and may repeat.
    pub stable_id: String,
    pub name: String,
    pub ty: ColumnType,
    pub nullable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Schema {
    pub schema_id: String,
    pub columns: Vec<Column>,
}

impl Schema {
    pub fn to_json(&self) -> Value {
        json!({
            "schema_id": self.schema_id,
            "columns": self.columns.iter().map(|column| json!({
                "ordinal": column.ordinal,
                "stable_id": column.stable_id,
                "name": column.name,
                "type": column.ty.name(),
                "nullable": column.nullable,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(value: &Value) -> WireResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| malformed("schema must be a JSON object"))?;
        only_keys(object, &["schema_id", "columns"], "schema")?;
        let schema_id = object
            .get("schema_id")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("schema lacks schema_id"))?
            .to_owned();
        let columns = object
            .get("columns")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("schema lacks columns"))?
            .iter()
            .map(|entry| {
                let column = entry
                    .as_object()
                    .ok_or_else(|| malformed("column must be an object"))?;
                only_keys(
                    column,
                    &["ordinal", "stable_id", "name", "type", "nullable"],
                    "column",
                )?;
                let text = |key: &str| {
                    column
                        .get(key)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| malformed(format!("column lacks string `{key}`")))
                };
                let type_name = text("type")?;
                Ok(Column {
                    ordinal: column
                        .get("ordinal")
                        .and_then(Value::as_u64)
                        .and_then(|v| u32::try_from(v).ok())
                        .ok_or_else(|| malformed("column ordinal must be a u32"))?,
                    stable_id: text("stable_id")?,
                    name: text("name")?,
                    ty: ColumnType::parse(&type_name).ok_or_else(|| {
                        WireError::new(
                            WireErrorKind::SchemaInvalid,
                            format!("column type `{type_name}` is not defined"),
                        )
                    })?,
                    nullable: column
                        .get("nullable")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| malformed("column lacks boolean `nullable`"))?,
                })
            })
            .collect::<WireResult<Vec<_>>>()?;
        let schema = Self { schema_id, columns };
        schema.validate()?;
        Ok(schema)
    }

    /// Ordinals are `0..n` in order, `stable_id` is non-empty and unique, there is
    /// at least one column. Display names are free to repeat.
    pub fn validate(&self) -> WireResult<()> {
        let invalid = |why: String| Err(WireError::new(WireErrorKind::SchemaInvalid, why));
        if self.schema_id.is_empty() || self.schema_id.len() > 256 {
            return invalid("schema_id must be 1..=256 bytes".to_owned());
        }
        if self.columns.is_empty() {
            return invalid("a schema needs at least one column".to_owned());
        }
        let mut seen = std::collections::BTreeSet::new();
        for (at, column) in self.columns.iter().enumerate() {
            if column.ordinal as usize != at {
                return invalid(format!("column {at} has ordinal {}", column.ordinal));
            }
            if column.stable_id.is_empty() || !seen.insert(column.stable_id.as_str()) {
                return invalid(format!("column {at} has an empty or repeated stable_id"));
            }
        }
        Ok(())
    }

    /// Identity bytes covered by the digest: schema id, then per column its
    /// ordinal, stable id, type and nullability (not the display name).
    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.schema_id.len() as u64).to_le_bytes());
        out.extend_from_slice(self.schema_id.as_bytes());
        out.extend_from_slice(&(self.columns.len() as u64).to_le_bytes());
        for column in &self.columns {
            out.extend_from_slice(&column.ordinal.to_le_bytes());
            out.extend_from_slice(&(column.stable_id.len() as u64).to_le_bytes());
            out.extend_from_slice(column.stable_id.as_bytes());
            out.push(column.ty.tag());
            out.push(u8::from(column.nullable));
        }
        out
    }

    fn check_row(&self, row: &[Cell], limits: &StreamLimits) -> WireResult<()> {
        if row.len() != self.columns.len() {
            return Err(WireError::new(
                WireErrorKind::RowShapeMismatch,
                format!(
                    "a row has {} cells for {} columns",
                    row.len(),
                    self.columns.len()
                ),
            ));
        }
        for (column, cell) in self.columns.iter().zip(row) {
            match cell.column_type() {
                None if !column.nullable => {
                    return Err(WireError::new(
                        WireErrorKind::CellTypeMismatch,
                        format!("column `{}` is not nullable", column.stable_id),
                    ));
                }
                Some(ty) if ty != column.ty => {
                    return Err(cell_type_error(&column.stable_id, column.ty, cell));
                }
                _ => {}
            }
            if cell.payload_bytes() > limits.max_cell_bytes {
                return Err(WireError::new(
                    WireErrorKind::CellTooLarge,
                    format!(
                        "a cell of {} bytes exceeds the {} byte cell limit",
                        cell.payload_bytes(),
                        limits.max_cell_bytes
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Running integrity digest over the schema identity and every batch, in order.
/// It covers types, NULLs, row order and each value's exact bytes.
#[derive(Clone, Debug)]
pub struct StreamDigest {
    state: String,
}

impl StreamDigest {
    pub fn new(schema: &Schema) -> Self {
        let mut seed = b"mdd-wire/1\0digest\0".to_vec();
        seed.extend_from_slice(&schema.canonical());
        Self {
            state: sha256(&seed),
        }
    }

    pub fn absorb(&mut self, sequence: u64, rows: &[Vec<Cell>]) {
        let mut buffer = self.state.clone().into_bytes();
        buffer.push(b'|');
        buffer.extend_from_slice(&sequence.to_le_bytes());
        buffer.extend_from_slice(&(rows.len() as u64).to_le_bytes());
        for row in rows {
            for cell in row {
                cell.digest_bytes(&mut buffer);
            }
        }
        self.state = sha256(&buffer);
    }

    pub fn finish(&self) -> String {
        self.state.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndSummary {
    pub rows: u64,
    pub batches: u64,
    pub digest: String,
}

impl EndSummary {
    fn to_json(&self) -> Value {
        json!({"rows": self.rows.to_string(), "batches": self.batches.to_string(), "digest": self.digest})
    }

    fn from_json(value: &Value) -> WireResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| malformed("end must be a JSON object"))?;
        only_keys(object, &["rows", "batches", "digest"], "end")?;
        let digest = object
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("end lacks digest"))?
            .to_owned();
        Ok(Self {
            rows: decimal_field(object, "rows")?,
            batches: decimal_field(object, "batches")?,
            digest,
        })
    }
}

/// A failure the peer reported in an Error frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerError {
    pub code: String,
    pub message: String,
    pub details: Map<String, Value>,
}

impl PeerError {
    /// The peer's code when it is one of ours, otherwise `INTERNAL_FAULT`; the
    /// original spelling is kept in the details either way.
    pub fn to_mdd(&self) -> MddError {
        let code = serde_json::from_value::<ErrorCode>(Value::String(self.code.clone()))
            .unwrap_or(ErrorCode::InternalFault);
        let mut error = MddError::new(code, "wire.peer", self.message.clone())
            .detail("peer_code", self.code.clone());
        for (key, value) in &self.details {
            error = error.detail(key.clone(), value.clone());
        }
        error
    }
}

fn only_keys(object: &Map<String, Value>, allowed: &[&str], what: &str) -> WireResult<()> {
    match object.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(extra) => Err(malformed(format!("{what} has an unknown field `{extra}`"))),
        None => Ok(()),
    }
}

fn to_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

pub fn credit_body(credit: Credit) -> Vec<u8> {
    to_bytes(&json!({"bytes": credit.bytes.to_string(), "batches": credit.batches.to_string()}))
}

pub fn parse_credit(frame: &Frame) -> WireResult<Credit> {
    let value = frame.json()?;
    let object = value
        .as_object()
        .ok_or_else(|| malformed("credit must be a JSON object"))?;
    only_keys(object, &["bytes", "batches"], "credit")?;
    Ok(Credit {
        bytes: decimal_field(object, "bytes")?,
        batches: decimal_field(object, "batches")?,
    })
}

// ---------------------------------------------------------------------------
// Producer
// ---------------------------------------------------------------------------

/// Builds the frame bodies of one stream and keeps the counts the End frame must
/// state. It validates what it emits, so a producer bug is caught here and not by
/// the consumer.
pub struct ProducerStream {
    stream_id: u64,
    limits: StreamLimits,
    schema: Option<Schema>,
    digest: Option<StreamDigest>,
    next_sequence: u64,
    rows: u64,
    terminal: bool,
}

impl ProducerStream {
    pub fn new(stream_id: u64, limits: StreamLimits) -> WireResult<Self> {
        if stream_id == 0 {
            return Err(WireError::new(
                WireErrorKind::BadStreamId,
                "stream 0 is the connection",
            ));
        }
        Ok(Self {
            stream_id,
            limits,
            schema: None,
            digest: None,
            next_sequence: 0,
            rows: 0,
            terminal: false,
        })
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    fn open(&self) -> WireResult<()> {
        if self.terminal {
            return Err(WireError::new(
                WireErrorKind::FrameAfterTerminal,
                "the stream already ended",
            ));
        }
        Ok(())
    }

    fn sized(&self, body: Vec<u8>) -> WireResult<Vec<u8>> {
        if body.len() as u64 > self.limits.max_body_bytes {
            return Err(WireError::new(
                WireErrorKind::FrameTooLarge,
                format!(
                    "body of {} bytes exceeds the {} byte limit",
                    body.len(),
                    self.limits.max_body_bytes
                ),
            ));
        }
        Ok(body)
    }

    pub fn schema(&mut self, schema: Schema) -> WireResult<Vec<u8>> {
        self.open()?;
        if self.schema.is_some() {
            return Err(WireError::new(
                WireErrorKind::UnexpectedFrame,
                "the schema was already sent",
            ));
        }
        schema.validate()?;
        let body = self.sized(to_bytes(&schema.to_json()))?;
        self.digest = Some(StreamDigest::new(&schema));
        self.schema = Some(schema);
        Ok(body)
    }

    /// The body of the next Batch. An empty row list is a legal batch and still
    /// advances the sequence, so the End frame's batch count stays exact.
    pub fn batch(&mut self, rows: &[Vec<Cell>]) -> WireResult<Vec<u8>> {
        self.open()?;
        let (Some(schema), Some(digest)) = (&self.schema, &mut self.digest) else {
            return Err(WireError::new(
                WireErrorKind::UnexpectedFrame,
                "a batch needs a schema first",
            ));
        };
        if rows.len() as u64 > self.limits.max_rows_per_batch {
            return Err(WireError::new(
                WireErrorKind::BatchTooLarge,
                format!(
                    "{} rows exceed the {} row batch limit",
                    rows.len(),
                    self.limits.max_rows_per_batch
                ),
            ));
        }
        for row in rows {
            schema.check_row(row, &self.limits)?;
        }
        let sequence = self.next_sequence;
        let body = to_bytes(&json!({
            "schema_id": schema.schema_id,
            "sequence": sequence.to_string(),
            "row_count": rows.len().to_string(),
            "rows": rows.iter().map(|row| Value::Array(row.iter().map(Cell::to_json).collect())).collect::<Vec<_>>(),
        }));
        if body.len() as u64 > self.limits.max_body_bytes {
            return Err(WireError::new(
                WireErrorKind::FrameTooLarge,
                format!(
                    "a batch of {} rows is {} bytes, over the {} byte limit; send fewer rows",
                    rows.len(),
                    body.len(),
                    self.limits.max_body_bytes
                ),
            ));
        }
        digest.absorb(sequence, rows);
        self.next_sequence += 1;
        self.rows += rows.len() as u64;
        Ok(body)
    }

    pub fn end(&mut self) -> WireResult<Vec<u8>> {
        self.open()?;
        let Some(digest) = &self.digest else {
            return Err(WireError::new(
                WireErrorKind::UnexpectedFrame,
                "End needs a schema first",
            ));
        };
        let summary = EndSummary {
            rows: self.rows,
            batches: self.next_sequence,
            digest: digest.finish(),
        };
        self.terminal = true;
        Ok(to_bytes(&summary.to_json()))
    }

    /// An Error terminal. It is the only way to end a stream that failed after
    /// rows were already sent.
    pub fn error(&mut self, error: &MddError) -> WireResult<Vec<u8>> {
        self.open()?;
        self.terminal = true;
        Ok(to_bytes(&json!({
            "code": error.code.to_string(),
            "message": error.message,
            "details": error.details,
        })))
    }
}

// ---------------------------------------------------------------------------
// Consumer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
enum Terminal {
    End(EndSummary),
    Error(PeerError),
    Cancel,
}

/// What a finished, verified stream delivered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Completed {
    pub schema: Schema,
    pub rows: Vec<Vec<Cell>>,
    pub batches: u64,
}

/// Why a stream did not complete, with what had been received by then.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub error: WireError,
    pub peer: Option<PeerError>,
    pub rows_received: u64,
}

pub struct ResponseStream {
    stream_id: u64,
    limits: StreamLimits,
    schema: Option<Schema>,
    digest: Option<StreamDigest>,
    next_sequence: u64,
    rows: Vec<Vec<Cell>>,
    buffered: u64,
    credit: CreditLedger,
    terminal: Option<Terminal>,
    failed: Option<WireError>,
}

impl ResponseStream {
    pub fn new(stream_id: u64, limits: StreamLimits) -> WireResult<Self> {
        if stream_id == 0 {
            return Err(WireError::new(
                WireErrorKind::BadStreamId,
                "stream 0 is the connection",
            ));
        }
        Ok(Self {
            stream_id,
            limits,
            schema: None,
            digest: None,
            next_sequence: 0,
            rows: Vec::new(),
            buffered: 0,
            credit: CreditLedger::default(),
            terminal: None,
            failed: None,
        })
    }

    /// Grant the producer credit and return the body of the Credit frame to send.
    pub fn grant_credit(&mut self, credit: Credit) -> WireResult<Vec<u8>> {
        self.credit.grant(credit)?;
        Ok(credit_body(credit))
    }

    pub fn rows_received(&self) -> u64 {
        self.rows.len() as u64
    }

    pub fn is_terminated(&self) -> bool {
        self.terminal.is_some() || self.failed.is_some()
    }

    /// A terminal was accepted and nothing has failed since, so [`finish`] has a
    /// verdict. Frames that arrive after this are still checked by [`accept`].
    ///
    /// [`finish`]: Self::finish
    /// [`accept`]: Self::accept
    pub fn finish_ready(&self) -> bool {
        self.terminal.is_some() && self.failed.is_none()
    }

    /// Check one frame. The first failure is sticky: later frames report it again
    /// instead of being interpreted on top of a broken stream.
    pub fn accept(&mut self, frame: &Frame) -> WireResult<()> {
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        match self.accept_inner(frame) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.failed = Some(error.clone());
                Err(error)
            }
        }
    }

    fn accept_inner(&mut self, frame: &Frame) -> WireResult<()> {
        if frame.header.stream_id != self.stream_id {
            return Err(WireError::new(
                WireErrorKind::BadStreamId,
                format!(
                    "frame for stream {} on stream {}",
                    frame.header.stream_id, self.stream_id
                ),
            ));
        }
        if self.terminal.is_some() {
            return Err(WireError::new(
                WireErrorKind::FrameAfterTerminal,
                format!("a {} frame follows the terminal", frame.header.kind.name()),
            ));
        }
        match frame.header.kind {
            FrameKind::Schema => {
                if self.schema.is_some() {
                    return Err(WireError::new(
                        WireErrorKind::UnexpectedFrame,
                        "a second schema",
                    ));
                }
                let schema = Schema::from_json(&frame.json()?)?;
                self.digest = Some(StreamDigest::new(&schema));
                self.schema = Some(schema);
                Ok(())
            }
            FrameKind::Batch => self.accept_batch(frame),
            FrameKind::Progress => {
                frame.json()?;
                Ok(())
            }
            FrameKind::End => {
                let (Some(_), Some(digest)) = (&self.schema, &self.digest) else {
                    return Err(WireError::new(
                        WireErrorKind::UnexpectedFrame,
                        "End before a schema",
                    ));
                };
                let summary = EndSummary::from_json(&frame.json()?)?;
                if summary.rows != self.rows.len() as u64 || summary.batches != self.next_sequence {
                    return Err(WireError::new(
                        WireErrorKind::CountMismatch,
                        format!(
                            "End states {} rows in {} batches but {} rows in {} batches arrived",
                            summary.rows,
                            summary.batches,
                            self.rows.len(),
                            self.next_sequence
                        ),
                    ));
                }
                if summary.digest != digest.finish() {
                    return Err(WireError::new(
                        WireErrorKind::DigestMismatch,
                        "the End digest does not match the received batches",
                    ));
                }
                self.terminal = Some(Terminal::End(summary));
                Ok(())
            }
            FrameKind::Error => {
                let value = frame.json()?;
                let object = value
                    .as_object()
                    .ok_or_else(|| malformed("error must be a JSON object"))?;
                only_keys(object, &["code", "message", "details"], "error")?;
                let text = |key: &str| {
                    object
                        .get(key)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| malformed(format!("error lacks string `{key}`")))
                };
                let details = match object.get("details") {
                    None => Map::new(),
                    Some(Value::Object(details)) => details.clone(),
                    Some(_) => return Err(malformed("error details must be an object")),
                };
                self.terminal = Some(Terminal::Error(PeerError {
                    code: text("code")?,
                    message: text("message")?,
                    details,
                }));
                Ok(())
            }
            FrameKind::Cancel => {
                self.terminal = Some(Terminal::Cancel);
                Ok(())
            }
            other => Err(WireError::new(
                WireErrorKind::UnexpectedFrame,
                format!(
                    "a {} frame does not belong in a response stream",
                    other.name()
                ),
            )),
        }
    }

    fn accept_batch(&mut self, frame: &Frame) -> WireResult<()> {
        let Some(schema) = &self.schema else {
            return Err(WireError::new(
                WireErrorKind::UnexpectedFrame,
                "a batch before the schema",
            ));
        };
        let value = frame.json()?;
        let object = value
            .as_object()
            .ok_or_else(|| malformed("batch must be a JSON object"))?;
        only_keys(
            object,
            &["schema_id", "sequence", "row_count", "rows"],
            "batch",
        )?;
        if object.get("schema_id").and_then(Value::as_str) != Some(schema.schema_id.as_str()) {
            return Err(WireError::new(
                WireErrorKind::SchemaInvalid,
                "a batch names another schema",
            ));
        }
        let sequence = decimal_field(object, "sequence")?;
        if sequence != self.next_sequence {
            return Err(WireError::new(
                WireErrorKind::SequenceGap,
                format!(
                    "batch {sequence} arrived where batch {} was due",
                    self.next_sequence
                ),
            ));
        }
        let row_count = decimal_field(object, "row_count")?;
        let raw_rows = object
            .get("rows")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("batch lacks rows"))?;
        if raw_rows.len() as u64 != row_count {
            return Err(WireError::new(
                WireErrorKind::CountMismatch,
                format!(
                    "row_count {row_count} but {} rows in the batch",
                    raw_rows.len()
                ),
            ));
        }
        if row_count > self.limits.max_rows_per_batch {
            return Err(WireError::new(
                WireErrorKind::BatchTooLarge,
                format!(
                    "{row_count} rows exceed the {} row batch limit",
                    self.limits.max_rows_per_batch
                ),
            ));
        }
        let mut rows = Vec::with_capacity(raw_rows.len());
        for raw in raw_rows {
            let cells = raw
                .as_array()
                .ok_or_else(|| malformed("a row must be an array"))?
                .iter()
                .map(Cell::from_json)
                .collect::<WireResult<Vec<_>>>()?;
            schema.check_row(&cells, &self.limits)?;
            rows.push(cells);
        }
        let body_bytes = frame.header.body_bytes;
        if self.buffered.saturating_add(body_bytes) > self.limits.max_buffered_bytes {
            return Err(WireError::new(
                WireErrorKind::BufferQuota,
                format!(
                    "buffering {body_bytes} more bytes would pass the {} byte quota",
                    self.limits.max_buffered_bytes
                ),
            ));
        }
        if self.limits.enforce_credit {
            self.credit.take(body_bytes)?;
        }
        if let Some(digest) = &mut self.digest {
            digest.absorb(sequence, &rows);
        }
        self.buffered += body_bytes;
        self.next_sequence += 1;
        self.rows.extend(rows);
        Ok(())
    }

    /// The verdict. Only an End whose counts and digest matched yields rows.
    pub fn finish(self) -> Result<Completed, Failure> {
        let rows_received = self.rows.len() as u64;
        if let Some(error) = self.failed {
            return Err(Failure {
                error,
                peer: None,
                rows_received,
            });
        }
        match self.terminal {
            Some(Terminal::End(_)) => {
                let schema = self.schema.ok_or_else(|| Failure {
                    error: WireError::new(WireErrorKind::UnexpectedFrame, "End without a schema"),
                    peer: None,
                    rows_received,
                })?;
                Ok(Completed {
                    schema,
                    rows: self.rows,
                    batches: self.next_sequence,
                })
            }
            Some(Terminal::Error(peer)) => Err(Failure {
                error: WireError::new(
                    WireErrorKind::PeerError,
                    format!(
                        "the producer failed after {rows_received} rows: {}",
                        peer.message
                    ),
                ),
                peer: Some(peer),
                rows_received,
            }),
            Some(Terminal::Cancel) => Err(Failure {
                error: WireError::new(WireErrorKind::Cancelled, "the stream was cancelled"),
                peer: None,
                rows_received,
            }),
            None => Err(Failure {
                error: WireError::new(
                    WireErrorKind::Disconnected,
                    format!("input ended after {rows_received} rows without an End frame"),
                ),
                peer: None,
                rows_received,
            }),
        }
    }
}

/// Hex of a digest or payload, for diagnostics and the conformance cases.
pub fn digest_hex(bytes: &[u8]) -> String {
    hex(bytes)
}
