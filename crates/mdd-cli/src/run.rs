//! Running one statement against an opened dataset.
//!
//! The statement is computed completely, then handed to the sink in owned batches.
//! Each batch is registered with the lifecycle (so its bytes count against the
//! buffer budget), given to the sink, acknowledged and released before the next one
//! is cut. The statement ends in exactly one terminal envelope: success only when the
//! computation finished and every row was delivered, otherwise a failure envelope
//! that says how many rows were delivered and whether the output was cut short.
use crate::dataset::Dataset;
use mdd_ffi::codec;
use mdd_session::{QueryBinding, QueryHandle, QueryPhase, ResourceLimits};
use mdd_sql::{control::SqlControl, values::SqlValue};
use mdd_types::{
    Completeness, Coverage, DecimalU64, ErrorCode, MddError, MddResult, ResultEnvelope, opaque_id,
    result::{ResultIdentity, TerminalBuilder},
};
use std::{
    io,
    time::{Duration, Instant},
};

pub const DEFAULT_BATCH_ROWS: u32 = 1000;
pub const MAX_BATCH_ROWS: u32 = 10_000;

pub struct RunOptions {
    pub batch_rows: u32,
    /// Stop after this many rows. The result is then a failure terminal marked
    /// truncated, never a success: a cut-off answer must not look complete.
    pub max_rows: Option<u64>,
    pub deadline_ms: Option<u64>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            batch_rows: DEFAULT_BATCH_ROWS,
            max_rows: None,
            deadline_ms: None,
        }
    }
}

/// Where the batches go. A write error stops the statement; the terminal envelope
/// is then returned to the caller instead of being delivered.
pub trait Sink {
    fn batch(&mut self, batch: &Batch<'_>) -> io::Result<()>;
}

pub struct Batch<'a> {
    pub columns: &'a [String],
    pub rows: &'a [Vec<SqlValue>],
    /// The `mdd.sdk-batch.v1` encoding of exactly these rows.
    pub encoded: &'a [u8],
}

pub struct Outcome {
    pub terminal: ResultEnvelope,
    /// The sink refused a write, so the terminal could not follow the batches.
    pub output_lost: Option<io::Error>,
}

impl Dataset {
    /// Run `sql` and deliver it to `sink`. Always returns a terminal envelope; the
    /// `Err` side is reserved for a failure to even build one.
    pub fn run(&self, sql: &str, options: &RunOptions, sink: &mut dyn Sink) -> MddResult<Outcome> {
        let mut run = Run::new(self, options);
        let result = run.execute(sql, sink);
        let output_lost = run.output_lost.take();
        // Failing to build the envelope for an outcome that is already known is a bug in
        // this program, not a mistake of the caller.
        let terminal = run.finish(result).map_err(|error| {
            MddError::new(
                ErrorCode::InternalFault,
                "cli",
                format!(
                    "the terminal envelope could not be built: {}",
                    error.message
                ),
            )
        })?;
        Ok(Outcome {
            terminal,
            output_lost,
        })
    }
}

struct Run<'a> {
    dataset: &'a Dataset,
    options: &'a RunOptions,
    query: Option<QueryHandle>,
    builder: Option<TerminalBuilder>,
    required_layers: Vec<String>,
    schema_id: String,
    output_lost: Option<io::Error>,
    /// The result's column names, once the statement has been computed. An empty
    /// result has no batch to carry them, so the terminal does.
    columns: Option<Vec<String>>,
}

impl<'a> Run<'a> {
    fn new(dataset: &'a Dataset, options: &'a RunOptions) -> Self {
        Self {
            dataset,
            options,
            query: None,
            builder: None,
            required_layers: Vec::new(),
            schema_id: "sql-result".to_owned(),
            output_lost: None,
            columns: None,
        }
    }

    fn coverage(&self) -> Coverage {
        let mut required = self.required_layers.clone();
        required.sort();
        Coverage {
            scope_id: self.dataset.scope_id.clone(),
            input: Completeness::Complete,
            facts: Completeness::Complete,
            required_layers: required,
            issues: Vec::new(),
        }
    }

    fn identity(&self, epoch: DecimalU64) -> MddResult<ResultIdentity> {
        Ok(ResultIdentity {
            request_id: opaque_id("cli-request")?,
            operation: "query".to_owned(),
            profile: self.dataset.dialect.profile().to_owned(),
            sql_dialect: Some(self.dataset.dialect.name().to_owned()),
            session_id: Some(self.dataset.session.id().to_owned()),
            snapshot_id: Some(self.dataset.snapshot_id().to_owned()),
            catalog_epoch: Some(epoch),
            query_id: self.query.as_ref().map(|q| q.id().to_owned()),
            schema_id: Some(self.schema_id.clone()),
        })
    }

    /// A statement may ask for less time than the dataset's ceiling, never more.
    fn limits(&self) -> MddResult<ResourceLimits> {
        let base = self.dataset.limits;
        match self.options.deadline_ms {
            Some(0) => Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cli",
                "deadline_ms must be positive",
            )),
            Some(ms) if ms > base.deadline_ms => Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cli",
                "deadline_ms is above the deadline ceiling of this dataset",
            )
            .detail("requested", ms.to_string())
            .detail("ceiling", base.deadline_ms.to_string())),
            Some(ms) => Ok(ResourceLimits {
                deadline_ms: ms,
                ..base
            }),
            None => Ok(base),
        }
    }

    fn execute(&mut self, sql: &str, sink: &mut dyn Sink) -> MddResult<()> {
        let dataset = self.dataset;
        let lifecycle = &dataset.lifecycle;
        if !(1..=MAX_BATCH_ROWS).contains(&self.options.batch_rows) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cli",
                format!("batch rows must be between 1 and {MAX_BATCH_ROWS}"),
            ));
        }
        let prepared = dataset.bridge.prepare(sql)?;
        self.required_layers = prepared
            .required_layers()
            .iter()
            .filter_map(|layer| serde_json::to_value(layer).ok())
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect();
        let limits = self.limits()?;
        let query = lifecycle.prepare_query(
            &dataset.session,
            QueryBinding {
                request_key: opaque_id("cli-request")?,
                schema_id: "sql-result".to_owned(),
                semantic_version: "mdd.cli.v1".to_owned(),
            },
            limits,
        )?;
        self.query = Some(query.clone());
        let deadline = Instant::now().checked_add(Duration::from_millis(limits.deadline_ms));
        let control = SqlControl::new(dataset.bridge.limits(), deadline);
        lifecycle.start_query(&dataset.session, &query, 1)?;
        let result = dataset.bridge.execute(&prepared, control)?;
        lifecycle.checkpoint(&query)?;
        if !result.calculation_complete() {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "cli",
                "the statement did not finish its calculation",
            ));
        }
        self.schema_id = result.schema_id();
        let columns = result.columns().to_vec();
        self.columns = Some(columns.clone());
        let rows = result.rows();
        lifecycle.complete_execution(&query)?;
        let epoch = lifecycle.query_status(&query)?.catalog_epoch;
        let mut builder = TerminalBuilder::new(self.identity(epoch)?, self.coverage())?;
        builder.computation_complete(rows.len() as u64)?;
        self.builder = Some(builder);

        let allowed = self.options.max_rows.unwrap_or(u64::MAX);
        let mut start = 0usize;
        let mut sequence = 0u64;
        while start < rows.len() {
            if start as u64 >= allowed {
                return Err(MddError::new(
                    ErrorCode::QuotaExceeded,
                    "cli",
                    "the row limit was reached before every row was delivered",
                )
                .detail("budget", "max_rows")
                .detail("limit", allowed.to_string())
                .detail("total_rows", rows.len().to_string()));
            }
            let end = (start + self.options.batch_rows as usize)
                .min(rows.len())
                .min(usize::try_from(allowed).unwrap_or(usize::MAX));
            let chunk = &rows[start..end];
            let encoded = codec::batch_bytes(&columns, chunk, sequence, start as u64);
            let handle = lifecycle.own_batch(&query, encoded.into_boxed_slice())?;
            let delivered = sink.batch(&Batch {
                columns: &columns,
                rows: chunk,
                encoded: handle.bytes(),
            });
            if let Err(error) = delivered {
                let message = error.to_string();
                self.output_lost = Some(error);
                return Err(MddError::new(
                    ErrorCode::Cancelled,
                    "cli.output",
                    format!("the output could not be written: {message}"),
                ));
            }
            // Counted only once the sink has taken the rows: `emitted_rows` is what was
            // delivered, so a batch the reader never got leaves emitted below total.
            if let Some(builder) = self.builder.as_mut() {
                builder.record_batch(sequence, chunk.len() as u64)?;
            }
            handle.acknowledge()?;
            handle.release()?;
            start = end;
            sequence += 1;
        }
        lifecycle.finish_delivery(&query)?;
        Ok(())
    }

    /// The terminal envelope for the outcome of `execute`.
    fn finish(mut self, result: MddResult<()>) -> MddResult<ResultEnvelope> {
        let envelope = match result {
            Ok(()) => {
                let mut builder = self.builder.take().ok_or_else(|| internal("no builder"))?;
                builder.succeed(self.data())
            }
            Err(error) => {
                let error = self.reconcile(error);
                let mut builder = match self.builder.take() {
                    Some(builder) => builder,
                    None => {
                        let epoch = self
                            .query
                            .as_ref()
                            .and_then(|q| self.dataset.lifecycle.query_status(q).ok())
                            .map_or(DecimalU64(0), |status| status.catalog_epoch);
                        TerminalBuilder::new(self.identity(epoch)?, self.coverage())?
                    }
                };
                builder.fail(error, false, self.data())
            }
        };
        if let Some(query) = self.query.take() {
            let _ = self.dataset.lifecycle.release_query(&query);
        }
        envelope
    }

    /// `{"columns": [...]}` once the statement has been computed, else nothing.
    fn data(&self) -> Option<serde_json::Map<String, serde_json::Value>> {
        let columns = self.columns.as_ref()?;
        let mut data = serde_json::Map::new();
        data.insert("columns".to_owned(), serde_json::json!(columns));
        Some(data)
    }

    /// A query cancelled before it ran is refused by the lifecycle with a phase
    /// error; it must still end as CANCELLED, which is what happened.
    fn reconcile(&self, error: MddError) -> MddError {
        if error.code != ErrorCode::InvalidArgument || error.stage != "lifecycle" {
            return error;
        }
        let Some(query) = &self.query else {
            return error;
        };
        match self.dataset.lifecycle.query_status(query) {
            Ok(status) if status.phase == QueryPhase::Cancelled => status.error.unwrap_or(error),
            _ => error,
        }
    }
}

fn internal(message: &str) -> MddError {
    MddError::new(ErrorCode::InternalFault, "cli", message)
}
