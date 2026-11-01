//! Monotonic stream bookkeeping over the existing mdd.result.v1 envelope.
use crate::{
    Coverage, DecimalU64, ErrorCode, Execution, MddError, MddResult, OperationStatus, Response,
    ResultEnvelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

fn invalid(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "result.terminal", message)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultIdentity {
    pub request_id: String,
    pub operation: String,
    pub profile: String,
    pub sql_dialect: Option<String>,
    pub session_id: Option<String>,
    pub snapshot_id: Option<String>,
    pub catalog_epoch: Option<DecimalU64>,
    pub query_id: Option<String>,
    pub schema_id: Option<String>,
}

/// Producer accounting only: required coverage is supplied by the scoped facts owner.
/// Query cancellation/worker errors do not downgrade already established fact coverage.
pub struct TerminalBuilder {
    identity: ResultIdentity,
    coverage: Coverage,
    emitted: u64,
    next_sequence: u64,
    computed: bool,
    total: Option<u64>,
    terminal: Option<ResultEnvelope>,
}
impl TerminalBuilder {
    pub fn new(identity: ResultIdentity, coverage: Coverage) -> MddResult<Self> {
        let state = Self {
            identity,
            coverage,
            emitted: 0,
            next_sequence: 0,
            computed: false,
            total: None,
            terminal: None,
        };
        state.envelope(None, false, None, 0, None)?.validate()?;
        Ok(state)
    }
    fn active(&self) -> MddResult<()> {
        if self.terminal.is_some() {
            Err(invalid("stream already has a terminal"))
        } else {
            Ok(())
        }
    }
    /// A producer may bind only a builder that has not recorded batches or a terminal.
    pub fn is_pristine(&self) -> bool {
        self.emitted == 0
            && self.next_sequence == 0
            && !self.computed
            && self.total.is_none()
            && self.terminal.is_none()
    }
    pub fn emitted_rows(&self) -> u64 {
        self.emitted
    }
    pub fn identity(&self) -> &ResultIdentity {
        &self.identity
    }
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }
    pub fn execution_complete(&self) -> bool {
        self.computed
    }
    pub fn record_batch(&mut self, sequence: u64, rows: u64) -> MddResult<()> {
        self.active()?;
        if sequence != self.next_sequence {
            return Err(invalid("out-of-order or duplicate batch sequence"));
        }
        let emitted = self
            .emitted
            .checked_add(rows)
            .ok_or_else(|| invalid("emitted row count overflow"))?;
        if self.total.is_some_and(|total| emitted > total) {
            return Err(invalid("delivered rows exceed exact computed total"));
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("batch sequence overflow"))?;
        self.emitted = emitted;
        Ok(())
    }
    pub fn computation_complete(&mut self, total_rows: u64) -> MddResult<()> {
        self.active()?;
        if self.computed || total_rows < self.emitted {
            return Err(invalid(
                "duplicate computation completion or total below delivered rows",
            ));
        }
        self.computed = true;
        self.total = Some(total_rows);
        Ok(())
    }
    fn envelope(
        &self,
        error: Option<MddError>,
        truncated: bool,
        cursor: Option<String>,
        emitted: u64,
        data: Option<Map<String, Value>>,
    ) -> MddResult<ResultEnvelope> {
        let status = match error.as_ref().map(|e| e.code) {
            Some(ErrorCode::Cancelled) => OperationStatus::Cancelled,
            Some(_) => OperationStatus::Error,
            None => OperationStatus::Ok,
        };
        let envelope = ResultEnvelope {
            schema_version: "mdd.result.v1".into(),
            request_id: self.identity.request_id.clone(),
            operation: self.identity.operation.clone(),
            profile: self.identity.profile.clone(),
            sql_dialect: self.identity.sql_dialect.clone(),
            session_id: self.identity.session_id.clone(),
            snapshot_id: self.identity.snapshot_id.clone(),
            catalog_epoch: self.identity.catalog_epoch,
            query_id: self.identity.query_id.clone(),
            operation_status: status,
            coverage: self.coverage.clone(),
            execution: Execution {
                complete: self.computed,
            },
            response: Response {
                schema_id: self.identity.schema_id.clone(),
                emitted_rows: DecimalU64(emitted),
                total_rows: self.total.map(DecimalU64),
                total_rows_exact: self.total.is_some(),
                more_available: cursor.is_some(),
                truncated,
                next_cursor: cursor,
            },
            data,
            error,
            warnings: Vec::new(),
        };
        envelope.validate()?;
        Ok(envelope)
    }
    /// A page response is not a stream terminal; the opaque cursor is owned by the session layer.
    pub fn page(
        &self,
        page_rows: u64,
        cursor: String,
        data: Option<Map<String, Value>>,
    ) -> MddResult<ResultEnvelope> {
        self.active()?;
        if cursor.is_empty() || page_rows > self.emitted {
            return Err(invalid("invalid page cursor or undelivered page rows"));
        }
        if self.total.is_some_and(|total| total <= self.emitted) {
            return Err(invalid(
                "page cursor claims more rows after exact computation is fully delivered",
            ));
        }
        self.envelope(None, false, Some(cursor), page_rows, data)
    }
    fn success_envelope(&self, data: Option<Map<String, Value>>) -> MddResult<ResultEnvelope> {
        self.active()?;
        if !self.computed || self.total != Some(self.emitted) {
            return Err(invalid(
                "success requires computation and all exact rows delivered",
            ));
        }
        self.envelope(None, false, None, self.emitted, data)
    }
    /// Verify success can be constructed without exposing or committing an envelope.
    pub fn validate_success(&self) -> MddResult<()> {
        self.success_envelope(None).map(|_| ())
    }
    pub fn succeed(&mut self, data: Option<Map<String, Value>>) -> MddResult<ResultEnvelope> {
        let envelope = self.success_envelope(data)?;
        self.terminal = Some(envelope.clone());
        Ok(envelope)
    }
    pub fn fail(
        &mut self,
        error: MddError,
        dropped_output: bool,
        data: Option<Map<String, Value>>,
    ) -> MddResult<ResultEnvelope> {
        self.active()?;
        let truncated = dropped_output || self.total.is_some_and(|total| self.emitted < total);
        let error = append_terminal_detail(
            error,
            "emitted_rows",
            "terminal_emitted_rows_",
            Value::String(self.emitted.to_string()),
        );
        let error = append_terminal_detail(
            error,
            "execution_complete",
            "terminal_execution_complete_",
            Value::Bool(self.computed),
        );
        let error = append_terminal_detail(
            error,
            "scope_id",
            "terminal_scope_id_",
            Value::String(self.coverage.scope_id.clone()),
        );
        let envelope = self.envelope(Some(error), truncated, None, self.emitted, data)?;
        self.terminal = Some(envelope.clone());
        Ok(envelope)
    }
    pub fn terminal(&self) -> Option<&ResultEnvelope> {
        self.terminal.as_ref()
    }
}

fn append_terminal_detail(mut error: MddError, name: &str, prefix: &str, value: Value) -> MddError {
    match error.details.get(name) {
        None => {
            error.details.insert(name.to_owned(), value);
            return error;
        }
        Some(existing) if existing == &value => return error,
        Some(_) => (),
    }
    // Keep existing diagnostics intact even if they already use our fallback names.
    let Some(attempts) = error.details.len().checked_add(1) else {
        return error;
    };
    for ordinal in 0..attempts {
        let candidate = format!("{prefix}{ordinal}");
        if !error.details.contains_key(&candidate) {
            error.details.insert(candidate, value);
            return error;
        }
    }
    error
}

/// A verified envelope still needs its scope manifest verified by the consuming integration.
pub struct VerifiedTerminal {
    envelope: ResultEnvelope,
    complete: bool,
}
impl VerifiedTerminal {
    pub fn envelope(&self) -> &ResultEnvelope {
        &self.envelope
    }
    pub fn is_complete_result(&self) -> bool {
        self.complete
    }
    pub fn require_complete(self) -> MddResult<ResultEnvelope> {
        if self.complete {
            return Ok(self.envelope);
        }
        Err(self.envelope.error.clone().unwrap_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "result.consume",
                "stream does not satisfy complete-result conditions",
            )
        }))
    }
}
pub struct StreamVerifier {
    identity: ResultIdentity,
    scope_id: String,
    required_layers: Vec<String>,
    rows: u64,
    sequence: u64,
    terminal: Option<ResultEnvelope>,
    fault: Option<MddError>,
}
impl StreamVerifier {
    pub fn new(
        identity: ResultIdentity,
        scope_id: String,
        mut required_layers: Vec<String>,
    ) -> MddResult<Self> {
        if scope_id.is_empty() {
            return Err(invalid("empty expected scope"));
        }
        required_layers.sort();
        if required_layers.iter().any(String::is_empty)
            || required_layers.windows(2).any(|v| v[0] == v[1])
        {
            return Err(invalid("invalid required layers"));
        }
        Ok(Self {
            identity,
            scope_id,
            required_layers,
            rows: 0,
            sequence: 0,
            terminal: None,
            fault: None,
        })
    }
    pub fn batch(&mut self, sequence: u64, schema_id: &str, rows: u64) -> MddResult<()> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if self.terminal.is_some()
            || sequence != self.sequence
            || self.identity.schema_id.as_deref() != Some(schema_id)
        {
            let error = invalid("batch after terminal, sequence or schema mismatch");
            self.fault = Some(error.clone());
            return Err(error);
        }
        let next_rows = match self.rows.checked_add(rows) {
            Some(value) => value,
            None => {
                let error = invalid("consumer row overflow");
                self.fault = Some(error.clone());
                return Err(error);
            }
        };
        let next_sequence = match self.sequence.checked_add(1) {
            Some(value) => value,
            None => {
                let error = invalid("consumer sequence overflow");
                self.fault = Some(error.clone());
                return Err(error);
            }
        };
        self.rows = next_rows;
        self.sequence = next_sequence;
        Ok(())
    }
    pub fn terminal(&mut self, envelope: ResultEnvelope) -> MddResult<()> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if self.terminal.is_some() {
            let error = invalid("duplicate terminal");
            self.fault = Some(error.clone());
            return Err(error);
        }
        if let Err(error) = envelope.validate() {
            self.fault = Some(error.clone());
            return Err(error);
        }
        let i = &self.identity;
        let mut layers = envelope.coverage.required_layers.clone();
        layers.sort();
        if envelope.request_id != i.request_id
            || envelope.operation != i.operation
            || envelope.profile != i.profile
            || envelope.sql_dialect != i.sql_dialect
            || envelope.session_id != i.session_id
            || envelope.snapshot_id != i.snapshot_id
            || envelope.catalog_epoch != i.catalog_epoch
            || envelope.query_id != i.query_id
            || envelope.response.schema_id != i.schema_id
            || envelope.coverage.scope_id != self.scope_id
            || layers != self.required_layers
            || envelope.response.emitted_rows.0 != self.rows
        {
            let error =
                invalid("terminal identity, scope, required layers or delivered count mismatch");
            self.fault = Some(error.clone());
            return Err(error);
        }
        // Check the final delivery claim independently from the complete-result
        // predicate: a stricter predicate must not hide a contradictory exact
        // total. Pages and error/truncated responses retain their own semantics.
        if envelope.operation_status == OperationStatus::Ok
            && envelope.execution.complete
            && !envelope.response.truncated
            && !envelope.response.more_available
            && envelope.response.next_cursor.is_none()
            && envelope.response.total_rows_exact
            && envelope.response.total_rows != Some(DecimalU64(self.rows))
        {
            let error = invalid("complete stream omitted exact rows");
            self.fault = Some(error.clone());
            return Err(error);
        }
        self.terminal = Some(envelope);
        Ok(())
    }
    pub fn finish(self) -> MddResult<VerifiedTerminal> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        let envelope = self.terminal.ok_or_else(|| {
            MddError::new(
                ErrorCode::WorkerLost,
                "result.consume",
                "EOF before explicit terminal",
            )
        })?;
        let complete = envelope.is_complete_result();
        Ok(VerifiedTerminal { envelope, complete })
    }
}

#[derive(Clone, Debug)]
pub struct FallbackPolicy {
    pub explicitly_allowed: bool,
    pub equivalence_id: String,
    pub source_key: String,
    pub result_contract: String,
}
#[derive(Clone, Debug)]
pub struct FallbackContext {
    pub source_key: String,
    pub result_contract: String,
    pub accepted_rows: u64,
    pub session_mutated: bool,
    pub side_effects: bool,
    pub backend_forced: bool,
    pub required_replacement_qualification: bool,
}
pub fn fallback_allowed(
    error: &MddError,
    policy: &FallbackPolicy,
    context: &FallbackContext,
) -> bool {
    matches!(
        error.code,
        ErrorCode::UnavailableBackend
            | ErrorCode::UnsupportedCapability
            | ErrorCode::UnsupportedQuery
    ) && policy.explicitly_allowed
        && !policy.equivalence_id.is_empty()
        && !policy.source_key.is_empty()
        && !policy.result_contract.is_empty()
        && policy.source_key == context.source_key
        && policy.result_contract == context.result_contract
        && context.accepted_rows == 0
        && !context.session_mutated
        && !context.side_effects
        && !context.backend_forced
        && !context.required_replacement_qualification
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Completeness;
    pub fn identity() -> ResultIdentity {
        ResultIdentity {
            request_id: "r".into(),
            operation: "query".into(),
            profile: "native-unqualified".into(),
            sql_dialect: None,
            session_id: Some("s".into()),
            snapshot_id: Some("snapshot".into()),
            catalog_epoch: Some(DecimalU64(u64::MAX)),
            query_id: Some("q".into()),
            schema_id: Some("rows-v1".into()),
        }
    }
    pub fn coverage() -> Coverage {
        Coverage {
            scope_id: "scope".into(),
            input: Completeness::Complete,
            facts: Completeness::Complete,
            required_layers: vec!["structure".into()],
            issues: Vec::new(),
        }
    }
    fn verifier() -> StreamVerifier {
        StreamVerifier::new(identity(), "scope".into(), vec!["structure".into()]).unwrap()
    }
    #[test]
    fn complete_result_requires_an_exact_matching_total() {
        let mut builder = TerminalBuilder::new(identity(), coverage()).unwrap();
        builder.computation_complete(1).unwrap();
        builder.record_batch(0, 1).unwrap();
        let valid = builder.succeed(None).unwrap();
        assert!(valid.is_complete_result());

        let mut inexact = valid.clone();
        inexact.response.total_rows = None;
        inexact.response.total_rows_exact = false;
        inexact.validate().unwrap();
        assert!(!inexact.is_complete_result());
        let mut receiver = verifier();
        receiver.batch(0, "rows-v1", 1).unwrap();
        receiver.terminal(inexact).unwrap();
        assert!(!receiver.finish().unwrap().is_complete_result());

        let mut mismatch = valid;
        mismatch.response.total_rows = Some(DecimalU64(2));
        mismatch.validate().unwrap();
        assert!(!mismatch.is_complete_result());
        let mut receiver = verifier();
        receiver.batch(0, "rows-v1", 1).unwrap();
        assert_eq!(
            receiver.terminal(mismatch).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let mut page = TerminalBuilder::new(identity(), coverage()).unwrap();
        page.computation_complete(2).unwrap();
        page.record_batch(0, 1).unwrap();
        let page = page.page(1, "cursor".into(), None).unwrap();
        page.validate().unwrap();
        assert!(!page.is_complete_result());
        let mut receiver = verifier();
        receiver.batch(0, "rows-v1", 1).unwrap();
        receiver.terminal(page).unwrap();
        assert!(!receiver.finish().unwrap().is_complete_result());
    }
    #[test]
    fn exact_total_larger_than_delivered_is_not_complete() {
        let mut builder = TerminalBuilder::new(identity(), coverage()).unwrap();
        builder.computation_complete(1).unwrap();
        builder.record_batch(0, 1).unwrap();
        let mut mismatch = builder.succeed(None).unwrap();
        mismatch.response.total_rows = Some(DecimalU64(2));
        mismatch.validate().unwrap();
        assert!(!mismatch.is_complete_result());
    }
    #[test]
    fn blocking_warning_cannot_be_a_complete_result() {
        let mut builder = TerminalBuilder::new(identity(), coverage()).unwrap();
        builder.computation_complete(0).unwrap();
        let mut result = builder.succeed(None).unwrap();
        result.warnings.push(crate::Issue {
            layer: "delivery".into(),
            reason: "consumer could not establish complete delivery".into(),
            blocking: false,
            entity_id: None,
            member_id: None,
            range: None,
            details: None,
        });
        result.validate().unwrap();
        assert!(result.is_complete_result());
        result.warnings[0].blocking = true;
        result.validate().unwrap();
        assert!(!result.is_complete_result());
        let mut receiver = verifier();
        receiver.terminal(result).unwrap();
        assert!(!receiver.finish().unwrap().is_complete_result());
    }
    #[test]
    fn pristine_builder_rejects_even_a_recorded_zero_row_batch() {
        let mut fresh = TerminalBuilder::new(identity(), coverage()).unwrap();
        assert!(fresh.is_pristine());
        fresh.record_batch(0, 0).unwrap();
        assert!(!fresh.is_pristine());

        let mut computed = TerminalBuilder::new(identity(), coverage()).unwrap();
        computed.computation_complete(0).unwrap();
        assert!(!computed.is_pristine());
        computed.succeed(None).unwrap();
        assert!(!computed.is_pristine());
    }
    #[test]
    fn success_validation_does_not_commit_and_can_be_followed_by_failure() {
        let mut builder = TerminalBuilder::new(identity(), coverage()).unwrap();
        builder.computation_complete(0).unwrap();
        builder.validate_success().unwrap();
        assert!(builder.terminal().is_none());
        let end = builder
            .fail(
                MddError::new(ErrorCode::DeadlineExceeded, "test", "delivery deadline"),
                false,
                None,
            )
            .unwrap();
        assert_eq!(end.error.unwrap().code, ErrorCode::DeadlineExceeded);
        assert!(end.execution.complete);
        assert!(!builder.terminal().unwrap().is_complete_result());
    }
    #[test]
    fn failure_terminal_preserves_existing_error_details() {
        let mut builder = TerminalBuilder::new(identity(), coverage()).unwrap();
        builder.record_batch(0, 2).unwrap();
        let prior = MddError::new(ErrorCode::QuotaExceeded, "source", "quota")
            .detail("emitted_rows", "original")
            .detail("terminal_emitted_rows_0", "collision")
            .detail("execution_complete", "source-value")
            .detail("scope_id", "source-scope");
        let end = builder.fail(prior.clone(), false, None).unwrap();
        let error = end.error.unwrap();
        assert_eq!(error.code, prior.code);
        assert_eq!(error.stage, prior.stage);
        assert_eq!(error.message, prior.message);
        for (name, value) in &prior.details {
            assert_eq!(error.details.get(name), Some(value));
        }
        assert_eq!(error.details["terminal_emitted_rows_1"], "2");
        assert_eq!(error.details["terminal_execution_complete_0"], false);
        assert_eq!(error.details["terminal_scope_id_0"], "scope");
    }
    #[test]
    fn part_rows_error_and_eof_never_complete() {
        for code in [
            ErrorCode::QuotaExceeded,
            ErrorCode::DeadlineExceeded,
            ErrorCode::Cancelled,
            ErrorCode::WorkerLost,
        ] {
            let mut builder = TerminalBuilder::new(identity(), coverage()).unwrap();
            builder.record_batch(0, 2).unwrap();
            let end = builder
                .fail(MddError::new(code, "test", "actual stop"), false, None)
                .unwrap();
            assert!(!end.execution.complete);
            assert_eq!(end.coverage.facts, Completeness::Complete);
            assert_eq!(end.response.emitted_rows.0, 2);
            assert!(!end.is_complete_result());
            let mut receiver = verifier();
            receiver.batch(0, "rows-v1", 2).unwrap();
            receiver.terminal(end).unwrap();
            assert_eq!(
                receiver
                    .finish()
                    .unwrap()
                    .require_complete()
                    .err()
                    .unwrap()
                    .code,
                code
            );
            assert!(builder.record_batch(1, 1).is_err());
            assert!(builder.succeed(None).is_err());
        }
        let mut receiver = verifier();
        receiver.batch(0, "rows-v1", 0).unwrap();
        assert_eq!(receiver.finish().err().unwrap().code, ErrorCode::WorkerLost);
    }
    #[test]
    fn computed_spool_cancel_page_and_complete_zero_are_independent() {
        let mut builder = TerminalBuilder::new(identity(), coverage()).unwrap();
        builder.computation_complete(4).unwrap();
        builder.record_batch(0, 2).unwrap();
        let page = builder.page(2, "opaque-cursor".into(), None).unwrap();
        assert!(
            page.execution.complete && page.response.more_available && !page.response.truncated
        );
        assert!(!page.is_complete_result());
        let end = builder
            .fail(
                MddError::new(ErrorCode::Cancelled, "test", "unconsumed spool cancelled"),
                false,
                None,
            )
            .unwrap();
        assert!(end.execution.complete && end.response.truncated);
        assert_eq!(end.coverage.input, Completeness::Complete);
        let mut zero = TerminalBuilder::new(identity(), coverage()).unwrap();
        zero.computation_complete(0).unwrap();
        let end = zero.succeed(None).unwrap();
        let mut receiver = verifier();
        receiver.terminal(end).unwrap();
        assert!(receiver.finish().unwrap().require_complete().is_ok());
        for coverage in [Completeness::Partial, Completeness::Unknown] {
            let mut c = self::coverage();
            c.facts = coverage;
            let mut builder = TerminalBuilder::new(identity(), c).unwrap();
            builder.computation_complete(0).unwrap();
            assert!(!builder.succeed(None).unwrap().is_complete_result());
        }
    }
    #[test]
    fn fallback_is_exact_three_code_gate_and_never_replays_partial_or_mutated_work() {
        let p = FallbackPolicy {
            explicitly_allowed: true,
            equivalence_id: "proved-contract-v1".into(),
            source_key: "input".into(),
            result_contract: "rows-v1".into(),
        };
        let context = FallbackContext {
            source_key: "input".into(),
            result_contract: "rows-v1".into(),
            accepted_rows: 0,
            session_mutated: false,
            side_effects: false,
            backend_forced: false,
            required_replacement_qualification: false,
        };
        let all = [
            ErrorCode::UnavailableBackend,
            ErrorCode::UnsupportedCapability,
            ErrorCode::UnsupportedQuery,
            ErrorCode::InvalidArgument,
            ErrorCode::InvalidInput,
            ErrorCode::PartialInput,
            ErrorCode::IncompleteFacts,
            ErrorCode::SourceChanged,
            ErrorCode::AmbiguousEntity,
            ErrorCode::StaleCache,
            ErrorCode::CacheCorrupt,
            ErrorCode::QuotaExceeded,
            ErrorCode::DeadlineExceeded,
            ErrorCode::Cancelled,
            ErrorCode::SnapshotClosed,
            ErrorCode::InvalidCursor,
            ErrorCode::InternalFault,
            ErrorCode::WorkerLost,
        ];
        for (index, code) in all.into_iter().enumerate() {
            assert_eq!(
                fallback_allowed(&MddError::new(code, "test", "original"), &p, &context),
                index < 3
            );
        }
        let error = MddError::new(ErrorCode::UnsupportedQuery, "test", "known unsupported");
        for c in [
            FallbackContext {
                accepted_rows: 1,
                ..context.clone()
            },
            FallbackContext {
                session_mutated: true,
                ..context.clone()
            },
            FallbackContext {
                side_effects: true,
                ..context.clone()
            },
            FallbackContext {
                backend_forced: true,
                ..context.clone()
            },
            FallbackContext {
                required_replacement_qualification: true,
                ..context.clone()
            },
            FallbackContext {
                source_key: "other".into(),
                ..context.clone()
            },
            FallbackContext {
                result_contract: "other".into(),
                ..context.clone()
            },
        ] {
            assert!(!fallback_allowed(&error, &p, &c));
        }
    }

    #[test]
    fn coverage_execution_and_delivery_axes_are_independent_and_protocol_faults_sticky() {
        let mut base = TerminalBuilder::new(identity(), coverage()).unwrap();
        base.computation_complete(0).unwrap();
        let complete = base.succeed(None).unwrap();
        for input in [
            Completeness::Complete,
            Completeness::Partial,
            Completeness::Unknown,
        ] {
            for facts in [
                Completeness::Complete,
                Completeness::Partial,
                Completeness::Unknown,
            ] {
                for computed in [false, true] {
                    for disposition in 0..3 {
                        let mut envelope = complete.clone();
                        envelope.coverage.input = input;
                        envelope.coverage.facts = facts;
                        envelope.execution.complete = computed;
                        if disposition == 1 {
                            envelope.response.more_available = true;
                            envelope.response.next_cursor = Some("unconsumed".into());
                        }
                        if disposition == 2 {
                            envelope.response.truncated = true;
                        }
                        envelope.validate().unwrap();
                        assert_eq!(
                            envelope.is_complete_result(),
                            input == Completeness::Complete
                                && facts == Completeness::Complete
                                && computed
                                && disposition == 0
                        );
                    }
                }
            }
        }
        let mut receiver = verifier();
        assert!(receiver.batch(1, "rows-v1", 0).is_err());
        assert!(receiver.terminal(complete.clone()).is_err());
        assert!(receiver.finish().is_err());
        let mut receiver = verifier();
        receiver.terminal(complete.clone()).unwrap();
        assert!(receiver.terminal(complete).is_err());
        assert!(receiver.finish().is_err());
        let mut empty = TerminalBuilder::new(identity(), coverage()).unwrap();
        empty.computation_complete(0).unwrap();
        assert!(empty.page(0, "invented-more".into(), None).is_err());
    }

    #[test]
    fn consumer_count_errors_remain_failed_and_do_not_partially_commit() {
        let mut producer = TerminalBuilder::new(identity(), coverage()).unwrap();
        producer.computation_complete(u64::MAX).unwrap();
        producer.record_batch(0, u64::MAX).unwrap();
        let terminal = producer.succeed(None).unwrap();
        let mut receiver = verifier();
        receiver.batch(0, "rows-v1", u64::MAX).unwrap();
        assert!(receiver.batch(1, "rows-v1", 1).is_err());
        assert!(receiver.terminal(terminal).is_err());
        assert!(receiver.finish().is_err());

        let mut receiver = verifier();
        receiver.rows = 7;
        receiver.sequence = u64::MAX;
        assert!(receiver.batch(u64::MAX, "rows-v1", 1).is_err());
        assert_eq!(receiver.rows, 7);
        assert_eq!(receiver.sequence, u64::MAX);
        assert!(receiver.finish().is_err());
    }
}
