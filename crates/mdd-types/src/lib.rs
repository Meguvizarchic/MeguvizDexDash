use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub mod result;
pub mod source_identity;

pub type MddResult<T> = Result<T, MddError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    UnavailableBackend,
    UnsupportedCapability,
    UnsupportedQuery,
    InvalidArgument,
    InvalidInput,
    PartialInput,
    IncompleteFacts,
    SourceChanged,
    AmbiguousEntity,
    StaleCache,
    CacheCorrupt,
    QuotaExceeded,
    DeadlineExceeded,
    Cancelled,
    SnapshotClosed,
    InvalidCursor,
    InternalFault,
    WorkerLost,
}

impl fmt::Display for ErrorCode {
    /// Stable SCREAMING_SNAKE_CASE text, matching the JSON representation so
    /// logs and machine output never disagree about a code's spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::UnavailableBackend => "UNAVAILABLE_BACKEND",
            Self::UnsupportedCapability => "UNSUPPORTED_CAPABILITY",
            Self::UnsupportedQuery => "UNSUPPORTED_QUERY",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::InvalidInput => "INVALID_INPUT",
            Self::PartialInput => "PARTIAL_INPUT",
            Self::IncompleteFacts => "INCOMPLETE_FACTS",
            Self::SourceChanged => "SOURCE_CHANGED",
            Self::AmbiguousEntity => "AMBIGUOUS_ENTITY",
            Self::StaleCache => "STALE_CACHE",
            Self::CacheCorrupt => "CACHE_CORRUPT",
            Self::QuotaExceeded => "QUOTA_EXCEEDED",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::Cancelled => "CANCELLED",
            Self::SnapshotClosed => "SNAPSHOT_CLOSED",
            Self::InvalidCursor => "INVALID_CURSOR",
            Self::InternalFault => "INTERNAL_FAULT",
            Self::WorkerLost => "WORKER_LOST",
        };
        f.write_str(name)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MddError {
    pub code: ErrorCode,
    pub stage: String,
    pub message: String,
    pub retryable: bool,
    pub details: Map<String, Value>,
}

impl MddError {
    pub fn new(code: ErrorCode, stage: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            stage: stage.into(),
            message: message.into(),
            retryable: false,
            details: Map::new(),
        }
    }

    pub fn detail(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

impl fmt::Display for MddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at {}: {}", self.code, self.stage, self.message)
    }
}

impl std::error::Error for MddError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DecimalU64(pub u64);

impl Serialize for DecimalU64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for DecimalU64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty()
            || text.len() > 20
            || text.bytes().any(|b| !b.is_ascii_digit())
            || (text.len() > 1 && text.starts_with('0'))
        {
            return Err(de::Error::custom("expected canonical decimal u64 string"));
        }
        text.parse::<u64>().map(Self).map_err(de::Error::custom)
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn content_id(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256(bytes))
}

pub fn opaque_id(kind: &str) -> MddResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| MddError::new(ErrorCode::InternalFault, "identity", error.to_string()))?;
    Ok(format!(
        "{kind}-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Ok,
    Error,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    pub layer: String,
    pub reason: String,
    pub blocking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub scope_id: String,
    pub input: Completeness,
    pub facts: Completeness,
    pub required_layers: Vec<String>,
    pub issues: Vec<Issue>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub schema_id: Option<String>,
    pub emitted_rows: DecimalU64,
    pub total_rows: Option<DecimalU64>,
    pub total_rows_exact: bool,
    pub more_available: bool,
    pub truncated: bool,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultEnvelope {
    pub schema_version: String,
    pub request_id: String,
    pub operation: String,
    pub profile: String,
    pub sql_dialect: Option<String>,
    pub session_id: Option<String>,
    pub snapshot_id: Option<String>,
    pub catalog_epoch: Option<DecimalU64>,
    pub query_id: Option<String>,
    pub operation_status: OperationStatus,
    pub coverage: Coverage,
    pub execution: Execution,
    pub response: Response,
    pub data: Option<Map<String, Value>>,
    pub error: Option<MddError>,
    pub warnings: Vec<Issue>,
}

impl ResultEnvelope {
    pub fn validate(&self) -> MddResult<()> {
        let fail = |message| MddError::new(ErrorCode::InvalidArgument, "contract", message);
        if self.schema_version != "mdd.result.v1"
            || self.request_id.is_empty()
            || self.operation.is_empty()
            || self.profile.is_empty()
            || self.coverage.scope_id.is_empty()
        {
            return Err(fail("invalid result identity"));
        }
        for identity in [
            &self.sql_dialect,
            &self.session_id,
            &self.snapshot_id,
            &self.query_id,
            &self.response.schema_id,
        ] {
            if identity.as_ref().is_some_and(|value| value.is_empty()) {
                return Err(fail("optional identity must be nonempty when present"));
            }
        }
        if let Some(error) = &self.error
            && (error.stage.is_empty() || error.message.is_empty())
        {
            return Err(fail("error stage and message must be nonempty"));
        }
        if self
            .coverage
            .issues
            .iter()
            .chain(&self.warnings)
            .any(|issue| {
                issue.layer.is_empty()
                    || issue.reason.is_empty()
                    || issue.entity_id.as_ref().is_some_and(|id| id.is_empty())
                    || issue.member_id.as_ref().is_some_and(|id| id.is_empty())
            })
        {
            return Err(fail("invalid issue identity or reason"));
        }
        if self.response.more_available
            != self
                .response
                .next_cursor
                .as_ref()
                .is_some_and(|c| !c.is_empty())
            || (!self.response.more_available && self.response.next_cursor.is_some())
        {
            return Err(fail("cursor and more_available disagree"));
        }
        if self.response.total_rows_exact && self.response.total_rows.is_none() {
            return Err(fail("exact row total is missing"));
        }
        if self.operation_status == OperationStatus::Ok && self.error.is_some()
            || self.operation_status != OperationStatus::Ok && self.error.is_none()
        {
            return Err(fail("operation status and error disagree"));
        }
        let cancelled = self
            .error
            .as_ref()
            .is_some_and(|e| e.code == ErrorCode::Cancelled);
        if cancelled != (self.operation_status == OperationStatus::Cancelled) {
            return Err(fail("cancellation code and status disagree"));
        }
        if self
            .coverage
            .required_layers
            .iter()
            .any(|layer| layer.is_empty())
            || self
                .coverage
                .required_layers
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.coverage.required_layers.len()
        {
            return Err(fail("required layers contain empty or duplicate names"));
        }
        if self.coverage.input == Completeness::Complete
            && self.coverage.facts == Completeness::Complete
            && self.coverage.issues.iter().any(|i| i.blocking)
        {
            return Err(fail("complete scope contains a blocking issue"));
        }
        if let Some(total) = self.response.total_rows
            && self.response.total_rows_exact
            && self.response.emitted_rows > total
        {
            return Err(fail("emitted rows exceed exact total"));
        }
        Ok(())
    }

    /// Validates the envelope only. A consumer must also verify all batch/page
    /// sequences, delivered row counts, scope manifests, and evidence bindings.
    pub fn is_complete_result(&self) -> bool {
        self.validate().is_ok()
            && self.operation_status == OperationStatus::Ok
            && self.coverage.input == Completeness::Complete
            && self.coverage.facts == Completeness::Complete
            && !self.warnings.iter().any(|warning| warning.blocking)
            && self.execution.complete
            && !self.response.truncated
            && !self.response.more_available
            && self.response.next_cursor.is_none()
            && self.response.total_rows_exact
            && self.response.total_rows == Some(self.response.emitted_rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_u64_is_lossless_and_strict() {
        let max = DecimalU64(u64::MAX);
        assert_eq!(
            serde_json::to_string(&max).unwrap(),
            "\"18446744073709551615\""
        );
        assert_eq!(
            serde_json::from_str::<DecimalU64>("\"18446744073709551615\"").unwrap(),
            max
        );
        for invalid in [
            "0",
            "\"00\"",
            "\"+1\"",
            "\"1e2\"",
            "\"18446744073709551616\"",
            "\"\"",
        ] {
            assert!(
                serde_json::from_str::<DecimalU64>(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn contract_examples_roundtrip_and_partial_states_do_not_pass() {
        for text in [
            include_str!("../../../contracts/examples/result_complete.example.json"),
            include_str!("../../../contracts/examples/result_page.example.json"),
            include_str!("../../../contracts/examples/result_error.example.json"),
        ] {
            let result: ResultEnvelope = serde_json::from_str(text).unwrap();
            result.validate().unwrap();
            let encoded = serde_json::to_value(&result).unwrap();
            assert_eq!(encoded, serde_json::from_str::<Value>(text).unwrap());
        }
        let mut result: ResultEnvelope = serde_json::from_str(include_str!(
            "../../../contracts/examples/result_complete.example.json"
        ))
        .unwrap();
        assert!(result.is_complete_result());
        result.coverage.facts = Completeness::Unknown;
        assert!(!result.is_complete_result());
        result.coverage.facts = Completeness::Complete;
        result.operation_status = OperationStatus::Cancelled;
        result.error = Some(MddError::new(
            ErrorCode::Cancelled,
            "delivery",
            "cancelled after computation",
        ));
        assert!(result.execution.complete);
        result.validate().unwrap();
        assert!(!result.is_complete_result());
    }
}
