//! Completeness guards preventing partial, interrupted, truncated, or unpaged outcomes
//! from entering complete or negative caches.

use mdd_types::{Completeness, Coverage, ErrorCode, Execution, MddError, MddResult, Response};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistEligibility {
    pub eligible: bool,
    pub denial_code: Option<ErrorCode>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistScopeCheck {
    pub input_complete: bool,
    pub facts_complete: bool,
    pub execution_complete: bool,
    pub pagination_complete: bool,
    pub untruncated: bool,
    pub blocking_issue_count: usize,
    pub scope_id: String,
    pub required_layers: Vec<String>,
}

impl PersistScopeCheck {
    pub fn from_envelope_parts(
        coverage: &Coverage,
        execution: &Execution,
        response: &Response,
        operation_error: Option<&MddError>,
    ) -> MddResult<()> {
        if let Some(error) = operation_error {
            return Err(MddError::new(
                error.code,
                "cache.guard",
                format!(
                    "refusing to persist failed/interrupted result as complete or negative cache: {}",
                    error.message
                ),
            ));
        }
        if coverage.input != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::PartialInput,
                "cache.guard",
                "refusing to persist cache with incomplete input coverage",
            )
            .detail("scope_id", coverage.scope_id.clone()));
        }
        if coverage.facts != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "cache.guard",
                "refusing to persist cache with incomplete facts coverage",
            )
            .detail("scope_id", coverage.scope_id.clone()));
        }
        if coverage.issues.iter().any(|issue| issue.blocking) {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "cache.guard",
                "refusing to persist cache with blocking coverage issues",
            )
            .detail("scope_id", coverage.scope_id.clone()));
        }
        if !execution.complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "cache.guard",
                "refusing to persist incomplete execution as complete cache",
            ));
        }
        if response.truncated {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "cache.guard",
                "refusing to persist truncated response as complete or negative cache",
            ));
        }
        if response.more_available {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "cache.guard",
                "refusing to persist unconsumed paged response as complete or negative cache",
            ));
        }
        Ok(())
    }

    pub fn evaluate_negative_finding(
        coverage: &Coverage,
        execution: &Execution,
        response: &Response,
        operation_error: Option<&MddError>,
        required_layers: &[String],
    ) -> PersistEligibility {
        if let Err(err) = Self::from_envelope_parts(coverage, execution, response, operation_error)
        {
            return PersistEligibility {
                eligible: false,
                denial_code: Some(err.code),
                reason: err.message,
            };
        }
        for needed in required_layers {
            if !coverage.required_layers.contains(needed) {
                return PersistEligibility {
                    eligible: false,
                    denial_code: Some(ErrorCode::IncompleteFacts),
                    reason: format!("negative cache missing required layer coverage: {needed}"),
                };
            }
        }
        PersistEligibility {
            eligible: true,
            denial_code: None,
            reason: "scope complete across all required layers".to_owned(),
        }
    }
}
