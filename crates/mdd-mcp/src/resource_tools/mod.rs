//! The resource tools: `get_manifest_components`, `list_resource_files`, `read_resource` and
//! `query_resources`, and the `xml` mode of `get_manifest`.
//!
//! They share one way of running: resolve the dataset and the archive input, do the work on a
//! thread with the call's deadline, turn a failure into the reference's `kind`, then build the
//! answer. A page is never clipped silently: rows are added while the serialized answer fits
//! `max_bytes`, a text page holds at most a quarter of `max_bytes` (the reference's rule), and
//! an answer that cannot hold even one row, or one character, is refused.
use crate::tools::{
    self, Failure, Outcome, Registry, deadline, panicked, refuse, timed_out, with_deadline,
    with_kind,
};
use mdd_facts::raw_fingerprints::ResourceByteEvidence;
use mdd_service::{Dataset, resources::ResourceFailure};
use mdd_types::ErrorCode;
use serde_json::{Value, json};

pub mod components;
pub mod files;
pub mod query;
pub mod read;

/// Rows per page when `limit` is not given, and the most a page may hold.
pub const MAX_LIMIT: u64 = 200;
/// What `max_bytes` is when not given, and its range for a text or binary page.
pub const DEFAULT_MAX_BYTES: u64 = 131_072;
pub const MIN_MAX_BYTES: u64 = 4_096;

pub(crate) fn limit_of(asked: Option<u64>) -> Result<u64, Failure> {
    let limit = asked.unwrap_or(MAX_LIMIT);
    if (1..=MAX_LIMIT).contains(&limit) {
        Ok(limit)
    } else {
        Err(tools::invalid(format!("limit must be in 1..={MAX_LIMIT}")))
    }
}

/// `max_bytes` of a text or binary page: in `4096..=131072`, 131072 when not given.
pub(crate) fn page_bytes_of(asked: Option<u64>) -> Result<u64, Failure> {
    let bytes = asked.unwrap_or(DEFAULT_MAX_BYTES);
    if (MIN_MAX_BYTES..=DEFAULT_MAX_BYTES).contains(&bytes) {
        Ok(bytes)
    } else {
        Err(tools::invalid(format!(
            "max_bytes must be in {MIN_MAX_BYTES}..={DEFAULT_MAX_BYTES}"
        )))
    }
}

/// The byte budget of an answer made of rows: `max_bytes`, in `4096..=131072` (131072 when
/// not given). It bounds the answer as sent, which holds the structured content and its text
/// copy; see `wire_size`.
pub(crate) fn row_budget(asked: Option<u64>) -> Result<u64, Failure> {
    page_bytes_of(asked)
}

/// What an answer weighs on the wire: the structured content as compact JSON, plus the same JSON
/// as the escaped string of the text content that travels with it. This is the accounting
/// that reproduces the page sizes the reference engine recorded.
pub(crate) fn wire_size(value: &Value) -> u64 {
    let compact = serde_json::to_string(value).unwrap_or_default();
    let escaped = serde_json::to_string(&compact).map_or(0, |s| s.len().saturating_sub(2));
    (compact.len() + escaped) as u64
}

fn kind_of(failure: ResourceFailure) -> Failure {
    let (error, kind) = match failure {
        ResourceFailure::NoSuchInput(message) => {
            (refuse(ErrorCode::InvalidArgument, &message), "not_archive")
        }
        ResourceFailure::NotFound(message) => {
            (refuse(ErrorCode::InvalidInput, &message), "not_found")
        }
        ResourceFailure::Directory(message) => {
            (refuse(ErrorCode::InvalidInput, &message), "invalid_input")
        }
        ResourceFailure::Several(message) => {
            (refuse(ErrorCode::AmbiguousEntity, &message), "ambiguous")
        }
        ResourceFailure::InvalidXml(error) => (error, "invalid_xml"),
        // a table that uses what this reader does not read is not an invalid table
        ResourceFailure::InvalidTable(error) if error.code == ErrorCode::UnsupportedCapability => {
            (error, "unsupported_capability")
        }
        ResourceFailure::InvalidTable(error) => (error, "invalid_resource_table"),
        ResourceFailure::Error(error) => {
            let broken_member = error
                .details
                .get("reason")
                .is_some_and(|reason| reason == "CRC_OR_DECOMPRESSION_FAILURE");
            let kind = if broken_member {
                "resource_error"
            } else if error.stage == "manifest" || error.stage == "resources.xml" {
                "invalid_xml"
            } else {
                match error.code {
                    ErrorCode::QuotaExceeded => "quota_exceeded",
                    ErrorCode::UnsupportedCapability => "unsupported_capability",
                    _ => "resource_error",
                }
            };
            (error, kind)
        }
    };
    Failure::Execution(with_kind(error, kind))
}

/// Several archives are open and the call did not choose one.
pub(crate) fn ambiguous_input(archives: &[usize]) -> Failure {
    Failure::Execution(
        with_kind(
            refuse(
                ErrorCode::InvalidArgument,
                &format!("select an archive using input_index; archive inputs: {archives:?}"),
            ),
            "ambiguous_input",
        )
        .detail(tools::HINT_ARCHIVE_INPUTS, json!(archives)),
    )
}

/// Resolve the dataset and archive input of a call and run `work` on it under the call's
/// deadline. A deadline that expires closes the dataset, as for every other tool.
pub(crate) fn run<T: Send + 'static>(
    registry: &mut Registry,
    tool: &str,
    dataset_id: &str,
    input_index: Option<u64>,
    timeout_ms: Option<u64>,
    work: impl FnOnce(&Dataset, usize) -> Result<T, ResourceFailure> + Send + 'static,
) -> Result<(usize, T), Failure> {
    let ms = deadline(timeout_ms, registry.config())?;
    let dataset = registry.find(dataset_id)?;
    let archives = dataset.archive_inputs();
    let wrong = |code: ErrorCode, message: &str, kind: &str| {
        Failure::Execution(with_kind(refuse(code, message), kind))
    };
    let index = match (input_index, archives.as_slice()) {
        (Some(wanted), _) => usize::try_from(wanted).unwrap_or(usize::MAX),
        (None, [only]) => *only,
        (None, []) => {
            return Err(wrong(
                ErrorCode::InvalidArgument,
                "this dataset has no archive input",
                "not_archive",
            ));
        }
        (None, _) => return Err(ambiguous_input(&archives)),
    };
    let id = dataset_id.to_owned();
    match with_deadline(ms, move || work(&dataset, index)) {
        Outcome::Done(Ok(value)) => Ok((index, value)),
        Outcome::Done(Err(failure)) => Err(kind_of(failure)),
        Outcome::TimedOut => {
            registry.close(&id);
            Err(Failure::Execution(
                timed_out(tool, ms)
                    .detail("mcp.dataset_id", id.as_str())
                    .detail("mcp.dataset_closed", "true"),
            ))
        }
        Outcome::Panicked => {
            registry.close(&id);
            Err(Failure::Execution(
                panicked(tool)
                    .detail("mcp.dataset_id", id.as_str())
                    .detail("mcp.dataset_closed", "true"),
            ))
        }
    }
}

/// Where a page of `limit` rows starts and ends among `total`.
pub(crate) fn window(offset: u64, total: usize, limit: u64) -> Result<(usize, usize), Failure> {
    if offset > total as u64 {
        return Err(Failure::Execution(with_kind(
            refuse(
                ErrorCode::InvalidArgument,
                &format!("offset {offset} exceeds total_rows {total}"),
            ),
            "invalid_range",
        )));
    }
    let start = offset as usize;
    let end = total.min(start.saturating_add(usize::try_from(limit).unwrap_or(usize::MAX)));
    Ok((start, end))
}

fn over_budget(budget: u64, observed: u64) -> Failure {
    Failure::Execution(
        refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail("budget", "max_bytes")
        .detail("limit", budget.to_string())
        .detail("observed", observed.to_string()),
    )
}

/// The answer with as many of `rows` as fit `budget`: `build(n)` is the answer with the first
/// `n` rows. At least one row must fit, or the answer is refused.
pub(crate) fn fit_rows(
    rows: &[Value],
    budget: u64,
    build: &dyn Fn(usize) -> Value,
) -> Result<Value, Failure> {
    let size = wire_size;
    let mut count = rows.len();
    // start from what the row sizes alone allow, then correct against the real answer
    let base = size(&build(0));
    let mut sum = base;
    let mut fitted = 0;
    for (position, row) in rows.iter().enumerate() {
        sum = sum
            .saturating_add(size(row))
            .saturating_add(u64::from(position > 0));
        if sum > budget {
            break;
        }
        fitted = position + 1;
    }
    count = count.min(fitted);
    loop {
        let answer = build(count);
        let observed = size(&answer);
        if observed <= budget && (count > 0 || rows.is_empty()) {
            return Ok(answer);
        }
        if count == 0 {
            return Err(over_budget(budget, observed));
        }
        count -= 1;
    }
}

/// Where a resource came from, so an answer can be traced to the member and snapshot it was
/// read from.
pub(crate) fn source_json(evidence: &ResourceByteEvidence) -> Value {
    let member = evidence.member();
    json!({
        "content_id": evidence.content_id(),
        "entry_index": member.archive_member_ordinal.map(|ordinal| ordinal.0),
        "member_id": member.member_id,
        "sha256": evidence.sha256(),
        "snapshot_id": evidence.snapshot_id(),
    })
}

/// One page of a text, as the `page` object the reference writes. A page holds whole lines up to
/// a quarter of `max_bytes`; a first line longer than that is cut at the last character that
/// fits and the page says it ends mid-line. `end_line` is `start_line` plus the line ends in
/// the page, so a page that ends inside a line does not count that line.
pub(crate) fn text_page(text: &str, offset: u64, max_bytes: u64) -> Result<Value, Failure> {
    let budget = usize::try_from(max_bytes / 4).unwrap_or(usize::MAX);
    let bytes = text.as_bytes();
    let start = usize::try_from(offset)
        .ok()
        .filter(|start| *start <= bytes.len() && text.is_char_boundary(*start))
        .ok_or_else(|| {
            Failure::Execution(with_kind(
                refuse(
                    ErrorCode::InvalidArgument,
                    "offset must be a UTF-8 boundary within the text; use the returned next_offset",
                ),
                "invalid_range",
            ))
        })?;
    let newlines = |slice: &[u8]| slice.iter().filter(|b| **b == b'\n').count() as u64;
    let start_line = newlines(&bytes[..start]);
    let mut end = start;
    while end < bytes.len() {
        let line_end = bytes[end..]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |at| end + at + 1);
        if line_end - start > budget {
            break;
        }
        end = line_end;
    }
    let mut cut_inside_line = false;
    if end == start && start < bytes.len() {
        // not even one whole line fits: the first one is cut where a character still fits
        let mut stop = (start + budget).min(bytes.len());
        while stop > start && !text.is_char_boundary(stop) {
            stop -= 1;
        }
        end = stop;
        cut_inside_line = end < bytes.len() && bytes[end - 1] != b'\n';
    }
    Ok(json!({
        "end_line": start_line + newlines(&bytes[start..end]),
        "ends_mid_line": cut_inside_line,
        "next_offset": (end < bytes.len()).then_some(end),
        "offset": offset,
        "start_line": start_line,
        "starts_mid_line": start > 0 && bytes[start - 1] != b'\n',
        "text": &text[start..end],
        "total_bytes": bytes.len(),
    }))
}

/// A tool's answer must also fit the server's own ceiling, whatever `max_bytes` asked.
pub(crate) fn check_ceiling(registry: &Registry, answer: &Value) -> Result<(), Failure> {
    let ceiling = registry.config().max_result_bytes;
    let observed = serde_json::to_string(answer).map_or(u64::MAX, |s| s.len() as u64);
    if observed > ceiling {
        return Err(over_budget(ceiling, observed));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::error_result;
    use mdd_types::MddError;

    fn kind(failure: ResourceFailure) -> String {
        let Failure::Execution(error) = kind_of(failure) else {
            panic!("a tool error");
        };
        error_result(&error)["error"]["kind"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn each_failure_has_the_kind_the_contract_names() {
        let error = |code| MddError::new(code, "t", "m");
        assert_eq!(
            kind(ResourceFailure::NoSuchInput("m".into())),
            "not_archive"
        );
        assert_eq!(kind(ResourceFailure::NotFound("m".into())), "not_found");
        assert_eq!(
            kind(ResourceFailure::Directory("m".into())),
            "invalid_input"
        );
        assert_eq!(kind(ResourceFailure::Several("m".into())), "ambiguous");
        assert_eq!(
            kind(ResourceFailure::InvalidXml(error(ErrorCode::InvalidInput))),
            "invalid_xml"
        );
        assert_eq!(
            kind(ResourceFailure::InvalidTable(error(
                ErrorCode::InvalidInput
            ))),
            "invalid_resource_table"
        );
        // a table that uses what is not read yet is not an invalid table
        assert_eq!(
            kind(ResourceFailure::InvalidTable(error(
                ErrorCode::UnsupportedCapability
            ))),
            "unsupported_capability"
        );
        assert_eq!(
            kind(ResourceFailure::Error(error(ErrorCode::QuotaExceeded))),
            "quota_exceeded"
        );
        let broken = MddError::new(
            ErrorCode::InvalidInput,
            "archive.member_bytes",
            "Invalid checksum",
        )
        .detail("reason", "CRC_OR_DECOMPRESSION_FAILURE");
        assert_eq!(kind(ResourceFailure::Error(broken)), "resource_error");
        let manifest = MddError::new(ErrorCode::InvalidInput, "manifest", "bad");
        assert_eq!(kind(ResourceFailure::Error(manifest)), "invalid_xml");
    }

    #[test]
    fn an_answer_weighs_its_compact_json_and_the_escaped_text_copy() {
        // {"a":"b"} is 9 bytes, and as the text of a JSON string {\"a\":\"b\"} is 13
        assert_eq!(wire_size(&json!({"a": "b"})), 9 + 13);
        assert_eq!(wire_size(&json!([])), 2 + 2);
    }

    #[test]
    fn rows_are_added_while_the_answer_fits_and_an_answer_exactly_at_the_budget_fits() {
        let rows: Vec<Value> = (0..4).map(|n| json!({"n": n})).collect();
        let build = |count: usize| json!({"rows": &rows[..count]});
        let one = wire_size(&build(1));
        let three = wire_size(&build(3));
        assert_eq!(fit_rows(&rows, three, &build).unwrap(), build(3));
        assert_eq!(fit_rows(&rows, three - 1, &build).unwrap(), build(2));
        assert_eq!(fit_rows(&rows, one, &build).unwrap(), build(1));
        assert!(
            fit_rows(&rows, one - 1, &build).is_err(),
            "not even one row fits"
        );
        assert_eq!(fit_rows(&[], 100, &build).unwrap(), build(0));
    }

    fn page(text: &str, offset: u64, max_bytes: u64) -> Value {
        text_page(text, offset, max_bytes).unwrap()
    }

    #[test]
    fn a_text_page_holds_whole_lines_up_to_a_quarter_of_max_bytes() {
        // a quarter of 4096 is 1024: a line of exactly 1024 bytes fits, one of 1025 is cut
        let exact = format!("{}\n{}\n", "a".repeat(1023), "b".repeat(5));
        let first = page(&exact, 0, 4096);
        assert_eq!(first["text"].as_str().unwrap().len(), 1024);
        assert_eq!(
            (first["ends_mid_line"].clone(), first["next_offset"].clone()),
            (json!(false), json!(1024))
        );
        let long = format!("{}\nrest\n", "a".repeat(1024));
        let cut = page(&long, 0, 4096);
        assert_eq!(cut["text"].as_str().unwrap().len(), 1024);
        assert_eq!(
            (cut["ends_mid_line"].clone(), cut["end_line"].clone()),
            (json!(true), json!(0))
        );
        // the rest of that line, then the next
        let rest = page(&long, 1024, 4096);
        assert_eq!(rest["text"], "\nrest\n");
        assert_eq!(
            (
                rest["starts_mid_line"].clone(),
                rest["start_line"].clone(),
                rest["end_line"].clone()
            ),
            (json!(true), json!(0), json!(2))
        );
        assert_eq!(page("", 0, 4096)["next_offset"], Value::Null);
        // never inside a character: 1023 bytes then a three-byte character that straddles the budget
        let wide = format!("{}世{}", "a".repeat(1023), "z");
        let page = page(&wide, 0, 4096);
        assert_eq!(page["text"].as_str().unwrap().len(), 1023);
        assert!(
            text_page(&wide, 1024, 4096).is_err(),
            "offset 1024 is inside the character"
        );
        assert!(text_page(&wide, 99_999, 4096).is_err());
    }

    #[test]
    fn the_range_of_a_page_and_of_a_limit_is_checked() {
        assert!(limit_of(Some(0)).is_err());
        assert!(limit_of(Some(201)).is_err());
        assert_eq!(limit_of(None).unwrap(), 200);
        assert_eq!(limit_of(Some(1)).unwrap(), 1);
        assert!(page_bytes_of(Some(4095)).is_err());
        assert!(page_bytes_of(Some(131_073)).is_err());
        assert_eq!(page_bytes_of(Some(4096)).unwrap(), 4096);
        assert_eq!(page_bytes_of(None).unwrap(), 131_072);
        assert_eq!(window(7, 7, 5).unwrap(), (7, 7));
        assert_eq!(window(2, 7, 3).unwrap(), (2, 5));
        assert!(window(8, 7, 5).is_err());
    }
}
