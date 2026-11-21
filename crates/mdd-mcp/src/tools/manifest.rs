use super::*;

// ---- get_manifest ---------------------------------------------------------------

pub const MAX_MANIFEST_LIMIT: u64 = 200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestArgs {
    dataset_id: String,
    input_index: Option<u64>,
    limit: Option<u64>,
    max_bytes: Option<u64>,
    mode: Option<String>,
    #[serde(default)]
    offset: u64,
    timeout_ms: Option<u64>,
}

/// The `xml` mode: the whole manifest as XML text, paged by UTF-8 byte offset.
pub(super) fn get_manifest_xml(
    registry: &mut Registry,
    args: ManifestArgs,
) -> Result<Value, Failure> {
    // `limit` pages permission rows, which this mode has none of; its range is checked all the same
    resource_tools::limit_of(args.limit)?;
    let max_bytes = resource_tools::page_bytes_of(args.max_bytes)?;
    let (input_index, text) = resource_tools::run(
        registry,
        "get_manifest",
        &args.dataset_id,
        args.input_index,
        args.timeout_ms,
        move |dataset, index| Ok(dataset.manifest_xml(index)?),
    )?;
    let answer = json!({
        "dataset_id": args.dataset_id,
        "input_index": input_index,
        "page": resource_tools::text_page(&text, args.offset, max_bytes)?,
    });
    resource_tools::check_ceiling(registry, &answer)?;
    Ok(answer)
}

pub(super) fn get_manifest(registry: &mut Registry, args: ManifestArgs) -> Result<Value, Failure> {
    match args.mode.as_deref() {
        None | Some("summary") => {}
        Some("xml") => return get_manifest_xml(registry, args),
        Some(_) => return Err(invalid("mode must be summary or xml")),
    }
    let limit = args.limit.unwrap_or(MAX_MANIFEST_LIMIT);
    if !(1..=MAX_MANIFEST_LIMIT).contains(&limit) {
        return Err(invalid(format!(
            "limit must be between 1 and {MAX_MANIFEST_LIMIT}"
        )));
    }
    let ms = deadline(args.timeout_ms, &registry.config)?;
    let budget = args
        .max_bytes
        .map_or(registry.config.max_result_bytes, |b| {
            b.min(registry.config.max_result_bytes)
        });
    let dataset = registry.find(&args.dataset_id)?;
    let id = args.dataset_id.clone();
    let wrong = |code: ErrorCode, message: &str, kind: &str| {
        Failure::Execution(with_kind(
            refuse(code, message).detail("mcp.dataset_id", id.as_str()),
            kind,
        ))
    };
    let archives = dataset.archive_inputs();
    let input_index = match (args.input_index, archives.as_slice()) {
        (Some(wanted), _) => usize::try_from(wanted).unwrap_or(usize::MAX),
        (None, [only]) => *only,
        (None, []) => {
            return Err(wrong(
                ErrorCode::InvalidArgument,
                "this dataset has no archive input, so it has no manifest",
                "not_archive",
            ));
        }
        (None, _) => return Err(resource_tools::ambiguous_input(&archives)),
    };
    let work = move || -> Result<manifest::Summary, ManifestFailure> {
        let document = dataset.manifest(input_index)?;
        Ok(manifest::summarize(&document)?)
    };
    let summary = match with_deadline(ms, work) {
        Outcome::Done(Ok(summary)) => summary,
        Outcome::Done(Err(ManifestFailure::NoSuchInput(message))) => {
            return Err(wrong(ErrorCode::InvalidArgument, &message, "not_archive"));
        }
        Outcome::Done(Err(ManifestFailure::Missing(message))) => {
            return Err(wrong(ErrorCode::InvalidInput, &message, "not_found"));
        }
        Outcome::Done(Err(ManifestFailure::Several(message))) => {
            return Err(wrong(ErrorCode::AmbiguousEntity, &message, "ambiguous"));
        }
        Outcome::Done(Err(ManifestFailure::Error(error))) => {
            return Err(error.detail("mcp.dataset_id", id.as_str()).into());
        }
        Outcome::TimedOut => {
            registry.close(&id);
            return Err(refuse(
                ErrorCode::DeadlineExceeded,
                "running computation was terminated and this dataset was closed; call open_dataset to use it again",
            )
            .detail("deadline_ms", ms.to_string())
            .detail("mcp.dataset_id", id.as_str())
            .detail("mcp.dataset_closed", "true")
            .into());
        }
        Outcome::Panicked => {
            registry.close(&id);
            return Err(panicked("get_manifest")
                .detail("mcp.dataset_id", id.as_str())
                .detail("mcp.dataset_closed", "true")
                .into());
        }
    };
    let total = summary.permissions.len() as u64;
    if args.offset > total {
        return Err(wrong(
            ErrorCode::InvalidArgument,
            "offset is past the last permission row",
            "invalid_range",
        ));
    }
    let end = total.min(args.offset.saturating_add(limit));
    let rows = &summary.permissions[args.offset as usize..end as usize];
    let next_offset = (end < total).then_some(end);
    let output = json!({
        "application": summary.application,
        "component_counts": summary.component_counts,
        "dataset_id": id,
        "input_index": input_index,
        "manifest": summary.manifest,
        "next_offset": next_offset,
        "offset": args.offset,
        "permissions": rows,
        "target_sdk": summary.target_sdk,
        "total_rows": total,
        "truncated": next_offset.is_some(),
        "uses_sdk": summary.uses_sdk,
    });
    let size = serde_json::to_string(&output)
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?
        .len() as u64;
    if size > budget {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail("budget", "max_bytes")
        .detail("limit", budget.to_string())
        .detail("observed", size.to_string())
        .into());
    }
    Ok(output)
}
