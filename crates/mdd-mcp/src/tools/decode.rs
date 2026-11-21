use super::*;

// ---- decode -------------------------------------------------------------------

pub const MAX_LINES: u64 = 1000;
pub const DEFAULT_LINES: u64 = 200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecodeArgs {
    dataset_id: String,
    class: Option<String>,
    file_id: Option<u32>,
    max_bytes: Option<u64>,
    max_lines: Option<u64>,
    method: Option<String>,
    method_idx: Option<u32>,
    method_limit: Option<u64>,
    #[serde(default)]
    method_offset: u64,
    mode: Option<String>,
    #[serde(default)]
    offset: u64,
    timeout_ms: Option<u64>,
}

pub(super) fn decode_error(error: MddError, dataset_id: &str) -> MddError {
    for_dataset(error, dataset_id).detail(HINT_DECODE, "true")
}

/// `{0, 1}`, the way the reference lists the DEX files that define one descriptor.
pub(super) fn file_id_set(ids: &[u32]) -> String {
    let inner: Vec<String> = ids.iter().map(u32::to_string).collect();
    format!("{{{}}}", inner.join(", "))
}

/// What a decode request shows of each method it selects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DecodeMode {
    Summary,
    Smali,
    Context,
}

impl DecodeMode {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Smali => "smali",
            Self::Context => "context",
        }
    }

    /// The version of the text this mode shows, `None` for a mode that shows no text.
    pub(super) fn text_format(self) -> Option<&'static str> {
        match self {
            Self::Summary => None,
            Self::Smali => Some(smali::SMALI_FORMAT),
            Self::Context => Some(smali::CONTEXT_FORMAT),
        }
    }
}

/// The reference's default of `method_limit`.
pub const DEFAULT_METHOD_LIMIT: u64 = 20;
pub const MAX_METHOD_LIMIT: u64 = 50;

pub(super) const CLASS_TEXT_PAGE: &str =
    "continue a class method's text page using its file_id and method_idx, not a class selector";

pub(super) fn decode_method(registry: &mut Registry, args: DecodeArgs) -> Result<Value, Failure> {
    let requested = match args.mode.as_deref() {
        None => None,
        Some("smali") => Some(DecodeMode::Smali),
        Some("summary") => Some(DecodeMode::Summary),
        Some("context") => Some(DecodeMode::Context),
        Some(_) => return Err(invalid("mode must be summary, smali or context")),
    };
    // A class shows its methods' metadata unless asked for more, a method its text.
    let mode = requested.unwrap_or(if args.class.is_some() {
        DecodeMode::Summary
    } else {
        DecodeMode::Smali
    });
    let max_lines = args.max_lines.unwrap_or(DEFAULT_LINES);
    if !(1..=MAX_LINES).contains(&max_lines) {
        return Err(invalid(format!(
            "max_lines must be between 1 and {MAX_LINES}"
        )));
    }
    if args.method_limit.is_some_and(|n| !(1..=50).contains(&n)) {
        return Err(invalid("method_limit must be between 1 and 50"));
    }
    let ms = deadline(args.timeout_ms, &registry.config)?;
    let id = args.dataset_id.clone();
    let refuse_here = |code: ErrorCode, message: &str| decode_error(refuse(code, message), &id);
    let selectors = u8::from(args.method.is_some())
        + u8::from(args.method_idx.is_some())
        + u8::from(args.class.is_some());
    if selectors != 1 {
        return Err(refuse_here(
            ErrorCode::InvalidArgument,
            "give exactly one of method, method_idx (with file_id) or class",
        )
        .into());
    }
    if args.method_idx.is_some() && args.file_id.is_none() {
        return Err(refuse_here(ErrorCode::InvalidArgument, "method_idx needs file_id").into());
    }
    if args.method.as_deref() == Some("") || args.class.as_deref() == Some("") {
        return Err(refuse_here(ErrorCode::InvalidArgument, "descriptor must not be empty").into());
    }
    if let Some(class) = args.class.clone() {
        // A text page is continued on its method, with `file_id`, `method_idx` and `offset`: the
        // methods of a class page come by `method_offset`, and one `offset` cannot continue
        // them all.
        if args.offset != 0 {
            return Err(refuse_here(ErrorCode::InvalidArgument, CLASS_TEXT_PAGE).into());
        }
        return decode_class(registry, &args, &class, mode, max_lines, ms);
    }
    if mode == DecodeMode::Summary && args.offset != 0 {
        return Err(refuse_here(
            ErrorCode::InvalidArgument,
            "offset applies to the smali text; summary has none",
        )
        .into());
    }
    if args.method_offset != 0 {
        return Err(refuse_here(
            ErrorCode::InvalidArgument,
            "method_offset applies to a class's method list; a method has one page of methods",
        )
        .into());
    }
    let dataset = registry.find(&args.dataset_id)?;
    require_dex(&dataset, &args.dataset_id)?;
    let cached = registry.decode_cache(&id);
    let method = args.method.clone();
    let (file_id, method_idx) = (args.file_id, args.method_idx);
    let work = move || -> Result<Arc<Decoded>, decode::Failure> {
        let selector = match (&method, method_idx) {
            (Some(descriptor), _) => Selector::Descriptor {
                descriptor,
                file_id,
            },
            (None, Some(method_idx)) => Selector::Key {
                file_id: file_id.expect("checked: method_idx comes with file_id"),
                method_idx,
            },
            (None, None) => unreachable!("checked: exactly one selector"),
        };
        let located = decode::select(&dataset, selector)?;
        if let Some((cached_file, cached_idx, decoded)) = cached
            && (cached_file, cached_idx) == (located.file_id, located.method_idx)
        {
            return Ok(decoded);
        }
        Ok(Arc::new(decode::render(
            &dataset,
            located,
            SmaliLimits::default(),
        )?))
    };
    let result = match with_deadline(ms, work) {
        Outcome::Done(result) => result,
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
            return Err(panicked("decode")
                .detail("mcp.dataset_id", id.as_str())
                .detail("mcp.dataset_closed", "true")
                .into());
        }
    };
    let decoded = match result {
        Ok(decoded) => decoded,
        Err(decode::Failure::NotFound { what }) => {
            // The request is echoed the way the reference does, so a client can tell which of
            // its requests was not found.
            let mut error = with_kind(refuse_here(ErrorCode::InvalidArgument, &what), "not_found");
            if let Some(file_id) = args.file_id {
                error = error.detail("file_id", file_id.to_string());
            }
            if let Some(method_idx) = args.method_idx {
                error = error.detail("method_idx", method_idx.to_string());
            }
            return Err(error.into());
        }
        Err(decode::Failure::Ambiguous { file_ids }) => {
            return Err(with_kind(
                refuse_here(
                    ErrorCode::AmbiguousEntity,
                    &format!(
                        "method occurs in multiple DEX files; supply file_id from {}",
                        file_id_set(&file_ids)
                    ),
                ),
                "ambiguous",
            )
            .into());
        }
        Err(decode::Failure::Error(error)) => {
            let mut error = decode_error(error, &id);
            if let Some(file_id) = args.file_id {
                error = error.detail("file_id", file_id.to_string());
            }
            if let Some(method_idx) = args.method_idx {
                error = error.detail("method_idx", method_idx.to_string());
            }
            return Err(error.into());
        }
    };
    registry.set_decode_cache(
        &id,
        decoded.file_id,
        decoded.method_idx,
        Arc::clone(&decoded),
    );
    let rendered = &decoded.rendered;
    let mut method = json!({
        "access_flags": decoded.access_flags,
        "code_units": rendered.code_units,
        "declaration": rendered.declaration,
        "descriptor": decoded.descriptor,
        "file_id": decoded.file_id,
        "method_idx": decoded.method_idx,
        "registers": rendered.registers,
        "try_count": rendered.try_count,
    });
    if mode == DecodeMode::Summary {
        // The summary has no text to continue, but a client that follows `next_offset`
        // finds the key in every mode.
        if let Value::Object(fields) = &mut method {
            fields.insert("next_offset".to_owned(), Value::Null);
        }
    } else {
        let shown = text_of(mode, &rendered.text);
        let page = page_text(&shown.text, args.offset, max_lines, args.max_bytes)
            .map_err(|error| text_page_error(error, &id))?;
        let Value::Object(fields) = &mut method else {
            unreachable!("a json object");
        };
        fields.extend(text_fields(&page, shown.source_lines));
        if let Some(left_out) = omitted(&decoded.report) {
            fields.insert("omitted".to_owned(), left_out);
        }
    }
    let output = json!({
        "dataset_id": id,
        "method_offset": 0,
        "methods": [method],
        "mode": mode.name(),
        "next_method_offset": null,
        "text_format": mode.text_format(),
        "total_methods": 1,
    });
    let size = serde_json::to_string(&output)
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?
        .len() as u64;
    if size > registry.config.max_result_bytes {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail("budget", "max_result_bytes")
        .detail("limit", registry.config.max_result_bytes.to_string())
        .detail("observed", size.to_string())
        .into());
    }
    Ok(output)
}

/// The text a mode shows of a method's full smali text, and how many lines the full text has
/// when the shown text is a view of it (the numbers of a context line count lines of the full
/// text, not of the view).
pub(super) struct Shown<'a> {
    pub(super) text: std::borrow::Cow<'a, str>,
    pub(super) source_lines: Option<u64>,
}

pub(super) fn text_of(mode: DecodeMode, full: &str) -> Shown<'_> {
    match mode {
        DecodeMode::Context => Shown {
            text: std::borrow::Cow::Owned(smali::method_context(full)),
            source_lines: Some(full.split_terminator('\n').count() as u64),
        },
        _ => Shown {
            text: std::borrow::Cow::Borrowed(full),
            source_lines: None,
        },
    }
}

/// The keys one page of text adds to a method row. Each counts its own unit: `offset`,
/// `next_offset` and `total_bytes` are UTF-8 bytes of the shown text, the others are lines of it
/// (`source_total_lines`, in the context mode, is the line count of the full text that the
/// `line N:` numbers index).
pub(super) fn text_fields(
    page: &smali_required::TextPage<'_>,
    source_lines: Option<u64>,
) -> Vec<(String, Value)> {
    let mut fields = vec![
        ("end_line", json!(page.end_line)),
        ("ends_mid_line", json!(page.ends_mid_line)),
        ("next_offset", json!(page.next_offset)),
        ("offset", json!(page.offset)),
        ("smali", json!(page.text)),
        ("start_line", json!(page.start_line)),
        ("starts_mid_line", json!(page.starts_mid_line)),
        ("total_bytes", json!(page.total_bytes)),
        ("total_lines", json!(page.total_lines)),
    ];
    if let Some(lines) = source_lines {
        fields.push(("source_total_lines", json!(lines)));
    }
    fields
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// What a text leaves out of the method it shows, as a row key; `None` when it leaves out nothing.
/// A missing line is never silent: the facts have more than the text says, and this names how
/// much (the rest is in the SQL relations).
pub(super) fn omitted(report: &smali::ExtrasReport) -> Option<Value> {
    let mut fields = Map::new();
    for (key, count) in [
        (
            "debug_events_not_at_an_instruction",
            report.debug_events_unplaced,
        ),
        (
            "positions_not_source_lines",
            report.positions_not_source_lines,
        ),
        (
            "parameter_annotation_slots_unplaced",
            report.parameter_annotation_slots_unplaced,
        ),
    ] {
        if count != 0 {
            fields.insert(key.to_owned(), json!(count));
        }
    }
    if report.annotation_layer_missing {
        fields.insert("annotation_layer_missing".to_owned(), json!(true));
    }
    (!fields.is_empty()).then_some(Value::Object(fields))
}

/// Where a text page cannot start is a range problem; a byte budget no character fits in is a
/// problem with the argument.
pub(super) fn text_page_error(error: MddError, dataset_id: &str) -> MddError {
    let kind = if error.message.starts_with("OFFSET_") {
        "invalid_range"
    } else {
        "invalid_input"
    };
    with_kind(decode_error(error, dataset_id), kind)
}

/// What a class page shows of one method: the reference's `summary` row, and the method's
/// declaration line when the page shows text.
pub(super) fn summary_row(summary: &decode::Summary, with_declaration: bool) -> Value {
    let mut row = json!({
        "access_flags": summary.access_flags,
        "code_units": summary.code_units,
        "descriptor": summary.descriptor,
        "file_id": summary.file_id,
        "method_idx": summary.method_idx,
        "next_offset": null,
        "registers": summary.registers,
        "try_count": summary.try_count,
    });
    if with_declaration && let Value::Object(fields) = &mut row {
        fields.insert("declaration".to_owned(), json!(summary.declaration));
    }
    row
}

/// What the work of a class page hands back.
pub(super) struct ClassAnswer {
    page: decode::ClassPage,
    rows: Vec<Value>,
    /// The rendered class, its first page of text, the line that page ends at, the lines and
    /// bytes of the whole text, and whether the page is all of it.
    class_text: Option<(smali::RenderedClass, String, u64, u64, u64, bool)>,
}

/// The page of one class: its methods in `method_idx` order, `method_limit` of them from
/// `method_offset`, each shown the way `mode` says. In the text modes `max_bytes` is one budget
/// of UTF-8 bytes for the text of the whole page: a method that does not fit is cut where the
/// budget ends (its `next_offset` continues it, with `file_id` and `method_idx`), and the
/// methods after it are left to the next page.
pub(super) fn decode_class(
    registry: &mut Registry,
    args: &DecodeArgs,
    class: &str,
    mode: DecodeMode,
    max_lines: u64,
    ms: u64,
) -> Result<Value, Failure> {
    let id = args.dataset_id.clone();
    let dataset = registry.find(&args.dataset_id)?;
    require_dex(&dataset, &args.dataset_id)?;
    let class = class.to_owned();
    let (file_id, method_offset, max_bytes) = (args.file_id, args.method_offset, args.max_bytes);
    let limit = args.method_limit.unwrap_or(DEFAULT_METHOD_LIMIT);
    let work = move || -> Result<ClassAnswer, decode::Failure> {
        let located = decode::select_class(&dataset, &class, file_id)?;
        let page = decode::class_page(&dataset, located, method_offset, limit)?;
        // The class's own text comes with the first page of its methods and only in a text mode.
        let class_text = if mode != DecodeMode::Summary && method_offset == 0 {
            let rendered = decode::render_class_text(&dataset, located)?;
            let shown = match mode {
                DecodeMode::Context => smali::class_context(&rendered.text),
                _ => rendered.text.clone(),
            };
            let text_page = page_text(&shown, 0, max_lines, None)?;
            Some((
                rendered,
                text_page.text.to_owned(),
                text_page.end_line,
                text_page.total_lines,
                text_page.total_bytes,
                text_page.next_offset.is_some(),
            ))
        } else {
            None
        };
        let mut rows: Vec<Value> = Vec::new();
        let mut budget = max_bytes;
        for &method in &page.methods {
            if mode == DecodeMode::Summary {
                let row = summary_row(&decode::summarize(&dataset, method)?, false);
                // In this mode the budget counts the serialized bytes of the rows: there is no text.
                if let Some(left) = budget.as_mut() {
                    let size = row.to_string().len() as u64;
                    if size > *left && !rows.is_empty() {
                        break;
                    }
                    *left = left.saturating_sub(size);
                }
                rows.push(row);
                continue;
            }
            let decoded = decode::render(&dataset, method, SmaliLimits::default())?;
            let shown = text_of(mode, &decoded.rendered.text);
            let text_page = match page_text(&shown.text, 0, max_lines, budget) {
                Ok(text_page) => text_page,
                // the budget is used up: this method and the rest wait for the next page
                Err(error) if error.message == "MAX_BYTES_TOO_SMALL" && !rows.is_empty() => break,
                Err(error) => {
                    return Err(decode::Failure::Error(with_kind(error, "invalid_input")));
                }
            };
            if let Some(left) = budget.as_mut() {
                *left -= text_page.text.len() as u64;
            }
            let mut row = summary_row(
                &decode::Summary {
                    file_id: decoded.file_id,
                    method_idx: decoded.method_idx,
                    descriptor: decoded.descriptor.clone(),
                    access_flags: decoded.access_flags,
                    declaration: decoded.rendered.declaration.clone(),
                    registers: decoded.rendered.registers,
                    code_units: decoded.rendered.code_units,
                    try_count: decoded.rendered.try_count,
                },
                true,
            );
            if let Value::Object(fields) = &mut row {
                fields.extend(text_fields(&text_page, shown.source_lines));
                if let Some(left_out) = omitted(&decoded.report) {
                    fields.insert("omitted".to_owned(), left_out);
                }
            }
            rows.push(row);
        }
        Ok(ClassAnswer {
            page,
            rows,
            class_text,
        })
    };
    let result = match with_deadline(ms, work) {
        Outcome::Done(result) => result,
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
            return Err(panicked("decode")
                .detail("mcp.dataset_id", id.as_str())
                .detail("mcp.dataset_closed", "true")
                .into());
        }
    };
    let ClassAnswer {
        page,
        rows,
        class_text,
    } = match result {
        Ok(done) => done,
        Err(decode::Failure::NotFound { what }) => {
            let mut error = with_kind(
                decode_error(refuse(ErrorCode::InvalidArgument, &what), &id),
                "not_found",
            );
            if let Some(file_id) = args.file_id {
                error = error.detail("file_id", file_id.to_string());
            }
            return Err(error.into());
        }
        Err(decode::Failure::Ambiguous { file_ids }) => {
            return Err(with_kind(
                decode_error(
                    refuse(
                        ErrorCode::AmbiguousEntity,
                        &format!(
                            "class occurs in multiple DEX files; supply file_id from {}",
                            file_id_set(&file_ids)
                        ),
                    ),
                    &id,
                ),
                "ambiguous",
            )
            .into());
        }
        Err(decode::Failure::Error(error)) => {
            let kind = (error.message == decode::METHOD_OFFSET_PAST_END).then_some("invalid_range");
            let mut error = decode_error(error, &id);
            if let Some(kind) = kind {
                error = with_kind(error, kind);
            }
            if let Some(file_id) = args.file_id {
                error = error.detail("file_id", file_id.to_string());
            }
            return Err(error.into());
        }
    };
    let next_method_offset = page.method_offset + rows.len() as u64;
    let mut class_object = json!({
        "access_flags": page.access_flags,
        "class_def_idx": page.class_def_idx,
        "descriptor": page.descriptor,
        "file_id": page.file_id,
        "instance_fields": page.instance_fields,
        "interfaces": page.interfaces,
        "source_file": page.source_file,
        "static_fields": page.static_fields,
        "superclass": page.superclass,
    });
    if let (
        Some((rendered, text, end_line, total_lines, total_bytes, truncated)),
        Value::Object(fields),
    ) = (class_text, &mut class_object)
    {
        // The class text is one page: it is not continued, because `offset` continues a method.
        // The fields that do not fit are in the `fields` table.
        if rendered.annotation_layer_missing {
            fields.insert("annotation_layer_missing".to_owned(), json!(true));
        }
        for (key, value) in [
            ("declaration", json!(rendered.declaration)),
            ("end_line", json!(end_line)),
            ("smali", json!(text)),
            ("total_bytes", json!(total_bytes)),
            ("total_lines", json!(total_lines)),
            ("truncated", json!(truncated)),
        ] {
            fields.insert(key.to_owned(), value);
        }
    }
    let output = json!({
        "class": class_object,
        "dataset_id": id,
        "method_offset": page.method_offset,
        "methods": rows,
        "mode": mode.name(),
        "next_method_offset": (next_method_offset < page.total_methods).then_some(next_method_offset),
        "text_format": mode.text_format(),
        "total_methods": page.total_methods,
    });
    let size = serde_json::to_string(&output)
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?
        .len() as u64;
    if size > registry.config.max_result_bytes {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail("budget", "max_result_bytes")
        .detail("limit", registry.config.max_result_bytes.to_string())
        .detail("observed", size.to_string())
        .into());
    }
    Ok(output)
}
