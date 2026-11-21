use super::*;

// ---- tables -------------------------------------------------------------------

pub(super) fn type_name(kind: SqlType) -> &'static str {
    match kind {
        SqlType::Bool | SqlType::I64 => "int64",
        SqlType::U64 => "uint64",
        SqlType::F64 => "float64",
        SqlType::Text => "utf8",
        SqlType::Bytes => "binary",
    }
}

pub(super) fn list_tables(dialect: SqlDialect) -> Value {
    let tables: Vec<Value> = compatibility::advertised_relations(dialect)
        .iter()
        .map(|relation| {
            json!({
                "name": relation.name(),
                "kind": "table",
                "column_count": relation.columns().len(),
            })
        })
        .collect();
    json!({"tables": tables})
}

pub(super) fn describe_table(dialect: SqlDialect, args: DescribeArgs) -> Result<Value, Failure> {
    let relation = compatibility::advertised_relations(dialect)
        .into_iter()
        .find(|relation| relation.name().eq_ignore_ascii_case(&args.name))
        .ok_or_else(|| {
            Failure::Execution(with_kind(
                refuse(ErrorCode::InvalidArgument, "UNKNOWN_TABLE")
                    .detail("name", args.name.clone()),
                "unknown_table",
            ))
        })?;
    let columns: Vec<Value> = relation
        .columns()
        .iter()
        .map(|(name, kind, nullable)| json!({"name": name, "data_type": type_name(*kind), "nullable": nullable}))
        .collect();
    let layers: Vec<Value> = relation
        .required_layers()
        .iter()
        .filter_map(|layer| serde_json::to_value(layer).ok())
        .collect();
    Ok(json!({"name": relation.name(), "kind": "table", "columns": columns, "fact_layers": layers}))
}

// ---- query --------------------------------------------------------------------

/// One cell in the reference's `Cell` shape. A value JSON cannot carry exactly is an
/// error, never a substitute: text with an unpaired surrogate has no UTF-8 form.
pub(super) fn cell(value: &SqlValue, statement: usize, column: usize) -> Result<Value, MddError> {
    let unrepresentable = |what: &str| {
        refuse(
            ErrorCode::UnsupportedCapability,
            "a cell cannot be represented in this response",
        )
        .detail("reason", what)
        .detail("statement_index", statement.to_string())
        .detail("column_index", column.to_string())
    };
    Ok(match value {
        SqlValue::Null => json!({"type": "null", "value": null}),
        // The reference tags every integer it returned as uint64 while it is not negative:
        // 3,904 recorded cells, none of them int64. A negative integer cannot be uint64.
        SqlValue::Bool(v) => json!({"type": "uint64", "value": i64::from(*v).to_string()}),
        SqlValue::I64(v) if v.0 >= 0 => json!({"type": "uint64", "value": v.0.to_string()}),
        SqlValue::I64(v) => json!({"type": "int64", "value": v.0.to_string()}),
        SqlValue::U64(v) => json!({"type": "uint64", "value": v.0.to_string()}),
        SqlValue::F64(bits) => {
            let number = f64::from_bits(bits.0);
            let value = if number.is_nan() {
                json!("NaN")
            } else if number.is_infinite() {
                json!(if number > 0.0 {
                    "Infinity"
                } else {
                    "-Infinity"
                })
            } else {
                json!(number)
            };
            json!({"type": "float64", "value": value})
        }
        SqlValue::Text(text) => match String::from_utf16(&text.utf16) {
            Ok(text) => json!({"type": "utf8", "value": text}),
            Err(_) => return Err(unrepresentable("text holds an unpaired surrogate")),
        },
        SqlValue::Bytes(bytes) => json!({"type": "binary", "value": hex(bytes)}),
        SqlValue::DexMutf8 { .. } => {
            return Err(unrepresentable(
                "a DEX string reached the response unconverted",
            ));
        }
    })
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `(data_type, nullable)` of a result column, from the values it holds. The result
/// does not carry declared types, so a column with no value says so.
pub(super) fn column_shape(rows: &[Vec<SqlValue>], column: usize) -> (&'static str, bool) {
    let mut kind: Option<&'static str> = None;
    let mut nullable = false;
    for row in rows {
        let found = match &row[column] {
            SqlValue::Null => {
                nullable = true;
                continue;
            }
            SqlValue::Bool(_) => "uint64",
            SqlValue::I64(v) if v.0 >= 0 => "uint64",
            SqlValue::I64(_) => "int64",
            SqlValue::U64(_) => "uint64",
            SqlValue::F64(_) => "float64",
            SqlValue::Text(_) | SqlValue::DexMutf8 { .. } => "utf8",
            SqlValue::Bytes(_) => "binary",
        };
        kind = match kind {
            None => Some(found),
            Some(previous) if previous == found => Some(previous),
            Some(_) => Some("mixed"),
        };
    }
    (kind.unwrap_or("unknown"), nullable)
}

pub(super) fn statement_json(
    index: usize,
    sql: &str,
    result: &TempStatementResult,
) -> Result<Value, MddError> {
    match result {
        TempStatementResult::Rows(result) => {
            let window = result.window().ok_or_else(|| {
                refuse(
                    ErrorCode::InternalFault,
                    "a windowed statement reported no window",
                )
            })?;
            let columns: Vec<Value> = result
                .columns()
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let (data_type, nullable) = column_shape(result.rows(), i);
                    json!({"name": name, "data_type": data_type, "nullable": nullable})
                })
                .collect();
            let mut rows = Vec::with_capacity(result.rows().len());
            for row in result.rows() {
                let cells: Result<Vec<Value>, MddError> = row
                    .iter()
                    .enumerate()
                    .map(|(i, v)| cell(v, index, i))
                    .collect();
                rows.push(Value::Array(cells?));
            }
            Ok(json!({
                "statement_index": index,
                "sql": sql,
                "kind": "query",
                "columns": columns,
                "rows": rows,
                "total_rows": window.total_rows.unwrap_or(window.offset + window.rows),
                "truncated": window.truncated,
                "offset": window.offset,
                "next_offset": window.next_offset,
            }))
        }
        TempStatementResult::Definition(report) => Ok(json!({
            "statement_index": index,
            "sql": sql,
            "kind": report.kind,
            "columns": [],
            "rows": [],
            "total_rows": 0,
            "truncated": false,
            "offset": report.window.offset,
            "next_offset": null,
        })),
    }
}

pub(super) fn query(registry: &mut Registry, args: QueryArgs) -> Result<Value, Failure> {
    let call_started = Instant::now();
    if args.sql.is_empty() || args.sql.len() > MAX_SQL_ITEMS {
        return Err(invalid(format!(
            "sql must hold between 1 and {MAX_SQL_ITEMS} statements"
        )));
    }
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(invalid(format!("limit must be between 1 and {MAX_LIMIT}")));
    }
    if args
        .offset
        .checked_add(limit)
        .is_none_or(|end| end > MAX_WINDOW_END)
    {
        return Err(invalid(format!(
            "offset + limit must be at most {MAX_WINDOW_END}"
        )));
    }
    if args.named_temp_queries.len() > MAX_NAMED_TEMP_QUERIES {
        return Err(invalid(format!(
            "named_temp_queries holds at most {MAX_NAMED_TEMP_QUERIES} entries"
        )));
    }
    let ms = deadline(args.timeout_ms, &registry.config)?;
    let budget = args
        .max_bytes
        .map_or(registry.config.max_result_bytes, |b| {
            b.min(registry.config.max_result_bytes)
        });
    let dataset = registry.find(&args.dataset_id)?;
    require_dex(&dataset, &args.dataset_id)?;
    let window = SqlWindow::new(args.offset, limit)?.counting_total();
    let id = args.dataset_id.clone();
    let work = {
        let sql = args.sql;
        let named = args.named_temp_queries;
        move || -> Result<(Vec<Value>, f64), MddError> {
            let sql_started = Instant::now();
            let items: Vec<&str> = sql.iter().map(String::as_str).collect();
            let named: Vec<NamedTempQuery<'_>> = named
                .iter()
                .map(|n| NamedTempQuery {
                    name: &n.name,
                    sql: &n.sql,
                })
                .collect();
            let texts = script_statements(&items)?;
            let results = dataset.temp()?.execute_call(&items, &named, Some(window))?;
            let statements = texts
                .iter()
                .zip(&results)
                .enumerate()
                .map(|(index, (text, result))| statement_json(index, text, result))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((statements, sql_started.elapsed().as_secs_f64() * 1000.0))
        }
    };
    let (statements, sql_wall_ms) = match with_deadline(ms, work) {
        Outcome::Done(result) => result?,
        Outcome::TimedOut => {
            // The statement cannot be stopped, so nothing may rely on this dataset any more.
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
            return Err(panicked("query")
                .detail("mcp.dataset_id", id.as_str())
                .detail("mcp.dataset_closed", "true")
                .into());
        }
    };
    let timing = if args.timing {
        // What happens once, at open_dataset, is not repeated per call and is reported as 0.
        json!({
            "cache_total_ms": 0.0,
            "load_inputs_ms": 0.0,
            "parse_ms": 0.0,
            "sql_wall_ms": sql_wall_ms,
            "table_build_ms": 0.0,
            "total_ms": call_started.elapsed().as_secs_f64() * 1000.0,
        })
    } else {
        Value::Null
    };
    let output =
        json!({"dataset_id": id, "statements": statements, "diagnostics": [], "timing": timing});
    let size = serde_json::to_string(&output)
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?
        .len() as u64;
    if size > budget {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail(
            "budget",
            if args
                .max_bytes
                .is_some_and(|b| b < registry.config.max_result_bytes)
            {
                "max_bytes"
            } else {
                "max_result_bytes"
            },
        )
        .detail("limit", budget.to_string())
        .detail("observed", size.to_string())
        .into());
    }
    Ok(output)
}
