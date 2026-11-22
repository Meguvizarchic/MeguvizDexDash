use super::*;
use std::io::Write;

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
#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

fn unrepresentable_cell(statement: usize, column: usize, what: &str) -> MddError {
    refuse(
        ErrorCode::UnsupportedCapability,
        "a cell cannot be represented in this response",
    )
    .detail("reason", what)
    .detail("statement_index", statement.to_string())
    .detail("column_index", column.to_string())
}

fn write_cell_json(
    buf: &mut Vec<u8>,
    value: &SqlValue,
    statement: usize,
    column: usize,
    scratch_text: &mut String,
) -> Result<(), MddError> {
    let json_err = |error: serde_json::Error| refuse(ErrorCode::InternalFault, &error.to_string());
    match value {
        SqlValue::Null => buf.extend_from_slice(br#"{"type":"null","value":null}"#),
        SqlValue::Bool(v) => buf.extend_from_slice(if *v {
            br#"{"type":"uint64","value":"1"}"#
        } else {
            br#"{"type":"uint64","value":"0"}"#
        }),
        SqlValue::I64(v) if v.0 >= 0 => {
            let _ = write!(buf, r#"{{"type":"uint64","value":"{}"}}"#, v.0);
        }
        SqlValue::I64(v) => {
            let _ = write!(buf, r#"{{"type":"int64","value":"{}"}}"#, v.0);
        }
        SqlValue::U64(v) => {
            let _ = write!(buf, r#"{{"type":"uint64","value":"{}"}}"#, v.0);
        }
        SqlValue::F64(bits) => {
            let number = f64::from_bits(bits.0);
            if number.is_nan() {
                buf.extend_from_slice(br#"{"type":"float64","value":"NaN"}"#);
            } else if number.is_infinite() {
                buf.extend_from_slice(if number > 0.0 {
                    br#"{"type":"float64","value":"Infinity"}"#
                } else {
                    br#"{"type":"float64","value":"-Infinity"}"#
                });
            } else {
                buf.extend_from_slice(br#"{"type":"float64","value":"#);
                serde_json::to_writer(&mut *buf, &number).map_err(json_err)?;
                buf.push(b'}');
            }
        }
        SqlValue::Text(text) => {
            scratch_text.clear();
            if text.utf16.iter().all(|&unit| unit < 0x80) {
                for &unit in &text.utf16 {
                    scratch_text.push(char::from(unit as u8));
                }
            } else {
                for decoded in char::decode_utf16(text.utf16.iter().copied()) {
                    match decoded {
                        Ok(ch) => scratch_text.push(ch),
                        Err(_) => {
                            return Err(unrepresentable_cell(
                                statement,
                                column,
                                "text holds an unpaired surrogate",
                            ));
                        }
                    }
                }
            }
            buf.extend_from_slice(br#"{"type":"utf8","value":"#);
            serde_json::to_writer(&mut *buf, scratch_text.as_str()).map_err(json_err)?;
            buf.push(b'}');
        }
        SqlValue::Bytes(bytes) => {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            buf.extend_from_slice(br#"{"type":"binary","value":""#);
            buf.reserve(bytes.len().saturating_mul(2).saturating_add(2));
            for &byte in bytes {
                buf.push(HEX[usize::from(byte >> 4)]);
                buf.push(HEX[usize::from(byte & 0x0f)]);
            }
            buf.extend_from_slice(br#""}"#);
        }
        SqlValue::DexMutf8 { .. } => {
            return Err(unrepresentable_cell(
                statement,
                column,
                "a DEX string reached the response unconverted",
            ));
        }
    }
    Ok(())
}

fn write_statement_json(
    buf: &mut Vec<u8>,
    index: usize,
    sql: &str,
    result: &TempStatementResult,
    scratch_text: &mut String,
) -> Result<(), MddError> {
    let json_err = |error: serde_json::Error| refuse(ErrorCode::InternalFault, &error.to_string());
    match result {
        TempStatementResult::Rows(result) => {
            let window = result.window().ok_or_else(|| {
                refuse(
                    ErrorCode::InternalFault,
                    "a windowed statement reported no window",
                )
            })?;
            buf.extend_from_slice(br#"{"columns":["#);
            for (i, name) in result.columns().iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                let (data_type, nullable) = column_shape(result.rows(), i);
                buf.extend_from_slice(br#"{"data_type":""#);
                buf.extend_from_slice(data_type.as_bytes());
                buf.extend_from_slice(br#"","name":"#);
                serde_json::to_writer(&mut *buf, name).map_err(json_err)?;
                let _ = write!(buf, r#","nullable":{nullable}}}"#);
            }
            buf.extend_from_slice(br#"],"kind":"query","next_offset":"#);
            match window.next_offset {
                Some(next) => {
                    let _ = write!(buf, "{next}");
                }
                None => buf.extend_from_slice(b"null"),
            }
            let _ = write!(buf, r#","offset":{},"rows":["#, window.offset);
            for (row_idx, row) in result.rows().iter().enumerate() {
                if row_idx > 0 {
                    buf.push(b',');
                }
                buf.push(b'[');
                for (col_idx, value) in row.iter().enumerate() {
                    if col_idx > 0 {
                        buf.push(b',');
                    }
                    write_cell_json(buf, value, index, col_idx, scratch_text)?;
                }
                buf.push(b']');
            }
            buf.extend_from_slice(br#"],"sql":"#);
            serde_json::to_writer(&mut *buf, sql).map_err(json_err)?;
            let total = window.total_rows.unwrap_or(window.offset + window.rows);
            let _ = write!(
                buf,
                r#","statement_index":{index},"total_rows":{total},"truncated":{}}}"#,
                window.truncated
            );
            Ok(())
        }
        TempStatementResult::Definition(report) => {
            buf.extend_from_slice(br#"{"columns":[],"kind":"#);
            serde_json::to_writer(&mut *buf, &report.kind).map_err(json_err)?;
            let _ = write!(
                buf,
                r#","next_offset":null,"offset":{},"rows":[],"sql":"#,
                report.window.offset
            );
            serde_json::to_writer(&mut *buf, sql).map_err(json_err)?;
            let _ = write!(
                buf,
                r#","statement_index":{index},"total_rows":0,"truncated":false}}"#
            );
            Ok(())
        }
    }
}

pub(super) fn query(registry: &mut Registry, args: QueryArgs) -> Result<CallResult, Failure> {
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
        move || -> Result<(Vec<u8>, f64), MddError> {
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
            let mut statements_json = Vec::with_capacity(512);
            let mut scratch_text = String::new();
            statements_json.push(b'[');
            for (index, (text, result)) in texts.iter().zip(&results).enumerate() {
                if index > 0 {
                    statements_json.push(b',');
                }
                write_statement_json(&mut statements_json, index, text, result, &mut scratch_text)?;
            }
            statements_json.push(b']');
            Ok((
                statements_json,
                sql_started.elapsed().as_secs_f64() * 1000.0,
            ))
        }
    };
    let (statements_json, sql_wall_ms) = match with_deadline(ms, work) {
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
    let json_err = |error: serde_json::Error| refuse(ErrorCode::InternalFault, &error.to_string());
    let mut out = Vec::with_capacity(statements_json.len().saturating_add(256));
    out.extend_from_slice(br#"{"dataset_id":"#);
    serde_json::to_writer(&mut out, &id).map_err(json_err)?;
    out.extend_from_slice(br#","diagnostics":[],"statements":"#);
    out.extend_from_slice(&statements_json);
    out.extend_from_slice(br#","timing":"#);
    serde_json::to_writer(&mut out, &timing).map_err(json_err)?;
    out.push(b'}');
    let size = out.len() as u64;
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
    let json = String::from_utf8(out)
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?;
    Ok(CallResult::Serialized(json))
}

#[cfg(test)]
mod zero_copy_tests {
    use super::*;
    use mdd_sql::{control::SqlLimits, values::SqlText};
    use mdd_types::DecimalU64;
    use std::path::PathBuf;

    #[test]
    fn write_cell_json_matches_cell_across_edge_cases() {
        let i64_val = |v: i64| -> SqlValue {
            serde_json::from_value(json!({"type": "i64", "value": v.to_string()})).unwrap()
        };
        let samples = [
            SqlValue::Null,
            SqlValue::Bool(false),
            SqlValue::Bool(true),
            i64_val(0),
            i64_val(i64::MAX),
            i64_val(-1),
            i64_val(i64::MIN),
            SqlValue::U64(DecimalU64(0)),
            SqlValue::U64(DecimalU64(u64::MAX)),
            SqlValue::F64(DecimalU64(f64::NAN.to_bits())),
            SqlValue::F64(DecimalU64(f64::INFINITY.to_bits())),
            SqlValue::F64(DecimalU64(f64::NEG_INFINITY.to_bits())),
            SqlValue::F64(DecimalU64((-0.0_f64).to_bits())),
            SqlValue::F64(DecimalU64(1.25_f64.to_bits())),
            SqlValue::text(""),
            SqlValue::text("ascii \"quote\" \\slash\n\r\t\u{0008}\u{000c}"),
            SqlValue::Text(SqlText {
                utf16: vec![0xd83d, 0xde00],
                original_mutf8: None,
            }),
            SqlValue::Bytes(vec![]),
            SqlValue::Bytes(vec![0, 0x0f, 0xab, 0xff]),
        ];
        let mut scratch = String::new();
        for (column, value) in samples.iter().enumerate() {
            let expected = serde_json::to_string(&cell(value, 2, column).unwrap()).unwrap();
            let mut actual = Vec::new();
            write_cell_json(&mut actual, value, 2, column, &mut scratch).unwrap();
            assert_eq!(String::from_utf8(actual).unwrap(), expected);
        }

        for bad in [
            SqlValue::Text(SqlText {
                utf16: vec![0x61, 0xd800],
                original_mutf8: None,
            }),
            SqlValue::DexMutf8 {
                bytes: vec![b'a'],
                utf16_code_units: DecimalU64(1),
            },
        ] {
            let expected = cell(&bad, 3, 2).unwrap_err();
            let mut actual = Vec::new();
            let err = write_cell_json(&mut actual, &bad, 3, 2, &mut scratch).unwrap_err();
            assert_eq!(err.code, expected.code);
            assert_eq!(err.message, expected.message);
            assert_eq!(
                err.details.get("statement_index"),
                expected.details.get("statement_index")
            );
            assert_eq!(
                err.details.get("column_index"),
                expected.details.get("column_index")
            );
        }
    }

    #[test]
    fn write_statement_json_matches_statement_json_for_rows_and_definitions() {
        let dex = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-038.dex");
        let dataset = Dataset::open_with_non_scalar_policy(
            &[InputRequest {
                path: dex,
                kind: None,
            }],
            Dialect::DexSql010,
            ResourceLimits::default(),
            SqlLimits::default(),
            NonScalarTextPolicy::Reject,
        )
        .unwrap();
        let sql = [
            "CREATE TEMP VIEW v AS SELECT class_idx, descriptor, source_file FROM classes",
            "SELECT class_idx, descriptor, source_file FROM v ORDER BY class_idx",
        ];
        let window = SqlWindow::new(0, 10).unwrap().counting_total();
        let texts = script_statements(&sql).unwrap();
        let results = dataset
            .temp()
            .unwrap()
            .execute_call(&sql, &[], Some(window))
            .unwrap();
        let mut scratch = String::new();
        for (index, (text, result)) in texts.iter().zip(&results).enumerate() {
            let expected =
                serde_json::to_string(&statement_json(index, text, result).unwrap()).unwrap();
            let mut actual = Vec::new();
            write_statement_json(&mut actual, index, text, result, &mut scratch).unwrap();
            assert_eq!(String::from_utf8(actual).unwrap(), expected);
        }
    }
}
