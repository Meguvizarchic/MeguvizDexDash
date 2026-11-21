use super::*;
use mdd_sql::values::SqlText;
use mdd_types::DecimalU64;

#[test]
fn each_decode_mode_names_the_text_it_shows_and_a_summary_names_none() {
    assert_eq!(DecodeMode::Summary.name(), "summary");
    assert_eq!(DecodeMode::Smali.name(), "smali");
    assert_eq!(DecodeMode::Context.name(), "context");
    assert_eq!(DecodeMode::Summary.text_format(), None);
    assert_eq!(DecodeMode::Smali.text_format(), Some("mdd.smali.v1"));
    assert_eq!(
        DecodeMode::Context.text_format(),
        Some("mdd.smali-context.v1")
    );
}

#[test]
fn the_context_of_a_text_counts_the_lines_of_the_full_text_beside_its_own() {
    let full = ".method a\n    .registers 1\n\n    :l\n    nop\n.end method\n";
    let shown = text_of(DecodeMode::Context, full);
    assert_eq!(shown.source_lines, Some(6));
    assert_eq!(
        shown.text.lines().count(),
        4,
        "the header and three anchor lines"
    );
    let plain = text_of(DecodeMode::Smali, full);
    assert_eq!(plain.source_lines, None);
    assert_eq!(plain.text, full);
}

#[test]
fn what_a_text_leaves_out_is_named_only_when_it_leaves_something_out() {
    assert_eq!(omitted(&smali::ExtrasReport::default()), None);
    let report = smali::ExtrasReport {
        debug_events_unplaced: 2,
        positions_not_source_lines: 0,
        parameter_annotation_slots_unplaced: 1,
        annotation_layer_missing: true,
    };
    assert_eq!(
        omitted(&report),
        Some(json!({
            "debug_events_not_at_an_instruction": 2,
            "parameter_annotation_slots_unplaced": 1,
            "annotation_layer_missing": true,
        }))
    );
}

#[test]
fn a_text_page_keeps_each_number_in_its_own_unit_and_names_the_full_texts_lines_apart() {
    let text = "é中\nab\n";
    let page = smali_required::page_text(text, 0, 1, None).unwrap();
    let fields: std::collections::BTreeMap<_, _> =
        text_fields(&page, Some(9)).into_iter().collect();
    assert_eq!(
        fields["next_offset"],
        json!(6),
        "é is two bytes and 中 three, then the newline"
    );
    assert_eq!(fields["total_bytes"], json!(9));
    assert_eq!(fields["total_lines"], json!(2));
    assert_eq!(
        (fields["start_line"].as_u64(), fields["end_line"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(fields["source_total_lines"], json!(9));
    assert!(
        !text_fields(&page, None)
            .iter()
            .any(|(key, _)| key == "source_total_lines")
    );
}

#[test]
fn a_text_page_error_is_a_range_error_for_an_offset_and_an_input_error_for_a_budget() {
    let offset = smali_required::page_text("abc\n", 99, 1, None).unwrap_err();
    let budget = smali_required::page_text("é\n", 0, 1, Some(1)).unwrap_err();
    let kind = |error: MddError| text_page_error(error, "ds").details["mcp.kind"].clone();
    assert_eq!(kind(offset), json!("invalid_range"));
    assert_eq!(kind(budget), json!("invalid_input"));
}

#[test]
fn a_class_row_has_no_text_keys_and_a_declaration_only_when_the_page_shows_text() {
    let summary = decode::Summary {
        file_id: 1,
        method_idx: 4,
        descriptor: "La;->f()V".to_owned(),
        access_flags: 9,
        declaration: ".method public static f()V".to_owned(),
        registers: None,
        code_units: None,
        try_count: None,
    };
    let row = summary_row(&summary, false);
    assert!(row.get("declaration").is_none());
    assert_eq!(row["next_offset"], Value::Null);
    assert_eq!(row["registers"], Value::Null, "no body is null, not zero");
    assert_eq!(
        summary_row(&summary, true)["declaration"],
        ".method public static f()V"
    );
}

fn text(units: Vec<u16>) -> SqlValue {
    SqlValue::Text(SqlText {
        utf16: units,
        original_mutf8: None,
    })
}

#[test]
fn cells_use_the_reference_shapes_and_keep_integers_exact() {
    assert_eq!(
        cell(&SqlValue::Null, 0, 0).unwrap(),
        json!({"type":"null","value":null})
    );
    assert_eq!(
        cell(&SqlValue::U64(DecimalU64(u64::MAX)), 0, 0).unwrap(),
        json!({"type":"uint64","value":"18446744073709551615"})
    );
    assert_eq!(
        cell(&SqlValue::text("é"), 0, 0).unwrap(),
        json!({"type":"utf8","value":"é"})
    );
    assert_eq!(
        cell(&SqlValue::Bytes(vec![0, 0xAB]), 0, 0).unwrap(),
        json!({"type":"binary","value":"00ab"})
    );
    assert_eq!(
        cell(&SqlValue::Bool(true), 0, 0).unwrap(),
        json!({"type":"uint64","value":"1"})
    );
}

#[test]
fn a_signed_integer_is_uint64_exactly_while_it_is_not_negative() {
    // Signed64 is private to the query crate; the wire form builds one.
    let signed = |v: i64| {
        let value: SqlValue =
            serde_json::from_value(json!({"type": "i64", "value": v.to_string()})).unwrap();
        assert!(matches!(value, SqlValue::I64(_)));
        cell(&value, 0, 0).unwrap()
    };
    assert_eq!(signed(0), json!({"type":"uint64","value":"0"}));
    assert_eq!(
        signed(i64::MAX),
        json!({"type":"uint64","value":"9223372036854775807"})
    );
    assert_eq!(signed(-1), json!({"type":"int64","value":"-1"}));
    assert_eq!(
        signed(i64::MIN),
        json!({"type":"int64","value":"-9223372036854775808"})
    );
}

#[test]
fn floats_that_json_cannot_carry_are_spelled_as_the_reference_spells_them() {
    let float = |value: f64| cell(&SqlValue::F64(DecimalU64(value.to_bits())), 0, 0).unwrap();
    assert_eq!(float(f64::NAN)["value"], "NaN");
    assert_eq!(float(f64::INFINITY)["value"], "Infinity");
    assert_eq!(float(f64::NEG_INFINITY)["value"], "-Infinity");
    assert_eq!(float(1.5)["value"], 1.5);
}

#[test]
fn text_that_has_no_utf8_form_is_an_error_naming_the_cell_not_a_substitute() {
    let error = cell(&text(vec![0x61, 0xd800]), 3, 2).unwrap_err();
    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
    assert_eq!(error.details["statement_index"], "3");
    assert_eq!(error.details["column_index"], "2");
    // a valid surrogate pair is fine
    assert_eq!(
        cell(&text(vec![0xd83d, 0xde00]), 0, 0).unwrap()["value"],
        "\u{1f600}"
    );
}

#[test]
fn a_column_shape_comes_from_its_values_and_says_so_when_it_has_none() {
    let rows = vec![
        vec![SqlValue::Null, SqlValue::Null, SqlValue::text("a")],
        vec![
            SqlValue::U64(DecimalU64(1)),
            SqlValue::Null,
            SqlValue::Bool(true),
        ],
    ];
    assert_eq!(column_shape(&rows, 0), ("uint64", true));
    assert_eq!(column_shape(&rows, 1), ("unknown", true));
    assert_eq!(column_shape(&rows, 2), ("mixed", false));
    assert_eq!(column_shape(&[], 0), ("unknown", false));
}

#[test]
fn a_deadline_is_never_longer_than_the_servers_and_never_zero() {
    let config = Config::default();
    assert_eq!(
        deadline(None, &config).unwrap(),
        config.operation_timeout_ms
    );
    assert_eq!(deadline(Some(5), &config).unwrap(), 5);
    assert_eq!(
        deadline(Some(config.operation_timeout_ms), &config).unwrap(),
        config.operation_timeout_ms,
        "asking for exactly the server's timeout is allowed"
    );
    assert!(deadline(Some(0), &config).is_err());
    assert!(deadline(Some(config.operation_timeout_ms + 1), &config).is_err());
}

#[test]
fn work_that_outlives_its_deadline_is_reported_and_work_that_panics_is_too() {
    assert!(matches!(with_deadline(5_000, || 7), Outcome::Done(7)));
    let slow = with_deadline(10, || {
        thread::sleep(Duration::from_millis(500));
        1
    });
    assert!(matches!(slow, Outcome::TimedOut));
    let broken = with_deadline(5_000, || -> u8 { panic!("injected") });
    assert!(matches!(broken, Outcome::Panicked));
}

#[test]
fn the_embedded_schemas_cover_exactly_the_registered_tools() {
    let definitions = definitions();
    let names: Vec<&str> = definitions
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, DESCRIPTIONS.map(|(name, _)| name));
    let embedded = schemas();
    assert_eq!(embedded.as_object().unwrap().len(), DESCRIPTIONS.len());
}

#[test]
fn a_dataset_that_is_not_open_is_refused_in_one_set_of_words() {
    // Never minted and closed are the same to a client: not open.
    let registry = Registry::new(Config::default());
    let error = registry.find("dataset-9").err().unwrap();
    assert_eq!(
        error.message,
        "dataset \"dataset-9\" is not open; call open_dataset first"
    );
    let rendered = error_result(&error);
    assert_eq!(rendered["error"]["kind"], "unknown_dataset");
    assert!(rendered.get("dataset_id").is_none());
    assert!(
        rendered["error"]["details"].get("kind").is_none(),
        "the kind moved out of the details"
    );
}

#[test]
fn an_error_renders_the_references_fields_and_keeps_this_engines_own() {
    let timeout = timed_out("query", 7)
        .detail("mcp.dataset_id", "dataset-3")
        .detail("mcp.dataset_closed", "true");
    let rendered = error_result(&timeout);
    assert_eq!(rendered["dataset_id"], "dataset-3");
    assert_eq!(rendered["error"]["kind"], "timeout");
    assert_eq!(rendered["error"]["dataset_closed"], true);
    assert_eq!(rendered["error"]["code"], "DEADLINE_EXCEEDED");
    assert_eq!(rendered["error"]["details"]["deadline_ms"], "7");
    assert!(
        rendered["error"]["details"].get("dataset_closed").is_none()
            && rendered["error"]["details"].get("dataset_id").is_none(),
        "lifted fields are not repeated in the details"
    );

    let statement =
        refuse(ErrorCode::UnsupportedQuery, "no such table").detail("statement_index", "4");
    let rendered = error_result(&statement);
    assert_eq!(rendered["error"]["kind"], "invalid_query");
    assert_eq!(rendered["error"]["statement_index"], 4);
    assert_eq!(rendered["error"]["details"]["statement_index"], "4");

    let unknown = refuse(ErrorCode::InvalidArgument, "UNKNOWN_RELATION").detail("relation", "base");
    assert_eq!(
        error_result(&unknown)["error"]["message"],
        "unknown relation `base`"
    );

    let plain = refuse(ErrorCode::InvalidInput, "bad");
    let rendered = error_result(&plain);
    assert_eq!(rendered["error"]["kind"], "invalid_input");
    assert!(rendered["error"].get("dataset_closed").is_none());
    assert!(rendered["error"].get("statement_index").is_none());
    assert!(rendered.get("dataset_id").is_none());
}

#[test]
fn a_detail_a_lower_layer_calls_kind_is_not_the_errors_kind() {
    // the DEX debug decoder sets a detail named "kind"; it must reach the client as a detail
    let lower = refuse(ErrorCode::InvalidInput, "BAD_DEBUG")
        .detail("kind", "position")
        .detail("dataset_id", "inner")
        .detail("dataset_closed", "true")
        .detail("file_id", "3");
    let rendered = error_result(&lower);
    assert_eq!(rendered["error"]["kind"], "invalid_input");
    assert_eq!(rendered["error"]["details"]["kind"], "position");
    assert_eq!(rendered["error"]["details"]["dataset_id"], "inner");
    assert_eq!(rendered["error"]["details"]["dataset_closed"], "true");
    assert_eq!(rendered["error"]["details"]["file_id"], "3");
    assert!(rendered.get("dataset_id").is_none());
    assert!(rendered["error"].get("dataset_closed").is_none());
    assert!(rendered["error"].get("file_id").is_none());
}

#[test]
fn the_session_quota_speaks_in_the_references_words() {
    let rendered = error_result(&session_quota());
    assert_eq!(rendered["error"]["kind"], "session_quota_exceeded");
    assert_eq!(
        rendered["error"]["message"],
        "dataset/input-byte quota exhausted; close unused datasets before opening another"
    );
    assert_eq!(rendered["error"]["code"], "QUOTA_EXCEEDED");
}
