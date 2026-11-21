use super::*;
use crate::control::SqlLimits;
use mdd_types::ErrorCode;

#[test]
fn udf_argument_materialization_preserves_text_and_bytes_values() {
    let db = Connection::open_in_memory().unwrap();
    let control = SqlControl::new(SqlLimits::default(), None);
    register(&db, SqlDialect::NativeV1, control).unwrap();
    let utf8: i64 = db
        .query_row("SELECT mdd_eq(?1, ?2)", ["A😀", "A😀"], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(utf8, 1);
    let lone = SqlValue::Text(SqlText {
        utf16: vec![0xd800, 0, 0xdc00],
        original_mutf8: None,
    })
    .sqlite(SqlLimits::default().max_cell_bytes)
    .unwrap();
    let same: i64 = db
        .query_row("SELECT mdd_eq(?1, ?2)", [&lone, &lone], |row| row.get(0))
        .unwrap();
    assert_eq!(same, 1);
    let raw = vec![0xc0, 0x80];
    let dex = SqlValue::DexMutf8 {
        bytes: raw.clone(),
        utf16_code_units: DecimalU64(1),
    }
    .sqlite(SqlLimits::default().max_cell_bytes)
    .unwrap();
    let bytes = SqlValue::Bytes(raw)
        .sqlite(SqlLimits::default().max_cell_bytes)
        .unwrap();
    let equivalent: i64 = db
        .query_row("SELECT mdd_eq(?1, ?2)", [&dex, &bytes], |row| row.get(0))
        .unwrap();
    assert_eq!(equivalent, 1);

    let db = Connection::open_in_memory().unwrap();
    let control = SqlControl::new(SqlLimits::default(), None);
    register(&db, SqlDialect::NativeV1, control.clone()).unwrap();
    assert!(
        db.query_row("SELECT mdd_eq(CAST(X'FF' AS TEXT), 'x')", [], |row| row
            .get::<_, i64>(0))
            .is_err()
    );
    let error = control.error().unwrap();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.message, "INVALID_UTF8_FROM_SQLITE");
}

#[test]
fn borrowed_text_length_keeps_utf16_errors_and_first_cancel() {
    let text = |units: &[u16]| {
        let mut carrier = TEXT.to_vec();
        for unit in units {
            carrier.extend_from_slice(&unit.to_be_bytes());
        }
        Cell::Blob(carrier)
    };
    let units = [0x61, 0xd800, 0xdc00, 0xdfff];
    for (dialect, expected) in [
        (SqlDialect::NativeV1, 4),
        (SqlDialect::DexSql010, 3),
        (SqlDialect::DexSql011, 3),
    ] {
        let db = Connection::open_in_memory().unwrap();
        let control = SqlControl::new(SqlLimits::default(), None);
        register(&db, dialect, control).unwrap();
        let actual: i64 = db
            .query_row("SELECT mdd_length(?1)", [text(&units)], |row| row.get(0))
            .unwrap();
        assert_eq!(actual, expected, "{dialect:?}");
    }
    for cancelled in [false, true] {
        let db = Connection::open_in_memory().unwrap();
        let control = SqlControl::new(SqlLimits::default(), None);
        register(&db, SqlDialect::NativeV1, control.clone()).unwrap();
        if cancelled {
            control.cancel().unwrap();
        }
        let bad = Cell::Blob([TEXT, &[0x31]].concat());
        assert!(
            db.query_row("SELECT mdd_length(?1)", [bad], |row| row.get::<_, i64>(0))
                .is_err()
        );
        assert_eq!(
            control.error().unwrap().code,
            if cancelled {
                ErrorCode::Cancelled
            } else {
                ErrorCode::InvalidArgument
            }
        );
    }
}

#[test]
fn empty_text_like_preserves_errors_null_and_cancellation() {
    let text = |units: &[u16]| {
        let mut carrier = TEXT.to_vec();
        for unit in units {
            carrier.extend_from_slice(&unit.to_be_bytes());
        }
        Cell::Blob(carrier)
    };
    for (input, escape, flag, expected) in [
        (text(&[]), Cell::Null, 0, Some(1)),
        (text(&[0xd800]), Cell::Null, 0, Some(0)),
        (Cell::Null, Cell::Null, 0, None),
        (text(&[]), text(&[b'\\' as u16]), 1, Some(1)),
        (text(&[]), Cell::Null, 1, None),
    ] {
        let db = Connection::open_in_memory().unwrap();
        let control = SqlControl::new(SqlLimits::default(), None);
        register(&db, SqlDialect::NativeV1, control).unwrap();
        let actual: Option<i64> = db
            .query_row(
                "SELECT mdd_like(?1, ?2, ?3, ?4)",
                rusqlite::params![input, text(&[]), escape, flag],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(actual, expected);
    }
    for (input, escape, flag, expected) in [
        (
            Cell::Blob([TEXT, &[0x31]].concat()),
            Cell::Null,
            0,
            "INVALID_TEXT_CARRIER",
        ),
        (text(&[]), Cell::Blob(vec![0xff]), 0, "UNTYPED_SQLITE_BLOB"),
        (
            text(&[]),
            text(&[b'a' as u16, b'b' as u16]),
            1,
            "LIKE_ESCAPE_REQUIRES_ONE_UTF16_UNIT",
        ),
    ] {
        let db = Connection::open_in_memory().unwrap();
        let control = SqlControl::new(SqlLimits::default(), None);
        register(&db, SqlDialect::NativeV1, control.clone()).unwrap();
        assert!(
            db.query_row(
                "SELECT mdd_like(?1, ?2, ?3, ?4)",
                rusqlite::params![input, text(&[]), escape, flag],
                |row| row.get::<_, Option<i64>>(0),
            )
            .is_err()
        );
        assert_eq!(control.error().unwrap().message, expected);
    }
    let db = Connection::open_in_memory().unwrap();
    let control = SqlControl::new(SqlLimits::default(), None);
    register(&db, SqlDialect::NativeV1, control.clone()).unwrap();
    control.cancel().unwrap();
    assert!(
        db.query_row(
            "SELECT mdd_like(?1, ?2, NULL, 0)",
            rusqlite::params![text(&[]), text(&[])],
            |row| row.get::<_, Option<i64>>(0)
        )
        .is_err()
    );
    assert_eq!(control.error().unwrap().code, ErrorCode::Cancelled);
}

#[test]
fn udf_argument_preflight_keeps_malformed_carrier_errors() {
    use rusqlite::types::Value as Cell;
    for (bytes, expected) in [
        (vec![0xff], "UNTYPED_SQLITE_BLOB"),
        ([TEXT, &[0x31]].concat(), "INVALID_TEXT_CARRIER"),
        (
            [b"\0MDDUINT1".as_slice(), &[1]].concat(),
            "INVALID_U64_CARRIER",
        ),
        (
            [b"\0MDDMUTF1".as_slice(), &[1]].concat(),
            "TRUNCATED_MUTF8_CARRIER",
        ),
        (
            [b"\0MDDMUTF1".as_slice(), &1u64.to_be_bytes(), &[0xff]].concat(),
            "INVALID_DEX_MUTF8_CARRIER",
        ),
    ] {
        let db = Connection::open_in_memory().unwrap();
        let control = SqlControl::new(SqlLimits::default(), None);
        register(&db, SqlDialect::NativeV1, control.clone()).unwrap();
        let result = db.query_row(
            "SELECT mdd_eq(?1, ?2)",
            [Cell::Blob(bytes), Cell::Integer(1)],
            |row| row.get::<_, Option<i64>>(0),
        );
        assert!(result.is_err());
        let error = control.error().unwrap();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.message, expected);
    }
}

#[test]
fn udf_argument_preflight_preserves_first_mutf8_error() {
    for (data, units, expected) in [
        (vec![0xff], 1u64, "INVALID_DEX_MUTF8_CARRIER"),
        (Vec::new(), 1u64, "DEX_MUTF8_UNIT_COUNT_MISMATCH"),
    ] {
        let db = Connection::open_in_memory().unwrap();
        let control = SqlControl::new(SqlLimits::default(), None);
        register(&db, SqlDialect::NativeV1, control.clone()).unwrap();
        let mut first = b"\0MDDMUTF1".to_vec();
        first.extend_from_slice(&units.to_be_bytes());
        first.extend_from_slice(&data);
        let later = [b"\0MDDUINT1".as_slice(), &[1]].concat();
        assert!(
            db.query_row(
                "SELECT mdd_eq(?1, ?2)",
                [Cell::Blob(first), Cell::Blob(later)],
                |row| row.get::<_, Option<i64>>(0),
            )
            .is_err()
        );
        let error = control.error().unwrap();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.message, expected);
    }
}

#[test]
fn truth_text_rejects_malformed_carrier_before_interpretation() {
    let db = Connection::open_in_memory().unwrap();
    let control = SqlControl::new(SqlLimits::default(), None);
    register(&db, SqlDialect::NativeV1, control.clone()).unwrap();
    let mut raw = TEXT.to_vec();
    raw.push(0x31); // A UTF-16 carrier must contain complete big-endian units.
    let result = db.query_row("SELECT mdd_truth_input(?1)", [Cell::Blob(raw)], |row| {
        row.get::<_, Option<i64>>(0)
    });
    assert!(result.is_err());
    let error = control.error().unwrap();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.message, "INVALID_TEXT_CARRIER");
}

#[test]
fn truth_utf8_checks_work_cancel_and_invalid_bytes() {
    let db = Connection::open_in_memory().unwrap();
    let reference = Connection::open_in_memory().unwrap();
    let control = SqlControl::new(SqlLimits::default(), None);
    register(&db, SqlDialect::NativeV1, control).unwrap();
    for input in ["", "0", "1", "1\0x", "-0.1", "1😀"] {
        let expected: i64 = reference
            .query_row("SELECT CASE WHEN ?1 THEN 1 ELSE 0 END", [input], |row| {
                row.get(0)
            })
            .unwrap();
        let actual: i64 = db
            .query_row(
                "SELECT CASE WHEN mdd_truth_input(?1) THEN 1 ELSE 0 END",
                [input],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(actual, expected, "{input:?}");
    }
    for (limits, cancelled, sql, expected) in [
        (
            SqlLimits {
                max_steps: 64,
                ..SqlLimits::default()
            },
            false,
            "SELECT mdd_truth_input(?1)",
            ErrorCode::QuotaExceeded,
        ),
        (
            SqlLimits::default(),
            true,
            "SELECT mdd_truth_input(?1)",
            ErrorCode::Cancelled,
        ),
        (
            SqlLimits::default(),
            false,
            "SELECT mdd_truth_input(CAST(X'FF' AS TEXT))",
            ErrorCode::InvalidArgument,
        ),
    ] {
        let db = Connection::open_in_memory().unwrap();
        let control = SqlControl::new(limits, None);
        register(&db, SqlDialect::NativeV1, control.clone()).unwrap();
        if cancelled {
            control.cancel().unwrap();
        }
        let outcome = if sql.contains("?1") {
            db.query_row(sql, [&"1".repeat(4096)], |row| row.get::<_, Option<i64>>(0))
        } else {
            db.query_row(sql, [], |row| row.get::<_, Option<i64>>(0))
        };
        assert!(outcome.is_err());
        assert_eq!(control.error().unwrap().code, expected);
    }
}

#[test]
fn truth_text_lease_survives_sqlite_to_sql_callback() {
    use mdd_query::budget::{BudgetLimits, BudgetPool, Resource};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    struct ObservedCell {
        inner: SqlCellWithWorkspaceLease,
        pool: BudgetPool,
        observed: Arc<AtomicU64>,
    }
    impl ToSql for ObservedCell {
        fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
            let used = self
                .pool
                .usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |value| value.0);
            self.observed.store(used, Ordering::Release);
            self.inner.to_sql()
        }
    }
    let pool = BudgetPool::global(
        "truth-to-sql-test".into(),
        BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 4096),
    )
    .unwrap();
    let observed = Arc::new(AtomicU64::new(0));
    let callback_pool = pool.clone();
    let callback_observed = Arc::clone(&observed);
    let db = Connection::open_in_memory().unwrap();
    db.create_scalar_function(
        "truth_lease_probe",
        0,
        FunctionFlags::SQLITE_UTF8,
        move |_| {
            let lease = callback_pool
                .reserve(Resource::QueryWorkspaceBytes, 64)
                .unwrap();
            Ok(ObservedCell {
                inner: SqlCellWithWorkspaceLease {
                    value: super::ReturnPayload::Cell(Cell::Text("1".to_owned())),
                    _workspace: Some(lease),
                },
                pool: callback_pool.clone(),
                observed: Arc::clone(&callback_observed),
            })
        },
    )
    .unwrap();
    let truth: i64 = db
        .query_row(
            "SELECT CASE WHEN truth_lease_probe() THEN 1 ELSE 0 END",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(truth, 1);
    assert_eq!(observed.load(Ordering::Acquire), 64);
    assert_eq!(
        pool.usage()
            .unwrap()
            .used
            .get(&Resource::QueryWorkspaceBytes)
            .map_or(0, |value| value.0),
        0
    );
}

#[test]
fn text_decode_obeys_step_budget_and_cancellation() {
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let limited = SqlControl::new(
            SqlLimits {
                max_steps: 8,
                ..SqlLimits::default()
            },
            None,
        );
        let value = SqlValue::Bytes(vec![b'A'; 256]);
        assert_eq!(
            cast(value.clone(), "text", dialect, &limited)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let cancelled = SqlControl::new(SqlLimits::default(), None);
        cancelled.cancel().unwrap();
        assert_eq!(
            cast(value, "text", dialect, &cancelled).unwrap_err().code,
            ErrorCode::Cancelled
        );
        let limited_mutf = SqlControl::new(
            SqlLimits {
                max_steps: 8,
                ..SqlLimits::default()
            },
            None,
        );
        let value = SqlValue::DexMutf8 {
            bytes: vec![b'A'; 256],
            utf16_code_units: DecimalU64(256),
        };
        assert_eq!(
            cast(value, "text", dialect, &limited_mutf)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let normal = SqlControl::new(SqlLimits::default(), None);
        assert_eq!(
            cast(SqlValue::Bytes(vec![0xff]), "text", dialect, &normal)
                .unwrap_err()
                .message,
            "CAST_TEXT_BAD_ENCODING"
        );
        let normal = SqlControl::new(SqlLimits::default(), None);
        assert_eq!(
            cast(SqlValue::Bytes(vec![0xe2, 0x82]), "text", dialect, &normal)
                .unwrap_err()
                .message,
            "CAST_TEXT_TRUNCATED_ENCODING"
        );
        let normal = SqlControl::new(SqlLimits::default(), None);
        let surrogate = SqlValue::DexMutf8 {
            bytes: vec![0xed, 0xa0, 0x80],
            utf16_code_units: DecimalU64(1),
        };
        assert_eq!(
            cast(surrogate, "text", dialect, &normal).unwrap(),
            SqlValue::Text(SqlText {
                utf16: vec![0xd800],
                original_mutf8: None,
            })
        );
    }
}

#[test]
fn text_and_bytes_comparisons_account_for_work() {
    let control = SqlControl::new(SqlLimits::default(), None);
    let text = |units| {
        SqlValue::Text(SqlText {
            utf16: units,
            original_mutf8: None,
        })
    };
    assert_eq!(
        compare(&text(vec![0, 0xd800]), &text(vec![0, 0xdfff]), &control).unwrap(),
        Ordering::Less
    );
    assert_eq!(
        compare(
            &SqlValue::Bytes(vec![0, 255]),
            &SqlValue::Bytes(vec![0, 255, 0]),
            &control
        )
        .unwrap(),
        Ordering::Less
    );
    assert_eq!(
        compare_literal(&SqlValue::Bytes(vec![1]), &text(vec![49]), &control).unwrap(),
        Ordering::Greater
    );
    for value in [text(vec![65; 128]), SqlValue::Bytes(vec![65; 128])] {
        let limited = SqlControl::new(
            SqlLimits {
                max_steps: 8,
                ..SqlLimits::default()
            },
            None,
        );
        assert_eq!(
            compare(&value, &value, &limited).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
        let cancelled = SqlControl::new(SqlLimits::default(), None);
        cancelled.cancel().unwrap();
        assert_eq!(
            compare(&value, &value, &cancelled).unwrap_err().code,
            ErrorCode::Cancelled
        );
    }
}

#[test]
fn legacy_integer_text_candidate_is_strict_and_budgeted() {
    for input in ["", " ", " \tword", "\0", "雪"] {
        let control = SqlControl::new(SqlLimits::default(), None);
        let value = SqlValue::text(input);
        assert_eq!(
            legacy_numeric_operand(&value, &control).unwrap().0.as_ref(),
            &SqlValue::I64(Signed64(0))
        );
    }
    for (input, expected) in [
        ("1", 1),
        ("+1", 1),
        (" -2 ", -2),
        ("-9223372036854775808", i64::MIN),
        ("9223372036854775807", i64::MAX),
    ] {
        let control = SqlControl::new(SqlLimits::default(), None);
        let value = SqlValue::text(input);
        let (result, exact) = legacy_numeric_operand(&value, &control).unwrap();
        assert!(exact);
        assert_eq!(result.as_ref(), &SqlValue::I64(Signed64(expected)));
    }
    for input in [
        ".5",
        "1.0",
        "1e2",
        "2x",
        "+",
        "9223372036854775808",
        "-9223372036854775809",
    ] {
        let control = SqlControl::new(SqlLimits::default(), None);
        let value = SqlValue::text(input);
        assert_eq!(
            legacy_numeric_operand(&value, &control).unwrap_err().code,
            ErrorCode::UnsupportedQuery
        );
    }
    let limited = SqlControl::new(
        SqlLimits {
            max_steps: 2,
            ..SqlLimits::default()
        },
        None,
    );
    assert_eq!(
        legacy_numeric_operand(&SqlValue::text("   x"), &limited)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let cancelled = SqlControl::new(SqlLimits::default(), None);
    cancelled.cancel().unwrap();
    assert_eq!(
        legacy_numeric_operand(&SqlValue::text("x"), &cancelled)
            .unwrap_err()
            .code,
        ErrorCode::Cancelled
    );
}

#[test]
fn legacy_concat_lossy_decoder_agrees_with_bounded_standard_oracle() {
    let tails: &[&[u8]] = &[
        &[],
        &[0x80],
        &[0xa9],
        &[0x41],
        &[0x9f, 0x98, 0x80],
        &[0xff, 0x80],
    ];
    for first in 0u8..=u8::MAX {
        for tail in tails {
            let mut bytes = vec![first];
            bytes.extend_from_slice(tail);
            let mut actual = Vec::new();
            legacy_concat_units(
                &SqlValue::Bytes(bytes.clone()),
                &SqlControl::new(SqlLimits::default(), None),
                |u| {
                    actual.push(u);
                    Ok(())
                },
            )
            .unwrap();
            let expected: Vec<_> = String::from_utf8_lossy(&bytes).encode_utf16().collect();
            assert_eq!(actual, expected, "{bytes:?}");
        }
    }
}

#[test]
fn legacy_concat_checks_steps_cell_limit_and_cancellation() {
    let values = [SqlValue::Bytes(vec![b'a'; 100]), SqlValue::text("b")];
    let limited = SqlControl::new(
        SqlLimits {
            max_steps: 16,
            ..SqlLimits::default()
        },
        None,
    );
    assert_eq!(
        legacy_concat(&values, &limited).err().unwrap().code,
        ErrorCode::QuotaExceeded
    );
    let cell = SqlControl::new(
        SqlLimits {
            max_cell_bytes: 6,
            ..SqlLimits::default()
        },
        None,
    );
    assert_eq!(
        legacy_concat(&values, &cell).err().unwrap().code,
        ErrorCode::QuotaExceeded
    );
    let cancelled = SqlControl::new(SqlLimits::default(), None);
    cancelled.cancel().unwrap();
    assert_eq!(
        legacy_concat(&values, &cancelled).err().unwrap().code,
        ErrorCode::Cancelled
    );
}

#[test]
fn concat_capacity_checks_addition_multiplication_and_cell_limit() {
    assert_eq!(concat_capacity(2, 2, 2, 8, "CONCAT_CELL_BYTES").unwrap(), 4);
    for (left, right, unit, max) in [
        (usize::MAX, 1, 1, u64::MAX),
        (usize::MAX, 0, u64::MAX, u64::MAX),
        (2, 3, 2, 9),
    ] {
        let error = concat_capacity(left, right, unit, max, "CONCAT_CELL_BYTES").unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
    }
}

#[test]
fn key_workspace_checked_amount_rejects_overflow() {
    let error = key_workspace_amount(u64::MAX).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(key_workspace_amount(1).unwrap(), 2 + BYTES.len() as u64);
}

#[test]
fn key_lease_survives_actual_rusqlite_to_sql_callback() {
    use mdd_query::budget::{BudgetLimits, BudgetPool, Resource};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    struct ObservedCell {
        inner: SqlCellWithWorkspaceLease,
        pool: BudgetPool,
        observed: Arc<AtomicU64>,
    }
    impl ToSql for ObservedCell {
        fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
            let used = self
                .pool
                .usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0);
            self.observed.store(used, Ordering::Release);
            self.inner.to_sql()
        }
    }

    let pool = BudgetPool::global(
        "key-to-sql-test".into(),
        BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8192),
    )
    .unwrap();
    let observed = Arc::new(AtomicU64::new(0));
    let callback_pool = pool.clone();
    let callback_observed = Arc::clone(&observed);
    let db = Connection::open_in_memory().unwrap();
    db.create_scalar_function(
        "key_lease_probe",
        0,
        FunctionFlags::SQLITE_UTF8,
        move |_| {
            let lease = callback_pool
                .reserve(Resource::QueryWorkspaceBytes, 64)
                .unwrap();
            Ok(ObservedCell {
                inner: SqlCellWithWorkspaceLease {
                    value: super::ReturnPayload::Cell(Cell::Blob(vec![0, 1, 0xff])),
                    _workspace: Some(lease),
                },
                pool: callback_pool.clone(),
                observed: Arc::clone(&callback_observed),
            })
        },
    )
    .unwrap();
    let copied: Vec<u8> = db
        .query_row("SELECT key_lease_probe()", [], |row| row.get(0))
        .unwrap();
    assert_eq!(copied, vec![0, 1, 0xff]);
    assert_eq!(observed.load(Ordering::Acquire), 64);
    assert_eq!(
        pool.usage()
            .unwrap()
            .used
            .get(&Resource::QueryWorkspaceBytes)
            .map_or(0, |v| v.0),
        0
    );
    // The SQLite/client copy can remain alive after the Rust lease drops;
    // this test does not claim that copy is covered by the reservation.
    assert_eq!(copied, vec![0, 1, 0xff]);
}

#[test]
fn scalar_minmax_comparisons_consume_step_budget() {
    let control = SqlControl::new(
        SqlLimits {
            max_steps: 2,
            ..SqlLimits::default()
        },
        None,
    );
    let arguments = vec![SqlValue::I64(Signed64(1)); 8];
    let error = scalar("mdd_min_scalar", &arguments, SqlDialect::NativeV1, &control).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
}

#[test]
fn empty_input_does_not_skip_long_pattern_step_budget() {
    let limits = SqlLimits {
        max_steps: 8,
        ..SqlLimits::default()
    };
    let control = SqlControl::new(limits, None);
    let value = SqlText {
        utf16: vec![],
        original_mutf8: None,
    };
    let pattern = SqlText {
        utf16: vec![u16::from(b'%'); 128],
        original_mutf8: None,
    };
    let error = like(&value, &pattern, None, SqlDialect::NativeV1, &control).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
}

#[test]
fn cancelled_empty_like_is_not_a_success() {
    let control = SqlControl::new(SqlLimits::default(), None);
    control.cancel().unwrap();
    let empty = SqlText {
        utf16: vec![],
        original_mutf8: None,
    };
    let error = like(&empty, &empty, None, SqlDialect::NativeV1, &control).unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
}

#[test]
fn trailing_escape_follows_selected_dialect_when_budget_sufficient() {
    let control = SqlControl::new(SqlLimits::default(), None);
    let empty = SqlText {
        utf16: vec![],
        original_mutf8: None,
    };
    let pattern = SqlText {
        utf16: vec![u16::from(b'!')],
        original_mutf8: None,
    };
    for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
        assert!(!like(&empty, &pattern, Some(u16::from(b'!')), dialect, &control).unwrap());
    }
    let error = like(
        &empty,
        &pattern,
        Some(u16::from(b'!')),
        SqlDialect::NativeV1,
        &control,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.message, "LIKE_DANGLING_ESCAPE");
}

#[test]
fn legacy_trailing_escape_does_not_hide_budget_or_cancel_errors() {
    let empty = SqlText {
        utf16: vec![],
        original_mutf8: None,
    };
    let pattern = SqlText {
        utf16: vec![u16::from(b'!')],
        original_mutf8: None,
    };
    for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
        let limited = SqlControl::new(
            SqlLimits {
                max_steps: 1,
                ..SqlLimits::default()
            },
            None,
        );
        let error = like(&empty, &pattern, Some(u16::from(b'!')), dialect, &limited).unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        let cancelled = SqlControl::new(SqlLimits::default(), None);
        cancelled.cancel().unwrap();
        let error = like(&empty, &pattern, Some(u16::from(b'!')), dialect, &cancelled).unwrap_err();
        assert_eq!(error.code, ErrorCode::Cancelled);
    }
}

#[test]
fn borrowed_udf_fast_paths_agree_with_scalar_reference() {
    let text_blob = |units: &[u16]| {
        let mut out = TEXT.to_vec();
        for u in units {
            out.extend_from_slice(&u.to_be_bytes());
        }
        Cell::Blob(out)
    };
    let uint_blob = |v: u64| {
        let mut out = crate::values::UNSIGNED.to_vec();
        out.extend_from_slice(&v.to_be_bytes());
        Cell::Blob(out)
    };

    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let db = Connection::open_in_memory().unwrap();
        let control = SqlControl::new(SqlLimits::default(), None);
        register(&db, dialect, control.clone()).unwrap();

        type Utf16LikeCase<'a> = (&'a [u16], &'a [u16], Option<u16>, i64);
        let cases: &[Utf16LikeCase<'_>] = &[
            (
                &[b'L' as u16, b'a' as u16, 0x0000, b'b' as u16],
                &[b'l' as u16, b'a' as u16, b'%' as u16],
                None,
                0,
            ),
            (
                &[b'p' as u16, b'_' as u16, b'q' as u16],
                &[b'p' as u16, b'X' as u16, b'q' as u16],
                None,
                0,
            ),
            (
                &[b'p' as u16, b'X' as u16, b'q' as u16],
                &[b'p' as u16, b'_' as u16, b'q' as u16],
                None,
                0,
            ),
            (&[0xd800, b'A' as u16], &[0xd800, b'a' as u16], None, 0),
        ];
        for &(val_u, pat_u, esc_u, flag) in cases {
            let v_cell = text_blob(val_u);
            let p_cell = text_blob(pat_u);
            let e_cell = esc_u.map_or(Cell::Null, |u| text_blob(&[u]));
            let sql_res: Option<i64> = db
                .query_row(
                    "SELECT mdd_like(?1, ?2, ?3, ?4)",
                    rusqlite::params![v_cell, p_cell, e_cell, flag],
                    |r| r.get(0),
                )
                .unwrap();
            let ref_res = like(
                &SqlText {
                    utf16: val_u.to_vec(),
                    original_mutf8: None,
                },
                &SqlText {
                    utf16: pat_u.to_vec(),
                    original_mutf8: None,
                },
                if flag != 0 { esc_u } else { None },
                dialect,
                &control,
            )
            .unwrap();
            assert_eq!(sql_res.unwrap() != 0, ref_res, "{dialect:?}");
        }

        // Trailing escape check uses its own SqlControl because a failing statement sticky-latches error state.
        let esc_db = Connection::open_in_memory().unwrap();
        let esc_control = SqlControl::new(SqlLimits::default(), None);
        register(&esc_db, dialect, esc_control.clone()).unwrap();
        let esc_sql = esc_db.query_row(
            "SELECT mdd_like(?1, ?2, ?3, 1)",
            rusqlite::params![
                text_blob(&[]),
                text_blob(&[b'!' as u16]),
                text_blob(&[b'!' as u16])
            ],
            |r| r.get::<_, Option<i64>>(0),
        );
        let esc_ref = like(
            &SqlText {
                utf16: vec![],
                original_mutf8: None,
            },
            &SqlText {
                utf16: vec![b'!' as u16],
                original_mutf8: None,
            },
            Some(b'!' as u16),
            dialect,
            &esc_control,
        );
        match (esc_sql, esc_ref) {
            (Ok(Some(v)), Ok(exp)) => assert_eq!(v != 0, exp, "{dialect:?}"),
            (Err(_), Err(e)) => assert_eq!(e.message, "LIKE_DANGLING_ESCAPE"),
            other => panic!("trailing escape mismatch on {dialect:?}: {other:?}"),
        }

        // Borrowed sort key matches `equality_key().sqlite()` byte-for-byte
        for (sql_arg, ref_val) in [
            (
                text_blob(&[0x41, 0xd800, 0x0062]),
                SqlValue::Text(SqlText {
                    utf16: vec![0x41, 0xd800, 0x0062],
                    original_mutf8: None,
                }),
            ),
            (Cell::Integer(i64::MIN), SqlValue::I64(Signed64(i64::MIN))),
            (Cell::Integer(0), SqlValue::I64(Signed64(0))),
            (uint_blob(u64::MAX), SqlValue::U64(DecimalU64(u64::MAX))),
        ] {
            let got: Cell = db
                .query_row("SELECT mdd_sort_key(?1)", rusqlite::params![sql_arg], |r| {
                    r.get(0)
                })
                .unwrap();
            let expected_bytes = equality_key(&ref_val, &control).unwrap();
            let expected_cell = SqlValue::Bytes(expected_bytes)
                .sqlite(SqlLimits::default().max_cell_bytes)
                .unwrap();
            assert_eq!(got, expected_cell, "sort key mismatch on {dialect:?}");
        }

        // Borrowed compare matches scalar compare for TEXT and exact integers
        let eq_pairs: &[(Cell, Cell, SqlValue, SqlValue)] = &[
            (
                text_blob(&[0x41, 0xd800]),
                text_blob(&[0x41, 0xdfff]),
                SqlValue::Text(SqlText {
                    utf16: vec![0x41, 0xd800],
                    original_mutf8: None,
                }),
                SqlValue::Text(SqlText {
                    utf16: vec![0x41, 0xdfff],
                    original_mutf8: None,
                }),
            ),
            (
                Cell::Integer(-5),
                uint_blob(5),
                SqlValue::I64(Signed64(-5)),
                SqlValue::U64(DecimalU64(5)),
            ),
        ];
        for (c1, c2, v1, v2) in eq_pairs {
            let lt: i64 = db
                .query_row("SELECT mdd_lt(?1, ?2)", rusqlite::params![c1, c2], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(
                lt != 0,
                compare(v1, v2, &control).unwrap() == Ordering::Less
            );
            let leq: i64 = db
                .query_row(
                    "SELECT mdd_literal_eq(?1, ?2)",
                    rusqlite::params![c1, c1],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(leq, 1);
        }
    }
}

#[test]
fn mdd_like_any_preserves_semantics_across_prefixes_nulls_utf8_and_errors() {
    let text_blob = |units: &[u16]| {
        let mut out = TEXT.to_vec();
        for u in units {
            out.extend_from_slice(&u.to_be_bytes());
        }
        Cell::Blob(out)
    };
    let pat_list: Vec<(&str, Option<u16>)> = vec![
        ("Lcom/alpha/ui/%", Some(b'\\' as u16)),
        ("Lcom/beta\\_pkg/%", Some(b'\\' as u16)),
        ("Lkntr/common/%suffix", None),
        ("nonAscii\u{0130}%", None),
    ];
    let spec_bytes = super::encode_like_any_spec(&pat_list).unwrap();
    let spec_cell = SqlValue::Bytes(spec_bytes)
        .sqlite(SqlLimits::default().max_cell_bytes)
        .unwrap();

    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let db = Connection::open_in_memory().unwrap();
        let control = SqlControl::new(SqlLimits::default(), None);
        register(&db, dialect, control.clone()).unwrap();

        for sample in [
            None,
            Some("Lcom/alpha/ui/Main;"),
            Some("lcom/ALPHA/ui/Sub;"),
            Some("Lcom/beta_pkg/Item;"),
            Some("Lcom/betaXpkg/Item;"),
            Some("Lkntr/common/TestSuffix"),
            Some("nonascii\u{0130}tail"),
            Some("nonAscii\u{0130}tail"),
            Some("Lunrelated/Class;"),
            Some(""),
        ] {
            let arg_text = sample.map(|s| s.encode_utf16().collect::<Vec<_>>());
            let blob_res: Option<i64> = db
                .query_row(
                    "SELECT mdd_like_any(?1, ?2)",
                    rusqlite::params![arg_text.as_deref().map_or(Cell::Null, text_blob), spec_cell],
                    |r| r.get(0),
                )
                .unwrap();
            // Scalar fallback via SQLite TEXT value (exercises slow fallback path too).
            let utf8_res: Option<i64> = db
                .query_row(
                    "SELECT mdd_like_any(?1, ?2)",
                    rusqlite::params![sample, spec_cell],
                    |r| r.get(0),
                )
                .unwrap();
            let expected = match arg_text {
                None => None,
                Some(ref u) => {
                    let v = SqlText {
                        utf16: u.clone(),
                        original_mutf8: None,
                    };
                    let mut hit = false;
                    for &(pat, esc) in &pat_list {
                        let p = SqlText {
                            utf16: pat.encode_utf16().collect(),
                            original_mutf8: None,
                        };
                        if like(&v, &p, esc, dialect, &control).unwrap() {
                            hit = true;
                            break;
                        }
                    }
                    Some(i64::from(hit))
                }
            };
            assert_eq!(
                blob_res, expected,
                "blob mismatch on {dialect:?} sample={sample:?}"
            );
            assert_eq!(
                utf8_res, expected,
                "utf8 mismatch on {dialect:?} sample={sample:?}"
            );
        }
    }

    // Trailing escape must still error in NativeV1 and return false/0 in legacy dialects.
    let bad_spec = super::encode_like_any_spec(&[("abc\\", Some(b'\\' as u16))]).unwrap();
    let bad_cell = SqlValue::Bytes(bad_spec)
        .sqlite(SqlLimits::default().max_cell_bytes)
        .unwrap();
    let db_native = Connection::open_in_memory().unwrap();
    let ctrl_native = SqlControl::new(SqlLimits::default(), None);
    register(&db_native, SqlDialect::NativeV1, ctrl_native.clone()).unwrap();
    assert!(
        db_native
            .query_row(
                "SELECT mdd_like_any(?1, ?2)",
                rusqlite::params![Cell::Null, bad_cell],
                |r| r.get::<_, Option<i64>>(0)
            )
            .is_err()
    );
    assert_eq!(ctrl_native.error().unwrap().message, "LIKE_DANGLING_ESCAPE");

    let db_legacy = Connection::open_in_memory().unwrap();
    let ctrl_legacy = SqlControl::new(SqlLimits::default(), None);
    register(&db_legacy, SqlDialect::DexSql011, ctrl_legacy).unwrap();
    let legacy_res: Option<i64> = db_legacy
        .query_row(
            "SELECT mdd_like_any(?1, ?2)",
            rusqlite::params![text_blob(&[b'x' as u16]), bad_cell],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(legacy_res, Some(0));
}
