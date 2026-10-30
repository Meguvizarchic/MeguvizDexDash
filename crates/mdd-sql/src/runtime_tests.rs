use crate::{
    SqlBridge,
    control::{SqlControl, SqlLimits},
    dialects::SqlDialect,
    provider::metadata::MetadataSqlProvider,
};
use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_query::budget::{BudgetLimits, BudgetPool, BudgetScope, Resource, RuntimeBudget};
use mdd_session::{Lifecycle, ResourceLimits, SessionHandle, cancellation::QueryCancellation};
use mdd_types::{DecimalU64, ErrorCode};
use std::{path::PathBuf, sync::Arc};

fn setup() -> (Lifecycle, SessionHandle, SessionHandle, SqlBridge) {
    setup_with_dialect(SqlDialect::NativeV1)
}

fn setup_with_dialect(dialect: SqlDialect) -> (Lifecycle, SessionHandle, SessionHandle, SqlBridge) {
    let snapshot = Arc::new(
        Snapshot::capture(
            &[InputSpec {
                path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/references/generated/nonscalar-string-035.dex"),
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap(),
    );
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let facts =
        Arc::new(MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap());
    let provider = Arc::new(MetadataSqlProvider::new(vec![facts], DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, dialect, SqlLimits::default()).unwrap();
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let snapshot_handle = lifecycle.register_snapshot(snapshot).unwrap();
    let a = lifecycle
        .open_session(&snapshot_handle, ResourceLimits::default())
        .unwrap();
    let b = lifecycle
        .open_session(&snapshot_handle, ResourceLimits::default())
        .unwrap();
    (lifecycle, a, b, bridge)
}

fn assert_concat_obeys_step_budget(values: Vec<crate::values::SqlValue>) {
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT CASE WHEN ? || ? IS NULL THEN 1 ELSE 0 END AS n",
                &values,
            )
            .unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QuerySteps, 64),
        );
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let error = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}");
        assert!(!token.status().unwrap().execution_complete);
    }
}

#[test]
fn concat_long_text_respects_session_step_budget() {
    use crate::values::SqlValue;
    assert_concat_obeys_step_budget(vec![
        SqlValue::text(&"A".repeat(50_000)),
        SqlValue::text("z"),
    ]);
}

#[test]
fn concat_long_bytes_respects_session_step_budget() {
    use crate::values::SqlValue;
    assert_concat_obeys_step_budget(vec![
        SqlValue::Bytes(vec![0x41; 50_000]),
        SqlValue::Bytes(vec![0xff]),
    ]);
}

#[test]
fn concat_preserves_null_non_scalar_nul_and_bytes() {
    use crate::values::{SqlText, SqlValue};
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (_, _, _, bridge) = setup_with_dialect(dialect);
        let left = SqlValue::Text(SqlText {
            utf16: vec![0xd800, 0],
            original_mutf8: None,
        });
        let right = SqlValue::Text(SqlText {
            utf16: vec![0xd83d, 0xde00],
            original_mutf8: None,
        });
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT ? || ?, NULL || ?, ? || NULL, ? || ?",
                &[
                    left,
                    right,
                    SqlValue::text("x"),
                    SqlValue::text("y"),
                    SqlValue::Bytes(vec![0, 0xff]),
                    SqlValue::Bytes(vec![0x41]),
                ],
            )
            .unwrap();
        let result = prepared
            .execute(SqlControl::new(SqlLimits::default(), None))
            .unwrap();
        let concatenated_bytes = if dialect == SqlDialect::NativeV1 {
            SqlValue::Bytes(vec![0, 0xff, 0x41])
        } else {
            SqlValue::Text(SqlText {
                utf16: vec![0, 0xfffd, 0x41],
                original_mutf8: None,
            })
        };
        assert_eq!(
            result.rows()[0],
            vec![
                SqlValue::Text(SqlText {
                    utf16: vec![0xd800, 0, 0xd83d, 0xde00],
                    original_mutf8: None
                }),
                SqlValue::Null,
                SqlValue::Null,
                concatenated_bytes,
            ],
            "{dialect:?}"
        );
        let error = bridge
            .query("SELECT missing || 'x' FROM native_strings")
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{dialect:?}");
    }
}

#[test]
fn concat_cancelled_after_copy_starts_stays_failed() {
    use crate::values::SqlValue;
    use std::time::{Duration, Instant};
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        for (kind, left, right) in [
            (
                "text",
                SqlValue::text(&"A".repeat(200_000)),
                SqlValue::text("z"),
            ),
            (
                "bytes",
                SqlValue::Bytes(vec![0x41; 200_000]),
                SqlValue::Bytes(vec![0xff]),
            ),
        ] {
            let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
            let prepared = bridge
                .prepare_with_parameters(
                    "SELECT CASE WHEN ? || ? IS NULL THEN 1 ELSE 0 END AS n",
                    &[left, right],
                )
                .unwrap();
            let (runtime, token) =
                runtime(&lifecycle, &session, &prepared, BudgetLimits::default());
            let pool = runtime.pool().clone();
            let bound = prepared.bind_runtime(&runtime).unwrap();
            let handle = std::thread::spawn(move || {
                bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let steps = pool
                    .usage()
                    .unwrap()
                    .used
                    .get(&Resource::QuerySteps)
                    .map_or(0, |v| v.0);
                if steps > 5_000 {
                    break;
                }
                if handle.is_finished() || Instant::now() >= deadline {
                    let _ = token.cancel();
                    let _ = handle.join();
                    panic!("concat copy was not observed before completion: {dialect:?} {kind}");
                }
                std::thread::yield_now();
            }
            token.cancel().unwrap();
            assert_eq!(
                handle.join().unwrap().unwrap_err().code,
                ErrorCode::Cancelled,
                "{dialect:?} {kind}"
            );
            assert!(!token.status().unwrap().execution_complete);
        }
    }
}

fn assert_key_obeys_workspace_budget(sql: &str, values: Vec<crate::values::SqlValue>) {
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge.prepare_with_parameters(sql, &values).unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8192),
        );
        let pool = runtime.pool().clone();
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let error = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}: {sql}");
        assert!(!token.status().unwrap().execution_complete);
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0),
            0
        );
    }
}

#[test]
fn key_workspace_distinct_text_respects_budget() {
    use crate::values::SqlValue;
    assert_key_obeys_workspace_budget(
        "SELECT COUNT(*) FROM (SELECT DISTINCT ? AS v)",
        vec![SqlValue::text(&"A".repeat(10_000))],
    );
}

#[test]
fn key_workspace_distinct_bytes_respects_budget() {
    use crate::values::SqlValue;
    assert_key_obeys_workspace_budget(
        "SELECT COUNT(*) FROM (SELECT DISTINCT ? AS v)",
        vec![SqlValue::Bytes(vec![0x41; 10_000])],
    );
}

#[test]
fn key_workspace_group_text_respects_budget() {
    use crate::values::SqlValue;
    let value = SqlValue::text(&"A".repeat(10_000));
    assert_key_obeys_workspace_budget(
        "SELECT COUNT(*) FROM (SELECT ? AS v GROUP BY ?)",
        vec![value.clone(), value],
    );
}

#[test]
fn key_workspace_order_text_respects_budget() {
    use crate::values::SqlValue;
    let value = SqlValue::text(&"A".repeat(10_000));
    assert_key_obeys_workspace_budget(
        "SELECT 1 FROM (SELECT ? AS v UNION ALL SELECT ? AS v ORDER BY v LIMIT 1)",
        vec![value.clone(), value],
    );
}

#[test]
fn key_workspace_releases_temporary_lease_after_success_and_result_drop() {
    use crate::values::SqlValue;
    use mdd_query::ir::Signed64;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT COUNT(*) FROM (SELECT DISTINCT ? AS v)",
                &[SqlValue::text(&"A".repeat(10_000))],
            )
            .unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 128 * 1024),
        );
        let pool = runtime.pool().clone();
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let result = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap();
        assert_eq!(
            result.rows(),
            &[vec![SqlValue::I64(Signed64(1))]],
            "{dialect:?}"
        );
        assert!(token.status().unwrap().execution_complete);
        let used = pool
            .usage()
            .unwrap()
            .used
            .get(&Resource::QueryWorkspaceBytes)
            .map_or(0, |v| v.0);
        assert!(
            (1..=8192).contains(&used),
            "temporary key lease retained: {dialect:?}: {used}"
        );
        drop(result);
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0),
            0
        );
    }
}

#[test]
fn key_workspace_cancellation_releases_temporary_lease() {
    use crate::values::SqlValue;
    use std::time::{Duration, Instant};
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT COUNT(*) FROM (SELECT DISTINCT ? AS v)",
                &[SqlValue::text(&"A".repeat(200_000))],
            )
            .unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 1024 * 1024),
        );
        let pool = runtime.pool().clone();
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let handle = std::thread::spawn(move || {
            bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let usage = pool.usage().unwrap();
            let used = usage
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0);
            let steps = usage.used.get(&Resource::QuerySteps).map_or(0, |v| v.0);
            if used > 700_000 && steps > 5_000 {
                break;
            }
            if handle.is_finished() || Instant::now() >= deadline {
                let _ = token.cancel();
                let _ = handle.join();
                panic!("key lease and scan were not observed before completion: {dialect:?}");
            }
            std::thread::yield_now();
        }
        token.cancel().unwrap();
        assert_eq!(
            handle.join().unwrap().unwrap_err().code,
            ErrorCode::Cancelled,
            "{dialect:?}"
        );
        assert!(!token.status().unwrap().execution_complete);
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0),
            0
        );
    }
}

#[test]
fn key_workspace_precancel_remains_cancelled_before_quota() {
    use crate::values::SqlValue;
    let (lifecycle, session, _, bridge) = setup_with_dialect(SqlDialect::NativeV1);
    let prepared = bridge
        .prepare_with_parameters(
            "SELECT COUNT(*) FROM (SELECT DISTINCT ? AS v)",
            &[SqlValue::text(&"A".repeat(10_000))],
        )
        .unwrap();
    let (runtime, token) = runtime(
        &lifecycle,
        &session,
        &prepared,
        BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8192),
    );
    let bound = prepared.bind_runtime(&runtime).unwrap();
    token.cancel().unwrap();
    let error = bound
        .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert!(!token.status().unwrap().execution_complete);
}

fn assert_key_scan_obeys_step_budget(sql: &str, values: Vec<crate::values::SqlValue>) {
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge.prepare_with_parameters(sql, &values).unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QuerySteps, 64),
        );
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let error = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}: {sql}");
        assert!(!token.status().unwrap().execution_complete);
    }
}

#[test]
fn key_distinct_long_text_respects_session_step_budget() {
    use crate::values::SqlValue;
    assert_key_scan_obeys_step_budget(
        "SELECT COUNT(*) FROM (SELECT DISTINCT ? AS v)",
        vec![SqlValue::text(&"A".repeat(50_000))],
    );
}

#[test]
fn key_distinct_long_bytes_respects_session_step_budget() {
    use crate::values::SqlValue;
    assert_key_scan_obeys_step_budget(
        "SELECT COUNT(*) FROM (SELECT DISTINCT ? AS v)",
        vec![SqlValue::Bytes(vec![0x41; 50_000])],
    );
}

#[test]
fn key_group_long_text_respects_session_step_budget() {
    use crate::values::SqlValue;
    let value = SqlValue::text(&"A".repeat(50_000));
    assert_key_scan_obeys_step_budget(
        "SELECT COUNT(*) FROM (SELECT ? AS v GROUP BY ?)",
        vec![value.clone(), value],
    );
}

#[test]
fn key_order_long_text_respects_session_step_budget() {
    use crate::values::SqlValue;
    let value = SqlValue::text(&"A".repeat(50_000));
    assert_key_scan_obeys_step_budget(
        "SELECT 1 FROM (SELECT ? AS v UNION ALL SELECT ? AS v ORDER BY v LIMIT 1)",
        vec![value.clone(), value],
    );
}

#[test]
fn key_scan_preserves_null_numeric_utf16_bytes_and_duplicates() {
    use crate::values::{SqlText, SqlValue};
    use mdd_query::ir::Signed64;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (_, _, _, bridge) = setup_with_dialect(dialect);
        let lone = SqlValue::Text(SqlText {
            utf16: vec![0xd800],
            original_mutf8: None,
        });
        let query = "SELECT v FROM (SELECT ? AS v UNION ALL SELECT ? AS v UNION ALL SELECT ? AS v UNION ALL SELECT ? AS v) GROUP BY v ORDER BY v";
        let prepared = bridge
            .prepare_with_parameters(
                query,
                &[
                    SqlValue::Null,
                    lone.clone(),
                    SqlValue::text("A"),
                    SqlValue::text("A"),
                ],
            )
            .unwrap();
        let result = prepared
            .execute(SqlControl::new(SqlLimits::default(), None))
            .unwrap();
        assert_eq!(
            result.rows(),
            &[vec![SqlValue::Null], vec![SqlValue::text("A")], vec![lone]],
            "{dialect:?}"
        );

        let prepared = bridge
            .prepare_with_parameters(
                query,
                &[
                    SqlValue::Bytes(vec![0xff]),
                    SqlValue::Bytes(vec![0]),
                    SqlValue::Bytes(vec![0]),
                    SqlValue::Null,
                ],
            )
            .unwrap();
        let result = prepared
            .execute(SqlControl::new(SqlLimits::default(), None))
            .unwrap();
        assert_eq!(
            result.rows(),
            &[
                vec![SqlValue::Null],
                vec![SqlValue::Bytes(vec![0])],
                vec![SqlValue::Bytes(vec![0xff])]
            ],
            "{dialect:?}"
        );

        let prepared = bridge
            .prepare_with_parameters(
                "SELECT COUNT(*) FROM (SELECT ? AS v UNION ALL SELECT ? AS v UNION ALL SELECT ? AS v) GROUP BY v",
                &[SqlValue::I64(Signed64(1)), SqlValue::U64(DecimalU64(1)), SqlValue::F64(DecimalU64(1.0f64.to_bits()))],
            )
            .unwrap();
        let result = prepared
            .execute(SqlControl::new(SqlLimits::default(), None))
            .unwrap();
        assert_eq!(
            result.rows(),
            &[vec![SqlValue::I64(Signed64(3))]],
            "{dialect:?}"
        );
        let error = bridge
            .query("SELECT missing FROM native_strings ORDER BY missing")
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{dialect:?}");
    }
}

#[test]
fn key_scan_cancelled_after_steps_stays_failed() {
    use crate::values::SqlValue;
    use std::time::{Duration, Instant};
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        for (kind, value) in [
            ("text", SqlValue::text(&"A".repeat(200_000))),
            ("bytes", SqlValue::Bytes(vec![0x41; 200_000])),
        ] {
            let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
            let prepared = bridge
                .prepare_with_parameters("SELECT COUNT(*) FROM (SELECT DISTINCT ? AS v)", &[value])
                .unwrap();
            let (runtime, token) =
                runtime(&lifecycle, &session, &prepared, BudgetLimits::default());
            let pool = runtime.pool().clone();
            let bound = prepared.bind_runtime(&runtime).unwrap();
            let handle = std::thread::spawn(move || {
                bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let steps = pool
                    .usage()
                    .unwrap()
                    .used
                    .get(&Resource::QuerySteps)
                    .map_or(0, |v| v.0);
                if steps > 5_000 {
                    break;
                }
                if handle.is_finished() || Instant::now() >= deadline {
                    let _ = token.cancel();
                    let _ = handle.join();
                    panic!("key scan was not observed before completion: {dialect:?} {kind}");
                }
                std::thread::yield_now();
            }
            token.cancel().unwrap();
            assert_eq!(
                handle.join().unwrap().unwrap_err().code,
                ErrorCode::Cancelled,
                "{dialect:?} {kind}"
            );
            assert!(!token.status().unwrap().execution_complete);
        }
    }
}

#[test]
fn hex_long_text_respects_session_step_budget() {
    use crate::values::SqlValue;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters("SELECT hex(?) AS h", &[SqlValue::text(&"A".repeat(50_000))])
            .unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QuerySteps, 64),
        );
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let error = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}");
        assert!(!token.status().unwrap().execution_complete);
    }
}

#[test]
fn hex_long_bytes_respects_session_step_budget() {
    use crate::values::SqlValue;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters("SELECT hex(?) AS h", &[SqlValue::Bytes(vec![0x41; 50_000])])
            .unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QuerySteps, 64),
        );
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let error = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}");
        assert!(!token.status().unwrap().execution_complete);
    }
}

#[test]
fn cast_text_to_blob_respects_session_step_budget() {
    use crate::values::SqlValue;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT CAST(? AS BLOB) AS b",
                &[SqlValue::text(&"A".repeat(50_000))],
            )
            .unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QuerySteps, 64),
        );
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let error = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}");
        assert!(!token.status().unwrap().execution_complete);
    }
}

#[test]
fn hex_preserves_null_bytes_nul_and_surrogate_encoding() {
    use crate::values::{SqlText, SqlValue};
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (_, _, _, bridge) = setup_with_dialect(dialect);
        let value = SqlValue::Text(SqlText {
            utf16: vec![0xd800, 0, 0xd83d, 0xde00],
            original_mutf8: None,
        });
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT hex(NULL),hex(?),hex(?)",
                &[SqlValue::Bytes(vec![0, 0xff]), value],
            )
            .unwrap();
        let result = prepared
            .execute(SqlControl::new(SqlLimits::default(), None))
            .unwrap();
        let encoded = if dialect == SqlDialect::NativeV1 {
            "EDA08000F09F9880"
        } else {
            "EDA080C080EDA0BDEDB880"
        };
        assert_eq!(
            result.rows()[0],
            vec![
                SqlValue::text(""),
                SqlValue::text("00FF"),
                SqlValue::text(encoded)
            ],
            "{dialect:?}"
        );
    }
}

#[test]
fn hex_cancelled_after_scan_starts_stays_failed() {
    use crate::values::SqlValue;
    use std::time::{Duration, Instant};
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        for (kind, value) in [
            ("bytes", SqlValue::Bytes(vec![0x41; 200_000])),
            ("text", SqlValue::text(&"A".repeat(200_000))),
        ] {
            let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
            let prepared = bridge
                .prepare_with_parameters("SELECT hex(?) AS h", &[value])
                .unwrap();
            let (runtime, token) =
                runtime(&lifecycle, &session, &prepared, BudgetLimits::default());
            let pool = runtime.pool().clone();
            let bound = prepared.bind_runtime(&runtime).unwrap();
            let handle = std::thread::spawn(move || {
                bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let steps = pool
                    .usage()
                    .unwrap()
                    .used
                    .get(&Resource::QuerySteps)
                    .map_or(0, |value| value.0);
                if steps > 5_000 {
                    break;
                }
                if handle.is_finished() || Instant::now() >= deadline {
                    let _ = token.cancel();
                    let _ = handle.join();
                    panic!("HEX scan was not observed before completion: {dialect:?} {kind}");
                }
                std::thread::yield_now();
            }
            token.cancel().unwrap();
            assert_eq!(
                handle.join().unwrap().unwrap_err().code,
                ErrorCode::Cancelled
            );
            assert!(!token.status().unwrap().execution_complete);
        }
    }
}

#[test]
fn length_legacy_scan_respects_session_step_budget() {
    use crate::values::SqlValue;
    for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT length(?) AS n",
                &[SqlValue::text(&"A".repeat(50_000))],
            )
            .unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QuerySteps, 64),
        );
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let error = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}");
        assert!(!token.status().unwrap().execution_complete);
    }
}

#[test]
fn length_preserves_code_unit_and_legacy_scalar_semantics() {
    use crate::values::{SqlText, SqlValue};
    use mdd_query::ir::Signed64;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (_, _, _, bridge) = setup_with_dialect(dialect);
        for (units, native_count, legacy_count) in [
            (vec![], 0, 0),
            (vec![0x41, 0, 0x42], 3, 3),
            (vec![0xd83d, 0xde00], 2, 1),
            (vec![0xd800], 1, 1),
            (vec![0xdc00], 1, 1),
            (vec![0xd800, 0xd800, 0xdc00], 3, 2),
        ] {
            let value = SqlValue::Text(SqlText {
                utf16: units,
                original_mutf8: None,
            });
            let prepared = bridge
                .prepare_with_parameters("SELECT length(?) AS n", &[value])
                .unwrap();
            let result = prepared
                .execute(SqlControl::new(SqlLimits::default(), None))
                .unwrap();
            let expected = if dialect == SqlDialect::NativeV1 {
                native_count
            } else {
                legacy_count
            };
            assert_eq!(result.rows()[0][0], SqlValue::I64(Signed64(expected)));
        }
    }
}

#[test]
fn length_native_constant_time_length_keeps_step_budget() {
    use crate::values::SqlValue;
    use mdd_query::ir::Signed64;
    let (lifecycle, session, _, bridge) = setup_with_dialect(SqlDialect::NativeV1);
    let prepared = bridge
        .prepare_with_parameters(
            "SELECT length(?) AS n",
            &[SqlValue::text(&"A".repeat(50_000))],
        )
        .unwrap();
    let (runtime, token) = runtime(
        &lifecycle,
        &session,
        &prepared,
        BudgetLimits::default().with(Resource::QuerySteps, 64),
    );
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let result = bound
        .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        .unwrap();
    assert_eq!(result.rows()[0][0], SqlValue::I64(Signed64(50_000)));
    assert!(token.status().unwrap().execution_complete);
}

#[test]
fn length_legacy_cancelled_after_scan_starts_stays_failed() {
    use crate::values::SqlValue;
    use std::time::{Duration, Instant};
    for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT length(?) AS n",
                &[SqlValue::text(&"A".repeat(300_000))],
            )
            .unwrap();
        let (runtime, token) = runtime(&lifecycle, &session, &prepared, BudgetLimits::default());
        let pool = runtime.pool().clone();
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let handle = std::thread::spawn(move || {
            bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let steps = pool
                .usage()
                .unwrap()
                .used
                .get(&Resource::QuerySteps)
                .map_or(0, |value| value.0);
            if steps > 5_000 {
                break;
            }
            if handle.is_finished() || Instant::now() >= deadline {
                let _ = token.cancel();
                let _ = handle.join();
                panic!("length scan was not observed before completion: {dialect:?}");
            }
            std::thread::yield_now();
        }
        token.cancel().unwrap();
        assert_eq!(
            handle.join().unwrap().unwrap_err().code,
            ErrorCode::Cancelled
        );
        assert!(!token.status().unwrap().execution_complete);
    }
}

#[test]
fn substring_long_text_respects_session_step_budget() {
    use crate::values::SqlValue;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT substr(?,1,1) AS v",
                &[SqlValue::text(&"A".repeat(50_000))],
            )
            .unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QuerySteps, 64),
        );
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let error = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}");
        assert!(!token.status().unwrap().execution_complete);
    }
}

#[test]
fn substring_offsets_require_session_workspace_budget() {
    use crate::values::SqlValue;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT substr(?,1,1) AS v",
                &[SqlValue::text(&"A".repeat(10_000))],
            )
            .unwrap();
        let (runtime, token) = runtime(
            &lifecycle,
            &session,
            &prepared,
            BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8192),
        );
        let pool = runtime.pool().clone();
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let error = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}");
        assert!(!token.status().unwrap().execution_complete);
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0),
            0
        );
    }
}

#[test]
fn substring_units_and_null_are_unchanged_by_budgeting() {
    use crate::values::{SqlText, SqlValue};
    let value = SqlValue::Text(SqlText {
        utf16: vec![0x41, 0, 0xd83d, 0xde00, 0xd800, 0x42],
        original_mutf8: None,
    });
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (_, _, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT substr(?,3,1),substr(?,4,1),substr('',1,1),substr(NULL,1,1)",
                &[value.clone(), value.clone()],
            )
            .unwrap();
        let result = prepared
            .execute(SqlControl::new(SqlLimits::default(), None))
            .unwrap();
        let text = |utf16| {
            SqlValue::Text(SqlText {
                utf16,
                original_mutf8: None,
            })
        };
        let (third, fourth) = if dialect == SqlDialect::NativeV1 {
            (vec![0xd83d], vec![0xde00])
        } else {
            (vec![0xd83d, 0xde00], vec![0xd800])
        };
        assert_eq!(
            result.rows()[0],
            vec![text(third), text(fourth), text(vec![]), SqlValue::Null],
            "{dialect:?}"
        );
    }
}

#[test]
fn substring_offsets_are_released_after_success() {
    use crate::values::SqlValue;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT substr(?,1,1) AS v",
                &[SqlValue::text(&"A".repeat(10_000))],
            )
            .unwrap();
        let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 200_000);
        let (runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
        let pool = runtime.pool().clone();
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let result = bound
            .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            .unwrap();
        assert_eq!(result.rows()[0][0], SqlValue::text("A"));
        assert!(token.status().unwrap().execution_complete);
        let retained = pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0;
        assert!(
            (1..=8192).contains(&retained),
            "offset lease retained: {retained}"
        );
        drop(result);
        assert_eq!(
            pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0,
            0
        );
    }
}

#[test]
fn substring_cancellation_during_scan_releases_offsets() {
    use crate::values::SqlValue;
    use std::time::{Duration, Instant};
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT substr(?,1,1) AS v",
                &[SqlValue::text(&"A".repeat(300_000))],
            )
            .unwrap();
        let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 4 * 1024 * 1024);
        let (runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
        let pool = runtime.pool().clone();
        let bound = prepared.bind_runtime(&runtime).unwrap();
        let handle = std::thread::spawn(move || {
            bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let used = pool
                .usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0);
            let steps = pool
                .usage()
                .unwrap()
                .used
                .get(&Resource::QuerySteps)
                .map_or(0, |v| v.0);
            if used > 100_000 && steps > 5_000 {
                break;
            }
            if handle.is_finished() || Instant::now() >= deadline {
                let _ = token.cancel();
                let _ = handle.join();
                panic!("substring scan was not observed before completion: {dialect:?}");
            }
            std::thread::yield_now();
        }
        token.cancel().unwrap();
        assert_eq!(
            handle.join().unwrap().unwrap_err().code,
            ErrorCode::Cancelled,
            "{dialect:?}"
        );
        assert!(!token.status().unwrap().execution_complete);
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0),
            0
        );
    }
}

#[test]
fn case_conversion_long_text_respects_session_step_budget() {
    use crate::values::SqlValue;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        for name in ["lower", "upper"] {
            let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
            let prepared = bridge
                .prepare_with_parameters(
                    &format!("SELECT {name}(?) AS v"),
                    &[SqlValue::text(&"A".repeat(50_000))],
                )
                .unwrap();
            let limits = BudgetLimits::default().with(Resource::QuerySteps, 64);
            let (runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
            let bound = prepared.bind_runtime(&runtime).unwrap();
            let error = bound
                .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?} {name}");
            assert!(!token.status().unwrap().execution_complete);
        }
    }
}

#[test]
fn case_conversion_reserves_output_workspace_before_scanning() {
    use crate::values::SqlValue;
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        for value in [
            SqlValue::text(&"A".repeat(5000)),
            SqlValue::DexMutf8 {
                bytes: vec![b'A'; 5000],
                utf16_code_units: DecimalU64(5000),
            },
        ] {
            let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
            let prepared = bridge
                .prepare_with_parameters("SELECT lower(?) AS v", &[value])
                .unwrap();
            let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 512);
            let (runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
            let pool = runtime.pool().clone();
            let bound = prepared.bind_runtime(&runtime).unwrap();
            let error = bound
                .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::QuotaExceeded, "{dialect:?}");
            assert_eq!(error.details["budget"], "query_workspace_bytes");
            let usage = pool.usage().unwrap();
            assert!(usage.used.get(&Resource::QuerySteps).map_or(0, |v| v.0) < 5000);
            assert_eq!(
                usage
                    .used
                    .get(&Resource::QueryWorkspaceBytes)
                    .map_or(0, |v| v.0),
                0
            );
            assert_eq!(
                usage.used.get(&Resource::ResidentBytes).map_or(0, |v| v.0),
                0
            );
            assert!(!token.status().unwrap().execution_complete);
        }
    }
}

#[test]
fn case_conversion_preserves_empty_nul_and_unpaired_units() {
    use crate::values::{SqlText, SqlValue};
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        let (_, _, _, bridge) = setup_with_dialect(dialect);
        for (units, lower, upper) in [
            (vec![], vec![], vec![]),
            (
                vec![0x41, 0, 0xd800, 0x61, 0xdc00],
                vec![0x61, 0, 0xd800, 0x61, 0xdc00],
                vec![0x41, 0, 0xd800, 0x41, 0xdc00],
            ),
        ] {
            let value = SqlValue::Text(SqlText {
                utf16: units,
                original_mutf8: None,
            });
            let prepared = bridge
                .prepare_with_parameters(
                    "SELECT lower(?) AS lo,upper(?) AS hi",
                    &[value.clone(), value],
                )
                .unwrap();
            let result = prepared
                .execute(SqlControl::new(SqlLimits::default(), None))
                .unwrap();
            let expected = |utf16| {
                SqlValue::Text(SqlText {
                    utf16,
                    original_mutf8: None,
                })
            };
            assert_eq!(
                result.rows()[0],
                vec![expected(lower), expected(upper)],
                "{dialect:?}"
            );
        }
    }
}

#[test]
fn case_conversion_cancelled_during_scan_stays_failed() {
    use crate::values::SqlValue;
    use std::time::{Duration, Instant};
    for dialect in [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ] {
        for name in ["lower", "upper"] {
            let (lifecycle, session, _, bridge) = setup_with_dialect(dialect);
            let prepared = bridge
                .prepare_with_parameters(
                    &format!("SELECT {name}(?) AS v"),
                    &[SqlValue::text(&"A".repeat(300_000))],
                )
                .unwrap();
            let (runtime, token) =
                runtime(&lifecycle, &session, &prepared, BudgetLimits::default());
            let pool = runtime.pool().clone();
            let bound = prepared.bind_runtime(&runtime).unwrap();
            let handle = std::thread::spawn(move || {
                bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let steps = pool
                    .usage()
                    .unwrap()
                    .used
                    .get(&Resource::QuerySteps)
                    .map_or(0, |v| v.0);
                if steps > 5_000 {
                    break;
                }
                if handle.is_finished() || Instant::now() >= deadline {
                    let _ = token.cancel();
                    let _ = handle.join();
                    panic!("case scan was not observed before completion: {dialect:?} {name}");
                }
                std::thread::yield_now();
            }
            token.cancel().unwrap();
            assert_eq!(
                handle.join().unwrap().unwrap_err().code,
                ErrorCode::Cancelled,
                "{dialect:?} {name}"
            );
            assert!(!token.status().unwrap().execution_complete);
            let usage = pool.usage().unwrap();
            assert_eq!(
                usage
                    .used
                    .get(&Resource::QueryWorkspaceBytes)
                    .map_or(0, |v| v.0),
                0
            );
            assert_eq!(
                usage.used.get(&Resource::ResidentBytes).map_or(0, |v| v.0),
                0
            );
        }
    }
}

fn runtime(
    lifecycle: &Lifecycle,
    session: &SessionHandle,
    prepared: &crate::PreparedSql,
    limits: BudgetLimits,
) -> (RuntimeBudget, QueryCancellation) {
    let query = lifecycle
        .prepare_query(
            session,
            prepared.runtime_query_binding().unwrap(),
            ResourceLimits::default(),
        )
        .unwrap();
    lifecycle.start_query(session, &query, 1).unwrap();
    let token = lifecycle.cancellation_token(&query).unwrap();
    let global = BudgetPool::global("sql-test-root".into(), limits.clone()).unwrap();
    let worker = global
        .child(
            token.worker_owner_id().unwrap(),
            BudgetScope::Worker,
            limits.clone(),
        )
        .unwrap();
    let session_budget = worker
        .child(session.id().into(), BudgetScope::Session, limits.clone())
        .unwrap();
    let query_budget = session_budget
        .child(query.id().into(), BudgetScope::Query, limits)
        .unwrap();
    (
        RuntimeBudget::new(query_budget, token.clone()).unwrap(),
        token,
    )
}

#[test]
fn same_snapshot_other_session_is_rejected_without_claiming_either_query() {
    let (lifecycle, a, b, bridge) = setup();
    let prepared = bridge.prepare("SELECT value FROM native_strings").unwrap();
    let (runtime_a, token_a) = runtime(&lifecycle, &a, &prepared, BudgetLimits::default());
    let (runtime_b, token_b) = runtime(&lifecycle, &b, &prepared, BudgetLimits::default());
    let bound = prepared.bind_runtime(&runtime_a).unwrap();
    let bad = SqlControl::new(SqlLimits::default(), None).with_runtime(runtime_b);
    assert_eq!(
        bound.execute(bad).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert!(token_b.status().unwrap().error.is_none());
    let good = SqlControl::new(SqlLimits::default(), None).with_runtime(runtime_a);
    let result = bound.execute(good).unwrap();
    assert!(!result.rows().is_empty());
    assert!(result.calculation_complete());
    assert!(token_a.status().unwrap().execution_complete);
    assert!(!token_a.status().unwrap().delivery_complete);
    token_b.claim_execution().unwrap();
}

#[test]
fn shared_work_budget_stops_real_metadata_before_owned_result_and_is_sticky() {
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge.prepare("SELECT value FROM native_strings").unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkBytes, 0);
    let (limited_runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
    let bound = prepared.bind_runtime(&limited_runtime).unwrap();
    let control = SqlControl::new(SqlLimits::default(), None).with_runtime(limited_runtime);
    assert_eq!(
        bound.execute(control).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    let status = token.status().unwrap();
    assert_eq!(status.error.unwrap().code, ErrorCode::QuotaExceeded);
    assert!(!status.execution_complete);
    assert!(!status.delivery_complete);
}

#[test]
fn typed_numeric_truth_preserves_sql_three_valued_conditions() {
    let (_, _, _, bridge) = setup();
    let output = bridge.query("SELECT CASE WHEN CAST(1 AS UNSIGNED) THEN 1 ELSE 0 END, CAST(1 AS UNSIGNED) IS TRUE, NOT CAST(1 AS UNSIGNED), CAST(1 AS UNSIGNED) AND 1, CAST(1 AS UNSIGNED) OR 0, NULL AND CAST(1 AS UNSIGNED), NULL OR CAST(1 AS UNSIGNED)").unwrap();
    use crate::values::SqlValue;
    use mdd_query::ir::Signed64;
    let int = |n| SqlValue::I64(Signed64(n));
    assert_eq!(
        output.rows()[0],
        vec![
            int(1),
            int(1),
            int(0),
            int(1),
            int(1),
            SqlValue::Null,
            int(1)
        ]
    );
    assert_eq!(
        bridge
            .query("SELECT 1 WHERE CAST(1 AS UNSIGNED)")
            .unwrap()
            .rows()
            .len(),
        1
    );
    assert_eq!(
        bridge
            .query("SELECT 1 WHERE CAST(0 AS UNSIGNED)")
            .unwrap()
            .rows()
            .len(),
        0
    );
}

#[test]
fn result_workspace_is_admitted_before_delivery_and_retained_until_drop() {
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge.prepare("SELECT value FROM native_strings").unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 1);
    let (limited_runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
    let limited_pool = limited_runtime.pool().clone();
    let bound = prepared.bind_runtime(&limited_runtime).unwrap();
    let control = SqlControl::new(SqlLimits::default(), None).with_runtime(limited_runtime);
    assert_eq!(
        bound.execute(control).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    assert!(!token.status().unwrap().execution_complete);
    assert_eq!(
        limited_pool
            .usage()
            .unwrap()
            .used
            .get(&Resource::QueryWorkspaceBytes)
            .map_or(0, |value| value.0),
        0
    );

    let prepared = bridge.prepare("SELECT value FROM native_strings").unwrap();
    let (runtime, token) = runtime(&lifecycle, &session, &prepared, BudgetLimits::default());
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let control = SqlControl::new(SqlLimits::default(), None).with_runtime(runtime);
    let result = bound.execute(control).unwrap();
    assert!(!result.rows().is_empty());
    let serialized = serde_json::to_value(&result).unwrap();
    assert!(serialized.get("rows").unwrap().is_array());
    assert!(serialized.get("_result_memory").is_none());
    assert!(pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0 > 0);
    assert!(token.status().unwrap().execution_complete);
    assert!(!token.status().unwrap().delivery_complete);
    drop(result);
    assert_eq!(
        pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0,
        0
    );
}

#[test]
fn small_exact_workspace_does_not_require_a_full_reservation_chunk() {
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge.prepare("SELECT 'a'").unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 3000);
    let (runtime, _) = runtime(&lifecycle, &session, &prepared, limits);
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let result = bound
        .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        .unwrap();
    assert_eq!(result.rows().len(), 1);
    let used = pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0;
    assert!((1..=3000).contains(&used));
    drop(result);
    assert_eq!(
        pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0,
        0
    );
}

#[test]
fn zero_rows_still_reserve_result_schema_and_identity() {
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge.prepare("SELECT 1 AS long_alias WHERE 0").unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 0);
    let (limited, token) = runtime(&lifecycle, &session, &prepared, limits);
    let bound = prepared.bind_runtime(&limited).unwrap();
    let result = bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(limited));
    assert_eq!(result.unwrap_err().code, ErrorCode::QuotaExceeded);
    assert!(!token.status().unwrap().execution_complete);

    let prepared = bridge.prepare("SELECT 1 AS long_alias WHERE 0").unwrap();
    let (runtime, _) = runtime(&lifecycle, &session, &prepared, BudgetLimits::default());
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let result = bound
        .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        .unwrap();
    assert!(result.rows().is_empty());
    assert_eq!(result.columns(), &["long_alias"]);
    assert!(pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0 > 0);
    drop(result);
    assert_eq!(
        pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0,
        0
    );
}

#[test]
fn like_token_allocation_requires_real_session_workspace_budget() {
    use crate::values::SqlValue;
    let (lifecycle, session, _, bridge) = setup();
    let pattern = SqlValue::text(&"%".repeat(10_000));
    let prepared = bridge
        .prepare_with_parameters("SELECT '' LIKE ? AS value", &[pattern])
        .unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8192);
    let (runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let error = bound
        .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert!(!token.status().unwrap().execution_complete);
    assert_eq!(
        pool.usage()
            .unwrap()
            .used
            .get(&Resource::QueryWorkspaceBytes)
            .map_or(0, |v| v.0),
        0
    );
}

#[test]
fn like_token_workspace_is_released_after_success() {
    use crate::values::SqlValue;
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge
        .prepare_with_parameters(
            "SELECT '' LIKE ? AS value",
            &[SqlValue::text(&"%".repeat(10_000))],
        )
        .unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 65_536);
    let (runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let result = bound
        .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        .unwrap();
    assert!(token.status().unwrap().execution_complete);
    assert_eq!(result.rows().len(), 1);
    let retained = pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0;
    assert!(
        (1..=8192).contains(&retained),
        "temporary token lease was not released: {retained}"
    );
    drop(result);
    assert_eq!(
        pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0,
        0
    );
}

#[test]
fn cancelling_during_like_pattern_scan_releases_token_workspace() {
    use crate::values::SqlValue;
    use std::time::{Duration, Instant};
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge
        .prepare_with_parameters(
            "SELECT '' LIKE ? AS value",
            &[SqlValue::text(&"%".repeat(300_000))],
        )
        .unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 4 * 1024 * 1024);
    let (runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let handle = std::thread::spawn(move || {
        bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let used = pool
            .usage()
            .unwrap()
            .used
            .get(&Resource::QueryWorkspaceBytes)
            .map_or(0, |v| v.0);
        if used > 100_000 {
            break;
        }
        if handle.is_finished() || Instant::now() >= deadline {
            let _ = token.cancel();
            let _ = handle.join();
            panic!("LIKE token reservation was not observed before completion");
        }
        std::thread::yield_now();
    }
    token.cancel().unwrap();
    assert_eq!(
        handle.join().unwrap().unwrap_err().code,
        ErrorCode::Cancelled
    );
    assert!(!token.status().unwrap().execution_complete);
    assert_eq!(
        pool.usage()
            .unwrap()
            .used
            .get(&Resource::QueryWorkspaceBytes)
            .map_or(0, |v| v.0),
        0
    );
}

#[test]
fn in_list_never_silently_guesses_column_or_cast_affinity() {
    let (_, _, _, bridge) = setup();
    for sql in [
        "SELECT CAST('01' AS INTEGER) IN ('1')",
        "SELECT CAST('01' AS INTEGER) NOT IN ('1')",
        "SELECT string_idx FROM native_strings WHERE string_idx IN ('0')",
        "SELECT string_idx FROM native_strings WHERE string_idx NOT IN ('0')",
        "SELECT d.string_idx IN (1) FROM (SELECT CAST('1' AS TEXT) AS string_idx) d",
        "SELECT d.string_idx NOT IN (1) FROM (SELECT CAST('1' AS TEXT) AS string_idx) d",
    ] {
        assert_eq!(
            bridge.query(sql).unwrap_err().code,
            ErrorCode::UnsupportedQuery,
            "{sql}"
        );
    }
    let rows = bridge
        .query("SELECT string_idx FROM native_strings WHERE string_idx IN (0)")
        .unwrap();
    assert_eq!(rows.rows().len(), 1);
    let rows = bridge
        .query("SELECT string_idx FROM native_strings WHERE string_idx NOT IN (0)")
        .unwrap();
    assert!(!rows.rows().is_empty());
    let joined = bridge.query("SELECT a.string_idx FROM native_strings a JOIN native_strings b ON a.string_idx=b.string_idx WHERE a.string_idx IN (0)").unwrap();
    assert_eq!(joined.rows().len(), 1);
    assert_eq!(
        bridge.query("SELECT 1 IN ('1')").unwrap().rows()[0][0],
        crate::values::SqlValue::I64(mdd_query::ir::Signed64(0))
    );
    assert_eq!(
        bridge
            .query("SELECT missing IN ('1') FROM native_strings")
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
}
