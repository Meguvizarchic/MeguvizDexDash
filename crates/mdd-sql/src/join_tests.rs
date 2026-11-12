use crate::{
    SqlBridge,
    control::{SqlControl, SqlLimits},
    dialects::SqlDialect,
    provider::{SqlBinding, SqlColumn, SqlFactCursor, SqlFactProvider, SqlRelation, SqlRow},
    values::{SqlType, SqlValue},
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use std::sync::Arc;

struct Provider {
    binding: SqlBinding,
}
struct Cursor(std::vec::IntoIter<SqlRow>);
impl SqlFactCursor for Cursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        Ok(self.0.next())
    }
}
fn col(name: &str, data_type: SqlType) -> SqlColumn {
    SqlColumn {
        id: name.into(),
        name: name.into(),
        data_type,
        nullable: false,
    }
}
fn uint(n: u64) -> SqlValue {
    SqlValue::U64(DecimalU64(n))
}
impl SqlFactProvider for Provider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        Ok(vec![
            SqlRelation {
                name: "classes".into(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("class_idx", SqlType::U64),
                    col("descriptor", SqlType::Text),
                ],
                required_layers: vec![],
                estimated_rows: Some(DecimalU64(2)),
            },
            SqlRelation {
                name: "class_interfaces".into(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("class_idx", SqlType::U64),
                    col("ordinal", SqlType::U64),
                    col("interface_descriptor", SqlType::Text),
                    col("descriptor", SqlType::U64),
                ],
                required_layers: vec![],
                estimated_rows: Some(DecimalU64(4)),
            },
        ])
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        if ["classes", "class_interfaces"].contains(&relation) {
            Ok(())
        } else {
            Err(MddError::new(
                ErrorCode::InvalidArgument,
                "fixture",
                "missing relation",
            ))
        }
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        _: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        self.require_relation(relation)?;
        let rows = if relation == "classes" {
            vec![
                vec![uint(0), uint(1), SqlValue::text("Lfixture/A;")],
                vec![uint(0), uint(2), SqlValue::text("Lfixture/B;")],
            ]
        } else {
            vec![
                vec![
                    uint(0),
                    uint(1),
                    uint(0),
                    SqlValue::text("Lfixture/I1;"),
                    uint(1),
                ],
                vec![
                    uint(0),
                    uint(1),
                    uint(1),
                    SqlValue::text("Lfixture/I1;"),
                    uint(1),
                ],
                vec![
                    uint(0),
                    uint(1),
                    uint(2),
                    SqlValue::text("Lfixture/I2;"),
                    uint(2),
                ],
                vec![
                    uint(0),
                    uint(2),
                    uint(0),
                    SqlValue::text("Lfixture/I3;"),
                    uint(3),
                ],
            ]
        };
        Ok(Box::new(Cursor(rows.into_iter())))
    }
}
fn bridge() -> SqlBridge {
    let provider = Arc::new(Provider {
        binding: SqlBinding {
            provider_identity: "q03-synthetic".into(),
            snapshot_id: "fixture-only".into(),
            catalog_epoch: DecimalU64(0),
        },
    });
    SqlBridge::new(provider, SqlDialect::DexSql010, SqlLimits::default()).unwrap()
}

/// A wide result must not fail merely because resident result memory is
/// admitted one row at a time. `BudgetPool` caps live reservations (10,000),
/// so a fixed 4 KiB ticket per row would exhaust that metadata budget at
/// roughly 40 MiB regardless of the `QueryWorkspaceBytes` ceiling. Chunked
/// admission keeps the ticket count logarithmic while `used` still matches the
/// exact admitted bytes.
#[test]
fn wide_result_admits_chunked_workspace_without_exhausting_reservation_metadata() {
    use mdd_query::budget::{BudgetLimits, BudgetPool, BudgetScope, Resource, RuntimeBudget};
    use mdd_session::{Lifecycle, ResourceLimits};
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let snapshot = Arc::new(
        mdd_input::snapshot::Snapshot::capture(
            &[mdd_input::snapshot::InputSpec {
                path: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/generated/minimal-035.dex"),
                kind: mdd_input::snapshot::InputKind::RawDex,
                expected_sha256: None,
            }],
            mdd_input::snapshot::CaptureLimits::default(),
        )
        .unwrap(),
    );
    let snapshot_id = snapshot.manifest().snapshot_id.clone();
    let snapshot = lifecycle.register_snapshot(snapshot).unwrap();
    let provider = Arc::new(WideProvider {
        binding: SqlBinding {
            provider_identity: "wide-synthetic".into(),
            snapshot_id,
            catalog_epoch: DecimalU64(0),
        },
        rows: 200_000,
    });
    let wide_limits = SqlLimits {
        max_result_rows: 1_000_000,
        max_result_bytes: 512 * 1024 * 1024,
        max_steps: 50_000_000,
        ..SqlLimits::default()
    };
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, wide_limits).unwrap();
    let prepared = bridge.prepare("SELECT a, b FROM wide").unwrap();
    let session = lifecycle
        .open_session(&snapshot, ResourceLimits::default())
        .unwrap();
    let query = lifecycle
        .prepare_query(
            &session,
            prepared.runtime_query_binding().unwrap(),
            ResourceLimits::default(),
        )
        .unwrap();
    lifecycle.start_query(&session, &query, 1).unwrap();
    let token = lifecycle.cancellation_token(&query).unwrap();
    let limits = BudgetLimits::default()
        .with(Resource::QueryWorkspaceBytes, 512 * 1024 * 1024)
        .with(Resource::QuerySteps, u64::MAX);
    let global = BudgetPool::global("wide-root".into(), limits.clone()).unwrap();
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
    let runtime = RuntimeBudget::new(query_budget, token.clone()).unwrap();
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let result = bound
        .execute(SqlControl::new(wide_limits, None).with_runtime(runtime))
        .expect("a 200k-row result must not exhaust reservation metadata");
    assert_eq!(result.rows().len(), 200_000);
    assert!(token.status().unwrap().execution_complete);
    let admitted = pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0;
    assert!(
        admitted > 40 * 1024 * 1024,
        "result must actually exceed the 4 KiB-per-row metadata ceiling: {admitted}"
    );
    drop(result);
    assert_eq!(
        pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0,
        0,
        "result workspace must be fully released after the result is dropped"
    );
}

struct WideProvider {
    binding: SqlBinding,
    rows: u64,
}
struct WideCursor(std::ops::Range<u64>);
impl SqlFactCursor for WideCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        Ok(self
            .0
            .next()
            .map(|n| vec![uint(n), SqlValue::text(&format!("row-{n:012}"))]))
    }
}
impl SqlFactProvider for WideProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        Ok(vec![SqlRelation {
            name: "wide".into(),
            columns: vec![col("a", SqlType::U64), col("b", SqlType::Text)],
            required_layers: vec![],
            estimated_rows: Some(DecimalU64(self.rows)),
        }])
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        if relation == "wide" {
            Ok(())
        } else {
            Err(MddError::new(
                ErrorCode::InvalidArgument,
                "fixture",
                "missing relation",
            ))
        }
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        _: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        self.require_relation(relation)?;
        Ok(Box::new(WideCursor(0..self.rows)))
    }
}

#[test]
fn q03_join_resolves_qualified_source_and_preserves_duplicate_rows() {
    let bridge = bridge();
    let sql = "SELECT ci.interface_descriptor,c.descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE c.descriptor IN ('Lfixture/A;') ORDER BY ci.file_id,ci.class_idx,ci.ordinal";
    let result = bridge.query(sql).unwrap();
    assert_eq!(result.columns(), &["interface_descriptor", "descriptor"]);
    assert_eq!(
        result.rows(),
        &[
            vec![
                SqlValue::text("Lfixture/I1;"),
                SqlValue::text("Lfixture/A;")
            ],
            vec![
                SqlValue::text("Lfixture/I1;"),
                SqlValue::text("Lfixture/A;")
            ],
            vec![
                SqlValue::text("Lfixture/I2;"),
                SqlValue::text("Lfixture/A;")
            ],
        ]
    );
    let numeric = bridge.query("SELECT ci.ordinal FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE ci.descriptor IN (1) ORDER BY ci.ordinal").unwrap();
    assert_eq!(numeric.rows().len(), 2);
    let sqlite = rusqlite::Connection::open_in_memory().unwrap();
    sqlite.execute_batch("CREATE TABLE classes(file_id INTEGER, class_idx INTEGER); CREATE TABLE class_interfaces(file_id INTEGER, class_idx INTEGER, ordinal INTEGER, descriptor INTEGER); INSERT INTO classes VALUES (0,1),(0,2); INSERT INTO class_interfaces VALUES (0,1,0,1),(0,1,1,1),(0,1,2,2),(0,2,0,3);").unwrap();
    let oracle_sql = "SELECT ci.ordinal FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE ci.descriptor IN ('1') ORDER BY ci.ordinal";
    let mut stmt = sqlite.prepare(oracle_sql).unwrap();
    let expected: Vec<SqlValue> = stmt
        .query_map([], |row| row.get::<_, u32>(0))
        .unwrap()
        .map(|n| uint(u64::from(n.unwrap())))
        .collect();
    let actual = bridge.query(oracle_sql).unwrap();
    assert_eq!(
        actual
            .rows()
            .iter()
            .map(|row| row[0].clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(bridge.query("SELECT descriptor IN ('1') FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx").unwrap_err().code, ErrorCode::InvalidArgument);
    assert_eq!(bridge.query("SELECT z.descriptor IN ('1') FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx").unwrap_err().code, ErrorCode::InvalidArgument);
}
