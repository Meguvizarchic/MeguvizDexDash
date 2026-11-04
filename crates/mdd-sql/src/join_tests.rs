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
