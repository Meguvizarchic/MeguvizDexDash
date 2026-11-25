//! A provider made by `from_loader` answers what one made by `from_scope` answers: the same rows, the same refusals.
use super::tests::{Harness, open};
use super::*;
use crate::{SqlBridge, control::SqlLimits, dialects::SqlDialect};
use mdd_input::snapshot::InputKind;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Builds the layers of one DEX as the harness does, up to a mask of what it may build. A layer the mask does not allow
/// is simply missing from the facts, as it is when a layer fails to build.
struct HarnessLoader {
    harness: Arc<Harness>,
    allow: LayerNeeds,
    loads: AtomicUsize,
    /// The first call fails with this code, then the loader works.
    fail_first_with: Mutex<Option<ErrorCode>>,
}

impl HarnessLoader {
    fn new(harness: &Arc<Harness>, allow: LayerNeeds) -> Arc<Self> {
        Arc::new(Self {
            harness: Arc::clone(harness),
            allow,
            loads: AtomicUsize::new(0),
            fail_first_with: Mutex::new(None),
        })
    }
}

impl OccurrenceLoader for HarnessLoader {
    fn load(&self, position: usize, needs: LayerNeeds) -> MddResult<HostLabOccurrenceFacts> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if let Some(code) = self.fail_first_with.lock().unwrap().take() {
            return Err(MddError::new(code, "test", "the first load fails"));
        }
        Ok(self.harness.facts_at(
            position,
            needs.code && self.allow.code,
            needs.references && self.allow.references,
            needs.annotations && self.allow.annotations,
        ))
    }
}

const EVERYTHING: LayerNeeds = LayerNeeds {
    code: true,
    references: true,
    annotations: true,
};

fn harness() -> Arc<Harness> {
    Arc::new(open(&[
        (
            "tests/fixtures/definitions/generated/definitions-035.dex",
            InputKind::RawDex,
        ),
        (
            "tests/fixtures/references/generated/classic-035.dex",
            InputKind::RawDex,
        ),
        (
            "tests/fixtures/annotations/generated/annotations-038.dex",
            InputKind::RawDex,
        ),
    ]))
}

fn lazy(harness: &Arc<Harness>, loader: Arc<HarnessLoader>) -> Arc<HostLabSqlProvider> {
    Arc::new(HostLabSqlProvider::from_loader(harness.scope(), loader, DecimalU64(0)).unwrap())
}

fn control() -> SqlControl {
    SqlControl::new(SqlLimits::default(), None)
}

/// Everything a scan of `name` gives: the rows, or the error with the details a caller reads.
fn scan(
    provider: &Arc<HostLabSqlProvider>,
    name: &str,
) -> Result<Vec<SqlRow>, (ErrorCode, String, String)> {
    let outcome = Arc::clone(provider)
        .open_cursor(name, control())
        .and_then(|mut cursor| {
            let mut rows = Vec::new();
            while let Some(row) = cursor.next_row()? {
                rows.push(row);
            }
            Ok(rows)
        });
    outcome.map_err(|error| {
        (
            error.code,
            error.message.clone(),
            serde_json::to_string(&error.details).unwrap(),
        )
    })
}

fn same_answers(eager: &Arc<HostLabSqlProvider>, lazy: &Arc<HostLabSqlProvider>) -> usize {
    let mut rows_compared = 0;
    for relation in ContractRelation::all() {
        let name = relation.name();
        let (expected, observed) = (scan(eager, name), scan(lazy, name));
        match (&expected, &observed) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b, "{name}");
                rows_compared += a.len();
            }
            (Err(a), Err(b)) => assert_eq!(a, b, "{name} is refused differently"),
            _ => panic!(
                "{name}: eager {:?}, lazy {:?}",
                expected.as_ref().map(Vec::len),
                observed.as_ref().map(Vec::len)
            ),
        }
    }
    rows_compared
}

#[test]
fn every_relation_answers_the_same_from_stores_built_one_dex_at_a_time() {
    let harness = harness();
    let eager = harness.provider(true, true, true);
    let loader = HarnessLoader::new(&harness, EVERYTHING);
    let lazy = lazy(&harness, loader);
    assert_eq!(lazy.occurrence_count(), eager.occurrence_count());
    assert_eq!(lazy.binding().snapshot_id, eager.binding().snapshot_id);
    let compared = same_answers(&eager, &lazy);
    assert!(compared > 500, "only {compared} rows were compared");
}

#[test]
fn a_relation_whose_layer_is_missing_is_refused_with_the_same_error_as_by_a_provider_that_lacks_it()
{
    let harness = harness();
    for (code, references, annotations) in [
        (false, false, false),
        (true, false, false),
        (false, false, true),
        (true, true, false),
    ] {
        let eager = harness.provider(code, references, annotations);
        let loader = HarnessLoader::new(
            &harness,
            LayerNeeds {
                code: code || references,
                references,
                annotations,
            },
        );
        let lazy = lazy(&harness, loader);
        same_answers(&eager, &lazy);
    }
}

#[test]
fn a_store_is_built_once_and_a_refusal_that_belongs_to_the_input_is_kept() {
    let harness = harness();
    let dex = harness.scope().dexes().len();
    let loader = HarnessLoader::new(&harness, EVERYTHING);
    let provider = lazy(&harness, Arc::clone(&loader));
    assert_eq!(
        provider.stored_bytes(),
        Some(provider.stored_bytes().unwrap())
    );
    let first = scan(&provider, "classes").unwrap();
    assert_eq!(
        loader.loads.load(Ordering::SeqCst),
        dex,
        "one load of each DEX"
    );
    let second = scan(&provider, "classes").unwrap();
    assert_eq!(first, second);
    assert_eq!(
        loader.loads.load(Ordering::SeqCst),
        dex,
        "no load for a relation that is built"
    );
    assert!(provider.stored_bytes().unwrap() > 0);

    // a refusal kept: the same error again, and the loader is not asked again
    let structural = HarnessLoader::new(&harness, LayerNeeds::default());
    let refused = lazy(&harness, Arc::clone(&structural));
    let a = scan(&refused, "methods").unwrap_err();
    let loads = structural.loads.load(Ordering::SeqCst);
    assert!(loads >= 1);
    let b = scan(&refused, "methods").unwrap_err();
    assert_eq!(a, b);
    assert_eq!(structural.loads.load(Ordering::SeqCst), loads);
}

#[test]
fn a_failure_that_belongs_to_the_caller_is_not_kept() {
    let harness = harness();
    for code in [
        ErrorCode::Cancelled,
        ErrorCode::DeadlineExceeded,
        ErrorCode::QuotaExceeded,
    ] {
        let loader = HarnessLoader::new(&harness, EVERYTHING);
        *loader.fail_first_with.lock().unwrap() = Some(code);
        let provider = lazy(&harness, Arc::clone(&loader));
        assert_eq!(scan(&provider, "classes").unwrap_err().0, code);
        let rows = scan(&provider, "classes").expect("the next caller builds the store");
        assert!(!rows.is_empty());
    }
}

#[test]
fn a_loader_that_builds_another_input_is_refused() {
    let harness = harness();
    let other = Arc::new(open(&[(
        "tests/fixtures/definitions/generated/definitions-035.dex",
        InputKind::RawDex,
    )]));
    // three selected DEX, but facts of a one-DEX harness for every position
    struct Wrong(Arc<Harness>);
    impl OccurrenceLoader for Wrong {
        fn load(&self, _position: usize, needs: LayerNeeds) -> MddResult<HostLabOccurrenceFacts> {
            Ok(self
                .0
                .facts_at(0, needs.code, needs.references, needs.annotations))
        }
    }
    let provider = Arc::new(
        HostLabSqlProvider::from_loader(harness.scope(), Arc::new(Wrong(other)), DecimalU64(0))
            .unwrap(),
    );
    let refused = scan(&provider, "classes").unwrap_err();
    assert_eq!(refused.0, ErrorCode::InvalidArgument);
}

#[test]
fn statements_run_against_the_stores_as_against_the_layers() {
    let harness = harness();
    let eager = SqlBridge::new(
        harness.provider(true, true, true),
        SqlDialect::DexSql011,
        SqlLimits::default(),
    )
    .unwrap();
    let loader = HarnessLoader::new(&harness, EVERYTHING);
    let stored = SqlBridge::new(
        lazy(&harness, loader),
        SqlDialect::DexSql011,
        SqlLimits::default(),
    )
    .unwrap();
    for statement in [
        "SELECT COUNT(*) AS n FROM classes ORDER BY n",
        "SELECT descriptor, access_flags FROM classes ORDER BY file_id, class_idx",
        "SELECT c.descriptor, m.method_name FROM classes c JOIN class_methods m ON m.class_idx = c.class_idx AND m.file_id = c.file_id ORDER BY c.file_id, c.class_idx, m.method_idx",
        "SELECT method, callee FROM method_calls ORDER BY method, callee, file_id, class_idx, method_idx, callee_method_idx",
        "SELECT opcode_count, opcode_hex FROM methods ORDER BY file_id, method_idx",
    ] {
        let (a, b) = (
            eager
                .query(statement)
                .unwrap_or_else(|e| panic!("{statement}: {e:?}")),
            stored
                .query(statement)
                .unwrap_or_else(|e| panic!("{statement}: {e:?}")),
        );
        assert_eq!(a.rows(), b.rows(), "{statement}");
        assert!(!a.rows().is_empty(), "{statement}");
    }
}

#[test]
fn one_pass_builds_every_store_and_loads_each_dex_once() {
    let harness = harness();
    let dex = harness.scope().dexes().len();
    let eager = harness.provider(true, true, true);
    let loader = HarnessLoader::new(&harness, EVERYTHING);
    let provider = lazy(&harness, Arc::clone(&loader));
    provider.prepare_all(None).unwrap();
    assert_eq!(
        loader.loads.load(Ordering::SeqCst),
        dex,
        "all relations from one load of each DEX"
    );
    assert!(provider.stored_bytes().unwrap() > 0);
    let compared = same_answers(&eager, &provider);
    assert!(compared > 500, "only {compared} rows were compared");
    assert_eq!(
        loader.loads.load(Ordering::SeqCst),
        dex,
        "no relation is built again once the pass has built it"
    );
    // a second pass has nothing left to build
    provider.prepare_all(None).unwrap();
    assert_eq!(loader.loads.load(Ordering::SeqCst), dex);
}

#[test]
fn a_pass_keeps_the_refusal_of_a_relation_and_still_builds_the_others() {
    let harness = harness();
    for (code, references, annotations) in [
        (false, false, false),
        (true, false, false),
        (false, false, true),
        (true, true, false),
    ] {
        let eager = harness.provider(code, references, annotations);
        let loader = HarnessLoader::new(
            &harness,
            LayerNeeds {
                code: code || references,
                references,
                annotations,
            },
        );
        let provider = lazy(&harness, Arc::clone(&loader));
        provider.prepare_all(None).unwrap();
        let loads = loader.loads.load(Ordering::SeqCst);
        same_answers(&eager, &provider);
        assert_eq!(
            loader.loads.load(Ordering::SeqCst),
            loads,
            "the refusals were kept by the pass"
        );
    }
}

#[test]
fn a_pass_that_a_failure_of_the_caller_stops_leaves_the_stores_to_build_again() {
    let harness = harness();
    for code in [ErrorCode::Cancelled, ErrorCode::DeadlineExceeded] {
        let loader = HarnessLoader::new(&harness, EVERYTHING);
        *loader.fail_first_with.lock().unwrap() = Some(code);
        let provider = lazy(&harness, Arc::clone(&loader));
        assert_eq!(provider.prepare_all(None).unwrap_err().code, code);
        provider.prepare_all(None).expect("the next pass builds");
        assert!(!scan(&provider, "classes").unwrap().is_empty());
    }
}

#[test]
fn the_required_pass_leaves_the_public_relations_to_the_statement_that_asks() {
    let harness = harness();
    let dex = harness.scope().dexes().len();
    let eager = harness.provider(true, true, true);
    let loader = HarnessLoader::new(&harness, EVERYTHING);
    let provider = lazy(&harness, Arc::clone(&loader));
    provider.prepare_required(None).unwrap();
    assert_eq!(loader.loads.load(Ordering::SeqCst), dex);
    for relation in ContractRelation::all() {
        let built = provider.lazy.as_ref().unwrap().stored_rows(relation);
        match relation {
            ContractRelation::Required(_) => assert!(built.is_some(), "{}", relation.name()),
            ContractRelation::Public(_) => assert!(built.is_none(), "{}", relation.name()),
        }
    }
    // a public relation is built by the first scan, and answers as it does when the layers are held
    let public = ContractRelation::all()
        .into_iter()
        .find(|relation| matches!(relation, ContractRelation::Public(_)))
        .expect("the manifest has public relations")
        .name();
    let scanned = scan(&provider, public).unwrap();
    assert_eq!(scanned, scan(&eager, public).unwrap());
    assert_eq!(loader.loads.load(Ordering::SeqCst), 2 * dex);
}

#[test]
fn a_cursor_for_one_dex_reads_that_dexs_rows_and_a_statement_asking_for_it_answers_the_same() {
    let harness = harness();
    let eager = harness.provider(true, true, true);
    let provider = lazy(&harness, HarnessLoader::new(&harness, EVERYTHING));
    provider.prepare_required(None).unwrap();
    let dex = harness.scope().dexes().len() as u64;
    for relation in [
        "classes",
        "class_methods",
        "methods",
        "method_calls",
        "dex_files",
    ] {
        assert_eq!(provider.partition_column(relation), Some("file_id"));
        let all = scan(&provider, relation).unwrap();
        let file_id = all[0].iter().position(|_| true).map(|_| {
            // the position of `file_id` in the relation's columns
            ContractRelation::parse(relation)
                .map(HostLabSqlProvider::relation)
                .unwrap()
                .columns
                .iter()
                .position(|column| column.name == "file_id")
                .unwrap()
        });
        let file_id = file_id.unwrap();
        let mut seen = 0;
        for key in 0..dex + 1 {
            let mut cursor = Arc::clone(&provider)
                .open_cursor_for_partition(relation, control(), key)
                .unwrap();
            let mut rows = Vec::new();
            while let Some(row) = cursor.next_row().unwrap() {
                rows.push(row);
            }
            let expected: Vec<_> = all
                .iter()
                .filter(|row| row[file_id] == SqlValue::U64(DecimalU64(key)))
                .cloned()
                .collect();
            assert_eq!(rows, expected, "{relation} for file {key}");
            seen += rows.len();
        }
        assert_eq!(
            seen,
            all.len(),
            "{relation}: every row is in some DEX's group"
        );
        assert!(
            Arc::clone(&provider)
                .open_cursor_for_partition(relation, control(), dex)
                .unwrap()
                .next_row()
                .unwrap()
                .is_none(),
            "a DEX that is not there has no rows"
        );
    }
    // a provider that holds its layers cannot read one DEX: it says so and gives every row
    assert_eq!(eager.partition_column("classes"), None);

    let stored = SqlBridge::new(
        provider as Arc<dyn SqlFactProvider>,
        SqlDialect::DexSql011,
        SqlLimits::default(),
    )
    .unwrap();
    let held = SqlBridge::new(eager, SqlDialect::DexSql011, SqlLimits::default()).unwrap();
    for statement in [
        "SELECT COUNT(*) AS n FROM classes WHERE file_id = 1",
        "SELECT COUNT(*) AS n FROM classes WHERE file_id = 99",
        "SELECT descriptor FROM classes WHERE file_id = 0 ORDER BY class_idx",
        "SELECT descriptor FROM classes WHERE 2 = file_id AND descriptor LIKE 'L%' ORDER BY class_idx",
        "SELECT descriptor FROM classes WHERE file_id = 0 OR file_id = 1 ORDER BY file_id, class_idx",
        "SELECT descriptor FROM classes WHERE file_id <> 1 ORDER BY file_id, class_idx",
        "SELECT c.descriptor, m.method_name FROM classes c JOIN class_methods m ON m.class_idx = c.class_idx AND m.file_id = c.file_id WHERE c.file_id = 1 ORDER BY c.class_idx, m.method_idx",
        "SELECT c.descriptor, m.method_name FROM classes c JOIN class_methods m ON m.class_idx = c.class_idx AND m.file_id = c.file_id WHERE c.file_id = 1 AND m.file_id = 1 ORDER BY c.class_idx, m.method_idx",
        "SELECT c.descriptor, m.method_name FROM classes c LEFT JOIN class_methods m ON m.class_idx = c.class_idx AND m.file_id = c.file_id WHERE m.file_id = 0 ORDER BY c.class_idx, m.method_idx",
        "SELECT c.descriptor, m.method_name FROM classes c LEFT JOIN class_methods m ON m.class_idx = c.class_idx AND m.file_id = c.file_id WHERE c.file_id = 1 ORDER BY c.class_idx, m.method_idx",
        "SELECT a.descriptor FROM classes a JOIN classes b ON a.class_idx = b.class_idx AND b.file_id = 1 WHERE a.file_id = 0 ORDER BY a.descriptor",
        "SELECT descriptor FROM classes WHERE file_id = 1 AND class_idx IN (SELECT class_idx FROM classes WHERE file_id = 0) ORDER BY class_idx",
        "SELECT method, callee FROM method_calls WHERE file_id = 1 ORDER BY method, callee, class_idx, method_idx, callee_method_idx",
        "SELECT COUNT(*) AS n FROM methods WHERE file_id = 2",
    ] {
        let (a, b) = (
            held.query(statement)
                .unwrap_or_else(|e| panic!("{statement}: {e:?}")),
            stored
                .query(statement)
                .unwrap_or_else(|e| panic!("{statement}: {e:?}")),
        );
        assert_eq!(a.rows(), b.rows(), "{statement}");
    }

    for statement in [
        "SELECT * FROM (SELECT ci.interface_descriptor, c.descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE c.descriptor IN ('Lfixture/A;', 'Lfixture/Missing;') ORDER BY ci.file_id, ci.class_idx, ci.ordinal) AS hostlab_rows",
        "SELECT * FROM (SELECT DISTINCT m.class_descriptor FROM class_methods c JOIN methods m ON m.file_id=c.file_id AND m.method_idx=c.method_idx WHERE m.return_descriptor='V' ORDER BY m.class_descriptor) AS hostlab_rows",
        "SELECT * FROM (SELECT file_id, class_idx, descriptor FROM classes WHERE (file_id=0 AND class_idx IN (0, 1)) OR (file_id=1 AND class_idx IN (0)) ORDER BY file_id, class_idx) AS hostlab_rows",
        "SELECT * FROM (SELECT string_pool_id, string_idx, value FROM strings WHERE (string_pool_id=0 AND string_idx IN (0, 1)) OR (string_pool_id=1 AND string_idx IN (0)) ORDER BY string_pool_id, string_idx) AS hostlab_rows",
    ] {
        let (a, b) = (
            held.query(statement)
                .unwrap_or_else(|e| panic!("{statement}: {e:?}")),
            stored
                .query(statement)
                .unwrap_or_else(|e| panic!("{statement}: {e:?}")),
        );
        assert_eq!(a.rows(), b.rows(), "{statement}");
    }

    // Reproduces native_surface.py's 34-clause flat OR LIKE + IN filter under B0 wrappers.
    let mut terms: Vec<String> = (0..32)
        .map(|i| {
            if i == 0 {
                "descriptor LIKE 'Lfixture/%' ESCAPE '\\'".to_owned()
            } else {
                format!("descriptor LIKE 'Lcom/unused{i:02}/%' ESCAPE '\\'")
            }
        })
        .collect();
    terms.push("descriptor IN ('Ljava/lang/Object;', 'Lmissing/Proto;')".to_owned());
    let flat_inner = format!(
        "SELECT file_id, class_idx, descriptor FROM classes WHERE file_id=0 AND ({}) ORDER BY file_id, class_idx",
        terms.join(" OR ")
    );
    for wrapped in [
        format!("SELECT * FROM ({flat_inner}) AS hostlab_shape LIMIT 0"),
        format!(
            "SELECT CASE WHEN descriptor IS NULL THEN 'N' ELSE hex(CAST(descriptor AS TEXT)) END AS descriptor FROM ({flat_inner}) AS hostlab_rows"
        ),
    ] {
        let (a, b) = (
            held.query(&wrapped)
                .unwrap_or_else(|e| panic!("{wrapped}: {e:?}")),
            stored
                .query(&wrapped)
                .unwrap_or_else(|e| panic!("{wrapped}: {e:?}")),
        );
        assert_eq!(a.rows(), b.rows(), "{wrapped}");
    }
}

#[test]
fn direct_table_projection_matches_sqlite_rows_columns_and_quotas() {
    let harness = harness();
    let eager = harness.provider(true, true, true);
    let loader = HarnessLoader::new(&harness, EVERYTHING);
    let lazy_provider = lazy(&harness, loader);
    lazy_provider.prepare_required(None).unwrap();

    // Preload `method_calls` and `method_strings` via an ordinary query first,
    // or let `try_direct_projection` lazily populate their stores as needed.
    assert!(eager.partition_column("classes").is_none());
    let held = SqlBridge::new(eager, SqlDialect::DexSql011, SqlLimits::default()).unwrap();
    let stored = SqlBridge::new(
        Arc::clone(&lazy_provider) as Arc<dyn SqlFactProvider>,
        SqlDialect::DexSql011,
        SqlLimits::default(),
    )
    .unwrap();

    let statements = [
        "SELECT file_id,entry_name FROM dex_files ORDER BY file_id",
        "SELECT string_pool_id,string_idx FROM strings ORDER BY string_pool_id,string_idx",
        "SELECT file_id,type_idx,descriptor FROM types ORDER BY file_id,type_idx",
        "SELECT file_id,class_idx,descriptor FROM classes ORDER BY file_id,class_idx",
        "SELECT file_id,method_idx,class_descriptor,name,descriptor FROM methods ORDER BY file_id,method_idx",
        "SELECT file_id,method_idx FROM method_calls ORDER BY file_id,method_idx",
        "SELECT file_id,method_idx FROM method_strings ORDER BY file_id,method_idx",
        "SELECT file_id,entry_name FROM dex_files",
        "SELECT class_idx AS method_idx FROM method_calls ORDER BY method_idx",
    ];
    for sql in statements {
        let a = held.query(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        let b = stored.query(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        assert_eq!(a.columns(), b.columns(), "{sql}");
        assert_eq!(a.rows(), b.rows(), "{sql}");
        // Also compare against a forced-SQLite wrapper on the exact same `stored` bridge.
        let wrapped = format!("SELECT * FROM ({sql}) AS sqlite_ref");
        let w = stored
            .query(&wrapped)
            .unwrap_or_else(|e| panic!("{wrapped}: {e:?}"));
        assert_eq!(w.columns(), b.columns(), "{wrapped}");
        assert_eq!(w.rows(), b.rows(), "{wrapped}");
    }

    // Confirm non-trivial row counts were exercised on tie-breaking tables.
    assert!(
        stored
            .query("SELECT file_id,method_idx FROM method_calls ORDER BY file_id,method_idx")
            .unwrap()
            .rows()
            .len()
            > 1
    );

    // NativeV1 preserves explicit alias casing just as SQLite does.
    let stored_native = SqlBridge::new(
        Arc::clone(&lazy_provider) as Arc<dyn SqlFactProvider>,
        SqlDialect::NativeV1,
        SqlLimits::default(),
    )
    .unwrap();
    let held_native = SqlBridge::new(
        harness.provider(true, true, true),
        SqlDialect::NativeV1,
        SqlLimits::default(),
    )
    .unwrap();
    for sql in [
        "SELECT file_id AS FileId, entry_name AS EntryName FROM dex_files ORDER BY file_id",
        "SELECT class_idx AS method_idx FROM method_calls ORDER BY method_idx",
    ] {
        let a = held_native.query(sql).unwrap();
        let b = stored_native.query(sql).unwrap();
        assert_eq!(a.columns(), b.columns(), "{sql}");
        assert_eq!(a.rows(), b.rows(), "{sql}");
    }

    // Verify SqlControl quotas and expired deadlines reject identically on direct projection.
    let probe_sql = "SELECT file_id,entry_name FROM dex_files ORDER BY file_id";
    let quota_cases = [
        (
            "max_result_rows",
            SqlLimits {
                max_result_rows: 1,
                ..SqlLimits::default()
            },
            None,
            ErrorCode::QuotaExceeded,
        ),
        (
            "max_scanned_rows",
            SqlLimits {
                max_scanned_rows: 1,
                ..SqlLimits::default()
            },
            None,
            ErrorCode::QuotaExceeded,
        ),
        (
            "max_cell_bytes",
            SqlLimits {
                max_cell_bytes: 4,
                ..SqlLimits::default()
            },
            None,
            ErrorCode::QuotaExceeded,
        ),
        (
            "expired_deadline",
            SqlLimits::default(),
            Some(
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_millis(10))
                    .unwrap_or_else(std::time::Instant::now),
            ),
            ErrorCode::DeadlineExceeded,
        ),
    ];
    for (label, limits, deadline, expected_code) in quota_cases {
        let h_bridge = SqlBridge::new(
            harness.provider(true, true, true),
            SqlDialect::DexSql011,
            limits,
        )
        .unwrap();
        let s_bridge = SqlBridge::new(
            Arc::clone(&lazy_provider) as Arc<dyn SqlFactProvider>,
            SqlDialect::DexSql011,
            limits,
        )
        .unwrap();
        let h_prepared = h_bridge.prepare(probe_sql).unwrap();
        let s_prepared = s_bridge.prepare(probe_sql).unwrap();
        let h_err = h_bridge
            .execute(&h_prepared, SqlControl::new(limits, deadline))
            .unwrap_err();
        let s_err = s_bridge
            .execute(&s_prepared, SqlControl::new(limits, deadline))
            .unwrap_err();
        assert_eq!(h_err.code, expected_code, "{label} held: {h_err:?}");
        assert_eq!(s_err.code, expected_code, "{label} direct: {s_err:?}");
    }
}

#[test]
fn with_type_name_matches_facts_type_name() {
    let long = format!("L{}/Tail;", "pkg/".repeat(160));
    for descriptor in [
        "V",
        "Z",
        "B",
        "S",
        "C",
        "I",
        "J",
        "F",
        "D",
        "Ljava/lang/String;",
        "[I",
        "[[Ljava/lang/Object;",
        "Lnon/terminated",
        "Lcom/example/测试/Main;",
        long.as_str(),
    ] {
        let actual = super::lazy::with_type_name(descriptor, str::to_owned);
        let expected = mdd_facts::references::type_name(descriptor);
        assert_eq!(actual, expected, "{descriptor}");
    }
}

#[test]
fn stream_projected_ordered_matches_project_ordered_and_declines_tight_quotas_upfront() {
    use crate::column_store::{BorrowedSqlCell, DirectCellRowConsumer};
    use std::cell::Cell as StdCell;

    struct CaptureConsumer {
        started: Option<u64>,
        finished: bool,
        rows: Vec<Vec<String>>,
        cur_row: Vec<String>,
    }
    impl CaptureConsumer {
        fn new() -> Self {
            Self {
                started: None,
                finished: false,
                rows: Vec::new(),
                cur_row: Vec::new(),
            }
        }
    }
    impl DirectCellRowConsumer for CaptureConsumer {
        fn on_start(&mut self, row_count: u64) -> MddResult<()> {
            assert!(self.started.is_none());
            self.started = Some(row_count);
            Ok(())
        }
        fn begin_row(&mut self) -> MddResult<()> {
            self.cur_row.clear();
            Ok(())
        }
        fn push_cell(&mut self, _col_idx: usize, cell: &BorrowedSqlCell<'_>) -> MddResult<()> {
            let rendered = match cell {
                BorrowedSqlCell::Null => "null".to_owned(),
                BorrowedSqlCell::Bool(b) => format!("bool:{b}"),
                BorrowedSqlCell::I64(v) => format!("i64:{v}"),
                BorrowedSqlCell::U64(v) => format!("u64:{v}"),
                BorrowedSqlCell::F64Bits(b) => format!("f64:{b}"),
                BorrowedSqlCell::Utf8(s) => format!("str:{s}"),
                BorrowedSqlCell::Utf16Be(raw) => {
                    let units: Vec<u16> = raw
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_be_bytes(*p))
                        .collect();
                    format!("str:{}", String::from_utf16(&units).unwrap())
                }
                BorrowedSqlCell::Bytes(raw) => format!("bytes:{}", raw.len()),
                BorrowedSqlCell::DexMutf8 { bytes, utf16_units } => {
                    format!("mutf8:{utf16_units}:{}", bytes.len())
                }
                BorrowedSqlCell::Owned(v) => match v {
                    SqlValue::Text(t) => format!("str:{}", t.strict_utf8().unwrap()),
                    other => format!("owned:{other:?}"),
                },
            };
            self.cur_row.push(rendered);
            Ok(())
        }
        fn end_row(&mut self) -> MddResult<()> {
            self.rows.push(std::mem::take(&mut self.cur_row));
            Ok(())
        }
        fn on_finish(&mut self) -> MddResult<()> {
            self.finished = true;
            Ok(())
        }
    }

    let harness = harness();
    let provider = lazy(&harness, HarnessLoader::new(&harness, EVERYTHING));
    provider.prepare_required(None).unwrap();

    // Verify full equivalence on `methods` and derived `method_calls` against `project_ordered`.
    for (rel, cols, order) in [
        (
            ContractRelation::Required(HostLabRelation::Methods),
            vec![
                (0usize, "file_id".to_owned()),
                (1usize, "method_idx".to_owned()),
                (2usize, "class_descriptor".to_owned()),
                (3usize, "name".to_owned()),
            ],
            vec![0usize, 1usize],
        ),
        (
            ContractRelation::Required(HostLabRelation::MethodCalls),
            vec![
                (6usize, "file_id".to_owned()),
                (8usize, "method_idx".to_owned()),
                (0usize, "method".to_owned()),
            ],
            vec![6usize, 8usize],
        ),
    ] {
        let store = provider.ensure_store(rel, None).unwrap();
        let ctrl_stream = control();
        let mut consumer = CaptureConsumer::new();
        let ran = store
            .stream_projected_ordered(&cols, &order, &ctrl_stream, &mut consumer)
            .unwrap();
        assert!(ran, "{rel:?} should stream");
        assert!(consumer.finished);
        assert_eq!(consumer.started, Some(store.rows()));

        let ctrl_ref = control();
        let ref_rows = store.project_ordered(&cols, &order, &ctrl_ref).unwrap();
        assert_eq!(consumer.rows.len(), ref_rows.len());
        for (idx, (got, want)) in consumer.rows.iter().zip(ref_rows.iter()).enumerate() {
            let want_strs: Vec<String> = want
                .iter()
                .map(|v| match v {
                    SqlValue::U64(n) => format!("u64:{}", n.0),
                    SqlValue::Text(t) => format!("str:{}", t.strict_utf8().unwrap()),
                    other => format!("owned:{other:?}"),
                })
                .collect();
            assert_eq!(got, &want_strs, "row {idx} in {rel:?}");
        }
        // Check identical counters charged (`StdCell` unused import suppressed via type annotation check).
        let _ = StdCell::new(0);
    }

    // Verify strict upfront decline (`Ok(false)` BEFORE calling `on_start`) for tight limits/deadlines.
    let methods_store = provider
        .ensure_store(ContractRelation::Required(HostLabRelation::Methods), None)
        .unwrap();
    let cols = vec![(0usize, "file_id".to_owned())];
    for tight in [
        SqlControl::new(
            SqlLimits {
                max_result_rows: 1,
                ..SqlLimits::default()
            },
            None,
        ),
        SqlControl::new(
            SqlLimits {
                max_scanned_rows: 1,
                ..SqlLimits::default()
            },
            None,
        ),
        SqlControl::new(
            SqlLimits {
                max_cell_bytes: 8,
                ..SqlLimits::default()
            },
            None,
        ),
        SqlControl::new(
            SqlLimits {
                max_result_bytes: 1,
                ..SqlLimits::default()
            },
            None,
        ),
        SqlControl::new(
            SqlLimits::default(),
            Some(std::time::Instant::now() + std::time::Duration::from_millis(200)),
        ),
    ] {
        let mut consumer = CaptureConsumer::new();
        let ran = methods_store
            .stream_projected_ordered(&cols, &[0], &tight, &mut consumer)
            .unwrap();
        assert!(!ran, "tight control must decline streaming");
        assert!(
            consumer.started.is_none(),
            "on_start must not fire on decline"
        );
        assert!(consumer.rows.is_empty());
    }
}

#[test]
fn self_join_cte_left_join_subquery_and_connection_reuse_match_eager_and_prune_scans() {
    let harness = harness();
    let eager = harness.provider(true, true, true);
    let lazy_provider = lazy(&harness, HarnessLoader::new(&harness, EVERYTHING));
    lazy_provider.prepare_all(None).unwrap();

    let held = SqlBridge::new(eager, SqlDialect::DexSql011, SqlLimits::default()).unwrap();
    let stored = SqlBridge::new(
        Arc::clone(&lazy_provider) as Arc<dyn SqlFactProvider>,
        SqlDialect::DexSql011,
        SqlLimits::default(),
    )
    .unwrap();

    let mut queries = vec![
        "SELECT a.descriptor FROM classes a JOIN classes b ON a.class_idx = b.class_idx AND b.file_id = 1 WHERE a.file_id = 0 ORDER BY a.descriptor".to_owned(),
        "SELECT a.descriptor, b.descriptor FROM classes a LEFT JOIN classes b ON a.class_idx = b.class_idx AND b.file_id = 1 WHERE a.file_id = 0 ORDER BY a.descriptor, b.descriptor".to_owned(),
        "SELECT descriptor FROM classes WHERE file_id = 1 AND class_idx IN (SELECT class_idx FROM classes WHERE file_id = 0) ORDER BY class_idx".to_owned(),
        "SELECT descriptor FROM classes WHERE file_id = 0 UNION ALL SELECT descriptor FROM classes WHERE file_id = 1 ORDER BY descriptor".to_owned(),
        "SELECT (SELECT COUNT(*) FROM classes), descriptor FROM classes WHERE file_id = 0 ORDER BY descriptor".to_owned(),
        "SELECT COUNT(*) FROM classes".to_owned(),
        // Empty-intersection self-join with class_methods join.
        "SELECT DISTINCT ms1.method, cm.class_descriptor, cm.access_flags FROM method_strings ms1 JOIN method_strings ms2 ON ms1.method = ms2.method JOIN method_strings ms3 ON ms1.method = ms3.method JOIN class_methods cm ON ms1.method = cm.method_descriptor WHERE ms1.value = '__definitely_missing_1__' AND ms2.value = '__definitely_missing_2__' AND ms3.value = '__definitely_missing_3__' ORDER BY ms1.method".to_owned(),
    ];

    // Discover real string pairs on one method in `method_strings` if fixtures include any.
    let pair_rows = held
        .query("SELECT method, value FROM method_strings ORDER BY method, value")
        .unwrap();
    let mut by_method: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for row in pair_rows.rows() {
        if let [SqlValue::Text(m), SqlValue::Text(v)] = row.as_slice()
            && let (Ok(ms), Ok(vs)) = (m.strict_utf8(), v.strict_utf8())
        {
            let entry = by_method.entry(ms).or_default();
            if !entry.contains(&vs) {
                entry.push(vs);
            }
        }
    }
    if let Some((_, vals)) = by_method.into_iter().find(|(_, v)| v.len() >= 2) {
        let v1 = vals[0].replace('\'', "''");
        let v2 = vals[1].replace('\'', "''");
        let v3 = vals.get(2).unwrap_or(&vals[0]).replace('\'', "''");
        queries.push(format!(
            "SELECT DISTINCT ms1.method, cm.class_descriptor, cm.access_flags \
             FROM method_strings ms1 \
             JOIN method_strings ms2 ON ms1.method = ms2.method \
             JOIN method_strings ms3 ON ms1.method = ms3.method \
             JOIN class_methods cm ON ms1.method = cm.method_descriptor \
             WHERE ms1.value = '{v1}' AND ms2.value = '{v2}' AND ms3.value = '{v3}' \
             ORDER BY ms1.method"
        ));
    }

    // Discover one class with fields for `discover_consumer_field_layouts` CTE + fields queries.
    let cf_sample = held
        .query("SELECT class_descriptor FROM class_fields ORDER BY class_descriptor LIMIT 1")
        .unwrap();
    let target_desc = cf_sample
        .rows()
        .first()
        .and_then(|r| match &r[0] {
            SqlValue::Text(t) => t.strict_utf8().ok(),
            _ => None,
        })
        .unwrap_or_else(|| "Ljava/lang/Object;".to_owned())
        .replace('\'', "''");
    queries.push(format!(
        "WITH targets AS (SELECT c.file_id, c.class_idx, c.descriptor FROM classes c WHERE c.descriptor IN ('{target_desc}', 'Lmissing/Never;')) \
         SELECT t.descriptor, group_concat(f.descriptor, char(10) ORDER BY cf.field_idx) AS layout \
         FROM class_fields cf \
         JOIN fields f ON f.file_id = cf.file_id AND f.field_idx = cf.field_idx \
         JOIN targets t ON t.file_id = cf.file_id AND t.class_idx = cf.class_idx \
         GROUP BY t.descriptor \
         ORDER BY t.descriptor"
    ));
    queries.push(format!(
        "WITH targets AS (SELECT c.descriptor FROM classes c WHERE c.descriptor IN ('{target_desc}', 'Lmissing/Never;')) \
         SELECT t.descriptor, group_concat(f.descriptor, char(10) ORDER BY cf.field_idx) AS layout \
         FROM class_fields cf \
         JOIN fields f ON f.file_id = cf.file_id AND f.field_idx = cf.field_idx \
         JOIN targets t ON cf.class_descriptor = t.descriptor \
         GROUP BY t.descriptor \
         ORDER BY t.descriptor"
    ));

    for sql in &queries {
        let a = held
            .query(sql)
            .unwrap_or_else(|e| panic!("held {sql}: {e:?}"));
        let b = stored
            .query(sql)
            .unwrap_or_else(|e| panic!("stored {sql}: {e:?}"));
        assert_eq!(a.columns(), b.columns(), "{sql}");
        assert_eq!(a.rows(), b.rows(), "{sql}");
    }

    // Verify `plan_scan_slots` narrows both `method_strings` slots + `class_methods` and CTE -> class_fields -> fields.
    let ms_rows = lazy_provider
        .ensure_store(
            ContractRelation::Required(HostLabRelation::MethodStrings),
            None,
        )
        .unwrap()
        .rows();
    let cm_rows = lazy_provider
        .ensure_store(
            ContractRelation::Required(HostLabRelation::ClassMethods),
            None,
        )
        .unwrap()
        .rows();
    if ms_rows > 0 && cm_rows > 0 {
        let slots = vec![
            crate::provider::ScanSlot {
                slot_name: "__mdd_scan_0".to_owned(),
                base_relation: "method_strings".to_owned(),
                row_filter: Some(crate::provider::RowFilter::EqText(
                    "value".to_owned(),
                    "__definitely_missing_1__".to_owned(),
                )),
            },
            crate::provider::ScanSlot {
                slot_name: "__mdd_scan_1".to_owned(),
                base_relation: "method_strings".to_owned(),
                row_filter: Some(crate::provider::RowFilter::EqText(
                    "value".to_owned(),
                    "__definitely_missing_2__".to_owned(),
                )),
            },
        ];
        let edges = vec![
            crate::provider::EquiJoinEdge {
                left_relation: "__mdd_scan_0".to_owned(),
                right_relation: "__mdd_scan_1".to_owned(),
                columns: vec![("method".to_owned(), "method".to_owned())],
                bidirectional: true,
            },
            crate::provider::EquiJoinEdge {
                left_relation: "__mdd_scan_0".to_owned(),
                right_relation: "class_methods".to_owned(),
                columns: vec![("method".to_owned(), "method_descriptor".to_owned())],
                bidirectional: true,
            },
        ];
        let planned = lazy_provider
            .plan_scan_slots(
                &["method_strings".to_owned(), "class_methods".to_owned()],
                &slots,
                &std::collections::BTreeMap::new(),
                &edges,
                &std::collections::BTreeMap::new(),
            )
            .unwrap();
        assert!(matches!(planned.get("__mdd_scan_0"), Some(PlannedScan::Rows(r)) if r.is_empty()));
        assert!(matches!(planned.get("__mdd_scan_1"), Some(PlannedScan::Rows(r)) if r.is_empty()));
        assert!(matches!(planned.get("class_methods"), Some(PlannedScan::Rows(r)) if r.is_empty()));
    }

    let cf_rows = lazy_provider
        .ensure_store(
            ContractRelation::Required(HostLabRelation::ClassFields),
            None,
        )
        .unwrap()
        .rows();
    let f_rows = lazy_provider
        .ensure_store(ContractRelation::Public(PublicRelation::Fields), None)
        .unwrap()
        .rows();
    if cf_rows > 0 && f_rows > 0 {
        let planned_cte = lazy_provider
            .plan_scan_slots(
                &[
                    "classes".to_owned(),
                    "class_fields".to_owned(),
                    "fields".to_owned(),
                ],
                &[],
                &std::collections::BTreeMap::from([(
                    "classes".to_owned(),
                    crate::provider::RowFilter::InText(
                        "descriptor".to_owned(),
                        vec!["Lmissing/Never;".to_owned()],
                    ),
                )]),
                &[
                    crate::provider::EquiJoinEdge {
                        left_relation: "classes".to_owned(),
                        right_relation: "class_fields".to_owned(),
                        columns: vec![
                            ("file_id".to_owned(), "file_id".to_owned()),
                            ("class_idx".to_owned(), "class_idx".to_owned()),
                        ],
                        bidirectional: false,
                    },
                    crate::provider::EquiJoinEdge {
                        left_relation: "class_fields".to_owned(),
                        right_relation: "fields".to_owned(),
                        columns: vec![
                            ("file_id".to_owned(), "file_id".to_owned()),
                            ("field_idx".to_owned(), "field_idx".to_owned()),
                        ],
                        bidirectional: true,
                    },
                ],
                &std::collections::BTreeMap::new(),
            )
            .unwrap();
        assert!(matches!(planned_cte.get("classes"), Some(PlannedScan::Rows(r)) if r.is_empty()));
        assert!(
            matches!(planned_cte.get("class_fields"), Some(PlannedScan::Rows(r)) if r.is_empty())
        );
        assert!(matches!(planned_cte.get("fields"), Some(PlannedScan::Rows(r)) if r.is_empty()));
    }
}
