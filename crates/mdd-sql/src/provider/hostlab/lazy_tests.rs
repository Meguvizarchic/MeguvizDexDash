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
}
