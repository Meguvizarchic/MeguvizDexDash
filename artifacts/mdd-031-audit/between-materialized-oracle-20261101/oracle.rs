//! Controlled SQLite materialization and evaluation-order oracle; not a bridge proof.
use rusqlite::{functions::FunctionFlags, Connection};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

fn run(db: &Connection, left: &AtomicUsize, upper: &AtomicUsize, sql: &str)
    -> (Result<Vec<Option<i64>>, String>, usize, usize) {
    left.store(0, Ordering::SeqCst);
    upper.store(0, Ordering::SeqCst);
    let result = (|| -> rusqlite::Result<Vec<Option<i64>>> {
        let mut statement = db.prepare(sql)?;
        let rows = statement.query_map([], |row| row.get::<_, Option<i64>>(0))?;
        rows.collect()
    })().map_err(|e| e.to_string());
    (result, left.load(Ordering::SeqCst), upper.load(Ordering::SeqCst))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Connection::open_in_memory()?;
    let left = Arc::new(AtomicUsize::new(0));
    let upper = Arc::new(AtomicUsize::new(0));
    let x = Arc::clone(&left);
    db.create_scalar_function("observe_left", 1, FunctionFlags::SQLITE_UTF8, move |ctx| {
        x.fetch_add(1, Ordering::SeqCst);
        ctx.get::<Option<i64>>(0)
    })?;
    let u = Arc::clone(&upper);
    db.create_scalar_function("fail_upper", 0, FunctionFlags::SQLITE_UTF8, move |_| -> rusqlite::Result<i64> {
        u.fetch_add(1, Ordering::SeqCst);
        Err(rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other("controlled upper error"))))
    })?;
    let cases = [
        ("select_false", "SELECT observe_left(1) BETWEEN 2 AND fail_upper()", "SELECT (WITH c AS MATERIALIZED (SELECT observe_left(1) AS v) SELECT v >= 2 AND v <= fail_upper() FROM c)"),
        ("where_false", "SELECT 1 WHERE observe_left(1) BETWEEN 2 AND fail_upper()", "SELECT 1 WHERE (WITH c AS MATERIALIZED (SELECT observe_left(1) AS v) SELECT CASE (v >= 2) WHEN 0 THEN 0 WHEN 1 THEN v <= fail_upper() ELSE NULL END FROM c)"),
        ("where_null", "SELECT 1 WHERE observe_left(1) BETWEEN NULL AND fail_upper()", "SELECT 1 WHERE (WITH c AS MATERIALIZED (SELECT observe_left(1) AS v) SELECT CASE (v >= NULL) WHEN 0 THEN 0 WHEN 1 THEN v <= fail_upper() ELSE NULL END FROM c)"),
        ("where_not", "SELECT 1 WHERE observe_left(1) NOT BETWEEN 2 AND fail_upper()", "SELECT 1 WHERE (WITH c AS MATERIALIZED (SELECT observe_left(1) AS v) SELECT CASE (v >= 2) WHEN 0 THEN 1 WHEN 1 THEN NOT (v <= fail_upper()) ELSE NULL END FROM c)"),
    ];
    for (label, original, candidate) in cases {
        let a = run(&db, &left, &upper, original);
        let b = run(&db, &left, &upper, candidate);
        if a != b { return Err(format!("{label}: original={a:?}, candidate={b:?}").into()); }
        println!("{label}: same result and call counts");
    }
    db.execute_batch("CREATE TABLE vals(id INTEGER); INSERT INTO vals VALUES(1),(2),(3)")?;
    let original = "SELECT observe_left(id) BETWEEN 1 AND 2 FROM vals ORDER BY id";
    let candidate = "SELECT (WITH c AS MATERIALIZED (SELECT observe_left(id) AS v) SELECT v >= 1 AND v <= 2 FROM c) FROM vals ORDER BY id";
    let a = run(&db, &left, &upper, original);
    let b = run(&db, &left, &upper, candidate);
    if a != b { return Err(format!("correlated_rows: original={a:?}, candidate={b:?}").into()); }
    println!("correlated_rows: same result and call counts");
    println!("sqlite_version={} observations=5 qualification=false", rusqlite::version());
    Ok(())
}
