//! Bundled SQLite evaluation-order observation; not engine qualification.
use rusqlite::{functions::FunctionFlags, Connection};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

fn check(db: &Connection, left: &AtomicUsize, upper: &AtomicUsize,
         sql: &str, expected_error: bool, expected_rows: usize,
         expected_left: usize, expected_upper: usize) -> Result<(), Box<dyn std::error::Error>> {
    left.store(0, Ordering::SeqCst);
    upper.store(0, Ordering::SeqCst);
    let actual = (|| -> rusqlite::Result<usize> {
        let mut statement = db.prepare(sql)?;
        let mut cursor = statement.query([])?;
        let mut rows = 0;
        while cursor.next()?.is_some() { rows += 1; }
        Ok(rows)
    })();
    if actual.is_err() != expected_error
        || actual.as_ref().is_ok_and(|n| *n != expected_rows)
        || left.load(Ordering::SeqCst) != expected_left
        || upper.load(Ordering::SeqCst) != expected_upper {
        return Err(format!("oracle mismatch: {sql}; result={actual:?}; left={}; upper={}",
            left.load(Ordering::SeqCst), upper.load(Ordering::SeqCst)).into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Connection::open_in_memory()?;
    let left = Arc::new(AtomicUsize::new(0));
    let upper = Arc::new(AtomicUsize::new(0));
    let l = Arc::clone(&left);
    db.create_scalar_function("observe_left", 1, FunctionFlags::SQLITE_UTF8, move |ctx| {
        l.fetch_add(1, Ordering::SeqCst);
        ctx.get::<String>(0)
    })?;
    let u = Arc::clone(&upper);
    db.create_scalar_function("observe_upper", 0, FunctionFlags::SQLITE_UTF8, move |_| {
        u.fetch_add(1, Ordering::SeqCst);
        Ok("z".to_owned())
    })?;
    let u = Arc::clone(&upper);
    db.create_scalar_function("fail_upper", 0, FunctionFlags::SQLITE_UTF8, move |_| -> rusqlite::Result<String> {
        u.fetch_add(1, Ordering::SeqCst);
        Err(rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other("controlled upper error"))))
    })?;
    check(&db, &left, &upper, "SELECT observe_left('a') BETWEEN 'b' AND fail_upper()", true, 0, 1, 1)?;
    check(&db, &left, &upper, "SELECT 1 WHERE observe_left('a') BETWEEN 'b' AND fail_upper()", false, 0, 1, 0)?;
    check(&db, &left, &upper, "SELECT 1 WHERE observe_left('a') NOT BETWEEN 'b' AND fail_upper()", false, 1, 1, 0)?;
    check(&db, &left, &upper, "SELECT observe_left('b') BETWEEN 'b' AND observe_upper()", false, 1, 1, 1)?;
    check(&db, &left, &upper, "SELECT observe_left('a') BETWEEN NULL AND observe_upper()", false, 1, 1, 1)?;
    check(&db, &left, &upper, "SELECT 1 WHERE observe_left('a') BETWEEN NULL AND observe_upper()", false, 0, 1, 0)?;
    println!("{{\"status\":\"passed\",\"sqlite_version\":\"{}\",\"observations\":6,\"qualification\":false}}", rusqlite::version());
    Ok(())
}
