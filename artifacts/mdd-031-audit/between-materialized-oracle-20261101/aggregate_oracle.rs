//! Counterexample for moving outer aggregates into a materialized scalar CTE.
use rusqlite::Connection;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE vals(id INTEGER); INSERT INTO vals VALUES(1),(2),(3)")?;
    let rows = |sql: &str| -> rusqlite::Result<Vec<i64>> {
        let mut statement = db.prepare(sql)?;
        let iter = statement.query_map([], |row| row.get::<_, i64>(0))?;
        iter.collect()
    };
    let original = rows("SELECT lower(CAST(count(*) AS TEXT)) BETWEEN '0' AND '9' FROM vals")?;
    let candidate = rows("SELECT (WITH c AS MATERIALIZED (SELECT lower(CAST(count(*) AS TEXT)) AS v) SELECT v >= '0' AND v <= '9' FROM c) FROM vals")?;
    if original != [1] || candidate != [1, 1, 1] {
        return Err(format!("unexpected aggregate counterexample: original={original:?}, candidate={candidate:?}").into());
    }
    println!("aggregate_scope: native_rows={} candidate_rows={}", original.len(), candidate.len());
    println!("sqlite_version={} qualification=false", rusqlite::version());
    Ok(())
}
