//! Which rows of a relation a statement can use, found without changing the statement.
//!
//! A relation whose provider keeps the rows of one DEX together can be read for one DEX. The statement does not say so to
//! SQLite in a way SQLite can use: the dialect rewrites `file_id = 0` into a call of a comparison function, which the
//! virtual table is never told about. This looks at the statement as the user wrote it, before the rewrite, and finds the
//! one shape that matters and is safe to read: a relation named exactly once in the whole statement, in the `FROM` of
//! the outermost `SELECT`, whose partition column is required to equal a non-negative integer by a conjunct of that
//! `SELECT`'s `WHERE`.
//!
//! A row with another value in that column cannot be part of any row the statement outputs: the conjunct is false for it
//! however the relation is joined, and an outer join does not change that (the `WHERE` removes the row it makes up).
//! The statement still contains the condition, so a cursor that returns more rows than asked for changes nothing but the
//! time; this only chooses a smaller cursor.
use sqlparser::{
    ast::{BinaryOperator, Expr, Query, SetExpr, TableFactor, Value},
    tokenizer::Token,
};
use std::collections::BTreeMap;

/// `partition_columns` maps a relation name (lower case) to its partition column (lower case). The result maps a relation
/// name (lower case) to the value its partition column must have.
pub(crate) fn partition_hints(
    query: &Query,
    tokens: &[Token],
    partition_columns: &BTreeMap<String, String>,
) -> BTreeMap<String, u64> {
    let mut hints = BTreeMap::new();
    if partition_columns.is_empty() {
        return hints;
    }
    let SetExpr::Select(select) = &*query.body else {
        return hints;
    };
    let Some(selection) = &select.selection else {
        return hints;
    };
    // the plain tables of the outermost FROM, by the name a column is qualified with
    let mut tables: Vec<(String, String)> = Vec::new();
    for from in &select.from {
        for factor in std::iter::once(&from.relation).chain(from.joins.iter().map(|j| &j.relation))
        {
            if let TableFactor::Table {
                name,
                alias,
                args: None,
                ..
            } = factor
                && name.0.len() == 1
                && let Some(ident) = name.0[0].as_ident()
            {
                let relation = ident.value.to_ascii_lowercase();
                let qualifier = alias.as_ref().map_or_else(
                    || relation.clone(),
                    |alias| alias.name.value.to_ascii_lowercase(),
                );
                tables.push((relation, qualifier));
            }
        }
    }
    let only_table = tables.len() == 1 && select.from.len() == 1 && select.from[0].joins.is_empty();
    // the conjuncts of the WHERE, without recursion: a statement may be a long chain
    let mut pending = vec![selection];
    let mut conflicting: Vec<String> = Vec::new();
    while let Some(expr) = pending.pop() {
        match expr {
            Expr::Nested(inner) => pending.push(inner),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => {
                pending.push(left);
                pending.push(right);
            }
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => {
                let Some((column, value)) =
                    column_and_number(left, right).or_else(|| column_and_number(right, left))
                else {
                    continue;
                };
                let relation = match column {
                    Column::Qualified(qualifier, name) => tables
                        .iter()
                        .find(|(_, candidate)| *candidate == qualifier)
                        .map(|(relation, _)| (relation.clone(), name)),
                    Column::Bare(name) if only_table => Some((tables[0].0.clone(), name)),
                    Column::Bare(_) => None,
                };
                let Some((relation, name)) = relation else {
                    continue;
                };
                if partition_columns.get(&relation) != Some(&name) {
                    continue;
                }
                match hints.insert(relation.clone(), value) {
                    Some(previous) if previous != value => conflicting.push(relation),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    for relation in conflicting {
        hints.remove(&relation);
    }
    // the relation must be named once in the whole statement; anything else may use its other rows. A name followed by a
    // period is a qualifier of a column (`classes.file_id`), not a mention of the table.
    hints.retain(|relation, _| mentions(tokens, relation) == 1);
    hints
}

/// How many times `name` appears in the statement other than as the qualifier of a column.
fn mentions(tokens: &[Token], name: &str) -> usize {
    tokens
        .iter()
        .enumerate()
        .filter(|(at, token)| {
            matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case(name))
                && tokens[at + 1..]
                    .iter()
                    .find(|next| !matches!(next, Token::Whitespace(_)))
                    != Some(&Token::Period)
        })
        .count()
}

enum Column {
    Bare(String),
    Qualified(String, String),
}

/// `column = number` with `column` a plain (possibly qualified) name and `number` a non-negative integer literal.
fn column_and_number(column: &Expr, number: &Expr) -> Option<(Column, u64)> {
    let value = match number {
        Expr::Value(value) => match &value.value {
            Value::Number(text, false) if text.bytes().all(|b| b.is_ascii_digit()) => {
                text.parse::<u64>().ok()?
            }
            _ => return None,
        },
        _ => return None,
    };
    let column = match column {
        Expr::Identifier(ident) => Column::Bare(ident.value.to_ascii_lowercase()),
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => Column::Qualified(
            parts[0].value.to_ascii_lowercase(),
            parts[1].value.to_ascii_lowercase(),
        ),
        _ => return None,
    };
    Some((column, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlparser::{ast::Statement, dialect::SQLiteDialect, parser::Parser, tokenizer::Tokenizer};

    fn hints(sql: &str) -> BTreeMap<String, u64> {
        let dialect = SQLiteDialect {};
        let tokens = Tokenizer::new(&dialect, sql).tokenize().unwrap();
        let statements = Parser::parse_sql(&dialect, sql).unwrap();
        let Statement::Query(query) = &statements[0] else {
            panic!("not a query");
        };
        let columns: BTreeMap<String, String> = ["classes", "class_methods", "method_calls"]
            .into_iter()
            .map(|name| (name.to_owned(), "file_id".to_owned()))
            .collect();
        partition_hints(query, &tokens, &columns)
    }

    fn one(relation: &str, value: u64) -> BTreeMap<String, u64> {
        BTreeMap::from([(relation.to_owned(), value)])
    }

    #[test]
    fn a_conjunct_that_requires_one_value_of_the_column_is_found() {
        for sql in [
            "SELECT * FROM classes WHERE file_id = 3",
            "SELECT * FROM classes WHERE 3 = file_id",
            "SELECT * FROM classes WHERE FILE_ID = 3 AND descriptor LIKE 'La%'",
            "SELECT * FROM classes WHERE descriptor LIKE 'La%' AND (file_id = 3)",
            "SELECT * FROM classes WHERE a = 1 AND (b = 2 AND (file_id = 3 AND c = 4))",
            "SELECT * FROM classes c WHERE c.file_id = 3",
            "SELECT * FROM classes AS c JOIN class_methods m ON m.class_idx = c.class_idx WHERE c.file_id = 3",
            "SELECT * FROM classes c LEFT JOIN class_methods m ON m.class_idx = c.class_idx WHERE c.file_id = 3 ORDER BY 1",
            "WITH x AS (SELECT 1) SELECT * FROM classes, x WHERE classes.file_id = 3",
        ] {
            assert_eq!(hints(sql), one("classes", 3), "{sql}");
        }
        assert_eq!(
            hints(
                "SELECT * FROM classes c JOIN class_methods m ON m.class_idx = c.class_idx WHERE c.file_id = 3 AND m.file_id = 3"
            ),
            BTreeMap::from([("classes".to_owned(), 3), ("class_methods".to_owned(), 3)])
        );
    }

    #[test]
    fn nothing_is_claimed_when_the_statement_could_use_other_rows() {
        for sql in [
            // not a conjunct that requires it
            "SELECT * FROM classes WHERE file_id = 3 OR descriptor = 'x'",
            "SELECT * FROM classes WHERE NOT (file_id = 3)",
            "SELECT * FROM classes WHERE file_id <> 3",
            "SELECT * FROM classes WHERE file_id >= 3",
            "SELECT * FROM classes WHERE file_id = 3 + 0",
            "SELECT * FROM classes WHERE file_id = -3",
            "SELECT * FROM classes WHERE file_id = 3.0",
            "SELECT * FROM classes WHERE file_id = '3'",
            "SELECT * FROM classes WHERE file_id = ?",
            "SELECT * FROM classes WHERE file_id = other",
            "SELECT * FROM classes WHERE file_id = 3 AND file_id = 4",
            "SELECT * FROM classes",
            // another column
            "SELECT * FROM classes WHERE class_idx = 3",
            // the relation is named more than once, so another use of it may need other rows
            "SELECT * FROM classes WHERE file_id = 3 AND class_idx IN (SELECT class_idx FROM classes)",
            "SELECT * FROM classes a JOIN classes b ON a.class_idx = b.class_idx WHERE a.file_id = 3",
            "WITH x AS (SELECT * FROM classes) SELECT * FROM classes WHERE file_id = 3",
            // the column is not the relation's
            "SELECT * FROM classes c JOIN class_methods m ON 1 = 1 WHERE file_id = 3",
            "SELECT * FROM classes c WHERE d.file_id = 3",
            // not a plain SELECT
            "SELECT * FROM classes WHERE file_id = 3 UNION SELECT * FROM classes WHERE file_id = 4",
            // the equality is inside a subquery or a derived table, not the outermost WHERE
            "SELECT * FROM (SELECT * FROM classes WHERE file_id = 3) t",
            "SELECT * FROM classes WHERE class_idx IN (SELECT 1 FROM class_methods WHERE file_id = 3)",
        ] {
            let found = hints(sql);
            assert!(found.is_empty(), "{sql}: {found:?}");
        }
    }
}
