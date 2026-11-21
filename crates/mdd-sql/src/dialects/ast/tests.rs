#[cfg(test)]
mod aggregate_scan_tests {
    use super::super::*;

    #[test]
    fn compound_carrier_nested_parentheses_charge_every_visit() {
        let mut expr = Expr::Value(Value::Number("1".into(), false).into());
        for _ in 0..4 {
            expr = Expr::Nested(Box::new(expr));
        }
        let budget = AggregateScan {
            depth_limit: 16,
            remaining: Cell::new(9),
        };
        assert!(charged_compound_expression(&expr, 0, &budget).is_ok());
        let error = charged_compound_expression(&expr, 0, &budget)
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.message, "SQL_AGGREGATE_DETECTION_NODES");
        let shallow = AggregateScan {
            depth_limit: 2,
            remaining: Cell::new(100),
        };
        let error = charged_compound_expression(&expr, 0, &shallow)
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.message, "SQL_AGGREGATE_DETECTION_DEPTH");
    }

    #[test]
    fn affinity_parentheses_use_bounded_stack() {
        let parse_expression = |sql: &str| {
            let mut statements = Parser::parse_sql(&SQLiteDialect {}, sql).unwrap();
            let Statement::Query(query) = statements.remove(0) else {
                panic!("expected SELECT")
            };
            let SetExpr::Select(mut select) = *query.body else {
                panic!("expected SELECT body")
            };
            let SelectItem::UnnamedExpr(expression) = select.projection.remove(0) else {
                panic!("expected projection expression")
            };
            expression
        };
        let cast_text = parse_expression("SELECT CAST('x' AS TEXT)");
        let cast_integer = parse_expression("SELECT CAST('1' AS INTEGER)");
        let cast_number = parse_expression("SELECT CAST(1 AS TEXT)");
        let result = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                fn wrap(mut value: Expr) -> Expr {
                    for _ in 0..5000 {
                        value = Expr::Nested(Box::new(value));
                    }
                    value
                }
                fn release(mut value: Expr) {
                    // Avoid recursive destructor work on this deliberately deep AST.
                    while let Expr::Nested(inner) = value {
                        value = *inner;
                    }
                }
                let expr = wrap(Expr::Value(Value::Number("1".into(), false).into()));
                assert!(no_affinity(&expr));
                assert!(nonnegative_i64_literal(&expr));
                assert!(matches!(literal_in_class(&expr), Some(Some(InStorageClass::Numeric))));
                assert!(!text_cast_string_literal(&expr));
                assert!(!integer_cast_string_literal(&expr));
                assert!(!text_cast_nonnegative_i64_literal(&expr));
                release(expr);
                let expr = wrap(cast_text);
                assert!(text_cast_string_literal(&expr));
                assert!(!integer_cast_string_literal(&expr));
                release(expr);
                let expr = wrap(cast_integer);
                assert!(integer_cast_string_literal(&expr));
                assert!(!text_cast_string_literal(&expr));
                release(expr);
                let expr = wrap(cast_number);
                assert!(text_cast_nonnegative_i64_literal(&expr));
                release(expr);
                let expr = wrap(Expr::Identifier(Ident::new("bound")));
                assert!(matches!(without_parentheses(&expr), Expr::Identifier(id) if id.value == "bound"));
                release(expr);
            })
            .unwrap()
            .join();
        result.unwrap();
    }

    #[test]
    fn between_length_guard_limits_nested_preflight_without_recursion() {
        let number = || Expr::Value(Value::Number("1".into(), false).into());
        let mut value = call("length", vec![number()]);
        let mut bound = number();
        for _ in 0..5000 {
            value = Expr::Nested(Box::new(value));
            bound = Expr::Nested(Box::new(bound));
        }
        assert!(!length_with_integer_between_bounds(
            &value,
            &number(),
            &number(),
            16
        ));
        assert!(!length_with_integer_between_bounds(
            &call("length", vec![number()]),
            &bound,
            &number(),
            16
        ));
        assert_eq!(exact_i64_numeric_literal(&bound), Some(1));
        // Unwrap iteratively so dropping the fixture itself cannot recurse.
        while let Expr::Nested(inner) = value {
            value = *inner;
        }
        while let Expr::Nested(inner) = bound {
            bound = *inner;
        }
    }

    #[test]
    fn aggregate_reference_scan_obeys_depth_and_visit_budgets() {
        let mut expr = Expr::Value(Value::Number("1".into(), false).into());
        for _ in 0..10 {
            expr = Expr::Nested(Box::new(expr));
        }
        let local = BTreeMap::new();
        for budget in [
            AggregateScan {
                depth_limit: 4,
                remaining: Cell::new(100),
            },
            AggregateScan {
                depth_limit: 100,
                remaining: Cell::new(2),
            },
        ] {
            assert_eq!(
                possible_outer_column(&expr, &local, 0, &budget)
                    .unwrap_err()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
    }

    #[test]
    fn aggregate_scope_schema_columns_are_charged() {
        let statements =
            Parser::parse_sql(&SQLiteDialect {}, "SELECT COUNT(id) FROM vals").unwrap();
        let Statement::Query(query) = &statements[0] else {
            panic!("expected SELECT")
        };
        let schemas = BTreeMap::from([(
            "vals".to_string(),
            (0..20).map(|n| format!("column{n}")).collect(),
        )]);
        let budget = AggregateScan {
            depth_limit: 100,
            remaining: Cell::new(5),
        };
        let error =
            nested_query_needs_binding(query, &schemas, &BTreeSet::new(), 0, &budget).unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.message, "SQL_AGGREGATE_DETECTION_NODES");
    }
}

#[cfg(test)]
mod mdd084_rewrite_tests {
    use super::super::*;
    use crate::{
        provider::{SqlColumn, SqlRelation},
        values::SqlType,
    };

    fn facts_relation() -> SqlRelation {
        SqlRelation {
            name: "facts".into(),
            columns: vec![SqlColumn {
                id: "value".into(),
                name: "value".into(),
                data_type: SqlType::Text,
                nullable: true,
            }],
            required_layers: vec![],
            estimated_rows: None,
        }
    }

    fn or_chain_sql(depth: usize, pattern: &str) -> String {
        let mut clause = format!("value LIKE '{pattern}'");
        for _ in 0..depth {
            clause = format!("({clause} OR value LIKE 'z%')");
        }
        format!("SELECT value FROM facts WHERE {clause}")
    }

    fn adapt_on_small_caller_stack(sql: String, limits: SqlLimits) -> MddResult<Adapted> {
        // MDD-084: before the fix the recursive rewrite overflowed this 1 MiB caller
        // stack at roughly ten levels of boolean nesting. adapt must do its recursive
        // work on its own proven-large stack, never on the caller's.
        let relation = facts_relation();
        std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(move || {
                adapt(
                    &sql,
                    limits,
                    &[],
                    &[relation],
                    crate::dialects::SqlDialect::NativeV1,
                    &BTreeMap::new(),
                )
            })
            .unwrap()
            .join()
            .unwrap()
    }

    #[test]
    fn deep_or_chain_like_rewrites_without_caller_stack_overflow() {
        let long_prefix = format!("{}%", "a".repeat(64));
        for depth in [9usize, 10, 11] {
            for pattern in ["a%", long_prefix.as_str()] {
                let sql = or_chain_sql(depth, pattern);
                let adapted = adapt_on_small_caller_stack(sql, SqlLimits::default())
                    .unwrap_or_else(|e| {
                        panic!("depth={depth} pattern_len={} {e:?}", pattern.len())
                    });
                assert!(adapted.sql.contains("mdd_like"));
                assert_eq!(adapted.required_relations, vec!["facts".to_string()]);
            }
        }
    }

    #[test]
    fn over_limit_or_chain_is_rejected_fail_closed() {
        // Default lexical depth quota: 60 parentheses exceed max_ast_depth = 48.
        let error = adapt_on_small_caller_stack(or_chain_sql(60, "a%"), SqlLimits::default())
            .err()
            .expect("over-depth chain must be rejected, never an empty success");
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.message, "SQL_LEXICAL_DEPTH");
        // Even with a raised configured depth, the absolute rewrite cap (64, aligned
        // with the native evaluator) rejects fail-closed instead of recursing deeper.
        let raised = SqlLimits {
            max_ast_depth: 1000,
            ..SqlLimits::default()
        };
        let error = adapt_on_small_caller_stack(or_chain_sql(100, "a%"), raised)
            .err()
            .expect("chain beyond the absolute rewrite cap must be rejected");
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.message, "SQL_AST_NODE_OR_DEPTH");
    }
}
