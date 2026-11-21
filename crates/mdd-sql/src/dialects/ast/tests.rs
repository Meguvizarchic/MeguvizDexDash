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

    #[test]
    fn flat_or_chain_like_rebalances_under_default_depth_limit() {
        let clauses: Vec<String> = (0..35)
            .map(|i| format!("value LIKE 'Lpkg/n{i:02}/%' ESCAPE '\\'"))
            .collect();
        let inner = format!(
            "SELECT value FROM facts WHERE {} ORDER BY value",
            clauses.join(" OR ")
        );
        let wrapped = format!("SELECT * FROM ({inner}) AS hostlab_shape LIMIT 0");
        let unfused = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn({
                let wrapped = wrapped.clone();
                move || {
                    adapt_with_fast_udf(
                        &wrapped,
                        SqlLimits::default(),
                        &[],
                        &[facts_relation()],
                        crate::dialects::SqlDialect::NativeV1,
                        &BTreeMap::new(),
                        false,
                    )
                }
            })
            .unwrap()
            .join()
            .unwrap()
            .expect("flat 35-term OR LIKE wrapped in hostlab_shape must fit max_ast_depth=48");
        // Each LIKE ... ESCAPE binds (pattern, escape, has_escape=true), plus 1 for LIMIT 0.
        assert_eq!(unfused.parameters.len(), 35 * 3 + 1);
        // Check left-to-right positional parameter order is preserved after rebalancing.
        let mut iter = unfused.parameters.iter().step_by(3);
        for i in 0..35 {
            assert_eq!(
                iter.next(),
                Some(&SqlValue::text(&format!("Lpkg/n{i:02}/%"))),
                "parameter order drifted at {i}"
            );
        }

        // Default fast-UDF path fuses contiguous same-column OR LIKE patterns into mdd_like_any.
        let fused = adapt_on_small_caller_stack(wrapped, SqlLimits::default())
            .expect("fused 35-term OR LIKE wrapped in hostlab_shape must fit max_ast_depth=48");
        assert!(fused.sql.contains("mdd_like_any"), "{}", fused.sql);
        assert_eq!(fused.parameters.len(), 2);
        assert!(matches!(fused.parameters[0], SqlValue::Bytes(_)));
    }

    #[test]
    fn fast_udf_keeps_native_same_type_int_eq_and_group_by_keys() {
        use crate::provider::{SqlColumn, SqlRelation};
        use crate::values::SqlType;

        let col = |name: &str, data_type: SqlType, nullable: bool| SqlColumn {
            id: name.into(),
            name: name.into(),
            data_type,
            nullable,
        };
        let relations = [
            SqlRelation {
                name: "classes".into(),
                required_layers: vec![],
                estimated_rows: None,
                columns: vec![
                    col("file_id", SqlType::U64, false),
                    col("class_idx", SqlType::U64, false),
                    col("access_flags", SqlType::I64, false),
                    col("descriptor", SqlType::Text, false),
                ],
            },
            SqlRelation {
                name: "class_interfaces".into(),
                required_layers: vec![],
                estimated_rows: None,
                columns: vec![
                    col("file_id", SqlType::U64, false),
                    col("class_idx", SqlType::U64, false),
                    col("ordinal", SqlType::U64, false),
                    col("interface_descriptor", SqlType::Text, false),
                ],
            },
        ];
        let join_sql = "SELECT c.file_id, c.descriptor, COUNT(ci.ordinal) AS ifaces \
            FROM classes c LEFT JOIN class_interfaces ci \
            ON c.file_id = ci.file_id AND c.class_idx = ci.class_idx \
            GROUP BY c.file_id, c.class_idx, c.descriptor \
            ORDER BY c.file_id, c.descriptor";

        let fast = adapt_with_fast_udf(
            join_sql,
            SqlLimits::default(),
            &[],
            &relations,
            crate::dialects::SqlDialect::DexSql010,
            &BTreeMap::new(),
            true,
        )
        .expect("fast join rewrite");
        assert!(!fast.sql.contains("mdd_eq"), "{}", fast.sql);
        assert!(!fast.sql.contains("mdd_truth_input"), "{}", fast.sql);
        assert!(!fast.sql.contains("mdd_key"), "{}", fast.sql);
        assert!(!fast.sql.contains("mdd_sort_key"), "{}", fast.sql);

        let slow = adapt_with_fast_udf(
            join_sql,
            SqlLimits::default(),
            &[],
            &relations,
            crate::dialects::SqlDialect::DexSql010,
            &BTreeMap::new(),
            false,
        )
        .expect("slow join rewrite");
        assert!(slow.sql.contains("mdd_eq"), "{}", slow.sql);
        assert!(slow.sql.contains("mdd_truth_input"), "{}", slow.sql);
        assert!(slow.sql.contains("mdd_key"), "{}", slow.sql);
        assert!(slow.sql.contains("mdd_sort_key"), "{}", slow.sql);

        let computed_group = "SELECT c.file_id FROM classes c \
            JOIN class_interfaces ci ON c.descriptor = ci.interface_descriptor \
            WHERE c.access_flags = ci.file_id \
            GROUP BY c.descriptor || 'x'";
        let mixed = adapt_with_fast_udf(
            computed_group,
            SqlLimits::default(),
            &[],
            &relations,
            crate::dialects::SqlDialect::DexSql010,
            &BTreeMap::new(),
            true,
        )
        .expect("mixed eq rewrite");
        assert!(mixed.sql.contains("mdd_eq"), "{}", mixed.sql);
        assert!(mixed.sql.contains("mdd_key"), "{}", mixed.sql);

        let expr_order = "SELECT c.file_id + 1 AS x FROM classes c ORDER BY x";
        let fast_expr_order = adapt_with_fast_udf(
            expr_order,
            SqlLimits::default(),
            &[],
            &relations,
            crate::dialects::SqlDialect::DexSql010,
            &BTreeMap::new(),
            true,
        )
        .expect("expr alias order rewrite");
        assert!(
            fast_expr_order.sql.contains("mdd_sort_key"),
            "{}",
            fast_expr_order.sql
        );
    }

    #[test]
    fn fast_udf_materializes_native_equi_joined_base_tables_safely() {
        let col = |name: &str, data_type: SqlType| SqlColumn {
            id: name.to_owned(),
            name: name.to_owned(),
            data_type,
            nullable: false,
        };
        let relations = vec![
            SqlRelation {
                name: "classes".to_owned(),
                required_layers: vec![],
                estimated_rows: None,
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("class_idx", SqlType::U64),
                    col("descriptor", SqlType::Text),
                ],
            },
            SqlRelation {
                name: "class_interfaces".to_owned(),
                required_layers: vec![],
                estimated_rows: None,
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("class_idx", SqlType::U64),
                    col("ordinal", SqlType::U64),
                    col("interface_descriptor", SqlType::Text),
                ],
            },
        ];

        // Aliased LEFT JOIN with native integer `=` wraps RHS as `(SELECT * FROM ... LIMIT -1) AS ci`.
        let aliased = "SELECT c.file_id, COUNT(ci.ordinal) AS n \
            FROM classes c LEFT JOIN class_interfaces ci \
            ON c.file_id = ci.file_id AND c.class_idx = ci.class_idx \
            GROUP BY c.file_id, c.class_idx";
        let fast_aliased = adapt_with_fast_udf(
            aliased,
            SqlLimits::default(),
            &[],
            &relations,
            crate::dialects::SqlDialect::DexSql010,
            &BTreeMap::new(),
            true,
        )
        .expect("fast aliased join");
        assert!(
            fast_aliased
                .sql
                .contains("(SELECT * FROM class_interfaces LIMIT -1) ci"),
            "{}",
            fast_aliased.sql
        );

        // Unaliased JOIN preserves table name as outer alias (`AS class_interfaces`).
        let unaliased = "SELECT c.file_id FROM classes c \
            JOIN class_interfaces ON c.file_id = class_interfaces.file_id";
        let fast_unaliased = adapt_with_fast_udf(
            unaliased,
            SqlLimits::default(),
            &[],
            &relations,
            crate::dialects::SqlDialect::DexSql010,
            &BTreeMap::new(),
            true,
        )
        .expect("fast unaliased join");
        assert!(
            fast_unaliased
                .sql
                .contains("(SELECT * FROM class_interfaces LIMIT -1) AS class_interfaces"),
            "{}",
            fast_unaliased.sql
        );

        // fast_udf = false does NOT wrap.
        let slow = adapt_with_fast_udf(
            aliased,
            SqlLimits::default(),
            &[],
            &relations,
            crate::dialects::SqlDialect::DexSql010,
            &BTreeMap::new(),
            false,
        )
        .expect("slow join");
        assert!(!slow.sql.contains("LIMIT -1"), "{}", slow.sql);

        // Non-native text `=` (rewritten to `mdd_eq`) is NOT wrapped.
        let text_eq = "SELECT c.file_id FROM classes c \
            JOIN class_interfaces ci ON c.descriptor = ci.interface_descriptor";
        let fast_text = adapt_with_fast_udf(
            text_eq,
            SqlLimits::default(),
            &[],
            &relations,
            crate::dialects::SqlDialect::DexSql010,
            &BTreeMap::new(),
            true,
        )
        .expect("text eq join");
        assert!(!fast_text.sql.contains("LIMIT -1"), "{}", fast_text.sql);

        // CTE RHS is NOT wrapped even with native `=`.
        let cte_join = "WITH ci_cte AS (SELECT file_id, class_idx FROM class_interfaces) \
            SELECT c.file_id FROM classes c \
            JOIN ci_cte ON c.file_id = ci_cte.file_id";
        let fast_cte = adapt_with_fast_udf(
            cte_join,
            SqlLimits::default(),
            &[],
            &relations,
            crate::dialects::SqlDialect::DexSql010,
            &BTreeMap::new(),
            true,
        )
        .expect("cte join");
        assert!(!fast_cte.sql.contains("LIMIT -1"), "{}", fast_cte.sql);
    }
}
