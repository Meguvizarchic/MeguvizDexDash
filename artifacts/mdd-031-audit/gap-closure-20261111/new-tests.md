# 新增 / 修改测试记录

## 1. `native_v1_integer_cast_requires_exact_text_and_diverges_from_sqlite_prefix`（新增）

位置：`crates/mdd-sql/src/bridge.rs`

断言：
- NativeV1 对 `CAST('1.9' AS INTEGER)`、`CAST('abc' AS INTEGER)`、
  `CAST('-5.9' AS INTEGER)`、`CAST('1e5' AS INTEGER)` 返回
  `ErrorCode::InvalidArgument` 且 `message == "INVALID_INTEGER_CAST"`。
- 同一文本在 DexSql010/DexSql011 下返回 SQLite 前缀解析值
  （1 / 0 / -5 / 1），与测试内 rusqlite SQLite  oracle 一致。
- NativeV1 对 `CAST('12' AS INTEGER)` 返回 12；对 `CAST(NULL AS INTEGER)`
  返回 NULL。

判别力：若干扰 NativeV1 的精确解析（例如改成前缀解析），错误断言立即失败；
若 legacy 漂移，值断言失败。

## 2. `compatibility_failure_preserves_counterexample_without_profile_admission`（改名）

原名称：`compatibility_failure_preserves_counterexample_and_blocks_profile`。

变化：
- 删除 `assert!(result.profiles_admitted.is_empty())`：该字段在执行路径中恒为
  `Vec::new()`，删除阻断机制测试也不会失败，不能作为验收 5 的覆盖证据。
- 保留语法错误 / 绑定错误 / 真 unsupported / provider 失败的分类断言。
- 成功路径改为断言 `result.rows.len() == 3`，确认成功计算真的发生。
- 注释明确：验收 5 的「阻断对应 profile」在 mdd-sql 内无强制载体，本测试不覆盖。

## 3. `pushdown_policy_matches_vtab_capabilities_and_results_match_sqlite`（修正）

删除：
- `assert_eq!(result.optimizer.omit, policy.omit)` 等 4 条同义反复断言
  （两侧都读 `VTB_POLICY`）。

新增：
- `virtual_tables::clear_best_index_reports()` 在形状循环前清空记录。
- 循环后读取 `virtual_tables::best_index_reports()`，断言：
  - 记录非空（证明 `xBestIndex` 确实被 SQLite 以带约束的查询调用）；
  - 每条 `omit == false`；
  - 每条 `argv_index == 0`。
- 记录由 `virtual_tables::best_index` 在每次 `usage.set_omit` /
  `usage.set_argv_index` 时写入 `BestIndexReport { omit, argv_index }`，
  反映的是实际传给 SQLite 的值，而非常量的自我复制。

保留：5 个形状 × 3 方言的行级等价比较（若 `omit` 为 true，SQLite 跳过自身
过滤，行级比较失败，构成第二重行为兜底）。

## 4. `hostlab_q_series_shapes_match_sqlite_per_dialect`（修正 fixture）

- `code_items`：`file_id=0` 两行 `method_idx` 11/12 → 5/7。
- `method_calls`：第一行 `callee` `Lfixture/F;->f()V` → `Lfixture/A;->f()V`，
  `callee_class` 同步为 `Lfixture/A;`。
- 每个形状新增 `assert!(!expected.is_empty(), "{label} oracle returned no rows")`。

修正后 oracle 行数：Q09 = 2，Q12 = 1，其余 7 个形状原本即非空。

## 5. `dialect_feature_matrix_matches_sqlite_for_null_cast_like_length_compare_aggregate_order_join_cte`（修正）

- 新增形状 `SELECT id, value LIKE NULL AS v FROM vals ORDER BY id`（7 行，
  每行 `v` 为 NULL），使 NULL 模式传播语义有非空、可判别的结果。
- 保留 `SELECT id FROM vals WHERE value LIKE NULL ORDER BY id`（0 行，有意保留
  的空结果形状），并加注释说明其语义由新投影形状覆盖。

## 运行记录

见 `readback/new-tests.log`（5 个测试逐个运行，均 `1 passed; 0 failed`）与
`readback/cargo-test.log`（全量 `208 passed; 0 failed` + doctest `1 passed`）。
