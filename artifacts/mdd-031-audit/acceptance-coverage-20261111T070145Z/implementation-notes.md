# MDD-031 验收缺口补齐：实现说明

日期：2026-11-11（UTC）
范围：仅 `crates/mdd-sql/src/**`。未改 `lib.rs` 的 pub mod 列表、未改 Cargo.toml/lock、未改其他 crate、未引入新生产依赖。

## 1. 下推策略与实际 vtab 行为绑定（验收 3）

**改什么**：在 `crates/mdd-sql/src/virtual_tables/mod.rs` 增加 `VtabPolicy` 与唯一常量 `VTB_POLICY`，`xBestIndex` 与 `bridge.rs` 的 `OptimizerPolicy` 都从它读取。

**为什么**：原来 `OptimizerPolicy` 在 `execute_inner` 里硬编码全 false，而 `xBestIndex` 也独立硬编码 `omit=false`/`order_by_consumed=false`。两处独立硬编码意味着将来任何一处启用下推而另一处忘记同步，报告就会与 cursor 契约不一致，违反「候选过滤不谎报精确处理」。绑定到单一常量后，报告值就是 vtab 实际行为。

**当前值**：`omit=false`、`order_by_consumed=false`、`limit_offset_pushdown=false`、`in_pushdown=false`；`xFilter` 仍收到 `argv_index=0`（不下传任何约束），SQLite 自己完成全部过滤/排序/LIMIT/OFFSET/IN。因此不存在候选预筛，也不存在精度谎报。

## 2. 新增独立 oracle 对照测试（验收 1/2/3/4/5）

全部位于 `crates/mdd-sql/src/bridge.rs` 的 `tests` 模块：

- `hostlab_q_series_shapes_match_sqlite_per_dialect`：用合成 provider 复刻冻结的 HostLab 关系名与列形状（`dex_files`/`classes`/`class_fields`/`class_methods`/`methods`/`class_interfaces`/`method_strings`/`code_items`/`method_calls`/`method_field_accesses`/`method_used_types`/`strings`/`types`），对 Q01/Q02/Q03/Q05/Q07/Q08/Q09/Q11/Q12 九种形状，在 NativeV1/DexSql010/DexSql011 三方言下与独立 SQLite 3.53.2（rusqlite 直连，不经 AST 适配器/UDF）逐行比较。
- `dialect_feature_matrix_matches_sqlite_for_null_cast_like_length_compare_aggregate_order_join_cte`：NULL、CAST（方言无关子集）、LIKE/ESCAPE、length、比较、聚合、ORDER、JOIN/CTE 共 18 个用例 × 3 方言，与同一 SQLite oracle 比较。
- `pushdown_policy_matches_vtab_capabilities_and_results_match_sqlite`：含 LIMIT/OFFSET、IN、BETWEEN、GROUP BY、JOIN 的 5 个用例 × 3 方言，比较结果并断言 `OptimizerPolicy` 四项与 `VTB_POLICY` 完全一致。
- `compatibility_failure_preserves_counterexample_and_blocks_profile`：语法错误→InvalidArgument、缺列→InvalidArgument、递归 CTE→UnsupportedQuery 且保留 `RECURSIVE` 原因、provider 失败→QuotaExceeded；成功结果 `profiles_admitted` 为空。
- `lazy_scan_cost_is_measured_after_prepare`：prepare 后 `open_cursor` 计数为 0（惰性）；`max_scanned_rows=2` 时第 3 行触发 SQL_WORK_BUDGET；默认额度下 3 行全部测量。

**注意**：Q 系列形状测试使用合成 provider，只验证 SQL 形状语义；真实 `native_*` 关系到 HostLab 无前缀名的映射是 MDD-032 范围，本任务不声称完成。

## 3. 独立 Python oracle

`oracle/oracle_matrix.py` 用 Python stdlib `sqlite3`（3.53.1）重建同一数据集，独立执行 Q 系列形状与特性用例，输出 `oracle-results.json`。它与 Rust 测试中的 rusqlite 3.53.2 oracle 在 5 个共享用例上逐值一致（见 `oracle/cross-check.json`）。

## 4. 未改动的部分

- `crates/mdd-sql/src/lib.rs`：未改。
- `Cargo.toml` / `Cargo.lock`：未改。
- `STATE.md` / `tasks/backlog.json`：未改。
- 其他 crate：未改。
- 未新增生产依赖（`serde_json` 已是 mdd-sql 依赖，仅测试使用）。
