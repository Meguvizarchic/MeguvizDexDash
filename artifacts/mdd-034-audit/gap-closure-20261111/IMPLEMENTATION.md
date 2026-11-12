# 本轮实现说明（gap-closure）

## 改动文件

只改动 `crates/mdd-query/src/executor/runtime_tests.rs`（测试代码）。未改生产逻辑，未新增模块，未改 `lib.rs` 的 pub mod 列表，未新增依赖。
上一轮目录 `cancel-fallback-isolation-20261111T065359Z/` 保持历史含义，未改写。

## 修正后的测试与理由

### 1. `production_queue_native_cancel_is_isolated_from_sibling_and_keeps_partial_failure`

- 覆盖验收 3「原生 cancel 仅影响目标 query」在生产 `execute_into` 队列路径上的行为。
- 场景：4 行数据，队列容量 4；`Control` 的 `output_row` hook 在第 2 行调用 `cancel.cancel()`。
- 终态断言（均已在代码中断言，非仅打印）：`operation_status=Cancelled`、`emitted_rows=1`、`error.code=CANCELLED`、`truncated=true`、`more_available=false`、`next_cursor=None`、`total_rows_exact`/`execution.complete` 按模式取值。逐项来源见 `ASSERTIONS.md`。
- 隔离断言真实执行：兄弟 query 用生产入口 `execute` 跑完并断言 4 行、`execution_complete()`；不是只 prepare/start/checkpoint。
- 删除了恒真的 `!is_complete_result()` 断言，并注释原因。

### 2. `in_process_worker_lost_fails_inflight_query_and_is_not_a_fallback_error`

- 原名 `worker_kill_fails_...` 与 `"controlled hard kill"` 名不副实，已改为进程内 `worker_lost` 的准确命名与 reason。**本测试不杀进程**；真实子进程强杀只在 supervisor 探针（且探针子进程不执行查询，见 SUMMARY 缺口）。
- 场景：8 行数据，队列容量 4；`output_row` hook 在第 2 行调用 `Lifecycle::worker_lost`。
- 终态断言：`operation_status=Error`、`error.code=WORKER_LOST`、`emitted_rows=1`、`truncated=true`、`more_available=false`、`next_cursor=None`、`total_rows_exact`/`execution.complete` 按模式取值。
- 兄弟 query 断言 `phase=Failed`、`error.code=WORKER_LOST`（`fail_worker` 会终结该 lifecycle 内所有未终态 query）。
- `fallback_allowed` 断言保留，但注释明确：该函数**无生产调用方**，只验证纯门控决策表。

### 3. `compat_cancel_profile_closes_only_owning_dataset_and_is_distinct_from_native`

- 覆盖验收 4「兼容能力使用 compat_cancel_closes_dataset 字段逐 profile 声明并验证」。
- 场景：同一 `SnapshotHandle` 上开 owning / sibling 两个 session，共用同一 snapshot；使用真实 MemoryCatalog + `prepare`，所有 lifecycle query 用 `prepared.runtime_binding()`。
- native profile(false)：只取消目标 query，owning session 仍可 prepare/start；`sibling_before` 生产 execute 读到 4 行（控制组）。
- compat profile(true)：关闭 owning session 的 dataset，后续 owning `prepare_query` 返回 `INVALID_ARGUMENT`；随后 `snapshot_lease(&sibling_session)` 成功且 snapshot_id 一致，`sibling_after` 生产 execute 读到 4 行。
- 隔离断言真实执行：兄弟 session 在 compat 关闭前后各执行一次生产 `execute` 并读行，且读取共享快照租约。
- 死代码标注：`cancel_with_profile`/`CancelProfile` 无生产调用方，本测试是 API 行为验证，不代表生产接线。

### 4. `fallback_whitelist_rejects_real_query_terminal_errors`

- 用真实执行产生 4 类终态错误：QUOTA_EXCEEDED、DEADLINE_EXCEEDED、CANCELLED、WORKER_LOST，验证 `fallback_allowed` 在 pristine context 下全部拒绝；三种许可码在 pristine 下接受；`accepted_rows>0` 即拒绝。
- 这些 `execute` 路径返回 `MddError`，不产生 envelope，因此终态 envelope 字段断言由测试 1/2 承担。
- 死代码标注：`fallback_allowed` 无生产调用方，本测试仅验证纯门控函数；“不得静默切换”在当前代码中属空洞成立，“可按显式等价策略 fallback”未接线到任何 adapter。

## 未改动的生产代码

`executor.rs`、`budget.rs`、`mdd-session`、`mdd-types` 均未改。本轮未发现需要修正的实现缺陷，改动均为补强测试断言与准确性标注。

## 验证

- `cargo test --offline -p mdd-query`：201 passed + 3 doc-tests passed（`query-full.stdout.txt`）。
- 4 个相关测试单独 `--nocapture` 运行，终态 JSON 与断言一致（`query-new-tests.stdout.txt`）。
- `cargo clippy --offline -p mdd-query --all-targets -- -D warnings`：0 warning（`clippy.stdout.txt`）。
