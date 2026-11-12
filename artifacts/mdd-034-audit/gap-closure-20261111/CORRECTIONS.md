# MDD-034 缺口闭合修正说明（2026-11-11）

范围：修复 Step-Reviewer 对上一轮 `cancel-fallback-isolation-20261111T065359Z` 提出的 6 项问题。
改动文件：仅 `crates/mdd-query/src/executor/runtime_tests.rs`（测试代码）。未改 `lib.rs` pub mod、未改 `Cargo.toml`/`Cargo.lock`、未改其他 crate、未改 `STATE.md`/`tasks/backlog.json`。
验证：`cargo test --offline -p mdd-query` 201 passed + 3 doc-tests passed；`cargo clippy --offline -p mdd-query --all-targets -- -D warnings` 0 warning。
声明：不授予 admitted / profile 资格。

## P1-1：终态字段断言缺失（原 IMPLEMENTATION.md:13 与代码矛盾）

- 修正：测试 1 `production_queue_native_cancel_is_isolated_from_sibling_and_keeps_partial_failure` 在 `receipt.finish` 后新增断言
  `operation_status == Cancelled`、`emitted_rows == 1`、`truncated == true`、`more_available == false`、`next_cursor.is_none()`、`total_rows_exact` 与 `execution.complete` 按模式取值。
- 测试 2 改为队列路径（`execute_into` + 显式 End + `finish`），对 WorkerLost 失败终态断言
  `operation_status == Error`、`error.code == WORKER_LOST`、`emitted_rows == 1`、`truncated == true`、`more_available == false`、`next_cursor.is_none()`、`total_rows_exact` 与 `execution.complete`。
- 期望值来源逐项写入 `ASSERTIONS.md`，并在代码注释中指向 `mdd-types/src/result.rs` / `executor.rs` 的推导位置。
- 验证：`query-new-tests.stdout.txt` 中两种模式各输出一组终态 JSON，字段值与断言一致。

## P1-2：`is_complete_result()` 恒真断言

- 修正：删除测试 1 中的 `assert!(!envelope.is_complete_result())`。该函数首项谓词即 `operation_status == Ok`（`mdd-types/src/lib.rs:320-332`），而上一行已断言 `Cancelled`，故恒真、零信息量。
- 代码中保留一行注释说明为何不断言。`readback.txt` 确认 4289-4501 行区间内无该断言。

## P2-3：隔离断言结构性恒真

- 测试 1：兄弟 query 现在通过生产入口 `execute(&f.prepared, &f.source, mode, &mut sibling_control)` 真实执行，断言 `rows().len() == 4` 且 `execution_complete()`。若原生 cancel 误关兄弟 session/查询或破坏共享快照租约，该 execute 会失败。
- 测试 3：兄弟 session 现在（a）在 compat 关闭 owning dataset 之前执行一次生产 `execute` 并断言 4 行；（b）在 compat 关闭后通过 `lifecycle.snapshot_lease(&sibling_session)` 读取共享快照并断言 snapshot_id 一致；（c）再执行一次生产 `execute` 并断言 4 行。若 compat 关闭误伤兄弟 session/查询，prepare/start/snapshot_lease/execute 会失败。
- 验证：`query-new-tests.stdout.txt` 中 `sibling_rows=4`、`sibling_before_rows=4`、`sibling_after_rows=4`、`sibling_snapshot_lease_ok=true`。

## P2-4：`"controlled hard kill"` 名不副实

- 修正：测试 2 重命名为 `in_process_worker_lost_fails_inflight_query_and_is_not_a_fallback_error`；`worker_lost` 的 reason 改为 `"in-process worker_lost API (no process termination)"`；测试 4 同步改名。代码注释明确：这是进程内 lifecycle API，不终止进程；真实子进程 kill 证据只在 supervisor 探针。
- 未新增真实子进程强杀执行查询的路径（超出本子代理范围，且现有 supervisor 探针子进程不执行查询）。`SUMMARY.md` 如实保留该缺口。

## P2-5：SQLite interrupt 证据与引擎无关

- 修正：`IMPLEMENTATION.md`/`SUMMARY.md` 改为准确表述：`conformance/runtime --sqlite` 是**裸 rusqlite 库能力外置演示**，与 mdd-sql 零关联；`crates/mdd-sql/src/` 无任何 interrupt 实现（仅一条注释）；探针测的是两个独立 connection，**不是同一 connection 上两个 query**。因此“同一 connection 多 query 隔离”未测。

## P2-6：死代码被标为「新覆盖」

- 修正：`IMPLEMENTATION.md`/`SUMMARY.md` 如实标注 `cancel_with_profile` / `CancelProfile` 与 `fallback_allowed` **均无生产调用方**（grep 证据见下）。验收 4 记为**部分覆盖**（引擎按字段执行正确，但无生产接线）；验收 5 记为**部分覆盖/未覆盖**（门控纯函数决策表已验证，但“可按显式等价策略 fallback”未接线到任何 adapter，“不得静默切换”在当前代码中属空洞成立）。
- 测试 4 保留，但在代码注释中明确它只验证纯门控函数，不代表任何 adapter 接线。
- grep 证据（2026-11-11）：
  - `cancel_with_profile`：仅 `mdd-session/src/cancellation.rs` 定义与自身测试、`mdd-query/src/executor/runtime_tests.rs` 本测试。
  - `fallback_allowed`：仅 `mdd-types/src/result.rs` 定义与自身测试、`mdd-query/src/executor/runtime_tests.rs` 本测试。
  - `crates/mdd-sql/src/` 中 `interrupt` 仅命中 `dialects/functions.rs:456` 一条注释。

## 未改动项

- `crates/mdd-query/src/lib.rs` 的 pub mod 列表未动。
- 未新增生产依赖。
- `artifacts/mdd-034-audit/cancel-fallback-isolation-20261111T065359Z/` 保持历史含义，未改写。
