# 本轮实现说明

## 改动文件

只改动 `crates/mdd-query/src/executor/runtime_tests.rs`（测试代码），新增 4 个测试，未改生产逻辑，未新增模块，未改 `lib.rs` 的 pub mod 列表。

## 新增测试与理由

### 1. `production_queue_native_cancel_is_isolated_from_sibling_and_keeps_partial_failure`

- 覆盖验收 3「原生 cancel 仅影响目标 query」在生产 `execute_into` 队列路径上的行为。原有同类测试 `native_cancel_after_prefix_isolated_from_sibling_and_computed_spool_retained` 走的是 `#[cfg(test)]` 的 `execute_trusted_into`，不是生产入口。
- 场景：4 行数据，队列容量 4；`Control` 的 `output_row` hook 在第 2 行取消目标 query。
- 断言：第 1 行已作为 `QueueEvent::Data` 交付并确认；随后收到显式 `QueueEvent::End(Err(CANCELLED))`；回执 `finish` 后终态 `operation_status=cancelled`、`emitted_rows=1`、`truncated=true`、`is_complete_result=false`；`execution.complete` 在 Streaming 为 false、MaterializedReference 为 true；兄弟 query 仍可 `checkpoint` 且无错误。
- 终端 JSON 见 `query-new-tests.stdout.txt`。

### 2. `worker_kill_fails_inflight_query_and_is_not_a_fallback_error`

- 覆盖验收 3「强杀 worker 明确影响该 worker 全部未完成任务」在查询执行边界的行为，并同时覆盖验收 5 的 WorkerLost 非 fallback 资格。
- 场景：`execute` 扫描中由 hook 在第 2 个 `scan_row` 调 `Lifecycle::worker_lost`；同 session 另有一个未完成的兄弟 query。
- 断言：在途 `execute` 返回 `WORKER_LOST`（stage=worker）；兄弟 query 状态为 `Failed/WorkerLost`；`fallback_allowed` 对真实 WorkerLost 返回 false。

### 3. `compat_cancel_profile_closes_only_owning_dataset_and_is_distinct_from_native`

- 覆盖验收 4「兼容能力使用 compat_cancel_closes_dataset 字段逐 profile 声明并验证，不混同原生取消」。
- 场景：同一 `SnapshotHandle` 上开两个 session（owning / sibling），共用同一 snapshot。
  - native profile（`compat_cancel_closes_dataset=false`）取消 owning 的 query：`CancelOutcome.compat_cancel_closes_dataset=false`，query 为 Cancelled，但 owning session 仍可继续 `prepare_query`/`start_query`。
  - compat profile（`compat_cancel_closes_dataset=true`）取消 owning 的另一个 query：`CancelOutcome.compat_cancel_closes_dataset=true`，owning session 被关闭（后续 `prepare_query` 返回 `INVALID_ARGUMENT`），而共享同一 snapshot 的 sibling session 仍可 prepare/start/checkpoint。
- 这同时验证了代码注释「Compatibility's dataset is the owning session, never every session sharing a snapshot」。

### 4. `fallback_whitelist_rejects_real_query_terminal_errors`

- 覆盖验收 5「仅 UNAVAILABLE_BACKEND、UNSUPPORTED_CAPABILITY、UNSUPPORTED_QUERY 可按显式等价策略 fallback；完整性、源变化、配额、取消和内部故障不得静默切换」。
- 用真实执行路径产生 4 类终态错误：`QUOTA_EXCEEDED`（QueryWorkBytes=0）、`DEADLINE_EXCEEDED`（deadline=0）、`CANCELLED`（query 已取消）、`WORKER_LOST`（worker_lost）。
- 断言：在显式允许、等价 id/源/契约均匹配、`accepted_rows=0` 的 pristine context 下，这 4 类真实错误全部不被 `fallback_allowed` 接受；三种许可码在 pristine context 下被接受；一旦 `accepted_rows>0` 即使许可码也被拒绝。
- 源变化（SOURCE_CHANGED）与非静默切换的适配器级证据来自既有测试：`crates/mdd-query/src/executor/scoped.rs::checked_source_detects_change_during_scan_before_limit_zero`（SourceChanged 保留）、`crates/mdd-input/src/snapshot/mod.rs` 的 SHA-256 变更返回 SourceChanged、`crates/mdd-facts/src/indexes/tests.rs::coverage_retains_late_genuine_errors_and_rejects_terminal_overwrite`（UnsupportedCapability 不覆盖既有真实错误）。本轮重跑 mdd-input / mdd-facts 全量并采集。

## 未改动的生产代码

`executor.rs`、`budget.rs`、`mdd-session`、`mdd-types` 均未改。本轮没有发现需要修正的实现缺陷，因此没有新增红例；新测试是对既有正确行为的绿例与终态断言。历史红例（`sender-drop-first-fault`、`finish-after-close-first-fault`、`receipt-prior-failure` 等）保留在 `artifacts/mdd-034-audit/` 原目录，未改动。

## 刷新证据

`conformance/runtime` 探针重新构建（binary sha256 `a86db254…`）并重跑：
- `--sqlite`：A 连接被 interrupt 返回 OperationInterrupted，B 连接得到正确和 20000100000，两连接事后均可复用（SELECT 7）。
- `--supervisor`：250ms worker deadline 触发 `child.kill()` 强杀直接子进程并回收（`direct_child_reaped=true`），该 worker 的 2 个未完成 query（含已计算未消费 spool）全部失败，先前已完整交付的 query 保持 completed。`process_tree_isolated=false` 明确保留。
