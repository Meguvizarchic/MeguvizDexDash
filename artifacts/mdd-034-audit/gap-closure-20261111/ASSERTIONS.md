# 新增/修正断言清单与期望值来源

代码位置：`crates/mdd-query/src/executor/runtime_tests.rs`（行号为本轮修改后）。

## 测试 1：`production_queue_native_cancel_is_isolated_from_sibling_and_keeps_partial_failure`（:4289）

场景：4 行数据，队列容量 4；`Control` 的 `output_row` hook 在第 2 行调用 `cancel.cancel()`。两种 ExecutionMode 各跑一次。

| 断言 | 期望值 | 来源 / 推导 |
| --- | --- | --- |
| `end.unwrap_err().code == Cancelled` | Cancelled | hook 调 `QueryCancellation::cancel` → lifecycle `end_query(Cancelled)`（`mdd-session/src/lib.rs:1366-1374`），队列发布显式失败 End |
| `envelope.operation_status == Cancelled` | Cancelled | `TerminalBuilder::envelope` 将 `ErrorCode::Cancelled` 映射为 `OperationStatus::Cancelled`（`mdd-types/src/result.rs:117-121`） |
| `envelope.response.emitted_rows.0 == 1` | 1 | 第 1 行已 `send_reserved_produced` 并交付；第 2 行 hook 取消后，`send_reserved_inner` 的 `checkpoint()` 返回 Cancelled，行未入队（`mdd-query/src/budget.rs:1829-1840`） |
| `envelope.response.truncated == true` | true | `control.step("output_row")` 之后的发送失败使 `execute_into` 置 `dropped=true`（`executor.rs:2454-2457`）；`finish` 将 `pending.dropped` 传给 `TerminalBuilder::fail`（`executor.rs:1665-1675`）；`fail` 计算 `truncated = dropped_output \|\| emitted < total`（`result.rs:196`） |
| `envelope.response.more_available == false` | false | `fail()` 固定以 `cursor=None` 构造 envelope（`result.rs:215`）；`more_available = cursor.is_some()`（`result.rs:142`） |
| `envelope.response.next_cursor.is_none()` | None | 同上 |
| `envelope.response.total_rows_exact == matches!(mode, MaterializedReference)` | Streaming=false；Materialized=true | Streaming 的 cursor 路径不调用 `computation_complete`，`total=None`；MaterializedReference 的 `reference()` 完成后调用 `terminal.computation_complete(rows.len())`（`executor.rs:2409-2411`），`total=Some(4)` |
| `envelope.execution.complete == matches!(mode, MaterializedReference)` | 同上 | `Execution.complete = self.computed`（`result.rs:134-136`）；仅 MaterializedReference 在输出循环前完成计算 |
| 兄弟 `execute(...).rows().len() == 4` | 4 | 兄弟 query 用生产入口 `execute` 真实执行并读行（`runtime_tests.rs:4380`）；若原生 cancel 误伤兄弟 session/查询则失败 |
| 兄弟 `execute(...).execution_complete()` | true | 4 行全部产出 |
| 兄弟 `query_status(...).error.is_none()` | true | 兄弟 query 未被 cancel 影响 |

已删除：`assert!(!envelope.is_complete_result())`。原因：`is_complete_result()` 首项谓词是 `operation_status == Ok`（`mdd-types/src/lib.rs:320-332`），已由上一行 `Cancelled` 断言否定，恒真。

## 测试 2：`in_process_worker_lost_fails_inflight_query_and_is_not_a_fallback_error`（:4392）

场景：8 行数据，队列容量 4；`output_row` hook 在第 2 行调用 `Lifecycle::worker_lost`（进程内 API，不杀进程）。两种模式各跑一次。

| 断言 | 期望值 | 来源 / 推导 |
| --- | --- | --- |
| `end.unwrap_err().code == WORKER_LOST`、`stage == "worker"` | WorkerLost / worker | `worker_lost` 构造 `MddError::new(WorkerLost, "worker", reason)`（`mdd-session/src/lib.rs:1428-1430`）；队列 checkpoint 返回该终态 |
| `envelope.operation_status == Error` | Error | 错误码非 Cancelled → `OperationStatus::Error`（`result.rs:117-121`） |
| `envelope.response.emitted_rows.0 == 1` | 1 | 第 1 行已交付；第 2 行后队列 checkpoint 返回 WorkerLost，行未入队 |
| `envelope.response.truncated == true` | true | 发送失败置 `dropped=true`；`fail` 由 `dropped_output` 派生 truncated |
| `envelope.response.more_available == false`、`next_cursor.is_none()` | false / None | `fail()` 固定无 cursor |
| `total_rows_exact` / `execution.complete` 按模式 | 同测试 1 | 同测试 1 |
| 兄弟 `query_status.phase == Failed`、`error.code == WORKER_LOST` | Failed / WorkerLost | `fail_worker` 将 lifecycle 内所有未终态 query 一并置为该错误（`mdd-session/src/lib.rs:1403-1426`）；若只影响目标 query 则此断言失败 |
| `!fallback_allowed(&error, &policy, &context)` | false | 纯门控函数决策表（`mdd-types/src/result.rs:423`）；**无生产调用方**，仅验证函数本身 |

## 测试 3：`compat_cancel_profile_closes_only_owning_dataset_and_is_distinct_from_native`（:4502）

场景：同一 `SnapshotHandle` 上开 owning / sibling 两个 session；真实 MemoryCatalog（4 行）+ `prepare`；所有 lifecycle query 用 `prepared.runtime_binding()`。

| 断言 | 期望值 | 来源 / 推导 |
| --- | --- | --- |
| native profile：`!compat_cancel_closes_dataset`、`status.phase == Cancelled` | false / Cancelled | `cancel_with_profile(false)` 走 `cancel_query` 单 query（`mdd-session/src/cancellation.rs:401-421`、`lib.rs:1366-1374`） |
| native 后 owning 仍可 `prepare_query`/`start_query` | 成功 | owning session 未关闭 |
| 兄弟 `before_output.rows().len() == 4`、`execution_complete()` | 4 / true | compat 关闭前的生产 `execute` 控制组 |
| compat profile：`compat_cancel_closes_dataset == true`、`status.phase == Cancelled` | true / Cancelled | `cancel_with_profile(true)` 走 `close_session(owning)`（`cancellation.rs:411-412`） |
| compat 后 owning `prepare_query` 返回 `INVALID_ARGUMENT` | InvalidArgument | `close_session` 置 `closed=true`（`mdd-session/src/lib.rs:815-832`），`active_session` 拒绝 |
| compat 后 `snapshot_lease(&sibling_session)` 成功且 snapshot_id 一致 | 一致 | 兄弟 session 的快照租约未被 owning dataset 关闭影响 |
| 兄弟 `after_output.rows().len() == 4`、`execution_complete()` | 4 / true | compat 关闭 owning 后，兄弟 query 仍通过生产 `execute` 读完 4 行；若被误伤则失败 |

## 测试 4：`fallback_whitelist_rejects_real_query_terminal_errors`（:4659）

- 4 类真实终态错误（QUOTA_EXCEEDED / DEADLINE_EXCEEDED / CANCELLED / WORKER_LOST）在显式允许、pristine context 下均 `!fallback_allowed`；三种许可码（UNAVAILABLE_BACKEND / UNSUPPORTED_CAPABILITY / UNSUPPORTED_QUERY）在 pristine 下 `fallback_allowed`；`accepted_rows=1` 时即使许可码也拒绝。
- 该测试仅验证纯门控函数。`fallback_allowed` 无生产调用方（见 `CORRECTIONS.md` P2-6），因此不构成“fallback 已接线/不得静默切换”的生产覆盖。
- 测试中的 `worker_lost` reason 已改为 `"in-process worker_lost API (no process termination)"`。

## 辅助函数

- `production_runtime`（:357）：为兄弟 query 建立独立 BudgetPool 树（Global→Worker→Session→Query）并绑定其自身 cancellation token，供生产 `execute` 使用；不共用 fixture 的目标 query 预算树。
