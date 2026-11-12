# MDD-034 验收覆盖审计 SUMMARY（gap-closure 修正版）

轮次：`gap-closure-20261111`（修正 `cancel-fallback-isolation-20261111T065359Z` 的 Step-Reviewer 问题）
范围：验收 3/4/5 的证据补齐与独立验证。只改 `crates/mdd-query/src/executor/runtime_tests.rs`（测试代码），未改生产逻辑、未加模块、未改 `lib.rs` pub mod。
声明：不授予 admitted / profile 资格；`export_changes_required` 为空。

## Step-Reviewer 6 项问题逐条修复结果

| # | 问题 | 修复 | 状态 |
| --- | --- | --- | --- |
| P1-1 | `IMPLEMENTATION.md:13` 声称断言 `truncated`/`more_available`/`next_cursor`，代码中没有 | 测试 1 补齐这些字段及 `operation_status`/`execution.complete`/`total_rows_exact` 断言；测试 2 改队列路径并补齐同类断言；来源见 `ASSERTIONS.md` | 已修复 |
| P1-2 | `is_complete_result()` 恒真断言 | 删除，并注释其首项谓词 `operation_status == Ok` 已被 Cancelled 断言否定 | 已修复 |
| P2-3 | 隔离断言结构性恒真（兄弟 query 从未 execute；兄弟 session 从未读数据） | 测试 1 兄弟 query 走生产 `execute` 并断言 4 行；测试 3 兄弟 session 在 compat 关闭前后各执行生产 `execute`、并读共享快照租约 | 已修复 |
| P2-4 | `"controlled hard kill"` 名不副实 | 测试重命名为 `in_process_worker_lost_...`；reason 改为 `"in-process worker_lost API (no process termination)"`；明确真实子进程 kill 只在 supervisor 探针 | 已修复（未新增真实强杀查询路径，超出范围） |
| P2-5 | SQLite interrupt 证据与引擎无关 | 改准确表述：裸 rusqlite 库能力演示；mdd-sql 无 interrupt 实现；探针为两个独立 connection，同一 connection 多 query 隔离未测 | 已修正措辞 |
| P2-6 | 死代码被标为「新覆盖」 | `cancel_with_profile`/`CancelProfile`、`fallback_allowed` 均标注无生产调用方；验收 4 记部分覆盖、验收 5 记部分覆盖/未覆盖 | 已修正 |

## 终态路径证据现状枚举

| 终态路径 | 证据 | 性质 |
| --- | --- | --- |
| 完整成功（exact total、零行） | `exact-total-completeness-20261101/`、`result-tests-1/`、`query-full.stdout.txt` | 真实执行 |
| 部分行后失败（配额/输出行） | `quota_after_rows_has_failure_terminal_and_preserves_real_compute_axis`、`queue_quota_delivers_only_acknowledged_prefix_with_failure_end`、`json_batches_partial_failure_preserves_consumed_rows_and_error` | 真实执行 |
| 预算耗尽 / deadline | `queue-deadline-20261030/`、`receipt-budget-deadline-20261030/`、`budget-admission-deadline-20261030/`、`json-consumer-budget-deadline-20261101/` | 真实时钟 + 受控注入混合 |
| EOF before terminal / 非 pristine | `nonpristine-terminal-20261030/`、`queue-terminal-first-fault-20261101/`、`part_rows_error_and_eof_never_complete` | 真实执行 + 受控注入 |
| 原生取消（终态原子性/首错） | `terminal-cancel-atomic-20261101/`、`atomic-cancel-publication-20261101/`、`send-cancel-before-lock-20261101/`、`owned-receipt-confirm-first-20261101/`、`receipt-prior-failure-20261101/`、`finish-after-close-first-fault-20261101/`、`sender-drop-first-fault-20261101/`、`receiver-close-last-sender-20261101/`、`reentrant-receiver-drop-20261101/` | 多为受控注入 / 确定性交错 |
| 原生取消仅影响目标 query | 本轮 `production_queue_native_cancel_is_isolated_from_sibling_and_keeps_partial_failure`（生产队列路径，兄弟真实 execute 4 行） | 确定性 hook 调度 |
| worker_lost 影响全部未完成任务 | 本轮 `in_process_worker_lost_fails_inflight_query_and_is_not_a_fallback_error`（进程内 API）；旧 `supervisor-1/` + 刷新 `supervisor-kill/`（真实子进程 kill，但子进程不执行查询） | 进程内 API + 真实子进程 kill（记账传播） |
| SQLite connection interrupt 隔离 | `sqlite-interrupt-1/`；刷新 `sqlite-interrupt/` | **裸 rusqlite 库能力演示，与引擎无关**；两个独立 connection |
| 兼容取消 profile | `mdd-session` 既有测试；本轮 `compat_cancel_profile_closes_only_owning_dataset_and_is_distinct_from_native`（兄弟真实 execute + 快照租约） | 真实 API 行为；**无生产调用方** |
| fallback 白名单 | `mdd-types` 门控测试；本轮查询边界测试；`mdd-input`/`mdd-facts` 错误码保留测试 | 纯函数 + 真实错误码；**无生产调用方** |

未覆盖：穷举并发排列、生产 IPC 跨进程回执、SQLite bridge per-query interrupt、同一 connection 多 query 隔离、进程树隔离（`process_tree_isolated=false`）、真实强杀下执行中的查询。

## 验收 5 条状态

### 1. operation_status、input/facts 三态 coverage、execution.complete 与 more_available/truncated/next_cursor 独立可验证
**已覆盖（原有，本轮刷新）。**
- `mdd-types/src/result.rs`：`coverage_execution_and_delivery_axes_are_independent_and_protocol_faults_sticky` 对 input/facts 各三态 × execution.complete 两态 × more_available/truncated/next_cursor 三态组合逐一验证 `is_complete_result`；`complete_result_requires_an_exact_matching_total`、`part_rows_error_and_eof_never_complete`、`computed_spool_cancel_page_and_complete_zero_are_independent` 补齐 exact total、page/cursor、零行与失败终态。
- 本轮重跑 `cargo test -p mdd-types` 通过；本轮 mdd-query 全量 201 passed。
- 缺口：无。本轮测试 1/2 在取消/失败路径上新增了 `truncated`/`more_available`/`next_cursor` 的真实断言。

### 2. 预算耗尽和 deadline 不返回普通 EOF；部分行之后仍发出明确失败终态，消费者不得当完整成功
**已覆盖（原有，本轮回归通过）。**
- 代表证据：`quota-after-*`、`queue-deadline-20261030/`、`receipt-budget-deadline-20261030/`、`budget-admission-deadline-20261030/`、`json-consumer-budget-deadline-20261101/`、`exact-total-completeness-20261101/`。
- 本轮回归：`quota_after_rows_has_failure_terminal_and_preserves_real_compute_axis`、`queue_deadline_has_explicit_error_end_and_no_complete_success`、`json_consumer_partial_deadline_preserves_earlier_worker_loss`、`delivery_receipt_does_not_succeed_after_query_budget_deadline` 等全部通过。
- 缺口：无新增缺口；穷举并发与生产 IPC 下的 deadline 行为仍未证。

### 3. 原生 cancel 仅影响目标 query；SQLite connection 的 interrupt 隔离有实证，强杀 worker 明确影响该 worker 全部未完成任务
**部分覆盖（原生 cancel 隔离本轮补强；SQLite 项为库能力演示，不算引擎实证；真实强杀查询路径仍缺）。**
- 原生 cancel 隔离：`production_queue_native_cancel_is_isolated_from_sibling_and_keeps_partial_failure` 在生产 `execute_into` 队列路径取消目标 query，兄弟 query 用生产 `execute` 真实执行并读 4 行，且无错误；终态 `truncated=true`/`more_available=false`/`next_cursor=None`。
- worker_lost：`in_process_worker_lost_fails_inflight_query_and_is_not_a_fallback_error` 验证进程内 `Lifecycle::worker_lost` 使在途查询与兄弟 query 均 Failed/WorkerLost；刷新 `conformance/runtime --supervisor` 的 `child.kill()` 强杀只证明父进程 lifecycle 记账传播（子进程不执行查询）。
- SQLite interrupt：**准确表述**——探针用裸 `rusqlite::Connection`，与 mdd-sql 零关联；`crates/mdd-sql/src/` 无 interrupt 实现；探针测两个独立 connection，不是同一 connection 上两个 query。因此「同一 connection 多 query 隔离」未测，不能算作引擎 interrupt 实证。
- 未覆盖：穷举并发取消/发布/回执竞争；生产 IPC（管道协议、跨进程回执）下的取消与强杀；真实强杀下执行中的查询。

### 4. 兼容能力使用 compat_cancel_closes_dataset 字段逐 profile 声明并验证，不混同原生取消
**部分覆盖（引擎行为正确，但无生产接线）。**
- `compat_cancel_profile_closes_only_owning_dataset_and_is_distinct_from_native`：两个 session 共享同一 snapshot；native profile(false) 只取消目标 query、owning session 保持可用；compat profile(true) 关闭 owning session 的 dataset（后续 prepare 返回 INVALID_ARGUMENT），兄弟 session 在关闭前后各执行生产 `execute` 读 4 行，且 `snapshot_lease` 可读、snapshot_id 一致。`CancelOutcome.compat_cancel_closes_dataset` 与 profile 声明一致。
- 既有 `mdd-session` 测试 `native_query_cancel_and_explicit_dataset_profile_have_distinct_ownership` 通过。
- **死代码**：`cancel_with_profile`/`CancelProfile` 无生产调用方（仅 mdd-session 自身测试与本轮测试）。因此这是 API 行为验证，不代表任何生产 adapter 使用该字段。
- 缺口：无 profile 注册表；profile 由调用方声明，CLI 在 `crates/mdd-cli/src/main.rs` 声明一个 `compat_cancel_closes_dataset=false`。逐 profile 注册的集中校验未实现。

### 5. 仅 UNAVAILABLE_BACKEND、UNSUPPORTED_CAPABILITY、UNSUPPORTED_QUERY 可按显式等价策略 fallback；完整性、源变化、配额、取消和内部故障不得静默切换
**部分覆盖 / 未覆盖（门控纯函数已验证；fallback 能力未接线）。**
- 门控：`mdd-types/src/result.rs::fallback_is_exact_three_code_gate_and_never_replays_partial_or_mutated_work` 对 18 种错误码与 7 种 context 违规逐一验证，只有三种许可码在显式等价、源/契约匹配、accepted_rows=0、无突变/副作用/后端强制/替代资格时通过。
- 查询边界：`fallback_whitelist_rejects_real_query_terminal_errors` 用真实执行产生 QUOTA_EXCEEDED / DEADLINE_EXCEEDED / CANCELLED / WORKER_LOST，全部不被白名单接受；三种许可码仅在 pristine context 接受，`accepted_rows>0` 即拒绝。
- 源变化/完整性非静默切换的适配器级证据：`scoped.rs::checked_source_detects_change_during_scan_before_limit_zero`、`mdd-input` SHA-256 变更返回 SourceChanged、`mdd-facts` `coverage_retains_late_genuine_errors_and_rejects_terminal_overwrite`。
- **死代码**：`fallback_allowed` 无任何生产调用方（全仓 grep 仅 mdd-types 自身测试与本轮测试）。因此：
  - “不得静默切换”在当前代码中**空洞成立**（根本没有 fallback 发生），不能算作生产覆盖；
  - “可按显式等价策略 fallback”**未接线到任何 adapter**，按项目规则算**未覆盖**。

## 未覆盖的并发 / IPC 范围

- 穷举并发：多线程同时取消、发布、回执、receiver drop 的全排列未证。本轮新测试为确定性 hook 调度。
- 生产 IPC：worker 进程管道协议、跨进程消费确认、MCP/FFI 接线未证。supervisor 探针是直接子进程 + 超时 kill，`process_tree_isolated=false`，且子进程不执行查询。
- SQLite bridge：query token 所有权与 per-query interrupt 未实现/未证；同一 connection 多 query 隔离未测。
- 资源声明：所有预算为逻辑/保守声明，不含 RSS、分配器开销、性能资格。
- 平台：仅 Windows（msvc）本轮执行；未做跨平台。

## 仍需主代理决策的 export / 接线

- **export 变更：无。** 本轮未新增模块，未改 `lib.rs` pub mod 列表。
- 决策项（非 export）：
  1. 是否将 `fallback_allowed` 接入输入/事实 adapter 的显式等价 fallback 路径（当前无调用方）。
  2. 是否新增逐 profile 的 cancel profile registry（当前由调用方声明）。
  3. SQLite bridge 的 per-query interrupt 所有权是否列入后续任务（当前 mdd-sql 无 interrupt 实现）。
  4. 是否补充真实子进程强杀执行中查询的证据（当前 supervisor 探针子进程不执行查询）。
