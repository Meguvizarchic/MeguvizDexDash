# MDD-034 验收覆盖审计 SUMMARY

轮次：`cancel-fallback-isolation-20261111T065359Z`
范围：验收 3/4/5 的证据补齐与独立验证。只改 `crates/mdd-query/src/executor/runtime_tests.rs`（测试代码），未改生产逻辑、未加模块、未改 `lib.rs` pub mod。
声明：不授予 admitted / profile 资格；`export_changes_required` 为空。

## 终态路径证据现状枚举

| 终态路径 | 证据 | 性质 |
| --- | --- | --- |
| 完整成功（exact total、零行） | `exact-total-completeness-20261101/`、`result-tests-1/`、`query-full.stdout.txt` | 真实执行 |
| 部分行后失败（配额/输出行） | `quota_after_rows_has_failure_terminal_and_preserves_real_compute_axis`、`queue_quota_delivers_only_acknowledged_prefix_with_failure_end`、`json_batches_partial_failure_preserves_consumed_rows_and_error` | 真实执行 |
| 预算耗尽 / deadline | `queue-deadline-20261030/`、`receipt-budget-deadline-20261030/`、`budget-admission-deadline-20261030/`、`json-consumer-budget-deadline-20261101/` | 真实时钟 + 受控注入混合 |
| EOF before terminal / 非 pristine | `nonpristine-terminal-20261030/`、`queue-terminal-first-fault-20261101/`、`part_rows_error_and_eof_never_complete` | 真实执行 + 受控注入 |
| 原生取消（终态原子性/首错） | `terminal-cancel-atomic-20261101/`、`atomic-cancel-publication-20261101/`、`send-cancel-before-lock-20261101/`、`owned-receipt-confirm-first-20261101/`、`receipt-prior-failure-20261101/`、`finish-after-close-first-fault-20261101/`、`sender-drop-first-fault-20261101/`、`receiver-close-last-sender-20261101/`、`reentrant-receiver-drop-20261101/` | 多为受控注入 / 确定性交错 |
| 原生取消仅影响目标 query | 旧 `incremental-tests-1/`（test-only 路径）；本轮 `production_queue_native_cancel_is_isolated_from_sibling_and_keeps_partial_failure`（生产队列路径） | 确定性 hook 调度 |
| worker 强杀影响全部未完成任务 | 旧 `supervisor-1/`；本轮刷新 `supervisor-kill/`；本轮 `worker_kill_fails_inflight_query_and_is_not_a_fallback_error` | 真实子进程 kill + 单元级 |
| SQLite connection interrupt 隔离 | `sqlite-interrupt-1/`；本轮刷新 `sqlite-interrupt/` | 真实 connection 级，非 bridge |
| 兼容取消 profile | `mdd-session` 既有测试；本轮 `compat_cancel_profile_closes_only_owning_dataset_and_is_distinct_from_native` | 真实 API 行为 |
| fallback 白名单 | `mdd-types` 门控测试；本轮查询边界测试；`mdd-input`/`mdd-facts` 错误码保留测试 | 纯函数 + 真实错误码 |

未覆盖：穷举并发排列、生产 IPC 跨进程回执、SQLite bridge per-query interrupt、进程树隔离（`process_tree_isolated=false`）。

## 验收 5 条状态

### 1. operation_status、input/facts 三态 coverage、execution.complete 与 more_available/truncated/next_cursor 独立可验证
**已覆盖（原有，本轮刷新）。**
- `mdd-types/src/result.rs`：`coverage_execution_and_delivery_axes_are_independent_and_protocol_faults_sticky` 对 input/facts 各三态 × execution.complete 两态 × more_available/truncated/next_cursor 三态组合逐一验证 `is_complete_result`；`complete_result_requires_an_exact_matching_total`、`part_rows_error_and_eof_never_complete`、`computed_spool_cancel_page_and_complete_zero_are_independent` 补齐 exact total、page/cursor、零行与失败终态。
- 本轮重跑 `cargo test -p mdd-types`：13 passed（`types.stdout.txt`）。
- 缺口：无。这些是 envelope/verifier 层语义；mdd-query 侧由 `late_delivery_failures_return_coverage_and_computation_envelope`、`json_batches_zero_partial_and_limits_never_fake_complete` 等保证不伪造成功。

### 2. 预算耗尽和 deadline 不返回普通 EOF；部分行之后仍发出明确失败终态，消费者不得当完整成功
**已覆盖（原有，本轮回归通过）。**
- 代表证据：`artifacts/mdd-034-audit/quota-after-*`、`queue-deadline-20261030/`、`receipt-budget-deadline-20261030/`、`budget-admission-deadline-20261030/`、`json-consumer-budget-deadline-20261101/`、`exact-total-completeness-20261101/`。
- 本轮回归：`quota_after_rows_has_failure_terminal_and_preserves_real_compute_axis`、`queue_deadline_has_explicit_error_end_and_no_complete_success`、`json_consumer_partial_deadline_preserves_earlier_worker_loss`、`delivery_receipt_does_not_succeed_after_query_budget_deadline` 等全部通过（`query-full.stdout.txt`，201 passed）。
- 缺口：无新增缺口；穷举并发与生产 IPC 下的 deadline 行为仍未证（见下）。

### 3. 原生 cancel 仅影响目标 query；SQLite connection 的 interrupt 隔离有实证，强杀 worker 明确影响该 worker 全部未完成任务
**新覆盖 + 仍缺一项。**
- 新覆盖：
  - `production_queue_native_cancel_is_isolated_from_sibling_and_keeps_partial_failure`（生产 `execute_into` 队列路径，取消目标 query 后兄弟 query 不受影响；部分行 + 显式 Cancelled 终态）。
  - `worker_kill_fails_inflight_query_and_is_not_a_fallback_error`（`execute` 在途 + 兄弟 query 均由 `worker_lost` 失败）。
  - 刷新 `conformance/runtime --supervisor`：250ms deadline 触发 `child.kill()` 强杀直接子进程并回收，该 worker 全部 2 个未完成 query（含已计算未消费 spool）失败，先前完整交付的 query 保持 completed（`supervisor-kill/stdout.txt`）。
  - 刷新 `conformance/runtime --sqlite`：connection A interrupt 返回 OperationInterrupted，connection B 得到正确和且两连接可复用（`sqlite-interrupt/stdout.txt`）。
- 仍缺：**SQLite interrupt 的 bridge / query-token 级隔离**。当前探针明确标注 `connection-level evidence only; query token ownership remains bridge integration`；`crates/mdd-sql` 未见 `get_interrupt_handle` / per-query interrupt 所有权实现。这属于 mdd-sql/mdd-session 集成范围，本子代理无权修改。
- 未覆盖：穷举并发取消/发布/回执竞争；生产 IPC（管道协议、跨进程回执）下的取消与强杀。

### 4. 兼容能力使用 compat_cancel_closes_dataset 字段逐 profile 声明并验证，不混同原生取消
**新覆盖。**
- `compat_cancel_profile_closes_only_owning_dataset_and_is_distinct_from_native`：两个 session 共享同一 snapshot；native profile(false) 只取消目标 query、owning session 保持可用；compat profile(true) 关闭 owning session 的 dataset（后续 prepare 返回 INVALID_ARGUMENT），而共享同一 snapshot 的 sibling session 仍可用。`CancelOutcome.compat_cancel_closes_dataset` 与 profile 声明一致。
- 既有 `mdd-session` 测试 `native_query_cancel_and_explicit_dataset_profile_have_distinct_ownership` 本轮重跑通过（`session.stdout.txt`，30 passed）。
- 缺口：无 profile 注册表；profile 由调用方声明，CLI 在 `crates/mdd-cli/src/main.rs` 声明一个 `compat_cancel_closes_dataset=false`。逐 profile 声明的验证依赖调用方传入，引擎只按字段执行。若需要「逐 profile 注册并校验」的集中声明，需要主代理决策是否新增 profile registry（当前无此实现）。

### 5. 仅 UNAVAILABLE_BACKEND、UNSUPPORTED_CAPABILITY、UNSUPPORTED_QUERY 可按显式等价策略 fallback；完整性、源变化、配额、取消和内部故障不得静默切换
**新覆盖（门控层 + 查询边界）。**
- 门控：`mdd-types/src/result.rs::fallback_is_exact_three_code_gate_and_never_replays_partial_or_mutated_work` 对 18 种错误码与 7 种 context 违规逐一验证，只有三种许可码在显式等价、源/契约匹配、accepted_rows=0、无突变/副作用/后端强制/替代资格时通过（`types.stdout.txt`）。
- 查询边界：`fallback_whitelist_rejects_real_query_terminal_errors` 用真实执行产生 QUOTA_EXCEEDED / DEADLINE_EXCEEDED / CANCELLED / WORKER_LOST，全部不被白名单接受；三种许可码仅在 pristine context 接受，`accepted_rows>0` 即拒绝。
- 源变化/完整性非静默切换的适配器级证据：`scoped.rs::checked_source_detects_change_during_scan_before_limit_zero`（SourceChanged 保留）、`mdd-input` SHA-256 变更返回 SourceChanged（`input.stdout.txt`，24 passed）、`mdd-facts` `coverage_retains_late_genuine_errors_and_rejects_terminal_overwrite`（UnsupportedCapability 不覆盖既有真实错误，`facts.stdout.txt`）。
- 仍缺/需决策：`fallback_allowed` 目前**没有任何生产调用方**（全仓 grep 仅 mdd-types 自身测试）。因此「不得静默切换」在当前代码中成立（根本没有 fallback 发生），但「可按显式等价策略 fallback」的能力尚未接线到任何 adapter。是否需要在输入/事实 adapter 中接入该门控，属于主代理/后续任务决策；本子代理无权修改其他 crate。

## 未覆盖的并发 / IPC 范围

- 穷举并发：多线程同时取消、发布、回执、receiver drop 的全排列未证。本轮新测试为确定性 hook 调度，既有证据也明确标注「不证明全部并发」。
- 生产 IPC：worker 进程管道协议、跨进程消费确认、MCP/FFI 接线未证。supervisor 探针是直接子进程 + 超时 kill，`process_tree_isolated=false`。
- SQLite bridge：query token 所有权与 per-query interrupt 未实现/未证。
- 资源声明：所有预算为逻辑/保守声明，不含 RSS、分配器开销、性能资格。
- 平台：仅 Windows（msvc）本轮执行；未做跨平台。

## 仍需主代理决策的 export / 接线

- **export 变更：无。** 本轮未新增模块，未改 `lib.rs` pub mod 列表；新增测试只使用既有公开 API（`mdd_session::cancellation::CancelProfile`、`mdd_types::result::fallback_allowed` 等均已公开）。
- 决策项（非 export）：
  1. 是否将 `fallback_allowed` 接入输入/事实 adapter 的显式等价 fallback 路径（当前无调用方）。
  2. 是否新增逐 profile 的 cancel profile registry（当前由调用方声明）。
  3. SQLite bridge 的 per-query interrupt 所有权是否列入后续任务（当前仅 connection 级实证）。
