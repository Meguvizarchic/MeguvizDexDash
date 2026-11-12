# Step-Reviewer 修正（2026-11-11）

本文件记录对抗审查对本目录证据的修正。原始文件保持历史含义，不做改写。

## P1：`IMPLEMENTATION.md:13` 的断言清单与代码矛盾

原文称测试 1 断言「终态 `operation_status=cancelled`、`emitted_rows=1`、`truncated=true`、`is_complete_result=false`」。

**实测**（`crates/mdd-query/src/executor/runtime_tests.rs:4311-4318`）：只断言 `operation_status`、`emitted_rows`、`error.code`、`execution.complete`、`!is_complete_result()`。**没有任何 `truncated` / `more_available` / `next_cursor` 断言**——这三个字段只出现在 `println!` 的 JSON 序列化里。

这三字段正是验收 1 点名要求的字段，因此本条证据**不能**作为验收 1 的终态字段证据。

## P1：`is_complete_result()` 断言零信息量

`runtime_tests.rs:4318` 的 `assert!(!envelope.is_complete_result())` 是派生断言：`ResultEnvelope::is_complete_result`（`crates/mdd-types/src/lib.rs:319-333`）的第一个合取项就是 `operation_status == Ok`，而 :4311 已断言 `Cancelled`，故恒真。

## P2：`is_complete_result()` 之外的两条「隔离」断言结构性恒真

- 测试 1（`:4319-4320`）：兄弟 query 从未被 `execute` 调用过（只 prepare/start/checkpoint），而 `cancel_query`（`mdd-session/src/lib.rs:1366-1374`）按构造只结束单个 query。**不可能失败**，作为反例检测器无效。
- 测试 3（`:4443`、`:4466-4472`）：单线程顺序断言；兄弟 session 从未通过它读任何 snapshot 数据，而 `close_session`（`mdd-session/src/lib.rs:815-832`）按构造不碰别的 session。真实风险（兄弟持有共享 snapshot 的 open cursor / batch handle 时被 compat 关闭）未测。

## P2：`"controlled hard kill"` 名不副实

`runtime_tests.rs:4353`、`:4539` 的字符串描述的是 `Lifecycle::worker_lost`（`mdd-session/src/lib.rs:1428-1430` → `fail_worker`），是**进程内 API 调用**，不杀任何进程。真实强杀只在 supervisor 探针（`mdd-worker/src/lifecycle/mod.rs:191-216` 的 `child.kill()`），而该探针子进程只 sleep 后 `exit(97)`，**从不执行查询**，所以「该 worker 全部未完成任务失败」只是父进程 lifecycle 记账传播。

## P2：SQLite interrupt 证据与引擎无关

探针用**裸 `rusqlite::Connection`**（`conformance/runtime/src/main.rs:19-99`），与 mdd-sql 零关联；`grep -rn "interrupt" crates/mdd-sql/src/` 只命中一条注释，**mdd-sql 无任何 interrupt 实现**。且探针测的是两个独立 connection，**不是同一 connection 上两个 query**（后者才是 per-query interrupt 的真问题）。

准确表述应为：**SQLite 库能力外置演示；引擎 SQL 执行路径无 interrupt；同一 connection 上多 query 隔离未测。**

## P2：死代码能力被标为「新覆盖」

`cancel_with_profile` / `CancelProfile` 与 `fallback_allowed` 均**无生产调用方**（grep 确认）。`fallback_allowed` 只有定义 + 测试；`cancel_with_profile` 只有 mdd-session 自身测试 + 本轮新测试。因此：

- 验收 5 的「不得静默切换」是**空洞成立**（根本没有 fallback 发生）；
- 「可按显式等价策略 fallback」**未接线到任何 adapter**，按项目规则算**未覆盖**。

## 仍然成立的结论

- 4 个新测试真实存在、稳定通过（连续 3 次无 flake）、clippy 干净；mdd-query 全量 **201 passed** 无回归。
- 本轮确实只改 `runtime_tests.rs` 一个被跟踪源文件；`lib.rs`、`Cargo.toml`、`Cargo.lock`、其他 crate、模块结构均未动。
- 9 个证据 stdout + 5 个源文件 + conformance 二进制的哈希与 `record.json` 全部一致。
- 验收 1/2 原有覆盖属实（本轮仅回归刷新，无新增覆盖）；验收 3/4/5 均为**部分覆盖 + 保留缺口**，`admitted:false` 处理正确。
