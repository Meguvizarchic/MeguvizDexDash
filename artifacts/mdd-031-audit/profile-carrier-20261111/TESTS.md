# 测试记录

- 命令与原始日志均在 `readback/` 与 `red-green/`，日志是原始输出，未编辑。
- 运行环境：Windows x86_64，Git Bash，`cargo --offline`。

## 1. 全量测试

```
cargo test --offline -p mdd-sql
```

- 退出码 0
- lib：**212 passed; 0 failed**（本轮之前 208，新增 4）
- doctest：1 passed
- 日志：`readback/cargo-test.log`

新增 4 个测试（均在 `crates/mdd-sql/src/bridge.rs` 的 `mod tests`）：

| 测试 | 断言内容 |
| --- | --- |
| `unsupported_query_blocks_declared_profile_and_preserves_counterexample` | 对 NativeV1 / DexSql010 / DexSql011 三个方言各自：真实 unsupported 形状返回 `UNSUPPORTED_QUERY` 且 `details.profile_blocked=true`；`registry.is_blocked(profile)` 为真；保留的反例 SQL、profile 名、SHA256 与原始语句一致；随后一条**原本成功**的查询被拒绝为 `UNSUPPORTED_CAPABILITY`，且 `blocked_query`/`profile` 详情回指反例；`blocked_profiles()==["hostlab-audit-v1"]`，`blocked_count()==1` |
| `non_compatibility_failures_never_block_profile` | 语法错误、缺列错误（`InvalidArgument`）与 `QuotaExceeded` 均不带 `profile_blocked`，registry 仍空；之后正常查询仍返回 3 行 |
| `execute_stage_gap_blocks_profile_for_prepared_statement` | 在 `execute` 阶段（非 prepare）发现缺口时登记 `stage="execute"`；同一 `PreparedSql` 的第二次执行返回 `UNSUPPORTED_CAPABILITY` 且 `requested_stage="execute"` |
| `profile_block_is_scoped_to_declared_profile_and_registry` | 无 profile 的桥只返回裸 `UNSUPPORTED_QUERY`；`hostlab-audit-v1` 阻断不影响另一 profile + 另一 registry（该桥仍正常返回 3 行）；方言不匹配的 profile 声明返回 `COMPATIBILITY_PROFILE_DIALECT_MISMATCH` |

## 2. Clippy

```
cargo clippy --offline -p mdd-sql --all-targets -- -D warnings
```

- 退出码 0，无 warning。日志：`readback/cargo-clippy.log`

## 3. 格式

```
cargo fmt -p mdd-sql -- --check
```

- 退出码 0。日志：`readback/cargo-fmt-check.log`
- 说明：本轮只在手写片段上执行过格式化；`bridge.rs` 的历史部分本来就不符合 rustfmt（`cargo fmt` 全文件重排会产生约 1989 行无关 diff），因此没有提交全文件格式化。

## 4. 红绿验证（证明删掉阻断逻辑测试会失败）

三处强制点分别独立禁用一次，每次只改一处，跑 `cargo test --offline -p mdd-sql --lib profile`：

| 探针 | 改动 | 结果 | 日志 |
| --- | --- | --- | --- |
| RED-1 | `record_compatibility_failure` 直接 `return error`（不再登记阻断） | 3 failed / 2 passed：`unsupported_query_blocks_...`、`execute_stage_gap_...`、`profile_block_is_scoped_...` | `red-green/red-1-blocking-disabled.log` |
| RED-2 | `blocked_profile_error` 直接返回 `None`（不再 fail-closed） | 2 failed / 3 passed：`unsupported_query_blocks_...`、`execute_stage_gap_...` | `red-green/red-2-fail-closed-read-disabled.log` |
| RED-3 | 去掉 `error.code != UnsupportedQuery` 的过滤（任何错误都阻断） | 1 failed / 4 passed：`non_compatibility_failures_never_block_profile` | `red-green/red-3-error-class-filter-removed.log` |
| GREEN | 恢复源码 | 212 passed / 1 doctest passed | `red-green/green-restored.log` |

三个探针各自命中不同测试，说明「登记」「读取阻断」「错误分类」三个必要条件都真正被测到，不是单一恒真断言。

## 5. 未执行

- 未跑全 workspace `cargo test`（本轮只允许改 mdd-sql；同时 `crates/mdd-facts` 处于他人并发编辑中，18:34 时 `coverage.rs` 编译失败，18:36 后被对方修复）。`cargo test -p mdd-sql` 已连带编译 `mdd-facts`/`mdd-query` 依赖。
- 未做跨进程/持久化阻断验证（不在本轮范围）。

## 6. 非稳定失败（如实记录，非本轮代码问题）

并发构建期间记录到两次 target 争用失败，均在本 crate 代码未改动的情况下重跑通过：

1. doctest 阶段 `error[E0463]: can't find crate for mdd_query`（退出码 1）。
   单独 `cargo test --offline -p mdd-sql --doc` → 1 passed（`readback/cargo-test-doc.log`）。
2. example 阶段 `crate rusqlite required to be available in rlib format, but was not found`。
   等待 45 秒后整包重跑 → 212 passed + doctest 1 passed，退出码 0。

原因：`crates/mdd-facts` 等其他 crate 在同一 `target/` 目录下被其他子代理并发编译，
`target/debug/deps` 的 rlib 在 rustdoc/example 链接时被替换。原始失败日志未删除，
最终通过的日志为 `readback/cargo-test-final.log`。
