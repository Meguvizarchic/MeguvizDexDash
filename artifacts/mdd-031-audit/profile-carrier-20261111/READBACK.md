# Readback：阻断载体的实际行为

目的：用可执行的最小程序确认「兼容性失败真的让对应 profile 不可用」，而不是只读测试断言。

## 证据来源

本 readback 直接取用 `cargo test --offline -p mdd-sql` 的真实运行（`readback/cargo-test.log`）
与三处红绿探针（`red-green/*.log`），没有另建独立二进制——本轮约束不允许改
`Cargo.toml` 或新增 crate/example，因此以测试进程内的真实 SQLite 执行作为观测点。

被测链条是真实的：`bridge.query(sql)` → `dialects::ast::adapt` →
`prepare_inner` → `execute_inner`（真实 `rusqlite::Connection` + eponymous vtab）→
错误回到 `record_compatibility_failure`。

## 观测 1：真实缺口 → 阻断 → 后续查询 fail-closed

测试 `unsupported_query_blocks_declared_profile_and_preserves_counterexample`，
三个方言各一次。以 DexSql010 为例，反例
`WITH RECURSIVE q(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM q WHERE n<3) SELECT n FROM q`：

1. 首次调用返回 `UNSUPPORTED_QUERY`，`details.profile_blocked == true`；
2. `registry.block_for(profile)` 返回的 `CompatibilityBlock` 中
   `sql` 等于原语句、`sql_sha256 == sha256(原语句字节)`、`stage == "prepare"`；
3. 紧接着执行 `SELECT id FROM facts`（同一 provider、同一绑定、限制充足）：
   返回 `UNSUPPORTED_CAPABILITY`，`details.blocked_query` 等于步骤 1 的反例原文，
   `details.profile == "hostlab-audit-v1"`；
4. `registry.blocked_profiles() == ["hostlab-audit-v1"]`，`blocked_count() == 1`。

这与本轮之前的状态形成直接对照：改动前同一条 `SELECT id FROM facts` 会成功返回 3 行，
`profiles_admitted` 仍为空，阻断完全不存在。

## 观测 2：非兼容错误不阻断

`non_compatibility_failures_never_block_profile`：`SELECT FROM`、
`SELECT missing FROM facts`、`max_scanned_rows=0` 的配额错误之后，
`registry.is_blocked(profile) == false`、`registry.blocks().is_empty() == true`，
且 `SELECT id FROM facts` 仍返回 3 行。

红测 RED-3 证明该结论有判别力：去掉错误类别过滤后此测试失败。

## 观测 3：execute 阶段缺口同样阻断

`execute_stage_gap_blocks_profile_for_prepared_statement`：
`prepare` 成功、`execute` 时 `UNSUPPORTED_QUERY` → `block.stage == "execute"`、
`block.sql` 为 prepare 时的原 SQL；同一 `PreparedSql` 再次 `execute` 返回
`UNSUPPORTED_CAPABILITY` 且 `requested_stage == "execute"`。

## 观测 4：作用域隔离

`profile_block_is_scoped_to_declared_profile_and_registry`：
- 未声明 profile 的桥：`profile_blocked` 详情不存在，错误码仍是裸 `UNSUPPORTED_QUERY`；
- `hostlab-audit-v1` 阻断后，用**另一个** registry 声明 `dexsql-0.1.0-compat-v1` 的桥
  仍能正常查询返回 3 行；
- `CompatibilityProfile::new(..., DexSql011)` 用于 `NativeV1` 桥被拒绝为
  `COMPATIBILITY_PROFILE_DIALECT_MISMATCH`。

## 观测 5：红绿探针对应的三处强制点

| 删掉的东西 | 失败测试 | 说明 |
| --- | --- | --- |
| 阻断登记 | 3 个 | 没有 `block()` 就没有 `is_blocked` |
| fail-closed 读取 | 2 个 | 有登记但不拦截时，「已阻断 profile 仍能回答」会暴露 |
| 错误类别过滤 | 1 个 | 任何错误都阻断时，输入错误会误废 profile |

三者不重叠，说明「登记」「读取」「分类」都是被独立强制的不变量。

## 未证明的部分

- 跨进程阻断、跨 session 持久化：未实现，未测。
- 真实 HostLab 全量语料上「哪些 shape 会触发阻断」：本轮只用 3 个已知缺口形状，
  全量语料属 MDD-035。
- `profiles_admitted` 仍恒空：本轮没有、也不应把阻断结果写进该字段。
