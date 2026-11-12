# MDD-031 profile 阻断载体 SUMMARY

- 日期：2026-11-11（UTC+8）
- 负责人：MDD-031 profile 准入载体子代理
- 证据目录：`artifacts/mdd-031-audit/profile-carrier-20261111/`
- 结论：**归属为两个层次。已在 MDD-031 内实现最小「阻断」载体；未实现、未声称任何「准入」。**
- 未 admitted 任何 profile，未签发资格，未改 `compatibility/ledger.json`、`capability-ledger.json`、`profile-requirements.json`。

## 1. 结论：MDD-031「阻断」与 MDD-035「准入门禁」是两个层次

| | MDD-031 第 5 条「阻断对应 profile」 | MDD-035「profile 准入门禁」 |
| --- | --- | --- |
| 方向 | 负向：一个具体 shape 不成立 → 该 profile 立即不可用 | 正向：必需集合全部成立 → 才允许 admitted |
| 时机 | 运行时，单条查询即可触发 | 离线，需完整 facts 上的冻结语料全量比较 |
| 依赖 | 只需 SQL 桥自身能判定的 `UNSUPPORTED_QUERY` | 需 MDD-026/032/033/034 产物 + typed IR 对照 + 分页/取消/TEMP/预算组合 |
| 产物 | 引擎内可查询的阻断状态 + 反例 | `conformance/manifests/query-profile-qualification.json` + ledger 更新 |

backlog 原文是决定性依据：

- MDD-031 要求「兼容失败保留具体反例并阻断对应 profile」——「兼容失败」是本 crate 直接产生的事件，无从外部注入。
- MDD-035 的 scope 是「建立 hostlab-audit-v1 查询层资格及兼容 profile 分项状态」，输出是外部资格清单，acceptance 全部围绕「冻结语料 + 完整 facts + 三条路径一致」。

若把「阻断」一并推迟到 MDD-035，则在 MDD-035 开工前，一个已知会让 `hostlab-audit-v1` 失败的 shape 在运行时没有任何后果，第 5 条后半句在整个 M3 期间是真空。若把「准入」提前放进 MDD-031，则等于在没有完整 facts 语料的情况下签发资格，直接违反 `docs/01` ADR-002「准备一个 query 能成功不意味着 profile 已 admitted」与 `profile-requirements.json` 的 `full_process_fallback_allowed_for_qualification: false`。

因此本轮选择「在 MDD-031 内提供最小载体」分支。与 Reviewer 第二轮判断的差别在于**载体边界**：提供的是 block-only registry，没有任何 `admit`/`issue` 接口，也不回写 ledger；`SqlResult.profiles_admitted` 保持恒空。详述见 `ADJUDICATION.md`。

## 2. 机制（最小实现）

改动文件（均在允许范围内，未新增模块文件）：

| 文件 | 改动 |
| --- | --- |
| `crates/mdd-sql/src/provider.rs` | 新增 `CompatibilityProfile`、`CompatibilityBlock`、`CompatibilityProfileRegistry` |
| `crates/mdd-sql/src/bridge.rs` | `SqlBridge`/`PreparedSql` 增加 `profile`/`profiles` 字段；新增 `for_compatibility_profile`、`compatibility_profile`；`prepare`/`execute` 接入阻断检查与登记 |
| `crates/mdd-sql/src/dialects/mod.rs` | `SqlDialect` 增加 `Ord`/`PartialOrd` derive，仅为让 profile 键可进 `BTreeMap` |

三个强制点：

1. **登记**：`prepare`/`execute` 返回 `UNSUPPORTED_QUERY` 时写入 `CompatibilityBlock`（profile、方言、阶段、原始 message、反例 SQL 原文 + SHA256）。
2. **fail-closed 读取**：同一 registry 上该 profile 一旦被阻断，后续 `prepare` 与 `execute` 一律返回 `UNSUPPORTED_CAPABILITY`，并在 details 中回指反例，不再尝试回答。
3. **错误分类**：只有 `UNSUPPORTED_QUERY` 触发阻断；`InvalidArgument`/`QuotaExceeded`/`Cancelled`/`DeadlineExceeded`/`IncompleteFacts` 等不阻断。

作用域：注册表由调用方以 `Arc` 持有，只有显式 `for_compatibility_profile` 的桥受约束；默认 `SqlBridge::new` 行为完全不变。阻断按 `(profile.name, dialect)` 隔离，一个 profile 阻断不影响其他 profile 或其他 registry。跨查询、跨语句的阻断由「同一 profile 复用同一 registry」实现，这一点是显式的，不是进程级全局。

**接口导出**：`provider` 已是 `pub mod`，新增的 `CompatibilityProfile`、`CompatibilityBlock`、`CompatibilityProfileRegistry` 自动可见；`SqlBridge` 已是公开类型，新方法随之导出。**无需主代理修改 `crates/mdd-sql/src/lib.rs`。**

## 3. 测试

```
cargo test --offline -p mdd-sql                                    → 212 passed / 0 failed，doctest 1 passed
cargo clippy --offline -p mdd-sql --all-targets -- -D warnings     → exit 0，无 warning
```

两处并发构建（他人子代理同时编译 mdd-facts）导致过 target 争用失败，原样记录在
`TESTS.md` 第 6 节，均已在不改代码的情况下重跑通过。
cargo fmt -p mdd-sql -- --check                                    → exit 0
```

新增 4 个测试：

- `unsupported_query_blocks_declared_profile_and_preserves_counterexample`（三个方言，验证「反例保留 + profile 不可用」）
- `non_compatibility_failures_never_block_profile`（输入错误/配额不误废 profile）
- `execute_stage_gap_blocks_profile_for_prepared_statement`（execute 阶段缺口 + 同一 PreparedSql 二次执行被拒）
- `profile_block_is_scoped_to_declared_profile_and_registry`（默认桥不受影响、profile/registry 隔离、方言不匹配报错）

**红绿证据**：分别禁用「登记」「fail-closed 读取」「错误类别过滤」三处，得到 3 failed / 2 failed / 1 failed，且失败的是不同测试；恢复后全绿。日志在 `red-green/`。这证明删掉阻断逻辑测试会失败，而不是断言恒真。

## 4. 验收 5 当前状态

| 子项 | 状态 | 依据 |
| --- | --- | --- |
| 所有查询绑定统一 snapshot/session | 已覆盖（前轮） | `SqlBinding` + `SqlExecutionBinding`；`SQL_RUNTIME_SNAPSHOT_EPOCH_OR_FINGERPRINT` 等 |
| 兼容失败保留具体反例 | 已覆盖（前轮 + 本轮强化） | 错误对象保留原始 message/细节；本轮新增 `CompatibilityBlock` 把反例 SQL 原文与 SHA256 持久在 registry 中 |
| 阻断对应 profile | **本轮新增覆盖（本 crate 范围）** | block-only registry + 三处强制点 + 4 个新测试 + 三处红绿探针 |

**结论表述**：验收 5 在 **mdd-sql 范围内** 现在算「已实现并被测试强制」。但必须同时声明其边界：

- 阻断只在显式声明 profile 并复用同一 registry 的调用链内生效；mdd-sql 自身不创建全局注册表，也未接入 CLI/MCP。
- `SqlResult.profiles_admitted` 仍恒空；「profile 被 admitted」这件事本 crate 不签发。
- 「准入」仍归 MDD-035：需要完整 facts 语料、typed IR/SQL/参考路径三路一致、分页/取消/TEMP/预算组合，以及 `query-profile-qualification.json`。本轮**没有**让验收 5 变成可宣布 profile 可用的状态。

## 5. 与 MDD-035 的接口建议

MDD-035 接入时需要的只有三件事：

1. 每个待验证 profile 建立一个 `Arc<CompatibilityProfileRegistry>`，整轮验证复用同一个实例；
2. 用 `SqlBridge::new(provider, dialect, limits)?.for_compatibility_profile(CompatibilityProfile::new(name, dialect)?, registry.clone())?` 构造桥；
3. 每轮结束后读 `registry.blocks()`，把每个 `CompatibilityBlock`（含 `sql`、`sql_sha256`、`stage`、`message`）写入 `query-profile-qualification.json` 的失败分项，并据此把该 profile 标为 not admitted。

反向不成立：本 crate 不提供任何「这些语句都通过 → admitted」的回写通道，也不读写 ledger；正向判定必须在 MDD-035 内基于完整证据做出。

## 6. 未做 / 未证明

- 未实现跨进程、跨 session 的阻断持久化。
- 未修改 `lib.rs` 的 `pub mod` 列表（也不需要）。
- 未修改 `Cargo.toml`/`Cargo.lock`/`STATE.md`/`tasks/backlog.json`/其他 crate/既有 artifacts。
- 未跑全 workspace 测试（受本轮改动范围约束；期间 `crates/mdd-facts` 有他人并发编辑，`cargo test -p mdd-sql` 已连带编译其依赖）。
- `bridge.rs` 历史部分不符合 rustfmt，未做全文件格式化以免产生近 2000 行无关 diff；只保证新增代码通过 `cargo fmt --check`。
- 阻断粒度为整个 profile，不是单个 SQL 形状，按第 5 条字面要求。
