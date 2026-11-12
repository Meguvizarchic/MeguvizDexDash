# 最小阻断载体实现说明

- 源码改动：`crates/mdd-sql/src/provider.rs`、`crates/mdd-sql/src/bridge.rs`、`crates/mdd-sql/src/dialects/mod.rs`
- 未改：`crates/mdd-sql/src/lib.rs` 的 `pub mod` 列表、`Cargo.toml`、`Cargo.lock`、`STATE.md`、`tasks/backlog.json`、`artifacts/**`（本目录为新增）、其他 crate
- 未引入新生产依赖、未新增模块文件

## 1. 数据模型（`provider.rs`）

```rust
pub struct CompatibilityProfile { pub name: String, pub dialect: SqlDialect }
pub struct CompatibilityBlock {
    pub profile: String, pub dialect: SqlDialect,
    pub stage: String,            // "prepare" | "execute"
    pub code: ErrorCode,          // 恒为 UnsupportedQuery
    pub message: String,          // 原始错误 message（反例原因）
    pub sql: String,              // 反例原文
    pub sql_sha256: String,
}
pub struct CompatibilityProfileRegistry { blocks: Mutex<BTreeMap<CompatibilityProfile, CompatibilityBlock>> }
```

`CompatibilityProfileRegistry` 的公开方法只有：`new`、`block`、`block_for`、`is_blocked`、`blocks`、`blocked_profiles`、`blocked_count`。**没有 `admit`/`issue`/`admitted` 任何正向接口。** `blocked_profiles()` 名字刻意不叫 `admitted_profiles`。

`CompatibilityProfile::new` 拒绝空名与含 NUL 的名字（`EMPTY_COMPATIBILITY_PROFILE`）。`SqlDialect` 增加 `Ord`/`PartialOrd` derive，仅为让 profile 键可放进 `BTreeMap`（该枚举无字段，语义不变）。

## 2. 桥接（`bridge.rs`）

新增字段：

```rust
pub struct SqlBridge { ..., profile: Option<CompatibilityProfile>, profiles: Option<Arc<CompatibilityProfileRegistry>> }
pub struct PreparedSql { ..., profile: Option<CompatibilityProfile>, profiles: Option<Arc<CompatibilityProfileRegistry>> }
```

新增 API：

- `SqlBridge::for_compatibility_profile(profile, registry) -> MddResult<Self>`：声明 profile 与承载 registry。方言不一致返回 `COMPATIBILITY_PROFILE_DIALECT_MISMATCH`；重复绑定返回 `COMPATIBILITY_PROFILE_ALREADY_BOUND`。**该方法不授予任何准入。**
- `SqlBridge::compatibility_profile() -> Option<&CompatibilityProfile>`：只读，doc 明示「Present does not mean admitted」。

三处强制点：

| 点位 | 行为 |
| --- | --- |
| `prepare_with_parameters` 入口 | 若该 profile 已被阻断，直接返回 `UnsupportedCapability`，不再解析或执行（`blocked_profile_error`） |
| `prepare_with_parameters` 出错 | 仅当 `error.code == UnsupportedQuery` 时登记阻断（`record_compatibility_failure`），其余错误原样透传 |
| `execute` 入口 | 再次检查阻断：`prepare` 时健康、之后被别的查询阻断，则该语句不再执行 |
| `execute` 失败 | 同上，按 `UnsupportedQuery` 登记，`stage = "execute"` |

`PreparedSql::execute` 会把 `profile`/`profiles` 传给内部重建的 `SqlBridge`，保持阻断跨语句一致；`PreparedSql` 自身也携带这两个字段，使 prepare 与 execute 归属同一 profile 作用域。

## 3. 阻断的错误形状

首次触发（真实兼容缺口）：

```
code   = UNSUPPORTED_QUERY        // 原始错误码保持不变
details.compatibility_profile = "hostlab-audit-v1"
details.profile_blocked       = true
details.profile_block_first   = true|false   // 是否本次调用造成阻断
```

后续任何查询（profile 已不可用）：

```
code    = UNSUPPORTED_CAPABILITY
stage   = "sql.profile"
details.profile              = 被阻断的 profile
details.sql_dialect          = 方言
details.blocked_at_stage     = "prepare" | "execute"
details.blocked_query        = 原始反例 SQL（原文）
details.blocked_query_sha256 = SHA256(反例 SQL)
details.blocked_error_code   = "UNSUPPORTED_QUERY"
details.blocked_error_message= 原始 message
details.requested_stage      = 本次被拒的入口
```

设计要点：

- 阻断后**不是**返回「空结果」或复用 `UnsupportedQuery`：`UnsupportedCapability` 与具体查询的 unsupported 明确分层（对齐 backlog MDD-034 第 5 条的 fallback 分类语义，但不引入 fallback）。
- 反例 SQL 原样保留（受 `SqlLimits.max_sql_bytes` 约束，能进入桥的 SQL 已被限额），并附 SHA256 便于与 ledger/证据对齐。
- 一个 profile 只保留**第一个**反例（`block()` 返回 `false` 表示已有反例，不覆盖），避免后续无关失败冲掉根因。

## 4. 阻断范围与作用域

- 注册表由调用方持有（`Arc<CompatibilityProfileRegistry>`），只有显式 `for_compatibility_profile` 的桥受约束。默认 `SqlBridge::new` 的 `profile`/`profiles` 均为 `None`，行为与本轮之前完全一致（212 个既有测试不变）。
- 阻断按 `(profile.name, dialect)` 键隔离：`hostlab-audit-v1` 被阻断不影响 `dexsql-0.1.0-compat-v1`，也不影响另一个 registry 上的同名 profile。
- 作用域是显式选择而非隐式全局，理由是：同一进程可能有独立 snapshot/探测用途；`docs/02` 要求 profile 与 session/snapshot 绑定而非进程级全局。跨查询、跨语句的阻断由「调用方把一个 registry 复用于同一 profile 的全部桥」实现，这一点在 `ADJUDICATION.md` 与 SUMMARY 中明确写出，不夸大。

## 5. 被刻意排除的错误类别

`record_compatibility_failure` 只接受 `UnsupportedQuery`。以下都不阻断 profile，并有专门测试：

- `InvalidArgument`：语法错误、缺列、未知 relation、绑定类型错误（输入错误）
- `QuotaExceeded`：预算耗尽
- `Cancelled` / `DeadlineExceeded`
- provider 侧错误（`IncompleteFacts` 等）

理由：这些错误不构成「兼容性缺口」的证据；把它们当作缺口会让一次拼写错误或一次预算停止永久废弃一个 profile。

## 6. 与 `profiles_admitted` 的关系

`SqlResult.profiles_admitted` 未改动，仍恒为 `Vec::new()`，且**没有**接入新 registry。理由：该字段名字表达正向签发，本 crate 无资格填写。旧测试
`compatibility_failure_preserves_counterexample_without_profile_admission` 保留，注释改为指向新 registry，不再声称覆盖阻断。

## 7. 未做的事（明确边界）

- 未提供任何准入/签发接口，未写 `compatibility/ledger.json`，未改 `conformance/manifests/profile-requirements.json`。
- 未把阻断持久化到 session/checkpoint（跨进程恢复不在第 5 条范围）。
- 未接入 CLI/MCP 的 capabilities 输出（`crates/mdd-cli/src/main.rs` 的 `profiles[]` 仍是 `admitted:false` 常量，属 MDD-035 集成点）。
- 未做 profile 级「部分阻断」（例如只阻断某个 SQL 形状）：第 5 条要求「阻断对应 profile」，本实现按字面执行整个 profile 不可用。
