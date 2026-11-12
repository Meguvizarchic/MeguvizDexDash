# MDD-033 SUMMARY：会话 TEMP catalog 与快照绑定分页

- 日期：2026-11-11（Asia/Shanghai）
- 角色：MDD-033 实施子代理
- 性质：**实现 + 自测证据**。不声称 admitted / task_complete_proven / profile 签发。
- 详细内容：`IMPLEMENTATION.md`、`TEST-RECORD.md`、`readback.txt`、`record.json`

## 1. 验收 5 条最新状态

| # | 验收原文 | 状态 | 实现位置 | 边界 / 缺口 |
|---|---|---|---|---|
| 1 | cursor 同时绑定 snapshot、session、catalog_epoch、query 和 schema；跨作用域或旧代次明确失败 | **本层实现完成，自测通过** | `cursors.rs` `CursorBinding` / `cursor_binding` / `validate_page_continuation` | 已补 `worker generation`（registry 级、`claim_supervision` 推进）与 AST 指纹、参数类型指纹、来源指纹。指纹由 SQL 层计算传入；真实执行链尚未接线 |
| 2 | catalog_epoch 使用十进制 u64 字符串；不能把运行中 cursor 暗中迁移到新 TEMP 定义 | **实体已存在，语义可构造并测通**（不再是空转） | `catalog.rs` `TempCatalog::resolve_at` / `bind_query_temp` / `verify_query_temp_binding` | 序列化仍是既有 `DecimalU64`；本层用 `DecimalU64` 承载 epoch 输出。旧 query 读旧定义、新 query 读新定义各有测试 |
| 3 | 同 SQL、相同 row count/schema 的来源变化仍不能拼接混合页面 | **拒绝逻辑实现，反例测通** | `cursors.rs` `source_changed` / `query_schema_or_total_changed` / `PageRequestShape` | 需要 SQL 层提供真实 `source_fingerprint` 才能端到端成立；当前是契约层证据 |
| 4 | 兼容 offset 的重执行成本和稳定性边界明确；原生快照 cursor 不被伪装为该行为 | **契约实现，端到端未接线** | `cursors.rs` `CompatOffsetState` / `CompatOffsetContract` / `PageResponseMetadata` | `max_executions`/`max_rows`/`max_page_rows` 硬预算、lookahead、`next_offset` 与 token 互斥均已实现。CLI 能力声明与请求入口未接 |
| 5 | TEMP 自有 catalog 遵循已验证 profile；循环、IF NOT EXISTS、DROP、重定义和跨会话隔离有准确错误 | **五项语义全部实现，自测通过** | `catalog.rs` `create`/`drop`/`inject_materialization` | 循环与跨会话隔离在既有 preflight oracle 中**未验证**，本轮实现是设计定义而非 oracle 复现；`AS SELECT` 只留注入点，不物化 |

量化：5 条中 **2 条（1、5）在本层完整可用**，**2 条（2、3）语义实现且可用**但仍需跨 crate 指纹接线才能端到端，**1 条（4）契约完整但缺入口接线**。没有一条可以宣称"已验证等价于参考引擎"。

## 2. 仍需主代理决策的 export / cross-crate 事项

按优先级排序。每项都**不在本子代理可写范围**。

### P1. `pub mod` 导出（阻塞下游使用）

`crates/mdd-session/src/lib.rs` 目前是：

```rust
pub mod cancellation;
mod catalog;   // 需改为 pub mod
mod cursors;   // 需改为 pub mod
```

私有模块下 `pub` 类型无法被外部 crate 命名（`mdd-sql`/`mdd-query` 若要用 `CursorSpec`、`TempCatalogChange`、`PageRequestShape` 就必须先导出）。

- 建议改动：`mod catalog;` → `pub mod catalog;`，`mod cursors;` → `pub mod cursors;`。
- 无需新增 `pub use`；如需扁平化，可另加 `pub use cursors::{CursorMode, CursorSpec, ...}`。
- 依据：`tasks/backlog.json` MDD-033 outputs 明确要求 `crates/mdd-session/src/catalog.rs` 与 `cursors.rs`。

### P1. `SqlResult` 分页字段（`crates/mdd-sql/src/bridge.rs`）

现状：`SqlResult` 只有 `columns/rows/calculation_complete/profiles_admitted/sqlite_version/optimizer/required_*`，无分页字段。要落地验收 3/4 的端到端链，至少需要：

- `next_offset: Option<DecimalU64>`（兼容 offset）
- `more_available: bool`（由 `limit+1` lookahead 得出）
- `source_fingerprint: String`（建议直接复用 `SnapshotManifest::snapshot_content_key`）
- `ast_fingerprint: String`、`parameter_types_fingerprint: String`

本轮提供的 `CursorSpec` / `CompatOffsetPage` / `CompatOffsetAdmission` 已按这些字段设计，可直接映射。

### P1. `TerminalBuilder::page` 的生产调用点

`mdd-types/src/result.rs:154-170` 的 `page()` 仍只有测试调用。本轮已在 `mdd-session` 内加入 `PageResponseMetadata::native_page` 作为首个非测试调用点，但真正的生产路径在 `mdd-query/src/executor.rs`（`Streaming`/`execute_into`）与 `mdd-sql`。需要主代理决定：

- 是否把 `native_page` 上移为 `mdd-types` 的构造器，还是由 `mdd-query` 直接调用 `page()` 并复用 `PageResponseMetadata` 校验。
- `Response` 结构（`mdd-types/src/lib.rs:190-199`）无 offset 字段。兼容 offset 若要进同一信封，需新增字段并升 `mdd.result.v1` 版本，或改用独立响应类型。**这是契约变更，必须主代理决定。**

### P2. `CREATE TEMP` SQL 语法与 `AS SELECT` 物化

`mdd-sql` 当前硬拒 DDL（`dialects/ast.rs:1213-1215`、`bridge.rs:929-931`、测试 `bridge.rs:4164`）。要闭合验收 5 的端到端链，需要：

1. `dialects/ast.rs` 允许 `Statement::CreateTable`/`CreateView` 的 TEMP 变体并提取定义哈希与依赖名；
2. 解析后调用 `Lifecycle::temp_catalog_create(session, CreateTempDefinition{..}, if_not_exists)`；
3. `AS SELECT` 执行后调用 `Lifecycle::temp_catalog_inject(session, name, hash, handle)`；
4. DDL 结果 metadata 需要 `kind=create_temp_table` 之类字段（preflight 观测到参考引擎对 TABLE/VIEW 都返回该 kind，但对象种类仍由 DROP 区分）。

本轮的 session 层契约已按上述四步设计，可直接对接。

### P2. `conformance/session/catalog-and-paging.json`

backlog outputs 之一，`conformance/` 不在可写范围。`TEST-RECORD.md` §2-§4 的表格已按可机读条目组织（test 名 + expected 语义 + 反例），可直接迁移为该 JSON 的 `session_cases` / `paging_cases` / `temp_catalog_cases` 三段。

### P2. `mdd-cli` 能力声明

`crates/mdd-cli/src/main.rs:74` 的 `"pagination_modes": []` 需要变为双模式声明。`CursorMode::capability()` 已提供稳定字符串：

- `native_snapshot_cursor`
- `compat_offset_reexecution`

### P3. backlog / STATE / ledger 同步

`tasks/backlog.json` MDD-033 仍为 `status: todo`。按项目约定这些共享文件由主代理单写，本轮未触碰。

## 3. 本轮实际交付

| 项 | 内容 |
| --- | --- |
| `crates/mdd-session/src/cursors.rs`（新增，1516 行） | 11 个类型 + `Lifecycle` 的 7 个新方法 + 13 条测试 |
| `crates/mdd-session/src/catalog.rs`（新增，1040 行） | 8 个类型 + `TempCatalog` 的 8 个方法 + `Lifecycle` 的 7 个新方法 + 10 条测试 |
| `crates/mdd-session/src/lib.rs`（+42/−14） | 私有 mod 声明、状态字段、`claim_supervision` 代次、`advance_catalog` 委托 |
| 测试 | 新增 23 条（catalog 10 + cursors 13），全绿；lib 合计 53 条 |
| 变异验证 | 6 处变异全部变红后完整恢复 |
| 回归 | `mdd-query` 201 绿、`mdd-sql` 213 绿、`mdd-worker` 1 绿 |

## 4. 诚实声明

- 未改 `Cargo.toml`/`Cargo.lock`/`STATE.md`/`tasks/backlog.json`/`conformance/`/其他 crate。
- 未新增任何生产依赖。
- 未修改 `lib.rs` 的既有 `pub mod` 列表（新增的两个 mod 是私有的）。
- 没有一条验收可以宣称"与参考引擎等价"：preflight 的 A0/A1 证据只用于语义对齐，本轮未重跑 oracle。
- 循环检测与跨会话隔离在 preflight 中**属未验证项**，本轮实现是设计定义 + 自测，不构成引擎行为复现。
