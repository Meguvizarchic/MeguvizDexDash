# MDD-033 实施说明：会话 TEMP catalog 与快照绑定分页

- 日期：2026-11-11（Asia/Shanghai）
- 范围：`crates/mdd-session/src/catalog.rs`（新增）、`crates/mdd-session/src/cursors.rs`（新增）、`crates/mdd-session/src/lib.rs`（最小内部接线）
- 未改动：`Cargo.toml`、`Cargo.lock`、`STATE.md`、`tasks/backlog.json`、`artifacts/**`（只读）、其他任何 crate
- 声明：**不授予 admitted / task_complete_proven / profile 资格**。本目录是实现与自测证据，不是任务完成或发行证书。

## 0. 结论先行

| acceptance | 本轮状态 | 说明 |
| --- | --- | --- |
| 1 cursor 同时绑定 snapshot/session/catalog_epoch/query/schema；跨作用域或旧代次明确失败 | **已在 mdd-session 层实现并自测通过** | 新增 `worker generation`、AST 指纹、参数类型指纹、来源指纹；逐项比对并给出分项错误 |
| 2 epoch 十进制 u64 字符串；运行中 cursor 不被暗中迁移到新 TEMP 定义 | **实体已存在，语义已可构造并测试** | `TempCatalog::resolve_at` 保留退役代次；`verify_query_temp_binding` 证明旧 query 仍解析旧定义 |
| 3 同 SQL、相同 row count/schema 的来源变化不能拼接混合页 | **mdd-session 层拒绝已实现** | `source_changed` / `query_schema_or_total_changed`；真实跨来源分页链由 mdd-sql 侧传入指纹后才能端到端成立 |
| 4 兼容 offset 成本与稳定性边界明确；原生 cursor 不被伪装 | **契约已实现**，端到端入口未接线 | `CompatOffsetState` 有重执行/行/页预算、lookahead 判定、`next_offset` 与 token 互斥；HTTP/CLI 入口仍需主代理接线 |
| 5 TEMP catalog 五类语义有准确错误 | **五项语义全部实现并自测通过** | 循环、IF NOT EXISTS、DROP 种类、重定义、跨会话隔离；`AS SELECT` 物化留注入点 |

仍有 4 项需要主代理决策或跨 crate 接线，见 `SUMMARY.md` §2。

## 1. 为什么 catalog 留在 mdd-session 且只存抽象

gap analysis 的 B1 指出：`mdd-session` 只依赖 `mdd-types` + `mdd-input`，而真实 TEMP 定义需要解析后 AST 与关系 schema，二者在 `mdd-sql`/`mdd-query`，而这两者反向依赖 `mdd-session`。

本轮采用 Step-Reviewer 建议的路径 1：`catalog.rs` 只保存与解析无关的抽象：

- `name: String`、`kind: TempKind`、`definition_hash: String`、`dependencies: Vec<String>`、`epoch`、`retired_epoch`、`materialization`。
- 定义哈希与依赖名由 SQL 层计算并传入；session 层不解析、不物化、不接触行。
- `CREATE TEMP ... AS SELECT` 的物化通过 `TempMaterialization::Deferred` + `Lifecycle::temp_catalog_inject(session, name, definition_hash, handle)` 注入。注入时强校验定义哈希，防止把上一版定义的行挂到新定义上。
- 依赖解析来自调用方给出的名称列表，不来自任何 SQL 文本匹配。

因此不存在 `mdd-session → mdd-sql` 的反向依赖，也没有新增 crate、没有新增生产依赖。

## 2. `catalog.rs` 的五项语义与 oracle 对齐

oracle 来源：`artifacts/mdd-033/preflight/README.md`（A0/A1 两版各 70 条 SQL 的实查行为表）。

| 语义 | 实现 | oracle 对照 |
| --- | --- | --- |
| 循环 | `validate_dependencies` 对全部 live 定义做可达性搜索；自引用单独判定；错误 `temp_error=cycle` + `path` | preflight 未验证循环（README「仍未验证」第 1 项）。此处是**设计定义**，不是 oracle 复现，报告中已标注 |
| IF NOT EXISTS | 命中已存在名称时返回 `Unchanged`，**不校验新 body 的依赖、不改种类、不推进 epoch** | 与「原值 1 保留；被忽略的新 body 引用 `never_defined` 也成功」一致 |
| DROP 种类校验 | 种类不符无论 `IF EXISTS` 都失败，消息 `use DROP {kind} to delete item`，错误 `drop_kind_mismatch`，对象与 epoch 不变 | 与「`IF EXISTS` 不能吞掉种类错误」一致 |
| 重定义 | 同名不同种类直接替换，`Replaced{previous_kind}`，旧定义进入 `retired` 并可被旧代次解析 | 与「TABLE→VIEW 后替换后的对象种类生效」一致 |
| 跨会话隔离 | `TempCatalog` 挂在 `SessionEntry`，同名在不同 session 独立 | preflight 未验证跨 session。此处是**设计定义**，已标注 |
| 前向引用 | 创建时即校验依赖存在；失败不发布、不推进 epoch | 与「四种形式都在 CREATE 时拒绝 `unknown relation \`future\``」一致 |
| 不存在对象 DROP | `no such table: X` / `no such view: X`；`IF EXISTS` 返回 `Absent` 且不推进 epoch | 一致 |

未对齐的 oracle 项：**语法损坏的 IF NOT EXISTS body**（oracle 本身也未验证）。`catalog.rs` 不做语法分析，语法错误由 SQL 层在调用前拒绝，因此 session 层无法也无需复现该行为。

## 3. `cursors.rs` 的绑定与两条分页契约

### 3.1 原生 cursor 绑定（acceptance 1）

`CursorBinding` 现在包含 `docs/02_ARCHITECTURE_AND_CONTRACTS.md:399` 要求的全部项：

```
session_id + query_id + snapshot_id + catalog_epoch
+ worker_owner + worker_generation
+ request_key + schema_id + semantic_version
+ ast_fingerprint + parameter_types_fingerprint + source_fingerprint
+ mode
```

- `request_key` / `schema_id` / `semantic_version` 沿用既有 `QueryBinding`（`mdd-query::PreparedQuery::runtime_binding` 已产出内容哈希，其中已含规范化 query 与 source_identity）。
- `ast_fingerprint` / `parameter_types_fingerprint` / `source_fingerprint` 由调用方以 `CursorSpec` 传入，必须是 64 位小写十六进制。`source_fingerprint` 对应 `docs/:253` 计划缓存键里的 `snapshot_content_key` 语义，由 SQL 层从 `SnapshotManifest` 派生。
- `worker_generation` 是 registry 级计数器，只在 `claim_supervision` 成功时 +1。旧 cursor 在下一 worker 实例下被 `worker_generation_changed` 拒绝，且该检查在 `checkpoint` 之后、任何页交付之前。
- 旧 `open_cursor`（无指纹）仍可用于非分页的交付游标，但 `validate_paged_cursor` 会以 `cursor_binding_incomplete` 拒绝它进入分页路径，避免把缺指纹的游标当成原生分页游标。

### 3.2 混合页拒绝（acceptance 3）

两道独立闸门：

1. **请求侧** `PageRequestShape::check`：`relation_limit` 或 `relation_offset` 任一存在 → `response_paging_over_relation_limit`（`InvalidCursor`），并回显两个值。这条覆盖「SQL `LIMIT` 是关系算子，不是 API page limit」（`docs/:405`）。
2. **响应侧** `validate_page_continuation`：第一页固定 `schema_id`、`total_rows`（含 `None` 这个"无精确总数"取值）与 `source_fingerprint`；后续页逐项比对，不一致分别是 `query_schema_or_total_changed` 与 `source_changed`。

`source_changed` 正是验收 3 的核心反例：SQL 文本、行数、列 schema 全同，只有来源不同，仍然拒绝。测试 `same_sql_same_schema_different_source_cannot_be_stitched` 直接构造该反例。

错误名对齐 HostLab 参考实现 `conformance/corpus/hostlab/source-8782f43/analysis_paging.py:165,171` 的 `query_page_identity_or_limit_mismatch` / `query_schema_or_total_changed`。

### 3.3 兼容 offset 契约（acceptance 4）

`CompatOffsetState` 明确回答「成本」和「稳定性」两个问题：

- **成本**：`CompatOffsetContract{max_page_rows, max_executions, max_rows}` 三项都必须为正，且 `max_rows >= max_page_rows`。每次 `admit` 计一次重执行；超 `max_executions` 或 `max_rows` 是 `QuotaExceeded`，不是静默截断。
- **稳定性**：第一页固定 `schema_id` 与 `total_rows`，后续页不一致即失败；`source_fingerprint` 同样固定。`catalog_epoch` 相反地**允许变化**并逐页记录在 `catalog_epochs_observed`，因为兼容 offset 每次重执行本来就应该看见新 catalog generation（`docs/:404`）。
- **more_available**：只有在 `rows == limit && !lookahead_exhausted && !total_reached` 时为真。短页却没有 lookahead 证据 → `lookahead_required`，不允许「为了避免判断就无条件标记没有下一页」（`docs/:405`）。
- **不伪装**：`CompatOffsetState` 不分配 `CursorHandle`；`PageResponseMetadata::validate` 强制 `mode` 与 continuation 形式一致，`CompatOffset` 下出现 `next_cursor` 是 `native_cursor_under_compat_offset`，`NativeSnapshot` 下出现 `next_offset` 是 `compat_offset_under_native_cursor`，两者同时出现是 `paging_mode_conflict`。请求侧对称：`ambiguous_continuation`。

### 3.4 `TerminalBuilder::page` 的接线

`PageResponseMetadata::native_page(builder, page_rows, cursor_token)` 是 `TerminalBuilder::page` 在 `mdd-session` 内的第一个非测试调用点：它调用生产 `page()`，再断言 envelope 的 `next_cursor` / `more_available` 与返回的 metadata 一致。`mdd.result.v1` 的 `Response` **没有** offset 字段（`crates/mdd-types/src/lib.rs:190-199`），所以原生页信封在类型层面就不可能携带兼容 offset 续页。

## 4. lib.rs 的内部改动清单（没有新增 pub mod 导出）

`lib.rs` 只做了让新模块可编译、可被自测的最小改动：

| 改动 | 原因 |
| --- | --- |
| `mod catalog; mod cursors;`（**私有**） | 新增模块；`pub mod` 属共享 export，留给主代理 |
| `SessionEntry.temp: catalog::TempCatalog`，并删除重复的 `catalog_epoch` 字段 | catalog 自身持有唯一 epoch 计数器，避免两份真相不一致 |
| `QueryEntry.temp_binding: Option<catalog::TempBinding>` | prepare 时冻结 TEMP 解析 |
| `CursorEntry` 增加 `worker_owner`/`worker_generation`/`spec`/`page_total`/`page_total_established`/`pages` | 绑定与分页状态 |
| `State.worker_generation`，`claim_supervision` 成功时 +1 | worker 实例代次 |
| `advance_catalog` 改为 `temp.advance()` | 保持既有 `Lifecycle::advance_catalog` 签名与行为（+1、溢出报错），只是计数器搬家 |
| `prepare_query` 的 `let epoch = entry.temp.epoch()` | 同上 |

既有 30 条 lib 测试全部保持通过；当前 lib 合计 53 条（本轮新增 23 条），见 `test.stdout.txt`。

## 5. 明确没有做的事

1. **没有实现 `CREATE TEMP` 的 SQL 语法**。`mdd-sql` 仍拒绝 `CREATE TEMP TABLE`（`bridge.rs:4164` 附近的既有测试）。本轮只提供 session 层契约与注入点。
2. **没有接线 CLI/HTTP 分页入口**。`mdd-cli/src/main.rs:74` 的 `pagination_modes` 仍为 `[]`。
3. **没有给 `SqlResult` 增加分页字段**。这需要改 `crates/mdd-sql/src/bridge.rs`，属跨 crate 改动，见 `SUMMARY.md` §2。
4. **没有在 `conformance/session/catalog-and-paging.json` 写入条目**。该文件是 backlog outputs 之一，但 `conformance/` 不在本子代理可写范围；测试清单已在 `TEST-RECORD.md` 中以等价表格形式给出，可直接迁移。
5. **没有跑真实引擎 oracle 对照**。oracle 行为来自既有 preflight 证据，本轮是语义实现 + 单元/集成自测，不是引擎间等价证明。
6. **没有证明混合页拒绝在真实 SQL 结果上成立**。`mdd-session` 只能校验调用方传入的指纹；真实指纹来自 SQL/执行层，尚未接线。
