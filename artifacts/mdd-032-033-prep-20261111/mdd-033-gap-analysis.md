# MDD-033 差距分析：会话 TEMP catalog 与快照绑定分页

- 日期：2026-11-11（Asia/Shanghai），分析时点 19:21
- 性质：**只读分析**
- 任务定义：`tasks/backlog.json` `MDD-033`（status=todo，deps = MDD-014/030/**031**）
- 权威契约：`docs/02_ARCHITECTURE_AND_CONTRACTS.md` §6.4（TEMP catalog，`:247-255`）、§9.1（原生 cursor 与兼容 offset，`:397-406`）
- 现有骨架：`crates/mdd-session/src/lib.rs`（82 KB）、`crates/mdd-session/src/cancellation.rs`、`crates/mdd-query/src/executor.rs`、`crates/mdd-types/src/result.rs`
- 目标产物：`crates/mdd-session/src/catalog.rs`、`crates/mdd-session/src/cursors.rs`、`conformance/session/catalog-and-paging.json`、`artifacts/mdd-033/paging-isolation.json`

**结论先行**：MDD-033 的 acceptance 5 条中，**只有"cursor 绑定 snapshot/session/catalog_epoch/query/schema"
这一条有骨架且部分成立**，其余 4 条（TEMP catalog 实体、跨代次失败、混合页拼接拒绝、
兼容 offset 契约分离）**完全没有实现载体**。目标产物 4 个中 3 个不存在。

---

## 1. 现有骨架逐项盘点

### 1.1 已存在且有实际实现的部分

| 能力 | 位置 | 状态 |
|---|---|---|
| 快照 → 会话 → 查询 → 游标句柄层级 | `mdd-session/src/lib.rs:19-38`（`Token{owner,id,generation}` + `handle!` 宏） | 完整 |
| 句柄跨所有权/代次/父代校验 | `lib.rs:457-462` `State::check` | 完整 |
| 会话级 `catalog_epoch` 字段 | `lib.rs:336`（`SessionEntry.catalog_epoch: u64`），初值 0 于 `:801` | 字段存在，**无 catalog 实体** |
| `advance_catalog()` 单调 +1 | `lib.rs:842-851` | 完整（含 `checked_add` 溢出 → `invalid`） |
| 查询在 prepare 时捕获 epoch | `lib.rs:869`（`let epoch = entry.catalog_epoch`）→ `:904` `catalog_epoch: DecimalU64(epoch)` | 完整 |
| `catalog_epoch` 十进制 u64 字符串序列化 | `mdd-types/src/lib.rs:98-118`（`DecimalU64` 自定义 `Serialize` 为 canonical decimal string，反序列化拒绝前导零/非数字/超 20 位） | **完整且已有严格校验** |
| cursor 同时绑定 session/query/snapshot/epoch/request_key/schema_id/semantic_version | `lib.rs:1150-1183`（`finish_delivery_cursor_with_budget`）、`:1272-1303`（`validate_cursor`） | **完整** |
| 游标打开要求 active query + 预算 | `lib.rs:1223-1270` | 完整 |
| 未消费游标阻塞交付完成 | `lib.rs:1188-1211` | 完整 |
| 关闭未消费游标永久标记 `delivery_abandoned` | `lib.rs:1305-1324` | 完整 |
| 取消/期限/worker 丢失终态 | `cancellation.rs:105-200, 397-500` | 完整 |
| 结果信封的 page 形状 | `mdd-types/src/result.rs:153-170` `TerminalBuilder::page(page_rows, cursor, data)` | 形状存在，**无生产调用者** |
| typed IR 执行 | `mdd-query/src/executor.rs:1411` `execute()`、`:2334` `execute_into()` | 完整 |
| 预算/背压/批量回执 | `mdd-query/src/budget.rs`（会话绑定在 `:1318` 校验 `QueryBinding`) | 完整 |

### 1.2 关键否定事实（已验证，逐条给出 grep 依据）

1. **`crates/mdd-session/src/catalog.rs` 不存在**；`crates/mdd-session/src/cursors.rs` 不存在。
   `mdd-session/src/` 只有 `lib.rs` 与 `cancellation.rs`。
2. **整个 workspace 无 TEMP 实现**：`grep -rn "TEMP|named_temp|CatalogEntry|TempTable" crates/` 只命中两处非实现文本
   ——`mdd-sql/src/bridge.rs:1094`（authorizer 注释）与 `bridge.rs:4150`（**断言拒绝** `CREATE TEMP TABLE x AS SELECT 1` 的测试）。
   `artifacts/mdd-033/preflight/README.md` 也自述"仍验证"清单包含"原生 MDD catalog/cursor"。
3. **SQL 侧不支持多语句或任何 DDL/DML**：
   - `dialects/ast.rs:1204-1211`：`statements.len() != 1` → `SQL_REQUIRES_ONE_STATEMENT`
   - `dialects/ast.rs:1213-1215`：非 `Statement::Query` → `SQL_STATEMENT_NOT_READ_ONLY_QUERY`
   - `bridge.rs:929-931`：`!statement.readonly()` → `SQLITE_STATEMENT_NOT_READONLY`
   - `bridge.rs:1109-1111`：`prepare` 预检同样拒绝
   - 测试钉死：`bridge.rs:4144-4157`（`SELECT 1; SELECT 2` 与 `CREATE TEMP TABLE ...` 均 `InvalidArgument`）
4. **`SqlResult` 无分页字段**：`bridge.rs:59-64` 只有 `columns/rows/calculation_complete/profiles_admitted/sqlite_version/optimizer/required_*`；
   `grep "next_offset|more_available|total_rows" crates/mdd-sql/src/bridge.rs` 只命中 `:773` 一处错误详情。
5. **`TerminalBuilder::page` 无生产调用**：`grep "\.page(" crates/` 仅命中 `mdd-types/src/result.rs:507,641,797` 的单元测试。
   生产路径只有 `succeed`/`fail`（`executor.rs:1538,1688,2057` 等）。
6. **`mdd-session` 不依赖 `mdd-query`/`mdd-facts`**：`crates/mdd-session/Cargo.toml` 只有 `mdd-types`、`mdd-input`、`serde`。
   反向依赖是 `mdd-query → mdd-session`（`budget.rs:2` 用 `QueryCancellation`）与 `mdd-sql → mdd-session`（`runtime.rs`）。
   因此 TEMP catalog 若要持有关系 schema/行，**必须新引入依赖或上移到 mdd-query/mdd-sql** —— 这是必须先定的架构决策。
7. **typed IR 的 `Limit` 明确不是响应分页**：`executor.rs:536-539` 的 node 描述字符串为
   `"relation_limit_not_response_paging"`。
8. **`Streaming` 模式仍是全量物化**：`executor.rs:1354-1361`，`ExecutionMode::Streaming` 走 `collect(...)`
   后一次性装入 `Vec<Row>`；只有 `execute_into`（`:2334`）经 `BoundedSender` 分批发。真正的页级流式只在
   `execute_into` 的 sender 路径上存在。
9. **无 page size / offset 参数入口**：`grep "page_size|pagination|max_pages" crates/` 只命中
   `mdd-cli/src/main.rs:74` 的 `"pagination_modes":[]`（声明为空）与 `dialects/ast.rs:2301,3613` 的注释。

---

## 2. acceptance 五条逐条差距

| # | 验收要求 | 现状 | 差距 |
|---|---|---|---|
| 1 | cursor 同时绑定 snapshot、session、catalog_epoch、query 和 schema；**跨作用域或旧代次明确失败** | 绑定字段齐全（`lib.rs:1150-1183`）；`validate_cursor` 逐项比对（`:1287-1301`）；测试 `computation_delivery_and_catalog_generations_remain_distinct`（`:1553-1584`）验证旧 epoch 游标对新 query 失败 | **基本成立**。缺：worker generation（`docs/02_ARCHITECTURE_AND_CONTRACTS.md:398` 要求 `worker generation`）；`QueryBinding` 只有 `request_key/schema_id/semantic_version`（`lib.rs:287-291`），无参数类型与 CST/AST 指纹（`:253` 计划缓存键要求） |
| 2 | catalog_epoch 用十进制 u64 字符串；**不能把运行中 cursor 暗中迁移到新 TEMP 定义** | `DecimalU64` 序列化已严格（`mdd-types/src/lib.rs:98-118`）；epoch 在 query prepare 时冻结，游标校验比对 query 的 epoch（`lib.rs:1173,1291`） | 序号本身成立。但"迁移到新 TEMP 定义"场景**无法构造**，因为没有 TEMP 定义实体；此条目前是**空转通过**（vacuous） |
| 3 | 同 SQL、相同 row count/schema 的来源变化**仍不能拼接混合页面** | 无页面拼接代码；`TerminalBuilder` 的 `page` 只校验 `page_rows <= emitted`（`result.rs:161-168`），不校验来源 | **完全缺失**。缺少：页 token 携带 `snapshot_content_key`/scope、跨页 schema_id 与 total 一致性校验（HostLab 参考实现已有该逻辑，见 `conformance/corpus/hostlab/source-8782f43/analysis_paging.py:165` 的 `query_page_identity_or_limit_mismatch` 与 `:171` 的 `query_schema_or_total_changed`） |
| 4 | 兼容 offset 重执行的**成本与稳定性边界明确**；原生快照 cursor **不被伪装**为该行为 | 无兼容 offset 实现；`SqlResult` 无 offset/next_offset；`VTB_POLICY` 四项全 false（`virtual_tables/mod.rs:71-76`），LIMIT/OFFSET 全由 SQLite 处理 | **完全缺失**。需新增：`offset`/`limit` 请求参数、重执行计数与成本上限、`more_available` 由 `limit+1` lookahead 判定（`docs/02_ARCHITECTURE_AND_CONTRACTS.md:404`），以及在 capabilities 中区分两种模式（`:257`） |
| 5 | TEMP 自有 catalog 遵循已验证 profile；**循环、IF NOT EXISTS、DROP、重定义、跨会话隔离**有准确错误 | 无 catalog。仅 `artifacts/mdd-033/preflight/README.md` 记录了 A0/A1 的**参考引擎行为**（IF NOT EXISTS 语义、跨种类替换、forward 引用拒绝、错误类别 `invalid_query`/`stage=execute_sql`） | **完全缺失**。参考行为已有独立证据可作 oracle，但自身实现为零 |

**量化**：5 条验收中，1 条基本成立但有 2 个字段缺口；1 条是空转；3 条完全缺失。

---

## 3. 目标产物差距

| 产物（backlog outputs） | 状态 |
|---|---|
| `crates/mdd-session/src/catalog.rs` | **不存在** |
| `crates/mdd-session/src/cursors.rs` | **不存在** |
| `conformance/session/catalog-and-paging.json` | **不存在**（`conformance/session/` 只有 `lifetime-cases.json`，task 标记 `MDD-014`，`not_qualified` 明确列出 MCP/真实 DEX/进程树隔离等） |
| `artifacts/mdd-033/paging-isolation.json` | **不存在**（`artifacts/mdd-033/` 只有 `preflight/`：A0/A1 TEMP 政策观测脚本与回读，2026-10-28） |

已有可复用资产：`artifacts/mdd-033/preflight/policy-readback.json` 与
`artifacts/mdd-033/preflight/A0/A1.observations.json`（README 自述两版各 70 条 SQL / 103 个工具调用，
`verify_policy.py` 在 `-O` 下 exit0）。这些是**参考引擎行为证据**，可直接作为 MDD-033 的独立 oracle 输入，
但不能替代本引擎证据。

---

## 4. 必须解决的三个架构阻塞点

### B1. TEMP catalog 的归属层（依赖方向冲突）

- `mdd-session` 只依赖 `mdd-types` + `mdd-input`（`Cargo.toml`）。
- 但 TEMP 定义需要（a）解析后的查询定义与依赖图、（b）关系 schema、（c）执行。
  这三者目前都在 `mdd-sql`（SQL 桥）与 `mdd-query`（typed IR），而二者**依赖** `mdd-session`。
- 若把 catalog 放进 `mdd-session/src/catalog.rs`（backlog 指定路径），`mdd-session` 必须获取
  SQL/IR 类型，形成循环依赖。
- 可行路径（需主代理决策，**不得由子代理自行新增生产依赖**）：
  1. `mdd-session` 只定义与解析无关的 catalog 抽象（`TempDefinitionId`、`catalog_epoch`、
     `dependencies: Vec<String>`、`definition_hash`），真实 AST/关系 schema 由 `mdd-sql`/`mdd-query`
     以泛型或回调解入；或
  2. 把 `catalog.rs` 放在 `mdd-sql`（偏离 backlog 路径，需显式记录）；或
  3. 新建 `mdd-catalog` crate（新增 crate，需授权）。
- **这条不解决，MDD-033 无法开始编码。**

### B2. 分页在哪一层产生

- 原生 cursor 语义要求"一次执行 + spool + 逐页送出"（`docs/02_ARCHITECTURE_AND_CONTRACTS.md:400-406`）。
- 现状：`mdd-query::execute` 返回全量 `QueryOutput`（`executor.rs:1377-1397`）；
  `execute_into` 才有 BoundedSender 分批，且要求 `RuntimeBudget`（`:2340-2346`）。
- `mdd-sql::SqlResult` 持有全量 `rows: Vec<Vec<SqlValue>>`（`bridge.rs:63`），无游标。
- 因此"原生快照 cursor"只能建在 `mdd-query::execute_into` 的 bound 队列之上，或需要给 `mdd-sql`
  增加一个真正的流式结果 API。当前 `SqlBridge` 每次 `execute_inner` 新建内存连接
  （`bridge.rs:786`），**无法跨请求复用**，也就无法承载"一次执行多次取页"。

### B3. 兼容 offset 与原生 cursor 的命名隔离

- 两层必须在 capabilities 中分别可见（`docs/02_ARCHITECTURE_AND_CONTRACTS.md:257`；
  `mdd-cli/src/main.rs:74` 现为 `"pagination_modes":[]`）。
- 二者不能共用一个 token。当前 `CursorHandle` 是唯一的游标类型（`lib.rs:36`），无模式标记。
- 建议：`CursorMode::{NativeSnapshot, CompatOffset}` 显式字段 + 分模式错误码；兼容 offset 每次重执行
  必须能观察到新 `catalog_epoch`。

---

## 5. 建议采用的可测量判据（供 MDD-033 落地时直接引用）

| 判据 | 可测形式 |
|---|---|
| 旧代次拒绝 | 已有测试形态可扩展：`advance_catalog` 后旧 cursor 用新 query 调 `validate_cursor` 必须 `InvalidCursor`（`lib.rs:1553-1584` 已示范） |
| epoch 字符串 | `serde_json::to_value(DecimalU64(u64::MAX))` 必须是 `"18446744073709551615"`；`DecimalU64(1)` 反序列化 `"01"` 必须失败（`mdd-types/src/lib.rs:106-117`） |
| 混合页拒绝 | 两次请求间改变 scope/来源但保持 SQL 与 schema，页合并必须报错；HostLab 参考错误名 `query_page_identity_or_limit_mismatch`（`analysis_paging.py:165`）、`query_schema_or_total_changed`（`:171`） |
| 不伪装 | 原生 cursor 的 `next_cursor` 不得由 offset 重执行产生；兼容 offset 响应必须标 `mode` 且失败时不得返回 `next_cursor` |
| TEMP 语义 | 直接以 `artifacts/mdd-033/preflight/README.md` 的 7 行行为表为 oracle（IF NOT EXISTS / 跨种类替换 / forward 引用 / DROP 种类不符 / 错误 kind） |

---

## 6. 本节结论

- 骨架可用部分：句柄与绑定体系（`mdd-session`）、`DecimalU64` 字符串契约（`mdd-types`）、终态与预算（`cancellation.rs`/`budget.rs`）。
- 缺口量与性质：**acceptance 5 条 → 1 条基本成立（含 2 个字段缺口）、1 条空转、3 条零实现**；
  4 个目标产物 → **3 个不存在**，1 个（`artifacts/mdd-033/paging-isolation.json`）的目录只含参考引擎前置证据。
- 最大风险：**依赖方向冲突（B1）**使 `mdd-session/src/catalog.rs` 不能按 backlog 指定路径直接落地；
  这属于架构决策，必须先由主代理定夺，否则任何实现都会返工。
