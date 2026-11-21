# MeguvizDexDash API 与模块速查

## 1. 工作区结构与工具链基线

- **版本与语言**：`0.1.0-dev`（`edition = "2024"`、`rust-version = "1.99"`、`publish = false`）
- **固定工具链**：`rust-toolchain.toml` 锁定 Rust **`1.99.0`**（`profile = "minimal"`，`components = ["clippy", "rustfmt"]`）
- **Profile 状态**：`capabilities` 中所有 profile（如 `mdd-native-v1`、`mdd-header-inspection-dev-v1`）当前 `admitted` 均为 `false`，仅用于独立分析与功能预览，不可替代已认证的 HostLab DexSQL 生产环境。

### 核心 Workspace Crates（13 个核心 + 2 个辅助工具）

| Crate | 职责定位 |
| --- | --- |
| `mdd-types` | 公共错误码 `ErrorCode`、`MddError`、`Completeness`、`DecimalU64`、`ResultEnvelope` 契约校验 |
| `mdd-input` | 输入捕获（`Snapshot`）、ZIP32/ZIP64 多成员清点（`ArchiveInventory`）、Manifest AXML 解析与原始资源读取 |
| `mdd-dex` | 标准小端 DEX（035/037/038/039/040）header、字符串、类型、原型、定义、指令与注解解码（显式拒绝 036/041） |
| `mdd-facts` | 分层事实对象与一站式门面 `FactsSession`，含 `MetadataFacts`、`DefinitionFacts`、`CodeFacts`、`ReferenceFacts`、`AnnotationFacts`、Smali 渲染及指纹 |
| `mdd-session` | 快照/会话/查询/游标/批次生命周期注册表（`Lifecycle`、`ResourceLimits`、`BatchHandle`） |
| `mdd-worker` | 直接子进程监督器（`Supervisor`），处理 stdout 限额、总期限与管道终止传播 |
| `mdd-query` | 版本化类型化关系查询 IR（`mdd.typed-query.v1`）与预算受控执行器 |
| `mdd-sql` | 只读 SQLite 虚拟表桥（`SqlBridge`、`PreparedSql`、`SqlLimits`），支持 `native-v1`、`dexsql-0.1.0`、`dexsql-0.1.1` |
| `mdd-service` | CLI 与 MCP 共用的数据集与单语句运行适配层（`Dataset`、`Dialect`、`RunOptions`） |
| `mdd-wire` | 本地 worker 通道的帧协商与类型化批次状态机（`mdd-wire/1`） |
| `mdd-cli` | 命令行二进制 `meguvizdexdash`（含 `query`、`serve` 与 `mcp` 入口） |
| `mdd-mcp` | 逐行 JSON-RPC 2.0 MCP 服务端实现（内置 12 个工具与参数校验） |
| `mdd-ffi` | C ABI 1.0 动态/静态库（`lib` name `mdd_ffi`，头文件 `include/mdd.h`） |

独立工作区：`apps/desktop`（`mdd-desktop`，Tauri `2.12.6`），通过子进程调用 `meguvizdexdash mcp`，不直接链接上述 `mdd-*` crate。

## 2. 五种消费形态速查

### 2.1 Rust 库接入（`mdd-facts`）

- **一站式门面 `mdd_facts::session::FactsSession`**：
  - 打开：`FactsSession::open(path)`、`FactsSession::open_with(path, FactsLimits)`、`FactsSession::open_spec(InputSpec, FactsLimits)`。
  - 查询：`dex_count()`、`occurrence(index)`、`metadata(index)`、`definitions(index)`、`code(index)`、`references(index)`、`annotations(index)`。
  - 缓存与共享：同一 DEX 索引下每层只构建一次并返回同一个 `Arc`；`definitions`、`references` 与 `annotations` 共享前驱层的 `Arc`，不深拷贝。
- **精细分层构造器**：
  1. `Snapshot::capture(&[InputSpec], CaptureLimits)`
  2. `ArchiveInventory::build(&snapshot.sources()[0], InventoryPolicy::default(), ArchiveLimits)`
  3. `MetadataFacts::build(&snapshot, &inventory, index, StringLimits)`
  4. `DefinitionFacts::build` / `build_arc` 与 `CodeFacts::build_all_code_items`
  5. `ReferenceFacts::build` / `build_arc` 与 `AnnotationFacts::build` / `build_arc`

### 2.2 CLI 命令行（`meguvizdexdash`）

- `meguvizdexdash version` / `--version`：输出版本信息
- `meguvizdexdash capabilities`：输出 `mdd.capabilities.v1` JSON（含有效限额与 `admitted: false` 状态）
- `meguvizdexdash inspect-dex PATH...` / `inspect-apk PATH...`：检查成员清单与 DEX header（只覆盖 `inventory` 与 `dex_header` 层）
- `meguvizdexdash query --input PATH... (--sql TEXT | --sql-file PATH|-) [--dialect native-v1|dexsql-0.1.0|dexsql-0.1.1] [--format jsonl|text] [--batch-rows N] [--max-rows N] [--deadline-ms N] [--sql-max-steps N --sql-max-scanned-rows N --sql-max-result-rows N]`
- `meguvizdexdash serve --input PATH... [--dialect NAME] [--deadline-ms N] [SQL BUDGETS]`：启动逐行 JSON 流协议（`mdd.cli-stream.v1`）工作进程

### 2.3 MCP 服务（`meguvizdexdash mcp`）

启动命令：`meguvizdexdash mcp [--dialect dexsql-0.1.0|dexsql-0.1.1] [--timeout-ms N] [--max-datasets N] [--max-total-input-bytes N] [--max-result-bytes N] [SQL BUDGETS]`。注意 `mcp` 默认使用 `dexsql-0.1.0`，并明确拒绝 `native-v1`。

内置 12 个 MCP 工具（JSON-RPC 2.0 逐行收发，协议版本支持 `2025-06-18`、`2025-03-26`、`2024-11-05`）：

| 类别 | 工具名 | 核心职责 |
| --- | --- | --- |
| 数据集生命周期 | `open_dataset`、`list_datasets`、`close_dataset` | 打开 1~64 个输入路径（保留资源-only APK 的 `has_dex=false` 状态）、查询配额与释放 |
| SQL 查询 | `list_tables`、`describe_table`、`query` | 列举与描述表结构，运行只读 SQL 语句与窗口分页 |
| Smali 反汇编 | `decode` | 按方法描述符、`file_id + method_idx` 或类描述符输出 `summary`/`smali`/`context` 分页文本 |
| Manifest 解析 | `get_manifest`、`get_manifest_components` | 读取摘要、权限分页或完整 XML 文本，分页列举 `activity`/`service`/`receiver`/`provider` 等组件 |
| 资源清点与 ARSC | `list_resource_files`、`read_resource`、`query_resources` | 清点归档条目（保留同名条目）、按名称读取二进制 XML/文本/Hex、查询 `resources.arsc` |

### 2.4 C ABI（`include/mdd.h`）与 Python SDK（`python/mdd`）

- **C ABI 1.0（`mdd_ffi`）**：
  - 协商与能力：`mdd_abi_negotiate_v1(1, 0, ...)`、`mdd_capabilities_json_v1`
  - 快照与会话：`mdd_open_snapshot_v1`、`mdd_snapshot_manifest_json_v1`、`mdd_snapshot_close_v1`、`mdd_snapshot_release`、`mdd_open_session_v1`、`mdd_session_close_v1`、`mdd_session_release`
  - 流式查询：`mdd_prepare_query_v1`、`mdd_start_query_v1`、`mdd_query_next_v1(query, demand_rows, &event)`、`mdd_event_kind_v1`（`MDD_EVENT_BATCH = 1` / `MDD_EVENT_TERMINAL = 2`）、`mdd_event_batch_v1`、`mdd_batch_ack_v1`、`mdd_batch_release`、`mdd_event_terminal_json_v1`、`mdd_query_cancel_v1`
- **Python SDK（纯标准库，位于 `python/mdd/`）**：
  - 进程内库模式：`mdd.open_snapshot([inputs])` -> `snapshot.open_session()` -> `session.execute(sql)` / `session.query(sql)` -> `mdd.is_complete(terminal)`
  - 隔离 worker 模式：`mdd.Worker([inputs], dialect=...)`（底层启动 `meguvizdexdash serve`）-> `worker.execute(sql)` / `worker.query(sql)`

### 2.5 桌面工作台（`apps/desktop`）

独立 Tauri 2 工作区，在前端纯静态 ES 模块与后端子进程监督（`src/engine.rs`）之间封装了 SQL 分页、完整导出行数对账（`src/export.rs`）、两输入集对比（`src/diff.rs`）、Smali 查看与 Manifest/资源浏览。窗口本身无文件/网络/shell 直连权限，所有查询通过 `meguvizdexdash mcp` 完成。

## 3. 错误码与多轴完整性字段

`ErrorCode`（JSON 输出均为 `SCREAMING_SNAKE_CASE`）：`UNAVAILABLE_BACKEND`、`UNSUPPORTED_CAPABILITY`、`UNSUPPORTED_QUERY`、`INVALID_ARGUMENT`、`INVALID_INPUT`、`PARTIAL_INPUT`、`INCOMPLETE_FACTS`、`SOURCE_CHANGED`、`AMBIGUOUS_ENTITY`、`STALE_CACHE`、`CACHE_CORRUPT`、`QUOTA_EXCEEDED`、`DEADLINE_EXCEEDED`、`CANCELLED`、`SNAPSHOT_CLOSED`、`INVALID_CURSOR`、`INTERNAL_FAULT`、`WORKER_LOST`。

`ResultEnvelope::is_complete_result()` 要求以下条件**同时**为真：`operation_status == Ok`、`coverage.input == Complete`、`coverage.facts == Complete`、无阻塞 `warnings`、`execution.complete == true`、`!response.truncated`、`!response.more_available`、`response.next_cursor.is_none()`、`response.total_rows_exact` 且 `total_rows == Some(emitted_rows)`。
