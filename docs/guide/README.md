# 接入指南

本指南面向希望将 MeguvizDexDash 作为 Rust 库、命令行工具、MCP 服务或 FFI 组件接入的开发者。当前仍为**功能预览版（未签发正式 profile）**：`capabilities` 中所有 profile 的 `admitted` 均为 `false`，不得宣称已具备替代生产 HostLab DexSQL 的资格。

本文说明已实现接口的调用方式、五种消费形态的能力边界及多轴完整性校验规则。

## 1 能力边界与交付状态

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| 输入捕获与来源身份 | 可用 | 同一次捕获内字节不可变；源文件后续改写不影响已打开快照 |
| APK/ZIP 清点与解压 | 可用 | 支持单磁盘 ZIP32/ZIP64、STORE/DEFLATE 与重复物理成员；明确拒绝 036/041、多卷与加密归档 |
| DEX header 与结构校验 | 可用 | 支持 035/037/038/039/040；计算 Adler32 与 DEX 原生 SHA-1，来源身份采用 SHA-256 |
| 字符串 / 类型 / 原型 / 定义 | 可用 | 保留原始 MUTF-8 与 UTF-16 代码单元，不做有损替换 |
| 代码布局 / 指令 / 异常表 | 可用 | 不执行 ART 类型流验证，也不推断运行时虚方法分派 |
| 引用位点 | 可用 | 保留调用者、PC、操作数、opcode 与重复出现次数 |
| 注解 / encoded values / Signature | 可用 | 仅当编码槽数与原型参数数一致时将参数位置标为已知，否则标记为 `unknown` |
| 原始代码 / 资源 / Manifest 指纹 | 可用 | 与方法体和资源读取共享同一快照 `Arc` |
| 类型化查询 IR 与执行器 | 可用 | 已实现预算控制、取消及终态多轴完整性上报 |
| SQLite 兼容桥 | **未签发 profile** | 支持 `native-v1`、`dexsql-0.1.0`、`dexsql-0.1.1`，方言等价仍在逐项验证 |
| Smali / MCP / C ABI & Python / 桌面 | **功能预览（未签发正式 profile）** | `decode`（Smali）、`meguvizdexdash mcp`（12 工具）、`mdd-ffi`（`include/mdd.h`）+ `python/mdd` 与 `apps/desktop`（Tauri 2）均可运行，仍处于预览阶段 |

## 2 快速开始：CLI 与 MCP

```text
cargo build --locked -p mdd-cli
cargo run --locked -p mdd-cli -- capabilities
cargo run --locked -p mdd-cli -- inspect-apk app.apk
```

- `capabilities` 输出 `mdd.capabilities.v1` 格式的能力清单与生效限额。
- `inspect-dex` / `inspect-apk` 仅扫描归档成员清单与 DEX header/map 层，输出中 `full_dex_validation_complete=false` 属于**预期值**，而非错误。
- 需要单数据集逐行交互流或接入外部 AI 工具时，分别使用 `meguvizdexdash serve --input app.apk` 与 `meguvizdexdash mcp --dialect dexsql-0.1.0`（`mcp` 拒绝 `native-v1`）。

## 3 快速开始：Rust 一站式门面

```rust
use mdd_facts::session::FactsSession;

let session = FactsSession::open("app.apk")?;
for index in 0..session.dex_count() {
    let definitions = session.definitions(index)?;   // 需要时自动构建 metadata
    let references = session.references(index)?;     // 需要时自动复用 definitions 与 code
    println!("{}", definitions.definition_coverage() as u8);
}
```

`FactsSession` 仅做按需组合，不改变底层完整性语义：

- `open` 只捕获输入并清点归档成员，**不会**提前构建全部关系，也不会绕过各层的限额检查。
- 同一 DEX 索引下每层只构建一次，返回同一个 `Arc`。`definitions()` 共享 `metadata` 的 `Arc`；`references()` 与 `annotations()` 也均共享已缓存的 `definitions` / `code` `Arc`，不会深拷贝整张大表。
- 遇到 `Completeness::Partial` 或 `Completeness::Unknown` 时**不会**折叠为空成功，仍交由调用方判断该层是否可用。
- 输入类型由 `InputKind::detect` 依据文件魔数判定，不依赖文件扩展名猜测。

可运行示例：`cargo run --locked -p mdd-facts --example quickstart -- app.apk`

## 4 分层 API（精细控制构建与预算时使用）

门面内部依次调用下列分层构造器，语义与限额一一对应：

```rust
let snapshot  = Snapshot::capture(&[InputSpec { path, kind, expected_sha256 }], CaptureLimits::default())?;
let inventory = ArchiveInventory::build(&snapshot.sources()[0], InventoryPolicy::default(), ArchiveLimits::default())?;
for index in 0..inventory.selected_dexes().len() {
    let metadata    = MetadataFacts::build(&snapshot, &inventory, index, StringLimits::default())?;
    let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
    let code        = CodeFacts::build_all_code_items(&snapshot, &inventory, index, CodeLimits::default())?;
    let references  = ReferenceFacts::build(definitions, code, ReferenceLimits::default())?;
}
```

层间依赖顺序为 `metadata -> definitions -> {annotations, references}`；`code` 仅依赖输入快照与归档清点，可与 `definitions` 并行分叉构建。每一步均要求前驱层满足 `coverage == Complete`，否则返回 `INCOMPLETE_FACTS` 而非空结果。

## 5 错误码与多轴完整性

引擎错误统一使用 `MddError { code, stage, message, retryable, details }`，`ErrorCode` 的 `Display` 输出与 JSON 中的 `SCREAMING_SNAKE_CASE` 命名严格一致：

| 错误码 | 含义 | 处置建议 |
| --- | --- | --- |
| `INVALID_INPUT` | 输入字节不合法或损坏 | 不要重试；保留并排查原始字节 |
| `INCOMPLETE_FACTS` | 所需前置事实层未完整构建 | 不能用空列表补齐，须先修复或补齐对应层 |
| `QUOTA_EXCEEDED` | 超出逻辑或缓冲预算 | 按需调整对应 `*Limits` 或缩小查询范围，不要屏蔽检查 |
| `DEADLINE_EXCEEDED` / `CANCELLED` | 超出总期限或被取消 | 不是流正常结束（EOF），不可当作完整结果 |
| `UNSUPPORTED_CAPABILITY` / `UNSUPPORTED_QUERY` | 当前版本或方言不支持 | 走显式拒绝或回退逻辑，禁止静默绕过 |

**完整性多轴必须分开检查**：`operation_status`、`coverage.input` / `coverage.facts`、`execution.complete` 以及分页标志（`more_available` / `truncated` / `next_cursor` / `total_rows_exact`）相互独立。任何部分覆盖、超时、截断或未读完的分页，均不能视作完整成功。

## 6 性能与所有权要点

- **复用快照**：同一输入仅捕获一次，后续各层共享同一份不可变 `Arc<[u8]>`，避免重复计算 SHA-256 与内存翻倍。
- **按需取层**：仅构建业务真正需要的层；例如只需字符串或类型表时只取 `metadata`，无需触发 `code` 与 `references`。
- **门面与分层对比**：`FactsSession` 会缓存已构建层的 `Arc`，重复读取零重建成本；若某次任务对单次访问极其敏感、只读一次且不复用，可直接调分层 API 省去门面内的互斥锁与查找开销。
- **逻辑额度边界**：`FactsLimits`、`ArchiveLimits` 等均为引擎内部逻辑与缓冲约束，不代表操作系统层面的硬 RSS 上限。

## 7 证据核验与常见问题

仓库内可复现证据保存在 `artifacts/<task>/<场景>/<run>/record.json`（含执行命令、退出码、输出摘要与源码哈希）。运行单个任务的复验脚本示例：

```text
python artifacts/mdd-022/reproduce.py
```

### 常见问题

- **为什么不返回 `anyhow` 或 `Box<dyn Error>`？** 调用方需要根据稳定的错误码（如区分 `QUOTA_EXCEEDED`、`INCOMPLETE_FACTS` 与 `INVALID_INPUT`）编写明确的分支处置逻辑，非结构化文本错误无法可靠分支。
- **为什么 `Partial` 不算成功？** 完整性只能由全部交付路径与实际检查共同证明，不能仅因返回结果非空或未报错就默认成功。
- **为什么函数返回 `Arc<Facts>` 而不是 `&Facts`？** 事实层常被多个查询、注解或引用消费者并发共享，`Arc` 既能确保生命周期安全，也能避免大表深拷贝。
- **可以绕开快照自己读文件解析吗？** 不可以。字节捕获、SQL 查询、Smali 反汇编、Manifest 与资源指纹必须绑定同一个快照，才能保证来源身份可追溯且不会读到外部中途修改的混合内容。
