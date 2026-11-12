# 接入指南

面向要把 MeguvizDexDash 作为库或 CLI 使用的开发者。当前是**未取得产品资格的开发版本**：
`capabilities` 中所有 profile 的 `admitted` 均为 `false`，不能用本引擎替代 HostLab DexSQL。

本指南只描述**已经实现并通过本机限定验收**的 API 形态。未交付的能力（SQL 兼容 profile、
Smali、MCP、FFI、桌面）在文中明确标注。

## 1 能力边界（先看这个）

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| 输入捕获与来源身份 | 可用 | 同一次捕获内字节不可变；源文件后续改写不影响快照 |
| APK/ZIP 清点与解压 | 可用 | ZIP32/ZIP64、STORE/DEFLATE、重复物理成员；036/041/多卷/加密明确拒绝 |
| DEX header/结构校验 | 可用 | 035/037/038/039/040；Adler32 与 DEX 原生 SHA-1，来源身份用 SHA-256 |
| 字符串/类型/原型/定义 | 可用 | 保留 UTF-16 单元与原始 MUTF-8，不做有损投影 |
| 代码布局/指令/异常表 | 可用 | 不做 ART 类型流验证，不推断运行时分派 |
| 引用位点 | 可用 | 保留 caller、PC、operand、opcode 与重复出现 |
| 注解/encoded values/Signature | 可用 | 参数位置只在编码槽数与原型参数数一致时标为已知，否则为 unknown |
| 原始代码/资源/Manifest 指纹 | 可用 | 与方法体和资源共用同一快照 Arc |
| 类型化查询 IR 与执行器 | 可用 | 预算、取消、终态完整性已实现 |
| SQLite 兼容桥 | **未准入** | 方言等价仍在逐项验证，profile 未签发 |
| Smali / MCP / C ABI / 桌面 | **未交付** | — |

## 2 快速开始：CLI

```text
cargo build --locked -p mdd-cli
cargo run --locked -p mdd-cli -- capabilities
cargo run --locked -p mdd-cli -- inspect-apk app.apk
```

`capabilities` 输出 JSON 能力清单与生效限额。`inspect-dex` / `inspect-apk` 只覆盖成员清单
与 header/map 层，输出中 `full_dex_validation_complete=false` 是**预期值**，不是错误。

## 3 快速开始：Rust 一站式门面

```rust
use mdd_facts::session::FactsSession;

let session = FactsSession::open("app.apk")?;
for index in 0..session.dex_count() {
    let definitions = session.definitions(index)?;   // 需要时自动构建 metadata
    let references = session.references(index)?;     // 需要时自动构建 definitions 与 code
    println!("{}", definitions.definition_coverage() as u8);
}
```

`FactsSession` 只做组合，不改变任何完整性判定：

- `open` 只捕获输入并校验清点，**不会**预建全部关系，因此不会绕过各层限额。
- 同一 DEX 的同层只构建一次，返回同一个 `Arc`。`references()` 与已缓存的 definitions/code
  共享 `Arc`，**不深拷贝**；`annotations()` 目前仍需要一份自有 `DefinitionFacts`（NewPipe 上
  约 66 ms 克隆），因为它必须持有可独立变异的定义。
- `Completeness::Partial`/`Unknown` **不会**被折叠成空成功，由调用方决定该层是否可用。
- 输入类型由 `InputKind::detect` 按 magic 判定，不再依赖扩展名猜测。

可运行示例：`cargo run -p mdd-facts --example quickstart -- app.apk`

## 4 分层 API（需要精细控制时用）

门面背后就是这些构造器，语义与限额一一对应：

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

依赖顺序：`metadata → definitions → {annotations, references}`，`code` 只依赖输入与清点，
可与 `definitions` 分叉。每一步都要求前一层 `coverage == Complete`，否则返回
`INCOMPLETE_FACTS` 而不是空结果。

## 5 错误与完整性

`MddError { code, stage, message, retryable, details }`，`ErrorCode` 实现了 `Display`，
输出与 JSON 中的 SCREAMING_SNAKE_CASE 完全一致。

必记的几条：

| 错误码 | 含义 | 处置 |
| --- | --- | --- |
| `INVALID_INPUT` | 输入字节不合规 | 不要重试；记录原字节 |
| `INCOMPLETE_FACTS` | 所需层未完整 | 不能用空值补齐，必须补齐该层 |
| `QUOTA_EXCEEDED` | 超出逻辑额度 | 调整对应 `*Limits`，不要关闭检查 |
| `DEADLINE_EXCEEDED` / `CANCELLED` | 预算期限/取消 | 不是 EOF，不能当完整结果 |
| `UNSUPPORTED_CAPABILITY` / `UNSUPPORTED_QUERY` | 未获资格 | 按显式等价策略处理，不可静默 fallback |

**完整性三态必须分开看**：`operation_status`、`input/facts` 的 coverage、
`execution.complete`、`more_available/truncated/next_cursor` 是彼此独立的轴。
任何 partial、超时、截断、未消费页都不能变成空成功。

## 6 性能要点

- **重用快照**：同一输入只捕获一次，之后所有层都引用同一 `Arc<[u8]>`。重复捕获会重复
  SHA-256 与内存占用。
- **按需取层**：只请求真正需要的层。`references` 需要 `code` 与 `definitions`，
  而 `metadata` 单独就够做字符串/类型查询。
- **门面 vs 分阶段**：`FactsSession` 缓存每层，重复取用不重建。但**首次**构建某一层的成本
  与手工分阶段相同（`references()` 现在通过 `Arc` 共享 definitions/code，无深拷贝），
  而 `annotations()` 会额外克隆一份 definitions。若同一层要反复取用，用门面；若只取一次且
  对延迟极敏感，直接用分阶段 API 可省去门面本身的查找与锁开销。
- **层级限额是逻辑额度，不是 RSS 上限**：`max_build_memory_bytes` 等字段不代表硬内存保证。

## 7 证据与可复验性

任何"已通过"的结论都必须绑定具体源码状态。仓库内证据的基本形态是
`artifacts/<task>/<场景>/<run>/record.json`，含实际命令、exit code、输出摘要与源码哈希。

复验单个任务请使用其自带脚本，例如：

```text
python artifacts/mdd-022/reproduce.py
```

脚本会把本次运行的命令记录写入新的 `run_id` 目录，不会覆盖历史证据。

## 8 常见问题

**为什么不返回 `anyhow`/`Box<dyn Error>`？**
调用方需要按错误码分支处理（重试、降级、终止），字符串错误无法可靠区分。

**为什么 partial 不算成功？**
历史上"未消费却报完整"被判定为严重缺陷。完整性必须由交付路径证明，不能由结果非空推断。

**为什么函数返回 `Arc<Facts>` 而不是 `&Facts`？**
事实对象被多个消费方（查询、注解、引用）共享；`Arc` 保证生命周期安全且避免深拷贝。

**可以直接读文件自己解析吗？**
不可以。捕获字节、查询、Smali、资源与指纹必须使用同一快照，否则来源身份无法证明。
