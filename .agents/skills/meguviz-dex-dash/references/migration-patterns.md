# MeguvizDexDash 迁移对照与排障

## 1. 消费形态选型与旧工具迁移对照

### 1.1 替换临时 `zipfile` + `dexdump` / `apktool` 拼装脚本

旧方式常见问题：不同脚本各自打开 APK 文件，遇到同名 ZIP 条目或重复 DEX 时互相覆盖，且一旦出现截断或局部解码失败仍返回不完整列表。

迁移建议：
- **Python 宿主（需要异常隔离）**：使用 `mdd.Worker`（底层运行 `meguvizdexdash serve`），同一份输入的快照在子进程内捕获，进程崩溃时明确抛出 `WorkerLost` 而非吞掉半截数据。
- **Python 宿主（进程内直接调用）**：先用 `cargo build --locked -p mdd-ffi` 编译共享库，再通过 `mdd.open_snapshot` 打开不可变快照。

```python
import mdd

# 1) 进程内库模式：同一份文件输入两次仍保留两个独立 dex_occurrence_id
with mdd.open_snapshot(["app.apk"]) as snapshot, snapshot.open_session() as session:
    result = session.execute(
        "SELECT dex_occurrence_id, class_def_idx, descriptor "
        "FROM native_classes ORDER BY dex_occurrence_id, class_def_idx"
    )
    assert result.is_complete  # 验证 operation_status、coverage、execution 与游标
    for row in result.rows:
        print(row)

# 2) 隔离 worker 模式：崩溃、超时或放弃读取会明确终止并报错
with mdd.Worker(["app.apk"], dialect="native-v1") as worker:
    res = worker.execute("SELECT COUNT(*) FROM native_classes")
    assert res.is_complete
```

### 1.2 从手工多阶段拼接迁移至 `FactsSession` 或精细分层 API

在 Rust 项目中，按需求选择接入粒度：
- **同一输入需要读取多层事实时**：优先使用 `mdd_facts::session::FactsSession`。各层按需首次构建并缓存 `Arc`，跨层调用（如 `definitions`、`references`、`annotations`）自动共享前驱层，不会重复扫描或克隆底层大表。
- **单次只取极少数信息且对锁查找极敏感时**：直接使用 `Snapshot::capture` -> `ArchiveInventory::build` -> `MetadataFacts::build` 等分层构造器。

```rust
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{DefinitionFacts, MetadataFacts};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{Completeness, ErrorCode, MddError, MddResult};
use std::path::PathBuf;

fn load_definitions(path: PathBuf) -> MddResult<()> {
    let kind = InputKind::detect(&path)?;
    let snapshot = Snapshot::capture(&[InputSpec { path, kind, expected_sha256: None }], CaptureLimits::default())?;
    let inventory = ArchiveInventory::build(&snapshot.sources()[0], InventoryPolicy::default(), ArchiveLimits::default())?;
    for idx in 0..inventory.selected_dexes().len() {
        let meta = MetadataFacts::build(&snapshot, &inventory, idx, StringLimits::default())?;
        if meta.metadata_coverage() != Completeness::Complete {
            return Err(MddError::new(ErrorCode::IncompleteFacts, "app", "metadata layer incomplete"));
        }
        let defs = DefinitionFacts::build(meta, DefinitionLimits::default())?;
        println!("dex[{idx}] classes={}", defs.definitions().classes.len());
    }
    Ok(())
}
```

### 1.3 接入外部 AI Agent 工具（MCP）

外部工具可直接启动 `meguvizdexdash mcp --dialect dexsql-0.1.0`，按逐行 JSON-RPC 2.0 流程操作：
1. 发送 `initialize`（`protocolVersion` 使用 `"2025-06-18"` 等支持版本）；
2. 调用 `open_dataset` 打开一组 APK/DEX，记住返回的 `dataset_id`；
3. 调用 `list_tables`、`query`、`decode`、`get_manifest`、`get_manifest_components`、`list_resource_files`、`read_resource`、`query_resources`；
4. 若工具返回 `more_available: true` 或带有 `next_offset` / `next_method_offset`，必须按文档说明（例如 `decode` 翻某方法的文本页时必须改用 `file_id` + `method_idx` + `offset`，不可继续传 `class`）继续翻页，直至下一页指示结束；
5. 用完及时调用 `close_dataset`。

## 2. 生命周期、所有权与完整性铁律

1. **禁止跨操作重读可变文件**：捕获快照后，文件在磁盘上被修改、替换或删除不影响当前快照；需要重新分析新版文件时，须重新捕获新快照并对比 `snapshot_id`。
2. **禁止按内容对输入去重，也禁止仅凭局部索引跨 DEX 关联**：
   - 两个路径或同路径两次传入的相同 DEX 会拥有不同的 `dex_occurrence_id`。
   - 不同 DEX 中的 `string_idx` / `type_idx` / `method_idx` 只在单个 DEX 发生实例内有效，关联时须带完整来源作用域（`dex_occurrence_id` 或 `file_id`）。
3. **多轴完整性不可混为一谈**：
   - `operation_status == "ok"` 不等于输入或事实层完整；
   - `execution.complete == true` 与请求是否在投递途中被取消相互独立；
   - **只有同时满足** `ok` + `input == complete` + `facts == complete` + `execution.complete == true` + 无截断且分页读完，才能认定为完整成功结果。
4. **C ABI 批次确认与指针借用规则**：
   - 每次通过 `mdd_query_next_v1` 收到 `MDD_EVENT_BATCH` 后，必须调用 `mdd_batch_ack_v1` 并释放该批次全部引用后，才能再次调用 `mdd_query_next_v1`，否则返回 `MDD_E_OUTSTANDING_BATCH`；未确认即释放会使流以失败终态结束。
   - `mdd_bytes_view` 返回的指针由所属对象拥有（如 `snapshot`、`event`、`batch`），严禁对其调用 `free()`。
5. **逻辑额度与内核 RSS 分离**：`CaptureLimits`、`ArchiveLimits`、`SqlLimits` 等仅是引擎内部的逻辑/缓冲额度，不是进程总 RSS 硬限制。

## 3. 高频错误排查表

| 错误码 / 现象 | 常见原因 | 解决方案 |
| --- | --- | --- |
| `UNSUPPORTED_CAPABILITY`（如启动 `mcp --dialect native-v1`） | `mcp` 服务仅服务 HostLab 契约方言 | 改传 `--dialect dexsql-0.1.0` 或 `--dialect dexsql-0.1.1`；原生关系走 `query --dialect native-v1` 或 `FactsSession` |
| `INCOMPLETE_FACTS` | 上游必需层（如 `metadata`、`definitions` 或 `code`）覆盖为 `Partial`/`Unknown` | 检查上一层构建错误与对应 `Limits`；禁止以空列表跳过 |
| `QUOTA_EXCEEDED` | 超过默认 `SqlLimits`（如步数、扫描行）、`ArchiveLimits` 或结果字节上限 | 在合理的进程资源预算内调整对应 `*Limits` 或 CLI 预算参数（`--sql-max-steps` 等），或缩小 SQL 范围并分页 |
| `DEADLINE_EXCEEDED` / `CANCELLED` | 超出 `deadline_ms` / `timeout_ms` 或被主动取消 | 切勿把中断前已收到的部分批次当作完整结果；在 `mcp` 中超时会自动关闭对应 `dataset_id`，须重新 `open_dataset` |
| `MDD_E_OUTSTANDING_BATCH`（状态码 `5`） | C ABI 上一批次未调用 `mdd_batch_ack_v1` 或仍有未释放的 `mdd_batch` 引用 | 先拷贝出需要的数据，再执行 `mdd_batch_ack_v1` 与 `mdd_batch_release` |
| `WORKER_LOST`（Python `mdd.Worker`） | 子进程异常退出或在流结束前意外终止 | 不能复用旧进程或假定已收到的行为全量结果；捕获异常并丢弃半截状态 |
| `inspect-apk` 输出中 `full_dex_validation_complete=false` | 预期行为：`inspect-*` 只检查归档清点与 DEX header/map | 需要完整结构、指令或引用校验时，使用 `FactsSession` 或 `query` 读取对应层 |

## 4. 安全回退与发布口径约束

1. **profile 合格认证边界**：由于当前所有 profile 的 `admitted` 均为 `false`，在接入原有 HostLab 业务流水线时，必须保留按原引擎执行的回退开关；未经独立全量等价对比门禁签发前，不得移除原有生产基线或声明已具备生产替换资格。
2. **失败与不完整回退**：遇到 `Partial`、`IncompleteFacts`、`QuotaExceeded`、`DeadlineExceeded` 或 `WorkerLost` 时，应显式向上游返回失败或触发既有安全降级分支，绝不将未完分页或超时残片折叠为成功响应。
