---
name: meguviz-dex-dash
description: 用于在桌面或服务端 Rust、CLI、MCP、Python、C ABI 或 Tauri 桌面项目中接入 MeguvizDexDash 静态 DEX/APK 分析引擎，或将旧版脚本解析、Ad-hoc 反编译工具迁移至快照与完整性受控的分析链路。若需 Android 端内 AAR 嵌入、C++20 嵌入式库或端内 Hook 候选绑定，转交 DexMeguviz。
---

# MeguvizDexDash 接入与迁移

MeguvizDexDash 是面向桌面与服务端的 Rust DEX/APK 静态分析引擎（当前版本 `0.1.0-dev`），支持多 DEX 成员清点、字节码与注解事实读取、只读 SQLite 虚表查询、Smali 文本生成、Manifest 与资源解析及 MCP 工具服务。

## 第 1 阶段：盘点工程现状

修改代码前，先核对目标工程形态并输出简短评估：

1. **选型分流核对**：
   - 需要 Android 端内 AAR 嵌入、与 `MeguvizHook` / `MeguvizRef` 配合或 C++20/C ABI 轻量嵌入：转交 `DexMeguviz`。
   - 需要桌面/服务端 Rust 引擎、全量 APK 资源与 Manifest/Smali 审计、SQL 引擎、MCP 服务、Python SDK、C ABI 或桌面可视化工作台：使用 `MeguvizDexDash`。
2. **工具链与版本基线**：
   - `rust-toolchain.toml` 固定 Rust **`1.99.0`**（`edition = "2024"`、`rust-version = "1.99"`、`publish = false`）；本地通过 Cargo path 依赖或 CLI/FFI 产物消费，不从公共 crate 仓库拉取。
   - **合格资格边界**：当前 `capabilities` 中所有 profile（如 `mdd-native-v1`、`mdd-header-inspection-dev-v1`）的 `admitted` 均为 `false`，处于功能预览阶段，**不可宣称已获准替代生产 DexSQL profile**。
3. **存量解析点盘点**：
   - 找出所有直接用 `zipfile` / `apktool` / `dexdump` 拼接的脚本、对同路径重复文件做暗中去重的逻辑，以及把超时/截断直接当作空列表处理的调用点。
   - 识别当前调用方对异常隔离与性能的需求：若宿主不可承受原生崩溃或 OOM 连带退出，优先使用 `mdd.Worker` 或 `meguvizdexdash mcp` 进程隔离方案。

## 第 2 阶段：选择模块与接入依赖

按消费场景选择对应的接入形态（五选一或按需组合，不链接未使用的 crate）：

| 消费方式 | 入口 / 制品 | 适用场景 | 核心约束 |
| --- | --- | --- | --- |
| **Rust 库接入** | `mdd_facts::session::FactsSession`（或分层 `Snapshot` + `ArchiveInventory` + `MetadataFacts`/`DefinitionFacts`/`CodeFacts`/`ReferenceFacts`）与 `mdd-query`、`mdd-sql` | 宿主就是 Rust 服务，需按需读取各事实层并复用 `Arc` | 依赖链 `metadata -> definitions -> {annotations, references}`；前驱不完整时报 `INCOMPLETE_FACTS` |
| **CLI 命令行** | `meguvizdexdash`（`crates/mdd-cli`） | 脚本或流水线调用：`capabilities`、`inspect-apk`、`inspect-dex`、`query`、`serve` | `serve` 使用逐行 JSON 流 `mdd.cli-stream.v1` |
| **MCP 服务** | `meguvizdexdash mcp`（`crates/mdd-mcp`） | 外部 AI 工具或工作台查询 APK/DEX、Smali、Manifest 与资源 | 逐行 JSON-RPC 2.0，共 12 个工具；拒绝 `native-v1`，默认 `dexsql-0.1.0` |
| **Python SDK & C ABI** | `mdd-ffi`（`include/mdd.h`）+ `python/mdd` | Python 或 C/C++ 宿主接入 | 支持进程内库（`mdd.open_snapshot`）与隔离进程（`mdd.Worker`）两种模式 |
| **桌面工作台** | `apps/desktop`（独立 Tauri 2 工作区） | 交互式浏览 DEX、Smali、Manifest、资源与对比 diff | 不链接任何 `mdd-*` crate，仅通过 `meguvizdexdash mcp` 通信 |

典型接入命令与 Cargo 依赖片段（按实际选用的消费形态择一配置）：

```toml
# 仅 Rust 库消费时按需通过 workspace/path 引入，不要混入 apps/desktop
[dependencies]
mdd-facts = { path = "../MeguvizDexDash/crates/mdd-facts" }
mdd-types = { path = "../MeguvizDexDash/crates/mdd-types" }
```

```sh
# 命令行检查与 MCP 服务启动（MCP 模式须使用 dexsql-0.1.0 或 dexsql-0.1.1）
cargo run --locked -p mdd-cli -- inspect-apk app.apk
cargo run --locked -p mdd-cli -- mcp --dialect dexsql-0.1.0
```

## 第 3 阶段：执行最小迁移与生命周期对齐

1. **同一输入快照不可变复用**：
   - 使用 `FactsSession::open` 或 `Snapshot::capture`（C ABI 为 `mdd_open_snapshot_v1`）一次性捕获输入；后续查询、Smali、Manifest 与资源读取全部绑定同一快照，严禁各自重新打开文件。
   - **保留物理重复 DEX 成员**：同一物理内容传入两次会生成两个独立的 `dex_occurrence_id`，不得静默合并或仅按 `method_idx` 跨 DEX 关联。
2. **多轴完整性检查（禁止把部分结果当空成功）**：
   - 任何结果消费前必须同时验证 `operation_status == "ok"`、`coverage.input == "complete"`、`coverage.facts == "complete"`、`execution.complete == true`、无阻塞 `warnings`、以及分页完成（`more_available == false`、`truncated == false`、`next_cursor == null`、`total_rows_exact == true`）。
   - `Partial`、超时（`DEADLINE_EXCEEDED`）、取消（`CANCELLED`）或未消费完的分页必须按失败或未完成路径处理。
3. **显式控制限额、批次确认与隔离边界**：
   - 使用 `FactsLimits` / `SqlLimits` / `ResourceLimits` 传入逻辑限额，勿将其视作操作系统 RSS 硬限。
   - 使用 C ABI（`include/mdd.h`）时，每次 `mdd_query_next_v1` 拿到批次后须调用 `mdd_batch_ack_v1` 并释放引用后才可读下一批；遇到异常隔离需求时，使用 `mdd.Worker`（`meguvizdexdash serve`）替代进程内 FFI。
4. **Rust 库接入最小骨架**：

```rust
use mdd_facts::session::FactsSession;
use mdd_types::{Completeness, MddResult};

fn inspect(path: &str) -> MddResult<()> {
    let session = FactsSession::open(path)?;
    for idx in 0..session.dex_count() {
        let defs = session.definitions(idx)?;
        if defs.definition_coverage() != Completeness::Complete {
            // 不可将该 DEX 当作空定义继续放行，须报错或上抛不完整问题
            continue;
        }
        let refs = session.references(idx)?; // 自动复用缓存的 definitions 与 code Arc
        refs.require_complete()?;
        println!("occ={} methods={} sites={}", session.occurrence(idx)?, defs.definitions().method_definitions.len(), refs.sites().len());
    }
    Ok(())
}
```

5. **Python SDK（进程内库 / 隔离 Worker）与 MCP 接入速览**：

```python
import mdd

# 方式 A：进程内库（需先 cargo build --locked -p mdd-ffi）
with mdd.open_snapshot(["app.apk"]) as snapshot, snapshot.open_session() as session:
    result = session.execute("SELECT dex_occurrence_id, class_def_idx, descriptor FROM native_classes")
    assert result.is_complete  # 同时校验 status、coverage、execution 与分页完成状态

# 方式 B：子进程隔离（底层拉起 meguvizdexdash serve，崩溃或超时抛出 WorkerLost/DeadlineExceeded）
with mdd.Worker(["app.apk"], dialect="native-v1") as worker:
    summary = worker.execute("SELECT COUNT(*) FROM native_classes")
    assert summary.is_complete
```

6. **MCP 工具会话要点**：
   - 先发 `initialize`（如 `"protocolVersion": "2025-06-18"`），再调用 `open_dataset` 获取 `dataset_id`。
   - 调用 `query`、`decode`、`get_manifest`、`list_resource_files` 或 `query_resources` 时，若返回分页游标或 `next_offset` 须继续拉取直至末页；结束后调用 `close_dataset` 释放数据集配额。

> **按需深入阅读**：完整 15 个 crate、CLI/MCP 参数、C ABI 签名与 Python SDK 清单见 [API 与模块速查](references/api-and-modules.md)；五种接入范式对照、多轴完整性校验写法与排障见 [迁移对照与排障](references/migration-patterns.md)。

## 第 4 阶段：验证与交付清单

1. **构建与契约校验**（在 `MeguvizDexDash` 根目录运行）：
   - 构建 CLI 与核心测试：`cargo build --locked -p mdd-cli` 与 `cargo test --locked --workspace`
   - 若消费 C ABI / Python SDK：`cargo build --locked -p mdd-ffi` 后运行 `python -I -m unittest discover -s python/tests -t python`
   - 校验 CLI 能力与未认证状态：`python conformance/check-cli-contract.py --binary target/debug/meguvizdexdash`（Windows 加 `.exe`）
   - 若修改本仓库进度或文档，**必须运行** `python tools/check_progress.py` 并确认退出码为 `0`。
2. **消费端检查**：确认所有 `ResultEnvelope` / `Worker` / `Snapshot` 均按多轴完整性规则判定，并验证 `close` / 取消后无僵尸子进程或未确认批次。
3. **回退检查**：确保原有生产基线或降级开关保持可用；遇到 `Partial` 或未认证 profile 时禁止静默放行。
4. **交付摘要**：列出选用的消费方式、涉及的 crate/CLI/MCP/SDK 接口、实际执行的命令与退出状态，并如实注明当前仍处于功能预览（`admitted = false`）。
