<div align="center">

<img src="docs/brand/MeguvizDexDash.svg" width="96" height="96" alt="MeguvizDexDash">

# MeguvizDexDash

**面向桌面与云端的 DEX 静态分析引擎**

Rust workspace · 不可变输入快照 · 类型化查询

<br>

[![Language](https://img.shields.io/badge/lang-Rust-DEA584?style=flat-square&labelColor=2d3a55)](https://github.com/Meguvizarchic/MeguvizDexDash)
[![Issues](https://img.shields.io/github/issues/Meguvizarchic/MeguvizDexDash?style=flat-square&labelColor=2d3a55)](https://github.com/Meguvizarchic/MeguvizDexDash/issues)

[当前开发版本](#当前开发版本) · [原始工程包与实施入口](#原始工程包与实施入口) · [阅读入口](#阅读入口) · [先验证本包](#先验证本包) · [当前性能口径](#当前性能口径) · [版本与证据](#版本与证据)

</div>

---

<details>
<summary><b>目录</b></summary>

- [当前开发版本](#当前开发版本)
- [原始工程包与实施入口](#原始工程包与实施入口)
- [阅读入口](#阅读入口)
- [先验证本包](#先验证本包)
- [当前性能口径](#当前性能口径)
- [版本与证据](#版本与证据)

</details>

---

MeguvizDexDash 是面向桌面与云端、可嵌入且可服务化的 DEX 静态分析引擎。首个业务接入点是 `jichuo1/innocent-lab-host-analysis` 中 DexSQL 承担的职能。Android 进程内 DexKit 替换属于独立的 DexMeguviz 项目。

本仓库基于 2026-10-26 工程包开始实现，保留完整规格、契约和历史研究证据。当前已有 Rust workspace、结果类型、CLI 能力入口、不可变输入快照、ZIP32/ZIP64 物理成员、会话和 worker 生命周期；字符串/类型/原型、定义、注解、代码布局、引用、原始指纹和必需 Manifest 已在各任务限定范围验收。候选索引、事实覆盖与类型化查询正在实施。当前为未取得产品资格的开发版本，尚不能替代 HostLab DexSQL。

任务与具体限制见 [STATE.md](STATE.md)、[唯一任务图](tasks/backlog.json)、[兼容账本](compatibility/ledger.json) 和 [实际证据索引](artifacts/index.json)。全部 profile 仍未准入，约 37%/47% 是历史条件预算，没有新引擎性能成绩。

## 当前开发版本

Rust 工具链固定为 1.99.0。先使用 Python 3.12 环境安装 `requirements-dev.lock` 并生成测试输入，再运行：

```text
python conformance/oracles/reproduce.py
cargo build --locked -p mdd-cli
cargo test --locked --workspace
cargo run --locked -p mdd-cli -- capabilities
cargo run --locked -p mdd-cli -- inspect-dex tests/fixtures/generated/structured-035.dex
cargo run --locked -p mdd-cli -- inspect-apk tests/fixtures/generated/multidex-deflated.apk
```

`inspect-dex` / `inspect-apk` 可以接收多个路径，结果只覆盖成员清单和标准 little-endian DEX 035/037/038/039/040 的 header/map/固定引用范围。返回来源内容摘要、独立 occurrence、物理成员与逻辑 DEX 标识，明确 `full_dex_validation_complete=false`。当前 header-v2 同时验证 Adler32 与 DEX 原生 SHA-1 摘要，来源身份仍采用 SHA-256；SHA-1 不是签名认证。输入支持受预算的单磁盘 ZIP32/ZIP64 STORE/DEFLATE，保留重复物理成员；真实65535/65536成员与独立小语料均已测试，不把虚拟64位边界当4GB实物通过。036、041、多卷、加密和其他codec等未获资格能力明确拒绝，损坏输入以真实错误拒绝。SQL、Smali、完整资源、MCP、FFI 和桌面尚未交付。

Windows x86_64 本机已实际运行；Linux x86_64 由 CI 验收，状态以真实 CI 结果为准。`.github/workflows/ci.yml` 对两个原生平台执行独立语料、构建、lint、测试和真实 CLI 检查，不执行或冒称生产性能基准。

事实 crate 的原生 API 与示例入口在 `crates/mdd-facts`，不会把窄范围 CLI 检查冒充完整事实查询。检查点 b29933d 已通过两平台原生 CI，以及独立测试 workspace 的 Linux ASan 正控制和六目标短 fuzz（2,426,570 次真实执行）。公开 NewPipe 的原始字节证据、AAPT2 Manifest 与固定参考比较见 [MDD-025 验收](artifacts/mdd-025/raw-evidence-conformance.json)，检测边界见 [解析器安全说明](conformance/sanitizers/README.md)。这些证据不授予完整 G1、HostLab、SQL 或正式性能资格。

## 原始工程包与实施入口

1. 将本包解压到编码 AI 可读取的工作区，保留相对目录结构。
2. 将 [AI_EXECUTION_PROMPT.md](AI_EXECUTION_PROMPT.md) 的完整内容交给 AI，并让它读取同目录的 [ENGINEERING_PLAN.md](ENGINEERING_PLAN.md)。若只有聊天输入权限，可先粘贴提示词，再上传本包。
3. 让 AI 检查当前工作区与仓库权限，创建或定位独立的 `MeguvizDexDash` 工程，从 M0 开始实施。现有 HostLab 与 BIL 工程作为接入方，保持独立。
4. 工作区已有规范优先按正常指令层级处理；[AGENTS 模板](templates/AGENTS.template.md) 用于补充工程约定，不覆盖用户已有指令。
5. 每完成一个任务，记录实际代码、实际命令、实际结果和证据。未执行或受阻的任务保留明确状态。

## 阅读入口

| 文件 | 用途 |
| --- | --- |
| [AI_EXECUTION_PROMPT.md](AI_EXECUTION_PROMPT.md) | 可直接复制的主执行提示词 |
| [ENGINEERING_PLAN.md](ENGINEERING_PLAN.md) | 目标、决策、阶段依赖、交付标准和实施顺序 |
| [证据基线](docs/00_EVIDENCE_BASELINE.md) | 已知事实、实测收益、未解问题与来源 |
| [决策与依赖](docs/01_DECISIONS_AND_DEPENDENCIES.md) | Rust、SQL 兼容桥、传输、可选 provider、桌面与依赖选择 |
| [核心架构与契约](docs/02_ARCHITECTURE_AND_CONTRACTS.md) | 模块、实体、生命周期、语义、协议与缓存 |
| [HostLab 迁移](docs/03_HOSTLAB_MIGRATION.md) | 真实入口、SQL、工具分层、适配、回退与切换 |
| [验证与性能](docs/04_VALIDATION_AND_PERFORMANCE.md) | 格式语料、独立验证、完整性、性能与发布门槛 |
| [执行与交接](docs/05_EXECUTION_AND_HANDOFF.md) | 多代理分工、开发循环、CI、证据与恢复 |
| [任务图](tasks/backlog.json) | 唯一任务依赖和当前实施状态；原始交付时均为 todo |
| [契约索引](contracts/README.md) | 拟定 JSON Schema 与语义约束 |
| [证据索引](evidence/index.json) | 原始附件、逐轮测量、行为观察及其 SHA256 |
| [交付包验证记录](VALIDATION_REPORT.md) | 本次实际执行的材料校验及其严格边界 |

## 先验证本包

对原始交接快照执行以下命令；开发后的源码应使用 `python tools/verify_original_handoff.py` 从初始提交重建并验证原包，不能对已更新任务图强套原 manifest：

```bash
python3 tools/verify_kit.py
python3 tools/recompute_targets.py
```

第一个命令验证文件摘要、链接、任务图及规格材料的内部一致性；第二个命令从原始 HostLab JSON 重新计算条件目标。它们不启动引擎，不依赖 APK，也不证明新引擎功能或性能已经达标。

## 当前性能口径

历史 A0 是 DexSQL 0.1.0 与已优化 HostLab，两个完整任务为 94.630/85.572 秒。让结构与 surface 两个完整阶段各快两倍、其余不变，对应 59.536/54.216 秒，降时 37.09%/36.64%。这只是阶段工程目标，完整 B 尚未实测。

已有上游 0.1.1 在公开 APK 的真实 HostLab 全量查询管道中测得配对中位约 2.88 倍速度；消费端列批原型对同条宽表查询测得约 6.78 倍组件速度。两者不相乘、不外推完整 BIL，也不都归为自研收益。M0 必须保留 A0、A1、A2、B0、B1 五组身份并重建同环境基准。

## 版本与证据

本包规格版本为 `0.1-draft`，整理日期为 2026 年 10 月 26 日，用户时区 Asia/Shanghai。原始日志时间保持其来源时区。HostLab 固定研究提交为 `8782f43d537c442905123e35af325c412caa5188`，后续实施必须同时保存固定基线与当时实际 checkout 身份，不能把快照当作所有部署实例的现状。

新设计与已知事实分开标注。接口实现进度以任务图和实际证据为准；架构文档中的远期契约不等于当前已交付能力。引用的闭源 DexSQL 行为只覆盖已经观察或文档说明的范围，不声称恢复完整内部源码。
