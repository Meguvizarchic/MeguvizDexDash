# MeguvizDexDash `0.1.0-dev` 发布与资格说明（MDD-082 / MDD-083）

> **发布授权边界**：本仓库完成的是标准 DEX 候选发布包、资格清单（`conformance/manifests/release-qualification.json`）、SBOM 与可复验切换演练；**仓库进度存储与远端推送不构成外部生产切换或部署授权**，所有默认配置仍保持 `dexsql` / `legacy_independent` 显式opt-in 前的状态。

## 1. 发行身份与锁定依赖

- **产品与命令**：`MeguvizDexDash`（CLI `meguvizdexdash`，工作区 crate 前缀 `mdd-`）
- **核心版本与工具链**：引擎 `0.1.0-dev`，Rust `1.99.0`，SQLite `3.53.2`，`Cargo.lock` / `apps/desktop/Cargo.lock` / `requirements-dev.lock` 全锁定离线构建
- **已验证 Windows Release 指纹（Wave 1.7d）**：
  - `meguvizdexdash.exe`：`11,951,616` 字节，SHA-256 `7a89484c6474b7fe4eb0bc8af97b813e56a0685511cc461b8bd16f54926c0053`，`build_id = source-sha256:8829a2218df097d58ed1283c4c87429d283a815f54a9f132c0a7f2c9c42940a3`
  - `mdd_ffi.dll`（C ABI `1.0`）：`8,359,936` 字节，SHA-256 `241d9cb3ed515ed5d3c5638fffbef030dbdd1b0a85828b697491e640af57332a`
  - `meguvizdexdash-desktop-preview-0.1.0-dev-windows-x86_64.zip`：`7,881,162` 字节，SHA-256 `1e3c14e43518fc8ae33327527b5abce45e29871d1f09f9732f3ea28c7694cc3e`
- **双平台构建说明**：Windows `x86_64` 与 Linux Ubuntu 24.04 `x86_64` 可分别由源码及锁文件独立复现并在 `MDD-080` 全部 5 项标准负载上产出逐字节一致的规范输出（`overall_canonical_sha256 = eb1deaaa26fc0836a1ba064c362cb224a350e5caf5439ae3b775a9c4af05838e`）；跨机器归档包装字节不强求相同，各平台独立校验对应清单元数据。

## 2. 核心性能、内存与桌面体验升级（MDD-060 / MDD-061 / MDD-062 / MDD-064 / MDD-066）

### 2.1 同环境配对性能成绩（独占测量窗口，0 污染 / 0 排除配对 / 0 Fallback）

在 `MDD-060` 排除不具备完整端到端资格的 `candidate A2`（`offset + limit > 100000` 拒绝，且缺不可变快照绑定与 HostLab 消费适配）后，以实测最快的合格现成引擎 `A1`（`dexsql 0.1.1`）为基准，`B1` 在校准阈值（关键负载降时 `>= 10%`、其余守护负载退化 `<= 5%`）下全项达标：

| 负载 | 基线 | 配对中位加速比 | 相对基线耗时变化 | 证据文件 |
| --- | --- | --- | --- | --- |
| `W05-newpipe-bulk` (13 对) | `A1` | `1.665x` | **`-39.95%`** (`1.469s` vs `2.412s`) | `artifacts/mdd-061/end-to-end-regression.json` |
| `W07-hostlab-9161100` (12 对) | `A1` | `1.800x` | **`-44.44%`** (`32.765s` vs `59.094s`) | `artifacts/mdd-061/end-to-end-regression.json` |
| `W07-hostlab-9170100` (12 对) | `A1` | `1.841x` | **`-45.67%`** (`35.319s` vs `65.032s`) | `artifacts/mdd-061/end-to-end-regression.json` |
| `W07-hostlab-9161100` (2 对) | `A0` | `1.994x` | **`-49.84%`** (`32.946s` vs `65.698s`; 阶段 S `9.10x`, 阶段 F `6.09x`) | `artifacts/mdd-061/end-to-end-regression.json` |
| `W07-hostlab-9170100` (2 对) | `A0` | `2.044x` | **`-51.06%`** (`35.213s` vs `71.963s`; 阶段 S `9.45x`, 阶段 F `6.43x`) | `artifacts/mdd-061/end-to-end-regression.json` |
| 守护 `W01-newpipe-intake` (5 对) | `A1` | `1.851x` | **`-45.96%`** (`0.00814s` vs `0.01472s`) | `artifacts/mdd-061/end-to-end-regression.json` |
| 守护 `W02-newpipe-lookup` (5 对) | `A1` | `1.229x` | **`-18.63%`** (`0.00579s` vs `0.00744s`) | `artifacts/mdd-061/end-to-end-regression.json` |
| 守护 `W03-newpipe-xref` (5 对) | `A1` | `2.204x` | **`-54.63%`** (`0.02928s` vs `0.06453s`) | `artifacts/mdd-061/end-to-end-regression.json` |
| 守护 `W04-newpipe-joins-agg` (5 对) | `A1` | `1.382x` | **`-27.66%`** (`0.02076s` vs `0.02892s`) | `artifacts/mdd-061/end-to-end-regression.json` |
| 守护 `W06-newpipe-smali` (5 对) | `A1` | `43.37x` | **`-97.69%`** (`0.000295s` vs `0.01255s`) | `artifacts/mdd-061/end-to-end-regression.json` |

> 重叠与消融诚实口径：`W07` 7 配置消融下 `all_on` (`33.120s`) 较 `all_off` (`127.078s`) 缩短 **`73.94%`**，各单项孤立减时之和 (`140.060s`) 不允许直接叠加；对 `A0` 的历史 `37%/47%` 条件目标已在相同主机 S/F 与端到端路径上超额达成（同时单独保留 `A0->A1` 上游贡献与 `MDD-062` 的独立 `E_gate` 时间窗）。

### 2.2 内存深度优化实测（MDD-066）

- **`W07-hostlab-9161100`（33 DEX，Windows Job 峰值提交内存）**：由优化前并发准备基线 `2.31 GiB` 降至探针 **`1.2144 GiB`**（`1,303,957,504` 字节；14 次配对回归中位 **`1.2154 GiB`**），较 `A1` (`1.4927 GiB`) 降低 **`-18.58%`**、较 `A0` (`1.4651 GiB`) 降低 **`-17.04%`**、较 `MDD-060` 未优化 `B1` (`1.28 GiB`) 降低 **`-5.05%`**。
- **`W07-hostlab-9170100`（35 DEX，Windows Job 峰值提交内存）**：14 次中位 **`1.2922 GiB`**（`1,387,460,608` 字节），较 `A1` (`1.6211 GiB`) 降低 **`-20.29%`**、较 `A0` (`1.6383 GiB`) 降低 **`-21.13%`**。
- **`NewPipe_v0.28.6.apk` 仅打开会话**：Job 峰值提交 **`261.37 MiB`**（`274,063,360` 字节），较优化前 `561.7 MiB` 下降 **`-53.47%`**；在全 7 条 `W05` 批量导出与常驻字典加速模式下，`B1` 引擎进程保留共享 `TextDict` 与列式索引（`240.5 MiB` vs `A1` `106.7 MiB`），换取 `-39.95%` `W05` 端到端降时与 `-18.6%` 至 `-97.7%` 的常驻单查询加速。
- **诚实未达标延伸目标说明**：联合 Windows Job 提交口径（包含 Python 消费端 `~0.17 GiB`、常驻列存储/字典及 `max_in_flight <= 2` 单 DEX 临时构建工作集）下，`33-DEX` 全审计 `< 1.0 GiB` 的延伸目标未达成，已如实记录于 `artifacts/mdd-066/deep-perf-and-ui-qualification.json` 与 `artifacts/mdd-082/compatibility-and-limitations.json`。

### 2.3 其他新增模块与修复

- **HostLab Gate 复用（`MDD-062`）**：`integrations/hostlab/audit_data_provider.py`（opt-in `mdd_fact_reuse`，默认仍为 `legacy_independent`）在 2 个实测 HostLab APK × 3 轮配对中与独立参考脚本 `intake`/`home` 判定及哈希 **100% 等价**，共享常驻会话模式下 `E_gate` 耗时分别加速 `1.473x` / `1.495x`（不计入阶段 1 `S`/`F` 目标）。
- **版本化持久缓存与全局调度（`MDD-063` / `MDD-064`）**：`mdd-index/1` 原子缓存、`GlobalBudget`/`Scheduler` 三并发档位公平排队与整内容对象复用已验证；未获闭包证明的细粒度增量保持明确 `disabled`。
- **桌面端 WebView2 UI 优化（`MDD-066` / `MDD-073`）**：升级 `apps/desktop/ui/` 排版层次、高对比选择器与浅深双主题可读性，保持严格 `default-src 'none'` CSP 与零外部网络依赖；重新打包后通过 `39/39` Rust、`41/41` 前端与 **`15/15` 真实 Windows WebView2 窗口流程**。

## 3. 兼容范围、排除项与已知限制

- **准入平台**：`windows-x86_64`、`linux-x86_64`；`macos-arm64`、`macos-x86_64`、`linux-aarch64`、`windows-aarch64` 保持 `not_admitted`。
- **准入格式**：标准 DEX `035 / 037 / 038 / 039 / 040` 与 APK ZIP；DEX `041` 仅作为独立 opt-in 可选能力且默认关闭；`cdex`、`vdex`、`oat`、`apk-split-bundle`、`protobuf-resources` 返回 `UNSUPPORTED_CAPABILITY`。
- **已钉住兼容边界（Fail-Closed）**：`Q16` 缺乏带标签大型 HostLab 语料；`GLOB`、递归 CTE 及 SQLite DQS（未知双引号标识符回退字符串字面量）均显式拒绝；桌面端 Diff 不比较指令操作数且界面为中文。

## 4. 独立核验与复现命令

```powershell
.\.venv\Scripts\python.exe -O -I tools/verify_original_handoff.py
.\.venv\Scripts\python.exe -O -I tools/check_progress.py
.\.venv\Scripts\python.exe -O -I tools/verify_mdd066.py --check
.\.venv\Scripts\python.exe -O -I tools/verify_mdd082.py --check
.\.venv\Scripts\python.exe -O -I tools/verify_mdd083.py --check
.\.venv\Scripts\python.exe -I tools/run_ci_conformance.py --binary target/debug/meguvizdexdash.exe --out-dir artifacts/local/ci
```
