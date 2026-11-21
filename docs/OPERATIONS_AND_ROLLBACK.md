# MeguvizDexDash 运维、分阶段启用与单步回滚手册（MDD-083）

> **默认值原则**：未显式配置且未完成本地二进制 SHA-256 Pin 校验前，HostLab 调度默认路由至 `dexsql`，审计门禁默认使用 `legacy_independent`。仓库中不存在隐式默认生产切换或静默兜底混合执行。

## 1. 分阶段显式启用步骤（HostLab）

1. **构建或接收对应平台的 Release 二进制并校对校验和**：
   - CLI / MCP 主程序：`target/release/meguvizdexdash.exe`（Windows）或 `target/release/meguvizdexdash`（Linux）
   - C ABI 动态库：`target/release/mdd_ffi.dll`（Windows）或 `target/release/libmdd_ffi.so`（Linux）
   - 先核对 `dist/SHA256SUMS` 与 `dist/release-manifest.json`。
2. **生成并深检本地 Pin 清单**：
   ```powershell
   .\.venv\Scripts\python.exe -I integrations/hostlab/install_meguvizdexdash.py --binary target/release/meguvizdexdash.exe pin --output <STATE_ROOT>/vendor/meguvizdexdash/manifest.json
   .\.venv\Scripts\python.exe -I integrations/hostlab/install_meguvizdexdash.py --manifest <STATE_ROOT>/vendor/meguvizdexdash/manifest.json --binary target/release/meguvizdexdash.exe --deep check
   ```
3. **从受审配置模板导出配置（`dist/hostlab-enablement-config.json`）**：
   - **阶段 1（标准 `B0`/`B1` 影子与受控启用）**：设置 `HOSTLAB_PROVIDER_CONFIG` 指向导出的 `provider_config`（`native_engine = "meguvizdexdash"`, `fallback.to = "none"`），`HOSTLAB_STRUCTURAL_CONFIG` 指向导出的 `structural_config`（推荐 `wire = "b1"`、`non_scalar_text = "lossy-replacement"`）。
   - **阶段 2（可选 Gate 事实复用）**：仅在明确需要加速 `intake`/`home` 门禁且已核对 `MDD-062` 证据后，在 gate 配置中显式传入 `GateConfig(mode="mdd_fact_reuse", wire="b1")`；默认仍保持 `legacy_independent`。
   - **持久化缓存隔离（`mdd-index/1`）**：新引擎缓存始终写入独立的 `<STATE_ROOT>/mdd-engine/` 命名空间与 `mdd-index/1` 清单绑定目录，绝不复用或覆盖旧版 `dexq-cache` / `reports` / `remote-*` 目录。

## 2. 配置升级迁移（M5 -> M8）

- 若原先使用 `MDD-055` 的 `wire = "b0"` 配置（`integrations/hostlab/enablement-config.example.json`），升级到 `M8` 仅需在核验新版本 `manifest.json` 后将 `structural_config.wire` 更新为 `"b1"`（或继续保留 `"b0"` 作为保守对照，二者对 20 组结果与全部 SQL 查询返回逐字一致的规范哈希）。
- 不允许将旧版本引擎或不同 `binary_sha256` / `config_digest` 生成的断点恢复文件（resume checkpoint）直接喂给新配置继续执行：一旦源摘要、引擎身份或配置摘要不一致，会 fail-closed 拒绝恢复。

## 3. 单步回滚与故障隔离规程

1. **配置级单步回滚（推荐）**：
   - 将启用配置中的 `provider_config.native_engine` 改回 `"dexsql"`（参见 `dist/hostlab-enablement-config.json` 的 `rollback_provider_config`），并将任何 gate 选项保持为 `legacy_independent`。
   - 取消 `HOSTLAB_PROVIDER_CONFIG` 与 `HOSTLAB_STRUCTURAL_CONFIG` 环境变量后，`provider.load_config()` 亦立即退回默认 `dexsql`。
2. **回滚不变量保证**：
   - **不删除历史与当前证据**：`artifacts/`、`reports/` 与 `<STATE_ROOT>/mdd-engine/` 记录保持原样，禁止用清空目录伪装历史结果。
   - **不伪装旧 schema 缓存**：`mdd-index/1` 索引头含 96 字节头 SHA-256 与原始 manifest 摘要，一旦源文件发生 1 字节变化或模式切换即返回 `CACHE_CORRUPT` / `STALE_CACHE` 并失效，绝不伪装为旧引擎缓存继续使用。
   - **拒绝跨引擎透明重放已发生副作用的任务**：当会话在 `dexsql` 与 `meguvizdexdash` 之间发生切引擎且已产生分页消费或 `TEMP` 表定义副作用时，恢复检查点直接报错拒绝（`SOURCE_CHANGED` / resume 拒绝），要求显式重开干净会话。

## 4. 离线与发行包复验清单

```powershell
.\.venv\Scripts\python.exe -O -I tools/verify_mdd082.py --check
.\.venv\Scripts\python.exe -O -I tools/verify_mdd083.py --check
.\.venv\Scripts\python.exe -I integrations/hostlab/rehearse_cutover.py --binary target/release/meguvizdexdash.exe
```
