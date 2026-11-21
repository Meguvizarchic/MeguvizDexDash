# HostLab 可切换后端启用与回滚说明（MDD-055）

> 状态说明：`MDD-055` 签发的是**功能等价预备（functional preview / switchable qualification）**，仅当操作方显式配置并完成自建 Pin 后生效；**不默认切换生产流量，也不代表已满足 37% 性能替代目标**（正式性能准入见 `MDD-082`）。

## 1. 启用前核验（Pin 与能力校验）

1. 按本地发布构建重新生成引擎 Pin 清单，避免未钉住二进制被执行：
   ```bash
   python -I integrations/hostlab/install_meguvizdexdash.py --binary target/release/meguvizdexdash.exe pin --output <STATE_ROOT>/vendor/meguvizdexdash/manifest.json
   python -I integrations/hostlab/install_meguvizdexdash.py --manifest <STATE_ROOT>/vendor/meguvizdexdash/manifest.json --binary target/release/meguvizdexdash.exe --deep check
   ```
2. 根据 `integrations/hostlab/enablement-config.example.json` 分别导出：
   - `provider-config.json`（取其中的 `provider_config` 对象，`schema = "mdd.hostlab-provider-config.v1"`）；
   - `structural-config.json`（取其中的 `structural_config` 对象，`schema = "mdd.hostlab-structural-config.v1"`，`non_scalar_text = "lossy-replacement"` 以匹配 A0 对合法孤立 UTF-16 代理的 `U+FFFD` 映射，引擎其余场景默认保持严格 `reject`）。
3. 导出环境变量以显式开启切换：
   ```powershell
   $env:HOSTLAB_PROVIDER_CONFIG = "<PATH_TO_PROVIDER_CONFIG_JSON>"
   $env:HOSTLAB_STRUCTURAL_CONFIG = "<PATH_TO_STRUCTURAL_CONFIG_JSON>"
   ```

## 2. 运行后必检字段（报告溯源与完整性）

每次以 `meguvizdexdash` 执行完整审计后，调用 `provider.check_report(report)` 与 `provider.completeness(...)` 核对以下字段（均可在报告中还原）：

- **Backend / Run 身份**：
  - `report["backend_versions"]["meguvizdexdash"]` 含 `engine_version`、`build_id`、`binary_sha256`、`profile`、`dialect`、`config_digest`；
  - `report["provider"]["run"]` 含 `request_sha256`、`source_sha256`、`config_digest`、`id`；
  - `report["backend_versions"]["dexsql"]` 不得混入 MeguvizDexDash 字段。
- **完整性与边界**：
  - 每次查询返回 `operation_status == "ok"`、`coverage.input == "complete"`、`coverage.facts == "complete"`、`execution.complete == True`；
  - `response.truncated == False` 且 `response.next_cursor is None`；
  - 正式资格要求 `fallback_count == 0`（若配置为 preview fallback 模式，任何回退均会明文写入 `report["provider"]["fallbacks"]`）。

## 3. 单步显式回滚

无需修改任何源码、已写报告或旧缓存即可立即回退到 `dexsql`：

- **方式 A（推荐，配置级切换）**：将 `provider-config.json` 中的 `"native_engine"` 改回 `"dexsql"`（如示例文件中的 `rollback_provider_config`）。
  - 所有 `backend = "auto"` 请求立即由 HostLab 原生规划器路由回 `dexsql`；
  - 所有显式指定 `backend = "meguvizdexdash"` 的请求会被明确拒绝（`ProviderDisabled` / `UNAVAILABLE_BACKEND`），绝不会静默降级为别的后端。
- **方式 B（环境取消）**：取消设置 `HOSTLAB_PROVIDER_CONFIG` 与 `HOSTLAB_STRUCTURAL_CONFIG` 环境变量；无配置文件时 `provider.load_config()` 默认返回 `native_engine = "dexsql"`。

## 4. 目录与断点隔离保证

- 新引擎的运行缓存、临时目录与结果严格限定在 `<state>/mdd-engine/` 命名空间内（由 `provider.namespaces()` 强制检查）；
- 对 HostLab 既有目录（`dexq-cache`、`reports`、`remote-output`、`remote-results`、`analysis-schedule`、`remote-requests`、`remote-job-map`、`version-matrices`、`artifact-cache`、`source-snapshots`、`samples`）保持**只读不写**；回滚后旧缓存内容逐字节保持不变；
- `provider.resume_compatible()` 会按 `(build_id, binary_sha256, profile, dialect, config_digest)` 校验检查点，引擎切换或回滚后绝不复用跨引擎断点。
