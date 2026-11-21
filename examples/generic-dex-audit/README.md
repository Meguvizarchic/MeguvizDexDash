# MeguvizDexDash 通用 DEX/APK 入口点与跨 DEX 可达性审计工具 (`MDD-065`)

本目录提供一个**完全独立于 BIL / HostLab / DexMeguviz / DexKit** 的第二个通用消费者包 `mdd-generic-dex-audit`，用于验证 MeguvizDexDash 核心架构的可复用性与边界隔离。

## 设计边界与所有权

- **仅依赖公开接口**：
  1. `--transport in-process`：通过 `python/mdd` 绑定稳定 C ABI `1.0` (`native-v1`)；
  2. `--transport worker`：通过 `mdd.Worker` (`mdd.cli-stream.v1`) 驱动独立子进程 `meguvizdexdash serve`（支持 `native-v1` 与 `dexsql-0.1.1`）；
  3. `--transport mcp`：通过标准 JSON-RPC 2.0 stdio 调用 `meguvizdexdash mcp`（12 个公开工具）。
- **无第二套解析核心**：自身不含 DEX/ZIP/AXML 二进制解析代码；所有事实、原始字节校验和与完整性终态均来自同一被测快照。
- **独立版本与包边界**：拥有独立 `pyproject.toml`（零第三方运行时依赖，零 `integrations/hostlab` 导入），不要求引擎内部为单一业务规则开特例。

## 分析能力

1. **快照与出处盘点 (`structure_audit`)**：在三种传输通道间以完全一致的 schema 输出逻辑 DEX 出现（保留物理内容重复文件的各自 `occurrence_ordinal` / `file_id`）、类、定义方法与 `code_off`/`insns_size` 边界。
2. **入口点与跨 DEX 调用可达性 (`reachability_audit`, `dexsql-0.1.1`)**：
   - 基于入口类前缀（`--entrypoint-prefix`）或方法名集合做有界多跳（`--max-hops`）调用图展开；
   - 严格区分 **总调用点数 (`call_site_count`)** 与 **去重边数 (`distinct_edge_count`)**，并标注跨 `file_id` 调用；
   - 收集可达方法引用的字符串常量及原始 `code_items` / `opcode_hex` SHA-256 证据。
3. **可选 MCP 富化视图 (`mcp_enrichment`)**：读取 `get_manifest_components` 导出组件并调用 `decode` 输出展示级 `mdd.smali.v1` 预览（与原始字节事实明确隔离）。
4. **取消与完整性验证 (`--cancel-probe`)**：验证流式查询中途取消触发 `CANCELLED` 终态、绝不把截断页或未完结流当成空结果成功。

## 用法示例

```bash
python -I examples/generic-dex-audit/audit.py --input conformance/generic-consumer/fixtures/public-app-audit.apk --transport in-process
python -I examples/generic-dex-audit/audit.py --input conformance/generic-consumer/fixtures/public-app-audit.apk --transport worker --dialect dexsql-0.1.1
python -I examples/generic-dex-audit/audit.py --input conformance/generic-consumer/fixtures/public-app-audit.apk --transport mcp --dialect dexsql-0.1.1
```
