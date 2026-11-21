# MeguvizDexDash HostLab 功能预览包（MDD-055）

- **产品**：MeguvizDexDash
- **引擎版本 / 构建 ID**：`0.1.0-dev` / `source-sha256:df1ab73e8d4dcddd609e301e199882420895cbc3852afc63cc0c5072145efdf7`
- **Windows 二进制 SHA-256**：`dd81f064164fa679ef52dd0c8e07a0c41d282d50947fd18fdb5b9f2528201e43`
- **交付属性**：`preview = true`（仅功能预览与可审查切换资格）
- **性能替代资格**：`performance_replacement_qualified = false`（尚未完成 MDD-080/081/082 独占窗口正式性能签发）
- **默认生产策略**：`default_production_cutover = false`（生产与默认配置保持 `native_engine = "dexsql"`）

## 已验证工作负载与等价结论

| 样本标识 | DEX 数 | 类总数 | 查询数 | 四层 shadow 比对 | Fallback |
|---|---:|---:|---:|---|---:|
| `hostlab-9161100` (9.16.1) | 33 | 310716 | 635 | `equal = true` (0 差异) | 0 |
| `hostlab-9170100` (9.17.0) | 35 | 345907 | 647 | `equal = true` (0 差异) | 0 |

## 显式启用与单步回退

1. 配置示例：[integrations/hostlab/enablement-config.example.json](../../../integrations/hostlab/enablement-config.example.json)
2. 操作与回退手册：[integrations/hostlab/ROLLBACK.md](../../../integrations/hostlab/ROLLBACK.md)
3. 资格清单：[conformance/manifests/hostlab-backend-qualification.json](../../../conformance/manifests/hostlab-backend-qualification.json)
4. 切换与回退演练记录：[artifacts/mdd-055/cutover-rehearsal.json](../../mdd-055/cutover-rehearsal.json)

## 明确声明限制

- 本预览包**不替代** `MDD-082` 性能合格发布，亦不将生产默认切换为 `meguvizdexdash`。
- 完整 12 个 MCP 工具、剩余 39 个公开关系及 Python/C-ABI/CLI SDK 等契约将在 M7（`MDD-060..065`）单独验收。
