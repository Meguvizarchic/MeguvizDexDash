# 未入库的原始执行证据

按项目决定，原始执行记录（编译输出、探针 stdout/stderr、`record.json`、`result.json`、证据生成脚本）里凡是带本机绝对路径的，都不进入公开仓库。它们保存在维护者本机的 `artifacts/local/withheld-evidence-20261112/` 下，目录结构与原路径一致，不入库。

## 范围

约 1,100 个文件、约 11 MB，主要来自：

| 任务 | 目录 |
|---|---|
| MDD-022 | `artifacts/mdd-022/validation/` 的 9 轮验证记录 |
| MDD-026 | 列账本 v2-v9、`column-audit-v10`、`current-source-rerun-20261109`、2026-11-11 两轮证据（definition / members / code-annotation 及其修复轮）、2026-11-12 干净重建（`*-clean-20261112`）与两份合并矩阵的 `merged-matrix.json`、`merge_evidence*.py` |
| MDD-031/033/034 | 缺口闭合、profile 阻断载体、TEMP catalog 与游标契约、取消/回退隔离的原始记录 |

这些目录里仍留着不含本机路径的文件（`SUMMARY.md`、不含路径的 JSON、`.dex` 夹具等），所以单个目录看起来是残缺的，这是有意的。

## 对仓库的影响

- CI 与 `cargo test` 不读取这些文件；唯一被测试依赖的一份已改为 `tests/fixtures/provenance/a0-dex-files-provenance.json`。
- `conformance/facts/` 下的历史审计脚本（`verify.py`、`readback_*.py`、`compile_column_ledger_v*.py` 等）和 `tests/fixtures/dynamic_source_boundary/verify.py` 读取这些记录，在没有本机副本时无法运行。它们不在 CI 里。
- `STATE.md`、各 `SUMMARY.md` 和 `tasks/backlog.json` 中指向这些文件的路径是对本机副本的引用。
- `artifacts/index.json` 只索引实际入库的文件。

## 另见

应用类名同样不入库：HostLab 目录与家族前缀表由运营方以 JSON 文件提供（见 `crates/mdd-facts/src/hostlab/catalog.rs` 与 `examples/surface_summary.rs` 的文件头）。
