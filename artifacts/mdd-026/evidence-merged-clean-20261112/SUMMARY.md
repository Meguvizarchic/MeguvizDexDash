# MDD-026 证据干净重建与合并（2026-11-12）

- 性质：证据记录。**不签发 MDD-026**；`task_complete_proven=false`、`profile_admitted=false`。
- 触发：2026-11-11 第二/三/四轮复审指出两组证据修复的 native 探针与当前源码"同一性不可验证"（exe/rlib 早于对 mdd-facts 的后续修改，且 rlib 文件名是写死的 Cargo 元数据哈希）。

## 做了什么

| 目录 | 内容 |
|---|---|
| `evidence-definition-members-clean-20261112/` | 复制 `evidence-definition-members-fix-20261111` 的 harness；`compile_probe` 不再使用写死的 rlib 文件名，改为运行 `cargo build -p mdd-facts --lib --locked --offline --message-format=json` 并取 cargo 报告的各 crate rlib，构建记录保存在 `evidence/cargo-build-facts-lib/`；`make_fixtures.py` 重新生成合成夹具 |
| `evidence-code-annotation-clean-20261112/` | 复制 `evidence-code-annotation-fix-20261111`；原目录只带一个预编译 `probe_relations.exe`，现新增 `compile_probe()`，同样链接 cargo 报告的 rlib，编译命令保存在 `slices/compile-probe_relations/` |
| `merge_evidence_clean.py` → `evidence-merged-clean-20261112/merged-matrix.json` | 与 `merge_evidence.py` 相同的 v10 严格口径，来源换成两组干净重建；修复一处合并缺陷（见下） |

两组 harness 都在 mdd-facts 当前源码上重新运行，`readback.py` 重读全部终端输出：定义/成员 3,271 项检查 0 失败；代码/注解 57 列、6 个用例、源码与夹具漂移均为空。

## 结果

**重建结果与 2026-11-11 的结果逐列相同**：定义/成员 107 列、代码/注解 57 列，两份 `result.json` 的列集合相同，逐列 `state` 与六类 `categories` 差异为 0，`measured_facts` 相等。也就是说此前"探针与源码同一性不可验证"的担忧没有产生任何不同的结论；现在每个探针都能追溯到 cargo 对当前源码报告的 rlib。

合并矩阵：156 列，**140 列六类全满足**（2026-11-11 为 139），**未装配生产关系列 0**（此前 5）。

## 合并脚本的缺陷（已修）

`merge_evidence.py` 把第一轮 Step-Reviewer 的静态降级表 `DOWNGRADES` 套在所有来源之后，包括重新取证过的修复轮结果。结果是 `class_interfaces.ordinal` 的 order/multiplicity 在矩阵里是 partial，而修复轮用 `two-interfaces.dex`（ordinal 0/1）取到的证据是 satisfied（序列相等、交换相邻行的负控制被拒绝、精确重复行 2 条）。`dex_files.string_pool_id` 的 source/raw_fingerprint 同理。`merge_evidence_clean.py` 现在只在没有修复轮来源重新取证该类别时才应用降级，被取代的 7 条降级记录在 `superseded_reviewer_downgrades`，不删除。2026-11-11 的旧矩阵保留为历史记录，不改写。

## 仍然不满足的 16 列

| 列 | 未满足的类别 | 原因 |
|---|---|---|
| `dex_files.file_id`、`types.file_id`、`methods.file_id`、`classes.file_id`、`class_interfaces.file_id`、`class_fields.file_id`、`class_methods.file_id`、`annotation_elements.file_id` | multiplicity | 每个 occurrence 的 `file_id` 取值唯一，含该列的投影里没有可重复的行；证据记录的原话是"结构上无法对该列锻炼精确重复保留" |
| `dex_files.source_path`、`dex_files.entry_name` | multiplicity | 取值会重复，但没有构造出精确重复行（"精确重复保留未被锻炼"） |
| `dex_files.string_pool_id` | field_type、multiplicity | 探针记录事实层的 Utf8 内容身份，SQL 提供者输出的是 UInt32 occurrence 坐标，后者在 A0 差分里与 A0 相等 |
| `strings.string_pool_id` | field_type | 同上 |
| `methods.param_descriptors`、`methods.opcode_count`、`methods.opcode_hex` | field_type、raw_fingerprint | harness 对这三列静态降级（`GATED_METHODS`），且探针不走 `MethodCodeFactViews::method_rows`；生产路径在 `a0-differential-20261112` 里与 A0 逐值相等，但那份证据没有按类别折算进矩阵 |
| `method_field_accesses.using_type` | null | `using_type` 的 NULL 分支没有 A0 反例 |

最后三类（`string_pool_id` 的 field_type、`methods` 的三列）是矩阵保守而非引擎有问题：差分测试已经覆盖了生产路径。是否把差分证据折算进六类矩阵，需要一个明确的口径决定，本次没有擅自改。

## 没有做的

- `conformance/facts/qualify.py` 仍然在 `tested source drift` 上失败。它钉的是 2026-10-28 冻结的索引组件运行（`artifacts/mdd-026/indexes/runs/20261028…`）的源码哈希和 `required-columns.json` 的哈希，并断言 69 列未装配；这是历史资格文件的生成器，ADR-017 规定历史资格文件保留为当时的限定检查记录。它不在 CI 里。重新签发需要重跑索引组件并出新版生成器，属 MDD-026 收口工作，不在本次范围。
- 未装配列已为 0，但 `conformance/facts/required-columns.json` 里仍写着 69 列，因为它被历史索引运行按哈希钉住，没有改。
