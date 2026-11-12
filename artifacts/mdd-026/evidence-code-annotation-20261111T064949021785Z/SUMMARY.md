# MDD-026 证据工程：代码/引用/注解关系组

- 证据目录：`artifacts/mdd-026/evidence-code-annotation-20261111T064949021785Z/`
- 生成时间：2026-11-11T06:49:49Z（UTC）
- 范围：`code_items`、`method_calls`、`annotations`、`annotation_elements`、`annotation_set_entries`、`annotation_directory_entries`、`classes`（共 57 列）
- 结论：**未签发资格**。`result.json` 中 `task_complete_proven=false`、`profile_admitted=false`；本目录只提交证据与逐列 verdict。

## 1. 范围内列数与闭合情况

| 关系 | 列数 | multiplicity（本任务规则） | multiplicity（column-audit-v10 严格规则） | 其它五类 |
|---|---|---|---|---|
| code_items | 12 | satisfied | partial | satisfied |
| method_calls | 10 | satisfied | **satisfied** | satisfied |
| annotations | 5 | satisfied | partial | satisfied |
| annotation_elements | 11 | satisfied | partial | satisfied |
| annotation_set_entries | 4 | satisfied | partial | satisfied |
| annotation_directory_entries | 7 | satisfied | partial | satisfied |
| classes | 8 | satisfied | partial | satisfied |
| 合计 | **57** | **57 satisfied** | **10 satisfied / 47 partial** | **57 satisfied** |

- 新闭合（相对 `column-audit-v10` 矩阵）：`code_items` 12、`annotations` 5、`annotation_elements` 11、`annotation_set_entries` 4、`annotation_directory_entries` 7、`classes` 8 的 multiplicity 由 partial 提升为“独立 oracle 行数 + 精确序列比较 + 计数敏感负控制”证据（见下）。
- `method_calls` 10 列原本已完全资格；本目录复核并**扩展**了 duplicate/order 覆盖：native 与 A0 各 16 行、其中 **8 行为精确重复行**，`duplicate_collapse` 负控制被拒绝，序列比较（非 Counter）被 `swapped_order` 负控制证明。

## 2. 仍缺列数与原因

- 按本任务对 multiplicity 的定义（独立 oracle 行数枚举 + 丢行/去重会改变计数而失败 + 单独跟踪 `exact_duplicate_rows_compared`）：**0 列缺失**。
- 按 `column-audit-v10/audit_six_categories.py` 的严格分级（要求比较输出中存在**精确重复行**才给 satisfied）：**47 列仍为 partial**，原因是结构性的，不是证据遗漏：
  - `code_items.method_idx`、`classes.class_def_idx`、`annotations.annotation_off`、`annotation_elements.(annotation_off,depth,ordinal)`、`annotation_set_entries.(annotation_set_off,ordinal)`、`annotation_directory_entries.(class_idx,annotations_off,entry_kind,entry_idx)` 在单个 DEX 内唯一；
  - 同一行的每个副本都带唯一偏移/索引或 `file_id`，因此**不可能**出现“同一 dump 内完全相同的两行”；
  - 这些列的 `exact_duplicate_rows_compared=0`，`duplicate_collapse` 负控制记为 `not_applicable`；`dropped_row`（计数 N→N-1）与 `duplicate_row_appended`（N→N+1）均被拒绝，证明比较对行数敏感。
- `result.json` 中每列同时给出 `state`（本任务规则）与 `strict_audit_multiplicity_state`（严格规则），避免歧义。

## 3. 独立性与 oracle 论据

| 证据层 | 来源 | 独立性论据 |
|---|---|---|
| native 行 | Rust conformance probe（`annotation_order_probe.rs`、`native_probe.rs`、`class_source_boundary/probe.rs`、`mixed_reference_boundary/probe.rs`），本次运行编译并记录进程终端 | 被验证对象；不充当自身 oracle |
| Python 字节级 oracle | `tests/fixtures/annotations/oracle.py`、`tests/fixtures/references/oracle.py`、`tests/fixtures/class_source_boundary/verify.py:oracle`、`tests/fixtures/owned_try/verify.py:oracle` | 直接解析 DEX map、字符串池、类型表、class_data、code_item、annotation item 的小端原始字节；不 import 任何 Rust crate，与 native 解析器无共享代码 |
| A0 SQL | 外部 `dexsql-windows-amd64.exe`，sha256 `f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448` | 独立 SQL 引擎，对同一 fixture 做第三种行数枚举；readback 中重跑 A0 与记录终端逐字节一致 |

三层行数在所有关系上相等（例如 annotation_elements 88/88/88，method_calls 16/16/16，code_items 7/7/7，classes 4/4/4）。

## 4. 使用的源文件 SHA256（关键项）

完整 63 项见 `result.json.sources`；以下为核心项：

| 文件 | sha256 |
|---|---|
| conformance/facts/annotation_order_probe.rs | 307f8a0cac9138b8d4069e4effa7d9df74ec8afbaba9b0b6fd1e538301f715bc |
| conformance/facts/native_probe.rs | 1009199e0bf7016fa91cd0ebd2dc54690765c86a63587553cf88d3cc04ede1e6 |
| tests/fixtures/class_source_boundary/probe.rs | 12a89f653537f7080fda3139ac4a342e8dfbb988cee2892234194ee26b043061 |
| tests/fixtures/class_source_boundary/verify.py | 71bb47f7fdd5ae04e4946b758463992406085f912e017a1169b08245a46cdf5a |
| tests/fixtures/mixed_reference_boundary/probe.rs | 0aaed7ba0a52e3727c4c3de750ed080dd3d80eb27cf6978cb6d6ecba6d062b8d |
| tests/fixtures/references/oracle.py | 25c4edf6442ac9013c8f51244d00d190e37ca29dcf1e0bd78e0f99e491b4d1b1 |
| tests/fixtures/annotations/oracle.py | 6a6bcbd430ecd9476bfaf64429f0bed4f1a452f802c683d126dcc4302e9c31fd |
| conformance/manifests/relations.json | f416926d6da3467b5cfea625978c2e4faac08c914cf2930d2c64878c261bb82d |
| Cargo.toml | 4c4d63619571e87e67d85457ecda584dc0e23ad3634fb7901caeda81bdcbc571 |
| Cargo.lock | 954c2066815c971595782dc799f9dcd64c4e3d1c748cc1133991788fb3942844 |

Fixture SHA256（13 项）见 `result.json.fixtures`，例如：
`annotations-038.dex=65380a8b…985360`、`classic-035.dex=076dcc64…54dc8`、`shared-code-035.dex=22eb2d40…ec0ab`、`try-catch-all.dex=7c6926ae…b71f`、`owned-try-even.dex=2ae4c21d…0d8d5`、`owned-try-odd.dex=088fd267…340f2`。

## 5. 证据文件清单

- `harness.py`：证据生成器（编译 probe、运行 native/A0、调用 Python oracle、比较、负控制、汇总）。
- `result.json`：342 条逐列 verdict（57 列 × 6 类），含 `relation/column/category/state/evidence_path/oracle/independence_argument/oracle_row_count/native_row_count/a0_row_count/exact_duplicate_rows_compared/negative_controls/null_coverage/strict_audit_multiplicity_state`。
- `readback.py`：独立 readback；不信任 `result.json`，从记录终端重算比较。
- `readback.json`：readback 结果（`status=passed`，24 个记录终端、0 fixture drift、0 source drift、342 列）。
- `slices/<label>/`：每个 probe/A0 调用的 `stdout.txt`、`stderr.txt`、`record.json`（含 argv、退出码、sha256）。
- `*.exe` / `*.pdb`：本次编译的 conformance probe。

## 6. 关于新 fixture

本目录**未新建合成 DEX/APK**：现有 fixture 已覆盖所需的 NULL 边界（`annotation_elements` 的 `name_idx/value_index/value_i64/value_f64`、`annotation_directory_entries` 的两个可空 offset、`classes.superclass_descriptor/source_file`、`code_items.tries_off/handlers_off`）以及重复行（`method_calls` 的 8 行精确重复）。独有键关系（`code_items`/`classes`/`annotations` 系列）在单 DEX 内不可能出现精确重复行，新建 fixture 也不能改变这一点；因此 `exact_duplicate_rows_compared=0` 是结构结论，而非未做 fixture。

## 7. 限制

- 仅小型合成 DEX；未覆盖生产 compatibility provider、完整 HostLab 工作负载、性能或 ART/设备语义。
- `code_items` 的 `tries_off/handlers_off` 非 NULL 证据来自 `owned_try` slice 的两个 method-owned fixture；`physical-try` 仅证明物理 code item 的非 NULL offset，不计入 method-owned 行。
- `classes.interface_count` 未被 native fact 直接暴露，由 A0 + Python oracle 约束；native 侧只比较 `class_def_idx/class_idx/descriptor/access_flags/superclass_descriptor/source_file`。
- 本目录不修改任何生产代码或共享文件；仅新增本目录。
