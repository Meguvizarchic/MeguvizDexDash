# MDD-026 证据修复：代码/注解关系组（multiplicity）

- 证据目录：`artifacts/mdd-026/evidence-code-annotation-fix-20261111/`
- 生成时间：2026-11-11（UTC）
- 范围：`code_items`(12)、`method_calls`(10)、`annotations`(5)、`annotation_elements`(11)、`annotation_set_entries`(4)、`annotation_directory_entries`(7)、`classes`(8)，共 **57 列**。
- 性质：**只是证据记录，不签发 MDD-026**。`result.json` 中 `task_complete_proven=false`、`profile_admitted=false`、`is_task_gate=false`。

## 1. 本轮修复的两个缺陷

### P0：上一轮“独有键关系不可能出现精确重复行”是假命题

上一轮 SUMMARY 第 74 行称“独有键关系在单 DEX 内不可能出现精确重复行，新建 fixture 也不能改变”。本轮用真实测量推翻该结论：

- 同一份不可变 DEX 被作为两个 scope occurrence 输入（`file_id` 0/1，`content_id` 相同）。
- 对比较输出做 **content 投影（去掉 `file_id`）** 后，两个 occurrence 的行逐字节相同，`exact_duplicate_rows_compared` 立即非 0。
- 逐关系实测（`annotations-duplicate` / `classic-duplicate` / `shared-duplicate`，见 `result.json.measured_facts`）：

| 关系 | full 投影重复行 | content 投影重复行 | 行数 |
|---|---|---|---|
| annotations | 0 | 4 | 8 |
| annotation_elements | 0 | 44 | 88 |
| annotation_set_entries | 0 | 5 | 10 |
| annotation_directory_entries | 0 | 5 | 10 |
| classes | 0 | 1 | 2 |
| code_items（shared） | 0 | 3 | 6 |
| method_calls（shared） | 8 | 12 | 16 |

- 上一轮 `result.json` 里 `slices.annotations.total_exact_duplicate_rows_compared` 非 0 已经说明这一点；本轮把该事实变成逐列可重算的断言。

### P1：`duplicate_collapse` 负控制不再空转

上一轮列级 `negative_controls` 把 `duplicate_collapse` 记成普通字符串（`harness.py:157-158` 实为 `rejected: None`），读起来像“已执行且被拒绝”。本轮：

- 每个 slice 的每个负控制都带 `rejected: true/false` 与 `not_applicable: true/false`。
- 有精确重复行时 `duplicate_collapse` 必须真的改变序列并被拒绝（`rejected=true`）。
- 无精确重复行时显式记 `rejected=null, not_applicable=true, note=...`，不混入“已执行”列表。
- `swapped_order` 也修正为交换第一对**不同**的行；若所有行都相同则记 `not_applicable`。

## 2. 逐列闭合情况

- **55 列满足**（六类全满足）。
- **2 列仍为 partial**：`classes.file_id`、`annotation_elements.file_id`。二者仅 multiplicity 为 partial，其余五类 satisfied。
- 没有 missing 列。

口径说明：7 个关系的 **content 投影**（去 `file_id`）都含精确重复行（见 `result.json.measured_facts`），因此按 `column-audit-v10` 的 relation 级规则（`exact_duplicate_rows > 0` 即 satisfied），全部 7 个关系都可判 satisfied。本目录另外给出**逐列** verdict：该列必须出现在某个含精确重复行的投影中才判 satisfied。两个口径都如实记录，不互相替代。

### 仍缺的 2 列及原因

| 列 | 状态 | 原因 |
|---|---|---|
| `classes.file_id` | partial | 每个 fixture 只有 1 个 class_def；duplicate-content 双 occurrence 中两行只差 `file_id`，任何保留 `file_id` 的投影都不会出现精确重复行。尝试构造“双 class_def 同内容”fixture 被引擎以 `DUPLICATE_CLASS_DEFINITION` 拒绝（`InvalidInput`，见 `slices/explore-duplicate-class/record.json` 与 `explore_duplicate_class.py`），因此该列在现有 fixture 下结构性不可锻炼。 |
| `annotation_elements.file_id` | partial | 每个 encoded value 的 `value_off`/`value_end_off` 在各自 annotation 内唯一；任何保留 `value_off`/`value_end_off` 的投影都不会出现精确重复行。只有额外丢掉 value offset 的投影才有重复行，本轮不把那种投影计入该列的 multiplicity 证据。 |

这两列的 `duplicate_collapse` 均记为 `not_applicable`，并保留 `dropped_row` / `duplicate_row_appended` / `swapped_order` / `null_to_zero:*` 等计数敏感负控制。

### 55 列的 multiplicity 证据

- 非 `file_id` 列：`content` 投影（去 `file_id`）+ duplicate-content 双 occurrence，`exact_duplicate_rows_compared > 0`，`duplicate_collapse rejected=true`。
- `file_id` 列：优先选择**保留该列**且重复行最多的投影：
  - `code_items.file_id`：`shared-code-035.dex` 上两个 method 共用同一 `code_off`，投影去掉 `method_idx` 后得到精确重复行（2 行）。
  - `method_calls.file_id`：full 投影内同一 method 对同一 callee 的重复调用产生精确重复行（8 行）。
  - `annotations.file_id`：投影去掉 `annotation_off`（4 行）。
  - `annotation_set_entries.file_id`：投影去掉 `(annotation_set_off, ordinal)`（2 行）。
  - `annotation_directory_entries.file_id`：投影去掉 `(class_idx, entry_kind, entry_idx)`（4 行）。
- 每列的 `exact_duplicate_rows_compared`、投影名、case、行数、负控制都在 `result.json.columns[].multiplicity` 中；readback 会从 recorded terminals 重算并核对。

## 3. 独立 oracle 与三层证据

| 层 | 来源 | 独立性 |
|---|---|---|
| native | `probe_relations.rs`（本目录），经 rustc 链接 workspace rlib 编译；逐 occurrence 输出 7 关系并带 scope `file_id` | 被验证对象，不充当自身 oracle |
| Python 字节 oracle | `oracle_bytes.py`（本目录）；直接解析 DEX header/map/string_ids/type_ids/class_defs/class_data/code_item/annotation item；method_calls 复用 `tests/fixtures/references/oracle.py`，annotation 复用 `tests/fixtures/annotations/oracle.py`（均为纯 Python stdlib 字节 reader，不 import Rust/mdd/A0，无运行时副作用） | 与 native 无共享代码 |
| A0 | 外部 `dexsql-windows-amd64.exe`，sha256 `f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448` | 第三方 SQL 引擎，对同一输入做第三种枚举 |

- native 与 Python oracle 在 full 投影上做**逐行序列相等**比较（不是 Counter/multiset）。
- A0 对 full / content / key-drop 三种投影分别查询，并与 Python oracle 的同一投影做序列比较。
- 每个 case 的 `content_id`、`dex_occurrence_id`、`file_id` 绑定关系被显式记录；两个 occurrence 内容相同但 `file_id` 不同。

## 4. 使用的源文件 SHA256（关键项）

| 文件 | sha256 |
|---|---|
| conformance/facts/native_probe.rs | 1009199e0bf7016fa91cd0ebd2dc54690765c86a63587553cf88d3cc04ede1e6 |
| conformance/facts/annotation_order_probe.rs | 307f8a0cac9138b8d4069e4effa7d9df74ec8afbaba9b0b6fd1e538301f715bc |
| conformance/manifests/relations.json | f416926d6da3467b5cfea625978c2e4faac08c914cf2930d2c64878c261bb82d |
| tests/fixtures/references/oracle.py | 25c4edf6442ac9013c8f51244d00d190e37ca29dcf1e0bd78e0f99e491b4d1b1 |
| tests/fixtures/annotations/oracle.py | 6a6bcbd430ecd9476bfaf64429f0bed4f1a452f802c683d126dcc4302e9c31fd |
| Cargo.toml | 4c4d63619571e87e67d85457ecda584dc0e23ad3634fb7901caeda81bdcbc571 |
| Cargo.lock | 954c2066815c971595782dc799f9dcd64c4e3d1c748cc1133991788fb3942844 |
| rust-toolchain.toml | b2c19d86958ed6810741488db5cd352856f303c53bcf0ea774e72f94ee4d201e |
| artifacts/mdd-026/evidence-code-annotation-fix-20261111/probe_relations.rs | 9bf88e0d2ab2466f47ede35b52f2bb9aecf156c97d85d034abf131da1dec2be2 |
| artifacts/mdd-026/evidence-code-annotation-fix-20261111/oracle_bytes.py | db7970f48264a93d66f049672feb3aca4f8360aa4b57deaa7d7a940719221911 |
| artifacts/mdd-026/column-audit-v10/audit_six_categories.py | 1ab6083520e6829960819d8d5cff879703c492e9f043814352fd4c4356c6926c |
| A0 dexsql | f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448 |
| probe_relations.exe | 见 `result.json.probe_binary_sha256` |

全部 63 个源文件（含 crates/mdd-{dex,input,types,facts} 全部 .rs）的 SHA256 见 `result.json.sources`；`readback.py` 逐个复核。

Fixture SHA256（9 项）见 `result.json.fixtures`，例如：
`annotations-038.dex=65380a8b…985360`、`classic-035.dex=076dcc64…54dc8`、`shared-code-035.dex=22eb2d40…ec0ab`、`owned-try-even.dex=2ae4c21d…0d8d5`、`owned-try-odd.dex=088fd267…340f2`。

## 5. 证据文件清单

- `probe_relations.rs` / `probe_relations.exe`：统一 native 事实探针（本目录编译）。
- `oracle_bytes.py`：独立 Python 字节 oracle（多 occurrence、content/key-drop 投影）。
- `run_evidence.py`：主 harness，输出 `result.json`。
- `readback.py` / `readback.json`：独立重读 recorded terminals 与 oracle，重算全部断言（`status=passed`，6 case、57 列、0 source drift、0 fixture drift）。
- `explore_duplicate_class.py` / `slices/explore-duplicate-class/`：负探索，证明双 class_def 同内容 fixture 被引擎拒绝。
- `slices/native-<case>/`：native 探针 stdout/stderr/record。
- `slices/a0-<case>-<relation>-{full,content,keydrop}/`：A0 表与 record。
- `result.json`：逐列 verdict、逐 case/relation/投影的重复数与负控制。

## 6. 限制

- 仅小型合成 DEX；未覆盖生产 compatibility provider、完整 HostLab 工作负载、SQL transport、跨平台或性能。
- `classes.file_id`、`annotation_elements.file_id` 在现有 fixture 下无法锻炼 exact-duplicate 保持，已如实记 partial，未用降低标准的投影冒充 satisfied。
- 本目录不修改任何生产代码、共享配置或 `column-audit-v10` / 上一轮证据目录；既有 harness 仅被只读引用。
