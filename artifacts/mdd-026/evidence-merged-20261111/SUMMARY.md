# MDD-026 证据合并结果（2026-11-11，含第二轮修复）

## 结论

| 指标 | v10 基线 | 第一轮后 | **第二轮后** |
|---|---:|---:|---:|
| 六类全满足列 | 10 | 77 | **139** |
| multiplicity satisfied / partial / missing | 19 / 97 / 40 | 78 / 78 / 0 | **144 / 12 / 0** |
| order satisfied | 106 | 155 | 155 |
| null missing | 9 | 1 | 1 |
| 未装配生产关系列 | 69 | 69 | **5** |

- 合并脚本：`artifacts/mdd-026/merge_evidence.py`（只读来源目录与 `indexes/columns.rs`）
- 矩阵：`merged-matrix.json`
- **口径**：multiplicity 一律采用 v10 严格规则（必须有 `exact_duplicate_rows_compared > 0`）。
- **来源顺序**：第一轮三组 → 第二轮修复两组（`definition_members_fix`、`code_annotation_fix`），后者覆盖前者对相同列的判定；`production_projection` 从 `crates/mdd-facts/src/indexes/columns.rs` 的 `assembled_projection` 现读。

## 来源目录

| 目录 | 范围 | 严格口径闭合 |
|---|---|---:|
| `evidence-definition-20261111T064943119769Z` | dex_files/strings/types/classes/class_interfaces + header/cross_dex | 39 |
| `evidence-members-20261111T064757Z` | methods/class_fields/class_methods/method_strings/method_field_accesses/method_used_types | 28 |
| `evidence-code-annotation-20261111T064949021785Z` | code_items/method_calls/annotations/annotation_*/classes | 10 |
| `evidence-definition-members-fix-20261111` | 同上 definition/members，修复 7 项 | 92 |
| `evidence-code-annotation-fix-20261111` | 同上 code/annotation，修复 P0/P1 | 55 |
| `assembly-relation-projections-20261111` | 6 个契约关系的行投影 API（代码） | 64/69 列装配 |

55 + 92 = 147，减去两组重叠的 `classes` 8 列 = **139**，与矩阵一致。

## Step-Reviewer（2026-11-11）认定并处理的降级/修正

**第一轮后降级 7 处**（`class_interfaces.ordinal` 的 order/multiplicity、`dex_files.string_pool_id` 三类、`methods.param_descriptors` 两类）——第二轮修复已就 `ordinal`、`string_pool_id`、`param_descriptors` 重新给出证据，但 `class_interfaces.ordinal` 的 order/multiplicity 仍因 ordinal 未被真实锻炼而保持 partial。

**第二轮 Reviewer 认定的问题（已修正或标注）**：
- 装配轮「5 列因真实 fact 层缺口」定性错误 → 已改为「2 列层所有权缺口 + 3 列分层边界与资格门槛」（见装配目录 `SUMMARY.md` 的更正节）。
- 装配轮 readback 只比 11/14 methods 列、dex_files 只比 2 个常量列 → 已披露。
- `assembled_projection` 旗标被 `coverage.rs` 消费，翻旗会改变 coverage 判定（64 列 Unknown → Complete），**无覆盖侧验证、无测试**；`strings.value`/`classes.source_file` 在含非标量字符串的 scope 上存在虚假 Complete 路径（`nonscalar-string-035.dex` 现成未用）。
- 两组证据修复的 native 探针与当前源码**同一性不可验证**（exe/rlib 早于并行轮次对 mdd-facts 的修改，且无编译终端）→ 需在独占时段用干净构建重跑。
- `evidence-definition-members-fix` 的「A0 序列相等 104/104」不成立（10/104 与 native 发射序不同，因引擎不消费 ORDER BY）。
- `methods` 的 11 个 satisfied 列走的是探针组装而非引擎 `method_rows()`，只覆盖取值不覆盖关系投影。

## 关键限制（不变）

- **5 列仍未装配**：`dex_files.source_path`、`dex_files.entry_name`（provenance 属 inventory 层）、`methods.param_descriptors`、`methods.opcode_count`、`methods.opcode_hex`（分层边界与资格门槛，按台账属 MDD-032）。
- HostLab 工作负载、SQL 传输、私有输入、生产 profile 仍未资格。
- **因此本矩阵不能签发 MDD-026 的「事实层完整性」**，更不可能支撑 MDD-082。
- `task_complete_proven=false`、`profile_admitted=false`。

## 相对最可信的部分

`method_calls`(10)、`method_strings`(8)、`method_used_types`(9)、`method_field_accesses`(11)、`annotation_directory_entries`(7)、`annotations`(5)、`annotation_set_entries`(4)、`code_items`(12) —— 重复行真实、负控制真被拒绝、空转显式标注、有独立 Python 字节 oracle 与 A0 三方交叉核验。
