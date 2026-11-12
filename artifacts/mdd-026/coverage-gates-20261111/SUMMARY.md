# MDD-026 coverage 列门闭合（2026-11-11）

## ⚠️ Step-Reviewer 第三轮更正（主代理应用）

1. **「闭合 6 关系虚假完成路径」的表述不成立。** 门在生产 `evaluate()` 路径**无可观测行为变化**：
   - 门会拒的列（未知列、未装配列）在到达门之前就已被 spec 查找（`coverage.rs:943`）与 `assembled_projection` 检查（`:739`）拒绝；
   - provider 缺失被 `layer_state` 抢先；`code_items` 的 `code_layout_coverage` 分支被 AllMethodBodies 层抢先；
   - 更根本的是 **`required_columns` 在所有生产代码中恒为空**（`CoverageRequest::for_scope` 置空，`:65`），整条 `column_state` 路径目前仅测试可达。
   因此本轮**唯一真实的行为修复是非标量扩展**；门目前是防御性/前瞻的（待 `required_columns` 被生产填充、或 provider 门获得作用域拒绝时才显效）。
2. **`dex_files.source_path`/`entry_name` 的行为表已更正**：改动前就是 `Unknown`（`assembled_projection=false`），非本轮变化。
3. **集成测试计数已更正**：实为 20（非 25）。
4. **`coverage.rs` 的注释已更正**：原称「每个有投影的关系都被门覆盖」，对 7 个兜底关系（`class_interfaces`/`class_fields`/`class_methods`/`annotation_directory_entries`/`annotation_set_entries`/`annotations`/`annotation_elements`）为假；现注释已列出这 7 个并说明今日结果相同的原因。
5. `method_strings.value` 的越界处理由 panic 改为 Unknown（`.get()` 取代直接索引）——符合「不能证明即不 Complete」的契约。

## 结论

`FrozenProjection` 列求值不再对 6 个新装配关系无条件返回 `Ok(())`。`dex_files`、
`strings`、`types`、`methods`、`classes`、`code_items` 现在各自咨询其行投影
provider 的 `require_relation_columns`；门拒绝或 provider 对象缺失都报
`Unknown`。非标量 UTF-16 特判从只覆盖 `method_strings.value` 扩展到
`strings.value` 与 `classes.source_file`。

本交付只闭合 coverage 门与测试，不改变任何 relation 的装配范围，也不签发
admitted / task_complete_proven / profile。

## 问题（Step-Reviewer 第二轮 S4）

改动前 `column_state` 的匹配只有 4 个臂：

```rust
"method_strings" | "method_calls" | "method_field_accesses" | "method_used_types" => gate,
_ => Some(Ok(())),   // ← 6 个新关系落在这里
```

后果是：只要 view 存在、层状态为 Complete，`strings.value`、`dex_files.byte_len`、
`code_items.code_off` 等 64 列一律报 `Complete`，从不向真正的投影实现求证。
`classes.source_file` 与 `strings.value` 在含合法非标量字符串的 scope 上投影会返回
`UnsupportedQuery`，而 coverage 仍报 Complete —— 即虚假完成路径。

## 实现

### 1. 六关系门接线（`crates/mdd-facts/src/coverage.rs`）

新增 `CoverageLedger::frozen_provider_gate(view, spec) -> Option<Option<MddResult<()>>>`：

| 关系 | 咨询的 provider 门 |
|---|---|
| `dex_files` | `MetadataFacts::require_relation_columns(MetadataRelation::DexFiles)` |
| `strings` | `MetadataFacts::require_relation_columns(MetadataRelation::Strings)` |
| `types` | `MetadataFacts::require_relation_columns(MetadataRelation::Types)` |
| `methods` | `DefinitionFacts::require_relation_columns(DefinitionRelation::Methods)` |
| `classes` | `DefinitionFacts::require_relation_columns(DefinitionRelation::Classes)` |
| `code_items` | `require_code_item_columns`（与 `MethodCodeFactViews::require_relation_columns` 同一实现） |

返回值语义：
- 外层 `None`：该关系仍由 coverage 自己的匹配臂处理（4 个引用关系）。
- 内层 `Some(Ok(()))`：门通过 → `Complete`。
- 内层 `Some(Err(e))`：门拒绝 → `Unknown` + reason `column_gate_rejected_required_scope` + 携带 provider 原始错误。
- 内层 `None`：provider 对象未构建 → `Unknown` + reason `column_provider_not_built`。

`code_items` 额外要求 `view.definitions` 与 `view.code` 同时存在且
`code_layout_coverage == Complete`：行投影由 `MethodCodeFactViews::build` 支撑，
仅凭列名检查不足以证明可投影。

### 2. 抽出 `require_code_item_columns`（`crates/mdd-facts/src/code.rs`）

`MethodCodeFactViews::require_relation_columns` 的行内列名循环抽成模块级
`pub fn require_code_item_columns(&[&str]) -> MddResult<()>`，原方法委托给它。
这样 coverage 不必为每个列重建 method/code join 就能复用同一拒绝契约。
`*` 与 12 个装配列通过；其他列名返回 `InvalidArgument`。

### 3. 非标量特判扩展（`CoverageLedger::non_scalar_text_gap`）

| 列 | 扫描范围 | reason |
|---|---|---|
| `method_strings.value` | `TargetKind::String` 的引用站点目标（既有行为，改为 `.get()` 越界安全） | `non_scalar_UTF16_cannot_be_plain_UTF8` |
| `strings.value` | 该 occurrence 的每个 `StringFact` | 同上 |
| `classes.source_file` | 该 occurrence 每个 `DefinitionFacts` class 的 `Some(source_file)` | 同上 |

`classes.source_file` 为 NULL（encoded NO_INDEX）不算缺口，仍报 Complete —— 测试用
`null-source.dex` 固定该语义。

## 行为变化

| 场景 | 改动前 | 改动后 |
|---|---|---|
| 6 关系任取一列，view 存在 | `Complete`（从不求证） | 门通过 → `Complete`；门拒绝 → `Unknown` + provider 错误 |
| `methods.param_descriptors` / `opcode_*` | `Complete` 或提前被层状态拦截 | `Unknown`，reason `frozen_relation_projection_not_assembled`（既有行为保持） |
| `dex_files.source_path` / `entry_name` | `Unknown`，reason `frozen_relation_projection_not_assembled`（**改动前就如此**，非本轮行为变化） | 同上 |
| `strings.value`，scope 含合法非标量 | `Complete`（虚假） | `Unknown`，reason `non_scalar_UTF16_cannot_be_plain_UTF8` |
| `classes.source_file`，scope 含非标量源码名 | `Complete`（虚假） | 同上 |
| 4 个引用关系 | 走各自 `ReferenceFacts::require_relation_columns` | 不变 |

## 测试

新增 `crates/mdd-facts/src/coverage.rs::coverage_column_gate_tests`，8 个测试：

1. `assembled_relations_report_complete_when_gates_accept` — 6 关系各 3 列，门通过时报 Complete 且无 issue。
2. `six_relation_gates_accept_and_reject_through_their_provider` — 每个关系已知列 `Some(Some(Ok))`，未知列 `Some(Some(Err(InvalidArgument)))`，证明「落到 `_ => Ok`」的路径已不存在。
3. `provider_gate_rejection_reports_unknown_with_provider_error` — 未装配列保持 `frozen_relation_projection_not_assembled`；6 关系未知列经 `column_state` 得到 `column_gate_rejected_required_scope` 且携带 provider 错误。
4. `missing_provider_object_is_unknown_not_complete` — 仅 metadata 视图下 methods/classes/code_items 报 Unknown，dex_files/strings 仍 Complete。
5. `non_scalar_text_columns_are_not_reported_complete` — `nonscalar-string-035.dex`：`string_rows` 确实返回 `UnsupportedQuery`，coverage 对 `strings.value` 报 Unknown，同关系 `string_idx` 仍 Complete。
6. `non_scalar_class_source_file_is_not_reported_complete` — `surrogate-source.dex`：`class_rows` 返回 `UnsupportedQuery`，coverage 报 Unknown；`null-source.dex` 仍 Complete。
7. `reference_relations_keep_their_gate_behaviour` — 4 个引用关系通过、未知列 Unknown、无 reference facts 时 Unknown。
8. `code_items_requires_complete_code_layout` — 空 offsets 的 code 投影下 code_items 非 Complete；`require_code_item_columns` 拒绝未知列、接受 `COLUMN` 全集与 `*`。

## 验证

```
cargo test --offline -p mdd-facts              # 133 lib + 20 集成 + 5 doctest 全通过
cargo clippy --offline -p mdd-facts --all-targets -- -D warnings   # 0 警告
cargo check --offline -p mdd-query -p mdd-sql  # 下游编译通过
```

`readback.json` 由 `readback.py` 重新运行上述 8 个测试生成，记录测试退出码、
门接线表、非标量特判范围与两个源文件的 sha256。

## 未做 / 仍缺

- 未改 `crates/mdd-facts/src/lib.rs` 的 pub mod 列表（无需改：`require_code_item_columns` 位于既有 `code` 模块，未新增模块）。
- 未改 `Cargo.toml` / `Cargo.lock` / `STATE.md` / `tasks/backlog.json` / 其他 crate。
- 未把 `param_descriptors` / `opcode_count` / `opcode_hex` / `source_path` / `entry_name` 转为装配列 —— 那是层所有权与资格签发问题（MDD-032 / inventory 层），不在本任务范围。
- **仍有同类缺陷未闭合（本任务范围之外，建议单独开条目）**：`_ => Some(Ok(()))`
  兜底臂（`coverage.rs:803`）目前仍承接 7 个 relation：
  `class_interfaces`、`class_fields`、`class_methods`、`annotation_directory_entries`、
  `annotation_set_entries`、`annotations`、`annotation_elements`。
  它们都已有 `assembled_projection=true` 的列，但对应 provider 门
  （`DefinitionFacts::require_relation_columns(ClassInterfaces/ClassFields/ClassMethods)`
  与 `AnnotationFacts::require_relation_columns(AnnotationRelation::*)`）尚未接到 coverage。
  本次按任务清单只闭合 6 个关系，未顺手扩面。
- 已知遗留（非本次范围，未被本改动覆盖）：`StringRow` 序列化含契约外键 `file_id`，`assert_contract_projection` 不检查额外键。此条来自 Step-Reviewer 第 2 点，机制未变。
- `profile_admitted` 恒为 `false`；本交付不构成任何准入结论。
