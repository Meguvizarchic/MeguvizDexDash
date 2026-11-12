# MDD-026 coverage 兜底关系门闭合（2026-11-11）

承接 `artifacts/mdd-026/coverage-gates-20261111`。上一轮明确遗留了 7 个兜底关系
（`_ => Some(Ok(()))`）和「`required_columns` 生产恒空」两处未闭合。本轮闭合这两处。

本交付只改 `crates/mdd-facts/src/**`，不签发 admitted / task_complete_proven /
profile，`profile_admitted` 仍恒为 `false`。

## 1. 七个兜底关系门接线结果

改动前：

```rust
let result = match spec.relation {
    "method_strings" => …,
    "method_calls" => …,
    "method_field_accesses" => …,
    "method_used_types" => …,
    _ => Some(Ok(())),   // ← 7 个关系落在这里，无门即 Complete
};
```

改动后 `frozen_provider_gate` 多 7 个臂，每个关系只咨询自己的 provider：

| 关系 | 门 | provider |
|---|---|---|
| `class_interfaces` | `DefinitionRelation::ClassInterfaces` | `view.definitions` |
| `class_fields` | `DefinitionRelation::ClassFields` | `view.definitions` |
| `class_methods` | `DefinitionRelation::ClassMethods` | `view.definitions` |
| `annotation_directory_entries` | `AnnotationRelation::DirectoryEntries` | `view.annotations` |
| `annotation_set_entries` | `AnnotationRelation::SetEntries` | `view.annotations` |
| `annotations` | `AnnotationRelation::Annotations` | `view.annotations` |
| `annotation_elements` | `AnnotationRelation::Elements` | `view.annotations` |

同时把 `_ => Some(Ok(()))` 改成 `_ => None`，于是任何未映射关系落到既有的
`column_provider_not_built` 分支报 **Unknown**，而不是 Complete。

覆盖完整性由测试断言保证：遍历 `column_specs()` 的 17 个 relation，凡不属 4 个
`method_*` 的，`frozen_provider_gate` 都必须返回 `Some(...)`。

### 有意义的行为变化 vs 今日等价

**今日 verdict 不变**：这 7 个关系的 spec 列集合与各自 provider 的 `available`
完全一致，未知列在 `evaluate` 里早就被 `column_specs()` 查找失败拦掉、未装配列被
`assembled_projection` 检查拦掉，provider 缺失被 `layer_state` 抢在列门之前。

**真正的变化**是 remove 了「无门即 Complete」这条路径本身：

| 场景 | 改动前 | 改动后 |
|---|---|---|
| 7 关系任一已装配列，provider 接受 | Complete | Complete（相同） |
| 7 关系任一列，provider 拒绝 | 不可能发生（无门） | Unknown + provider 原始错误 |
| 7 关系任一列，provider 对象缺席 | 层状态先报 Unknown；若层状态 Complete 则 Complete（虚假） | Unknown，绝不 Complete |

## 2. `required_columns` 生产填充：结论与影响面

### 结论

`for_scope` **保持置空**，另加显式生产入口。理由如下。

若让 `for_scope` 按 layer 自动展开列，会把 `SnapshotFactIndex` 内部 30 处
`require(FactLayer::X)`（以及 mdd-query `ScopedCatalog` 的 `for_scope` 调用）全部
升级成列门。而 `dex_files.source_path` / `entry_name` / `methods.param_descriptors` /
`methods.opcode_count` / `opcode_hex` 是已知未装配列，直接后果是：原本 Complete 的
Metadata / Definitions / CodeProjection 层在现有生产路径上变成 Unknown。这是语义
扩大，会影响索引构建与 scoped 查询的门槛，风险与授权范围都不成立。

### 实现（保守版，显式请求才填）

- `CoverageRequest::for_relations(scope, relations) -> MddResult<Self>`：从冻结
  schema 为给定关系填充**全部**列（含 5 个未装配列，语义是「证明整个关系」），并
  把拥有这些列的 fact layer 一并放进 `required_layers`。未知关系返回
  `InvalidArgument`，不静默当空集。
- `SnapshotFactIndex::coverage_for_relations(&self, relations) -> MddResult<CoverageReport>`：
  生产入口，返回 report 而不强制 `require_complete`，由调用方决定是否阻断。
- `native_column_layers` 的实体下沉为模块级 `column_layers(relation, column)`，
  由 request 构造与 `column_state` 共用，避免两套映射漂移。

### 影响面

| 路径 | 是否受影响 |
|---|---|
| `SnapshotFactIndex::require(layer)`（crate 内 30 处） | 否，`for_scope` 仍无列 |
| mdd-query `ScopedCatalog` 的 coverage 评估 | 否，仍用 `for_scope` |
| `coverage_cache` 命中判定（要求列为空） | 否，新入口天然不进缓存 |
| 显式调用 `coverage_for_relations` / `for_relations` 的调用方 | 是，新增列门 |

回归测试把两种语义并排钉住：
`relation_request_fills_columns_and_scope_request_stays_layer_only`。

### 未接线说明

`coverage_for_relations` 目前**只有 crate 内测试可达**。mdd-query / mdd-sql 接线
需要修改其他 crate，本任务硬约束禁止。跨 crate 接线需主代理在授权范围内决定。

## 3. 一个必须记录的优先级事实

provider 对象缺席时，列门不是第一道防线。`column_state` 先求 `layers`
（`column_layers` → `layer_state`），view 缺 annotations/definitions 时
`layer_state` 已返回 Unknown + `required_fact_scope_not_built`，列门不会被咨询。

测试最初按「provider 缺失应报 `column_provider_not_built`」写，被真实行为推翻后
改为断言真实优先级。这很重要：如果只依赖列门来兜 provider 缺失，是错的假设；
两条路径都只能是 Unknown。

## 4. 测试清单

新增 4 个测试（前 3 个在 `coverage.rs::coverage_column_gate_tests`，第 4 个在
`indexes::tests`）：

1. `seven_fallback_relations_are_gated_by_their_own_provider`
   - 7 关系各一个已知列 → `frozen_provider_gate` 返回 `Some(Some(Ok))`
   - 7 关系各一个 `invented_column` → `Some(Some(Err(InvalidArgument)))`
   - 无 provider 视图 → `Some(None)`
   - 全 schema 扫描：除 4 个 `method_*` 外无关系缺门
2. `seven_fallback_relations_reject_and_report_gap_through_evaluate`
   - 7 关系未知列经 `column_state` → Unknown + `column_gate_rejected_required_scope`
     + provider 的 `InvalidArgument`
   - provider 缺席 → Unknown + `required_fact_scope_not_built`（真实优先级）
3. `relation_request_fills_columns_and_scope_request_stays_layer_only`
   - `for_scope` 列仍空；`for_relations` 列数 == schema 计数、domain 全
     `FrozenProjection`、`required_layers` 含 Definitions 与 Annotations
   - 未知关系 → `InvalidArgument`
   - 生产 `evaluate`：provider 齐备 → Complete；去掉 annotations → Unknown，
     且只有 4 个 annotation 关系报列 issue、3 个 class 关系不受影响
4. `coverage_for_relations_fills_columns_and_uses_the_provider_gate`（生产路径可达性）
   - 经 `SnapshotFactIndex::coverage_for_relations` 走完整填充
   - 仅 definitions 视图：`Annotations` 层 Unknown + 27 个 annotation 列 issue，
     3 个 class 关系仍 Complete，`require_complete` 报 `IncompleteFacts`
   - 加回 annotations：全部 Complete
   - 未知关系 → `InvalidArgument`

既有 8 个 coverage 门测试保持通过（含非标量 UTF-16 特判、`code_items` 布局要求、
4 个引用关系行为不变）。

## 5. 验证

```
cargo test --offline -p mdd-facts
  → 137 lib + 10 + 1 + 6 + 3 + 1 + 4 集成/doctest 全通过
cargo clippy --offline -p mdd-facts --all-targets -- -D warnings
  → exit 0，无警告
cargo check --offline -p mdd-query -p mdd-sql
  → exit 0
```

`test-record.json` 由 `build_test_record.py` 生成，`readback.json` 由 `readback.py`
重新运行 lib 测试后生成；两者都记录实际退出码、门接线表、request 语义对照与源文件
sha256。

### 一次非本改动的失败（已复跑通过）

首次 `downstream_check` 因 `crates/mdd-session` 编译失败（`CursorEntry` 缺
`page_schema_id` 等字段、随后一次是借用冲突）。该 crate 是工作区内他人未提交的
WIP（`git status` 显示 `M lib.rs` + 未跟踪 `catalog.rs`/`cursors.rs`），不在本任务
改动范围。复跑时已可编译。此条记录用于避免把并发编辑误读为本改动的回归。

## 6. 未做 / 仍缺

- 未把 5 个未装配列（`dex_files.source_path`/`entry_name`、
  `methods.param_descriptors`/`opcode_count`/`opcode_hex`）转为装配列 —— 层所有权
  与资格签发问题（MDD-032 / inventory 层），不在本任务范围。
- 未改 `for_scope` 语义（理由见 §2）。
- 未在 mdd-query / mdd-sql 接线 `coverage_for_relations`（禁止改其他 crate）。
- 未改 `crates/mdd-facts/src/lib.rs` 的 pub mod 列表：本轮无新增模块，
  `require_code_item_columns` 位于既有 `code` 模块，新函数都在既有 `coverage` /
  `indexes` 模块内。
- 已知遗留（非本次范围）：`StringRow` 序列化含契约外键 `file_id`，
  `assert_contract_projection` 不检查额外键。
- 未签发任何准入结论。
