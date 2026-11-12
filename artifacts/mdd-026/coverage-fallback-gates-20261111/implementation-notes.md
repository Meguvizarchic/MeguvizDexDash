# MDD-026 coverage 兜底关系门闭合 — 实现说明（2026-11-11）

范围：只改 `crates/mdd-facts/src/coverage.rs`、`crates/mdd-facts/src/indexes/mod.rs`、
`crates/mdd-facts/src/indexes/tests.rs`。未改 `lib.rs` 的 `pub mod` 列表（无新增模块），
未改 `Cargo.toml` / `Cargo.lock` / `STATE.md` / `tasks/backlog.json` / 其他 crate，
未引入新依赖。

## 1. 七个兜底关系接门

改动前 `column_state` 的列求值有两条信息源：`frozen_provider_gate` 覆盖 6 个关系，
其余落到 `_ => Some(Ok(()))` —— 无门即 Complete。风险不是今天的列名不匹配，而是
provider 未来获得作用域感知拒绝时 coverage 不会反映。

改动后：

1. `frozen_provider_gate` 新增 7 个臂，每个关系只咨询**自己的** provider：

| 关系 | 咨询的 provider 门 |
|---|---|
| `class_interfaces` | `DefinitionFacts::require_relation_columns(DefinitionRelation::ClassInterfaces)` |
| `class_fields` | `DefinitionFacts::require_relation_columns(DefinitionRelation::ClassFields)` |
| `class_methods` | `DefinitionFacts::require_relation_columns(DefinitionRelation::ClassMethods)` |
| `annotation_directory_entries` | `AnnotationFacts::require_relation_columns(AnnotationRelation::DirectoryEntries)` |
| `annotation_set_entries` | `AnnotationFacts::require_relation_columns(AnnotationRelation::SetEntries)` |
| `annotations` | `AnnotationFacts::require_relation_columns(AnnotationRelation::Annotations)` |
| `annotation_elements` | `AnnotationFacts::require_relation_columns(AnnotationRelation::Elements)` |

`class_*` 的 provider 是 `view.definitions`；四个 annotation 关系的 provider 是
`view.annotations`（`AnnotationFacts` 自己持有 `DefinitionFacts` 克隆，因此不带
annotations 的 view 不应借用 definitions 的列集合）。两条关系族各写独立臂而不是
共享 `expect`，避免「关系臂没绑到 relation 变体」的 panic 路径。

2. `column_state` 的 `_ => Some(Ok(()))` 改为 `_ => None`，于是走既有的
   `column_provider_not_built` 分支报 Unknown。现在 17 个关系里，除 4 个
   `method_*` 引用关系（在下方 inline 门处理）外，全部由 `frozen_provider_gate`
   返回 `Some(...)`；没有任何关系在 `assembled_projection == true` 且 provider
   缺席时还能报 Complete。

新增测试 `seven_fallback_relations_are_gated_by_their_own_provider` 把这一点做成
断言：遍历 `column_specs()` 的全部 relation，凡不是 4 个 `method_*` 的，都必须让
`frozen_provider_gate` 返回 `Some`，否则列名集合非空即失败。

## 2. `required_columns` 的生产填充

### 判断

`for_scope` 保持置空是**正确**的：`required_layers` 只声明「这些层要完整」，不能
推断「该层的每个关系列都可投影」。若让 `for_scope` 按 layer 自动展开列，会把
`require(FactLayer::Metadata)` 这类索引构建门（`SnapshotFactIndex` 内部 30 处调用、
mdd-query scoped 路径）全部升级成列门，其中 `dex_files.source_path` /
`entry_name` / `methods.param_descriptors` / `methods.opcode_*` 是已知未装配列，
会让现有 Complete 的层变成 Unknown —— 属于语义扩大，超出本任务授权。

因此采用**保守且显式**的方案：新增独立生产入口，不改变 `for_scope` 的语义。

### 实现

- `CoverageRequest::for_relations(scope, relations) -> MddResult<Self>`（coverage.rs）：
  从冻结 schema（`column_specs()`）为给定关系填充**全部**列，并把拥有这些列的
  fact layer 一并放进 `required_layers`。未知关系返回 `InvalidArgument`，不静默
  匹配空集。
  未装配列（`dex_files.source_path`/`entry_name`、`methods.param_descriptors`/
  `opcode_count`/`opcode_hex`）**故意包含**：语义是「证明这个关系」，有关系级缺口
  就必须 Unknown，不能悄悄收窄成已装配子集。
- `SnapshotFactIndex::coverage_for_relations(&self, relations) -> MddResult<CoverageReport>`
  （indexes/mod.rs）：把上面的 request 绑定到已构建的 ledger 上执行，返回 report
  而不强制 `require_complete`，让调用方决定是否阻断。
- `native_column_layers` 的实体下沉为模块级 `column_layers(relation, column)`，
  由 `CoverageRequest::for_relations` 与 `column_state` 共用，避免两处映射漂移。

### 影响面

`for_scope` 行为零变化（仍 `required_columns = Vec::new()`），因此：

- `SnapshotFactIndex::require(layer)` 与 mdd-query `ScopedCatalog` 的
  `CoverageRequest::for_scope` 路径完全不变；
- `coverage_cache` 的 cacheable 判定（要求 `required_columns.is_empty()`）不受影响，
  新入口天然不进缓存（每次请求列集合不同）；
- 只有显式调用 `coverage_for_relations` / `for_relations` 的调用方才进入列门。

回归测试 `relation_request_fills_columns_and_scope_request_stays_layer_only`
把两种语义并排钉住：`for_scope` 的 `required_columns` 为空且同 scope 下
Definitions 层报 Complete；`for_relations` 的列数等于 schema 计数、domain 全为
`FrozenProjection`、`required_layers` 同时含 Definitions 与 Annotations。

## 3. 一个必须说清的优先级事实

provider 缺席时，**列门不是第一道防线**：`column_state` 先求 `layers`
（`native_column_layers` → `layer_state`），view 缺 annotations/definitions 时
`layer_state` 已经返回 `Unknown` + `required_fact_scope_not_built`，列门根本不会被
咨询。测试最初按「provider 缺失应报 `column_provider_not_built`」写,被真实行为
推翻后改为断言真实优先级（`required_fact_scope_not_built`），并保留一条断言说明
两条路径都只能是 Unknown、不会 Complete。

这意味着：`column_provider_not_built` 只在「层状态 Complete 但列门要的 provider
对象不在 view 里」这种刻意构造下可达（见
`seven_fallback_relations_are_gated_by_their_own_provider` 里对
`frozen_provider_gate` 直接调用的 `Some(None)` 断言）。

## 4. 未做

- 未把 5 个未装配列转为装配列（层所有权/资格签发问题，不在本任务范围）。
- 未改 `for_scope` 语义（见上，风险过大且非授权）。
- 未在 mdd-query / mdd-sql 接线调用 `coverage_for_relations`（禁止改其他 crate）。
  新入口目前只有 crate 内测试可达；跨 crate 接线需要主代理在授权范围内决定。
- 未签发 admitted / task_complete_proven / profile；`profile_admitted` 恒为 false。
