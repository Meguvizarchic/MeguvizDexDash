# 实现说明

## 改动文件

| 文件 | 变更 |
|---|---|
| `crates/mdd-facts/src/coverage.rs` | 新增 `frozen_provider_gate`、`non_scalar_text_gap`；`column_state` 接入门；新增 `coverage_column_gate_tests` 模块（8 测试） |
| `crates/mdd-facts/src/code.rs` | 抽出 `pub fn require_code_item_columns`；`MethodCodeFactViews::require_relation_columns` 委托给它 |

未新增模块，因此 `crates/mdd-facts/src/lib.rs` 的 pub mod 列表无需改动。
`require_code_item_columns` 是 `code` 模块内的既有 `pub` 可见性风格，不需要在
`lib.rs` 里 re-export（现有 `CodeItemRow`/`CodeRelation` 也未 re-export）。

## coverage 求值顺序（改动后）

`FrozenProjection` 域内，`column_state` 依次判断：

1. 层状态（`native_column_layers` + `layer_state` 聚合）。非 Complete 直接返回，携带层证据。
2. `!spec.assembled_projection` → `Unknown` / `frozen_relation_projection_not_assembled`。
3. view 不存在 → `Unknown` / `column_source_not_built`。
4. `non_scalar_text_gap` → `Unknown` / `non_scalar_UTF16_cannot_be_plain_UTF8`。
5. `frozen_provider_gate`：
   - 外层 `Some` 时立即返回（内层 `Some(Ok)`→Complete、`Some(Err)`→gate 拒绝、`None`→provider 未构建）。
   - 外层 `None` 时继续到第 6 步。
6. 既有 4 个引用关系的 `match spec.relation` 臂。

第 2 步排在第 3 步之前是刻意保留的既有行为：未装配列不需要 view 存在就已经是
确定的缺口，这样 `methods.param_descriptors` 等仍报 not-assembled 而非
source-not-built。

## 为什么 `code_items` 的门不直接构 `MethodCodeFactViews`

`MethodCodeFactViews::build` 会做一次完整的 method/code join 并按 occurrence
建立 `code_index`（`Vec<usize>` + 排序）。`column_state` 对每个 dex occurrence、
每个 required column 各调用一次；在 4096 列上限下重建 4k 次 join 是纯粹的浪费，
且 `code_items` 的 12 列全部是 header atom，不需要行数据就能判定可投影性。

因此 `code_items` 走两段判断：
- 列名契约：`require_code_item_columns`（拒绝未知列，等价于行 API 的门）。
- provider 存在性：`view.definitions.is_some() && view.code.is_some_and(layout complete)`。

两段合起来与「能否调用 `code_item_rows`」仍不等价于行数正确性，但那属于行投影
自身的测试范围（`metadata.rs::relation_projections_match_contract_columns_types_and_nullability`
已覆盖），coverage 只需保证不谎报 Complete。

## `non_scalar_text_gap` 的越界处理

原实现对 `method_strings.value` 用 `strings()[idx]` 直接索引。改为 `.get(idx)`：

```rust
.any(|site| {
    !references
        .definitions()
        .metadata()
        .strings()
        .get(site.target_local_index as usize)
        .is_some_and(|fact| fact.data.text.strict_utf8().is_ok())
})
```

语义是「找不到目标字符串也算缺口」。这在已验证 scope 下不可达（引用站点目标必须
是真实字符串），但把 panic 路径换成保守的 `Unknown` 更符合 coverage 的职责：
它的输出只允许在能证明时是 Complete。

## 无新增依赖

只用到 `crate::code`、`crate::definitions`、`crate::metadata`、`crate::references`
既有类型，以及 `mdd-types` 的 `MddResult`/`ErrorCode`。`code.rs` 抽出的是内部
重构，不引入任何新 crate。
