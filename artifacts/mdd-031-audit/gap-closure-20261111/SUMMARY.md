# MDD-031 缺口闭合 SUMMARY

- 日期：2026-11-11（UTC）
- 负责人：MDD-031 缺口闭合子代理
- 证据目录：`artifacts/mdd-031-audit/gap-closure-20261111/`
- 结论：**未 admitted 任何 profile，未签发兼容性资格**；只提交实现与证据。
- 上一轮目录：`acceptance-coverage-20261111T070145Z/`（原始文件保持历史含义，未改写）。

## 1. 五项问题逐条修复结果

| # | Reviewer 问题 | 修复 | 证据 |
| --- | --- | --- | --- |
| 1 | `counterexamples.json:30` 称 dedicated cast tests 覆盖两个政策，实际 NativeV1 `CAST('1.9' AS INTEGER)` 零测试 | 新增 `native_v1_integer_cast_requires_exact_text_and_diverges_from_sqlite_prefix`，覆盖 `1.9`/`abc`/`-5.9`/`1e5`（NativeV1 报 `INVALID_INTEGER_CAST`）与 `12`（成功），并对照 legacy 与 SQLite | `bridge.rs` 新测试；`oracle/cross-check.json`；修正后的 `counterexamples.json` |
| 2 | `compatibility_failure_..._blocks_profile` 的 `profiles_admitted.is_empty()` 恒真 | 测试改名 `compatibility_failure_preserves_counterexample_without_profile_admission`；删除恒真断言；注明验收 5 的 profile 阻断在本 crate 无强制载体 | `bridge.rs` 测试；本文件第 3 节 |
| 3 | `pushdown_policy_...` 的 `assert_eq!(result.optimizer.omit, policy.omit)` 两侧读同一常量 | 删除 4 条同义反复断言；`xBestIndex` 实际报告值由 `BestIndexReport` 线程局部记录，测试断言记录非空、全部 `omit=false`、`argv_index=0` | `virtual_tables/mod.rs`；`bridge.rs` 测试 |
| 4 | Q09/Q12 空对空（合计 9/84 方言级比较空对空） | Q09 fixture `method_idx` 11/12→5/7；Q12 首行 `callee` F→A；Q 系列每个形状加 `assert!(!expected.is_empty())`；特性矩阵补非空 `like-null-projection` 形状，并同样加非空守卫 | `bridge.rs` fixture 与断言；`oracle/oracle-results.json` |
| 5 | `VtabPolicy` 文档称常量使报告值不可能漂移，夸大 | 重写注释：只有 `omit`/`order_by_consumed` 有 `sqlite3_index_info` 通道；`limit_offset_pushdown`/`in_pushdown` 信息性；`argv_index` 硬编码 0；常量防不住 `omit` 静默翻转 | `virtual_tables/mod.rs` 文档注释 |

### 空对空数量变化

- 修复前：Q 系列 6/27（Q09、Q12 各 3 方言），特性矩阵 3/57（`like-null` 谓词形状；19 形状 × 3 方言），合计 9/84。
- 修复后：Q 系列 0/27（9 个形状全部非空，测试内断言保证）；特性矩阵 3/57（`like-null` 谓词形状，空结果是 NULL 语义的正确结果，同一语义由新增的 `like-null-projection` 非空形状覆盖）。
- 分母更正：Step-Reviewer 实测特性矩阵为 19 形状 × 3 方言 = 57（此前写的 18×3=54 是新增 `like-null-projection` 之前的旧值），总计 27+57=84（此前写 81）。

## 2. 验收 5 条最新状态

| # | 验收 | 状态 | 关键证据 |
| --- | --- | --- | --- |
| 1 | 不全量 ETL，装载/惰性构建成本在测量内 | **已覆盖 + 新覆盖** | `vtab-prewarm-20261030`、`aggregate-input-workspace-20261101`；`lazy_scan_cost_is_measured_after_prepare` |
| 2 | NULL/CAST/LIKE/ESCAPE/长度/比较/聚合/ORDER/JOIN/CTE 逐方言验证 | **新覆盖（逐方言矩阵 + NativeV1 CAST 专项）+ 已覆盖（专项）** | `dialect_feature_matrix_...`（19 用例 × 3 方言）、`hostlab_q_series_shapes_...`（9 形状 × 3 方言）、`native_v1_integer_cast_...`；`oracle/oracle-results.json` |
| 3 | omit/orderByConsumed/LIMIT/OFFSET/IN 下推只在完整等价证据下启用；不谎报精确处理 | **新覆盖（真实 xBestIndex 上报记录 + 等价矩阵）** | `VTB_POLICY`；`BestIndexReport` 记录；`pushdown_policy_...` |
| 4 | 语法/绑定/输入错误与真正 unsupported 分开；不正则改写 | **已覆盖 + 新覆盖** | 结构 AST 适配 + `original_binding_error`；`compatibility_failure_preserves_counterexample_without_profile_admission` |
| 5 | 统一 snapshot/session；兼容失败保留反例并阻断 profile | **部分覆盖** | 快照/会话绑定已覆盖；反例保留在错误对象；**profile 阻断机制缺失**（`profiles_admitted` 恒空，无具名注册表，本 crate 不强制） |

### 验收 2 的 NativeV1 CAST 分歧

NativeV1 对 `CAST('1.9' AS INTEGER)` / `CAST('abc' AS INTEGER)` 返回
`INVALID_ARGUMENT`（`INVALID_INTEGER_CAST`），SQLite 与 legacy 方言分别返回 1/0。
这是文档化的方言政策（NativeV1 精确解析 vs legacy 前缀解析），不是静默错答。
本轮之前该分歧在测试中零覆盖，现在由专项测试固定下来，并与两个独立 SQLite
oracle 对照。

### 验收 5 的 profile 阻断

`profiles_admitted` 在执行路径中恒为 `Vec::new()`，mdd-sql 内没有具名兼容
profile 注册表，因此「阻断对应 profile」是真空而非强制。本轮删除了依赖该恒空
字段的断言，不再把该测试列为验收 5 的覆盖证据。是否把 profile 注册表放在
MDD-031 还是 MDD-032/033，需主代理决策。

## 3. 新增 / 修改测试清单

| 测试 | 变化 |
| --- | --- |
| `native_v1_integer_cast_requires_exact_text_and_diverges_from_sqlite_prefix` | 新增 |
| `compatibility_failure_preserves_counterexample_without_profile_admission` | 改名 + 删除恒真断言 |
| `pushdown_policy_matches_vtab_capabilities_and_results_match_sqlite` | 删除同义反复断言，新增 xBestIndex 上报断言 |
| `hostlab_q_series_shapes_match_sqlite_per_dialect` | fixture 改 Q09/Q12 数据；新增非空断言 |
| `dialect_feature_matrix_matches_sqlite_for_null_cast_like_length_compare_aggregate_order_join_cte` | 新增 `like-null-projection` 形状 |

## 4. 复现命令

```text
cargo test --offline -p mdd-sql
cargo clippy --offline -p mdd-sql --all-targets -- -D warnings
.venv/Scripts/python.exe -O artifacts/mdd-031-audit/gap-closure-20261111/oracle/oracle_matrix.py
```

测试结果：`208 passed; 0 failed`（lib）+ `1 passed`（doctest），见
`readback/cargo-test.log`。clippy 全绿，见 `readback/cargo-clippy.log`。
源码 SHA256 见 `readback/source-sha256.json`。
