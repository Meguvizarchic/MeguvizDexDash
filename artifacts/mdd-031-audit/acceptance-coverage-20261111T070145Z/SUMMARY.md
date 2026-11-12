# MDD-031 验收覆盖补齐 SUMMARY

- 日期：2026-11-11（UTC）
- 负责人：MDD-031 子代理（SQLite 只读虚表兼容桥）
- 证据目录：`artifacts/mdd-031-audit/acceptance-coverage-20261111T070145Z/`
- 结论：**未 admitted 任何 profile，未签发兼容性资格**；只提交实现与证据。

## 1. 现状枚举（动手前）

- **已注册关系（32 个，全部 `native_` 前缀）**：metadata 6、definitions 7、annotations 11、code 5、references 3。见 `acceptance-matrix.json`。
- **已声明方言（3 个）**：`NativeV1`、`DexSql010`、`DexSql011`。
- **已启用下推标志**：无。`omit=false`、`order_by_consumed=false`、`limit_offset_pushdown=false`、`in_pushdown=false`；`xFilter` 收到 `argv_index=0`，SQLite 完成全部过滤/排序/LIMIT/OFFSET/IN。
- **已区分错误类别**：`InvalidArgument`（语法/绑定/输入）、`UnsupportedQuery`（真实未实现）、`QuotaExceeded`/`UnavailableBackend`/`InternalFault`/`IncompleteFacts`、`Cancelled`/`DeadlineExceeded`。AST 解析错误带 `confirm_sqlite_syntax=true`，经只读 SQLite 绑定复核；结构 AST 适配，无正则改写。
- **快照/会话绑定**：`SqlBinding` + `SqlExecutionBinding` + `runtime_query_binding`；`profiles_admitted` 恒为空。

## 2. 验收 5 条状态

| # | 验收 | 状态 | 关键证据 |
| --- | --- | --- | --- |
| 1 | 不全量 ETL，装载/惰性构建成本在测量内 | **已覆盖 + 新覆盖** | `vtab-prewarm-20261030`、`aggregate-input-workspace-20261101`；新增 `lazy_scan_cost_is_measured_after_prepare` |
| 2 | NULL/CAST/LIKE/ESCAPE/长度/比较/聚合/ORDER/JOIN/CTE 逐方言验证 | **新覆盖（逐方言矩阵）+ 已覆盖（专项）** | 新增 `dialect_feature_matrix_...`（18 用例 × 3 方言）、`hostlab_q_series_shapes_...`（9 形状 × 3 方言）；`oracle/oracle-results.json` |
| 3 | omit/orderByConsumed/LIMIT/OFFSET/IN 下推只在完整等价证据下启用；不谎报精确处理 | **新覆盖（防谎报绑定 + 等价矩阵）** | `VTB_POLICY` 单一常量同时驱动 `xBestIndex` 与 `OptimizerPolicy`；新增 `pushdown_policy_...` |
| 4 | 语法/绑定/输入错误与真正 unsupported 分开；不正则改写 | **已覆盖 + 新覆盖** | 结构 AST 适配 + `original_binding_error`；新增 `compatibility_failure_...` |
| 5 | 统一 snapshot/session；兼容失败保留反例并阻断 profile | **部分覆盖** | 快照/会话绑定已覆盖；新增 `compatibility_failure_...`；**profile 阻断机制缺失**（见下） |

### 仍缺 /  residual

1. **验收 5 的「阻断对应 profile」机制不存在**：mdd-sql 内没有具名兼容 profile 注册表，`profiles_admitted` 恒为空，因此「阻断」是真空而非强制。反例保留在错误对象上（code+details+ast_error），且确实不签发任何 profile。是否把 profile 注册表放在 MDD-031 还是 MDD-032/033，需主代理决策。
2. **验收 2 的 NativeV1 CAST 策略差异**：NativeV1 对 `CAST('1.9' AS INTEGER)`/`CAST('abc' AS INTEGER)` 返回 `INVALID_ARGUMENT`，而 SQLite/legacy 方言分别返回 1/0。这是文档化的方言政策（NativeV1 精确解析 vs legacy 前缀解析），不是静默错答，但与 SQLite oracle 存在真实分歧。已记入 `counterexamples/counterexamples.json`。
3. **`total()` 聚合未实现**：真实 `UNSUPPORTED_QUERY`（`FUNCTION_NOT_IMPLEMENTED`），分类正确，但聚合函数集有覆盖缺口。
4. **真实 provider 惰性构建的 wall/RSS 成本未端到端测量**：逻辑步数/扫描/结果额度已覆盖；SQLite allocator/RSS 明确不在范围内。
5. **Q14/Q16 属 MDD-033**（分页、TEMP/多语句），不在 MDD-031 的 SQL 语义形状范围。

## 3. 新增关系 / 方言 / 下推清单

- **新增关系**：0。Q 系列形状测试使用合成 provider 复刻 HostLab 冻结名（`classes`、`class_fields` 等），不改动真实 `native_*` 关系注册。真实映射是 MDD-032。
- **新增方言**：0。
- **新增下推**：0（四项仍全 false）。
- **新增实现**：`virtual_tables::VtabPolicy` + `VTB_POLICY` 常量，消除 `OptimizerPolicy` 与 `xBestIndex` 的独立硬编码。
- **新增测试**：5 个（Q 系列形状、逐方言特性矩阵、下推策略等价、兼容失败分类、惰性扫描成本）。

## 4. 仍需主代理决策的 export / 依赖

- **export 变更**：无。未改 `crates/mdd-sql/src/lib.rs` 的 pub mod 列表；新增的 `VtabPolicy`/`VTB_POLICY` 均为 `pub(crate)`，未新增公开 API。
- **依赖**：无新增生产依赖。
- **profile 注册表**：见 residual 1，需决策归属。
- **MDD-032 衔接**：Q 系列形状已在合成 provider 上验证；真实 `native_*` → HostLab 名前缀/列映射、跨 DEX 关联、泛型顺序、raw code 单位等仍需 MDD-032 完成。

## 5. 复现命令

```text
cargo test -p mdd-sql --locked --offline
.venv/Scripts/python.exe -O artifacts/mdd-031-audit/acceptance-coverage-20261111T070145Z/oracle/oracle_matrix.py
```

测试结果：`207 passed; 0 failed`（lib）+ `1 passed`（doctest），见 `readback/cargo-test.log`。源码 SHA256 见 `readback/source-sha256.json`。
