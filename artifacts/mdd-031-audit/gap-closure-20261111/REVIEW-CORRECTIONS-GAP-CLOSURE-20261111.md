# MDD-031 缺口闭合修正说明（2026-11-11）

本文件针对 `acceptance-coverage-20261111T070145Z/REVIEW-CORRECTIONS-20261111.md`
列出的 5 项问题逐条给出真实修复。上一轮目录中的原始文件保持历史含义，未改写；
本目录是新的修正证据。

## 1. NativeV1 CAST 覆盖声明不成立 → 已补专项测试

新增 `bridge.rs::native_v1_integer_cast_requires_exact_text_and_diverges_from_sqlite_prefix`：

| 输入 | NativeV1 | DexSql010/011 | SQLite 3.53.1/3.53.2 |
| --- | --- | --- | --- |
| `CAST('1.9' AS INTEGER)` | `INVALID_ARGUMENT` / `INVALID_INTEGER_CAST` | 1 | 1 |
| `CAST('abc' AS INTEGER)` | `INVALID_ARGUMENT` / `INVALID_INTEGER_CAST` | 0 | 0 |
| `CAST('-5.9' AS INTEGER)` | `INVALID_ARGUMENT` / `INVALID_INTEGER_CAST` | -5 | -5 |
| `CAST('1e5' AS INTEGER)` | `INVALID_ARGUMENT` / `INVALID_INTEGER_CAST` | 1 | 1 |
| `CAST('12' AS INTEGER)` | 12（成功） | 12 | 12 |

测试同时用 Python stdlib sqlite3（3.53.1）和 rusqlite 内置 SQLite（3.53.2）复跑，
两者对这些形状一致，见 `oracle/cross-check.json`。

## 2. `blocks_profile` 断言恒真 → 改名并删除恒真断言

- 测试改名：`compatibility_failure_preserves_counterexample_and_blocks_profile`
  → `compatibility_failure_preserves_counterexample_without_profile_admission`。
- 删除 `assert!(result.profiles_admitted.is_empty())`：该字段在 `bridge.rs` 执行路径中
  恒为 `Vec::new()`，删除阻断机制测试也不会失败，不能作为验收 5 的覆盖证据。
- 补注释说明：验收 5 的「阻断对应 profile」在 mdd-sql 内无强制载体，本测试不覆盖该部分。
- 顺带删除 `owned_cursor_is_lazy_and_preserves_multiplicity_and_nul` 中另一处
  `assert!(output.profiles_admitted.is_empty())`：同一恒空字段，同样不能作为任何
  覆盖证据；该测试的惰性/多重性/NUL 断言不受影响。

## 3. `assert_eq!(result.optimizer.omit, policy.omit)` 同义反复 → 换成真实 xBestIndex 上报记录

- 删除 4 条 `result.optimizer.* == policy.*` 断言（两侧都读 `VTB_POLICY`，永不失败）。
- `virtual_tables/mod.rs` 新增 `#[cfg(test)]` 记录：`best_index` 每调用一次
  `usage.set_omit` / `usage.set_argv_index`，就把实际传入的值记入
  `TEST_BEST_INDEX: Vec<BestIndexReport>`；测试通过 `best_index_reports()` 读取。
- `pushdown_policy_matches_vtab_capabilities_and_results_match_sqlite` 末尾断言：
  记录非空、每条 `omit == false`、每条 `argv_index == 0`。这验证的是 SQLite 在
  prepare 时真实调用的 `xBestIndex` 回调所报告的值，而不是常量的自我复制。
- 保留原有 5 个形状 × 3 方言的行级等价比较（若 `omit` 为 true，SQLite 会跳过自身
  过滤，行级比较会失败，构成第二重行为兜底）。

## 4. Q09/Q12 空对空 → 改 fixture 使 oracle 非空

- `code_items`：`file_id=0` 的两行 `method_idx` 由 11/12 改为 5/7，落在
  `BETWEEN 0 AND 8` 内。Q09 oracle 由 0 行变为 2 行：`[[5,100,8],[7,200,12]]`。
- `method_calls`：第一行 `callee` 由 `Lfixture/F;->f()V` 改为 `Lfixture/A;->f()V`，
  `callee_class` 同步改为 `Lfixture/A;`。Q12 oracle 由 0 行变为 1 行：
  `[[0,"Lfixture/A;->alpha()V"]]`。
- Q 系列循环内新增 `assert!(!expected.is_empty(), "{label} oracle returned no rows")`，
  9 个形状全部要求非空，防止再次退化为空对空。
- 特性矩阵中 `WHERE value LIKE NULL` 是有意的空结果形状（NULL 模式传播 NULL），
  补一条非空投影形状 `SELECT id, value LIKE NULL AS v FROM vals ORDER BY id`（7 行），
  使 NULL 语义有判别力；空形状保留并加注释。

修正后 84 个方言级比较（Q 系列 27 + 特性矩阵 57）中的空对空数量：Q 系列 0/27，
特性矩阵 3/57（仅 `like-null` 谓词形状，已由 `like-null-projection` 非空形状覆盖同一语义）。
两个循环现在都有 `assert!(!expected.is_empty())` 非空守卫（Q 系列早已有，特性矩阵本轮补上），
空形状若再现会被测试直接拒绝，不再依赖人工计数。

分母更正：Step-Reviewer 实测特性矩阵为 19 形状 × 3 方言 = 57，总计 84；此前写的
18×3=54 / 81 是新增 `like-null-projection` 之前的旧值。

## 5. `VtabPolicy` 文档夸大 → 重写注释

新注释明确：

- 只有 `omit` 与 `order_by_consumed` 有 `sqlite3_index_info` 通道；
- `limit_offset_pushdown` / `in_pushdown` 是信息性字段，SQLite 无法通过
  `xBestIndex` 感知，常量不强制它们；
- `argv_index` 在 `best_index` 中硬编码为 0，未被常量覆盖；
- 常量本身防不住「把 `omit` 改 true 而 `filter` 仍不收约束」的静默错答，
  真正兜底的是测试里对 `xBestIndex` 上报值的记录与行级等价比较。

## 未改动

- 未改 `crates/mdd-sql/src/lib.rs` 的 pub mod 列表。
- 未改 `Cargo.toml` / `Cargo.lock` / `STATE.md` / `tasks/backlog.json` / 其他 crate。
- 未新增生产依赖。
- 未改写上一轮证据目录中的任何文件。
