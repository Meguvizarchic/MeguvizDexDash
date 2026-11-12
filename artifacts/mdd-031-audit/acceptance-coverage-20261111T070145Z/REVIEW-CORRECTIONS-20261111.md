# Step-Reviewer 修正（2026-11-11）

本文件记录对抗审查对本目录证据的修正。原始文件保持历史含义，不做改写。

## 必须修正的覆盖声明

### 1. `counterexamples/counterexamples.json:30` 的 cast 覆盖声明不成立

原文称：

> "dedicated cast tests (legacy_integer_cast_matches_sqlite_prefix_and_saturation_without_lossy_text, cast-replay) cover both policies."

**实测不成立**：

- `legacy_integer_cast_matches_sqlite_prefix_and_saturation_without_lossy_text`（`bridge.rs:3640`）只遍历 `[DexSql010, DexSql011]`，**从不涉及 NativeV1**。
- `cast-replay`（2026-10-28 旧证据）只跑 A0/A1，即 DexSql010/011。
- NativeV1 精确 CAST 仅 `CAST('bad' AS INTEGER)` 被既有测试顺带覆盖；**`CAST('1.9' AS INTEGER)`（本反例本体）全仓零测试**。

结论：反例 #2 记录的分歧是真实的，但「双政策均有测试覆盖」是虚假声明。NativeV1 文本→整数 CAST 应补专门测试或在验收中明确记为未覆盖。

### 2. `compatibility_failure_preserves_counterexample_and_blocks_profile` 的 "blocks profile" 断言恒真

`bridge.rs:5681` 的 `assert!(result.profiles_admitted.is_empty())` 中，`profiles_admitted` 在 `bridge.rs:914` 恒为 `Vec::new()`。把阻断机制整个删掉，该测试依然通过。

**不得**把该测试列为验收 5 的覆盖证据。验收 5 的「阻断对应 profile」在 mdd-sql 内**无强制载体**（Reviewer 独立判断应归 MDD-035）。

### 3. `pushdown_policy_matches_vtab_capabilities_and_results_match_sqlite` 的同义反复

`bridge.rs:5596-5606` 的 `assert_eq!(result.optimizer.omit, policy.omit)` 两侧都读同一个 `VTB_POLICY`，**永远不可能失败**，不验证 `xBestIndex` 实际向 SQLite 报告了什么。该测试有分量的部分是 `assert!(!policy.*)` 与形状 ×3 方言的行级等价。

### 4. Q09/Q12 是空对空比较

- Q09（`method_idx BETWEEN 0 AND 8`，数据为 11/12）oracle 返 0 行，bridge 也返 0 行即通过。
- Q12（`callee='Lfixture/A;->f()V'`，数据全为 `Lfixture/F;->f()V`）同样 0 对 0。

两者对 BETWEEN 与文本等值**零判别力**。合计 9/81 个方言级比较是空对空。

### 5. `VtabPolicy` 的文档表述超出实际保证

`virtual_tables/mod.rs` 注释称该常量使「报告值不可能与 cursor 契约漂移」，但：

- `limit_offset_pushdown` 与 `in_pushdown` 在 `sqlite3_index_info` 中**没有对应通道**，常量对它们绑定不到任何 vtab 行为；
- 若将来把 `omit` 改 true 而 `xFilter` 仍不收约束，常量**防不住**静默错答；真正兜底的只有测试里的 `assert!(!policy.omit)`；
- `argv_index` 是第二处独立硬编码，未被常量覆盖。

## 仍然成立的结论

- 本轮实际只改 `virtual_tables/mod.rs` 与 `bridge.rs`（未暂存部分），无越界、无新依赖、无 `lib.rs` 变更。
- `cargo test --offline -p mdd-sql` → **207 passed; 0 failed**，5 个新测试真实运行。
- oracle 是真实 SQLite（rusqlite 3.53.2 + Python stdlib sqlite3 3.53.1 独立复跑一致）。
- `total()` 确为 `UNSUPPORTED_QUERY`（`FUNCTION_NOT_IMPLEMENTED`），非静默错答。
- 验收 1/3/4 成立；验收 2 打折（CAST 方言差异项被排除 + 空对空形状）；验收 5 诚实标注缺口。
