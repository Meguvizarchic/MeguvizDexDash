# MDD-032 / MDD-033 准备分析 SUMMARY

## ⚠️ Step-Reviewer 第三轮更正（主代理应用）

事实性主张 8 条中 6 条完全属实、1 条部分属实、1 条方向属实但范围算错；行号引用约 6 处漂移。实质性问题：

1. **B1 定性错误**：`mdd-033-gap-analysis.md` §4 称 TEMP catalog 的依赖方向「硬阻塞」「无法开始编码」——**不成立**。验收 4 的五项语义（循环、IF NOT EXISTS、DROP、重定义、跨会话隔离）全部是名称+依赖图操作，用 `String`/`Vec<String>`/`definition_hash` 即可在 `mdd-session/src/catalog.rs` 内落地；只有 `AS SELECT` 物化需要执行器，可由 mdd-sql 注入。**这是接口设计约束，不是编码阻塞**，且与子代理自己的 `implementation-plan.md` §2「第一交付件是 cursors.rs，可立即动手」自相矛盾。
2. **互锁范围漏算 Q16**：只算 Q13.boundary + Q14，实为 **3 个变体**（Q16 `native_statement_results` 同属 MDD-032 scope 的「冻结十六类模板」）。
3. **变体计数错误**：032-A 写「32−2 = 30」，实为 **29**（Q01–Q12 共 28 + Q15 的 1；Q15 的 `required_profile` 不在 32 内）。
4. **`source_path`/`entry_name` 的 NULL 判决规则未提**：契约要求 `Utf8` 且 `nullable: false`，而 `SelectedInput.origin_display`/`MemberIdentity.name_utf8` 都是 `Option<String>`，裸 DEX 输入为 `None`——这是 NOT NULL 契约 vs Option 源的判决问题，比 R 项更硬。
5. **HostLab 数值序会主动拒绝输入**：`hostlab_file_ids()` 对非 `classes<N>.dex` 命名返回 `InvalidArgument`，`surface::dex_file_order()` 另拒合成 `#N` 成员；与 MDD-032 acceptance[4]「任何必需查询 unsupported 使任务不通过」存在张力，须先裁定。
6. **`string_pool_id` 应改造存量而非新造**：`SelectedScope::occurrence_pool_coordinates()`（`indexes/scope.rs:1143-1177`）已产出 `occurrence_pool_ordinal: dex.file_id`，并有 A0 对照测试；应把序源从 ZIP 序改为 HostLab 数值序，不是「从零定义赋值器」。
7. **行号漂移 6 处**（`functions.rs` ASCII 折叠、`coverage.rs` 门位置、`code_item_rows`、`StringPoolIdentity`、`duplicate-interface.dex` 路径等）；后者实际在仓库根 `tests/fixtures/definitions/generated/`，文中沿用了 merged-matrix 的错误路径。
8. **基线已失真且未申报**：`coverage.rs` 于 19:38（分析窗口后）被并行代理改写；`bridge.rs` 在审查窗口内被反复改写。实施前须重取基线。
9. **oracle 覆盖度高估**：`artifacts/mdd-033/preflight/README.md` 的「仍未验证」清单含「循环」与「跨 session TEMP 隔离」，即验收 4 五项语义中只有 3 项有参考证据。

**未发现错误的部分**（避免重复劳动）：17 关系清单、156/139/17 列统计、32 个 `native_*` 精确枚举、34/32 变体、0/16 golden、`expected-results/` 不存在、`TerminalBuilder::page` 无生产调用、`mdd-session` 依赖方向、`executor.rs` Limit 定性、`method_field_accesses.using_type` A0 只有 get/put。

- 日期：2026-11-11（Asia/Shanghai），分析时点 19:21
- 性质：**纯只读**；未改生产代码、未改 `Cargo.toml`/`Cargo.lock`/`STATE.md`/`tasks/backlog.json`/`artifacts/**` 既有文件
- 目录内容：`mdd-032-gap-analysis.md`、`mdd-033-gap-analysis.md`、`implementation-plan.md`、`SUMMARY.md`

## 核心结论（10 行内）

1. **MDD-032 关系缺口 17/17**：mdd-sql 生产路由注册 32 个 `native_*`，HostLab 的 17 个契约名**一个都没有**；`"dex_files"` 等仅在 `bridge.rs:5912` 起 `#[cfg(test)]` 的 `MultiProvider`（`:5400`）里出现。
2. **事实层不差**：**17/17** 关系都已有 `*_rows()` 行投影，156 列中 151 列已装配，5 列未装配（`columns.rs:23,30,317,331,338`：`source_path`、`entry_name`、`param_descriptors`、`opcode_count`、`opcode_hex`）；`methods` 的 3 列在 `definitions.rs:1316-1331` 被显式门控拒绝。
3. **按六类口径 139/156 列完全合格**；17 列未完全合格，其中 `method_field_accesses.using_type` 是唯一的 `null: missing`。
4. **corpus 缺口**：hostlab-audit-v1 的 32 个变体中 14 个有 SQL 形状测试、18 个没有；**0/16 族有 golden**；`conformance/corpus/hostlab/expected-results/` 不存在。
5. **MDD-033 距 acceptance 很远**：5 条验收中 1 条基本成立（含 2 个字段缺口）、1 条空转（无 TEMP 实体可迁移）、3 条零实现；4 个目标产物中 3 个不存在。
6. **MDD-033 硬阻塞**：`mdd-session` 只依赖 `mdd-types`+`mdd-input`，但 TEMP 定义需要 SQL/IR 类型，形成依赖方向冲突；`catalog.rs` 不能按 backlog 路径直接落地，需主代理决策。
7. **两处硬冲突**：Q13 `boundary` 需要多语句（被 `dialects/ast.rs:1204-1215` 拒绝），Q14 需要响应分页（`executor.rs:536-539` 明确 `Limit` 不是响应分页）——使 MDD-032 验收 2 隐含依赖 MDD-033。
8. **三个必须先定的契约**：`file_id` 必须用 HostLab 数值序而非 `SelectedDex.file_id`（`scope.rs:770` 是 ZIP 序，已知分歧记于 `hostlab/rules.rs:436-447`）；`string_pool_id` 需正式 UInt32 目录赋值器；HostLab 必须绑 DexSql010/011（NativeV1 的 LIKE 无 ASCII 折叠，`functions.rs:938-943`）。
9. **建议顺序**：先 **MDD-032**，且第一交付件是"仅 `dex_files` 一个关系的真实映射 + Q01 两变体对 A0 逐行对照"，因为它一次性验证 `file_id` 序、池号赋值、provenance 拼接三个高危项；MDD-033 第一交付件是 `cursors.rs`（模式标记 + 来源指纹 + 混合页拒绝），不碰 TEMP。
10. **不建议直接开始编码**：`bridge.rs`/`provider.rs` 在分析窗口内仍被并行修改（18:41/18:46 mtime，19:21 哈希已快照于 `source-baseline.json`）；且 032-C 的依赖标注、033 的 B1 归属均需主代理先决策。

## 分析时点源码基线（SHA256）

见同目录 `source-baseline.json`。若实施前哈希不同，须重取基线后复核本目录结论。

## 声明

- 本目录**未**声称任何任务完成、profile admitted 或性能结论。
- 未运行 HostLab 工作负载、私有输入或性能测量。
- 所有"已验证"结论均附文件路径+行号或 JSON 路径；推断项在正文中显式标注"推断"。
