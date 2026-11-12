# MDD-032 / MDD-033 实施计划建议

- 日期：2026-11-11（Asia/Shanghai）
- 前置：MDD-031 尚 `in_progress`，两者均被阻塞；本文件只给顺序与第一交付件，不实施
- 依据：`mdd-032-gap-analysis.md`、`mdd-033-gap-analysis.md`（同目录）

---

## 1. 结论：先做 MDD-032，但 MDD-032 必须先切一刀

**建议顺序：MDD-032 → MDD-033，且 MDD-032 的第一个可交付件不能是任一最终产物，而是
"HostLab profile 关系映射契约 + 17 关系真实注册（只读形状）"。**

### 理由（按权重）

1. **MDD-032 是数据面，MDD-033 是交付面。** MDD-033 的验收 3（混合页拼接）与验收 4（offset 契约）
   需要一个"可被分页的执行结果"；如果关系本身还查不出正确的行，分页只能测形状，测不出内容。
   当前 17 关系在 SQL 生产路由中 0 注册（`mdd-032-gap-analysis.md` §0），这是更底层的阻塞。
2. **MDD-033 存在依赖方向冲突（B1）**，需要主代理先做架构决策（catalog 放哪一层 /
   是否新增 crate / 是否允许 `mdd-session` 反向依赖）。这类决策周期长，先启动可并行推进
   而不返工的是 MDD-032 的事实/映射部分。
3. **但 MDD-032 不能一路做完再交**：其验收第 2 条（"所有必需模板…均执行完整"）包含 Q13 `boundary`
   （多语句）与 Q14（响应分页），而这两项当前被硬拒（`mdd-032-gap-analysis.md` §2.3）。
   若把 32 个变体一次性作为 MDD-032 验收，MDD-032 实际依赖 MDD-033，形成互锁。

### 因此建议的分割（需主代理在 backlog 层面确认，子代理无权改共享文件）

| 阶段 | 内容 | 归属 | 是否需修订 backlog |
|---|---|---|---|
| **032-A** | 17 关系在 SQL 生产路由注册 + 列契约一致 + `file_id` 数值序 + `string_pool_id` 目录赋值；覆盖 Q01–Q12 与 Q15 的 32−2 个变体（排除 Q13 boundary 与 Q14） | MDD-032 | 否（可解释为"必需模板"中 Q13/Q14 单列后续） |
| **032-B** | Q13 的 `representative_shape` + `hex_value_wrapper` 两变体（当前已有形状测试，需换成真实关系） | MDD-032 | 否 |
| **033-A** | `cursors.rs`：原生 cursor 模式标记 + 页级流式（基于 `execute_into`）+ 混合页拒绝 | MDD-033 | 否 |
| **033-B** | 兼容 offset 重执行契约 + capabilities 双模式声明 | MDD-033 | 否 |
| **033-C** | TEMP catalog（依赖 B1 决策）+ 循环/IF NOT EXISTS/DROP/跨会话隔离 | MDD-033 | 可能需新增/移动 crate |
| **032-C** | Q13 `boundary`（多语句）+ Q14 | 依赖 033-C | **建议主代理显式把这两项在 MDD-032 验收中标注为"依赖 MDD-033 完成后闭合"** |

如主代理不接受 032-C 的依赖标注，则唯一替代是把 `boundary`/Q14 移入 MDD-033 的验收范围并同步
`conformance/manifests/profile-requirements.json`。**两条路都必须改共享文件，所以必须主代理决定。**

---

## 2. 各自第一个可交付件

### MDD-032 第一交付件：`HostLab relation mapping`（无 TEMP、无分页依赖）

**范围**：只做 Q01 一条链，把"映射骨架"立起来并被真实事实验证。

具体：

1. 新建 `crates/mdd-sql/src/profiles/mod.rs` + `profiles/hostlab.rs`（backlog 指定 `hostlab.rs`）。
   由 `lib.rs` 增加 `pub mod profiles;` —— **这是 export 变更，属主代理单写点，子代理不得自行改。**
2. 在 `hostlab.rs` 实现 `HostLabProvider`，只暴露 **`dex_files`（28 列）** 一个关系，
   列顺序/类型/可空性逐列对照 `conformance/manifests/relations.json:10-152`。
3. 行来源：`MetadataFacts::dex_file_rows`（`metadata.rs:697`）+ `SelectedScope::inventory_metadata_rows`
   （`indexes/scope.rs:1024`）补 `source_path`/`entry_name`。
4. `file_id` 用 `NativeSession::hostlab_file_ids`（`hostlab/mod.rs:491`）或
   `surface::dex_file_order`（`surface.rs:188`）的数值序，**不得用 `SelectedDex.file_id`**。
5. 验收：真实 DEX（`tests/fixtures/generated/multidex-stored.apk` 或
   `duplicate-content.apk` 的现有证据切片）上执行
   `SELECT file_id,entry_name FROM dex_files ORDER BY file_id`（Q01 inventory）与
   `SELECT file_id,string_pool_id FROM dex_files ORDER BY file_id`（Q01 pool_mapping），
   与 A0 记录逐行对照，并把结果写入 `artifacts/mdd-032/hostlab-query-matrix.json`（首条记录）。

**为什么是这个而不是全 17 关系**：
- 它同时验证了三个最危险的不确定项：`file_id` 排序（R1）、`string_pool_id` 目录赋值（§3.2）、
  provenance 两列的层所有权拼接（§1.2）。
- 这三个一旦定错，后面 16 个关系全部要返工（所有 JOIN 键都依赖它们）。
- 它不依赖 TEMP、不依赖分页、不依赖 Q13/Q14，因此可以在 MDD-031 闭合后立即开始。

### MDD-033 第一交付件：`cursors.rs` 的模式与绑定扩充（不碰 TEMP）

具体：

1. 新建 `crates/mdd-session/src/cursors.rs`，把 `lib.rs:352-361` 的 `CursorEntry` 与
   `:1223-1370` 的游标方法迁入，并新增：
   - `enum CursorMode { NativeSnapshot, CompatOffset }`
   - `source_fingerprint: String`（页级来源，用于验收 3 的混合页拒绝）
   - `worker_generation: String`（`docs/02_ARCHITECTURE_AND_CONTRACTS.md:398` 已要求，当前缺失）
2. `open_cursor` 增加 `mode` 参数；`validate_cursor` 返回 `(catalog_epoch, mode, source_fingerprint)`。
3. 新增 `validate_page_continuation(session, query, cursor, page_schema_id, page_total)`：
   拒绝 schema/total/来源变化 —— 对应 HostLab 参考的 `query_schema_or_total_changed`
   （`conformance/corpus/hostlab/source-8782f43/analysis_paging.py:165,171`）。
4. 测试：在 `mdd-session` 内新增
   `same_sql_same_width_source_change_rejects_page_stitching`；
   并补 `mdd-types/src/result.rs:153-170` 的 `page()` 首个**生产形态**调用测试。

**为什么不是 TEMP first**：TEMP 受 B1 依赖方向冲突阻塞，且 `catalog.rs` 的落点未定。
cursors 部分只依赖 `mdd-types`/`mdd-input`，与现有 `mdd-session` 依赖一致，可立即动手。

---

## 3. 依赖互锁的显式处理（必须由主代理决定）

现状事实：

- `MDD-032.depends_on` = MDD-012/020/021/022/023/024/025/**031**（无 033）
- `MDD-033.depends_on` = MDD-014/030/**031**（无 032）
- `MDD-032.acceptance[1]` 要求"所有必需模板、动态参数类别与 helper 语句均执行完整"
- Q13 的 `boundary` 变体需要多语句（`native_cli.py:117`），Q14 需要响应分页
- 两者当前都被 `dialects/ast.rs:1204-1215` 与 `executor.rs:536-539` 的语义硬拒

三个可选方案（**都需主代理在 backlog 层选择，子代理不得改 `tasks/backlog.json`**）：

| 方案 | 做法 | 代价 |
|---|---|---|
| **A（推荐）** | MDD-032 验收按 §1 的 032-A/032-B/032-C 三段解释；032-C 在 MDD-033 完成后闭合；backlog `implementation_notes` 记录该依赖 | 需主代理写一条 implementation_notes；无需改 acceptance 文本 |
| B | 把 Q13 boundary 与 Q14 从 MDD-032 移入 MDD-033 验收 | 要改两处 acceptance 与 `profile-requirements.json` 的 `required_query_families` 归属 |
| C | 先做 MDD-033 的 033-A/033-B（cursors + offset），再做 MDD-032 全部 | 顺序反转；但 MDD-033 的验收 3/4 在关系未通时无法测内容，只能测形状，等于返工 |

---

## 4. 风险与前置检查清单

实施前必须逐项确认（否则返工）：

| # | 检查 | 依据 |
|---|---|---|
| 1 | 重取 `crates/mdd-sql/src/bridge.rs`、`provider.rs` 的哈希基线 | 分析期间（19:21）该文件仍被并行改动；18:41 与 18:46 mtime 不一致 |
| 2 | 确认 `crates/mdd-facts/tests/opcode_projection.rs`、`parameter_descriptors.rs`（19:12 写入）与 `definitions.rs:81-85` 的门控注释是否仍一致 | 两文件是并行子代理新增，`MethodRow::COLUMNS` 尚未扩展（`definitions.rs:103-115` 仍 11 列） |
| 3 | 确认 `record_compatibility_failure` 未被改回短路 | 当前 `bridge.rs:593-616` 已正常接线（无 `if true`）；`profiles_admitted` 仍恒空但 `CompatibilityProfileRegistry` 已具备阻断能力（`provider.rs:78-148`） |
| 4 | 确认 `lib.rs` 的 `pub mod` 变更由主代理执行 | 新增 `profiles` 模块属 export 变更 |
| 5 | 决定 `string_pool_id` 的 UInt32 目录赋值规则 | `mdd-032-gap-analysis.md` §3.2；事实层只有不透明 String |
| 6 | 决定 B1（catalog 归属层） | `mdd-033-gap-analysis.md` §4 |
| 7 | 若新增生产依赖或 crate，先取得用户确认 | 项目 AGENTS.md 明确要求 |

---

## 5. 工作量粗估（按已验证缺口，不含未知）

| 项 | 规模 | 说明 |
|---|---|---|
| 032-A 关系注册 | 17 关系 × 平均 8 列 | 事实层行 API 已有 17/17，主要是映射与目录坐标 |
| 032-A 未装配 5 列 | 2 列层拼接 + 3 列编码资格 | 3 列需资格签发，不是纯编码工作 |
| 032-A 未合格 17 列 | 12 列是 `file_id`/`string_pool_id`/`ordinal` 类坐标 | 一旦 §3.1/§3.2 定案，多数会一次性转好 |
| corpus golden | 16 族 / 32 个 hostlab 变体 | 0 已存在；需真实 APK（当前环境无私有样本） |
| 033-A cursors | 迁移 + 3 字段 + 1 校验函数 | `lib.rs` 已有 2200+ 行，迁移需谨慎保持既有测试 |
| 033-B offset | 新请求参数 + lookahead + 双模式能力声明 | 涉及 `mdd-cli/src/main.rs:74` 的 `pagination_modes` |
| 033-C TEMP | catalog + 依赖图 + 5 类语义 + 跨会话 | 参考 oracle 已备（`artifacts/mdd-033/preflight/`） |

**未计**：私有 APK 取得、Linux A0/A1、完整 HostLab 工作负载（这些属 MDD-054/055 门，不应塞进 032/033）。

---

## 6. 与下游的衔接

- MDD-032 完成后，MDD-035（`required query suite` + `query-profile-qualification.json`）才有输入：
  035 的 4 个输出目前**全部不存在**（`conformance/run-required-query-suite.py`、
  `conformance/manifests/query-profile-qualification.json`、`artifacts/mdd-035/`）。
- MDD-033 完成后，MDD-053（分页/checkpoint/batch/remote runner）才有 `depends_on` 满足。
- 两者都不能宣称 `hostlab-audit-v1` admitted：`compatibility/ledger.json:8-14` 与
  `conformance/manifests/profile-requirements.json:5-20` 均为 `admitted:false`，且
  `merged-matrix.json` 明确 `task_complete_proven:false, profile_admitted:false`。
