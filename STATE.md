# MeguvizDexDash 当前状态

更新：2026-11-12（Asia/Shanghai）。唯一任务图：tasks/backlog.json；当前产品仍在实施，所有产品 profile admitted=false。

## 2026-11-11 生产前资格推进（5 子代理 + 3 Step-Reviewer）

依赖图核查：51 项任务中仅 MDD-005/026/031/034 未阻塞，其余 26 项全部下游；MDD-082（签发功能、正确性与性能发布资格）仍 todo，本轮不改变发行状态。

**MDD-026 六类证据（3 组并行）**：definition 48 列 / members 59 列 / code-annotation 57 列，全部只写各自新目录，未改生产代码与共享文件。合并脚本 `artifacts/mdd-026/merge_evidence.py` 按 **v10 严格口径**（multiplicity 必须有 `exact_duplicate_rows_compared>0`）装配 `artifacts/mdd-026/evidence-merged-20261111/merged-matrix.json`：六类全满足 **10 → 77** 列，multiplicity 19/97/40 → **78 satisfied / 78 partial / 0 missing**，order 106 → 155，null missing 9 → 1。冲突解决：两 agent 意见不一致时取实际锻炼了精确重复行的一方。**77 列中 36 列落在 unassembled_production_relation 上**，69 个兼容投影仍未装配，故本矩阵不能签发 MDD-026「事实层完整性」。

**MDD-031（SQL 桥）**：新增 `VtabPolicy`/`VTB_POLICY`（`virtual_tables/mod.rs`）统一 vtab 与 bridge 的策略报告，5 个新测试（`bridge.rs`），`cargo test -p mdd-sql` 207 passed。验收 1/3/4 成立，2 打折。**当时记录「验收 5 的 profile 阻断应归 MDD-035」的判断已被第三轮推翻**（见下节）。

**MDD-034（预算/取消/终态）**：只新增 4 个测试（`executor/runtime_tests.rs`），零生产逻辑改动，`cargo test -p mdd-query` 201 passed。验收 1/2 原有覆盖，3/4/5 部分覆盖。

**对抗审查（3 个 Step-Reviewer）发现的实质问题**：Agent C 的「独有键关系不可能出现精确重复行」被其自身 `total_exact_duplicate_rows_compared` 与 Agent A 的 `duplicate-content.apk` 双重推翻——47 列是「没做」不是「不可能」；Agent C 列级 `negative_controls` 中 `duplicate_collapse` 在 47 列上是空转；Agent A 的 `class_interfaces.ordinal` order/multiplicity 因 ordinal 恒 0 而夸大（`duplicate-interface.dex` 在手边未用）；Agent B 的 `methods.file_id` 是常量比常量且隐瞒引擎自报 `INCOMPLETE_FACTS`；Agent A 的 `dex_files.string_pool_id` oracle 值系编造。已按严格口径降级 7 处，修正记录见各目录 `REVIEW-CORRECTIONS-20261111.md` 与合并目录 `SUMMARY.md`。

**验证**：`cargo test --offline --workspace` 全绿（mdd-sql 207 / mdd-query 201 / mdd-session 30 等，24 个 test target 全 ok）；**`cargo clippy --offline --workspace --all-targets -- -D warnings` 0 错误**。已修复 22 处历史遗留 clippy 错误：`mdd-session/src/cancellation.rs` 2 处 `.err().expect()`→`.expect_err()`（已提交代码 `15052c9` 遗留）；`mdd-sql` 20 处（`dialects/ast.rs` 5 处 collapsible_if/redundant_guard/`is_multiple_of` + 测试模块移到文件末尾，`dialects/functions.rs` 2 处 needless_borrow，`provider/metadata.rs` 1 处 needless_borrow + 抽出 `AnnotationColumnSpec`/`AnnotationRelationSpec` 类型别名，`bridge.rs` 2 处 clone_on_copy、3 处 `.err().expect()`、1 处类型别名、2 处 `&[value.clone()]`→`std::slice::from_ref`）。均为纯风格/等价改写，无行为变化；`cargo fmt` 仅剩 `crates/mdd-sql/src/join_tests.rs`（用户暂存改动，保持不动）。

**未做**：MDD-026 的 69 个兼容投影装配、MDD-031 验收 5 的 profile 阻断、MDD-034 的 SQLite per-query interrupt 与 fallback 接线、以及 MDD-032/033/035/051/052/053/054/055/060 等全部下游门。

## 2026-11-11 第二轮（5 子代理 + 3 Step-Reviewer）

**MDD-026 生产关系装配**：为 6 个契约关系（dex_files/strings/types/methods/classes/code_items）新增行投影 API（`metadata.rs`、`definitions.rs`、`code.rs`），**69 列装配 64 列**，5 列因层所有权/分层边界未装配。`assembled_projection=true` 由 87 增至 151。`cargo test -p mdd-facts --lib` 125 passed。

**MDD-026 证据修复**：两组修复轮就第一轮 Reviewer 认定的 P0/P1 与 7 项缺陷重新取证。合并矩阵（`artifacts/mdd-026/evidence-merged-20261111/merged-matrix.json`）：六类全满足 **77 → 139** 列，multiplicity **78/78/0 → 144/12/0**，未装配生产关系 **69 → 5**。

**MDD-031 缺口闭合**：补 NativeV1 文本→整数 CAST 专项测试；删除恒真的 `profiles_admitted` 断言并改名；用 `BestIndexReport` 线程局部记录真实 `xBestIndex` 上报；Q09/Q12 fixture 改为非空并对两个循环都加非空守卫；重写 `VtabPolicy` 注释。`cargo test -p mdd-sql` **208 passed**，clippy 0。

**MDD-034 缺口闭合**：补齐 `truncated`/`more_available`/`next_cursor`/`total_rows_exact`/`execution.complete` 断言；删除恒真的 `is_complete_result()`；兄弟 query/session 改为真实生产 `execute` 并读数据；`"controlled hard kill"` 改名并标注为进程内 API；SQLite interrupt 措辞改正；死代码如实标注。`cargo test -p mdd-query` **201 passed**，clippy 0。

**Step-Reviewer（第二轮）认定的实质问题**：
- 装配轮「5 列因真实 fact 层缺口」定性错误——冻结台账对这 5 列均记 `available_in_validated_declared_scope`，实为**层所有权缺口（2 列）+ 分层边界与资格门槛（3 列）**，已在装配目录 SUMMARY 更正。
- 装配轮 readback 只比 11/14 methods 列、dex_files 只比 2 个常量列，覆盖面被高估。
- `assembled_projection` 被 `coverage.rs:651-656` 消费：翻旗使 64 列 coverage 由 `Unknown` 变 `Complete`，**无覆盖侧验证、无测试**；`strings.value`/`classes.source_file` 在含非标量字符串的 scope 上存在虚假 Complete 路径（`nonscalar-string-035.dex` 现成未用）。
- 两组证据修复的 native 探针与当前源码**同一性不可验证**（exe/rlib 早于并行轮次对 mdd-facts 的修改，无编译终端）——需在独占时段用干净构建重跑。
- 「A0 序列相等 104/104」不成立（10/104 与 native 发射序不同，因引擎不消费 ORDER BY）。
- `methods` 的 11 个 satisfied 列走探针组装而非引擎 `method_rows()`，只覆盖取值不覆盖关系投影。
- `VtabPolicy` 注释一度把 LIMIT/OFFSET 说成「SQLite 无法感知」，与 rusqlite 暴露的 `SQLITE_INDEX_CONSTRAINT_LIMIT`/`OFFSET`（SQLite ≥3.38，本仓 3.53.2）矛盾——已改为「未接线、信息性」。
- MDD-031 证据分母 81/54 过期，实际 84/57——已更正。

**验证**：`cargo test --offline --workspace -j 4` 全绿；`cargo clippy --offline --workspace --all-targets -- -D warnings` **0 错误**（本轮新引入的 2 个 mdd-facts 测试 clippy 错误已修）。新增非空守卫立刻抓出一个有意的空形状（`WHERE value LIKE NULL`），已显式列入 `INTENTIONAL_EMPTY_SHAPES` 例外并保留守卫判别力。

**未做**：5 列未装配（其中 3 列按台账属 MDD-032 前提）、coverage 侧对 6 个新关系的门验证与非标量特判、证据探针的干净重建重跑、MDD-031 验收 5 的 profile 阻断、MDD-034 的 fallback 接线与真实强杀查询。

## 2026-11-11 第三轮（3 子代理 + 3 Step-Reviewer）

**MDD-026 coverage 门**：`coverage.rs` 新增 `frozen_provider_gate`，为 `dex_files`/`strings`/`types`/`methods`/`classes`/`code_items` 接上 provider 门；非标量 UTF-16 特判扩展到 `strings.value` 与 `classes.source_file`（`nonscalar-string-035.dex`/`surrogate-source.dex`/`null-source.dex` 三方复算）。mdd-facts 133 lib + 20 集成 + 5 doctest 全通过。

**MDD-031 profile 阻断载体**：归属研判裁定为**两层机制**——MDD-031 第 5 条是运行时负向门禁，MDD-035 是离线正向资格；本轮在 mdd-sql 内实现 **block-only** registry（`CompatibilityProfileRegistry`，只有 `block`/`is_blocked`/`blocks`，无 `admit`），prepare/execute 入口 fail-closed，仅 `UNSUPPORTED_QUERY` 登记阻断，反例 SQL 原文+SHA256 入库。4 个新测试 + 3 处红绿探针（复跑确认有牙齿）。`cargo test -p mdd-sql` **213 passed**。**上一轮「应归 MDD-035」的判断被本轮 Reviewer 明确推翻**：block-only 载体不构成准入签发，归 MDD-031 正确。

**MDD-032/033 只读准备**（`artifacts/mdd-032-033-prep-20261111/`）：MDD-032 的 17 个 HostLab 契约关系在 mdd-sql 生产路由中**一个都没有**（32 个 `native_*` 是内部名），事实层 17/17 已有 `*_rows()`；corpus 32 变体中 18 个无形状测试、0/16 族有 golden。MDD-033 验收 5 条中 1 条基本成立、1 条空转、3 条零实现。建议先做 MDD-032。

**Step-Reviewer（第三轮）认定的实质问题**：
- **coverage 门的「闭合虚假完成」不成立**：门对 6 个关系的真实列无可观测行为变化——门会拒的列在到达门之前已被 spec 查找与 `assembled_projection` 检查拒绝；provider 缺失被 `layer_state` 抢先；且 **`required_columns` 在所有生产代码中恒为空**（`CoverageRequest::for_scope` 置空），整条 `column_state` 路径仅测试可达。**本轮唯一真实的行为修复是非标量扩展**。已更正 SUMMARY 与代码注释（原注释称「每个有投影的关系都被门覆盖」，对 7 个兜底关系为假）。
- **profile 阻断有一处真漏洞**：`SqlBridge::execute` 只读 `self.profile`，从不读 `prepared.profile`——未声明的桥可执行已阻断 profile 的语句，声明别的 profile 的桥会把反例记到别的 profile 账上。**已修**：新增 `SQL_PREPARED_PROFILE_SCOPE_MISMATCH` 作用域一致性检查 + 测试（213 passed）。
- **032/033 分析**：B1「TEMP catalog 依赖方向硬阻塞」定性错误（是接口约束不是编码阻塞，且与子代理自己的 plan 矛盾）；互锁漏算 Q16（实为 3 个变体）；变体计数 30 应为 29；6 处行号错误。

**验证**：`cargo test --offline --workspace -j 4` 全绿（24 个 test target）；`cargo clippy --offline --workspace --all-targets -- -D warnings` 0 错误；`cargo fmt --all -- --check` 干净。

**未做**：5 列未装配、coverage 的 7 个兜底关系补门、`required_columns` 的生产填充、证据探针的独占干净重建、MDD-031/033/035 闭合。

### 待主代理决策（来自 032/033 准备分析）

1. **Q13.boundary + Q14 + Q16 三个变体互锁**：建议记入 MDD-032 `implementation_notes`——032 的最终闭合以 MDD-033 的 033-B/033-C 完成为前提，032-A/032-B 完成不构成 done（不改 acceptance，只记录依赖）。
2. **TEMP catalog 归属层**：建议保留 `crates/mdd-session/src/catalog.rs`，只放与解析无关的名称/依赖图抽象；`AS SELECT` 物化由 mdd-sql 侧注入。
3. **`lib.rs` 增加 `pub mod profiles;` 属 export 变更**，须主代理单写；且需先定 `profiles` 是否同时承载方言绑定策略。

## 2026-11-11 第四轮（4 子代理完成，Step-Reviewer 待补）

**本轮完成 4 个子代理，全部成功；3 个 Step-Reviewer 已拉起但被取消（用户要求明日继续），故本轮改动尚未经过对抗审查。**

**MDD-026 coverage 兜底门**（`coverage-fallback-gates-20261111`）：`frozen_provider_gate` 扩展 7 个关系（`class_interfaces`/`class_fields`/`class_methods`/`annotation_directory_entries`/`annotation_set_entries`/`annotations`/`annotation_elements`），各自查自己的 provider；`_ => Some(Ok(()))` 改为 `_ => None`；新增 `CoverageRequest::for_relations` + `SnapshotFactIndex::coverage_for_relations` 作为显式列覆盖入口（`for_scope` 保持置空，保守）。mdd-facts 137 lib 通过。**自报：`coverage_for_relations` 目前只有 crate 内测试可达；今日各列判定结果不变（7 关系 spec 列集与 provider available 完全一致）。**

**MDD-026 未装配列收口**（`unassembled-columns-20261111`）：**5 列全部收口，`assembled_projection` 5→0（156/156 全 true）**。provenance 两列在 `SelectedScope` 新增 28 列投影（`dex_file_provenance`），未往 `MetadataSource` 塞字段；`param_descriptors` 有序向量逗号 join（编码 `comma-separated-utf8-v1`）；`opcode_count`/`opcode_hex` 经 `MethodCodeFactViews::method_rows`（code_layout 层，`insns_size` 不计入）。另补 `coverage.rs::provenance_gap` 堵「翻旗即 Complete」。mdd-facts 145 lib 通过。**自报待决：`required-columns.json`/ledger/`compile_column_ledger_v*.py` 的 `==69` 硬断言需单写点同步；raw DEX `entry_name` 叶子名策略；`string_pool_id` UInt32 目录赋值契约。**

**MDD-032 关系注册**（`relation-registration-20261111`）：新增 `crates/mdd-sql/src/provider/hostlab.rs`，**17/17 契约关系全部真实注册**（`HostLabRelation` 枚举映射到事实层行投影），156/156 列对齐 `relations.json`；用冻结 A0 二进制现场取 17 张表逐行全等。mdd-sql 231 passed。**★ 发现契约级冲突（待裁决）**：A0 实测 `file_id` 是**归档枚举序**（`member-policy.apk`：`classes10.dex`=0、`classes2.dex`=1），与 gap 分析断言的数值序、与项目内 `hostlab_file_ids()`/`surface::dex_file_order()` 的数值序实现**相反**；影响所有 JOIN 键。子代理按 A0 实测实现。另：`source_path`/`entry_name` 无 NULL（无法无损表示时整关系失败）；`string_pool_id` 样本上与 `file_id` 相同。**自报待决：Q13 `boundary`/Q14 未实现（属 032-A 切分）；`using_type` NULL 分支无 A0 反例；`provider.rs` 新增 `pub mod hostlab;` 属 export 变更须主代理确认。**

**MDD-033 零实现项**（`catalog-cursors-20261111`）：新增 `crates/mdd-session/src/catalog.rs`（TempCatalog 五项语义：循环/IF NOT EXISTS/DROP 种类/重定义进 retired/跨会话隔离）与 `cursors.rs`（CursorBinding 13 项含 `worker_generation` 与 AST/参数指纹、混合页拒绝、`CompatOffsetState` 兼容 offset 契约）。验收 1/2/3/5 本层完成，验收 4 契约完成但入口未接线。mdd-session 53 passed，6 处变异验证。**自报待决：`lib.rs` 私有 `mod catalog; mod cursors;` 需改 `pub mod`；`SqlResult` 缺分页字段；`mdd.result.v1` 无 offset 字段；`CREATE TEMP` 语法与 `AS SELECT` 物化未接线。**

**验证**：`cargo test --offline --workspace -j 4` 全绿（24 个 test target）；`cargo clippy --offline --workspace --all-targets -- -D warnings` 0 错误；`cargo fmt --all -- --check` 干净。

**⚠️ 明日待办（按优先级）**：
1. **补跑第四轮 Step-Reviewer**（4 个方向：coverage 兜底门、5 列收口、MDD-032 注册（含 `file_id` 裁决）、MDD-033 实现）
2. **裁决 `file_id` 序冲突**（A0 归档枚举序 vs 项目数值序，影响所有 JOIN 键）
3. **单写点同步台账**：`required-columns.json`、`compile_column_ledger_v*.py` 的 `==69` 断言、`column-audit-v10`、合并矩阵口径（156/156 装配后需重算）
4. **主代理 export 变更**：`mdd-session/src/lib.rs` 的 `pub mod catalog; pub mod cursors;`；确认 `mdd-sql/src/provider.rs` 的 `pub mod hostlab;`
5. **独占时段干净重建 MDD-026 证据**（F1/G1 溯源断裂，本轮改动后更需重跑）
6. 5 列收口后重算合并矩阵；`required_columns` 生产填充接线（需改 mdd-query/mdd-sql）

## 2026-11-12 门禁收口（接续第四轮中断）

**门禁验证（经 ucodex runner，本地配置 `.codex-workflow/gate.json` 已加入本地 `.git/info/exclude`，未入库；日志在 `.codex-workflow/runs/`）**：

| profile | 内容 | 结果 |
|---|---|---|
| static | `verify_original_handoff.py`（须用 `.venv` 的 Python 3.12.14 + jsonschema 4.26.0，系统 Python 缺 jsonschema）、`cargo fmt --check`、`check-workspace-boundaries.py` | 通过 |
| native | `cargo check/clippy -D warnings/test`（`--offline --locked --workspace`） | 通过：35 个 test target，754 passed / 0 failed / 0 ignored |
| cli | `cargo build -p mdd-cli`、`check-cli-contract.py`、`check-inspection.py` | 通过 |
| conformance | `conformance/oracles/reproduce.py`（8 metamorphic + 72 oracle checks）、`cargo run -p mdd-build-probe` | 通过；reproduce.py 会把解释器路径写进 `artifacts/mdd-004/fixture-reproducibility.json`，已 `git checkout` 还原以保持历史含义 |
| progress | `tools/check_progress.py` | 先后失败两次，修复后通过：① MDD-022 `implementation_evidence` 指向目录 `.../run1/`，要求为文件，已改指 `run1/record.json`；② `artifacts/index.json` 哈希陈旧，已用 `tools/refresh_artifact_index.py`（工作区模式，9120 条）重算 |

`passed` 只表示所配进程退出码为 0；CI 里的 `record_command` 包装与 ASan/fuzz/Linux 矩阵本地未跑。**提交前必须按暂存内容重跑 `refresh_artifact_index.py --from-index`**，工作区模式的索引不是提交检查点。

**`file_id` 序冲突已裁决（第四轮待办 2）**：A0（`dexsql 0.1.0`，sha256 `f354ebcf…c448`）的 `file_id` 是**归档枚举序**，不是 `classes<N>.dex` 数值序。独立证据：4 个乱序合成归档全部等于 ZIP 序；真实 Bilibili 9.16.1 上 `file_id=4` 是 `classes13.dex`（A0 数得 7,328 个类），不是 `classes5.dex`（12,038 个类）。旧 `NativeSession::hostlab_file_ids()` 注释「A0 证据证实 file_id=4 为 classes5.dex」被直接反证，已改为恒等映射（`mdd-facts/src/hostlab/{mod,rules}.rs`），新增测试 `hostlab_file_id_follows_archive_enumeration_not_numeric_member_order`。`surface::dex_file_order()` 的数值序是 `native_surface.scan` 的二次映射，保持不动（字段名 `file_id` 易误导，留给 MDD-052）。证据：`artifacts/mdd-032-audit/file-id-adjudication-20261112/`，复跑说明：`artifacts/mdd-051/skeleton-20261112-file-id-fix/NOTE.md`（Bilibili `class_count` 310,716 与 A0 一致；两份 Bilibili 原始运行记录含应用内部类名，已移出仓库，仅留在本机 `artifacts/local/mdd-051-private/`）。mdd-sql 的 `dex_files.file_id` 本就按归档序，无需改。

**backlog 如实化**：MDD-032、MDD-033 由 `todo` 改为 `in_progress`（均已有实质实现，注明未完成部分，验收未改）；MDD-026 过期的 `blocking_reasons`（MDD-022 重开）换为当前真实阻塞；MDD-032 记录 Q13.boundary/Q14/Q16 与 MDD-033 的互锁依赖。

**第四轮对抗审查已补跑（2026-11-12，主代理内联，未用子代理）**：
- **MDD-032 关系注册**：新建对冻结 A0 的独立差分，185 个夹具 × 17 关系共 3,145 条记录（A0 作答 2,703）。2,097 条逐值相等（含上述修复后变为相等的 11 条）；603 条本引擎显式拒绝（缺层、合法非标量字符串、结构非法输入，均为 fail-closed）；3 条作答但有差异（非 BMP 字符）；2 条 A0 拒绝而本引擎作答（`class_methods` 不依赖 A0 所拒的 code item）；440 条两边都拒绝。真实 NewPipe 0.28.6 上 17 个关系的行数与 A0 全等。新增永久测试 `a0_differential_over_the_fixture_corpus_has_only_declared_divergences`，已用序号 +1 的变异验证有效。证据：`artifacts/mdd-032-audit/a0-differential-20261112/`。
- **发现 1（已关闭）**：夹具含合法孤立（无人引用）注解项时，`annotation_set_entries`/`annotations`/`annotation_elements` 比 A0 多行（7 个夹具、11 条记录）。用户裁决「只投影可达项」：`AnnotationFacts` 新增 `reachable_*` 行生产者（类绑定目录经 class/field/method/parameter-ref-list 可达的集合、注解项与元素），事实层保留孤立项，`mdd-sql` 的 hostlab 提供者改用 `reachable_*`。11 条记录变为与 A0 相等，NewPipe 四个注解关系行数仍与 A0 全等，三处可达性变异均被杀死；新增事实层测试 `unreferenced_items_stay_facts_but_are_not_reachable`。
- **发现 2（兼容台账待登记）**：补充字符（非 BMP）的 MUTF-8，A0 把每个字节替换为 U+FFFD，本引擎还原为正确标量；不复制 A0 的有损行为。
- **5 列收口**：由差分覆盖（`dex_files` 28 列、`methods` 的 `param_descriptors`/`opcode_count`/`opcode_hex`），未发现缺陷；`source_path` 与 A0 只差路径拼写。
- **coverage 兜底门**：三处变异，两处被现有测试杀死，`_ => None` 改成默认 Complete 的一处存活（该分支对现有 156 列不可达）。已补测试 `unmapped_relation_is_never_gated_to_complete`，复跑该变异已被杀死。
- **MDD-033**：只精读了 `cursors.rs` 的游标绑定/页延续/兼容 offset 路径与 `lib.rs` 的 catalog epoch 交互，未发现缺陷；`catalog.rs`（1,079 行）未读，`cursors.rs` 约四分之三未读，**不能当作完整审查**。
- 桥的 AST 适配器未实现 `typeof` 与 `replace`（必需语料 `representative_sql` 未使用 `replace`，已核对）。

**磁盘（ucompact，2026-11-12 经用户确认已合并）**：扫描 `artifacts` 与 `handoff`（5.27 GB），`apply --yes` 合并 25 个文件为只读硬链接，回收 2,273,135,108 字节（约 2.1 GB），0 跳过；其中 1.92 GB 来自 `artifacts/local/mdd-perf/golden/{new,old}-encoded/newpipe-classes.dex.json`。`verify --content` 无 corrupt object；2 条 `path missing` 属 `D:\MeguvizUI\.mimosa\hook-state` 的他项目文件，与本仓库无关。合并后的文件为只读（链接数 3，含存储对象）：重写这些文件的脚本须先 `ucompact restore --path <前缀> --yes`。`handoff/verified-*` 是 `verify_original_handoff.py` 每次运行留下的可再生目录，未删除。扫描报告在 `%TEMP%\ucompact-report.json`（临时，不入库）。

**待办收口（2026-11-12 续，用户要求一口气做完上线前待办并注意复审；全部由主代理内联完成并用独立 oracle/变异验证，没有使用子代理）**：

| 第四轮待办 | 状态 |
|---|---|
| 1 对抗审查 / MDD-033 全文 | 已读完 `catalog.rs`（1,079 行）与 `cursors.rs`（1,524 行），修了 4 处，见下 |
| 2 `file_id` 序冲突 | 已裁决并修复（前文） |
| 3 台账同步 | `compatibility/ledger.json` 登记了 4 条 HostLab SQL 关系分歧/裁决，`fact_indexes_and_coverage` 改为现状；`qualify.py` 是历史生成器，按设计在源码漂移上失败，已在文件头写明，不改其断言 |
| 4 导出变更 | `provider.rs` 的 `pub mod hostlab;` 已在；`catalog`/`cursors` 仍为私有 `mod`——没有消费者，等 mdd-sql 接线 `CREATE TEMP`/分页字段时再改，本次未动 |
| 5 独占时段干净重建 | 已做：两组 harness 在 cargo 对当前源码报告的 rlib 上重跑，结果与 2026-11-11 逐列相同；合并矩阵 140/156 列六类全满足，未装配 0（`artifacts/mdd-026/evidence-merged-clean-20261112/`） |
| 6 `required_columns` 生产填充 | HostLab SQL 提供者现在在打开任何关系前用 `CoverageRequest::for_relations` 取账本裁定（每关系计算一次并缓存）；typed-IR 的 mdd-query 执行器路径仍只请求层，未改 |

**复审发现并修复**：
- `CompatOffsetState::admit`：首页的精确总数不参与 `more_available` 判断，会给出不存在的续页；页内行数/lookahead 与精确总数互相矛盾时被放行。现在对首页和后续页都校验，矛盾返回 `total_conflicts_with_page`，被拒页不计入。
- `CompatOffsetState::next_request`：行预算耗尽而上一页仍报 `more_available` 时返回 `Ok(None)`，驱动循环会把截断当成结束。现在返回 `QuotaExceeded(max_rows)`。
- `bind_query_temp`：只绑定 SQL 里写出的名字，视图背后的表不在存储绑定里，`verify_query_temp_binding` 保护不到。现在按查询代次传递闭合地绑定依赖，缺失的依赖报 `unknown_relation` 并写明 `required_by`。
- `cursors.rs` 的恒真断言 `assert_eq!(x.worker_owner, x.worker_owner)` 改为与注册表的真实 owner 比对。
- 验证方式：`cursors.rs` 的三项先写出红测试、修复后变绿；`bind_query_temp` 的两个测试与实现同时写成，随后用「删除依赖入队」的变异确认两个测试都会失败。

**合并脚本缺陷**：`merge_evidence.py` 把第一轮的静态降级表套在修复轮重新取证过的结果上，`class_interfaces.ordinal` 的 order/multiplicity 因此被错误地保持 partial。`merge_evidence_clean.py` 只在没有修复轮来源重取证该类别时才应用降级，被取代的 7 条降级记录在 `superseded_reviewer_downgrades`。旧矩阵保留。

**行为变化（已写入差分测试的固定值）**：coverage 账本接入后，`references/generated/` 下 `bad-caller-ins-size`、`bad-custom-argument-count`、`bad-custom-prefix` 三个夹具的 `methods`/`code_items` 共 6 条记录由「与 A0 相等」变为显式拒绝：这三个夹具无法构建引用层，账本在没有引用层/raw code 时无法证明 `MethodBindings`（ADR-017 把它与 `AllMethodBodies` 区分）。差分测试的相等记录数因此由 2,097 变为 2,091。

**验证**：static、native（35 个 test target，763 passed / 0 failed / 0 ignored，clippy 无告警）、cli、conformance、progress 全部通过。NewPipe 0.28.6 上接入账本后 17 个关系行数仍与 A0 全等，账本开销单个关系 2–455 ms。

**仍未做**：16 列未满足全部六类（见 `evidence-merged-clean-20261112/SUMMARY.md`），差分证据是否折算进六类矩阵需要口径决定；typed-IR 路径的列级覆盖；`catalog`/`cursors` 导出与 `CREATE TEMP`/`mdd.result.v1` 分页字段接线；MDD-035 以后的 30 个 todo 任务；CI 的 Linux/ASan 与 `record_command` 包装。以上改动已在分支 `codex/m2-facts-20261028` 上分四次本地提交（conformance 脚本、证据与 artifact 索引、引擎代码、状态文档），尚未推送。

## 2026-11-12 合入 origin/main 与公开范围

**事实更正**：`origin` 是公开仓库（`Meguvizarchic/MeguvizDexDash`），不是此前文档写的私有远端。2026-11-12 本分支曾被整体推送，随后发现这一点，已删除远端分支（GitHub 上提交仍可按 SHA 读取）。此后按用户决定「证据和类名都不入库」做了下列处理，本地分支至今**没有再次推送**。

- 合入 `origin/main`：`git merge -s ours`，因为 main 的 `27ac27e` 是本分支 `71dfce9` 的脱敏副本，它在 `crates/` 下的实质修补本分支都已包含（逐文件核对，仅 lint 写法不同）。自动合并曾向 `indexes/mod.rs` 插入约 300 行重复定义、把 MDD-022 改回 in_progress，均不采用。采纳 main 的内容：README 头部与图标、`benchmarks/README.md` 去掉本机解释器绝对路径、`artifacts/public-progress-20261104/` 两份记录。
- **应用类名不入库**：`hostlab/catalog.rs` 不再含任何应用类名，只保留规则读取的键名（`REQUIRED_LISTS` / `REQUIRED_CONSTANTS`）和校验构造器 `HostlabCatalog::new`；载荷在运营方提供的 JSON 文件里，`hostlab_audit` 示例以第二个参数读取。`surface_summary` 示例的家族前缀表同样改为 `--families FILE.json`。载荷导出到本机被忽略的 `artifacts/local/hostlab/`。在私有 APK 上用外部文件重跑，`surface_summary` 与 `hostlab_audit` 的业务输出与改动前逐项相同（只有每次运行都不同的 occurrence/snapshot id 不同）。rules.rs、surface.rs 里引用应用类名的注释与测试字符串改为中性写法。
- **含本机路径的原始证据不入库**：本分支新增的证据文件中有 1,143 个含 开发盘符路径或 Windows 用户目录之类的本机路径（此前口头报告的 128 个是 grep 转义写错造成的低估），共约 11 MB，已整体移到本机 `artifacts/local/withheld-evidence-20261112/`（保持原目录结构），不进入提交。说明见 `artifacts/WITHHELD.md`。唯一被代码依赖的一份（`scope.rs` 测试读取的 A0 provenance 记录）改为可移植夹具 `tests/fixtures/provenance/a0-dex-files-provenance.json`：`source_path` 记为相对仓库根的路径，测试按本机检出根去前缀后比较，不再要求仓库位于录制机器上的固定目录（原测试在任何其他路径上都会失败）。
- 两份对私有 Bilibili APK 的原始运行记录同样只留在本机 `artifacts/local/mdd-051-private/`。
- **更早提交里的 31 个带 Windows 用户目录路径的日志文件已用改写历史去掉**（用户决定）：对本分支相对 `origin/main` 的 77 个提交逐个过滤——删除 31 个证据文件（mdd-005 15 个、mdd-031-audit 15 个、mdd-026 1 个）、把历史版本 `benchmarks/README.md` 里的解释器绝对路径改为 `python`、并同步删去 `artifacts/index.json` 中对应的记录。改写后按内容重扫整段历史，含本机路径或应用类名且 `main` 上没有的文件内容为 0；77 个提交作者仍为 `jichuo1`，无任何附加署名；每个提交的索引记录都能在该提交的树里找到对应文件。提交号因此全部改变。`main` 上本来就有 258 个含此类路径的文件，未触碰。
- 本地备份分支 `backup/pre-clean-20261112`、`backup/pre-withhold-20261112`、`backup/pre-history-rewrite-20261112` 已按用户决定删除。改写前的提交现在只剩在 `.git` 的 reflog 与未回收对象里，`git gc` 前仍可恢复；此前就存在的 `archive/m2-unpublished-e024eca`（含不在本分支历史里的工作）保留未动。

## Checkout 与交付

工程目录 D:\MeguvisDexDash（保留目录原拼写）。远端已迁移到 https://github.com/Meguvizarchic/MeguvizDexDash（**公开仓库**，旧地址 jichuo1/MeguvizDexDash 自动转发）；PR #1 已于 2026-11-04 合并，`main` 现为 a9aa1f0，其中 27ac27e 是由本分支 71dfce9 生成的「脱敏工程进度快照」，之后 8 个提交是修补与 README/图标。本地分支 codex/m2-facts-20261028 当前**没有远端分支**：2026-11-12 曾整体推送，随后发现仓库公开，已按用户决定删除远端分支（GitHub 上提交仍可按 SHA 读取）。重新推送前必须先决定公开范围，见下节。

大范围 push main 曾被自动审批以缺少本次默认分支推送明确授权为由拒绝；后续采用独立分支和草稿 PR。没有合并、默认后端切换、部署或正式发布。

原工程包 SHA-256 b5f2f3859a5a7753f83f8edc24c73ce15781075afb899e4e63b274fdcc161844，原始规格提交 3bbf1088137e70c5d3d722534a5eeab8b69a596c；handoff/original/MeguvizDexDash 保持不变。原包 verify_kit/recompute_targets 实际通过（56 文件、23 历史证据、51 DAG 任务）；这些不是引擎测试。

## 已验收的实现范围

- M0：MDD-001/002/003/004/006 已完成各自验收；005 尚未完成。
- M1：MDD-010/011/012/013/014 已完成限定任务范围，包括不可变快照、逻辑出现次数、ZIP32/ZIP64 物理成员、生命周期与真实 worker 故障。012 曾重新打开补齐 ZIP64，52 向量及 65,535/65,536 成员边界已重验。
- M2：MDD-020/021/022/023 已完成。MDD-022 于 2026-11-09 完成独立完整复验并关闭：重开根因（短参数列表把 Unknown 位置误报为已知）已修复；参数槽 i 对应原型参数 i 依据 ART `GetAnnotationForMethodParameter` 直接索引 `annotation_set_ref_list.list_[parameter_idx]` 的实现事实，而非 DEX 规范（规范不要求长度相等）；编码槽数与原型参数数相等才标 Complete，否则 Unknown，缺失尾部位置绝不补 NULL。新增跨全部 7 个参数夹具的聚合不变量测试（覆盖 complete/unknown/unbound 三类，取代原先对未绑定 ref-list 的空转循环）。证据 artifacts/mdd-022/annotation-conformance.json（run 20261109T044316003186Z，12 条命令全 exit 0，reader 8/facts 29 为实测解析而非硬编码）与 artifacts/mdd-022/parameter-position-art-adjudication-20261109/adjudication.json。020 曾因内部 item 引用反例重新打开，已用物理起点、合法 orphan、SDK 正反例与公开样本重新验收。Ready facts 对外只读。MDD-026 依赖门现已全部满足，但其 156 列逐列资格仍未完成。
- MDD-024：9 引用测试、18 手工 fixture（11 所需层成功、7 真损坏）、43 个固定 A0 完整小关系比较通过。公开 NewPipe 两 DEX 共 509,322 operand sites 完整读取。精确声明查找不等于运行时分派/继承解析；合法非 scalar 文本保留 UTF-16，拒绝有损 UTF-8 投影。
- MDD-025：原始方法体、资源和 Manifest 所需事实验收完成。公开 55,763 方法、8,540 类聚合 recipe、792 资源逐项/摘要对齐固定 A0、Python 和原 HostLab 规则；76 Manifest 向量、AAPT2 完整树及 A0 六页结果通过。方法无 body 与空 body 区分，Manifest 与资源持有同一 Arc，源改写/重命名/释放后仍保持同快照证据。见 artifacts/mdd-025/raw-evidence-conformance.json。

公开样本为官方 NewPipe 0.28.6，10,885,562 字节，SHA-256 e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58。APK 位于 ignored artifacts/local/inputs，不进入 Git。上述均非 ART 完整验证、完整 HostLab 替代或性能资格。

## Step-Reviewer 对抗审查结果（2026-11-09，3 路并行）

三个 Step-Reviewer 分别审查预算/终态、DEX 解析/debug 记忆化、解包/门面 API，均给出可复现反例。已按风险修复：

- **`charge_row` 报错顺序反转（已回退）**：批量记账会让 `MAX_CELL_BYTES` 先于 `MAX_BUFFERED_BYTES` 触发，且 `step()` 内的 `MAX_STEPS` 与单元额度的交错顺序无法在批量路径复现。审查者给出最小反例（`buffered=B-1`、cell 含 `C+1` 字节）。**已回退为原顺序**，注释说明原因；`budget.rs` 层面的优化已让每次调用便宜很多，不再需要批量化。
- **`SqlControl` 原子计数丢失更新（已修）**：`load`+`store` 非 RMW，两个线程同时 checkpoint 会少计步数，`max_result_rows` 理论上可超至 N 倍。当前 mdd-sql 是叶子 crate、每次执行私有内存连接、`SQLITE_LIMIT_WORKER_THREADS=0`，实际单线程不可达；但 `SqlControl: Clone` 且派生控制共享 counters，公开 API 允许并发。**已改为 `try_update`（RMW）**，无锁且不丢更新。
- **`read_member` 对撒谎成员一次性预留 512MiB（已修）**：126 字节 APK 把声明尺寸改成 512MiB 即触发 ~514MiB 真实提交，之后才报长度不符。**已改为有界初始窗口 + 几何增长**（分块读，无零填充），恶意声明最多只占窗口。
- **`InputKind::detect` 与 `capture` 错误码不一致（已修）**：detect 对坏 magic 返回 `UnsupportedCapability` 并附带本机绝对路径 detail，而 capture 返回 `InvalidInput`。已统一为 `InvalidInput` / stage `capture` / 相同 message，并去掉 path detail。
- **门面深拷贝（已修 + 文档纠正）**：`references()` 实测 538ms vs 分阶段 183ms，其中 `CodeFacts` 深拷贝 ~277ms、`DefinitionFacts` ~66ms；而 `docs/guide/README.md` 宣称门面「不会重复深拷贝」，与代码相反。**已为 `DefinitionFacts.metadata`、`ReferenceFacts.definitions/code` 改为 `Arc` 并新增 `build_arc` 变体**（启用 serde `rc`，JSON 逐字节不变），门面 `references()` 现在零拷贝；`AnnotationFacts` 因测试对 definitions 有可变注入需求且收益仅 66ms，**保持自有所有权**，文档已改为事实与量级。
- **测试缺口（已补）**：① 无任何测试锁住「debug 程序只解码一次」——删掉缓存 51/51 仍全绿，已加 thread-local 解码计数器与断言；② `SignedDecimal` 的 `i64::MIN`（20 字符，正好卡栈缓冲边界）未入测试值表，已补 `i64::MIN/MAX`；③ 缺 `RESOURCES[i].slot()==i` 一致性断言（枚举与数组顺序耦合，漂移会导致越界 panic 或静默错账），已补。
- **注释准确性（已修）**：`sticky` 的首错窗口说明原先对 `SQL_WORK_BUDGET` 路径不成立；`Node.soft/hard` 「never rewritten」应限定为「无生产路径改写，仅测试改写」。
- **`add` 深度守卫 fault 登记不对称（已修）**：`add` 不登记 `state.fault` 而 `release` 登记，同一种内部损坏会有两种故障语义，已统一。

审查者同时确认（附方法）：`Resource::slot()` 与 `RESOURCES` 顺序严格一致；`add` 的「先全链校验再统一写入」失败时零写入；`charge_row` 的 accept/reject 判定完全等价（仅 reason/observed 有差，故回退）；`RuntimeBudget` 缓存 deadline 安全且 poisoned 测试机制未变；debug 记忆化的错误顺序、寄存器重放、额度 replay、`StrictSourceLinesV1` 顺序、`code_item_address_scope` 边界均与旧实现一致——审查者用 `git archive HEAD` 构建差分 oracle，**约 95,600 个用例**（含 178 个真实 dex × 2 策略 × 6 档预算、25 个手工构造程序 × 8 种寄存器宽度 × 7 种 code size）逐字节比对 `CodeSection` JSON 与完整 `MddError` 全部一致；解包侧的错误码/阶段/detail 也逐场景一致。

## DexSQL 实测对照（2026-11-10，首次真实数据）

**阻断已解除**：可用物理内存 19.10 GiB（≥ 预注册 10 GiB）；参考 checkout 已按 commit `8782f43d` 重建于 `artifacts/local/hostlab-reference`（97 个源文件哈希全部匹配）；A0/A1 引擎二进制哈希与 manifest 一致；Java / SDK 工具 / MCP 2.2.0 / Windows Job smoke 全部通过。因工作区与私有输入都已迁移，另存了**仅改路径**的 manifest 副本 `artifacts/local/baseline-manifest-20261110.pathadapt.json`（原 `benchmarks/baseline-manifest.json` 未动，改动清单见同名 `.adaptations.json`）。

**A0（DexSQL 0.1.0）实测**：输入 Bilibili 9.16.1（9161100，226,519,215 字节，33 个 DEX），独占 Job 下 **wall 70.39 s**（监督器 wall 72.86 s、CPU user 79.81 s），阶段拆分 prepare 2.28 s / structural 10.33 s / surface 41.67 s；覆盖 **310,716** 个类、27 项 FEATURE 中 25 FOUND / 1 PARTIAL / 1 MISSING、635 条查询、20 组证据、零 fallback，进程树已核实清空。证据 `artifacts/local/perf-20261109/dexsql-a0-9161100-20261110T030926Z/`。该运行是 observed qualification（`formal_performance_qualified=false`），**不是** MDD-082 性能资格；其 `business_exit_code=1` 是 FEATURE 缺口计数（25 FOUND / 1 PARTIAL / 1 MISSING），不是运行失败。

**同一 APK 上本引擎实测**：约 **19.46–22.86 s/轮**（随机器负载，原始记录 our-bilibili/record.json）（捕获 0.22 / 清点解压 0.81 / metadata 1.30 / definitions 1.40 / code 9.27 / references 3.91 / annotations 2.55），同样 33 个 DEX、**310,716** 个类，另构建 1,731,482 方法定义与 959,036 字段定义。

**口径**：两者**不是端到端等价比较**。DexSQL 的 70.39 s 覆盖 HostLab 完整业务审计（635 查询、20 组证据、surface 报告、home 探针）；本引擎的 19.46 s 只覆盖「读入→清点解压→事实构建」。本引擎尚未实现 HostLab 查询与审计面（MDD-051 未开始）。唯一完全对齐的事实是同一 APK、33 个 DEX、310,716 个类。报告已写入 `artifacts/local/perf-20261109/APK解包性能证据报告.pdf`（含该对照表与口径警告）。

## 对抗审查发现的缺陷与修复（2026-11-10）

三路 Step-Reviewer 对抗审查（正确性 / 性能等价性 / 基准与证据）。确认缺陷全部修复：

1. **`valid_member_text` 放宽**（`mdd-dex/src/definitions.rs`）：新实现无条件跳过前导 `<`，使 `<init`、`<clinit`、`<foo` 这类单侧 `<` 的畸形名从「拒绝」变成「接受」。已改回要求 `<` 与 `>` **成对**，与旧的 `strip_prefix('<').and_then(strip_suffix('>'))` 等价。
2. **`decode_mutf8` 错误类别漂移**（`mdd-dex/src/strings.rs`）：ASCII 批量快路径把 `STRING_LENGTH_MISMATCH` 误报成 `STRING_BYTE_BUDGET`（两者同时越界时）。已改为**只有整段都 fit 两个预算才走快路径**，否则回落逐单元；并把整串 ASCII 快路径限制在 `length == declared` 的成功情形。新增穷举等价测试 `decode_mutf8_matches_the_historical_per_unit_decoder`：**356,550 例**（1~3 字节 × 12 字母表 × declared 0~3 × max_bytes 0~4）与新旧实现逐字段比对，**零分歧**。
3. **`BudgetUsage.used` JSON 形状变化**（`mdd-query/src/budget.rs`）：由「只含已计费资源」变成恒含 19 项。已加 `charged: u32` 位掩码，恢复只输出真正计费过的键。
4. **`FactsSession::definitions()` 仍深拷贝 `MetadataFacts`**（`crates/mdd-facts/src/session.rs`）：改用 `build_arc` 共享 `Arc`，并加 `Arc::ptr_eq` 断言锁死（此前文档与实现不符）。
5. **`RuntimeBudget::checkpoint()` 漏掉 `state.fault`**（`mdd-query/src/budget.rs`）：原本只查 `is_poisoned()`。已加 `sticky_fault: AtomicBool`，`lock()` 观察到 fault 时置位；正常路径仍无锁，异常路径才取锁并**经 `stop()` 记录 lifecycle 终态**（裸 `?` 会跳过终态，已由测试 `poisoned_budget_checkpoint_records_fault_and_preserves_prior_cancel` 捕获并修复）。

审查同时确认无误的项：`Registers` 全边界（空/1~5/恰好5/6/255/256）语义与 JSON 一致；`SignedDecimal` 与 `i64::to_string()` 逐字节一致且拒绝非规范形式；SWAR 零/高位检测 2 字节穷举 + 200 万随机词零分歧；`Arc` 共享无 `make_mut` 隐式深拷贝；`InputKind::detect` 与 capture 错误码一致；`budget`/`control` 原子计数 RMW 不丢更新。

## 按 DEX 并行（2026-11-10）

`crates/mdd-facts/src/pipeline.rs` 新增 `FactsPipeline`（`std::thread::scope`，无新依赖）：每 DEX 走与串行相同的链，窗口约束领取（默认 `2*threads`）+ 窗口内按大小优先，交付严格按 inventory 序，失败语义 = 串行中止位置。Bilibili 33 DEX / 4 CPU lease 实测：串行 18.3 s，**3 线程最优 ≈1.66×**（11.1 s），4 线程因分配器/堆压力回退到 1.28×。跨进程 serial vs threads=3 的 `combined_sha256` 相等、33/33 逐 DEX 五层 digest 位置全等、Arc 共享图与串行一致。

**必须注意的风险**：`available_parallelism()` **无视 CPU lease** —— 在 24 核机器上默认会起 24 线程，实测 182 s（比串行慢 10 倍）、峰值 16.4 GB。默认值只在整机独占时安全，受限环境必须显式传 `PipelineConfig::threads`。

## 线程分配与大小核调度（2026-11-10）

**问题**：`PipelineConfig::resolve_threads` 原先用 `std::thread::available_parallelism()`，而 Rust std 文档明示它在 Windows 上「**may overcount** ... systems limited by process-wide affinity masks, or job object limitations」。实测：4 CPU lease（affinity mask 15）下该 API 仍返回 24，默认会起 24 个 worker —— 182 s、峰值 16.4 GB，**比串行（18.3 s）慢 10 倍**。

**已实施**（`crates/mdd-facts/src/threads.rs`，无新依赖，仅 FFI）：
- `leased_cpu_count()`：Windows 用 `GetProcessAffinityMask` 按掩码计数；Linux 用 `sched_getaffinity`；其他平台返回 `None`。
- `default_threads()`：优先级 `MDD_FACTS_THREADS`（正整数，未设上限）> `leased_cpu_count` > `available_parallelism`，再经 `workers_for()`。
- `workers_for()`：**预留一个逻辑 CPU 给协调线程**（`available - 1`），并封顶 `DEFAULT_MAX_THREADS = 4`。依据是实测：4 CPU lease 上串行 18.3 s、2 线程 11.4 s、**3 线程 11.1 s（最优）**、4 线程 14.4 s —— 第 4 个线程因 per-DEX `Vec`/`String` 分配竞争让 CPU 时间从 18 s 膨胀到 31 s。
- 新增 `affinity_mask_bounds_the_detected_thread_count`（Windows）：显式把进程亲和掩码设为 4 CPU，断言检测值 = 4 且解析值 = 3。用共享 `Mutex` 串行化所有触碰进程级状态（亲和掩码与 `MDD_FACTS_THREADS`）的测试。

**大小核（P-core / E-core）结论**：**本轮不做显式 P 核绑定**。理由：① Windows 只通过 `GetLogicalProcessorInformationEx` 的 `EfficiencyClass` 暴露核型（Chromium 用 max class 判 P 核），需要一大块 `unsafe` 结构体布局；② Windows 调度器在 Intel Thread Director 配合下已负责把延迟敏感线程放到 P 核，应用只能「影响」不能「指定」；③ 本负载是内存带宽/分配密集型，实测 3 线程即饱和，P/E 区分带来的收益小于其 unsafe 面积与测量成本。若将来要做过，前提是先有「P 核池 vs E 核池」的对照测量。

## 性能等价性审查（2026-11-10，第三个审查者）

**确认的结果错误（已修）**：定义名索引 `finish()` 用 `&str`（UTF-8 字节序）排序，却用 `[u16]`（UTF-16 码元序）二分查找。对含补充平面字符的**合法** DEX 名（如 `La\u{10000};` 与 `La\u{E000};`），两者顺序不同，导致已存在实体查不到，并使 `absence_proven_within_selected_scope` 给出**虚假的「已证明不存在」**（无错误码）。旧实现用 `BTreeMap<(kind, Vec<u16>), …>` 天然一致。已抽出 `cmp_definition_name()` 按 UTF-16 码元排序，并加回归测试 `definition_name_postings_use_utf16_code_unit_order`（同时证明 UTF-8 序确实相反）。已核对其他索引：`Vec<u16>` 系（strings/units/raw/definitions）与 `String` 系（descriptor/symbol）各自排序与查找同序，无同类问题。

**一并修复的可观测差异**：
- `DexText::strict_utf8` 的 ASCII 快路径原先只检查 raw 全为 ASCII，对 `Deserialize` 出来的不一致 `DexText`（raw 为空、units 为 "A"）会返回空串而旧实现返回 "A"；已加 `raw.len() == units.len()` 一致性条件，仅解码器输出走快路径。
- `RuntimeBudget::checkpoint()` 的 `sticky_fault` 原先只在 `lock()` 里置位，而 `release`/`add` 是**持锁直接写** `state.fault` 的；若此后无人调 `lock()`，`checkpoint()` 仍会漏报。已在全部故障写入点（`add` 深度守卫、`release` 深度守卫与下溢、`Drop for ReservationInner` 的计数下溢与 `release` 错误）直接置位。新增回归测试 `sticky_fault_flag_is_raised_by_lock_and_shared_with_derived_pools`。

**已核对无问题**（含方法）：`Arc` 字段 JSON 透明（serde rc 实测逐字节相同）、`SignedDecimal` 与 200 万随机值零分歧、`Registers` 序列化与边界、`valid_member_text` 与旧实现穷举 0 差异、`needs_arrays/needs_handles` 决策等价、CSR `TargetIndex` 同序、`class_data_starts` 去重等价、`BudgetUsage.used` 位掩码恢复原形状、`budget::add/release` 先校验后写入与失败零写入、`decode_mutf8` 356,550 例穷举零分歧、debug 记忆化的额度/寄存器/scope 顺序、`session.rs` 无 `make_mut` 隐式深拷贝。

**仍存在的可观测差异（多为有意或仅内部故障可达，未改）**：`ReferenceUsage.fact_bytes` 随 `mnemonic: String→&'static str` 下降（8 字节/站点，已记录）；索引记账口径变化（`UnitPostings` 固定 +262,148 字节/实例、定义项按 UTF-8 字节而非 UTF-16）；`SqlControl` 的四个 `*_OVERFLOW` 由一次性错误变为粘性首错（需计数器真正到 u64 上界）；`Instruction/DebugInfo/LocalReferenceSite` 的源码级 API 类型变化（JSON 与语义不变）。

## 当前推进与阻塞

2026-11-09 本轮（性能与可用性改造，全部语义等价、测试全绿）：
- **新增阶段计时探针** `tools/mdd-timing`（workspace 成员，仅 dev 工具，无新外部依赖）：把 capture / inventory / metadata / definitions / code / references / annotations 分阶段计时并输出 `mdd.timing.v1`，只做开发归因，不构成性能资格。基线（NewPipe 10.9MB，2 DEX）：全链 3446.9ms/轮，code 独占 1990.7ms（58%），capture 18.1ms，inventory+解压 31.0ms。
- **debug 程序记忆化 + 零分配类型**（`crates/mdd-dex/src/instructions/{debug,mod,decode}.rs`）：实测同一 debug 物理程序被约 18 个 code item 重复解析（47110 item / 2616 唯一程序 / 4439385 事件），且每事件一个 `String`。现按 debug offset 记忆化程序级解析（`DebugProgram`/`ProgramEvent`，不含依赖 code item `size` 的 `code_item_address_scope`，按 item 现算），寄存器越界按事件顺序重放、额度逐事件 replay、只缓存成功解码；`encoded_line_decimal: String` → `SignedDecimal(i64)`（栈缓冲序列化，JSON 逐字节不变），`Instruction::mnemonic/format` → `Cow<'static,str>`（OPCODES 表为 'static，零分配）。**golden 等价证据**：用 `git archive HEAD` 在仓库外构建旧实现 oracle，63 个输入（含 NewPipe 2 DEX、全部 debug 反例、4 个合成反例）在 EncodedFactsV1 与 StrictSourceLinesV1 两种策略下 **59/59 逐文件 JSON 全等**；`debug_events_materialized` 保持 4419385/24141 不变；`code_layout_summary` normalized SHA-256 与 artifacts/mdd-023/public-newpipe-code-layout-encoded-policy/stdout.txt 同值。变异测试（临时把失败程序也缓存）使新测试立即失败，证明测试锁住了该反例。**收益**：code 阶段 652→360ms（DEX1，−44.2%），全链 3535.5→2503.2ms（−29.2%），DEX1 分配 8784381→2229639（−74.6%）、分配字节 −48.7%。
- **查询预算热路径**（`crates/mdd-query/src/budget.rs`）：`Node.used: BTreeMap<Resource,u64>` → `[u64; 19]`（按 `Resource::slot()`）；`BudgetPool` 缓存不可变祖先路径 `Arc<[String]>`，`add`/`release` 改为「先全链校验、再统一写入」且零堆分配；`RuntimeBudget` 缓存构造期 `DeliveryBudgetDeadline`（`Node.soft/hard` 构造后从不改写），`checkpoint` 仍每次探测锁中毒（`is_poisoned` 为原子读，保留 `poisoned_budget_checkpoint_records_fault_and_preserves_prior_cancel` 语义）。`Control::charge_row` 由每 cell 一次 `charge` 改为本地聚合后单次记账，并补回等量步数；`Control::step` 的 hook phase 序列不变。
- **SQL 控制快路径**（`crates/mdd-sql/src/control.rs`）：`State` 的四个计数器改为原子 `Counters`，`failed: AtomicBool` 让 `error()` 热路径免锁，sticky 首错仍写同一把锁；`checkpoint`/`output` 的限值判定与首错语义保持，发布/Ack/End 路径一律未动。
- **解包快路径**（`crates/mdd-input/src/{archive/mod,snapshot/mod}.rs`）：capture 复用已算 digest（消除重复全量 SHA-256）并按 `metadata.len()` 与剩余额度取小预分配（保留 fallible→QuotaExceeded）；`read_member` 改为预分配后单次填充读（去掉 64KiB 循环 + 每轮 `try_reserve` + `extend_from_slice` 二次拷贝），并在分配前检查声明 size 对 `max_member_bytes`/`max_total_uncompressed_bytes`；新增 `member_index: BTreeMap<String,usize>` 消除成员线性查找。**收益**：capture 20.1→11.7ms（−42%），STORE 成员 5.73→2.0–2.8ms；8 个 APK 夹具（bad-crc/invalid-dex-member/member-policy/duplicate-name/duplicate-content/multidex-deflated/multidex-stored/renamed-member）与 HEAD 版本逐成员输出 diff 为空。**明确放弃（附实测依据）**：每成员重建 ZipArchive 固定开销仅 0.5–45µs，非热点；并行解压在 NewPipe（classes.dex 占 92.8%）受 Amdahl 限制仅 1.08x；去掉 zip crate 直读 flate2 差 ~3% 且需新增两个直接依赖；STORE 零拷贝需改 `MemberBlob` 的 `lease()` 语义，触碰资源共用 Arc 契约。
- **可用性（DX）**：新增 `crates/mdd-facts/src/session.rs` 一站式门面 `FactsSession`（`open`/`metadata`/`definitions`/`code`/`references`/`annotations`，同层只构建一次并复用 `Arc`，`open` 不预建关系、`Partial`/`Unknown` 不折叠），`FactSet` 便捷句柄；`InputKind::detect`/`matches_magic` 按 magic 判定输入类型（消除 6 处扩展名猜测，且与 capture 校验同源）；`ErrorCode` 实现 `Display`（与 JSON 的 SCREAMING_SNAKE_CASE 一致）；新增可运行示例 `crates/mdd-facts/examples/quickstart.rs`；新增接入指南 `docs/guide/README.md`。分阶段 API 全部保留，未破坏兼容。
- **受控交错 A/B 性能结论（2026-11-10 最终版，权威）**：用 `git archive HEAD` 构建改动前二进制（SHA-256 `4bd8ba20…`），与当前二进制交替运行共 12 轮（每种 6 轮）。**全链 1128.3 → 680.5 ms/轮（−39.7%，各阶段中位数之和）**：
  - annotations 104.7 → 48.3（**−53.9%**，离散度 9.4%）——`DefinitionFacts.metadata` 改 `Arc` 后克隆成本由整份字符串/类型/原型表降为指针引用。
  - code 653.9 → 355.7（**−45.6%**，离散度 1.2%）——debug 程序记忆化 + `SignedDecimal` + `Cow<'static,str>` + `Registers` 内联。
  - capture 17.7 → 10.3（**−41.9%**）；references 176.5 → 133.6（**−24.3%**，两次全量指令扫描合并为一次）。
  - definitions 83.2 → 50.9（**−38.8%**）、metadata 61.4 → 51.1（**−16.8%**）——SWAR ASCII 快路径 + 单次预留 + class_data 遍历合并。
  - 清点+解压 30.9 → 30.6（−1.0%，在噪声内）。
  - 逐轮原始数据：artifacts/local/perf-20261109/ab-controlled/record.json。
  - **样本量与局限**：共 12 轮（每种 6 轮），不是「各 12 轮」；判据用「变化 > 基线极差/中位数」，n=6 时该极差对离群点敏感（capture 基线离散度 34%，其阈值分辨力弱）。code 阶段基线离散度仅 1.2%、6/6 同向，结论最稳健。
  - **二进制时效**：该 A/B 对应改动前二进制 `4bd8ba20…` 与当时当前二进制 `086e273b…`；此后源码仍有变更，结论描述的是那几个二进制而非当前工作区。
- **独立差分验证（正确性）**：用 HEAD 与当前二进制对同一 NewPipe APK 运行 `metadata_summary` / `definition_summary` / `code_layout_summary` / `annotation_summary`，归一化随机 snapshot id 后**输出逐字节一致**。`reference_summary` 仅 `ReferenceUsage.fact_bytes` 不同（63557158 → 59742974），原因是 `LocalReferenceSite.mnemonic` 由 `String`(24B) 改为 `&'static str`(16B)，`site()` 按 `size_of::<LocalReferenceSite>()` 记账，结构体真实缩小 8 字节 × 476,773 站点 = 3,814,184，与差值分毫不差；sites/callers/units/postings 全部相同。这是真实的内存节省被如实记账。
- **更正**：此前记录的 "metadata +16.0% / definitions +14.1% / annotations +40.0% 未解释回归" **不成立**，那是环境噪声（跨时段、跨二进制的混合对比曾出现 22% 的总量差异；同二进制三连测只有 0.64%/3.12%）。metadata 与 definitions 实为真实改进，annotations 改进幅度比当时估计更大。
- **这些仍是本机开发构建的分阶段归因**，不是 MDD-082 性能资格，也不是 A0/A1/A2 配对结论。

- **修复 FactsSession 自死锁**：`definitions()` 持锁后又调用 `self.metadata()`（同一把 per-DEX mutex）会自死锁，导致 `quickstart` 示例挂死。改为公开方法只加锁、内部 `_locked` 变体在已持锁状态下递归，保持 single-flight 且不嵌套同锁；`quickstart` 现可完整跑通（2 DEX、64754/3722 字符串、7815/725 类、50046/5717 方法、47110/5222 code items，全层 Complete，exit 0）。
- **测试**：`cargo test --offline --workspace` 全绿（627 项通过 / 0 失败，22 个测试目标）；严格 clippy 对本轮改动的 crate（mdd-types/mdd-input/mdd-dex/mdd-facts/mdd-query/mdd-timing，以及 mdd-sql 的 `control.rs`）通过。这些是 Windows 本机 debug 构建证据；Linux/CI 未运行。**注意**：`cargo clippy --workspace --all-targets -- -D warnings`（CI 第 50 行所跑）存在既有失败，已逐一核实非本轮引入：`crates/mdd-session/src/cancellation.rs:568/660` 的 `.err().expect()`、`crates/mdd-sql/src/dialects/ast.rs:282/294/602`、`bridge.rs` 8 处、`dialects/functions.rs` 2 处、`provider/metadata.rs` 3 处——这些文件在会话开始时即为已暂存或未修改状态，问题在 HEAD（b70d999）同样存在。本轮只清理了 mdd-query 与自有新文件的 lint；修复这些既有 lint 属独立范围，未擅自扩大改动。另外 `cargo fmt --all -- --check` 仍会报 `crates/mdd-sql/src/join_tests.rs`，该文件是会话开始前已暂存的用户改动（+155 行）且未过格式，同样未擅自改动。

2026-11-01 本轮修正后按用户要求暂停：MDD-005 同步桥可选核验调用方观察的物理成员，并拒绝行错位、元组子类和自相矛盾的物理身份；Windows 输入锁与合成生产者局部 6 项、优化模式 6 项及既有 4+2 项回归通过，见 artifacts/mdd-005/sync-physical-binding-20261101/。回调可伪造记录且同步阻塞不受硬期限保证，生产者代次仍未证明。MDD-022 按已验证有序的物理注解集合查找 Signature 类型，避免对每个 owner 全表扫描；合成及已有 signature 定向见 artifacts/mdd-022/signature-type-search-20261101/，不构成性能或完整事实验收，022 仍 in_progress、026 门未解锁。MDD-034 对绑定 runtime 的严格来源校验计入查询步骤；真实零额度红例与最终 21 项 scoped 定向见 artifacts/mdd-034-audit/scoped-runtime-budget-20261101/；旧通用 FactSource、provider 回调、准备阶段及 Control 自有步数尚不受此修正覆盖。MDD-031 聚合输入物化、保留值和输出副本接入现有预算，真实低额度红例及 14+4+1 项定向见 artifacts/mdd-031-audit/aggregate-input-workspace-20261101/；聚合输出租约只通过共享包装器间接验证，SQLite 自身开销与循环内中断未证明。全量、跨平台、真实 HostLab 及性能验证均未运行，profile 与发行资格不变。

2026-11-01 继续推进依赖满足功能（全量验证延后）：MDD-022 新增同源 owner→编码注解项受界借用视图，保留共享项/重复、多来源及参数 Unknown，区分未绑定、零偏移与真实空集合；一项合成定向见 artifacts/mdd-022/owner-annotation-forward-20261101/run1/，范围损坏为注入，参数零槽列表与无绑定仍需结合已有参数列表视图，不能推断运行时不存在。MDD-022 仍 in_progress、MDD-026 依赖未满足。MDD-034 修正队列首错及终态传播：真实反例表明先前 WORKER_LOST/CANCELLED 会被后续协议错误覆盖，尚未消费的 Ok End 在重复 finish/send、取消或 worker loss 后也可能被错误交付；候选在队列锁内替换尚未交付的成功终态，读取时复核期限与查询，已交付终态不撤回并阻断成功回执。生产已完成后晚到错误的 receipt 仅在与 query 首错全部字段及队列/runtime/消费计数匹配时形成失败 envelope；tracker 锁损坏返回真实 INTERNAL_FAULT 或保留更早首错。12 项新增、4 项 owned queue、6 项 JSON 回归通过，见 artifacts/mdd-034-audit/queue-terminal-first-fault-20261101/green-final/；一个 --exact 零测试操作仅保留转录、非通过证据，绑定 send-after-End 的线性化点与锁损坏为受控注入，不证明所有并发或生产 IPC。MDD-031 Q03/Q05 的双来源定义、引用、原型、返回类型 JOIN 与缺层共三项合成对照通过，见 artifacts/mdd-031-audit/native-q03-join-20261101/run2/；Q03 是多重集比较不证明顺序，未修改 SQL 生产逻辑。仅列出源码身份，未运行全量、真实 HostLab、跨平台或性能验证；用户原有 A2 未暂存改动保留。

2026-11-01 继续推进依赖满足功能（全量验证延后）：MDD-022 补同一物理 Signature 同时关联方法与两个方法的重复参数编码槽的合成样本，并增加受界 signature_parameter_position：以完整同源身份及内容校验，区分 NotParameter、Known 与 Unknown，支持等价 clone、拒绝篡改/跨来源且不按集合去重；两个 fixture 重建与一项 Rust 定向通过，见 artifacts/mdd-022/parameter-signature-sharing-20261101/run3/。该样本不证明 ART 或 MDD-022 全验收，任务仍 in_progress，MDD-026 依赖门未解锁。MDD-034 ScopedCatalog 现在先按 max_entries 约束的清单核验重复/外快照身份，再按实际 v1 帧长在 SelectedScope 构造前检查 max_commitment_bytes；重复清单遇低额度原本 INVALID_ARGUMENT 被候选提前改为 QUOTA 的真实红例已保留，空清单 code/stage/message 保持既有语义，四项定向见 artifacts/mdd-034-audit/scoped-commitment-preflight-20261101/final/。该上限只界定预像长度，不覆盖其他分配、CPU/RSS 或来源真实性。MDD-031 Q04 形状的 OR/IN 注解过滤、跨来源、重复、NULL 与缺列分类一项合成 SQLite 对照见 artifacts/mdd-031-audit/hostlab-q04-filter-20261101/run1/；仅测试形状，不证明真实注解事实、HostLab/A0/A1 或性能。以上仅固定列出源码，全量和跨平台验证未运行，用户已有 A2 未暂存改动保留。

2026-11-01 继续推进依赖满足功能（全量验证延后）：MDD-022 补真实物理空 set 的合成样本：两方法共享 `[空 set, 零偏移, 同一空 set]`，另有 orphan 空 set；生成器按 DEX map 与小端原始字节核验真实起点，旧 fixture 字节不变，一项事实测试和重建检查通过，见 artifacts/mdd-022/parameter-empty-set-20261101/run1/。仅合成布局，不证明 ART/全部注解；MDD-022 仍 in_progress、MDD-026 依赖门未解锁。MDD-034 ScopedCatalog 的 AllPhysicalCode 覆盖前计数所有所选 occurrence 的 code items 与 declared offsets，默认上限 8,000,000，可用 prepare_with_code_coverage_limit 显式调整；两项定向检查见 artifacts/mdd-034-audit/scoped-coverage-work-20261101/run1/。该默认值会使极大 scope 返回 QUOTA，只约束逻辑条目，不保证 CPU/RSS/取消硬上限。MDD-031 旧方言直接 I64/U64 列可与精确数值文本按限定范围比较；真实 SQLite 对照发现内层直接 SELECT alias 在 WHERE、JOIN ON、GROUP BY 中应先于外层同名列绑定，旧桥误推断并返回 UNSUPPORTED；现仅这些子句使用可证明直接列 alias，本层物理列优先，复杂/重复 alias 不推断。最终 9 项定向见 artifacts/mdd-031-audit/numeric-comparison-text-20261101/final3/；三个真实红例保留，U64 MAX 为手写预期，非 SQLite/A0/A1 证明，多重 JOIN 所有作用域尚未穷尽。全量、真实 HostLab、跨平台、性能和 MDD-022 完整独立验收均未运行；用户已有 A2 未暂存改动保留。

2026-11-01 继续推进依赖满足功能（全量验证延后）：MDD-022 新增受界编码参数槽借用视图，区分无绑定、显式空列表、零偏移和物理 set，保留槽 ordinal、共享集合和 Unknown；一项合成长列表定向检查见 artifacts/mdd-022/encoded-parameter-slots-20261101/run1/，悬空 set 为注入，槽指向物理空 set 尚未独立实证。MDD-022 保持 in_progress，完整独立验收与 MDD-026 依赖门仍未通过。MDD-034 ScopedCatalog 的引用事实路径曾因同一 snapshot 的 deflate inventory 重建产生不同 Arc 而误拒，真实红例见 artifacts/mdd-034-audit/scoped-reference-rebuild-20261101/red/；现仅 scoped 内部允许在来源身份匹配后按同一累计字节预算比较实际 metadata/code 内容，公共 ReferenceCatalog::new 保持同 Arc 限制。四项局部检查见 green/，随后只扩充测试：三个同快照 inventory 的 definitions/code 分别使用不同分配、精确双次预算通过和少一字节拒绝，见 split-final/record.json；green 早于测试源码扩充。MDD-031 Q15 形状的描述符拼接、排序别名、NULL/重复和缺列分类三项合成 SQLite 对照见 artifacts/mdd-031-audit/q15-concat-shape-20261101/run2/；只新增测试，非真实 HostLab、固定 A0/A1 或完整 SQL 资格。全量、跨平台、生产 IPC 与性能验证未运行，已有 A2 未暂存改动保留。

2026-11-01 继续推进依赖满足工作（全量验证延后）：MDD-022 补 4 个单独命名的合成参数列表样本，覆盖长列表、非零原型零槽 Unknown、零原型零槽 Complete、无绑定且物理孤儿空列表，以及重复内容的独立 occurrence；Python 字节重建和 4 项 Rust 定向检查通过，见 artifacts/mdd-022/parameter-position-boundaries-20261101/run1/。该样本是合成编码布局，不证明 ART 或原任务全部独立验收；MDD-022 保持 in_progress，MDD-026 依赖门未解锁。MDD-034 增加 ScopedCatalog/ScopedPrepared 内部 SDK 路径，从实际 Snapshot、显式 inventory、同 occurrence 事实和 coverage ledger 重算 scope 与所需层，并构造自己的终态 coverage；支持 metadata/structure/完整物理 code/references，未验收 annotations 和 resources 显式拒绝。此前同快照重建 deflate 得到不同 Arc 但等字节被错误拒绝，真实红例已保留；现先做数量预算预检，非同 Arc 按显式比较字节额度逐字节核验；仅允许 native-unqualified profile、typed dialect 必须为 null。最终 5 项 scoped 与 2 项 JSON 回归通过，见 artifacts/mdd-034-audit/scoped-catalog-20261101/final2/；max_commitment_bytes 不限制 SelectedScope 初始分配，AllCapturedInputs 不证明所有归档成员或安装 split，外部来源真实性、完整格式和 HostLab profile 未获准入。MDD-031 Q10 形状的多键 GROUP BY/COUNT/ORDER 合成 SQLite 对照一项通过，见 artifacts/mdd-031-audit/q10-group-calls-20261101/run1/，仅新增测试，不证明真实 HostLab/Q10 或固定 A0/A1。以上只固定所列源码，未运行全量、跨平台、真实 HostLab 或性能验收，用户已有 A2 未暂存改动保留。

2026-11-01 任务重开与局部修复：MDD-022 短参数列表实际反例显示 position coverage=Unknown 时旧 parser 仍输出 Some(true)，与原完成范围冲突；已重开 MDD-022，MDD-026 的该依赖门未满足。现 parser 对长度不匹配的编码列表保留槽位并将原型位置标为未知；typed 原始 owner 关系显式区分 complete/unknown/not_applicable，物理 set/entry 保留共享、多来源和顺序。解析器与 typed 三项、SQL 双来源按 occurrence/class_def/method 关联 coverage 一项通过，见 artifacts/mdd-022/parameter-position-unknown-20261101/；只直接实证短列表，长列表、空列表与原任务完整独立验收仍待统一验证。SQL 原生 nullable 位置须与 owner kind 和 parameter-list coverage 共同解释，不能单独作为无注解证明；typed 当前无 parameter-list 绑定关系，空 owner 结果不能区分无绑定与零槽列表。MDD-034 真实反例显示倒序消费第二批时 callback 在 ACK 拒绝前已执行；现 callback 前检查队列序号，最终 ACK 仍复核，五项局部检查见 artifacts/mdd-034-audit/json-consumer-order-20261101/，不证明所有并发交错或回调副作用回滚。MDD-031 Q13 shape/HEX 包装和缺层两项局部检查见 artifacts/mdd-031-audit/hostlab-q13-wrapper-20261101/run2/；首轮标准 UTF-8 假设失败保留，固定 A0 相同 A\0B 的 41C08042 为 MUTF-8，冻结 HostLab 的严格 UTF-8 解码会拒绝，完整 Q13/HostLab 仍未认证。以上只固定所列源码，未运行全量、跨平台、真实 HostLab 或性能验收；用户已有 A2 未暂存修改保留。

2026-11-01 继续推进依赖满足功能（全量验证延后）：MDD-030 typed AnnotationCatalog 新增物理 annotation_items/annotation_values，按 DEX 出现保留位置、节点顺序、NULL、同源字符串引用、标量原始字节与浮点位型；双来源一项合成测试对照保存的独立物理项/元素 oracle、DEX scalar bytes 和 NaN 位型，见 artifacts/mdd-030/typed-annotation-values-20261101/run1/。MDD-031 允许类型可证明的直接列 CTE 参与同类型 JOIN USING，保留 SQLite 列合并、NULL 和重复；最终四项局部测试覆盖 INNER/LEFT、限定列、U64/Bool 和错误分类，见 artifacts/mdd-031-audit/direct-cte-using-20261101/run3/。此前 run2 因测试将 SQLite 布尔结果误包装为 Bool 而失败，已按实际 INTEGER 载体修正并保留；u64::MAX 仅手写预期，非独立 SQLite 证明。MDD-034 修复结果完整性误判：未知总数、精确总数与已交付数不一致或 blocking warning 不再判为完整；无后续页却精确总数矛盾的流独立报错，合法分页/未知总数仍可作为未完成响应。三类真实红例和四项局部检查见 artifacts/mdd-034-audit/exact-total-completeness-20261101/。这些结果只固定所列源码/样本，不授予完整 HostLab、跨平台、生产 IPC 或性能资格；用户已有 A2 未暂存改动保留，全量验证未运行。

2026-11-01 继续推进（全量验证延后）：MDD-026/030 增加可组合 NativeCatalog 与 ReferenceCatalog 的 typed AnnotationCatalog，校验来源身份、完整注解与捕获字节 lease，暴露签名头及有序片段；双来源一项合成测试通过，见 artifacts/mdd-026/typed-signature-catalog-20261101/run3/。参数序号仅为编码槽，当前 fixture 未直接实证 Unknown 参数槽；头/片段值在 provider 构造时克隆，未证明 RSS 或性能。MDD-031 旧方言对可证明的直接 I64/U64 列 BETWEEN/NOT BETWEEN 两个边界分别复用已限定的精确整数文本亲和；两项 signed SQLite 局部对照及原回归通过，见 artifacts/mdd-031-audit/numeric-between-text-20261101/run2/，U64 大值、Native 扩权、A0/A1 和 HostLab 未验证。MDD-034 修正 query-bound JSON 消费的期限与确认：callback 前后及下一行解析前检查预算；partial 路径同锁核对已登记首错和实际 lifecycle/budget 期限，普通与 partial 批确认从所属预算取得 witness，在生命周期锁内再检查两期限后设置 ACK。原候选曾在 callback 期间预算到期、已有 WORKER_LOST 后预算或生命周期到期、以及检查通过后 ACK 前跨期限时仍执行/确认；实际红例保留于 artifacts/mdd-034-audit/json-consumer-budget-deadline-20261101/，最终 30 项定向检查见 final4/record.json。公开低层不带 witness 的既有 BatchHandle ACK 接口保持原语义；callback 或单行解码无法硬中断、此前回调副作用不回滚，逻辑预算不证明 RSS，双锁全部并发和生产 IPC 尚未验证。全量、真实 HostLab、跨平台与性能验证仍未运行，用户已有 A2 未暂存修改保留。

2026-11-01 恢复后继续推进（全量验证延后）：MDD-030 增加按 UTF-16 类型 descriptor 精确查询编码 Type 引用的 typed 查询，按完整同源实体关联并保留 caller、PC、operand、opcode 和重复；一项双来源合成 fixture 检查对照保存的独立站点 oracle，最终组合见 artifacts/mdd-030/typed-type-reference-query-20261101/run2/。查询使用 scan/filter/join，构造字面量在运行预算之前，不证明全快照覆盖、运行时解析、稳定顺序或性能。MDD-034 增加 query-bound JSON 批消费者：调用方显式提供预期 RuntimeBudget，核验实际 query/session、预算树、catalog epoch、快照、计划和 source，按输入字节/行/列限制逐行解码并验证，整包 callback 成功后才 ack。旧候选对不同 query 和错误 epoch 实际误接受，红例保留于 artifacts/mdd-034-audit/json-batch-consumer-20261101/red-binding/；最终消费者、身份、生产者与队列 20 项定向检查通过，见同目录 final/record.json。已执行 callback 副作用不回滚，显式 ack 是调用方消费断言，逻辑限额不证明解析器/回调的 RSS、时间或生产者/覆盖真实性。MDD-031 对同类型、单基础表或可证明直接列 CTE 的有序 DISTINCT+LIMIT/OFFSET 子查询保留先去重后分页；三项整数、Bytes/Bool、UTF-16 边界定向检查见 artifacts/mdd-031-audit/ordered-distinct-limit-20261101/run2/。NativeV1 补充平面文本按项目 UTF-16 合同排序，与 SQLite BINARY 的观察差异不是 Native 合同错误；缺固定 A0/A1 oracle，旧两方言 Text 去重分页仍拒绝。记录只固定列出源码，不授予真实 HostLab、全部语义或性能资格；全量、跨平台与生产 IPC/FFI 验证未运行，已有 A2 未暂存修改保留。

2026-10-30 本轮修正（全量验证延后）：MDD-026 新增同源 class/field/method owner Signature 借用视图，保留分片次序、多重签名和引用/定义身份，不推断参数槽映射；一项双来源合成 fixture 检查通过，partial/重复为注入，见 artifacts/mdd-026/owner-signature-view-20261030/run1/。MDD-031 旧方言整数列 IN/NOT IN 支持受限十进制/指数文本：最多 18 位尾数、数学上精确为整数且绝对值小于 2^53，非整数、下溢及超界仍拒绝；最终组合两项固定 SQLite 定向对照见 artifacts/mdd-031-audit/legacy-exact-real-text-20261030/run3/，仅锁定所列依赖，非 A0/A1 或完整亲和性资格。MDD-034 将 typed 执行器连接至 query-bound owned JSON 字节批队列，按行数/字节上限形成多行数组；成功必须逐批确认、消费成功 End 并通过同队列/runtime/批次数与终态封套检查。此前部分批次后配额失败时普通确认无法形成失败回执，真实 red-partial 保留；新增显式 partial ack 严格绑定查询已记录的完整首错，仍发失败 envelope 并只记确认消费的批次行数。最终 15 项定向检查通过，见 artifacts/mdd-034-audit/json-batch-executor-20261030/run4/，含空结果、切分、NULL/孤立代理、额度、取消/worker loss、重复租约、绕过和 tracker 锁中毒；run3 早于毒锁修正，故障中毒为受控注入。scope/input/facts 由调用方提供，显式 ack 是消费断言；只实现内部 SDK 路径，未连接生产 MCP/IPC/FFI，不证明 RSS、完整工作负载或性能。全量、真实 HostLab 与跨平台验证未运行，现有 A2 未暂存改动保留；按用户要求完成本轮后暂停。

2026-10-30 SQL 亲和与布尔遮蔽修正：旧方言已知 TEXT 直接列的 IN/NOT IN 可将 i64/布尔字面量按限定的 SQLite TEXT 亲和性转换；F64、越界、未知类型及 NativeV1 未扩展。真实反例显示同名 TRUE/FALSE 列可能使旧桥的文本或数值 IN 错误返回 NULL，而 SQLite 返回 1；通用布尔 token、IS [NOT] TRUE/FALSE 和提前转换现检查当前、外层、alias 与未知作用域，无法确认时 UNSUPPORTED，真实缺列仍 INVALID_ARGUMENT。无 FROM 本地范围仍检查外层。两条 LIKE 红例显示内部 has_escape 裸布尔标记被同名列遮蔽，现改为绑定参数；IS 文本载体同名列红例 SQLite 返回 [1,0,1,0]、桥返回 [0,1,0,1]，这些红例均在第一个 NativeV1 方言失败，不能推断其余方言红例。IS 整数同名对照实际通过，虽目录名 red-is-boolean-shadow 不应当成失败。最终源码 5 项 IS/布尔/LIKE 与 3 项文本 IN 回归通过，见 artifacts/mdd-031-audit/legacy-text-in-integer-20261030/green-is-boolean-shadow/ 和 green-is-final-text-regression/；此前首次 SQLite 预期错误与首次过度拒绝无 FROM 的失败均保留。保守检查可能拒绝部分合法 SQL，不证明完整布尔/亲和性、真实 HostLab、A0/A1、跨平台或性能资格；未运行全量验证。

2026-10-30 继续推进依赖满足功能（统一验证延后）：MDD-030 增加 UTF-16 字段 descriptor 的 typed 精确编码引用查询，按完整实体身份连接并保留来源、caller、PC、operand、opcode 和重复；双来源一项局部测试对照保存的 classic fixture PC/opcode，owner/type 仍来自同一 facts，见 artifacts/mdd-030/typed-field-reference-query-20261030/run1/。该查询采用 scan/filter/join，构造字面量分配在执行预算之前，不证明稳定顺序、运行时字段行为、HostLab 或性能。MDD-034 新增 query-bound owned 字节批队列，私有载荷同时保留 BatchHandle 与 QueryWorkspace 租约；消费方显式逐批 ack，回执核对同队列/runtime、批次数、成功 End 与期限，未消费与失败不能签完整交付。4 项新增和 2 项既有回归通过，见 artifacts/mdd-034-audit/owned-batch-queue-20261030/run1/；双重确认中途失败为受控损坏注入，双锁全部并发交错未穷尽，RetainedOwnedBatch 清理错误经 lifecycle/budget 状态观察。该独立字节通道实际复用受界队列和 BatchHandle，但尚未自动连接 execute_into 的 Row 生产或生产 IPC/FFI；输入分配在调用前，逻辑额度不证明 RSS。所列源码固定不覆盖所有依赖，全量、真实 HostLab、跨平台和性能验证未运行，A2 原有未暂存改动保留。

2026-10-30 继续推进依赖满足功能（统一验证延后）：MDD-030 增加按 UTF-16 方法描述符精确查询编码 Method invoke 的 typed 查询，关联完整来源实体并保留 PC/operand/重复；一项双来源合成测试对照已保存的 PC/目标 oracle，见 artifacts/mdd-030/typed-method-call-query-20261030/run4/。run1 期间 session 源码漂移，run2/3 早于后续 session 修改，首个 run4 尝试因工作目录拼写错误未启动；最终 run4 所列源码前后稳定。该查询不含 CallSite invoke-custom、不推断运行时分派，scan/filter/join、顺序与构造时内存均未获得性能资格。MDD-031 旧方言整数列 IN/NOT IN 增加可无损解析 i64 的 ASCII 空白、正负号与前导零文本，三项 SQLite 局部对照通过，见 artifacts/mdd-031-audit/legacy-in-decimal-text-20261030/run2/；首次 run1 因遗漏既有 helper 引用编译失败已保留。小数/指数/越界/非 ASCII 空白及 NativeV1 仍拒绝，SQL 记录早于最终 session 修改且仅固定所列源码，不证明最终全依赖或 A0/A1/HostLab。MDD-034 新增独立 owned BatchHandle：持有字节及快照 lease，克隆共享额度、最后释放归还，query/session 移除后仍有效；未确认批次阻断交付，先有终态不被清理故障覆盖，故障独立可查，已确认计算与交付状态分离。11 项合成定向测试见 artifacts/mdd-034-audit/owned-batch-20261030/green5/；多次 batch 身份损坏与故障顺序红例为受控注入，green3 曾因旧测试预期而失败保留，red-completed 只直接复现 fail_query 分支。调用方显式 ack 仍是消费断言；尚未连接生产队列、IPC、C ABI，不证明真实 RSS、全部并发或正式资格。全量、真实 HostLab、跨平台及性能验证未运行，用户已有 A2 未暂存改动保留。

2026-10-30 继续推进依赖满足功能（统一验证延后）：MDD-030 增加按 UTF-16 code units 精确定位编码字符串引用的 typed 查询构造器，以完整 EntityRef 关联同源站点和字符串，保留重复、PC、operand、字符串池和原始 MUTF-8；一项双来源局部测试对照保存的合成 caller/PC/string index oracle，见 artifacts/mdd-030/typed-string-reference-query-20261030/run1/。该实现采用 scan/filter/join，未证明索引加速、稳定顺序或 HostLab 旧表等价；构造字面量的分配在执行预算之前。MDD-031 对单基表直接列的 I64/U64/Bool 混合 IN/NOT IN 采用既有精确数学键；两项局部测试覆盖 signed 范围 SQLite 对照与旧同类型回归，见 artifacts/mdd-031-audit/mixed-integral-in-subquery-20261030/run1/；超 i64 的 U64 为手写精确预期而非 SQLite/A0/A1 对照，Text/数值与 F64 仍拒绝。MDD-034 真实红例显示查询取消后已交付缓冲仍被持有，却提前清零共享额度并允许另一查询超额；候选保留额度直到显式释放，余额非零时 release_query 返回错误且保留句柄，取消/session release/worker loss、重复释放、首错与已有回归四项通过，见 artifacts/mdd-034-audit/live-buffer-accounting-20261030/。当前依赖 QueryHandle 显式归还，尚非独立 BatchHandle 可在 query 移除后自行归还的完整所有权；逻辑额度不证明 RSS 或生产 IPC。以上记录仅固定所列源码；未运行全量、真实 HostLab、跨平台或性能验证，不授予 profile 资格。用户已有 A2 未暂存改动保留。

2026-10-30 继续推进依赖满足功能（统一验证延后）：MDD-005 新增 capture_scope_binding，将调用方独立可信的捕获来源与所选 scope 按 ordinal 和摘要关联；8 项合成检查与两次同一 APK 出现的 Rust 交叉检查通过，见 artifacts/mdd-005/scope-verifier-20261030/python-bound-run2/ 与 cross-bound-run1/。all_captured_sources_selected 仅表示来源均被选择，不证明策略涵盖全部成员、真实捕获或事实/页面完整；交叉检查快照句柄仍由 Rust 自报。MDD-030 typed ReferenceCatalog 按快照、DEX occurrence、完整引用和同一字节租约连接 NativeCatalog，新增 reference_sites，可按完整实体身份连接 caller/目标方法；一项双来源局部测试覆盖两路径、JOIN、限额与缺层，见 artifacts/mdd-030/typed-reference-catalog-20261030/run3/record.json，站点预期来自同一 facts，显式 occurrence 列表不证明整个快照覆盖。MDD-031 为单基础表直接列 CTE 传播可证明类型，允许同类型 IN/NOT IN；两项局部检查覆盖 NULL、重复、相关查询、遮蔽、重复输出和错误限定符，见 artifacts/mdd-031-audit/direct-cte-types-20261030/run3/。部分合法同名 CTE/重复输出仍保守 UNSUPPORTED，U64/非 scalar 文本仅同桥对照，多层 CTE、表达式及 Text/I64 混合亲和性反例仍未实现。MDD-034 真实红例证明 Prepared 查询取消后 mark_computed 曾误写 execution_complete=true；现记录是否进入 Active，未启动取消/worker 丢失保留首错且不写计算完成，两项局部检查见 artifacts/mdd-034-audit/never-started-computed-20261030/。仅红例第一种 Prepared 取消已实际复现，其他为最终测试覆盖；不证明生产 worker/IPC、全并发或性能资格。所有记录仅固定所列源码，未运行全量、真实 HostLab、跨平台或性能验证；已有 A2 未暂存改动保留。

2026-10-30 继续推进依赖满足功能（全量验证延后）：MDD-005 新增捕获快照清单内容键检查器，以调用方提供的来源摘要/长度/种类/顺序和快照身份核对 occurrence 与内容键；7 项合成 Python 检查和 Rust 两次合成 APK 出现的交叉检查通过，见 artifacts/mdd-005/scope-verifier-20261030/python-snapshot-run2/ 与 cross-snapshot-run1/。交叉检查的快照句柄由被测 Rust 输出提供，并非独立认证，不证明真实生产者快照、全部 DEX 或交付。MDD-026 增加 invoke-custom 编码站点借用视图，保留来源、caller、PC、CallSite 与 bootstrap；一项双来源合成测试对照保存的独立 caller/PC/CallSite oracle，bootstrap 仍来自同一 facts，见 artifacts/mdd-026/dynamic-call-view-20261030/run1/。MDD-031 新增 native_dynamic_call_sites 原生关系及组合关联，两项局部测试通过，见 artifacts/mdd-031-audit/native-dynamic-call-sites-20261030/run1/；bootstrap 不是运行时 callee，运行时目标仍 Unknown。MDD-034 将预算截止检查与准入记账放在同一锁内，避免检查后等待锁到期仍记账；一项受控注入的到期检查通过，见 artifacts/mdd-034-audit/budget-admission-deadline-20261030/run1/；旧竞态为源码推断而非自然红例，不证明硬实时或工作必在期限前完成。以上记录只固定所列源码，未运行全量、真实 HostLab、跨平台或性能验证，不授予 profile 资格；现有 A2 未暂存修改保留。

2026-10-30 SQL 排序作用域修正：允许同类型、单基础表直接列的 IN/NOT IN 子查询保留 ORDER BY 和非 DISTINCT 的 LIMIT/OFFSET；DISTINCT 搭配限制仍拒绝。独立复核构造了真实反例：内层 CTE 文本列与外层整数列同名时 SQLite 返回 1，而原桥错误返回 0 且完成；原始红例见 artifacts/mdd-031-audit/in-subquery-order-20261030/red-scope/。候选在排序改写期间恢复当前 SELECT 来源作用域，并对未知 CTE/派生或可能遮蔽的输出名拒绝不安全类型推断；该反例现明确返回 UNSUPPORTED，尚未实现其完整 SQL 语义。最终两项局部测试覆盖遮蔽、限定列、排序别名/位置、NULL、相关 LIMIT 和三方言；U64 与非标量文本为合成手写预期，见同目录 final-scope/record.json。未运行全量、A0/A1、真实 HostLab 或跨平台验证，不能宣布完整 ORDER BY/CTE 支持。

2026-10-30 目标继续推进（全量验证延后）：MDD-005 基准结果消费者现要求调用方提供独立可信的期望 request、operation、profile、dialect、session、snapshot、epoch、query、scope 和响应 schema 身份，并逐项比较；非 query 依契约可接受 null epoch，query 仍要求 decimal-u64。两项定向检查与包含它们的 19 项模块自测通过，见 artifacts/mdd-005/result-identity-binding-20261030/run2/record.json。目前仅内置测试调用该接口，未接入真实 HostLab 驱动；调用方来源可信性、实际覆盖和消费分页仍须独立证明，structured 模式仍拒绝资格。旧 structured 历史探针调用旧签名，不能直接作为新版回归。MDD-026 新增参数注解物理编码列表视图，保留绑定、原始字节和槽，不将 Unknown 原型位置补齐；一项合成短列表检查通过，含原始字节及显式注入的 partial/重复，见 artifacts/mdd-026/encoded-parameter-list-20261030/run1/record.json。物理起点与槽引用仍依赖既有 parser；严格参数映射入口仍拒绝 Unknown。记录仅固定列出的源码，均非全格式、HostLab 或性能资格；未运行全量验证，原有 A2 未暂存修改保留。

2026-10-30 依赖已满足功能继续推进（全量验证延后）：MDD-026 新增对不含终止零的原始 MUTF-8 载荷精确查找字符串编码引用，保留双来源及站点；原始字节和既有 UTF-16 查询各一项合成测试通过，预期来自同一事实实现，见 artifacts/mdd-026/raw-mutf8-reference-index-20261030/run1/record.json。任意查询字节可作为精确谓词，不声称其必然是合法 MUTF-8。MDD-031 新增 native_method_call_sites，按 Method 目标及 invoke 类型过滤并保留来源与重复；两项局部测试通过，见 artifacts/mdd-031-audit/native-method-call-sites-20261030/run3/record.json。第一次实际测试因误读合成 oracle 的调用数失败，run2 保留；run1 路径清单错误未启动测试。此关系排除以 CallSite 为目标的 invoke-custom，不代表完整调用图；PC/operand 与同一事实对照。被过滤站点计步骤和工作字节，SQL 返回行限额不等于底层扫描总数。MDD-034 的 remaining 对五类驻留预算同时计算每级共享 ResidentBytes 余额，避免给出高于实际共享额度的逻辑余额；兄弟查询、释放和五类别一项定向测试通过，见 artifacts/mdd-034-audit/remaining-resident-20261030/run1/record.json。余额只是瞬时逻辑快照，并发预约和资源元数据额度仍可能导致失败，不是 RSS。以上记录仅固定所列源码，未运行全量、跨平台、真实性能或 HostLab 资格验证；已有 A2 未暂存改动保留。

2026-10-30 继续推进（统一验证延后）：MDD-026 新增按 UTF-16 类型描述符查找选中来源中的编码注解 owner，保留共享物理项的多个 owner、来源、集合序号和参数位置原值；完整注解层与额度必需，一项合成定向测试通过，见 artifacts/mdd-026/annotation-type-owner-index-20261030/run1/record.json。标量与索引共用遍历，非独立解析器；“不存在”仅指范围内编码 owner 关联，不能推断未知原型参数位置或运行时行为。测试后仅加两行说明，源码摘要变化和未重跑见同目录 post-test-comment.json。MDD-031 新增 native_class_definition_details，逐来源输出类定义的原始声明偏移、可空 class-data 范围和成员计数；一项局部测试对照合成 DEX 原始字节，长度仍与同一 facts 对照，见 artifacts/mdd-031-audit/native-class-details-20261030/run1/record.json。MDD-005 修复对照脚本启动失败和超时不记录结果的问题，6 项 Python 合成检查及两来源四 DEX 交叉检查通过，见 artifacts/mdd-005/scope-verifier-20261030/python-final4/ 与 cross-run3/；失败为显式注入，快照身份仍未独立认证。对照记录与编译日志中的本机路径经明确标注脱敏，原始文件保留于忽略目录并记录摘要。所有这些结果只覆盖局部，未运行全量、跨平台或性能验证，不改变任务与 profile 资格。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 增加借用式方法调用站点，保留同源 caller/callee、编码 PC/operand 和重复出现；一项合成测试对照既有独立关系多重集，PC/ordinal 不由该 oracle 独立证明，见 artifacts/mdd-026/borrowed-method-calls-20261030/run1/record.json。MDD-030 增加 class_definition_details 类型化关系，保留来源、NULL、class data 范围与计数；两来源局部测试的预期来自同一事实实现，见 artifacts/mdd-030/class-definition-details-ir-20261030/run1/record.json。其中 annotations_offset 与 static_values_offset 是 class_def 声明的原始偏移，Structure 层不证明其为有效物理项起点或可解引用身份。MDD-031 限定支持同类型直接列的 IN/NOT IN 普通 DISTINCT 子查询，拒绝 DISTINCT 加排序或限制；两项局部检查含 SQLite 对照，文本和 U64 的新增断言只对照自身无 DISTINCT 结果，见 artifacts/mdd-031-audit/distinct-in-subquery-20261030/green/record.json。MDD-005 新增 scope 预像检查器：调用方须独立提供可信来源总数、有序输入/DEX 清单和快照身份，分别约束各类条目；5 项合成检查和两次出现、四个 DEX 的 ZIP 独立读取交叉检查通过，见 artifacts/mdd-005/scope-verifier-20261030/python-final2/record.json 与 cross-run2/record.json。后者的快照身份取自 Rust 输出，并非独立认证；早期版本记录保留。所有记录只固定所列源码，不能证明完整依赖身份；上述均不授予覆盖、HostLab、profile 或性能资格。用户既有 A2 未暂存补丁保留。

MDD-026 的索引和三态 coverage 已有测试证据，但逐列事实验收尚未完成；MDD-030 类型化 IR/基础算子已完成Windows限定范围验收：7单元+2compilefail、36查询case、20LIKE、322正/12负Base64均实际通过，源码稳定且根复验通过。031 SQL桥与034预算/取消/终态的前置依赖已满足。未通过的 Methods 代码列、参数文本编码与参数注解 slot Unknown 均须显式阻断相应查询，不能填零/空值制造完整结果。

解析安全独立 fuzz workspace 已实际完成 10,400 次本地 mutation、2 Rust 与 2 Python oracle/驱动测试、严格 Clippy。b29933d 两平台原生 CI 已通过，原始十份命令记录均 exit0。Linux ASan run40692557250 也真实通过：正控制非零检测到预期越界，六个各 15 秒目标共 2,426,570 次执行、无 crash 文件或超时，原 ZIP 的 GitHub 摘要及每份日志计数/锁参数均独立核验。见 artifacts/conformance/parser-safety/ci-readback.json。G1 未签发；固定预算不是完备证明，测试 nightly 不改变发布 stable 1.99.0。

两个授权 APK 已核验完整 SHA/长度和 33/35 DEX，原位置未改变且不入 Git：9161100=226,519,215 字节/41efb1c9acb07badab5296953fb3da1def6925e2b34662120ca96df9d17bbfb2；9170100=243,687,778 字节/f0f880e841d017db335b3919e6d4792961f2e08aa9993da661b626d52cfcb955。实际路径及 mtime 前后核验见 artifacts/bootstrap/20261028/private-input-acquisition.json。两个私有输入另有实际受限 CLI 成员/头部检查通过：68 个 DEX 全为 037，进程树均清空，峰值 Job commit 623,386,624/676,052,992 字节；原始输出留在 artifacts/local，摘要为 artifacts/integration/20261028/private-headers-20261028T130804307935Z.json。该检查不含完整事实、业务审计或性能试次。

MDD-005 的固定 HostLab 驱动、A0/A1 身份、隔离 Python 环境及 Windows Job 监督器已就绪。2026-10-29 可用内存重新达到原定10 GiB准入后，已对两个授权输入各执行一次 A0 与 A1 完整静态资格检查；每份覆盖27 FEATURE、20组证据，零 fallback、完整交付、子进程树清空，同输入的20组结果全部相等。四次业务程序返回码均为1，完整运行与等价不表示业务审计结论通过。重新读取原始证据及身份见 artifacts/mdd-005/static-qualification-20261029.json；私有原始输出留在 artifacts/local/baseline-runs。项目代理在该时段暂停，但系统其他应用未隔离；本轮不是性能试次。A2 完整适配、正式配对测量和最强合格基线选择仍未完成，历史约37%/47%仅条件目标。

## 锁定与恢复

发布 Rust/Cargo 1.99.0，Windows x86_64 MSVC；Linux 同版本原生验证按不可变 CI checkout 单独登记。十项直接生产依赖均获用户批准：serde、serde_json、sha2、sha1、zip、rusqlite、getrandom、quick-xml、sqlparser、log；根 lock 目前46个外部 package。SHA-1 仅 DEX 兼容校验；来源身份 SHA-256。SQLite 3.53.2 只读虚表桥正在 MDD-031 实施，兼容性尚未验收。Python 本地 3.12.14，CI 3.12.10；依赖与许可证见 conformance/manifests/dependencies.json。

root 单写共享 Cargo/lock、exports、STATE/backlog/ledger/index 和 CI；026 索引/coverage、030 查询、独立全事实验证分开文件所有权。性能测量先暂停其它 CPU/IO 工作并取得真实资源窗口。并行检查点用 refresh_artifact_index.py --from-index 登记精确暂存 blob，再重建检查点运行 check_progress.py，不能混入活动文件。

恢复先检查 Git/任务/进程，不重建任务图。现有 BIL/HostLab 外部工作树、配置和用户修改保持原状。原始成功/失败记录保留；当前回滚为在审查分支创建范围 revert 提交，保留初始规格和失败证据，不 reset/clean/强推。完整审计、SQL、MCP、FFI、桌面、ARSC、正式发行与 MDD-082 性能资格仍未取得。

031 SQL桥正在实施，034预算/取消/终态限定机制已完成本机验收。用户已另行批准sqlparser0.63.0（仅std）与log0.4.34，独立探针实际构建/AST往返通过；根锁仅增这两包，无其他外部升级。两个私有Manifest完整树与原始属性逐项通过：2115/2119节点、5275/5291属性，含exact float32 bits、TYPE_REFERENCE零值与TYPE_NULL分开；首轮日志quota及显示比较失败原样保留，见private-manifest-captured-conformance.json。这些仍不代表完整HostLab审计或性能通过。

私有完整raw诊断另行在启动前被4GiB开发任务准入拒绝（并非正式基线阈值调整），没有开始编译或解析；后续独立WMI观察仅2404388KiB可用。失败记录private-raw-diagnostic-20261028T135952890645Z.json保留，不能推断引擎解析失败或性能结果。

内存条件变化后重试：固定 e56db3e 二进制受限诊断在两份授权 APK 上完成原始事实计算，分别覆盖33/35 DEX、1,731,482/1,848,430方法记录及310,716/345,907类记录；输入与二进制身份、完整输出摘要和进程树终态已回读。证据 artifacts/integration/20261028/private-raw-diagnostic-20261028T172024248736Z-readback.json，原始输出留在本机忽略目录。它不是逐字段 A0 等价、完整HostLab审计或性能资格。

两个APK的资源指纹另完成三方逐项核对：e56原生、固定A0/HostLab和从原始归档独立流式重算的 resources.arsc 与 res/*.xml 解压字节 SHA-256 分别17,755/17,770项一致。证据 artifacts/integration/20261028/private-resource-readback-20261028T173518129052Z.json；摘要不含私有逐项内容。类/方法输出覆盖和聚合粒度不同，尚未比较；业务退出码1不等于审计业务通过。

MDD-026 已重新打开：独立复核发现资格脚本对17关系156列主要检查原子可用性声明，尚不能证明每列的字段/类型、NULL、顺序、重复性、来源及 raw 指纹均有独立证据；例如 dex_files.file_id 已有原生分配代码，但尚缺固定旧实现和全部来源场景的端到端逐列验证。已有219候选请求（55残余反例）、35 facts+4 compile-fail组件测试、11索引/coverage根测试及8场景43关系比较仍有效，69个兼容投影缺口仍明确阻断。原 conformance/manifests/hostlab-fact-qualification.json 保留为限定原生原子检查的历史记录，不代表 MDD-026 原验收完成。G1/G2、完整私有事实与 HostLab 资格仍未签。033正在只读预研，依赖031尚未完成，不先假解锁。

补充事实对照：合成样本中三个定义关系的21列与固定A0完整行多重集合一致，含错误编号、NULL和缺行负例；三个合成DEX的24个头字段与独立原始字节解码及A0单输入结果一致，含四个损坏/篡改负例。原始记录和回读分别为 artifacts/mdd-026/new-audit/definition-projections/readback.json、artifacts/mdd-026/header-audit/20261028T163754102728Z/readback.json。完整A0多输入编号和兼容关系装配仍未证明。

随后真实 A0 多输入合成实验完整消费三组79行，验证原生六个来源出现及字符串坐标。相同内容两次输入在 A0 有两个兼容池编号，而原生物理池身份共享；兼容层必须显式映射，不能直接将物理池 ID 作为旧编号。证据 artifacts/mdd-026/cross-dex-audit/20261028T164250980578Z/readback.json；生产兼容映射和完整 HostLab 尚未完成。

方法代码项补充对照：classic/shared 合成 DEX 的12列与原始字节 oracle 和 A0 有序结果相等，共享物理方法体仍保留多个方法行；无体为 NULL。非空 try/handler 只在无方法所有者的物理项上验证，不能算 A0 非空兼容行。证据 artifacts/mdd-026/code-item-audit/20261028T164825508666Z/readback.json。

后续两份合成DEX补充了方法实际拥有的非空 try/handler，覆盖偶数和奇数 code-unit 对齐；12列与 A0/原生/独立字节 oracle 一致，SDK dexdump 通过。损坏 handler 被原生及 SDK 拒绝，A0 却返回行，原始反例保留；该对照不改变真实错误或授予设备/ART资格。证据 artifacts/mdd-026/owned-try-audit/20261028T171328758066Z/result.json。

四类注解关系在双来源合成样本中验证行序、NULL和来源；A0 的116行在数值零符号归一化后匹配，其中两处原生 -0.0 被 A0 文本 CAST 显示为 0.0，不能称逐位相等。参数位置 Unknown 继续阻断。证据 artifacts/mdd-026/annotation-order-audit/20261028T165221569757Z/readback.json。

三份合成DEX的24个方法、14个字段由独立字节 oracle、原生事实组合和A0数值顺序逐行对照，覆盖纯引用NULL、无体定义、三参数及共享体多所有者；生产 methods 关系仍未装配。首轮因测试查询文本别名排序失败的记录已保留，修正数值排序后通过。证据 artifacts/mdd-026/method-atom-audit/20261028T165707192974Z/readback.json。

四份合成DEX的67个字符串与独立 UTF-16/MUTF-8 字节 oracle 一致，两个类型样本的16个 descriptor/java_name 与 A0 一致；严格 UTF-8 拒绝孤立代理项，坏 checksum 与不支持版本分别保留真实错误。A0 的 NUL/孤立代理项/补充字符 CAST hex 是 MUTF-8 字节，不能称为普通 UTF-8 兼容。生产 java_name 行尚未装配。证据 artifacts/mdd-026/type-text-audit/20261028T170219193130Z/readback.json。

四个合成来源的类事实验证了 NULL/空 source_file、孤立代理项、NULL superclass 和重复 descriptor 的来源及顺序；非标量仅以原始 MUTF-8 比较。越界 source_file 索引被原生与 SDK 拒绝，A0 则显示 NULL，差异保留在 artifacts/mdd-026/class-source-audit/20261028T174234924728Z/result.json。

多DEX引用边界新增三个来源出现、同一目标不同本地索引、40个精确操作数站点、16行固定A0调用结果和共享物理代码的两个方法所有者对照；跨来源查找真实返回INVALID_ARGUMENT。证据 artifacts/mdd-026/mixed-reference-audit/20261029T004552809470Z/result.json，仅为合成静态样本。

字段及类型引用另以三个来源核验不同本地索引、重复出现及各6个目标位点，A0字段访问7行与类型引用6行的多重集合一致；跨来源查找返回INVALID_ARGUMENT。A0不提供站点PC，PC仅由原生与独立字节oracle对照。证据 artifacts/mdd-026/field-type-audit/20261029T010629766313Z/result.json。

动态引用及孤立代码以四个合成来源对照57个编码位点，4个invoke-custom目标保持未知，未归属物理代码不生成调用者；A0方法调用20行的多重集合一致。位点PC来自原生与独立字节oracle，不推断运行时分派。证据 artifacts/mdd-026/dynamic-source-audit/20261029T012418079194Z/result.json。

有效与坏索引DEX以两种顺序同快照验证：联合范围保留原始INVALID_INPUT、input complete/facts partial；只选有效来源时虽complete但covers_all_captured_sources=false。SDK和A0对该坏索引均退出0，不能当完整成功。证据 artifacts/mdd-026/mixed-failure-audit/20261029T015522772300Z/result.json。

非空partial引用反例中，不完整来源仍有10个真实位点和2个匹配，但严格关系及全范围索引/标量查询保持INCOMPLETE_FACTS；完整兄弟子范围明确covers_all_captured_sources=false。A0的8行仅对照完整来源，不能证明partial完整。证据 artifacts/mdd-026/partial-reference-audit/20261029T021708996807Z/result.json。

合成资源身份验证：同一APK两次输入中保留6个物理资源出现，包括同名不同字节成员；捕获后源文件改写不改变快照读取。缺成员时facts为unknown，完整子来源不宣称覆盖全部输入，外源注册返回INVALID_ARGUMENT。证据 artifacts/mdd-026/resource-scope-audit/20261029T043749212277Z/result.json，仅覆盖合成资源身份与coverage。

同一路径合成APK真实改写前后分别捕获两代快照，独立ZIP字节oracle核对6个物理资源出现：旧代保留旧字节，新代读取新字节；跨代登记返回INVALID_ARGUMENT且缺失覆盖仍unknown，本代登记后才complete。证据 artifacts/mdd-026/resource-generation-audit/20261029T050623250919Z/result.json，仅覆盖资源事实，不证明SQL/Smali/分页跨代绑定。

同一路径合成DEX真实改写合法指令引用并重算签名/校验和后捕获第二代；原生方法体与独立字节oracle及A0范围一致，旧快照保留旧字节，新代有不同指纹。跨代方法EntityRef及混合definitions/code均返回INVALID_ARGUMENT，native无体保持None。证据 artifacts/mdd-026/raw-generation-audit/20261029T062620399999Z/result.json；不证明完整类指纹、SQL/Smali/分页或profile。

逐列总表 artifacts/mdd-026/column-ledger/20261028T170548736531Z/column-ledger.json 固定17关系156列，逐项列出已有证据与剩余边界；追加式独立重算和4项负例通过，但所有列的完整资格均为false，不据汇总签发MDD-026或产品profile。

v2总表 artifacts/mdd-026/column-ledger-v2/20261028T171808763956Z/column-ledger.json 增量关联方法持有 try/handler 的12列证据，并保留损坏输入在A0与原生之间的真实差异；追加式回读和负例通过，全部字段完整资格仍为false。

v3总表 artifacts/mdd-026/column-ledger-v3/20261028T174511331094Z/column-ledger.json 增量关联8个 classes 字段的多来源边界，追加式回读和5项篡改负例通过；仍不签发 MDD-026。

v4总表 artifacts/mdd-026/column-ledger-v4/20261029T005209769816Z/column-ledger.json 增量关联10个 method_calls 和4个类身份字段的多来源引用证据，独立重算和7项篡改负例通过；156列完整资格仍均为false。

v5总表 artifacts/mdd-026/column-ledger-v5/20261029T013609946354Z/column-ledger.json 再关联字段、类型及动态/孤立代码来源证据，独立重算和9项篡改负例通过；156列完整资格仍均为false，69个兼容投影未装配。

v6总表 artifacts/mdd-026/column-ledger-v6/20261029T020323493739Z/column-ledger.json 增量关联混合损坏来源的引用层传播证据，独立重算和11项篡改负例通过；关联39列仅表示该层传播证据，不证明其字段值全部验收。任务、profile及156列完整资格仍为false。

v7总表 artifacts/mdd-026/column-ledger-v7/20261029T021940078907Z/column-ledger.json 增量关联非空partial引用与兄弟来源覆盖证据；独立追加重算及11项篡改负例通过，关联39列仅证明所列引用层边界，不代表字段值完整验收。原分母17关系156列、69个未装配兼容投影及所有字段完整资格false保持不变，MDD-026和profile仍未完成。

v8总表 artifacts/mdd-026/column-ledger-v8/20261029T044457978884Z/column-ledger.json 追加合成资源物理成员及覆盖证据，独立重算和9项篡改负例通过；资源切片独立于DEX字段，156列完整资格、MDD-026及profile仍为false。

v9总表 artifacts/mdd-026/column-ledger-v9/20261029T051611066996Z/column-ledger.json 追加同一路径实际改写前后两代快照的资源证据，独立重算和10项负例通过；初次负例因未拦截旧版读取入口失败并保留。该切片不证明SQL/Smali/分页跨代绑定，不提升字段或profile资格。

MDD-034 已重新打开：独立真实组合反例中，executor向有界队列发送4行后消费者尚未读取，查询却报告成功且delivery_complete；随后消费者因查询已结束被拒绝。原始输出 artifacts/mdd-034-audit/delivery-boundary-independent-20261029/probe/stdout.txt。先前27 query、10 session、7 types、2 compile-fail、SQLite双连接及子进程deadline的限定机制证据仍保留，但不能代替未消费数据的交付验收。生产worker/MCP/FFI尚未接线，不推断生产已发生；进程树隔离未由先前探针证明。

消费者确认候选现以绑定队列逐包ack和显式End换取对应收据，再取得最终envelope；零行也需End，旧受信回调限制为测试私有入口。独立真实会话16场景、20次并发（完成先胜2、取消先胜18）、伪造收据及旧入口编译负例通过；未释放生命周期缓冲另有真实红绿修复。证据 artifacts/mdd-034-audit/delivery-confirmation-independent-20261029/final-20261029/verify-run/record.json。Windows工作区232项测试、严格Clippy通过；生产worker/IPC、完整分页和各兼容profile尚未验证，MDD-034保持in_progress。

后续队列行将wire字节与Row持有容量分别做checked逻辑计量：稀疏数组低额度红绿与UTF-16、bytes、Entity内部容量、四级额度和取消持有测试通过；与拼接计步组合的Windows工作区241项测试、严格Clippy通过。独立探针在保留两次低内存准入阻断及两次测试预期失败后，按原3GiB门槛重建并完成8个限定场景；相同wire的紧凑/稀疏行分别按各自容量计费，工作区、输出与队列quota发生阶段分别核对，证据 artifacts/mdd-034/row-capacity-independent-20261029/readback-1/record.json。provider入队前分配、消费者克隆、allocator/RSS及生产传输仍未覆盖；流式计数候选尚待最终独立验收。

流式JSON候选对固定serde_json writer进行逐块Bytes编码和精确计数，成功后原子charge；真实低额度单线程红绿的最大单次分配申请由699108降至632字节，原始quota维度与截断终态保留。Windows工作区247项测试与严格Clippy通过。独立探针保留首次180秒超时、低内存未启动及缺少pywintypes的启动失败；满足原3GiB准入后在2GiB Job内完成7个合成真实队列场景，25项独立回读通过，见 artifacts/mdd-034-audit/streaming-json-independent-20261029/verify-probe4-run/record.json。长Entity探针首次编译根进程退出时仍有子进程，被作业判失败且探针未启动；独立重试完成，合成50万字节普通字符用54步完成，等长转义字符在64步额度下报QUOTA，见 artifacts/mdd-034-audit/long-entity-steps-20261029/runs/20261030T014930199186Z/probe/stdout.txt。该对比不证明取消延迟或实际产品缺陷。provider预分配、部分值的临时对象、其他serializer、allocator/RSS与传输未覆盖。长Entity字符串的serde内部扫描仍是待验证的细粒度取消风险。

MDD-034累计驻留反例与修复：两行各3989字节、额度5983时，旧代码在第二行计数时仅预约首行3989，随后入队才报7978超额；现将当前行的累计工作区预约移至计数前并交由队列持有。独立红绿回读确认第二行计数回调为0、输出仅首行427字节、首行确认后预约归零且最终不完整，见 artifacts/mdd-034-audit/prequeue-resident-fixed-20261030/readback-record.json。修复后Windows工作区248项测试和严格Clippy通过；这是合成进程内队列的逻辑容量证据，不代表provider预分配、RSS、生产传输或任务资格。

MDD-034入队前取消边界：独立代码复核指出流式输出行已计数但output_row检查失败时未标记丢弃；真实回归先因truncated=false失败，修复后保留原取消错误并标记截断，计数中取消和入队前取消的QueryWorkspaceBytes及ResidentBytes预约均验证归零。最终源码Windows工作区249项测试、严格Clippy通过，见 artifacts/mdd-034/output-row-truncation-20261030/；未重新执行先前7场景独立流式矩阵，不代表生产worker/传输或MDD-034整体准入。

MDD-031尾部转义与字节拼接实测：固定A0/A1在合成DEX上完成12个CLI查询，尾部LIKE为0、NOT LIKE为1，普通转义为1、NULL保持NULL；bytes拼接为text，含NUL和非UTF-8的HEX分别41C0804243/EFBFBD41。旧方言此前误报INVALID_ARGUMENT；现仅对DexSql010/011返回false，NativeV1保留原错误，配额/取消仍传播。该修复检查点独立桥探针21场景和8项旧引擎语义对照通过，见 artifacts/mdd-031-audit/legacy-escape-bridge-20261030/runs/20261030T020805554030Z/readback-run/record.json；Windows工作区251项测试、严格Clippy通过。旧版NULL wire与候选不同；当时bytes拼接类型和编码不等价，完整corpus及MDD-031资格未通过。

MDD-031拼接候选：A0/A1合成矩阵32项与独立replacement/MUTF-8 oracle一致，覆盖跨操作数字节、无效/截断、混合类型、NULL和DEX来源；候选旧方言按操作数增量解码Bytes、保留DEX UTF-16并在分配前检查额度与预约，Native路径保持原样。目标红绿及SQL模块测试通过；首次严格Clippy报manual_contains并保留失败，修正后最终源码Windows工作区255项测试和严格Clippy通过，见 artifacts/mdd-031/legacy-concat-20261030-final/。最终源码独立桥探针构建完成后，运行前可用内存2082922496字节低于原3GiB门槛，未启动，见 artifacts/mdd-031-audit/legacy-concat-independent-20261030/runs/20261030T022444872913Z/report.json；不能将旧引擎矩阵等同最终桥对照。输入载体复制、SQLite副本、allocator及RSS未覆盖，完整语料和profile仍未准入。

MDD-005 A2 查询转换候选位于 benchmarks/a2_compact_adapter.py，涵盖shape、HEX DTO、分页终态、额度、错误透传与失败后禁止复用。固定A1及公开合成DEX在旧接口上曾完成7行分页并与标准MCP DTO一致，前期生产者参数配置失败保留在 artifacts/mdd-005/a2-adapter-development-20261030/。最终接口新增强制快照绑定与投影确定总序检查，仅做Python语法检查，尚无已验证回调或真实producer重跑；未连接完整HostLab pipeline，20组等价与A2性能资格均not_run，MDD-005仍in_progress。

2026-10-30 功能推进（统一验证待后续执行）：MDD-026 新增按 FieldSymbol 跨输入出现次数查询编码字段引用的懒索引、精确复验、独立标量扫描和失败重试；局部 field_symbol_indexes_preserve_sites_and_source_occurrences 通过，不推断运行时解析。MDD-034 实体来源标识在固定 JSON writer 路径按 UTF-8 边界分段，单次扫描最多约1024字节；局部 long_entity_text_is_chunked_without_changing_json 通过，其他序列化器与完整取消/性能资格未验证。MDD-031 旧方言新增无数值前缀文本/字节的零转换，逐单元检查预算和取消；数字、符号及小数点前缀仍显式未实现，Native 不变；相关三个局部测试通过，旧版 DTO 与完整数值语义未验证。依用户要求，完整工作区、跨平台、独立 oracle 及正式资格验证均留待统一执行，三项任务保持 in_progress。

2026-10-30 后续功能候选（统一验证待后续）：MDD-026 新增跨出现次数的UTF-16字符串编码引用站点查询与标量路径，孤立代理项等一项局部测试通过，未推断原始MUTF-8字节相等或运行时值。MDD-031 两个旧方言增加直接字符串字面量CAST AS TEXT与非负i64字面量比较，局部测试通过并保留白名单失败记录 artifacts/mdd-031-audit/direct-text-affinity-20261030/；Native、列、CTE、VARCHAR/CHAR、浮点及动态表达式未扩大。A2候选增加只在明确output_too_large、相同dataset未关闭且continuation guard允许时缩小页面的重试，最终分支仅语法检查，真实producer验证not_run。完整工作区、跨平台、独立oracle和资格统一留待后续，任务状态不变。

2026-10-30 第三批功能候选（统一验证待后续）：MDD-026 增加精确类型描述符跨出现次数的编码operand站点索引及标量路径，一项局部测试通过，不推断运行时解析/继承。MDD-031 增加严格完整ASCII有符号i64文本的旧方言算术候选，逐单元计步并用checked运算，小数/指数/尾部非空白、浮点混合及溢出仍未实现；两项局部测试通过，A0/A1现有54项为CAST而非算术证据，故算术等价未验证，记录 artifacts/mdd-031-audit/legacy-integer-text-candidate-20261030/。MDD-005 新增 benchmarks/a2_hostlab_session.py 同步桥候选，要求外部producer快照/总序、真实inventory、可确认close及进程树abort；仅py_compile通过，未接真实HostLab与未消费/取消完整验证。先物化查询改变管线重叠，后续性能归因须单列；统一验证和各任务资格均未完成。

2026-10-30 持续功能推进（全量验证后续统一执行）：MDD-026 增加按原型描述符跨输入出现查询编码Prototype operand站点的懒索引、精确复验和标量路径，038/039及重复出现等一项局部测试通过，不推断运行时分派。MDD-031 对无亲和性的字面量BETWEEN/NOT BETWEEN、简单CASE使用已有存储类型比较，并将旧方言直接TEXT CAST字面量对非负i64字面量的限定规则扩至上述结构；两个局部测试通过，A0/A1对照、跨平台及全量not_run。MDD-005 新增 benchmarks/a2_input_inventory.py 完整SHA与物理DEX清单候选，合成输入十项局部检查与固定HostLab清单规则对照通过，记录 artifacts/mdd-005/a2-input-inventory-20261030/record.json；文件观测不证明producer不可变快照、041逻辑完整性或SQL总序。任务和profile均未签发。

2026-10-30 持续功能推进续（全量验证后续统一执行）：MDD-026 方法句柄跨来源候选按完整句柄kind及FieldSymbol/MethodSymbol精确键返回实际编码operand站点，039字段/方法句柄、重复来源、无句柄引用和缺层/预算等一项局部测试通过；不推断实际调用、字段访问或运行时解析。MDD-031 两个旧方言对当前无歧义基础表I64/U64列的IN/NOT IN支持规范十进制i64字符串字面量；局部覆盖NULL、负数、未知列和Native边界，非规范文本、越界、浮点、参数、派生表/CTE仍保守未实现，最终A0/A1对照not_run。MDD-005 A2同步桥新增完成迭代后的有序DTO消费回执，区分NULL/空值、重复与顺序；原候选的零行schema未知、未消费不发回执，局部合成检查通过。回执不证明producer快照、总序或完整审计，编码开销需单独性能归因。

2026-10-30 继续功能候选（全量验证后续统一执行）：MDD-026 动态调用点新增同一快照、同DEX内容身份与完整原始encoded_array字节键查询，保留所有来源出现与编码引用站点，不声称不同DEX语义相等或推断运行时目标；局部fixture仅含前三个必需元素，合法附加参数、浮点和独立oracle未验证。MDD-031 旧方言对直接INTEGER CAST字符串字面量与规范i64文本字面量补充IN/NOT IN及=/<>限定候选；局部测试通过，首次编译因并行facts中间态失败，稳定后重跑通过；旧DTO uint64与候选i64仍不同，完整A0/A1差分未运行。A2 compact外层可选排序只接收shape中存在的列及固定方向，并引用原值；局部合成客户端/SQLite检查通过，最终语义等价、确定总序和producer快照仍须独立证明，额外排序成本需单独归因。各任务及profile仍未准入。

2026-10-30 继续功能候选续（全量验证后续统一执行）：MDD-026 支持按精确类descriptor跨出现次数查询直接声明字段/方法，复验候选及owner，不推断继承；一项局部测试通过，独立oracle未运行。MDD-031 旧方言仅对直接非负i64数字字面量 CAST AS TEXT 与非负i64字面量的等值比较补充候选，局部测试通过，旧wire uint64与候选i64仍不同，完整对照not_run。MDD-005 compact result()将同一次查询shape列、完整页、总行数与页数一并交付，同步桥v2消费回执可保留零行实际schema，原rows()保持列表；局部合成检查通过，最终真实producer、快照、总序及HostLab验证not_run。任务与profile均未准入。

2026-10-30 本轮后续功能候选（统一验证延后）：MDD-026 增加借用式方法事实视图，按同一DEX出现的method-id连接引用、prototype及可选真实definition，区分reference-only、native、abstract、present；未建代码和注解不填NULL，局部测试通过，HostLab methods关系及独立oracle未完成。MDD-031 对无关WITH保留可证明且未被可见CTE遮蔽的基础表IN作用域；局部检查覆盖别名、大小写遮蔽、派生表、歧义及未知列、递归拒绝，该次facts编译与并行修改有时间重叠，不当作最终工作区验证，A0/A1对照not_run。MDD-005 新增固定A1独占dataset关闭及空闲回读候选，合成DEX实际受控运行通过，见 artifacts/mdd-005/a2-dataset-close-20261030/record.json；两次环境/目录错误发生在作业创建前，非producer失败。此回读不证明快照、总序、生产进程树或A2资格，真实完整HostLab及全量验证均未运行。

2026-10-30 后续功能候选（统一验证延后）：MDD-026 新增借用式字段与类事实视图，完整metadata/definitions前提下分别保留同DEX field-id的引用/类型/可选定义及class_def顺序、NO_INDEX父类/源文件、直接接口ordinal；不合成初始值或注解、不推断继承，各一项局部测试通过，类/接口条数预算不等于扫描字节或RSS预算。MDD-031 共享Text/Bytes/DexMutf8比较逐单元检查额度和取消，保持原有UTF-16/原始字节排序；函数与真实SQL桥各一项局部测试通过，逐单元成本及A0/A1/独立oracle待统一验证。MDD-005 新增A1独占dataset打开候选：前后检查来源、空闲状态、输入路径与dataset回执，任何已提交生命周期请求在取消/超时/不确定结果时要求owner中止；12项模拟客户端局部检查通过，原始记录 artifacts/mdd-005/a2-dataset-open-20261030/run2/record.json。最终源码未连接真实producer，不证明快照、总序或A2资格。

2026-10-30 继续功能候选（统一验证延后）：MDD-026 新增同源method→code借用视图，绑定snapshot/occurrence/member/content并逐项核对真实物理code item起点和指令范围；区分reference-only、native、abstract、present及有体空指令，scoped缺项/partial明确失败，局部一项测试通过；旧opcode_count/hex、真实跨代和独立oracle未验证。MDD-031 对相关子查询IN按作用域由内向外解析可证明的基础表列，未知CTE/派生scope阻断推断、遮蔽/歧义/缺列保留真实绑定错误；局部首测发现合法CTE内部READ被预检误拒，后仅对当前AST可见CTE且database=None/column空的容器读取放行，局部测试及sqlite_master/DELETE/ATTACH拒绝检查通过。合成反例不证明真实HostLab corpus，A0/A1、独立安全及全量验证not_run。MDD-005 新增A1独占dataset生命周期组合，共享client/source/deadline，open/消费/close失败或取消要求owner确认中止；9项模拟客户端局部检查通过，记录 artifacts/mdd-005/a2-dataset-lifecycle-20261030/run2/record.json，不证明真实producer、快照、总序或A2资格。

2026-10-30 持续功能候选（全量验证后续统一执行）：MDD-026 增加同快照和DEX出现内的方法参数借用视图，区分未编码列表、显式零槽、非零集合及短列表Unknown；注解未建或位置不完整返回INCOMPLETE_FACTS，局部一项测试通过，兼容文本映射和独立oracle未运行。MDD-031 已解析CTE名称随PreparedSql传递；执行authorizer只放行database=None、空列名且名称命中的SQLite内部CTE容器读取，局部红绿覆盖直接/嵌套CTE及系统表、写入、ATTACH拒绝，A0/A1、独立安全和全量not_run。MDD-005 增加Windows自有Job持有期候选：隐藏无继承子进程挂起创建，分配验证后恢复，取消/期限/关闭核验自有child及Job归零；首次Job参数错误和中间清理竞态失败保留，最终 run5 注入创建失败时实际直接终止访问拒绝保留，随后确认同一子进程退出和树空，见 artifacts/mdd-005/a2-windows-job-owner-20261030/run5/record.json。无MCP双向通道，不证明Linux、输入快照、完整A2或资源资格。

2026-10-30 后续功能候选（统一验证延后）：MDD-026 同源MethodCodeBody增加无分配已解码普通指令opcode迭代，保留reference-only/native/abstract/present-empty区别，单独保存的switch/array payload不当普通指令；两项局部测试通过，旧HEX表示及独立A0对照未运行。MDD-031 对明确要求SQLite语法确认的AST未实现错误统一传递当时可见、已解析CTE名称；局部检查合法CTE仍返回真实UNSUPPORTED、缺列/禁用函数保持INVALID_ARGUMENT，相关IN回归通过，完整A0/A1/安全验证not_run。MDD-005 Windows受控双向管道仅有自有短命进程原型：两次准入分别3004952576与2064080896字节，低于原3221225472字节，均未创建Job或子进程；记录 artifacts/mdd-005/a2-windows-pipe-prototype-20261030/。Job句柄白名单、挂起恢复与双向IPC未运行、未实现，MCP及快照资格不推断。

2026-10-30 继续功能候选（统一验证延后）：MDD-026 增加借用式字符串引用站点视图，保留同源调用方法/PC/operand、原始MUTF-8及UTF-16、字符串池和每次输入出现；partial拒绝，完整消费预留两次遍历2N逻辑站点访问，局部1项测试含2N边界通过，字节/CPU/RSS及独立oracle未验收。MDD-031 Bytes/DEX MUTF-8文本解码逐编码点检查预算/取消，每次最多读取4字节；局部真实红绿及facts冻结后桥单项通过，见 artifacts/mdd-031-audit/text-decode-budget-20261030/bridge-final/record.json；输入载体、Text克隆、SQLite副本/RSS未覆盖。MDD-005 Windows显式handle_list自有Job管道候选有受界读写、stderr drain、后台首错传播、期限与取消清理；run6真实复现单个transport.close异常导致后续清理被跳过，修复后run7自有隐藏合成子进程13项检查通过；随后补保留首个异常对象链与取消原类型，最终源码run8两项定向检查通过，见 artifacts/mdd-005/a2-windows-pipe-owner-20261030/run8/record.json；run7的13项未在最终源码全部重跑，清理异常汇总并使cleanup不予确认。run1哨兵断言失败时未显式关闭owner，进程结束后只读未见该特征进程，但无该次Job树空证明；run2仅按句柄数值判断不能证明继承，后续才用内核事件身份；失败原始记录保留。stdout上限只计read消费量，OS/asyncio缓冲、RSS及启动前SHA/路径扫描不由此限额证明；EOF/close不是协议成功。真实MCP、快照、Linux、A2与完整验证均not_run。

2026-10-30 持续功能候选（统一验证延后）：MDD-026 新增同源借用式 Method/Field/Type 编码引用站点视图，保留 caller、target、operand位置与各输入出现，完整覆盖必需，2N逻辑站点访问与结果额度受限；一项局部测试通过，不推断运行时分派或字段访问。MDD-031 对已持有Text的LIKE、length和substr路径改用借用，避免预算检查前额外整段克隆；两项局部真实桥回归通过，见 artifacts/mdd-031-audit/text-borrow-20261030/，Bytes/MUTF解码及结果所有权保持，SQLite/输入/结果副本、RSS与性能未证明。MDD-005 新增固定MCP 2.2.0的Windows自有Job管道实验传输，受限换行JSON-RPC帧、UTF-8、重复键、帧/总量和取消/EOF错误；run4中14项局部检查包括固定A1+合成DEX open/query/close及Job树空通过，见 artifacts/mdd-005/a2-mcp-transport-20261030/run4/record.json。run1/2 AnyIO取消导致树空未确认的失败原样保留；SDK正常关闭可能让owner记录预期reader CancelledError，关闭意图/协议交流不证明页面已消费、快照或审计完成；SDK pending可能只报告connection-closed，原始传输错误需检查transport.failure。完整HostLab、A2、Linux、性能和profile均未准入。

2026-10-30 继续功能候选（统一验证延后）：MDD-026 增加按同snapshot/occurrence的MethodDefinition查找编码operand站点的懒索引及标量路径，可选TargetKind并精确复验caller，保留PC/ordinal/重数；扫描与结果额度、partial和失败重试的局部1项测试通过，不推断dispatch。MDD-031 Q08 lower/upper的Text/DexMutf8输出按checked UTF-16长度先预约QueryWorkspaceBytes及SQLite载体逻辑容量再构造，租约保持至ToSql；低额度、NUL/孤立代理、取消/释放三项真实会话局部检查通过，见 artifacts/mdd-031-audit/case-output-workspace-20261030/；输入载体、SQLite副本、allocator/RSS、性能与A0/A1未证明。MDD-005 A1BoundedCandidate组合自有Job、SDK、A1打开/查询/关闭；查询在rows()调用时登记，未启动、未消费、取消或worker loss阻断正常退出；固定A1和合成DEX的七项局部检查通过，见 artifacts/mdd-005/a2-bounded-candidate-20261030/run2/record.json。snapshot/order/inventory回调在测试中均为明确标注的模拟调用方断言，固定A1无generation/hash证明，qualified只读恒false；不证明完整HostLab、A2或性能资格。

2026-10-30 持续功能候选（统一验证延后）：MDD-026 按同snapshot/occurrence的物理AnnotationRef提供借用式完整encoded值节点及原始字节，保留序号/嵌套、NULL和float bits；局部测试对照现有oracle并覆盖假起点、跨来源、partial与逻辑访问额度，首次缺DecimalU64导入失败已修正，全量与独立整体验证not_run。MDD-034 QueryCancellation::checkpoint在同一生命周期锁内检查期限/worker错误与phase；取消、首个deadline、worker loss及完成态3项局部测试通过，见 artifacts/mdd-034-audit/checkpoint-atomic-20261030/record.json；原二次锁竞态是源码推断，未独立受控复现。MDD-031 增加单基础表、直接单列且与左侧已知类型相同的I64/U64/Text IN子查询，WHERE仍走原AST/readonly/依赖；局部三方言检查NULL/重复/空集/相关/别名、U64极值及Text非scalar，见 artifacts/mdd-031-audit/typed-in-subquery-20261030/cte-final/record.json。派生表深层CTE容器错误分类的静态担忧未复现：合法情况保持UNSUPPORTED，真实缺列为INVALID_ARGUMENT，未扩大授权；混合/F64、子查询WITH/ORDER/GROUP/DISTINCT/派生及完整Q14仍未支持，A0/A1及profile未准入。本批A2组合暂存后出现的跨task退出未暂存补丁来源未确认，未覆盖或收入本批；本地run3-cross-task仅针对该工作区补丁，未收入证据索引，不作为已提交版本验证。

2026-10-30 目标持续功能（统一验证延后）：MDD-005 基线consumer真实合成反例证明空structured DTO自报2行、字符串rows自报2行及布尔false fallback先前均被误认完整；现structured在缺少工作负载完整性验证器时明确拒绝资格，ordered/bag要求真实行列表、fallback要求整数0，合法零行仍接受，3项红绿及5项局部测试通过，见 artifacts/mdd-005/structured-completeness-20261030/result2.json。structured验证器仍待实现，未缩减任务原验收；首次反例因夹具类名称错误未运行，后按实际类重跑。MDD-026 增加同snapshot/occurrence的受界Java类型名渲染，primitive/对象/数组保留原descriptor及Unicode/嵌套，1项局部测试通过，见 artifacts/mdd-026/java-type-name-20261030/record.json；仅7个样本有历史A0观察。MDD-034 绑定队列deadline先登记query首错，防止receiver释放改为CANCELLED；实际红例及3项局部绿例见 artifacts/mdd-034-audit/queue-deadline-20261030/，非绑定、先前取消/worker loss保留原语义。MDD-031 旧方言单来源单列CTE直接CAST字符串AS TEXT与非负i64字面量比较候选，局部红绿及原混合比较回归通过，见 artifacts/mdd-031-audit/cte-text-affinity-20261030/；A0/A1未重跑、DTO和完整CTE资格未通过。现有A2未暂存补丁与run3证据按原样保留，本批未触碰。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 增加同一snapshot/DEX出现的method prototype参数类型借用视图，按ordinal保留真实TypeFact、引用及可选定义，不要求注解层，也不推断注解或旧参数文本；双来源、reference-only/definition、零/多参数、额度及错误身份一项局部测试通过，见 artifacts/mdd-026/prototype-parameters-20261030/record.json。MDD-031 冻结HostLab Q13的HEX输出现在按既有Native/legacy字节语义先计数、预约内部TEXT载体逻辑工作区，再构造并持有至ToSql；原512红例在元数据先触发quota而未触及HEX，调整后red2真实101、最终额度/编码/取消局部绿例通过，见 artifacts/mdd-031-audit/hex-output-workspace-20261030/；输入载体、SQLite副本、allocator/RSS与性能未覆盖。MDD-034 真实反例显示绑定send的quota后仍可发布Ok End，且在途发送或execute_into JSON计数时外部finish可提前发布成功；现发送在途和同队列producer整程租约阻断外部成功End/发送，首错和显式失败回执保留。真实竞态红绿、零/多行、quota、取消、弃置、预检、背压与未绑定局部检查见 artifacts/mdd-034-audit/bound-send-quota-20261030/；记录脚本的历史source_before未包括executor.rs，因此不能由该记录单独证明执行器源身份，status检查后并发取消的极窄窗口也未独立受控证明。以上任务/profile未准入，全量、跨平台与独立oracle后续统一执行；既有A2未暂存源码及记录本轮未修改。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 RawCodeEvidence 直接从完整验证的当前 method definition 构造同源实体并拒绝重复定义，避免逐项重复线性查找；双occurrence、共享code、原始bytes及既有手写/Python摘要局部检查通过，见 artifacts/mdd-026/raw-method-identity-20261030/。此为合成正确性范围，不是性能测量或全格式资格。MDD-031 MetadataSqlProvider 增加 native_types、native_prototypes 和有序 native_prototype_parameters，保留同snapshot各occurrence、原始MUTF-8、参数ordinal及真实offset NULL；真实桥单项和既有字符串回归通过，见 artifacts/mdd-031-audit/native-metadata-20261030/green/ 与 string-regression/。首次在max_cell=1时SQLite于虚表构造前返回INVALID_ARGUMENT而非游标QUOTA，原始失败与诊断保留；直接游标额度已单独验证，该极小SQLite长度下的桥接错误分类仍未解决。Owned行/SQLite副本/RSS和HostLab兼容未准入。MDD-034 真实零行红例在BudgetPool软期限到期后仍返回delivery_complete；候选从budget树复制不可变截止见证，session同一锁内核验query owner、cursor token/session/snapshot/epoch/request/schema/语义、其他游标/缓冲及较早截止，并原子确认cursor与最终交付，保留先前首错与计算完成状态。session两项及query两项局部绿例通过，见 artifacts/mdd-034-audit/receipt-budget-deadline-20261030/；query green2源码快照早于后续SQL provider测试诊断修改，不能当最终全部源码身份；完整并发、生产worker、跨平台及profile均not_run。本批未修改现有A2未暂存内容。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 类精确查询绑定所选快照、范围和覆盖，旧接口对空事实、partial和重复出现显式拒绝，不把所选范围缺失当全部输入缺失；两项局部检查见 artifacts/mdd-026/class-scope-20261030/，逐列及profile资格未通过。MDD-034 查询接收前拒绝已有记录的终态构造器；交付时的期限、取消及worker丢失保留覆盖与计算状态并产生错误终态，清理错误及详情键冲突保留首错。真实红绿、局部检查及最终源码两项检查见 artifacts/mdd-034-audit/nonpristine-terminal-20261030/ 和 artifacts/mdd-034-audit/late-delivery-envelope-20261030/；计数不一致为测试注入，分配器耗尽不保证追加详情。MDD-031 小单元格限额下仅对所需虚表进行受界预连接，恢复并回读SQLite长度后才准备用户SQL；最终源码7项局部检查包含真实单字节额度和2001列虚表失败后的恢复，见 artifacts/mdd-031-audit/vtab-prewarm-20261030/candidate/record.json。取消仅检查限额提升前，工作区逻辑额度不覆盖SQLite内部分配或RSS；下游完整编译、真实HostLab corpus、跨平台、性能及完整验收均未运行。各任务及profile状态不因局部候选改变；已有A2未暂存工作保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 新增同快照和DEX出现内的物理annotation项到编码owner反查，保留共享集合、每个owner、set ordinal和参数编码槽，不推断参数语义；局部1项见 artifacts/mdd-026/annotation-owner-view-20261030/run2/record.json，孤儿及损坏集合由测试注入，逻辑访问额度不含结果向量/allocator/RSS。MDD-031 对同类型直接列的Bytes/Bool IN/NOT IN子查询增加候选支持，三方言和SQLite对照含NULL、重复、空集及相关子查询，既有类型回归也通过，见 artifacts/mdd-031-audit/in-subquery-bytes-bool-20261030/；记录只固定SQL两文件及lock，未锁全部依赖，A0/A1、混合类型/F64、完整Q14和profile未通过。MDD-005 生命周期文本与结构化回执现在类型敏感比较，打开后的嵌套回读同样比较，拒绝非JSON和非有限数；布尔/数字误认的合成红例、固定Python 3.12.14下5项检查及既有12项打开流程见 artifacts/mdd-005/a2-lifecycle-json-20261030/，解析递归错误为显式注入；两轮默认递归深度测试假设失败原样保留。不证明真实生产者兼容、输入快照或A2资格，也不单独限制解析内存。全量和跨平台验证未运行，用户既有A2未暂存补丁保留。

MDD-034 期限顺序补充：真实受控反例中两个期限都到期后，查询检查和绑定队列分别可能先报告较晚的期限；候选复制同owner预算截止见证并在生命周期锁内使用同一时刻比较，等时按原生命周期规则。另实际构造预算互斥锁中毒，修复见证读取错误未登记终态的问题并保留已登记首错。最终10项局部检查通过，记录 artifacts/mdd-034-audit/checkpoint-deadline-order-20261030/final/；不代表完整并发或生产worker验收。SQL新类型对照在本批query/session源码上又单项通过，见 artifacts/mdd-031-audit/in-subquery-bytes-bool-20261030/integrated/record.json；该记录仅固定列出的源码，非全量。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 方法body新增受界普通opcode数量及小写文本投影，纯引用为None，无体定义与实际空体由body状态区分；三份合成DEX共24个方法与保存的固定A0表逐行对照，见 artifacts/mdd-026/opcode-text-20261030/a0/record.json，仅此范围，额外分配、RSS和取消延迟未证。MDD-031 新增所选同snapshot DEX出现的原生类和直接接口惰性SQL提供器，保留来源、NULL、UTF-16、MUTF-8和接口序号；局部组合源码检查见 artifacts/mdd-031-audit/native-classes-20261030/integrated/record.json，不证明全快照覆盖、旧表或完整HostLab资格。MDD-034 绑定与非绑定队列在预算到期后仍发布成功End的受控红例已修复；最终6项局部检查见 artifacts/mdd-034-audit/queue-finish-budget-20261030/final2/record.json，检查后并发取消和生产worker未完整覆盖；前一条0测试筛选记录保留。MDD-005 compact页要求显式next_offset、有效错误状态、空内容列表和整数语句序号；合成红绿及固定A1、小DEX的7行4页对照见 artifacts/mdd-005/a2-compact-terminal-20261030/final/，snapshot/排序是模拟回调，未授予A2资格；首轮HEX空白/小写反例与固定消费者转换一致，未改变。全量、跨平台及性能资格仍未执行，原有A2未暂存内容保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 增加方法参数descriptor的受界逗号连接投影，分别保留源MUTF-8及UTF-16；固定A0已保存的24个合成方法、独立补充字符夹具与额度3项局部检查通过，孤立代理descriptor由既有类型读取明确返回INVALID_INPUT，见 artifacts/mdd-026/parameter-descriptor-text-20261030/run2/record.json；不声明支持非标量descriptor或完整旧列资格。MDD-031 新增所选同snapshot DEX出现的四个原生方法/字段引用和定义关系，保留源身份、原始MUTF-8及真实body状态；合成样本成员和类关系在最终组合源码上各1项通过，见 artifacts/mdd-031-audit/native-member-relations-20261030/integrated2/record.json；先前integrated筛选错名得到0测试的记录保留，不作通过。未验证全快照、旧methods关系或完整HostLab。MDD-034 无绑定队列的成功End若发布后、接收前预算到期，接收时现返回真实期限错误；局部5项通过并保留红例，见 artifacts/mdd-034-audit/unbound-end-delivery-deadline-20261030/；绑定队列仍由回执确认，全部竞态和worker未证。MDD-005 同步HostLab桥在调用rows时立即登记待消费查询，未启动、启动前关闭和部分消费不能当会话成功；合成红绿及固定A1、小DEX 7行对照见 artifacts/mdd-005/a2-sync-unstarted-20261030/，快照、顺序和inventory回调是模拟，不构成A2资格。全量、跨平台和性能验证仍未执行，既有A2未暂存工作保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 标量定义查询直接遍历事实，避免在结果额度前收集完整本地索引向量；清理构建缓存后离线定向1项通过，另外两个二进制筛选0项不算通过，见 artifacts/mdd-026/scalar-definition-stream-20261030/record.json；未测内存或性能。MDD-031 同snapshot、epoch及完全相同所选DEX出现的原生metadata/definitions provider可组合，实际桥接双来源JOIN与范围/epoch拒绝1项通过，见 artifacts/mdd-031-audit/combined-native-provider-20261030/run1/record.json；不证明全来源或旧表资格。MDD-005 基准消费者补查结果必需身份、scope、schema和无重复事实层；六个合成反例及12项本地自检见 artifacts/mdd-005/result-identity-20261030/，仍需独立scope manifest及真实来源绑定证明，structured无验证器继续拒绝。全量、跨平台及性能资格未运行，用户已有A2未暂存工作保留。

MDD-034 预算释放候选先核对所有祖先及资源计数，再统一写入；内部计数故障注入反例确认下溢时不作部分更新，析构计数故障亦不覆盖已登记首错。最终3项局部检查通过，见 artifacts/mdd-034-audit/atomic-release-fault-20261030/drop-green/record.json；故障由测试注入而非自然输入复现，OOM、完整并发和跨平台未验证。上述事实与SQL测试早于最终预算补丁，不证明所有模块组合资格。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 方法与字段视图新增完整实体身份直接查询，区分引用/定义并拒绝跨来源，双来源对照1项通过，见 artifacts/mdd-026/direct-member-lookup-20261030/record.json；另外两个二进制筛选0项不计通过，未测性能或完整资格。MDD-031 增加 native_dex_occurrences 原生关系，分别返回快照、DEX出现、物理DEX、成员、输入出现及内容身份；同字节双来源桥检查1项通过，见 artifacts/mdd-031-audit/native-dex-occurrences-20261030/run1/record.json，不证明全范围或旧dex_files兼容。MDD-005 基准消费者用类型敏感编码比较输入清单，避免布尔和整数混同，并拒绝缺少层/原因的coverage issue；四个合成反例及14项局部自检见 artifacts/mdd-005/input-coverage-integrity-20261030/，不证明输入与scope manifest的真实绑定。全量、跨平台与性能验证未执行；用户已有A2未暂存工作保留。

MDD-034 消费确认内部故障补充：受控锁中毒红例中INTERNAL_FAULT被未确认包析构改记为CANCELLED；候选在析构前登记首错，计数溢出亦处理。最终1项局部检查含两类内部故障注入，见 artifacts/mdd-034-audit/ack-internal-first-20261030/final/record.json；非自然输入复现，生产worker及完整并发未证。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 方法代码视图新增同来源实体直接查询，保留引用及实际方法体状态，双来源与迭代结果、原始字节对照1项通过，见 artifacts/mdd-026/direct-method-code-20261030/record.json；另两个二进制0项未计通过。MDD-031 新增独立 native_reference_sites provider，要求引用事实完整并保留来源、调用者、目标坐标及原始范围；双来源桥1项检查覆盖10列，见 artifacts/mdd-031-audit/native-reference-sites-20261030/run1/record.json；目标类型、调用类型和长度未逐列独立核验，尚未接入CombinedSqlProvider，不证明旧method_calls或完整资格。MDD-005 基准消费者对ordered/bag检查连续列ordinal、非空type及行数组宽度；六个合成反例和15项自检见 artifacts/mdd-005/row-shape-20261030/，不验证单元格类型或真实工作负载。全量、跨平台和性能验证未运行，现有A2未暂存工作保留。

MDD-034 终态跟踪锁中毒的受控反例显示接收End和获取回执返回INTERNAL_FAULT但生命周期被清理改记CANCELLED；候选先登记首错，新测试及已有确认路径回归各1项通过，见 artifacts/mdd-034-audit/terminal-tracker-fault-20261030/green/record.json。锁故障为测试注入，非自然输入，生产worker与完整并发未验证。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 类事实视图新增完整同源实体直接查询，双来源、错误身份、来源文件和接口对照1项通过，见 artifacts/mdd-026/direct-class-lookup-20261030/record.json；另两测试二进制0项未计通过。覆盖报告在原始错误已有scope_id时不再覆盖该详情，受控红绿见 artifacts/mdd-026/coverage-error-detail-20261030/；首次修复误用仅测试依赖导致编译失败原样保留，后用既有接口通过1项，分配失败不承诺可恢复。MDD-031 引用位点provider可选接入组合provider，要求相同snapshot、epoch和所选出现、完整引用；双来源JOIN及范围/代次/快照/partial/重复绑定1项通过，见 artifacts/mdd-031-audit/combined-reference-provider-20261030/run1/record.json；未证明旧method_calls、全范围或profile。MDD-034 受控tracker锁故障在receipt.matches曾被清理改记CANCELLED，候选先登记真实首错；两项局部检查通过，见 artifacts/mdd-034-audit/receipt-match-fault-20261030/，反例由内部注入，其他依赖身份未完全固定。全量、跨平台和性能资格未验证；已有A2未暂存工作保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 原始方法证据新增同snapshot/occurrence/MethodDefinition直接查找，原始方法体复用该校验；实际空体、双来源共享代码及既有手工/Python摘要三项局部检查通过，见 artifacts/mdd-026/direct-raw-method-evidence-20261030/record.json，不证明完整事实或性能。MDD-031 独立CodeSqlProvider新增native_code_items/native_code_bytes，要求完整物理代码map，双来源原始字节、部分范围及低cell额度1项局部桥检查通过，见 artifacts/mdd-031-audit/native-code-items-20261030/run1/record.json；未接Combined，Vec/SQLite副本及RSS未受该额度证明，未授予旧表或profile资格。MDD-034 producer租约预检锁故障曾被清理改为CANCELLED；候选先登记首错并保留已有取消，真实受控红例及2项局部测试见 artifacts/mdd-034-audit/claim-tracker-fault-20261030/，锁故障为内部注入，不证明自然输入或全并发。MDD-005 基准消费者检查coverage issue和warning的必需字段、可选类型及阻断标志，合成红绿和16项自检见 artifacts/mdd-005/diagnostic-contract-20261030/final2/record.json；不证明真实错误覆盖或完整工作负载。全量、跨平台和性能验证未运行，用户已有A2未暂存工作保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 新增同来源类直接成员借用视图，保留字段/方法kind、ordinal及编码顺序；额度 max_member_entries 仅限制全集条目数，不计每次访问、CPU或RSS；双来源及边界1项见 artifacts/mdd-026/class-members-view-20261030/final/record.json，错误ordinal为内部注入。MDD-031 完整物理代码项可选接入同snapshot、epoch、出现范围的组合provider，双来源共享方法体JOIN和范围拒绝1项见 artifacts/mdd-031-audit/combined-code-provider-20261030/run1/record.json；该记录早于类成员额度命名调整，未同时验证引用provider或旧表资格。MDD-034 绑定队列锁中毒的受控反例中真实INTERNAL_FAULT被清理改记CANCELLED；receive/finish/receipt/try_clone候选先登记首错，最终3项局部测试见 artifacts/mdd-034-audit/queue-lock-first-fault-20261030/final/record.json；受控红例仅证明先到的失败入口，锁故障为注入。MDD-005 MCP帧拒绝解析为非有限浮点的数字，合成红绿与固定A1小DEX 7行4页回归见 artifacts/mdd-005/a2-mcp-finite-number-20261030/；generation/order回调模拟，非A2资格。未运行全量、跨平台或性能验证，用户原有A2未暂存内容保留。

组合代码provider在本批最终事实与运行时源码上重跑1项通过，所列源码与fixture身份见 artifacts/mdd-031-audit/combined-code-provider-20261030/final2/record.json；未列依赖与引用provider同时组合仍未证明。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 引用事实新增完整站点身份查询，要求同snapshot/occurrence与完整事实，验证caller、PC、operand ordinal/kind；双来源及原始操作数字节1项通过，partial和重复站点为内部注入，见 artifacts/mdd-026/direct-reference-site-20261030/record.json；条目额度不涵盖定义校验、CPU或RSS。MDD-034 已记录取消后遇乱序确认的受控反例原先返回次生INVALID_ARGUMENT，候选保留原首错；局部红绿见 artifacts/mdd-034-audit/ack-prior-fault-20261030/，乱序由测试注入，生产worker与全并发未验证。MDD-005 基准消费者检查结果信封及coverage/execution/response必需和未知字段、可选身份与data类型；十个合成反例及17项自检见 artifacts/mdd-005/result-envelope-shape-20261030/，结构有效不证明scope manifest或实际来源绑定。全量、跨平台及性能验证未执行；用户已有A2未暂存工作保留。

MDD-031 既有组合provider的引用、方法定义和代码字节三方JOIN新增双来源定向对照，两种绑定顺序1项通过，见 artifacts/mdd-031-audit/combined-three-layer-20261030/run1/record.json；夹具的共享方法体有既有证据，本测试自身未断言两个caller共享同一偏移。对照来自现有事实，并非独立DEX oracle，未证明A0/A1或profile，且本次未新增生产SQL实现。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 SelectedScope 可将所选DEX出现与已验证metadata/头部按范围顺序配对，检查snapshot、来源及内容等身份；双来源、子范围、partial等1项局部检查见 artifacts/mdd-026/scoped-metadata-rows-20261030/run1/record.json，不授予旧dex_files、池编号或全快照资格。MDD-030 类型化NativeCatalog新增prototype_parameters关系，仅需metadata，保留原型实体、ordinal和类型实体；双来源1项见 artifacts/mdd-030/prototype-parameter-ir-20261030/run1/record.json，对照同一事实实现，未独立验证同一原型内重复参数。MDD-031 新增同范围注解provider并可接入组合查询，提供物理item、encoded value node、owner/parameter slot及精确float bits；双来源、NULL、位型、owner及范围拒绝1项见 artifacts/mdd-031-audit/native-annotation-provider-20261030/final/record.json，同一事实对照非独立oracle，set-entry/ref-list及完整参数位置、旧表、SQLite/RSS仍未准入。MDD-005 Windows读共享锁候选在受锁前后核对输入，合成测试观察写入/重命名拒绝、已有写句柄阻断、注入关闭错误重试与首错保留；固定A1受锁合成副本7行4页，见 artifacts/mdd-005/a2-windows-input-pin-20261030/final3/record.json。进入阶段校验和关闭同时失败时须预先持有对象以重试，否则句柄可能保留至进程退出；现有可写映射、特权操作和生产者快照/总序未证明，候选未接入A2。全量、跨平台及性能资格未验证，用户既有A2未暂存工作保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 增加同来源物理注解set/ref-list借用视图，保留真实起点、原始bytes、顺序与NULL槽；合成DEX原始字节逐项对照、有效孤儿空集合和额度1项见 artifacts/mdd-026/physical-annotation-collections-20261030/final/record.json，partial/重复为内部注入，额度不代表CPU/RSS。MDD-031 增加五个原生注解set/ref-list头、entry及参数列表关系，保留空容器、NULL和参数位置coverage；两项局部桥检查见 artifacts/mdd-031-audit/native-annotation-sets-20261030/final/record.json，计数与偏移对照原始字节但起点依赖既有解析器，owner/参数对照同一事实，未授予旧表或profile。MDD-030 类型化code_items保留发生次序身份、物理DEX、范围和头字段；同源完整代码布局不再误要求definitions，ReadCodeBytes显式依赖Structure+CodeLayout，相关红绿及3项局部检查见 artifacts/mdd-030/native-code-items-ir-20261030/；首次误认为code_item_id跨来源共享的失败保留，不推断运行时行为。MDD-005 Windows输入锁可供A1打开器作为持锁来源并委托inventory检查，未持锁时在发送请求前失败；8项合成检查及固定A1锁定合成副本7行4页对照见 artifacts/mdd-005/a2-pin-opener-20261030/final/record.json；快照和总序未证明，不授予A2资格。历史输入锁probe恢复原始blob，新增测试另存，run1记录反映当时源码。全量、跨平台、性能验证未运行；用户已有A2未暂存工作保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 新增所选scope内DEX出现到候选池序号和物理字符串池身份映射，同字节来源不合并；导出后1项对照已保存A0两组合成raw DEX，见 artifacts/mdd-026/scope-pool-coordinates-20261030/final/record.json；不证明APK、041或旧profile。MDD-030 类型化class_method_members输出同源类/方法定义、direct/virtual及ordinal，仅需完整definitions，双来源局部1项见 artifacts/mdd-030/class-method-members-ir-20261030/run1/record.json；期望来自同一事实，非独立oracle。MDD-031 native_string_pools 按DEX出现保留物理池身份，双来源与native_strings关联局部1项见 artifacts/mdd-031-audit/native-string-pools-20261030/run1/record.json，不授予旧数值池编号资格。MDD-005 生命周期正常关闭前后复核来源与共享期限，close_confirmed和source_confirmed分开；合成失效注入、既有9场景及固定A1锁定合成DEX七行四页见 artifacts/mdd-005/a2-lifecycle-source-20261030/final/record.json；source_confirmed仅是前后观察，同步哈希不能硬中断，未固定全部Job/环境依赖，不证明生产者快照或A2资格。未运行全量、跨平台、性能验证；已有A2未暂存工作保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 所选scope可受界关联输入、物理归档成员、逻辑DEX和metadata，保留原始成员名与来源出现；双来源多DEX合成APK、重建inventory、无DEX空归档额度等1项局部检查见 artifacts/mdd-026/scope-inventory-metadata-20261030/final3/record.json，不证明旧dex_files、041或全范围资格。MDD-030 typed dex_occurrences/string_pools 在仅metadata时保留逻辑出现与共享物理池，两执行路径按多重集合对照且低额度拒绝，见 artifacts/mdd-030/native-occurrence-pools-ir-20261030/final/record.json；MDD-031 新增原生注解目录、目录条目和类绑定，合成DEX原始字节对照目录头/条目/类绑定，见 artifacts/mdd-031-audit/native-annotation-directories-20261030/run1/record.json；起点仍依赖既有parser，均未授予旧表或profile。MDD-005 Windows输入锁对外提供构造时固定的SHA并检查底层路径/摘要重绑定；合成及固定A1锁定副本局部检查见 artifacts/mdd-005/a2-pin-source-identity-20261030/final/record.json，摘要真实性依赖原输入校验，generation/order为模拟，未授予A2资格。全量、跨平台、性能验证未运行；用户已有A2未暂存工作保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 新增既有scope承诺预像重构，核对输入次序、内容、成员序号、头偏移及两个hash；独立解帧和篡改/额度/跨snapshot/子范围1项见 artifacts/mdd-026/scope-commitment-preimage-20261030/final/record.json，帧解释仍需已验证inventory roster，非覆盖签名或独立DEX oracle。MDD-030 typed class_field_members 保留类/字段定义、static/instance和ordinal，双来源两执行路径及额度1项见 artifacts/mdd-030/class-field-members-ir-20261030/run1/record.json，同事实对照未授予旧表/profile。MDD-031 新增物理try/handler/typed-catch原生关系及组合路由，合成奇偶padding、catch-all、typed-only按原始字节对照，最终3项见 artifacts/mdd-031-audit/native-code-handlers-20261030/final/record.json；首次测试辅助代码编译失败保留，SQL记录早于最终scope额度补丁，不证明所有组合依赖。MDD-005 输入清单现在打开所选DEX ZIP成员以检查局部头与中央名称一致，合成坏签名/名称红绿和固定HostLab清单局部对照见 artifacts/mdd-005/a2-inventory-local-header-20261030/；不解压内容、不证明CRC或生产者快照。全量、跨平台、性能验证未运行，用户已有A2未暂存工作保留。

MDD-031 SQL桥仍进行中：受限虚表、会话预算绑定、U64真值、USING和子串路径有本机测试；独立真值18例及固定A0/A1子串16例通过，合成Q15结果与SQLite一致。真实完整corpus、legacy适配及生产工作区内存绑定尚未验收。检查点862b3dd的 Windows 离线测试161项、0失败/跳过，工作区严格Clippy通过，命令记录在 artifacts/integration/20261029/workspace-tests/ 与 workspace-clippy/。

后续 SQL 结果驻留预算修复在 Windows 工作区重新运行165项测试、0失败/跳过及严格Clippy；零行 schema 的零预算错误、结果持有与释放独立复现。该计量是保守逻辑额度，SQLite内部分配、provider/调用方副本、传输缓冲及租约自身元数据仍需单独准入，不能称 RSS 硬上限。证据 artifacts/mdd-031-audit/result-memory-probe/after-fix.json、artifacts/integration/20261029/workspace-tests-result-budget/record.json。

SQL 附加对照：真实合成DEX和无损参数两条路径覆盖空字符串、NUL、普通字符、孤立代理项与补充字符；固定A0/A1各7行 CAST TEXT 的 HEX 与原始MUTF-8一致，普通显示对孤立代理项有替换，与原始字节分开。冻结Q10聚合在合成provider上与SQLite对照，并验证缺事实及源变化真实错误。证据 artifacts/mdd-031/text-projection-20261029/runs/20261028T170439632106Z/readback.json、artifacts/mdd-031-audit/q10-aggregation-audit/qualification.json；不代表完整查询集资格。

SQL 比较路径已修复派生表同名遮蔽造成的 IN/NOT IN 静默错行，并支持可证明直接基础表 JOIN 的列作用域；Q03 合成provider与独立SQLite的重复行/别名反例通过，A0/A1固定小DEX另实际返回完整零行。未证明的亲和性返回明确未实现；旧版文本算术与部分文本转整数仍不兼容。该版 Windows 工作区168项测试及严格Clippy通过，见 artifacts/integration/20261029/workspace-tests-join-scope/record.json；本版Linux CI需对应提交后验证。

后续文本/bytes→INTEGER 转换在固定A0/A1的54项小样本上数值一致，但30项有 signed/unsigned DTO 类型差异，完整兼容仍受阻；Windows工作区170项测试和严格Clippy通过，见 artifacts/mdd-031/integer-cast-20261029/runs/20261028T174502714475Z/readback.json。Q04非零注解查询与A0/A1/SQLite的数值和顺序对照通过，但候选类型标签与旧wire不同，未签传输或profile资格。

LIKE模式预处理与尾部扫描现按单元计步并检查取消，token逻辑容量在分配前预留并在成功、配额失败和取消后释放。最终源码的Windows工作区176项测试、严格Clippy通过；独立真实会话实测低额度QUOTA、结果释放归零，以及观察到token预留后请求取消最终CANCELLED并归零，证据 artifacts/mdd-031-audit/like-workspace-independent-20261029/readback/record.json。该额度不覆盖SQLite、参数缓冲、allocator额外容量、RSS或传输；取消到达的具体内部指令不可观测。此历史检查点的尾部ESCAPE为INVALID_ARGUMENT；后续A0/A1及修复证据见下。

ORDER BY投影别名遮蔽输入列的静默错行已修复，含括号、位置编号、wildcard和NULL等限定反例；同一合成DEX的排序从10/9/8纠正为SQLite的-2/-1/0。独立桥探针72项覆盖排序、NULL、聚合及注入错误终态；SQLite限定对照通过，但已有A0 NULL结果的DTO包装仍不同，其他旧版方言未重新采样。Windows工作区177项测试和严格Clippy通过；见 artifacts/mdd-031-audit/null-aggregate-independent-20261029/qualification.json。

GROUP BY括号位置被误认常量的错分组已修复：同一13行样本从(0,13)改为SQLite的(0,7)/(1,6)；涵盖嵌套括号、符号、超32位位置范围常量、NULL/HAVING和真实绑定错误。最终源码Windows工作区179项测试、严格Clippy通过，独立桥90项含78项SQLite对照；未重启A0/A1，注入的源变化不等于真实磁盘变化。证据 artifacts/mdd-031-audit/group-ordinal-boundary-20261029/qualification.json。

多参数 min/max 已与单参数聚合分开，Windows工作区181项测试和严格Clippy通过。独立合成provider三方言69例中，45项默认BINARY结果与SQLite一致，6项零参数返回真实INVALID_ARGUMENT，18项显式COLLATE保持UNSUPPORTED_QUERY；provider尚无逐列collation元数据，不称NOCASE schema等价。未重启A0/A1，DTO/profile仍未准入。证据 artifacts/mdd-031-audit/multi-minmax-independent-20261029/qualification.json。

Q08使用的lower及对应upper现逐UTF-16单元计步骤并检查取消，真实会话长参数低额度反例由成功变为QUOTA；Windows工作区184项测试与严格Clippy通过。独立三方言60例涵盖SQLite可表示文本、孤立代理、长结果、配额和取消，证据 artifacts/mdd-031-audit/case-budget-independent-20261029/qualification.json。旧A0/A1对应完整语义未找到可比较记录，仍为not_run；参数复制、SQLite及传输内存不在该计步证明内。

Q15拼接路径对实际UTF-16或bytes复制计步骤，低额度真实红绿与隔离快照48项会话验证通过。SQLite对bytes拼接的HEX与候选相同但类型为TEXT而候选为Bytes，A0/A1该类型未采样，不能签DTO等价。参数解码、部分转换、结果载体、SQLite及RSS不在本轮计步范围。证据 artifacts/mdd-031-audit/concat-independent-20261029/verify-run/record.json。

`substr` 文本偏移表在分配前按 UTF-16 单元数量预留逻辑工作区并逐单元计步，配额失败和取消后释放；Windows工作区189项测试、严格Clippy通过，独立真实会话36例及固定A0/A1各5个已有参考对照通过，见 artifacts/mdd-031-audit/substring-independent-20261029/verify-run/record.json。SQLite截取含NUL文本返回空串，旧版与候选旧方言保留NUL及后续字符；Native按UTF-16单元、旧方言按有效代理对截取。旧版NULL DTO仍不同，参数/结果副本、SQLite、分配器实际容量、RSS和传输未由此额度覆盖；旧版其余3项已有样本未在该轮比较。

旧方言 `length` 对UTF-16的实际扫描现逐单元计步并检查取消；Native直接长度仍为常数时间。冻结源码的Windows工作区193项测试和严格Clippy通过，独立真实会话33例回读见 artifacts/mdd-031-audit/length-independent-20261029/verify-run/record.json。既有A0对补充字符和含NUL样本分别为1和3，SQLite为1和1，Native对补充字符按两个UTF-16单元计数；A1参考本轮未运行。额度仅为逻辑步骤，不覆盖参数副本、SQLite内存、分配器、RSS或传输。

HEX的字节输出和共享文本转字节扫描现计步骤并检查取消；独立真实会话45例保留 SQLite UTF-8 与 A0/A1 已存 MUTF-8 的不同字节，见 artifacts/mdd-031-audit/hex-independent-final-20261029/verify-run/record.json。前次因源码漂移导致独立回读失败的记录保留；参数和输出缓冲、SQLite、分配器及RSS/传输未由此计步覆盖。

Q09的NOT BETWEEN因生成SQL缺少括号而静默漏行，现使用显式嵌套修复；同一合成provider由空行恢复为SQLite的9、12。独立三方言27例中21项与SQLite一致、6项混合类型亲和性明确未支持，见 artifacts/mdd-031-audit/between-independent-20261029/after-readback/record.json；未重新运行A0/A1。最终源码Windows工作区200项测试、严格Clippy通过，完整SQL profile仍未准入。

DISTINCT/GROUP/ORDER文本或字节键构造现逐单元计步骤并检查取消，四个真实低步骤红例由错误完整成功改为QUOTA。冻结源码Windows工作区206项测试、严格Clippy通过；独立合成provider的三方言9个长键请求均返回QUOTA，见 artifacts/mdd-031-audit/hostlab-case-hex-independent-20261029/verify-run/record.json。键Vec、SQLite TRANSIENT及排序器副本、输入和RSS尚未受该步骤计量约束。

后续键Vec和带类型标记的Rust载体在分配前按检查过的上界预留逻辑工作区，租约持续至rusqlite设置结果调用返回；隔离快照48项真实会话、实际ToSql回调和低额度/取消释放独立验证，见 artifacts/mdd-031-audit/key-lease-independent-20261029/verify-run/record.json。SQLite TRANSIENT副本及排序器后续内存、参数/输入复制、分配器额外开销与RSS仍未覆盖。

固定HostLab CASE/HEX包装的合成对照发现：对旧方言输出的MUTF-8 NUL、代理对及孤立代理字节，现有CLI严格UTF-8解码步骤会抛UnicodeDecodeError；只直接复现了解码步骤，未运行完整HostLab。该适配边界、旧版NULL DTO和signed/unsigned差异仍阻断完整兼容。

旧版 NULL 单元包含 `value: null`，当前原生 SQL 单元仅含 `type: null`，固定 HostLab 消费者会读取 `value`；适配层必须明确补齐并验证。字面 CAST 的非负结果与DEX列 CAST 的类型不同，不能仅按数值正负推断旧类型。扩展旧版类型采样两次在打开样本时超时，未执行查询；错误保留于 artifacts/mdd-031-audit/dto-type-observations/，不能由此推断规则。

检查点862b3dd的 Windows 和 Linux CI 均通过，各161项测试、10条构建/检查/Clippy/探针命令原始记录已核验；有限 Linux ASan/fuzz workflow 通过，但本次执行次数尚未回读。见 artifacts/integration/20261029/ci-862b3dd.json。后续源码修改须另行验证，不能继承此检查点的CI结论。

2026-11-01 本轮修正后暂停：MDD-022 同来源物理 encoded array 借用视图提供原始字节和值节点，孤儿空/非空及调用点数组定向1项通过；嵌套和真实共享未独立验证，MDD-022 仍 in_progress，MDD-026 依赖未满足。MDD-034 队列接收端关闭时，载荷在锁外释放以避免重入死锁，已关闭接收端释放最后 sender 不再误记 WorkerLost；两项关闭测试与一项生产者丢失回归通过，红例保留，完整并发与生产 IPC 未验证。MDD-031 旧方言简单 CASE 对已证明数值列采用既有精确文本亲和性，三项 SQLite 对照/回归通过；修前红例仅在会话观察，未持久化原始输出，不签 A0/A1、HostLab 或 profile 资格。运行命令、证据、事后源码摘要及脱敏前摘要见 artifacts/integration/20261101-round-correction/record.json；未运行全量、跨平台或性能验证，用户既有 A2 修改保留。

2026-11-01 恢复功能推进：MDD-022 增加物理 encoded array 的同来源类定义与调用点反向绑定；合成 DEX 两个类共享同一空数组、孤儿及调用点等定向1项通过，多个调用点共享与静态值类型仍未验收，MDD-022 保持 in_progress，MDD-026 依赖未满足。MDD-034 修复最后 sender 退出时以 WorkerLost 遮盖已有首错，红例和最终首错1项、关闭/真实丢失回归3项见 artifacts/mdd-034-audit/sender-drop-first-fault-20261101/；初次绿例源码漂移已排除，生产 IPC 和穷举并发未证。MDD-031 对可精确转换为整数的直接 LIMIT/OFFSET 文本、浮点及无符号值进行限定转换，SQLite红例和两项局部检查见 artifacts/mdd-031-audit/limit-carrier-20261101/，计算表达式与极端文本及 HostLab/A0/A1 未验收。MDD-005 关闭数据集回执解码和最终空闲校验后检查共享期限；受控红绿及9项生命周期合成检查见 artifacts/mdd-005/a2-close-decode-deadline-20261101/，同步解码不可硬中断，未授予 A2 或性能资格。全量、跨平台和正式性能测试未执行；用户已有 A2 未暂存工作保留。

2026-11-01 依赖满足的功能继续推进：MDD-022 增加受 snapshot/DEX 出现/物理数组起点/节点 ID 约束的单节点视图，合成嵌套 array→NULL 字节及父子节点定向1项通过；嵌套 annotation、其他物理数组节点及共享调用点未覆盖，MDD-022 保持 in_progress、MDD-026 依赖未满足，见 artifacts/mdd-022/nested-array-direct-20261101/。MDD-034 接收端关闭后 finish 保留查询首错，实际红例及首错1项和关闭回归2项通过，穷举并发和生产 IPC 未验收，见 artifacts/mdd-034-audit/finish-after-close-first-fault-20261101/。MDD-031 无 FROM 内层对明确限定的外层列可解析 IN 类型，SQLite 定向1项和已有回归1项通过；红例期间事实源码漂移、仅作观察，不签 HostLab/A0/A1/profile，见 artifacts/mdd-031-audit/qualified-correlated-empty-scope-20261101/。MDD-005 修复阻塞中止回调超时仍确认的问题，3项合成检查及9项生命周期回归通过；阻塞不可硬中断，非真实进程或 A2 资格，见 artifacts/mdd-005/a2-abort-deadline-20261101/。全量、跨平台、正式性能验证未执行，用户已有 A2 未暂存工作保留。

2026-11-01 持续推进：MDD-022 用合成物理 DEX 检查嵌套 annotation→array→NULL/true 的原始字节、节点关系及双数组身份，定向1项通过；仅增加测试，无生产逻辑变更，共享调用点、ART和完整资格未覆盖，MDD-022 仍 in_progress，MDD-026 依赖未满足，见 artifacts/mdd-022/nested-annotation-array-20261101/。MDD-034 修复回执拒绝时已有配额或 worker 错误被 InvalidArgument 遮盖，红例、首错1项及回归5项见 artifacts/mdd-034-audit/receipt-prior-failure-20261101/，未证明穷举并发或生产 IPC。MDD-031 Q06 实际查询形状以通用合成值在三方言对照 SQLite，1项通过，只有测试代码变化，未验证真实 HostLab、A0/A1 或宽 Unicode 语义，见 artifacts/mdd-031-audit/hostlab-q06-filter-20261101/run2/。MDD-005 同步消费在行处理和回执登记前复核期限，超时不能继续交付或登记零行完成；两项合成反例与四项已有回归通过，非生产者、快照、A2或性能资格，见 artifacts/mdd-005/a2-sync-consumer-deadline-20261101/。全量、跨平台和正式性能验证未执行，用户已有 A2 未暂存工作保留。

2026-11-01 继续推进：MDD-022 增加同来源 call_site_id 到物理编码数组直接视图，合成 DEX 两个真实调用点共享一数组，逐字节核验指针和三项前缀及反向重复，最终定向1项通过；不推断 bootstrap 或 ART，完整重验延后、MDD-022 保持 in_progress，MDD-026 依赖未满足，见 artifacts/mdd-022/shared-callsite-view-20261101/final/record.json。MDD-034 受控反例中两份独立批次可复用同一驻留预算或通过共享注册表重新获取，导致低估；现要求生产批次使用独占非共享预约，红例2项、最终3项和 JSON/保留克隆3项回归通过；现有 JSON 生产者原本使用独立预约，不声称生产已触发，未证明 IPC/RSS或全部并发，见 artifacts/mdd-034-audit/producer-reservation-alias-20261101/summary.json。MDD-031 修复无 GROUP BY/HAVING 的直接 DISTINCT COUNT 被错误改写为聚合分组；SQLite 红绿及2项回归通过，窗口函数仍不支持，非完整 HostLab/A0/A1资格，见 artifacts/mdd-031-audit/ungrouped-distinct-count-20261101/。MDD-005 compact 终页校验和逐单元解码超时不再返回完整结果，2项受控反例及2项终态回归通过，同步解析不可硬中断、逐单元检查增加的开销需未来实测；不证明生产者快照或 A2 资格，见 artifacts/mdd-005/a2-final-page-deadline-20261101/。全量、跨平台和正式性能验证未执行；用户已有 A2 未暂存工作保留。

2026-11-01 持续推进：MDD-034 普通行生产路径的两个受控红例发现独立行可克隆或重获共享预约而少计驻留额度，现仅生产者行要求独占非共享预约，2项红绿与2项回归通过；现有 executor 本来按行新申请，不声称真实生产已触发，未证明 IPC/完整并发/RSS，见 artifacts/mdd-034-audit/produced-row-reservation-20261101/summary.json。MDD-005 compact 查询等待锁受共享期限约束；1项反例及4项终页/终态回归通过；中间变更遮盖既有 poisoned 错误造成失败，已修复并保留记录，不证明真实并发生产者或 A2资格，见 artifacts/mdd-005/a2-query-lock-deadline-20261101/record.json。MDD-031 支持无分组同层聚合表达式 DISTINCT/HAVING，相关聚合归属未知时先核原 SQL 并显式拒绝，聚合误用及非聚合 HAVING 保留真实错误；独立复核发现 ORDER BY 错误被改写为结果与额度遗漏，均加受界检查，整句共享逻辑扫描额度覆盖表与schema列；保护曾错误拒绝无关 UNION，隔离 HEAD 对照确认回退后恢复。最终8项局部检查通过，历史失败含测试代码编译错误均保留；相关聚合未完整支持，投影克隆/字符串/SQLite/RSS不在额度证明内，见 artifacts/mdd-031-audit/ungrouped-distinct-aggregate-20261101/。MDD-022 仅只读复核，完整重验延后、任务仍 in_progress、MDD-026 依赖未满足；全量、跨平台、真实 HostLab 和性能验证未执行，用户已有 A2 未暂存工作保留。

2026-11-01 持续推进：MDD-022 修复 Signature 展开遗漏 owner definition 来源身份成本，使用受检计数和加乘；预算差1红绿、精确边界及共享 Signature 回归各1项，见 artifacts/mdd-022/signature-identity-budget-20261101/；额度为逻辑成本，不证明 RSS/ART，全量重验延后，任务仍 in_progress、MDD-026 依赖未满足。MDD-031 聚合 FILTER 条件现复用现有真值转换；文本条件旧桥0与SQLite 5的红例、最终文本/U64/F64及聚合回归共3项见 artifacts/mdd-031-audit/aggregate-filter-truth-20261101/；NaN/无穷、真实 HostLab/A0/A1和完整 profile 未验收。MDD-005 增加完整物化有序行及 bag 差异定位，保留重复并校验两侧操作；6项合成检查和19项合同自检通过，见 artifacts/mdd-005/row-difference-20261101/；该诊断不认证实际分页消费、不验证单元格类型或来源，coverage 层顺序可能产生误差，不授予审计/性能资格。MDD-034 本轮仅只读复核，未发现有证据的新缺口。未运行全量、跨平台或性能测试，用户已有 A2 未暂存工作保留。

2026-11-01 持续推进：MDD-022 Signature owner 定义查找先一次校验类和成员段的种类/顺序/归属，再在类内字段和方法各自两段二分；1项真实合成多成员检查与6项 Signature 定向回归通过（含新增项），无定义、交错索引和异常布局为注入，首次布局扫描不受 decoded-byte 额度限制，未测性能/RSS/ART，MDD-022 保持 in_progress、MDD-026 依赖未满足，见 artifacts/mdd-022/signature-owner-layout-20261101/。MDD-034 批次回执 confirm 的计数/身份或信封拒绝保留已登记首错，无首错保持可重试；红绿各1项、重试回归1项，关键测试在最终组合源码重跑1项，非生产 IPC/穷举并发资格，见 artifacts/mdd-034-audit/owned-receipt-confirm-first-20261101/。MDD-031 针对可证明 length 左值与 i64/NULL 字面上下界保留 SQLite 原生 BETWEEN，避免重复计算并保留短路/参数顺序；最终9项局部检查通过，i64极值、三方言、NULL、配额和深度均覆盖。原文本 LOWER 红例仍未解决；数字首轮红例有源码漂移，另一冻结红例保留，首次绿例和中间键方案保留，非完整 SQL/HostLab资格，见 artifacts/mdd-031-audit/between-single-evaluation-20261101/summary.json。MDD-005 行差异诊断可按调用方指定唯一列 ID 返回左右来源列值及可辨差异列 ID；3项合成检查和6项回归通过，来源值未认证、bag排序位置不证明实体配对，非性能资格，见 artifacts/mdd-005/row-difference-provenance-20261101/record.json。未运行全量、跨平台、真实 HostLab或性能验证，用户已有 A2 未暂存工作保留。

2026-11-01 继续推进：MDD-005 已物化行差异比较将 required_layers 按现有唯一集合语义规范化，保留原 v1 摘要并另标识比较摘要；真实合成顺序反例、最终4项和既有9项差异回归通过，比较可增加重新摘要成本，未认证分页/类型/来源或性能资格，见 artifacts/mdd-005/required-layer-order-20261101/record.json。MDD-034 修复发送首次检查后等待队列锁期间取消仍可入队：取得锁后重新检查；红例1项、最终发送交错2项及5项回归通过，检查后与入队间仍可能并发取消，不证明全部并发原子性或生产 IPC，见 artifacts/mdd-034-audit/send-cancel-before-lock-20261101/summary.json。MDD-031 独立链接 SQLite 3.53.2 受控6项观察确认 SELECT 与直接 WHERE 的 BETWEEN 上界求值不同，禁止用急切三参数函数冒充等价；LOWER 等复杂左值重复求值仍未修复，未改 SQL 生产代码，不授予 profile，见 artifacts/mdd-031-audit/between-context-oracle-20261101/record.json。MDD-022 本轮只读复核，完整重验延后、任务仍 in_progress 且 MDD-026 依赖未满足；未运行全量、跨平台、真实 HostLab或性能验证，用户已有 A2 未暂存工作保留。

2026-11-01 持续推进：MDD-034 受控反例证明最后 checkpoint 之后取消仍可入队，另有额度错误被载荷析构取消遮盖；现由 session 固定单项 VecDeque 发布操作与取消共用生命周期锁，不暴露长期锁守卫或任意回调，失败回滚计数、解锁后先记首错再析构。最终13项局部检查通过并经独立锁序复核；其中一次有期限等待只观察受控调度，deadline为瞬时准入检查，不证明全部并发、生产 IPC或RSS，见 artifacts/mdd-034-audit/atomic-cancel-publication-20261101/summary.json。MDD-005 比较器可选按外部可信 schema、snapshot 和 occurrence 检验 native QueryIR 类型化行，覆盖 NULL、整数范围、UTF-16 单元、规范 base64 与实体身份，逻辑行/单元格/变长字节额度在排序与摘要前生效；最终6项及既有32项相关检查通过，首轮夹具漏列 dex-B 被正确拒绝并保留，见 artifacts/mdd-005/native-typed-rows-20261101/record.json；来源清单真实性、实体实际存在、页面消费、JSON解析和RSS仍未证明。MDD-031 固定 SQLite 3.53.2 物化左值候选在5个合成情形匹配，但真实聚合作用域反例使原生1行变候选3行；未修改 SQL 生产实现，LOWER 等复杂左值单次求值仍未解决，见 artifacts/mdd-031-audit/between-materialized-oracle-20261101/。MDD-022 本轮只读复核，完整重验延后、任务仍 in_progress、MDD-026 依赖未满足；全量、跨平台、真实 HostLab与正式性能验证未执行，用户已有 A2 未暂存工作保留。

2026-11-01 持续推进：MDD-034 受控红例确认 finish 检查后、成功终态发布前完成取消仍返回 Ok；现用无回调的固定空槽发布与取消共用生命周期锁，owned producer 失败路径仍显式发送原首错。公开/producer交错各1项、session空槽1项、终态组19项（含新增两项）与队列组4项通过，不重复相加；未证明全部并发、生产 IPC/RSS 或 deadline 全程原子，见 artifacts/mdd-034-audit/terminal-cancel-atomic-20261101/summary.json。MDD-031 文本真值转换借用 UTF-16 载体，精确长度预扫描和输出均计步/检查取消，按实际输出申请并保持临时预约至 ToSql；空输出无零额预约。11项定向通过，首次10000额度失败及测试编译失败保留；测试中另有4096并存逻辑额度来源未单独验证，同步UTF-8验证不可硬中断，SQLite/输入/分配器/RSS及实际 HostLab 未证，见 artifacts/mdd-031-audit/truth-text-budget-20261101/summary.json。MDD-005 原生类型化结果可选独立可信实体名册，按 occurrence、引用/定义种类、索引核对；tuple 先逐项检查再建集合并拒绝重复，3项及31项回归通过，来源名单真实性、occurrence大小、页消费、完整事实及性能资格仍待独立证明，见 artifacts/mdd-005/native-entity-roster-20261101/record.json。MDD-022 仅只读复核未发现可证新缺口，完整重验延后、任务仍 in_progress、MDD-026 依赖未满足；复杂左值 BETWEEN 未解决；全量、跨平台、真实 HostLab和正式性能验证未执行，用户已有 A2 未暂存工作保留。

2026-11-01 持续推进：MDD-005 增加选定 APK DEX 物理成员完整读取/CRC/长度/SHA-256 记录，保留 central ordinal 和重复内容出现，并拒绝 Python 规范化的 NUL 名称；5项合成检查在普通及 -O 模式通过，前后哈希不证明中间代次不可变，ZIP64/descriptor、逻辑 DEX、生产者快照及 RSS 未验收，读取成本须未来完整测量，见 artifacts/mdd-005/a2-physical-member-digest-20261101/record.json。MDD-031 七个亲和性预判的外层括号改用迭代；128 KiB 小栈处理5000层合成 AST 的独立红例 STATUS_STACK_OVERFLOW，修后单项及 affinity 筛选14项（含新增项）通过；不证明普通 SQL 可自然触发或 parser/其他路径栈安全，复杂左值 BETWEEN 仍未解决，见 artifacts/mdd-031-audit/affinity-deep-parentheses-20261101/summary.json。MDD-034 只读核查记录低层调用方可构造同 owner 的期限 witness，公开接口不认证其来自预算树；正式队列从已校验 RuntimeBudget 取期限，生命周期期限/首错/回执仍独立生效，未运行反例或证明审计绕过，非不可信 SDK 安全资格，见 artifacts/mdd-034-audit/budget-witness-trust-20261101/review.json。MDD-022 只读复核无可证新缺口，完整重验延后、任务仍 in_progress、MDD-026 依赖未满足；未运行全量、跨平台、真实 HostLab或性能验证，用户已有 A2 未暂存工作保留。

2026-11-01 继续推进：MDD-005 可将一次复制固定的生产者 dex_files 行关联至完整读取并校验 CRC 的 APK 物理成员摘要，保留 file ID、原始 entry_name、行次序与成员出现，不按相同内容去重；3项合成检查及5项既有摘要回归通过。仅按固定 HostLab 后缀规则关联，未认证生产者真实输入、快照、逻辑 DEX 数量/偏移或性能，见 artifacts/mdd-005/a2-observed-member-binding-20261101/record.json。MDD-031 修复空 LIKE token 仍申请零字节预约而在 live 预约满时误报 QUOTA；真实预算对象受控红绿1项、额度/LIKE/Q06回归4项通过，非实际生产触发或 HostLab 资格，见 artifacts/mdd-031-audit/like-empty-reservation-20261101/summary.json。MDD-034 只读复核发现预约元数据上限可能通过释放恢复，现有契约不足以认定等待为错误，未修改；MDD-022 仅只读复核，完整重验延后，MDD-026 依赖未满足。复杂左值 BETWEEN 仍未解决，未运行全量、跨平台、真实 HostLab 或性能验证；用户已有 A2 未暂存工作保留。

2026-11-01 继续推进：MDD-005 观察到的文件行使用独立 max_observed_rows 额度，复制前后均检查，不与 ZIP 物理成员/解压额度混同；4项合成检查在普通及 -O 模式通过，5项成员摘要回归通过；并发修改可在复制前后检查间产生临时分配，不证明 RSS/生产者快照，见 artifacts/mdd-005/a2-observed-row-budget-20261101/record.json。上轮证据脚本/记录已恢复提交时原字节，本轮早期输出另保留。MDD-022 Signature 元素名直接比较捕获的 UTF-16 单元，避免展开时重复分配 UTF-8；最终1项及7项 signature 过滤回归通过（含新增项），首次孤立代理错误归属假设失败并保留，parser 先报 ANNOTATION_NAME_NON_SCALAR；未证明性能/RSS/ART或完整资格，见 artifacts/mdd-022/signature-name-units-20261101/。MDD-031 实际差分发现 I64/F64 逻辑相等值在 UNION/INTERSECT/EXCEPT 静默错行；现仅对可证同载体或物理标签互斥类执行去重，其余经原 SQL 绑定/参数复核明确 Unsupported，未实现完整集合等价。复合 ORDER 另修原始表达式/分支别名/单表 wildcard 绑定与大小写，最终13项及5项相关回归通过；首分支 wildcard ORDER、legacy补充平面顺序/DQS、复杂 BETWEEN 仍未准入，见 artifacts/mdd-031-audit/compound-numeric-carriers-20261101/summary.json。MDD-034 两条 generic scan 用真实捕获 DEX 的合成不一致自定义 provider 返回未知 occurrence 却成功，实际红例与复现补丁保留；未直接逐行调用可能二次复杂度且不受 Control 约束的 provider 验证，需要有预算实体索引或封闭可信边界；未证明 ScopedCatalog/真实 HostLab 受影响，见 artifacts/mdd-034-audit/scanned-entity-scope-20261101/summary.json。MDD-022完整重验延后、MDD-026依赖未满足；未运行全量、跨平台、真实 HostLab或性能验证，用户已有 A2 未暂存工作保留。

2026-11-01 持续推进：MDD-005 文件行名称增加独立 UTF-8 总字节额度和分段编码，拒绝伪造长度的 str 子类；Windows pin 前置检查 source 是否接受该额度，source 自身 TypeError 保留。5项合成检查在普通/-O 通过，行数/真实 Windows pin 共6项回归通过；既有字典/名称内存、并发复制、生产者快照、RSS和性能未证，见 artifacts/mdd-005/observed-name-budget-20261101/record.json。MDD-022 Signature 展开复用已验证严格物理顺序的 set/item 起点二分，避免重复 BTreeMap 并使用 try_reserve；单项1及 signature_ 筛选8项通过（含该单项），共享/空/孤儿覆盖，未注入实际分配失败，不证明 parser/RSS/ART/完整资格，见 artifacts/mdd-022/signature-physical-lookup-20261101/。MDD-031 标量 UDF 的变长参数在复制前进行载体检查、工作计量与逻辑 workspace 预约，MUTF8 维持逐参数首错；中间空 LIKE/length 回归失败经有界借用路径修正，保留旧阈值与失败。最终相关筛选通过，UDF 6项在最终组合源码上重跑通过；AggregateValue::step/累积态、SQLite/输出/allocator/RSS、完整 HostLab 和复杂 BETWEEN 未覆盖，见 artifacts/mdd-031-audit/udf-input-materialization-20261101/。MDD-034 从已验证 ScopedCatalog 建实体键索引并提供独立受界严格执行入口，验证 occurrence/kind/index、runtime 绑定和 iterator EOF/提前析构身份与首错；多个真实受控红例及定向测试保留，严格入口不认证 provider 内容/代码字节/覆盖，独立检查额度不自动计入 QuerySteps/QueryWorkBytes，也不约束 provider 回调；旧 generic 执行的来源缺口仍未修复，不得关闭任务，见 artifacts/mdd-034-audit/scoped-entity-authority-20261101/ROUND_REPORT.md。MDD-022完整重验延后、MDD-026依赖未满足；未运行全量、跨平台、真实 HostLab或性能验证，用户已有 A2 未暂存工作保留。

MDD-005 Windows read-sharing pin 现可在持锁期间转发物理成员摘要及观察行关联；自有合成 APK 的真实持锁、新写句柄拒绝与未持锁调用拒绝在最终源码上2项通过，见 artifacts/mdd-005/pinned-member-binding-20261101/record.json。既有可写映射、特权更改及 producer 捕获同代次未证明。
