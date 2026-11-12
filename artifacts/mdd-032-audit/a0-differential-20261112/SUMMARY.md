# 第四轮对抗审查：17 关系对 A0 的独立差分

- 日期：2026-11-12（Asia/Shanghai）
- 范围：补跑第四轮 Step-Reviewer。**由主代理内联执行，没有使用子代理。** 方向：MDD-032 关系注册、5 列收口、coverage 兜底门、MDD-033 catalog/cursors。
- 性质：审查与回归防护记录。**不**宣称 HostLab 等价、profile 准入或 MDD-032/MDD-026 完成。

## 方法

`generate.py` 只用冻结 A0（`dexsql 0.1.0`，sha256 `f354ebcf…c448`）对 `tests/fixtures` 下全部 185 个 `.dex`/`.apk` 各取 17 个关系的全列结果，共 3,145 条记录（A0 作答 2,703，拒绝 442）。每个单元格编码为 `typeof(c)||':'||hex(c)`（NULL 为 `N`），使 NULL、空串、文本 `NULL` 不混淆。`a0-corpus.json` 不含本引擎的任何输出。

引擎侧由新增测试 `a0_differential_over_the_fixture_corpus_has_only_declared_divergences`（`crates/mdd-sql/src/provider/hostlab/tests.rs`）读取该语料，对同一输入用生产分层（metadata 必需，其余层缺失则该层关系失败）执行 `SELECT <列> FROM <关系>`，按相同编码比较行多重集。`bridge` 的 AST 适配器尚未实现 `typeof`（以及 `replace`），所以编码在 Rust 侧做；`value_f64` 只比存储类别，位型比较仍在原 `every_relation_matches_the_recorded_a0_readback_row_for_row`。

## 结果

| 类别 | 记录数 | 判定 |
|---|---|---|
| 两边都作答且逐行相等 | 2,097 | 一致（含 `dex_files` 28 列、`methods` 的 `param_descriptors`/`opcode_count`/`opcode_hex`） |
| A0 作答、本引擎显式拒绝 | 603 | fail-closed，不是空成功（见下） |
| 两边都作答但有差异 | 3 | 已声明的分歧（见下） |
| A0 拒绝、本引擎作答 | 2 | `class_methods` 不依赖 A0 所拒绝的 code item |
| 两边都拒绝 | 440 | 一致 |

2,097 + 3 + 603 = 2,703 = A0 作答总数。

**真实 APK**：NewPipe 0.28.6（sha256 `e56ef628…6be58`）上 17 个关系的 `count(*)` 与 A0 逐关系全等（`newpipe-counts-engine.txt` / `newpipe-counts-a0.txt`；引擎侧计数由一个临时测试产生，该测试已删除，A0 侧为同一命令行）。

### 已声明的 3 个分歧（`ANSWERED_DIVERGENCES`）

**非 BMP 字符（3 条，`unicode-parameters-038.dex` 的 `strings`/`types`/`methods`）**：MUTF-8 把补充字符存成两个 3 字节代理；本引擎还原成标量值，A0 把每个字节替换为 U+FFFD。本引擎的输出是正确的，属 A0 的有损投影；需要在兼容台账登记为"拒绝复制 A0 的有损行为"。

### 已关闭：孤立注解项（审查首轮发现 14 个分歧中的 11 个）

首轮差分发现：夹具含合法但无人引用的 annotation set / annotation / encoded value 时（7 个夹具，已用 A0 的 `annotation_sets`、`annotation_set_refs` 表确认这些项未被任何 set 或 ref list 引用），`annotation_set_entries`、`annotations`、`annotation_elements` 比 A0 多行。原因是本引擎按物理 map 枚举全部合法项，A0 只枚举可从类注解目录到达的项。

**裁决（用户，2026-11-12）：SQL 关系只投影可达项，事实层保留孤立项。** 实现：`AnnotationFacts` 新增 `reachable_set_entry_rows`/`reachable_annotation_rows`/`reachable_element_rows`（可达 = 类绑定目录的 class 注解集、field/method 目录项的注解集、parameter 目录项经 ref list 指向的注解集，及这些集合包含的注解项与其元素）；物理的 `set_entry_rows`/`annotation_rows`/`element_rows` 不变，仍对独立 oracle 比对。`mdd-sql` 的 hostlab 提供者改用 `reachable_*`。

验证：11 条记录全部变为与 A0 逐值相等（无需改 A0 语料）；NewPipe 0.28.6 上四个注解关系行数仍与 A0 全等；对可达性算法的三处变异（忽略 class 注解集、忽略 parameter ref list、忽略 field/method 注解集）均被差分测试与新增的事实层测试 `unreferenced_items_stay_facts_but_are_not_reachable` 同时杀死。

### 603 个显式拒绝的构成

缺失层（`annotation/reference/definition/code-layout facts are not attached`）、合法非标量字符串无法放入纯 UTF-8 列（`strings`/`classes`/`method_strings`）、以及结构非法输入（`metadata:`/`inventory:`）。其中大部分夹具本来就是故意构造的非法 DEX（`definitions/generated/*` 等），A0 对其宽松而本引擎严格。测试只允许这几类消息；出现其他拒绝原因即失败。

## 对其余三个方向的审查

- **5 列收口（provenance、`param_descriptors`、`opcode_*`）**：由上述差分直接覆盖，185 个夹具上与 A0 逐值相等；`source_path` 与 A0 的差异只是路径拼写（A0 原样回显命令行参数），测试改为核对它等于传给捕获的路径。**未发现缺陷。** `entry_name` 对裸 DEX 取叶子名与 A0 一致（`definitions-035.dex`）。
- **coverage 兜底门**：对 `frozen_provider_gate` 做三处变异。两处（把 `class_fields` 换成 annotations 提供者、把 `annotation_elements` 换成 definitions 提供者）被现有测试杀死；第三处（把 `_ => None` 改成 `_ => Some(Some(Ok(())))`，即未映射关系默认 Complete）**存活**，145 个测试全绿。已新增测试 `unmapped_relation_is_never_gated_to_complete` 并复跑该变异，现被杀死。当前 156 列都有映射，所以该分支对现有规格不可达，这是防御性分支缺测试，不是现有行为错误。
- **MDD-033 catalog/cursors**：只精读了 `cursors.rs` 的 `open_cursor_with_spec`、`cursor_binding`、`validate_page_continuation`、`open_compat_offset` 和 `lib.rs` 中 catalog epoch 与 cursor 校验的交互。epoch 绑定在 query 创建时（`prepare_query` 取 `entry.temp.epoch()`），旧 query 的游标不会迁移到新 TEMP 定义，新 query 拒绝旧游标，与验收 2 一致；**未发现缺陷。** 这不是完整审查：`catalog.rs`（1,079 行）未读，`cursors.rs` 约 1,524 行只读了约四分之一。

## 复现

```text
python generate.py <A0 exe> <repo root> a0-corpus.json
cargo test --offline -p mdd-sql --lib a0_differential_over_the_fixture_corpus
```

测试固定了 `EXPECTED_EQUAL_RECORDS = 2097` 与 `EXPECTED_BOTH_FAIL_RECORDS = 440`：任何一边变得更宽松或更严格都会使测试失败，需要显式更新并说明原因。对 `set_entry_rows` 的序号加 1 的变异已被该测试杀死。
