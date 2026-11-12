# MDD-032-A：HostLab 十七契约关系的真实 SQL 注册

- 日期：2026-11-11（Asia/Shanghai）
- 范围：MDD-032 的 032-A 段（17 关系真实注册 + Q01–Q12/Q15 的 29 个变体形状），**不含** Q13 `boundary`（多语句）与 Q14（响应分页）
- 性质：实施记录。**未**宣称 `hostlab-audit-v1` admitted、未签发 `task_complete_proven`、未做 profile admitted 判定

## 0. 结论先行

| 项 | 结果 |
|---|---|
| 17 个契约关系名在生产 provider 注册 | **17 / 17** |
| 契约列逐列对齐 `relations.json`（名称/顺序/载体类型/可空性） | **156 / 156** |
| 与 A0（冻结 `dexsql-windows-amd64.exe`）逐行对照 | **17 / 17 关系全等** |
| Q01–Q12 + Q15 变体在真实事实层执行 | **29 / 29 非空且完整** |
| Q13 `boundary`、Q14 | **未覆盖**（见 §6） |
| `cargo test --offline -p mdd-sql` | **231 passed / 0 failed** + 1 doc-test |
| `cargo clippy --offline -p mdd-sql --all-targets -- -D warnings` | **无告警** |

## 1. 代码位置

| 文件 | 变更 | 性质 |
|---|---|---|
| `crates/mdd-sql/src/provider/hostlab.rs` | **新增**（1347 行） | `HostLabRelation` 枚举、17 组契约列常量、`HostLabSqlProvider`、单 occurrence 游标 |
| `crates/mdd-sql/src/provider/hostlab/tests.rs` | **新增**（1036 行） | A0 逐行对照、29 变体、层门控、坐标与 provenance 判决 |
| `crates/mdd-sql/src/provider.rs` | 仅新增 `pub mod hostlab;` 一行 | **未改** `lib.rs` 的 `pub mod` 列表 |

`provider.rs` 中的 `CompatibilityProfile*` 等新增内容在本次工作开始时已存在于工作区（属其他子代理/主代理改动），本次未触碰。

源哈希（本次交付）：

```
11a249fc10f94ed24ce1fc6caf9f288f1bb7c495a937f2fd45984ae660090c89  crates/mdd-sql/src/provider/hostlab.rs
443ed45745c7f20867ef39a7d8a55c4eb5c4bb1f5680e8db64435211885179fa  crates/mdd-sql/src/provider/hostlab/tests.rs
830dde8df553b46cfe745c445c2fce1a50d7bd4ab178bfd621809d4263984bfa  crates/mdd-sql/src/provider.rs
4045b5a1c1cbc2cae32b601bac11e9509365a42d3b6835bca6e0e0fb9ca9f15a  crates/mdd-sql/src/lib.rs  （未修改）
```

## 2. 十七关系映射表

契约名 → 事实层 API → 列映射。所有关系共用同一组坐标：
`file_id` = 选中 DEX 的 roster 位置，`string_pool_id` = 同一位置（见 §3）。

| # | 契约名（列数） | 事实层投影 | 列映射 |
|---|---|---|---|
| 1 | `dex_files` (28) | `MetadataFacts::dex_file_rows(file_id, string_pool_id)` + `SelectedScope::dex_file_provenance` | 26 个 header/表原子直传；`source_path`/`entry_name` 由 scope provenance 提供（§4） |
| 2 | `strings` (3) | `MetadataFacts::string_rows(file_id, string_pool_id)` | `string_pool_id, string_idx, value` 直传；非标量字符串 → `UNSUPPORTED_QUERY`（保留，不替换） |
| 3 | `types` (4) | `MetadataFacts::type_rows(file_id)` | `file_id, type_idx, descriptor, java_name` 直传 |
| 4 | `methods` (14) | `MethodCodeFactViews::method_rows(file_id)`（`CodeFacts` 层，含 opcode/参数描述符 tokenizer） | 14 列直传；`access_flags`/`opcode_count`/`opcode_hex`/`method_kind` 对 reference-only 方法保持 NULL |
| 5 | `classes` (8) | `DefinitionFacts::class_rows(file_id)` | 8 列直传；`superclass_descriptor`/`source_file` 的 NO_INDEX → NULL |
| 6 | `class_interfaces` (5) | `DefinitionFacts::class_interface_rows(file_id)` | 5 列直传；`ordinal` 为编码序 |
| 7 | `class_fields` (8) | `DefinitionFacts::class_field_rows(file_id)` | 8 列直传；`kind` 已是 `static`/`instance` |
| 8 | `class_methods` (8) | `DefinitionFacts::class_method_rows(file_id)` | 8 列直传；`kind` 已是 `direct`/`virtual`；只遍历 `method_definitions`，不混入纯引用 |
| 9 | `code_items` (12) | `MethodCodeFactViews::code_item_rows(file_id)` | 12 列直传；`insns_size` 是 code units（**不乘 2**，与 A0 一致）；`tries_off`/`handlers_off` 在 try 列表为空时 NULL |
| 10 | `annotation_directory_entries` (7) | `AnnotationFacts::directory_entry_rows(file_id)` | 契约 `entry_kind`/`entry_idx` ← 事实层 `entry_kind`/`entry_idx`（同义直传） |
| 11 | `annotation_set_entries` (4) | `AnnotationFacts::set_entry_rows(file_id)` | 4 列直传 |
| 12 | `annotations` (5) | `AnnotationFacts::annotation_rows(file_id)` | 5 列直传；`visibility` u8 → UInt32 |
| 13 | `annotation_elements` (11) | `AnnotationFacts::element_rows(file_id)` | 9 列直传；`value_i64`（事实层 `Option<String>` 规范十进制）→ `SqlValue::I64`；`value_f64`（`ExactFloat`）→ `SqlValue::F64(bit pattern)`，两者 NULL 保持 NULL |
| 14 | `method_strings` (8) | `ReferenceFacts::method_string_rows(file_id)` | 8 列直传；非标量字符串 → `UNSUPPORTED_QUERY`（与 `strings` 同一错误面） |
| 15 | `method_calls` (10) | `ReferenceFacts::method_call_rows(file_id)` | 10 列直传；每个 invoke 点一行，保留重数 |
| 16 | `method_field_accesses` (12) | `ReferenceFacts::method_field_rows(file_id)` | 12 列直传；`using_type` 由助记符前缀推导 get/put，NULL 分支保留 |
| 17 | `method_used_types` (9) | `ReferenceFacts::method_type_rows(file_id)` | 9 列直传 |

**未注册：0**。所有 17 个关系均可查、非空（测试 `all_seventeen_relations_return_rows_from_real_facts` 对每个关系断言 `SELECT * FROM <name>` 返回非空行且列数与契约一致）。

## 3. `file_id` 与 `string_pool_id` 的坐标来源

坐标来自 `SelectedScope::occurrence_pool_coordinates()`（`crates/mdd-facts/src/indexes/scope.rs`），
over `SelectedDex.file_id`（选中 roster 位置）。两个契约列在全部观察样本上相等，但代码里保持两个字段，
以便将来拆分而不改行形状。

**关键实测结论（与 `mdd-032-gap-analysis.md` §3.1 的假设相反）**：

用冻结后端 `dexsql-windows-amd64.exe`（sha256 `f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448`）
对判别性样本取证：

| 样本 | 成员顺序 | A0 的 `file_id` 顺序 |
|---|---|---|
| `tests/fixtures/generated/member-policy.apk` | `classes10.dex`, `classes2.dex`（ZIP 序） | `classes10.dex`=0、`classes2.dex`=1 |
| 临时判别样本 `dict-order.apk` | `classes.dex`, `classes10.dex`, `classes2.dex`, `classes3.dex` | 按 ZIP 枚举序 0,1,2,3 |
| 临时判别样本 `numeric-order.apk` | `classes.dex`, `classes2.dex`, `classes3.dex`, `classes10.dex` | 按 ZIP 枚举序 0,1,2,3 |
| 临时判别样本 `twelve.apk` | 12 个成员乱序存放 | 严格 ZIP 枚举序 0..11 |
| `tests/fixtures/generated/duplicate-content.apk` | 两个字节相同的成员 | `file_id`/`string_pool_id` 均为 0 和 1（按 occurrence，不按物理池去重） |

因此 A0 的 `file_id` 是**归档枚举序**，不是 "classes\<N\>.dex 的 N-1 数值序"。
`NativeSession::hostlab_file_ids()` 与 `surface::dex_file_order()` 采用的数值序在
`member-policy.apk` 这类样本上会与 A0 不一致。

本次实现选择**与 A0 实测一致**的归档枚举序（即 `SelectedDex.file_id`），
并把该冲突作为**需主代理裁决事项 A**记录（§7），因为它与项目内既有的两处数值序实现相反。
注：单 DEX 样本与常规 `classes.dex`/`classes2.dex`… 顺序的样本上两者相同，只有乱序归档才暴露差别。

## 4. `source_path` / `entry_name` 的 NULL 判决规则

**判决：不存在 NULL。契约 `nullable: false`，无法无损表示时整关系失败，不产出 NULL、空串或猜测拼写。**

解析由 `SelectedScope::dex_file_provenance()` 完成，规则如下：

| 情形 | `source_path` | `entry_name` |
|---|---|---|
| 常规输入（APK 或裸 DEX），路径可 UTF-8 | 捕获输入的路径文本 | — |
| APK 成员名可 UTF-8 | — | 成员名原文 |
| APK 成员名非 UTF-8 | — | **失败** `ENTRY_NAME_NOT_UTF8` |
| 裸 DEX（无归档成员） | 捕获输入路径 | 该路径的最后一个分量（文件名） |
| 捕获路径非 UTF-8 | **失败** `SOURCE_PATH_NOT_UTF8` | — |

`HostLabSqlProvider` 把上游 `UNSUPPORTED_QUERY` 重新表述为
`INCOMPLETE_FACTS`，`stage = "sql.hostlab.provenance"`，并保留 `column`、
`nullable_contract: "false"`、`resolution: "fail_closed; no NULL and no empty placeholder"`、
以及上游 `cause_code`/`cause_message`/`cause_reason`。

重要设计点：**注册与 schema 不因 provenance 缺失而失败**。该 gap 在 `from_scope` 时就被捕获并挂在对应
occurrence 上，只有真正扫描 `dex_files` 时才报错。否则一个非 UTF-8 的输入路径会让其余 16 个关系
完全不可用。测试 `missing_provenance_fails_closed_instead_of_emitting_null` 验证了
`prepare("SELECT file_id,source_path FROM dex_files")` 成功而 `query(...)` 报 `INCOMPLETE_FACTS`。

## 5. A0 逐行对照记录

`a0-readback.txt` 是用冻结后端对 4 个 fixture（1 个 APK + 3 个 DEX）现场取得的 17 张表，
每块标注 `input=` 与所用 SQL。测试 `every_relation_matches_the_recorded_a0_readback_row_for_row`
逐关系重新打开该块记录的输入、执行同一条 SQL、比对列名/列序/行值：

- 整数、文本、NULL 逐值严格相等；
- `value_f64` 列按 **binary64 位型**比较（A0 输出 `1.0`/`Inf`/`NaN`，本引擎输出 `1`/`inf`/`NaN`，
  文本形式不同但位型相等，这是唯一被允许的差异，且比较的仍是值而非格式）。

fixture 哈希（对照可复现性）：

```
4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc  tests/fixtures/definitions/generated/definitions-035.dex
076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8  tests/fixtures/references/generated/classic-035.dex
65380a8b23601e17339379be211e417d8b4c8383b686b6d173f800656b985360  tests/fixtures/annotations/generated/annotations-038.dex
6b88277747a49dfddcc91900c171ae6420449cc424d57ffd46f896891ad26098  tests/fixtures/generated/multidex-stored.apk
78c3264f1aa9ffad0096b8b69e8127ac1898dd6a24a878fad7cc11eb2ac5655d  tests/fixtures/generated/member-policy.apk
2f8ff0d537beb8d331c40e76e153c37bf2ae5a1c9cb69c2808aa6f4324433529  tests/fixtures/generated/duplicate-content.apk
```

另有两张逐列 A0 表对照（`artifacts/mdd-026` 下历史记录）：

- `methods` 全 14 列（含 `param_descriptors`/`opcode_count`/`opcode_hex`）对 `definitions-035.dex` 逐行全等；
- `types` 全 4 列对 `definitions-035.dex` 逐行全等。

## 6. Q01–Q12 + Q15 的 29 个变体

`REQUIRED_HOSTLAB_VARIANTS` 常量逐条登记 `(族, 变体, SQL)`，共 **29** 条，
测 `required_q01_q12_and_q15_variants_all_execute_on_real_facts` 断言每条：
真实 provider 上 `prepare` 成功（关系名与列名真实存在）、`execute` 完整、行非空、列非空。
13 个族（Q01–Q12、Q15）全部出现。

覆盖的 29 个变体：

| 族 | 变体 |
|---|---|
| Q01 | inventory, pool_mapping |
| Q02 | cf_wildcard, cm_wildcard, class_meta |
| Q03 | interface_join |
| Q04 | Signature_type, directory, set_entries, annotation_type, elements, string_pool |
| Q05 | return_discovery |
| Q06 | string_candidates |
| Q07 | class_count |
| Q08 | class_surface, field_surface, method_surface |
| Q09 | raw_body_ranges |
| Q10 | call_counts |
| Q11 | protocol_definitions |
| Q12 | locate_class, locate_method, locate_field, refs_string, refs_method, refs_field, refs_type |
| Q15 | legacy_locate_method |

Q11 的 IN 列表用 fixture 实际定义的 descriptor 替换了业务类（`Lfixture/Protocol;` → `Lfixture/Base;`），
`Lcom/bapis/%Moss;` 的 LIKE 前缀保留 —— 形状不变，只是让它在 sudo fixture 上非空。

## 7. 仍需主代理裁决的事项

1. **裁决 A（重要）：`file_id` 的权威序。** 本次实测证明冻结后端在乱序归档上给的是**归档枚举序**，
   而项目内 `NativeSession::hostlab_file_ids()`（`hostlab/mod.rs:491`）与 `surface::dex_file_order()`
   （`surface.rs:188`）实现的是**数值序**，且 `hostlab/rules.rs:436-447` 把"数值序"记为参考语义。
   两者在 `member-policy.apk` 这类样本上直接冲突。本次 `dex_files` 取归档枚举序以对齐 A0 实测；
   若主代理判定数值序才是权威，需要同步修改 `hostlab/rules.rs` 的 divergence 文案、
   `NativeSession::hostlab_file_ids()`、`surface::dex_file_order()`，并把本 provider 的坐标源换掉。
   **该决定影响所有 JOIN 键**，请在 032-B/033 之前定案。
2. **`string_pool_id` 没有独立规则。** 全部样本上它与 `file_id` 相同（含字节相同的双 occurrence）。
   如果真实产品上存在一个 DEX 多个池、或池跨 DEX 共享的编号规则，当前实现不覆盖。
3. **`methods` 的三个门控列已由事实层补齐**（`MethodCodeFacts::method_rows` 直接产出 14 列）。
   注意该 API 是并行的另一个子代理在 `crates/mdd-facts/src/code.rs` 新增的；本 provider 依赖它，
   若该 API 被回退，`methods` 会退回 11 列。
4. **Q13 `boundary`（多语句）与 Q14（响应分页）仍未实现**，符合 032-A 的切分，但 MDD-032 验收
   第 2 条仍未闭合。
5. **`method_field_accesses.using_type` 的 NULL 分支仍无 A0 反例**：本实现保留了 NULL（事实层从助记符
   推导 get/put），但没有任何样本观测到该列为 NULL。这与原 gap 分析的 R7 一致，未被本次工作解决。
6. 未做：`hostlab-audit-v1` admitted、`task_complete_proven`、profile 签发、corpus golden
   （`conformance/corpus/hostlab/expected-results/` 仍不存在）。

## 8. 验证记录

```
cargo test --offline -p mdd-sql
  test result: ok. 231 passed; 0 failed; 0 ignored
  Doc-tests: 1 passed

cargo clippy --offline -p mdd-sql --all-targets -- -D warnings
  （无告警）

cargo build --offline -p mdd-sql   # 清理后从零编译通过
```

新增测试清单（21 条，位于 `provider/hostlab/tests.rs`）：

- `dex_files_registers_every_contract_column_and_matches_a0_rows`
- `strings_and_types_match_recorded_a0_rows_value_for_value`
- `methods_match_recorded_a0_rows_value_for_value`
- `every_relation_matches_the_recorded_a0_readback_row_for_row`
- `all_seventeen_relations_return_rows_from_real_facts`
- `every_contract_relation_name_is_registered_with_its_contract_columns`
- `dex_files_uses_archive_roster_order_not_numeric_member_order`
- `dex_files_string_pool_ids_follow_occurrence_not_physical_pool`
- `dex_files_provenance_is_the_resolved_snapshot_and_inventory_value`
- `provenance_gap_mapping_names_the_column_and_keeps_the_cause`
- `annotation_elements_convert_integers_and_floats_exactly`
- `q02_class_surfaces_match_a0_rows`
- `q03_interface_join_is_answerable`
- `q04_annotation_chain_is_answerable`
- `q05_q06_q07_q10_q11_q12_are_answerable`
- `q08_q09_q15_are_answerable`
- `reference_relations_match_recorded_relation_counts`
- `required_q01_q12_and_q15_variants_all_execute_on_real_facts`

（其余为原有 bridge 层 hostlab 测试，未改动。）

## 9. 本记录的证据边界

- A0 对照是**本次现场执行**冻结后端得到的；`a0-readback.txt` 是原始输出，未做后处理。
- `twelve.apk` / `dict-order.apk` / `numeric-order.apk` 是临时判别样本，位于系统临时目录，
  未纳入仓库；其结论已在上表以文字记录，可随时用同一命令复现。
- 未使用私有 APK，未做性能测量，未做设备/UI 证据。
