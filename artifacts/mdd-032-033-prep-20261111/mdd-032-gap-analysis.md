# MDD-032 差距分析：HostLab 十七关系与必需 SQL corpus

- 日期：2026-11-11（Asia/Shanghai），分析时点 19:21
- 性质：**只读分析**，未修改任何生产代码/共享文件
- 任务定义：`tasks/backlog.json` 中 `MDD-032`（status=todo，deps 含 MDD-031）
- 契约权威：`conformance/manifests/relations.json`（`required_count: 17`，见 `:7`）
- 事实层证据：`artifacts/mdd-026/evidence-merged-20261111/merged-matrix.json`（156 列）
- 装配证据：`artifacts/mdd-026/assembly-relation-projections-20261111/`
- SQL 层现状：`crates/mdd-sql/src/`（分析时点哈希见 `SUMMARY.md`）

**结论先行**：17 个 HostLab 必需关系在 mdd-sql **生产路由中一个都没有注册**（0/17）；
mdd-facts 已为其中 16 个关系提供了行投影 API，156 列中 151 列已装配、5 列未装配；
按六类口径 139/156 列完全合格。因此 MDD-032 的主要工作不是"补事实"，而是
**新建生产兼容 profile 层：关系名映射、列契约、`file_id` 排序、`string_pool_id` 目录赋值、
以及 3 个门控列的文本编码资格**。

---

## 0. 两类缺口的区分（后文所有结论都按此口径）

| 层 | 现状 | 证据 |
|---|---|---|
| **事实层（mdd-facts）** | **17/17** 关系都有 `*_rows()` 行投影（其中 `methods` 的 3 列被门控拒绝）；151/156 列已装配 | `merged-matrix.json` `columns` 数组；`mapping-analysis.json` `relations[].projection_api` |
| **SQL 层（mdd-sql）** | 注册 32 个 `native_*` 关系，**合法契约名 0 个** | `crates/mdd-sql/src/provider/metadata.rs:60-82, 544-563, 1280-1307, 1896-1911, 2160-2164` |
| **方言层** | 3 个方言枚举已存在（NativeV1 / DexSql010 / DexSql011） | `crates/mdd-sql/src/dialects/mod.rs:5-9` |
| **profile 层** | `crates/mdd-sql/src/profiles/` **不存在**；`lib.rs` 无 `profiles` 模块 | `crates/mdd-sql/src/lib.rs:3-10`；目录 `ls` 为空 |

SQL 层已注册的 32 个关系（精确枚举，脚本提取自 `provider/metadata.rs`）：

- metadata 6：`native_dex_occurrences`、`native_string_pools`、`native_strings`、`native_types`、`native_prototypes`、`native_prototype_parameters`
- definitions 7：`native_classes`、`native_class_definition_details`、`native_class_interfaces`、`native_method_references`、`native_method_definitions`、`native_field_references`、`native_field_definitions`
- annotations 11：`native_annotation_items`、`native_encoded_value_nodes`、`native_annotation_owners`、`native_annotation_sets`、`native_annotation_set_entries`、`native_annotation_ref_lists`、`native_annotation_ref_entries`、`native_annotation_parameter_lists`、`native_annotation_directories`、`native_annotation_directory_entries`、`native_annotation_directory_bindings`
- code 5：`native_code_items`、`native_code_bytes`、`native_code_tries`、`native_code_handlers`、`native_code_catches`
- references 3：`native_reference_sites`、`native_method_call_sites`、`native_dynamic_call_sites`

**关键否定事实（已验证）**：`grep 'eq_ignore_ascii_case("<契约名>")'` 对 17 个契约名全部为 0 命中；
`grep '"dex_files"' crates/mdd-sql/src/*.rs` 仅命中 `bridge.rs:5912` 的**测试内合成 provider**
（`struct MultiProvider`，`bridge.rs:5400` 起；`#[cfg(test)] mod tests` 起点 `bridge.rs:1155`），
不是生产注册。

---

## 1. 十七关系逐列状态表

列级状态取自 `merged-matrix.json`（六类：field_type / null / order / multiplicity / source / raw_fingerprint）。
`列合格` = 六类全部 satisfied。

| # | 关系（契约列数） | SQL 层 | 事实层行 API（位置） | 契约列已合格 | 缺口分类 | 可复用实现 | 建议实现路径 |
|---|---|---|---|---|---|---|---|
| 1 | `dex_files` (28) | **缺关系** | `MetadataFacts::dex_file_rows(file_id, string_pool_id)` `metadata.rs:697`；`DexFileRow` `:476-535` | 24/28 | 缺关系 + 缺 2 列（`source_path`/`entry_name` 层所有权）+ 2 个目录坐标需赋值 | `SelectedInput.origin_display`（`indexes/scope.rs:616-624`）、`MemberIdentity.name_utf8`（`input/archive/mod.rs:65-79`） | 新建 `profiles/hostlab.rs`；`entry_name` 取 `name_utf8`（裸 DEX 用 `origin_display` 的 file name，需与 A0 对齐）；`file_id` 用 HostLab 数值序（见 §3）；`string_pool_id` 需 UInt32 目录赋值契约 |
| 2 | `strings` (3) | **缺关系** | `string_rows(file_id, string_pool_id)` `metadata.rs:748`；`StringRow` `:541-550` | 2/3（`string_pool_id` field_type partial） | 缺关系 + `string_pool_id` 类型 | `string_rows` | 同上；池号必须不是 `native_strings.string_pool_id` 的不透明 String |
| 3 | `types` (4) | **缺关系** | `type_rows(file_id)` `metadata.rs:801`；`TypeRow` `:556-565` | 3/4（`file_id` multiplicity partial） | 缺关系 + `java_name` 语义待核 | `MetadataFacts::java_type_name`（`metadata.rs:195`） | 映射为 SQL 关系；`java_name` 是"descriptor 派生显示名"，是否等于 DexSQL `java_name` **未验证**，需 A0 对照（见 §4 风险 R3） |
| 4 | `methods` (14) | **缺关系** | `method_rows(file_id)` `definitions.rs:1399`；`MethodRow` `:87-99`，`COLUMNS:103-115` | 10/14 | 缺关系 + 3 列门控（`param_descriptors`/`opcode_count`/`opcode_hex`）+ `file_id` multiplicity | `ParameterDescriptorText`/`descriptor_text`（`definitions.rs:428,447,486`）；`OpcodeText`/`opcode_text`（`code.rs:1031,1047,1071`） | 3 列原子已具备：`opcode_text` 产出小写十六进制、单空格分隔（`code.rs:1068-1070` 注释）；`descriptor_text` 只产出 `raw_mutf8` + `utf16_units`，**没有 Utf8 兼容编码**，契约要求 `Utf8View` → 需资格决定 |
| 5 | `classes` (8) | **缺关系** | `class_rows(file_id)` `definitions.rs:1446`；`ClassRow` `:122-145` | 7/8（`file_id`） | 缺关系 + 目录坐标 | `ClassRow` | 直接映射；`superclass_descriptor`/`source_file` 的 NO_INDEX → NULL 已由事实层实现 |
| 6 | `class_interfaces` (5) | **缺关系** | `class_interface_rows(file_id)` `definitions.rs:1382`；`ClassInterfaceRow` `:69-75` | 3/5（`file_id`、`ordinal` order+multiplicity partial） | 缺关系 + `ordinal` 证据缺口 | `ClassInterfaceRow` | 直接映射；`ordinal` 的 order/multiplicity 被 Reviewer 降级（`merged-matrix.json.reviewer_downgrades[0..1]`：比较行 `ordinal` 恒 0，`tests/fixtures/definitions/generated/duplicate-interface.dex` 未使用），MDD-032 须补该 fixture 对照 |
| 7 | `class_fields` (8) | **缺关系** | `class_field_rows(file_id)` `definitions.rs:1344`；`ClassFieldRow` `:47-56` | 7/8（`file_id`） | 缺关系 + 目录坐标 | `ClassFieldRow` | 直接映射；`kind` 已是 `static`/`instance`（`mdd-dex/definitions.rs:55-62`） |
| 8 | `class_methods` (8) | **缺关系** | `class_method_rows(file_id)` `definitions.rs:1363`；`ClassMethodRow` `:58-67` | 7/8（`file_id`） | 缺关系 + 目录坐标 | `ClassMethodRow` | 直接映射；`kind` 已是 `direct`/`virtual`（`:69-76`）；不能混入只被引用的外部方法（`class_method_rows` 只遍历 `method_definitions`） |
| 9 | `code_items` (12) | **缺关系** | `code_item_rows(file_id)` `code.rs:1306`；`CodeItemRow` `:1428-1458`，`COLUMNS:1445-1458` | 12/12 | 仅缺关系 | `CodeItemRow` | 直接映射；`insns_size` 是 code units，HostLab 在 `native_surface.py:64` 自行 ×2 转字节，**不要在引擎侧乘**（见 §4 R4） |
| 10 | `annotation_directory_entries` (7) | **缺关系** | `directory_entry_rows(file_id)` `annotations.rs:2724`；`AnnotationDirectoryEntryRow` `:521-529` | 7/7 | 仅缺关系 + 列改名 | `directory_entry_rows` | 契约 `entry_kind/entry_idx` ← 事实层 `kind/local_index`；`native_annotation_directory_entries` 是另一套 6 列形状（`provider/metadata.rs:1722-1731`），**不可直接改名复用** |
| 11 | `annotation_set_entries` (4) | **缺关系** | `set_entry_rows(file_id)` `annotations.rs:2758`；`AnnotationSetEntryRow` `:531-536` | 4/4 | 仅缺关系 | `set_entry_rows` | 直接映射 |
| 12 | `annotations` (5) | **缺关系** | `annotation_rows(file_id)` `annotations.rs:2792`；`AnnotationRow` `:545-551` | 5/5 | 仅缺关系 | `annotation_rows` | 直接映射；`visibility` 是 u8（`mdd-dex/annotations.rs:131,913-920`） |
| 13 | `annotation_elements` (11) | **缺关系** | `element_rows(file_id)` `annotations.rs:2805`；`AnnotationElementRow` `:553-565` | 10/11（`file_id`） | 缺关系 + 值类型转换 | `element_rows` | 契约 `value_i64: Int64?` 而事实层是 `Option<String>`、`value_f64: Float64?` 而事实层是 `Option<ExactFloat>`；SQL 侧需 `SqlValue::I64`/`F64(bits)` 转换并保持 NULL |
| 14 | `method_strings` (8) | **缺关系** | `method_string_rows(file_id)` `references.rs:1982`；`MethodStringRow` `:1834-1843` | 8/8 | 仅缺关系 | `method_string_rows` | 直接映射；非标量字符串会返回 `UnsupportedQuery`（`references.rs:2001`），与 HostLab hex 包装后 strict-UTF8 失败是**不同错误面**（见 §4 R5） |
| 15 | `method_calls` (10) | **缺关系** | `method_call_rows(file_id)` `references.rs:2026`；`MethodCallRow` `:1845-1856` | 10/10 | 仅缺关系 | `method_call_rows` | 直接映射；每个 invoke 点一行，保留重数 |
| 16 | `method_field_accesses` (12) | **缺关系** | `method_field_rows(file_id)` `references.rs:2065`；`MethodFieldRow` `:1858-1871` | 11/12（`using_type` **null 类缺失**） | 缺关系 + NULL 证据 | `method_field_rows` | `using_type` 由助记符前缀推导 get/put（`references.rs:2080-2086`），NULL 分支从未被执行；A0 观测只出现 `get`/`put`（`artifacts/mdd-024/reference-observations-20261028T113535753094Z.json` 的 `text` 字段多数据集），需补 NULL 反例或证明该列永不 NULL |
| 17 | `method_used_types` (9) | **缺关系** | `method_type_rows(file_id)` `references.rs:2115`；`MethodTypeRow` `:1873-1883` | 9/9 | 仅缺关系 | `method_type_rows` | 直接映射 |

### 1.1 逐列统计（脚本从 merged-matrix.json 复算，非人工估计）

| 关系 | 契约列 | 完全合格 | 部分/缺失 |
|---|---|---|---|
| dex_files | 28 | 24 | 4 |
| strings | 3 | 2 | 1 |
| types | 4 | 3 | 1 |
| methods | 14 | 10 | 4 |
| classes | 8 | 7 | 1 |
| class_interfaces | 5 | 3 | 2 |
| class_fields | 8 | 7 | 1 |
| class_methods | 8 | 7 | 1 |
| code_items | 12 | 12 | 0 |
| annotation_directory_entries | 7 | 7 | 0 |
| annotation_set_entries | 4 | 4 | 0 |
| annotations | 5 | 5 | 0 |
| annotation_elements | 11 | 10 | 1 |
| method_strings | 8 | 8 | 0 |
| method_calls | 10 | 10 | 0 |
| method_field_accesses | 12 | 11 | 1 |
| method_used_types | 9 | 9 | 0 |
| **合计** | **156** | **139** | **17** |

17 个未完全合格列的精确清单：

1. `dex_files.file_id`（multiplicity）
2. `dex_files.string_pool_id`（field_type + multiplicity + raw_fingerprint + source）
3. `dex_files.source_path`（multiplicity）
4. `dex_files.entry_name`（multiplicity）
5. `strings.string_pool_id`（field_type）
6. `types.file_id`（multiplicity）
7. `methods.file_id`（multiplicity）
8. `methods.param_descriptors`（field_type + raw_fingerprint）
9. `methods.opcode_count`（field_type + raw_fingerprint）
10. `methods.opcode_hex`（field_type + raw_fingerprint）
11. `classes.file_id`（multiplicity）
12. `class_interfaces.file_id`（multiplicity）
13. `class_interfaces.ordinal`（multiplicity + order）
14. `class_fields.file_id`（multiplicity）
15. `class_methods.file_id`（multiplicity）
16. `annotation_elements.file_id`（multiplicity）
17. `method_field_accesses.using_type`（**null: missing**）

### 1.2 事实层装配缺口（5 列，`crates/mdd-facts/src/indexes/columns.rs`）

| 行号 | 列 | `assembled_projection` | 原因类别 |
|---|---|---|---|
| `:23` | `dex_files.source_path` | false | 层所有权：属于 Snapshot `SourceIdentity::origin_display` |
| `:30` | `dex_files.entry_name` | false | 层所有权：属于 `ArchiveInventory` `MemberIdentity` |
| `:317` | `methods.param_descriptors` | false | 缺 Utf8 兼容文本编码资格（原子精确，序列化未签发） |
| `:331` | `methods.opcode_count` | false | 需 code_layout 层门 |
| `:338` | `methods.opcode_hex` | false | 同上 |

注意：`assembled_projection` 不是纯标记 —— `coverage.rs:651-656` 在 `false` 时直接返回 `Unknown`，
`:688-718` 在 `true` 且 view 存在时返回 `Complete`。翻旗会实质改变覆盖度结论，
因此 MDD-032 装配这 5 列时必须同步补 coverage 侧验证（`assembly-relation-projections-20261111/SUMMARY.md:17`）。

---

## 2. 必需 SQL corpus 清单与覆盖现状

### 2.1 corpus 规模（`conformance/corpus/hostlab/queries.jsonl`，16 行 = 16 族）

- `hostlab-audit-v1` 必需：Q01–Q14（`conformance/manifests/profile-requirements.json:5-20` `required_query_families`）
- `legacy-sqlite-or-public-product`：Q15、Q16（同文件后续 profile 条目）
- 变体总数 34；其中 hostlab-audit-v1 32 个变体
- **所有 16 族的 `golden` 均为 `null`、`execution_status` 均为 `not_run`**
  （`queries.jsonl` 每行；README 亦声明 `conformance/corpus/hostlab/README.md`）
- 目标产物 `conformance/corpus/hostlab/expected-results/` **目录不存在**

### 2.2 逐族覆盖矩阵

"现有测试"指 `crates/mdd-sql` 内已存在、与 SQLite 真库对比的测试。
**重要限定**：这些测试全部跑在合成 provider 上（`MultiProvider` 仅含 13 个关系，
`bridge.rs:5912-6095` 定义，13 个关系名见该段 `multi_relation(...)` 调用；`vals` 单表用于其余形状），
**不经过真实 17 关系**，也不使用真实 DEX 事实。

| 族 | 必需变体 | 已有测试覆盖的变体 | 未覆盖变体 | 证据 |
|---|---|---|---|---|
| Q01 | inventory、pool_mapping | inventory | pool_mapping（`file_id,string_pool_id` 组合） | `bridge.rs:6160` |
| Q02 | cf_wildcard、cm_wildcard、class_meta | cf_wildcard | **cm_wildcard**（`SELECT cm.* FROM class_methods`）、class_meta | `bridge.rs:6164`；`grep 'SELECT cm\.\*'` = 0 |
| Q03 | interface_join | interface_join | — | `bridge.rs:6168`；`join_tests.rs:267` |
| Q04 | Signature_type、directory、set_entries、annotation_type、elements、string_pool | elements（仅谓词形状） | **5 个**：Signature_type、directory、set_entries、annotation_type、string_pool | `bridge.rs:4461`（`vals` 表，非真实关系） |
| Q05 | return_discovery | return_discovery | — | `bridge.rs:6172` |
| Q06 | string_candidates | string_candidates（两 LIKE + ESCAPE + DISTINCT） | — | `bridge.rs:4584` |
| Q07 | class_count | `COUNT(*) AS n FROM classes ORDER BY n` | — | `bridge.rs:6175` |
| Q08 | class_surface、field_surface、method_surface | class_surface | **field_surface、method_surface** | `bridge.rs:6177` |
| Q09 | raw_body_ranges | `BETWEEN` + `insns_off/insns_size` | — | `bridge.rs:6181` |
| Q10 | call_counts | GROUP BY 三键 + COUNT(*) + LIKE | — | `bridge.rs:5192` |
| Q11 | protocol_definitions | IN + `Lcom/bapis/%Moss;` LIKE | — | `bridge.rs:6185` |
| Q12 | locate_class、locate_method、locate_field、refs_string、refs_method、refs_field、refs_type | refs_method | **6 个**：三类 locate + refs_string/refs_field/refs_type | `bridge.rs:6189` |
| Q13 | representative_shape、hex_value_wrapper、boundary | representative_shape、hex_value_wrapper（`CASE WHEN ... THEN 'N' ELSE hex(CAST(...))`） | **boundary**（`;SELECT '<marker>'` 多语句） | `bridge.rs:4295` |
| Q14 | arbitrary_select_with | **无** | 全部（响应分页 + 独立 ORDER BY） | 无对应测试 |
| Q15 | legacy_locate_method | `||` 拼接 + ORDER BY | — | `bridge.rs:5299` |
| Q16 | native_statement_results | **无** | 全部（TEMP/多语句） | 无对应测试 |

统计：hostlab-audit-v1 的 32 个变体中，**14 个有 SQL 形状级测试，18 个无**。
全 34 变体中 15 个有形状级测试。

### 2.3 现有测试无法覆盖的两处硬冲突（已验证）

1. **Q13 `boundary` 与只读单语句设计冲突**：`native_cli.py:117` 发送
   `sql; \n SELECT '<marker>' AS hostlab_boundary;`。桥在 AST 层直接拒绝多语句
   （`dialects/ast.rs:1204-1211` `SQL_REQUIRES_ONE_STATEMENT`），且要求必须是 `Query`
   （`:1213-1215` `SQL_STATEMENT_NOT_READ_ONLY_QUERY`）。`bridge.rs:4144-4157` 的
   `sql_authority_and_real_errors_are_not_success_or_unsupported` 明确断言
   `"SELECT 1; SELECT 2"` 与 `"CREATE TEMP TABLE x AS SELECT 1"` 都是 `InvalidArgument`。
2. **Q14 与响应分页语义冲突**：typed IR 的 `Node::Limit` 明确定义为
   `"relation_limit_not_response_paging"`（`executor.rs:536-539`），而 Q14 要求
   "SQL 自己的 LIMIT/OFFSET 与响应页限的独立语义"。这一层目前只在
   `mdd-types` 的 `TerminalBuilder::page`（`result.rs:153-170`）有契约，**无生产调用者**
   （`grep '\.page(' crates/` 仅命中 `result.rs` 测试）。

这两点意味着：**如果按字面执行 MDD-032 验收第 2 条"所有必需模板…均执行完整"，
MDD-032 将隐式依赖 MDD-033 的分页与 session 的多语句/TEMP 能力**，而其 `depends_on`
只写了 MDD-031。这是需要在实施顺序上处理的结构性问题（见 `implementation-plan.md` §3）。

---

## 3. 三个必须先定的跨层契约（否则逐个关系实现会返工）

### 3.1 `file_id` 排序：DexSQL 数值序 vs ZIP 归档序

- `SelectedScope::from_inventories` 把 `file_id` 赋成**归档遍历序号**：
  `indexes/scope.rs:770` `file_id: dexes.len() as u32`，顺序来自 `inventory.selected_dexes()`
  （`mdd-input/src/archive/mod.rs:360-362`），即 ZIP 成员顺序。
- HostLab/DexSQL 的 `file_id` 是**数值 DEX 序号**（`classes.dex`=0、`classes2.dex`=1、
  …`classes10.dex`=9）。项目内已有两处正确实现：
  - `NativeSession::hostlab_file_ids()` `crates/mdd-facts/src/hostlab/mod.rs:491-555`
  - `surface::dex_file_order()` `crates/mdd-facts/src/surface.rs:188-236`
  - 分歧本身被记录为 ADR 级事实：`hostlab/rules.rs:436-447`（`file-id-vs-dex-ordinal`，含
    "`file_id=4` holds exactly the classes of `classes5.dex`" 的 A0 探针结论）
- **结论（已验证）**：MDD-032 的 `dex_files.file_id` 及所有 JOIN 键**不能**直接用
  `SelectedDex.file_id`，必须用 HostLab 数值序；否则多 DEX 样本上 Q03/Q05/Q09/Q10/Q11
  的 JOIN 会整体错位，而单 DEX 样本（`file_id` 恒 0）无法暴露该错误。
  这直接对应 MDD-026 中 `file_id` 列 multiplicity 全部为 partial 的现象。

### 3.2 `string_pool_id`：不透明 String → UInt32 目录号

- 事实层的池身份是 `StringPoolIdentity::string_pool_id: String`（`mdd-facts/src/metadata.rs:465-469` 注释）。
- MDD-026 采用"调用方传入 UInt32 坐标"的约定（`assembly-relation-projections-20261111/SUMMARY.md:57-59`），
  Reviewer 因此把 `dex_files.string_pool_id` 的 source / raw_fingerprint 降级为 partial
  （`merged-matrix.json.reviewer_downgrades[2..3]`：oracle 值是假设而非字节推导）。
- **结论**：MDD-032 必须定义正式的 `string_pool_id` 目录赋值器（按 scope 序或按池内容去重序），
  并给出字节级 oracle；否则 Q04 `string_pool` 变体（跨 DEX 字符串关联）无法被证明。

### 3.3 方言选择：候选超集必须走 DexSql010/011

- `like()` 的方言差异（`dialects/functions.rs:889-966`）：
  DexSql010/011 对 ASCII 大写折叠（`:938-943`），NativeV1 不折叠；
  `_` 通配只在 NativeV1 生效（`:934-935`）。
- HostLab `native_surface.prefix` 依赖**大小写不敏感 LIKE 作为候选超集**，随后由 Python
  精确分类（`docs/03_HOSTLAB_MIGRATION.md:196-199` §5.3）。
- **结论**：HostLab profile 必须绑定 DexSql010 或 DexSql011；若用 NativeV1，
  Q08/Q10/Q11 会少行。这是 MDD-032 验收第 4 条（"LIKE 等候选条件保留既有 Python
  精确分类所需的完整候选超集"）的直接实现约束。

---

## 4. 风险清单（按阻塞程度排序）

| ID | 风险 | 证据 | 判别 |
|---|---|---|---|
| R1 | **`file_id` 排序错用**导致多 DEX 全错且单 DEX 测不出 | §3.1 | 已验证的分歧存在；影响为推断（未跑多 DEX 对照） |
| R2 | **Q13 boundary / Q16 需要多语句与 TEMP**，当前设计硬拒 | §2.3 | 已验证 |
| R3 | **`types.java_name` 格式可能与 DexSQL 不同** | `metadata.rs:553-565` 注释称"descriptor-derived display name, not a compatibility formatter" | 推断，需 A0 实值对照 |
| R4 | **`insns_size` 单位易错**（code units vs bytes） | `native_surface.py:64` 显式 `*2`；`CodeItemRow` 存 code units | 已验证的双方语义；乘/不乘的选择为设计决定 |
| R5 | **非标量字符串错误面不同**：引擎返回 `UnsupportedQuery`，HostLab 是 hex 后 strict-UTF8 失败 | `references.rs:2001`；`bridge.rs:4295-4310` 注释明确 "not compatibility proof" | 已验证 |
| R6 | **`methods.param_descriptors` 缺 Utf8 兼容编码** | `descriptor_text` 只给 `raw_mutf8`+`utf16_units`（`definitions.rs:447-486`）；契约 `Utf8View` | 已验证 |
| R7 | **`method_field_accesses.using_type` NULL 无证据** | `merged-matrix.json` 该列 `null: missing`；A0 只观测到 get/put | 已验证 |
| R8 | **`class_interfaces.ordinal` 的 order/multiplicity 证据空转** | `reviewer_downgrades[0..1]` | 已验证 |
| R9 | 5 类列翻 `assembled_projection` 会改变 coverage 结论 | `coverage.rs:651-656, 688-718` | 已验证 |
| R10 | 工作区并发写入：`bridge.rs`/`provider.rs` 在分析期间被其他子代理改动 | 19:21 哈希快照与 18:41/18:46 mtime | 已验证（需在实施前重取基线） |

---

## 5. 本节结论（供主代理直接引用）

- 关系缺口：**17/17**（SQL 生产路由一个都没有）。
- 列缺口：事实层 **5/156 未装配**；六类口径 **17/156 未完全合格**（1 列为 `missing`）。
- 语料缺口：hostlab-audit-v1 的 **32 个必需变体中 18 个无 SQL 形状级测试**；
  **0/16 族有 golden**；`expected-results/` 不存在。
- 结构性问题：Q13 boundary 与 Q14 分页把 MDD-033 的能力变成了 MDD-032 验收的前置，
  需要在实施顺序或验收分解上显式处理。
