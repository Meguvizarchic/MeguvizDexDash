# MDD-026 未装配列收口：逐列判定报告

日期：2026-11-11
范围：`crates/mdd-facts/src/**`（未改 `lib.rs` 的 `pub mod` 列表，未改 `Cargo.toml`/`Cargo.lock`、
未新增依赖、未新增 crate、未新增模块文件）
任务：对 `crates/mdd-facts/src/indexes/columns.rs` 中 5 列 `assembled_projection: false`
逐列判定并尽可能收口。

## 0. 结论总览

| # | 列 | 台账可用性 | 本轮判定 | 收口状态 |
|---|---|---|---|---|
| 1 | `dex_files.source_path` | `available_in_validated_declared_scope`（Snapshot `SourceIdentity::origin_display`） | **层所有权缺口已补**：新增 scope 级 28 列投影，`source_path` 取同一快照 `origin_display` | **已装配** |
| 2 | `dex_files.entry_name` | 同上（ArchiveInventory `MemberIdentity`） | **层所有权缺口已补**：APK 取 `name_utf8`，raw DEX 取捕获路径叶子名（显式策略） | **已装配** |
| 3 | `methods.param_descriptors` | `available_in_validated_declared_scope`（"exact native parameter_descriptors vector; compatibility UTF8 serialization UNBUILT"） | **已核实向量确为 exact**：`MethodReference::parameter_descriptors` 由 proto 的 `parameter_type_indices` 逐个 `type.descriptor` 有序克隆；逗号 join 是全域安全的（非标量描述符在读类型阶段即被 `NON_SCALAR_DESCRIPTOR_OR_SHORTY` 拒绝） | **已装配**，编码资格标注为 `comma-separated-utf8-v1` |
| 4 | `methods.opcode_count` | `available_in_validated_declared_scope`，boundaries 明写门"intentionally narrow"、原子"available and independently checked" | **code_layout 层门可放开**：新增 `MethodCodeFactViews::method_rows`，读 `MethodCodeBody::opcode_text`（已解码普通指令） | **已装配** |
| 5 | `methods.opcode_hex` | 同上 | 同上，同一投影 | **已装配** |

5 列全部装配；`crates/mdd-facts/src/indexes/columns.rs` 中 `assembled_projection: false`
的数量从 5 归零（总计 156 列全部为 true）。

## 1. 关键更正：不是「引擎自报缺口」

上一轮 SUMMARY 的原始措辞把 5 列写成「引擎自报 `INCOMPLETE_FACTS` 缺口」。本轮按
Step-Rever 第二轮的更正口径重新核对，结论与更正一致：

- **2 列是层所有权缺口**（`dex_files.source_path`/`entry_name`）。`MetadataFacts` 从来不是它们
  的所有者：`source_path` 的原生原子是 `mdd_types::source_identity::SourceIdentity::origin_display`
  （`Option<String>`，在 `Snapshot::capture` 里由 `input.path.to_str()` 填入）；
  `entry_name` 的原生原子是 `mdd_input::archive::MemberIdentity::raw_name`/`name_utf8`。
  这两个值在 `MetadataFacts::build` 里根本拿不到——`MetadataSource` 只保留了
  `member_id` 与 `content_id`，不含路径也不含成员名。
- **3 列是分层边界与资格门槛**（`methods.param_descriptors`、`opcode_count`、`opcode_hex`）。
  `DefinitionFacts::require_relation_columns` 里那三条 `IncompleteFacts` 是**本 crate 自己
  写的门**，不是解析器上报的缺口。台账 `conformance/facts/required-columns.json` 对这 5 列
  全部记 `native_fact_availability: available_in_validated_declared_scope`。

因此本轮没有放宽任何契约；改变的是「谁拥有该列、由哪个对象投影」：
- provenance 两列改由 `SelectedScope` 投影（scope 本来就同时持有 snapshot 身份与
  inventory 的成员身份）；
- 三个 `methods` 门控列改由持有对应层的对象投影：`param_descriptors` 归
  `DefinitionFacts`（不需要 code），`opcode_count`/`opcode_hex` 归
  `MethodCodeFactViews`（需要 code_layout）。

## 2. 逐列判定与实现

### 2.1 `dex_files.source_path`（`Utf8`，非空）

- 原生原子：`SourceIdentity::origin_display`，由 `Snapshot::capture` 在读取字节的同一次
  pass 里写入，因此与已捕获内容是同一 generation。
- 实现：`SelectedInput.origin_display` 已在 `SelectedScope::pending`/
  `from_inventories` 中保留；新增 `SelectedScope::dex_file_provenance(dex)` 把它取出。
- 失败语义：`origin_display == None`（路径不是合法 UTF-8，`to_str()` 返回 `None`）时报
  `UnsupportedQuery` + `reason=SOURCE_PATH_NOT_UTF8`，不返回 `to_string_lossy()`
  拼出来的有损值。契约列是 `Utf8` 且非空，替换字符属于伪造。

### 2.2 `dex_files.entry_name`（`Utf8`，非空）

- 原生原子：`MemberIdentity::name_utf8`（APK 成员名）与 raw DEX 的捕获路径。
- 实现策略（显式，写在 `dex_file_provenance` 的文档注释里）：
  - APK：`SelectedDex.member_name`（= `MemberIdentity::name_utf8`）。非 UTF-8 成员名
    （`name_utf8 == None` 且 `archive_member_ordinal.is_some()`）报 `UnsupportedQuery` +
    `reason=ENTRY_NAME_NOT_UTF8`。
  - raw DEX：`archive_member_ordinal == None`，取 `Path::new(source_path).file_name()`
    的精确 `&str`（`to_str()`，不做 `to_string_lossy`）。若路径没有叶子分量则报
    `reason=ENTRY_NAME_POLICY_UNAVAILABLE`。
- 这一策略与记录的 A0 一致：raw DEX 的 `entry_name` 是文件名
  （`classic-035.dex`），APK 是成员名（`classes.dex`/`classes2.dex`）。
- 说明：A0 对同一成员 `duplicate-raw-input` 报两行相同 `source_path`/`entry_name`，
  本轮投影同样按 occurrence 逐行输出、不去重（readback 已逐行比对）。

### 2.3 `methods.param_descriptors`（`Utf8View`，非空）

**核对「向量确实 exact」的依据（可复算，不引用引擎自述）：**

1. `crates/mdd-dex/src/definitions.rs:638-681`：`method_references` 按 `method_idx`
   递增遍历 `method_ids`，`parameters` 由 `proto.parameter_type_indices` 顺序迭代、逐个
   `pools.dex_type(*index)?.descriptor.clone()` 推入。顺序、重数、每个描述符文本都来自
   已校验的 type/proto 事实，没有重排、去重或再格式化。
2. `crates/mdd-dex/src/types.rs:109-122`：`scalar_string` 用 `DexText::strict_utf8()`
   取描述符，失败即 `NON_SCALAR_DESCRIPTOR_OR_SHORTY`。因此**任何**合法输入里的
   descriptor 都是标量 UTF-8；元数据构建阶段就已拒绝非标量描述符，行投影阶段
   永远不会遇到需要替换字符的描述符。
3. 独立字节复算：`artifacts/mdd-026/unassembled-columns-20261111/readback.py`
   从 `proto_ids` 的 `parameters_off` 逐条读 `type_list`，再用 `string_ids`+`type_ids`
   解出描述符文本，自己 join 一次，与 A0 与本轮 native 三方比较。24 行方法
   （definitions 13 + shared 5 + dynamic 6）0 差异。

**编码资格（明确标注）：** 逗号分隔是 compatibility text encoding，常量
`crates/mdd-facts/src/definitions.rs::PARAM_DESCRIPTOR_ENCODING = "comma-separated-utf8-v1"`
写明了规则：有序向量、`','` 连接、无空白、空向量编码为空串。该编码**在此域内全域**（不会
有值无法表示），但这不等于「compatibility profile 已 admitted」——本轮不签发任何 profile。

### 2.4 `methods.opcode_count`（`UInt32`，可空）

- 原生原子：`MethodBody` 绑定 + `CodeItem.instructions`（`mdd-dex` 已解码的普通指令，
  含 `opcode`/width/ordinal），**不是** `insns_size`。台账 boundaries 原文：
  "insns_size is not opcode_count"。
- 实现：`MethodCodeFactViews::method_rows(file_id)` 逐方法调
  `MethodCodeBody::opcode_text(OpcodeTextLimits::default())`，取 `text.count`。
  `MethodCodeBody` 的四种状态语义保留：
  | 状态 | `opcode_count` | `opcode_hex` |
  |---|---|---|
  | `ReferenceOnly`（无任何定义） | `NULL` | `NULL` |
  | `Native`/`Abstract` | `0` | `""` |
  | `Present`（含零指令） | 解码计数 | 小写十六进制，单空格分隔 |

  payload 伪指令不计入也不渲染（`decoded_opcode_bytes` 只取 `instructions`）。
- 前提：`MethodCodeFactViews::build` 要求 `code_layout_coverage == Complete` 且
  每个 present body 都在同一 occurrence 的物理 code item 起点上；这些前置检查保持原样。

### 2.5 `methods.opcode_hex`（`Utf8View`，可空）

同一投影，`MethodCodeBody::opcode_text` 的 `text`：两个小写十六进制字符一组、单空格分隔，
空序列为空串。NULL 集合与 `opcode_count` 完全一致。

## 3. 新增/变更的投影（API 清单）

全部位于既有模块内，**不需要主代理修改 `lib.rs` 的 `pub mod` 列表**。

### `crates/mdd-facts/src/indexes/scope.rs`

- `SelectedDex` 新增两个字段：`member_name: Option<String>`、`archive_member_ordinal: Option<DecimalU64>`。
  这两个字段在 `from_inventories` 里由 `DexCandidate::blob.identity` 填入；`None` 的
  两种含义由 `archive_member_ordinal` 区分，不会互相混淆。
- `pub struct DexFileProvenance { source_path: String, entry_name: String }`
- `pub struct ScopeDexFileRow`（28 列，字段顺序 = 契约顺序）+ `ScopeDexFileRow::COLUMNS`
- `SelectedScope::dex_file_provenance(&SelectedDex) -> MddResult<DexFileProvenance>`
- `SelectedScope::require_dex_file_columns(&[&str]) -> MddResult<()>`
  （接受 `"*"` 与 28 列全集；未知列 `InvalidArgument`）
- `SelectedScope::dex_file_rows(&[&MetadataFacts], &[u32], max_entries) -> MddResult<Vec<ScopeDexFileRow>>`
  - 26 个 header/table 原子复用 `MetadataFacts::dex_file_rows`；
  - `file_id` = scope 局部 occurrence 序号，`string_pool_id` = 调用方提供的目录坐标
    （与既有约定一致，fact 层没有 UInt32 池号，本轮不发明）；
  - `string_pool_ids.len() != dexes.len()` 时 `InvalidArgument`，不截断、不补零。

### `crates/mdd-facts/src/definitions.rs`

- `MethodRow` 新增 `param_descriptors: String` 字段，`MethodRow::COLUMNS` 按契约顺序加入该列
  （12/14）。
- `pub const PARAM_DESCRIPTOR_ENCODING: &str = "comma-separated-utf8-v1"`
- `pub(crate) fn parameter_descriptors_text(&[String]) -> MddResult<String>`
- `DefinitionFacts::require_relation_columns`：
  - `param_descriptors` 从拒绝改为接受；
  - `opcode_count`/`opcode_hex` 仍报 `IncompleteFacts`，`required_layer=code_layout`，
    并新增 `assembled_by=MethodCodeFactViews::method_rows` 指明真正的装配点；
  - `*` 仍报错（它会包含 code_layout 两列），明细改为 `unavailable_columns=opcode_count,opcode_hex`。
- `MethodFactViews::method_count()`（`pub(crate)`）用于调用方预分配，避免再暴露私有字段。

### `crates/mdd-facts/src/code.rs`

- `pub struct MethodCodeRow`（14 列，字段顺序 = 契约顺序）+ `MethodCodeRow::COLUMNS`
- `MethodCodeFactViews::require_method_columns(&[&str]) -> MddResult<()>`
  （接受 `"*"` 与 14 列全集，未知列 `InvalidArgument`）
- `MethodCodeFactViews::method_rows(file_id) -> MddResult<Vec<MethodCodeRow>>`

### `crates/mdd-facts/src/metadata.rs`

- `DexFileRow` 的文档改为指向 `ScopeDexFileRow`（该行仍是 26 列，不伪装 28 列）。
- `MetadataFacts::require_relation_columns` 对 `dex_files` 的 provenance 两列保留
  `IncompleteFacts`（该对象确实不拥有它们），新增 `assembled_by=SelectedScope::dex_file_rows`
  明细。仍未放宽 `dex_files` 的 `*`。

### `crates/mdd-facts/src/coverage.rs`

- `frozen_provider_gate`：
  - `dex_files.source_path`/`entry_name` → `SelectedScope::require_dex_file_columns`
  - `methods.opcode_count`/`opcode_hex` → 需要 `(definitions, code)` 且
    `code_layout_coverage == Complete`，再走 `MethodCodeFactViews::require_method_columns`；
    provider 缺失时返回 `Some(None)`（`column_provider_not_built`），不是静默 `Complete`。
- 新增 `CoverageLedger::provenance_gap(occurrence)`：把「provenance 不可表示」变成显式
  `Unknown` + 具名 reason（`lossless_source_path_representation_unavailable` /
  `lossless_entry_name_representation_unavailable` / `entry_name_policy_unavailable`），
  **`NativeAtoms` 与 `FrozenProjection` 两个域都检查**。这堵住了「翻旗即 Complete」的假完成
  路径：一个非 UTF-8 成员名的 scope 上，这两列不会报 `Complete`。

### `crates/mdd-facts/src/indexes/columns.rs`

5 列的 `assembled_projection` 由 `false` 改为 `true`。

## 4. 刻意没有做的事

- **没有**放宽任何「列必须真实拥有」的判定：`MetadataFacts` 依旧拒绝 provenance 两列，
  `DefinitionFacts` 依旧拒绝 opcode 两列，`CodeRelation::CodeItems` 依旧拒绝
  `opcode_count`（它属于 `methods`，不属于 `code_items`）。
- **没有**给 `file_id`/`string_pool_id` 发明 UInt32 池号；仍沿用调用方目录坐标约定。
- **没有**把 `insns_size` 当作 `opcode_count`，也没有把 payload 词渲染进 `opcode_hex`。
- **没有**为通过测试而改写契约或 golden；`conformance/manifests/relations.json` 与
  `conformance/facts/required-columns.json` 均未修改（按约束只读）。
- **没有**声称 admitted / task_complete_proven / profile 签发。

## 5. 仍需主代理决策的事项

1. **`conformance/facts/required-columns.json` 与 ledger 同步**：本目录的 5 列
   `production_projection` 仍是 `unassembled_production_relation`，
   `column-audit-v10` 的 69 列口径也需同步。这属于共享文件的单写点，本轮按约束未改。
   `conformance/facts/compile_column_ledger_v*.py`、`qualify.py`、`audit_columns.py`
   里存在 `unassembled_projection_columns == 69` 的硬断言，需要主代理统一更新。
2. **`selected-scope` 序列化面发生变化**：`SelectedDex` 多了 `member_name`/
   `archive_member_ordinal` 两个字段。`scope_id`/`scope_content_key` 的前映像计算**未改**
   （仍只用 content_id、member ordinal、header offset），因此既有 scope 承诺值不变，
   但导出 JSON 的形状变了。`conformance/facts/verify_cross_dex_identity.py` 与
   `readback_cross_dex_identity.py` 只读 `selected.file_id`，本轮不破；
   若有其他消费方按严格 shape 解析需要主代理确认。
3. **raw DEX 的 `entry_name` 策略**：本轮取「捕获路径叶子名」，与记录的 A0 一致
   （`classic-035.dex`）。但台账原文只说 "raw DEX scope uses explicit entry policy"，
   没有指定策略细节。若主代理要求不同策略（例如空串、或 `input_ordinal` 派生名），
   需要改 `dex_file_provenance` 的 `(None, None)` 分支与对应测试。
4. **`string_pool_id` 的 UInt32 目录赋值**：本轮 `dex_file_rows` 要求调用方传入
   `string_pool_ids`（每个选中 DEX 一个），因为 fact 层没有 UInt32 池号。
   上一轮 `evidence-definition-members-fix` 已把该列的 `field_type` 如实降为 partial
   （声明 `UInt32`、引擎实际为内容派生 `String`）。若要把这一列判为完全合格，
   需要主代理定义正式目录赋值契约并同步 schema。
5. **`methods.param_descriptors` 的 compatibility 资格**：本轮把编码规则写成
   具名常量并证明其在该域内全域，但 `compatibility_profile_admitted` 仍是 `false`。
   是否把它记为「编码已定义但 profile 未签发」需要主代理在台账措辞里明确。
6. **非 UTF-8 provenance 的正向 fixture 缺失**：`ENTRY_NAME_NOT_UTF8` 与
   `SOURCE_PATH_NOT_UTF8` 两个分支只有构造性单测（直接改 `SelectedDex` 字段），
   没有端到端 fixture。真正的非 UTF-8 成员名需要生成一个 APK 并对 capture 路径
   传入非 UTF-8 字符串（Windows 上难以稳定构造），因此本轮只做构造性覆盖并如实记录。
