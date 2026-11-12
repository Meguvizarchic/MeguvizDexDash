# MDD-026 生产关系装配：实现说明

日期：2026-11-11
范围：`crates/mdd-facts/src/**`（未改 `lib.rs` 的 `pub mod` 列表，未新增模块、未新增依赖）

## 1. 装配模式

复用 `crates/mdd-facts/src/references.rs` 的既有投影模式：

1. 一个 `XxxRow` 结构体，`#[derive(Serialize)]`，字段名与契约列名逐字一致，字段顺序与
   `conformance/manifacts/relations.json` 的列顺序一致。
2. 一个 `XxxRow::COLUMNS` 常量，列出该关系**真正装配**的列（按契约顺序）。
3. 一个行投影方法 `xxx_rows(...)`，返回 `MddResult<Vec<XxxRow>>`。
4. 一个列门 `require_relation_columns(relation, columns)`，拒绝未装配列并给出
   `IncompleteFacts` / `InvalidArgument` 及 `required_layer` 明细。
5. `crates/mdd-facts/src/indexes/columns.rs` 中把已装配列的 `assembled_projection`
   置为 `true`；未装配列保持 `false`。

`assembled_projection` 只在列确实有生产投影时置真，与既有 87 列的判定一致
（例如 `methods.param_descriptors` 引擎自报 `IncompleteFacts`，保持 `false`）。

## 2. 逐关系实现

### 2.1 `dex_files`（26/28）

- 类型：`metadata::DexFileRow`，方法 `MetadataFacts::dex_file_rows(file_id, string_pool_id)`。
- 原始 header 字（`endian_tag` / `link_size` / `link_off` / `map_off`）直接从**同一份已验证
  DEX 成员字节**的固定偏移 40/44/48/52 读取小端 u32，而不是从 `DexHeader` 的结构化字段
  推导。这样当 link section 不存在时，投影是编码出来的 0，而不是 `link_range: None`
  的臆测。
- 六个 `_count` / `*_off` 来自 `DexHeader::tables`（按表名查找，找不到即 `InternalFault`）。
- `byte_len` 用 `MetadataFacts::bytes().len()`。
- `file_id` / `string_pool_id` 是**调用方目录坐标**，与本 crate 所有既有行 API 的
  `file_id` 约定一致；`StringPoolIdentity::string_pool_id` 是不透明 `String`，fact 层
  没有 UInt32 目录赋值器，因此不伪造。
- 未装配：`source_path`、`entry_name`。二者属于 Snapshot / ArchiveInventory 的
  provenance 层，不属于 `MetadataFacts`；门会返回 `IncompleteFacts` +
  `required_layer=input_inventory`。

### 2.2 `strings`（3/3）

- 类型：`metadata::StringRow`，方法 `MetadataFacts::string_rows(file_id, string_pool_id)`。
- `value` 用 `DexText::strict_utf8()`，与 `references.rs::method_string_rows` 完全一致：
  合法的非标量 DEX 字符串返回 `UnsupportedQuery` + `NON_SCALAR_TEXT_PROJECTION`，
  绝不替换成有损占位符。
- 逐条校验 `string_idx` / `entity.kind` / `string_pool_id` 与已验证事实一致，不一致即
  `InternalFault`。
- 保留 DEX 顺序与重复值，不做去重。

### 2.3 `types`（4/4）

- 类型：`metadata::TypeRow`，方法 `MetadataFacts::type_rows(file_id)`。
- `java_name` 复用 `MetadataFacts::java_type_name`（版本相关文法、255 维上限），
  不是新的兼容格式化器。

### 2.4 `methods`（11/14）

- 类型：`definitions::MethodRow`，方法 `DefinitionFacts::method_rows(file_id)`。
- 复用 `MethodFactViews` 的 `method_idx -> definition` 连接，因此 reference-only 成员
  保留身份且 `access_flags` / `method_kind` 为**真实 NULL**，而不是被丢弃或填默认值。
- 未装配：`param_descriptors`（引擎自报 `IncompleteFacts`，compatibility text encoding
  未获资格）、`opcode_count` / `opcode_hex`（需 code_layout 层）。三者保持
  `assembled_projection=false`，`require_relation_columns` 继续拒绝；`*` 请求对
  `Methods` 也继续报错，不会静默包含受限列。

### 2.5 `classes`（8/8）

- 类型：`definitions::ClassRow`，方法 `DefinitionFacts::class_rows(file_id)`。
- `superclass_descriptor` / `source_file` 是编码的 NO_INDEX，投影为真实 NULL。
- `source_file` 用 `DexText::strict_utf8()`；非标量文本返回 `UnsupportedQuery`，
  绝不有损转换。
- `interface_count` 按 `class_def_idx` 统计已声明的 interface 条目（直接声明，
  不做继承闭包）。

### 2.6 `code_items`（12/12）

- 类型：`code::CodeItemRow`，方法 `MethodCodeFactViews::code_item_rows(file_id)`，
  门为 `MethodCodeFactViews::require_relation_columns(CodeRelation::CodeItems, ..)`。
- 关系行是 **method-owned** 的：`method_idx` 由 `DefinitionFacts` 的
  `MethodBody::Present.code_byte_offset` 与同一 occurrence 的 `CodeFacts` 物理起点连接
  得到；共享 body 按 owner 展开多次；无声明方法的物理 code item 不产生行（因为
  `method_idx` 是 NOT NULL）。
- `tries_off = insns_off + insns_size*2 + (insns_size % 2)*2`（仅当 `tries_size > 0`），
  `handlers_off = tries_off + tries_size*8`；与冻结的 `raw_fields` 布局一致。
- `debug_info_off` 投影编码 header 字：无 debug section 时是编码 0，不是 NULL
  （`CodeItem::debug_info_byte_offset` 仅在原始值为 0 时为 `None`）。

## 3. 列门与 `*`

- `MetadataRelation::DexFiles` 的 `*` 请求返回 `IncompleteFacts`，并列出
  `unassembled_columns=source_path,entry_name`；其余两个 metadata 关系允许 `*`。
- `Strings` / `Types` 允许 `*`。
- `Methods` / `Classes` 沿用既有 `DefinitionRelation` 门（`Methods` 的 `*` 仍被拒）。
- `CodeItems` 允许 `*`，未知列报 `InvalidArgument`。

## 4. 未改动项

- `crates/mdd-facts/src/lib.rs`：未改 `pub mod` 列表；所有新增类型/方法都落在既有
  模块中，无需主代理应用 export 变更。
- 未新增任何生产依赖；未改 `Cargo.toml` / `Cargo.lock`。
- 未改 `conformance/**`、`STATE.md`、`tasks/backlog.json`、其它 crate。
- `artifacts/**` 只新增本目录，未改既有证据。

## 5. 已知限制（如实）

1. `dex_files.source_path` / `entry_name` 未装配：需要 Snapshot/ArchiveInventory
   组合层，当前 `MetadataFacts` 不提供。
2. `methods.param_descriptors` / `opcode_count` / `opcode_hex` 未装配：引擎自报
   `IncompleteFacts`，本次不伪造完整实现。
3. `string_pool_id`（`dex_files`、`strings`）与 `file_id` 一样是调用方目录坐标，
   fact 层没有 UInt32 赋值器；`strings`/`dex_files` 的 A0 join 语义依赖该坐标由
   调用方按 occurrence 顺序给出。
4. `strings.value` / `classes.source_file` 对合法非标量 DEX 字符串会报错而非有损输出；
   小样本 fixture 全为 ASCII，未覆盖非标量路径。
5. 行投影没有引入新的字节预算结构；行数受已验证 fact 规模约束（与既有
   `class_field_rows` 等一致）。
