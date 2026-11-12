# MDD-026 未装配列收口 SUMMARY

日期：2026-11-11
执行：MDD-026 未装配列收口子代理
范围：`crates/mdd-facts/src/**`（未改 `lib.rs` 的 `pub mod` 列表，未改 `Cargo.toml`/`Cargo.lock`，
未新增依赖，未新增 crate 或模块文件）

## 结论

`crates/mdd-facts/src/indexes/columns.rs` 中 **5 列 `assembled_projection: false` 全部收口**，
归零；156 列全部为 `true`。

| 列 | 结论 | 装配点 |
|---|---|---|
| `dex_files.source_path` | **已装配** | `SelectedScope::dex_file_rows`（取 `SourceIdentity::origin_display`） |
| `dex_files.entry_name` | **已装配** | `SelectedScope::dex_file_rows`（APK 成员名；raw DEX 取捕获路径叶子名） |
| `methods.param_descriptors` | **已装配** | `DefinitionFacts::method_rows`（精确有序向量 `,` 连接） |
| `methods.opcode_count` | **已装配** | `MethodCodeFactViews::method_rows`（code_layout 层） |
| `methods.opcode_hex` | **已装配** | 同上 |

**性质更正（与 Step-Rever 第二轮一致）**：这 5 列此前不是「引擎自报缺口」，而是
**2 列层所有权缺口 + 3 列分层边界与资格门槛**。本轮把每一列交给真正持有该原子的层，
没有放宽任何契约、没有伪造实现。

## 逐列判定

### 1–2. `dex_files.source_path` / `entry_name`（层所有权缺口）

- 原生原子：`mdd_types::source_identity::SourceIdentity::origin_display`（`Option<String>`）
  与 `mdd_input::archive::MemberIdentity::raw_name`/`name_utf8`。
- `MetadataFacts::build` 虽然同时接收 `Snapshot` 与 `ArchiveInventory`，但把身份压成
  `MetadataSource`（只有 id 字段），路径与成员名在构造时即丢弃。所以这两列**本来就不属于**
  metadata 层。
- 处理：`SelectedScope` 本就是 snapshot + inventory 的组合层，且已保留
  `SelectedInput::origin_display`。新增：
  - `SelectedDex` 两个字段 `member_name` / `archive_member_ordinal`（后者区分「raw DEX 无成员」
    与「成员名非 UTF-8」两种 `None`）；
  - `DexFileProvenance`、`ScopeDexFileRow`（28 列）、`dex_file_provenance`、
    `require_dex_file_columns`、`dex_file_rows`。
- 失败语义：路径或成员名不是精确 UTF-8 时返回 `UnsupportedQuery`
  （`SOURCE_PATH_NOT_UTF8` / `ENTRY_NAME_NOT_UTF8`），不用 `to_string_lossy` 造值。
- 验证：记录的三份 A0 多输入用例（duplicate-raw-input / two-distinct-raw /
  same-content-multidex-apk，共 6 行）逐列相等。

### 3. `methods.param_descriptors`（分层边界 + 编码资格）

- 台账说向量 exact，本轮独立核实：
  1. `mdd-dex` 按 `proto.parameter_type_indices` 顺序逐个克隆 `type.descriptor`，
     无重排、去重、再格式化；
  2. `scalar_string` 在读类型阶段用 `strict_utf8()` 拒绝非标量描述符
     （`NON_SCALAR_DESCRIPTOR_OR_SHORTY`），所以进入行投影的描述符必然标量 UTF-8，
     逗号 join 全域安全；
  3. `readback.py` 从原始字节重算 `proto_ids → type_list → string_ids → type_ids`，
     24 行（definitions 13 + shared 5 + dynamic 6）与 A0 与本轮 native 三方一致。
- 装配：`MethodRow.param_descriptors`（`MethodRow::COLUMNS` 12/14）。
- 编码资格标注：`PARAM_DESCRIPTOR_ENCODING = "comma-separated-utf8-v1"`
  （有序向量、`','` 连接、无空白、空向量为空串）。该编码在此域内全域，但
  **不签发 compatibility profile**，`compatibility_profile_admitted` 仍为 `false`。

### 4–5. `methods.opcode_count` / `opcode_hex`（code_layout 层门）

- 台账 boundaries 原文：门是 "intentionally narrow"、原子
  "available and independently checked"，完整 legacy Methods 装配属 MDD-032。
  本轮据此把门从「无条件的 `IncompleteFacts`」改为「由持有 code_layout 的对象投影」。
- 装配：`MethodCodeFactViews::method_rows` → `MethodCodeBody::opcode_text`：
  - `ReferenceOnly` → `(NULL, NULL)`
  - `Native`/`Abstract` → `(0, "")`
  - `Present` → 解码普通指令的计数与小写十六进制（单空格分隔），payload 不计入不渲染
  - **`insns_size` 从不被当作 `opcode_count`**
- 前提不变：`MethodCodeFactViews::build` 仍要求 `code_layout_coverage == Complete`
  且每个 present body 落在同一 occurrence 的物理 code item 起点。
- 验证：definitions-035.dex 13 行逐行与记录的 A0 slice 相等（`<init>` = 2 / `70 0e`，
  `nativeCall` = 0 / `""`，`externalCall` = NULL / NULL）。

## 新增/变更的投影

| 模块 | 新增或变更 |
|---|---|
| `indexes/scope.rs` | `SelectedDex.{member_name, archive_member_ordinal}`；`DexFileProvenance`；`ScopeDexFileRow` + `COLUMNS`；`SelectedScope::{dex_file_provenance, require_dex_file_columns, dex_file_rows}` |
| `definitions.rs` | `MethodRow.param_descriptors`；`PARAM_DESCRIPTOR_ENCODING`；`parameter_descriptors_text`；`MethodFactViews::method_count`（`pub(crate)`）；门控只拒 opcode 两列并给出 `assembled_by` |
| `code.rs` | `MethodCodeRow` + `COLUMNS`；`MethodCodeFactViews::{require_method_columns, method_rows}` |
| `metadata.rs` | `DexFileRow` 文档指向 `ScopeDexFileRow`；provenance 门错误新增 `assembled_by`（仍拒绝，该对象确实不拥有） |
| `coverage.rs` | `frozen_provider_gate` 为 provenance 与 opcode 列各加一条路由；`provenance_gap` 在 `NativeAtoms` 与 `FrozenProjection` 两域都堵住「翻旗即 Complete」 |
| `indexes/columns.rs` | 5 列 `assembled_projection: false → true` |

**主代理无需应用任何 export 变更**：全部改动落在既有模块内，`lib.rs` 未改。

## 验证

| 命令 | 结果 |
|---|---|
| `cargo test --offline -p mdd-facts` | 145 lib + 10 + 1 + 6 + 3 + 1 doc + 4 doctest，**0 失败** |
| `cargo clippy --offline -p mdd-facts --all-targets -- -D warnings` | 通过，**0 warning** |
| `cargo check --offline --workspace --all-targets` | 通过 |
| `python -I .../run_probe.py` | 探针通过（rustc 直编，未新增 Cargo target） |
| `python -I .../readback.py` | **passed，0 失败**；6 行 `dex_files` + 24 行 `methods` 独立复算与 A0 三方一致 |

独立 oracle 不复用被测解析器：`readback.py` 自己解 `string_ids`/`type_ids`/`proto_ids`/
`type_list`，并从 zip 中央目录读 APK 成员名。

## 仍需主代理决策的事项

1. **台账与 ledger 同步（最重要）**：`conformance/facts/required-columns.json` 的 5 列
   `production_projection` 仍是 `unassembled_production_relation`；
   `conformance/facts/compile_column_ledger_v*.py`、`qualify.py`、`audit_columns.py`、
   `readback_column_ledger_v*.py` 里有 `unassembled_projection_columns == 69` 的硬断言。
   这属于共享文件单写点，本轮按约束未改。
2. **`SelectedDex` 序列化面变化**：新增 `member_name`/`archive_member_ordinal` 两字段。
   `scope_id`/`scope_content_key` 前映像**未变**（仍只用 content_id、member ordinal、
   header offset），既有 scope 承诺值不变；但导出 JSON 形状变了。已确认
   `conformance/facts/verify_cross_dex_identity.py` 只读 `selected.file_id`，不受影响。
3. **raw DEX 的 `entry_name` 策略**：本轮取捕获路径叶子名，与记录的 A0 一致
   （`classic-035.dex`）。台账只写 "explicit entry policy"，未指定细节；若要改策略需同步
   修改 `dex_file_provenance` 的 `(None, None)` 分支与测试。
4. **`string_pool_id` 的 UInt32 目录赋值**：`dex_file_rows` 要求调用方按 roster 逐个传坐标
   （fact 层无 UInt32 池号，本轮不发明）。上一轮证据已把该列 `field_type` 降为 partial；
   要判为完全合格需主代理定义正式目录赋值契约并同步 schema。
5. **`param_descriptors` 的资格措辞**：编码规则已具名并证明全域，但未签发 profile。
   台账是否把「编码已定义 / profile 未签发」分开记录，需要主代理确认。
6. **非 UTF-8 provenance 缺少端到端 fixture**：`ENTRY_NAME_NOT_UTF8` 与
   `SOURCE_PATH_NOT_UTF8` 只有构造性单测（直接改 `SelectedDex` 字段），
   没有真实 APK + 非 UTF-8 成员名的端到端用例；Windows 上构造非 UTF-8 路径不稳定，
   本轮如实记录为未覆盖。

## 声明

- 未声称 `admitted` / `task_complete_proven` / profile 签发。
- 未做性能测量，无性能声明。
- 未运行 HostLab 工作负载与私有输入。
- 未修改 `conformance/**`、`STATE.md`、`tasks/backlog.json`、其他 crate。
