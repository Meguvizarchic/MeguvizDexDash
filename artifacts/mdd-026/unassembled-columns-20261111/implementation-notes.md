# MDD-026 未装配列收口：实现说明

日期：2026-11-11
代码范围：`crates/mdd-facts/src/**`（5 个文件改动 + 1 个测试文件）
约束核对：未改 `lib.rs` 的 `pub mod` 列表、未改 `Cargo.toml`/`Cargo.lock`、未新增依赖、
未新增 crate、未新增模块文件、未改 `STATE.md`/`tasks/backlog.json`/`conformance/**`。

## 1. 设计取舍

### 1.1 为什么 provenance 两列不放进 `MetadataFacts`

`MetadataFacts::build(snapshot, inventory, dex_index, limits)` 确实同时拿到了 `Snapshot` 和
`ArchiveInventory`，但 `MetadataFacts` 把它压缩成 `MetadataSource`
（`snapshot_id`/`dex_occurrence_id`/`physical_dex_id`/`member_id`/`source_occurrence_id`/
`content_id`），路径与成员名在构造时就被丢弃了。

两条路可选：
- (a) 往 `MetadataSource` 加 `source_path`/`entry_name` 字段；
- (b) 在 `SelectedScope` 上加 scope 级投影。

选 (b)，理由：
- `MetadataSource` 是 6 个 fact 对象（metadata/definitions/code/annotations/references/
  raw_fingerprints）共用的身份结构，`references.rs::same_source` 逐字段比较它。
  加两个只在 `dex_files` 一列上用的文本字段会污染所有层的身份比较与序列化，
  并且让 `MetadataFacts` 单独持有「不属于 metadata 层」的值。
- `SelectedScope` 本来就是 snapshot + inventory 的组合层，且 `SelectedInput.origin_display`
  已经在那里；`SelectedDex` 只要补两个从 `DexCandidate::blob.identity` 抄过来的字段即可。
- `scope_id` 的前映像计算完全不看这两个新字段（仍只用 `content_id`、
  `archive_member_ordinal`、`logical_header_byte_offset`），所以既有 scope 承诺值不变。

### 1.2 为什么 `dex_file_rows` 要求调用方传 `string_pool_ids`

fact 层没有 UInt32 池号：`StringPoolIdentity::string_pool_id` 是内容派生的 `String`。
本轮沿用既有约定（`MetadataFacts::dex_file_rows(file_id, string_pool_id)` 也是调用方坐标），
但把 28 行的枚举放在 scope 上，所以需要「每个选中 DEX 一个坐标」。
传入长度不匹配时报 `InvalidArgument`，不截断、不补零——避免静默产生错误的目录号。

### 1.3 为什么 `param_descriptors` 不需要 compatibility profile 签发

台账 boundaries 原文是："native ordered parameter_descriptors vector is exact;
compatibility UTF8 text serialization is separately unqualified"。
本轮把它拆成两件事：

1. **向量 exact**：可复算，见 `readback.py`（从 `proto_ids` 的 `parameters_off` 读
   `type_list`，再解 `string_ids`/`type_ids`）——24 行与 A0 三方一致。
2. **comma join 的全域性**：`mdd-dex` 的 `scalar_string` 在**读类型阶段**就用
   `strict_utf8()` 校验描述符，非标量直接 `NON_SCALAR_DESCRIPTOR_OR_SHORTY` 拒绝。
   所以进入 `MethodRow` 的描述符必然是标量 UTF-8，`join(",")` 不可能失败、不可能有损。

结论：编码规则明确（`comma-separated-utf8-v1`），在该域内全域；但
`compatibility_profile_admitted` 仍为 `false`，本轮不签发 profile。
这与台账"serialization separately unqualified"并不冲突：不是「无法序列化」，
而是「未作为 compatibility profile 签发」。

### 1.4 为什么 opcode 两列归 `MethodCodeFactViews` 而不是 `DefinitionFacts`

`DefinitionFacts` 只有 `DexDefinitions`（含 `MethodBody::Present { code_byte_offset,
declared_insns_size }`），拿不到解码后的指令流。要算 `opcode_count` 必须：
- 用 `code_byte_offset` 在同一 occurrence 的 `CodeFacts` 里定位物理 code item；
- 校验 `declared_insns_size` 与 `insns_range` 一致；
- 取 `CodeItem::instructions`（已解码普通指令）。

这些前置校验全部在 `MethodCodeFactViews::build`/`body` 里，且 `build` 要求
`code_layout_coverage == Complete`。所以完整 `methods` 关系只能在那个视图上装配。
`DefinitionFacts` 继续对这两列报 `IncompleteFacts`（它确实没有），但错误明细新增
`assembled_by=MethodCodeFactViews::method_rows`，让调用方知道去哪拿。

`insns_size` 明确不用作 `opcode_count` 的替代：`insns_size` 是 code unit 数（含 payload），
`opcode_count` 是解码后的普通指令条数。测试里 `packed-switch`/`sparse-switch`/`fill-array`
的 payload 情形已有既有覆盖（`decoded_opcode_iteration_excludes_payload_words`），
本轮新增的 A0 对照也逐行验证了非等价（例如 `dynamic` 的 `caller` 是 16 条指令，
而 `insns_size` 不同）。

### 1.5 假完成路径的处理

上一轮 Reviewer 指出 `assembled_projection` 被 `coverage.rs` 消费：翻旗后只要 view 存在
就报 `Complete`。本轮 5 列翻旗后补了两处防线：

1. `frozen_provider_gate` 把 provenance 两列路由到 `SelectedScope::require_dex_file_columns`，
   把 opcode 两列路由到「definitions + complete code layout」条件；provider 缺失返回
   `Some(None)` → `column_provider_not_built`。
2. 新增 `provenance_gap`，在 `NativeAtoms` 与 `FrozenProjection` 两个域都检查
   `dex_file_provenance` 是否可表示；不可表示则 `Unknown` + 具名 reason。
   测试 `dex_file_provenance_policy_and_budgets_fail_closed` 构造了
   `member_name = None` + `archive_member_ordinal = Some(3)` 的 scope，验证得到
   `UnsupportedQuery / ENTRY_NAME_NOT_UTF8`。

## 2. 逐文件改动

| 文件 | 改动 |
|---|---|
| `crates/mdd-facts/src/indexes/columns.rs` | 5 列 `assembled_projection: false → true` |
| `crates/mdd-facts/src/indexes/scope.rs` | `SelectedDex` 两字段；`DexFileProvenance`；`ScopeDexFileRow`；`dex_file_provenance`；`require_dex_file_columns`；`dex_file_rows`；4 个新测试 |
| `crates/mdd-facts/src/definitions.rs` | `MethodRow.param_descriptors`；`PARAM_DESCRIPTOR_ENCODING`；`parameter_descriptors_text`；门控只拒 opcode 两列；`MethodFactViews::method_count`；A0 对照测试 |
| `crates/mdd-facts/src/code.rs` | `MethodCodeRow`；`require_method_columns`；`method_rows`；2 个新测试 |
| `crates/mdd-facts/src/metadata.rs` | 文档指向 `ScopeDexFileRow`；provenance 门错误新增 `assembled_by`；契约断言改为 `["opcode_count","opcode_hex"]` |
| `crates/mdd-facts/src/coverage.rs` | `frozen_provider_gate` 三分支；`provenance_gap`；`provider_gate_rejection` 测试改为断言新语义 |
| `crates/mdd-facts/src/indexes/tests.rs` | 未装配集合断言改为空集；新增 `newly_assembled_columns_keep_contract_type_and_nullability` |

## 3. 交付目录内容

| 文件 | 说明 |
|---|---|
| `SUMMARY.md` | 5 列结论、投影变更、待决事项 |
| `per-column-verdict.md` | 逐列判定与实现（本文件的前置详版） |
| `implementation-notes.md` | 本文件 |
| `probe_rows.rs` | 独立 rustc 探针源码（调用生产行 API） |
| `run_probe.py` | 编译 + 运行探针，记录 argv/exit/digest |
| `native-rows.json` | 探针输出（`dex_files` 3 用例 6 行 + `methods` 3 用例 24 行） |
| `readback.py` | 独立复算 + 与 A0 三方比对 |
| `readback.json` | readback 结果（passed，0 失败） |
| `probe.json` | 探针记录（rlib 哈希、源码哈希、行数） |
| `build/`、`compile/`、`run/` | 探针三步的 stdout/stderr/record |
| `test-record.json` | 测试与验证记录 |
| `cargo-test.log`、`cargo-clippy.log` | 原始日志 |

## 4. 复现命令

```bash
cargo test --offline -p mdd-facts
cargo clippy --offline -p mdd-facts --all-targets -- -D warnings
python -I artifacts/mdd-026/unassembled-columns-20261111/run_probe.py
python -I artifacts/mdd-026/unassembled-columns-20261111/readback.py
```

`run_probe.py` 从 `cargo build --message-format=json` 拿到 cargo 实际链接的 rlib 路径，
避免用目录 mtime 选中签名不同的同僚构建（那会导致 `MddError` 名义不同而 `?` 无法转换）。
