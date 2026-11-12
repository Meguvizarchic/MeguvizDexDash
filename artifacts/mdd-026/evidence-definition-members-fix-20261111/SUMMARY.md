# MDD-026 定义/成员关系组证据修复汇总

目录：`artifacts/mdd-026/evidence-definition-members-fix-20261111/`
生成时间：2026-11-11（UTC）
性质：**只是证据记录，不签发 MDD-026，不声称 task_complete_proven / profile_admitted。**

## 0. 结论

- 范围内 107 列（`dex_files` 28、`strings` 3、`types` 4、`classes` 8、`class_interfaces` 5、
  `methods` 14、`class_fields` 8、`class_methods` 8、`method_strings` 8、
  `method_field_accesses` 12、`method_used_types` 9）。
- 六类全满足：**92 列**；partial：**14 列**；missing：**1 列**。
- 104 个关系/用例/投影比较全部通过（native 序列相等 104/104，A0 序列相等 104/104）。
- 所有适用的负控制都被拒绝（0 个 applicable-but-not-rejected）。
- `readback.py` 重读全部 captured 输出并重算 3271 项检查，**passed=true，0 失败**。

## 1. 修复项逐条结果

### P1-2 `class_interfaces.ordinal`（ordinal 恒为 0）

- 上一轮所有用例中每个类最多 1 个 interface，ordinal 只会是 0。
- 项目 fixture `tests/fixtures/definitions/generated/duplicate-interface.dex`
  （sha256 `6dd171bf…`）确实含 `Lfixture/I1;` 的 2 个 interface（ordinal 0/1），
  但它是生成器里标记为 `DUPLICATE_INTERFACE` 的**错误用例**：引擎在
  `DefinitionFacts::build` 阶段直接拒绝（`InvalidInput / DUPLICATE_INTERFACE`），
  不能作为正向 native 用例。A0 对同一字节是宽容的（接受并输出两行）。
- 处理：
  - 新增有效合成 fixture `fixtures/generated/two-interfaces.dex`
    （sha256 `1c2eb98c…`，由本目录 `generate_two_interfaces.py` 生成，
    项目生成器未修改）：类 `Lfixture/Base;` 实现 `Lfixture/I0;` 与 `Lfixture/I1;`，
    ordinal 0/1。
  - `two-interfaces` 用例进入 native/oracle/A0 三方比较：3 行，ordinal 取值 `{0,1,0}`，
    native 与 A0 序列均与独立 oracle 相等。
  - 负控制：交换相邻不同行、删行、改单元格、key 去重、NULL 注入全部 rejected=true。
  - `duplicate-interface.dex` 作为**拒绝控制**单独记录：引擎 exit=1 且
    `DUPLICATE_INTERFACE`，A0 接受（3 行），语义差异如实记录。
- 结果：`class_interfaces.ordinal` 六类全满足；`exact_duplicate_rows_compared=2`
  （来自 duplicate-content-apk 的 content 投影）。

### P2-2 `dex_files.string_pool_id`（循环论证）

- 上一轮 `oracle_bytes.py` 把 `string_pool_id` 编成 `file_id`，与 A0 的 occurrence
  局部编号对齐；native 侧的 `string_pool_id` 从未进入比较。这是循环论证。
- 处理：独立 oracle 从字节重算**内容派生**标识
  `sha256:<content>:physical-dex:0:string-pool:<string_ids_off>:<string_count>`，
  与 native 的实际值比较；A0 的 `string_pool_id` 是 occurrence 局部 UInt32，
  另用 occurrence 索引作为期望值比较。两种语义分别记录，不再混为一行。
- 事实：声明 schema（`column-ledger-v9`）为 `UInt32`，引擎实际输出为 Utf8 内容派生串，
  A0 为 UInt32 occurrence 局部编号；生产 query executor
  （`crates/mdd-query/src/executor/facts.rs`）也把 `string_pool_id` 声明为 `Utf16`。
- 结果：`dex_files.string_pool_id` 与 `strings.string_pool_id` 的 `field_type`
  如实降为 **partial**（语义/类型不一致），并保留独立 sha256 重算证据；
  null/order/source/raw_fingerprint 仍满足。`strings.string_pool_id` 的
  multiplicity 由 duplicate-content-apk 的 32 个 exact duplicate 行满足。

### P2-3 定义组零负控制

- 上一轮定义组只有序列相等断言，没有任何负控制。
- 处理：`run_evidence.py` 对每个关系/用例/投影都计算并记录：
  `swap_adjacent_distinct_rows`、`drop_first_row`、`mutate_first_cell`、
  `key_dedup_changes_count`、`exact_dedup_changes_count`、逐列 NULL 注入/删除。
- 结果：所有适用的控制 `rejected=true`；空转控制显式记 `not_applicable`。
  `result.json` 的 `negative_controls` 字段逐列给出 `true/false/not_applicable`。

### P1-3 `methods.file_id`（常量比常量）

- 上一轮 `run_evidence.py` 把 `file_id: 0` 写死进 native 行，oracle 也写死 0。
- 处理：新探针 `probe_members.rs` 通过公共 `SelectedScope` 取 `selected.file_id`，
  两个输入时 native 输出 0/1；独立 oracle 用同一 occurrence 索引；A0 多输入
  `--input members-dup --input classic` 输出 0/1。三方交叉核验。
- 结果：`members-dup-classic` 的 methods 行 native/A0/oracle 的 file_id 集合均为
  `{0,1}`，序列相等；`methods.file_id` 的 field_type/null/order/source/raw_fingerprint
  满足，multiplicity 因每 occurrence 内 file_id 重复但无 exact duplicate 行记 partial。

### P1-4 漏掉第三方 oracle 的 methods

- 上一轮 `a0_specs` 覆盖 5 个关系，独漏 `methods`。
- 处理：A0 specs 现在覆盖全部 6 个成员关系，包括 `methods`（含多输入）。
- 结果：`methods` 的 A0 有序表与独立 oracle 有序表在 5 个成员用例上全部相等。

### P1-5 隐瞒引擎自报门控

- `native/native-general-members-dup-classic/stdout.txt` 的 `method_column_gates`
  记录 `param_descriptors` / `opcode_count` / `opcode_hex` 为 `INCOMPLETE_FACTS`。
- 处理：`probe_members.rs` 原样输出 `method_column_gates`；`result.json` 记录全部
  8 个 occurrence 的门控；这三个列的 `field_type` 与 `raw_fingerprint` 如实降为
  **partial**，note 标注 `engine self-reported gate: INCOMPLETE_FACTS`。
- 结果：`methods.param_descriptors` / `opcode_count` / `opcode_hex` 为 partial，
  不再声称 satisfied。

### P2-4 native_subjects 只校验 content_id

- 处理：`check_native_terminal()` 对每个 native 进程终端校验
  `operation_status == "ok"`、`probe_complete is True`、`profile_admitted is False`，
  并逐个 occurrence 校验 `content_id == sha256:<fixture>`。
- 结果：全部 9 个 native 运行通过；readback 重新校验终端字段。

## 2. 仍缺的列与原因（15 列）

| 列 | 状态 | 缺失类别 | 原因 |
|---|---|---|---|
| dex_files.file_id | partial | multiplicity | 每 occurrence 一行，值唯一；无 exact duplicate，行数已由独立 oracle 枚举 |
| dex_files.entry_name | partial | multiplicity | 每 occurrence 一行，值唯一 |
| dex_files.source_path | partial | multiplicity | 两个相同 occurrence 共享同一 APK 路径，但无整行 exact duplicate |
| dex_files.string_pool_id | partial | field_type, multiplicity | 声明 UInt32 vs 引擎 Utf8 内容派生 vs A0 UInt32；无 exact duplicate 行 |
| strings.string_pool_id | partial | field_type | 同上语义/类型不一致（multiplicity 已由 32 个 exact duplicate 行满足） |
| types.file_id / classes.file_id / class_interfaces.file_id / class_fields.file_id / class_methods.file_id / methods.file_id | partial | multiplicity | 每 occurrence 内 file_id 重复但跨 occurrence 不同，full 投影无 exact duplicate 行 |
| methods.param_descriptors / opcode_count / opcode_hex | partial | field_type, raw_fingerprint | 引擎自报 `INCOMPLETE_FACTS`；探针侧推导不是合格关系列 |
| method_field_accesses.using_type | missing | null | schema nullable，但 DEX 字段访问 opcode（0x52–0x6d）的 mnemonic 全部属于 iget/sget/iput/sput，合法 DEX 不可能产生 NULL；NULL 分支结构性不可观测 |

这些缺口都是结构性或引擎自报门控，未通过降标准掩盖。

## 3. 独立 oracle 与独立性论据

- `oracle_bytes.py`：纯 Python 标准库（zipfile/struct/hashlib/zlib）逐字节读取
  DEX/APK，从 header、string_ids、type_ids、class_defs、interface type_list 枚举行；
  重算内容派生 `string_pool_id`。不 import 任何 Rust crate、mdd-*、A0 或已记录输出。
- `oracle_members.py`：纯 Python stdlib `struct` 字节级 DEX reader；不 import 任何
  Rust crate、不 import 仓库 reference oracle。枚举 6 关系行、NULL、重复行、行数。
- A0（dexsql，sha256 `f354ebcf…`）作为第三方独立 parser，覆盖全部 12 个关系
  （6 定义 + 6 成员），提供同投影的有序表。
- native 探针 `probe_definition.rs` / `probe_members.rs` 只通过 mdd-facts 公共 API
  读取事实并打印 JSON，自身不做比较。
- 三者在 `run_evidence.py` 中做**序列比较**（列表相等），不用 Counter/multiset。

## 4. 证据布局

- `oracle_bytes.py` / `oracle_members.py`：独立字节 oracle。
- `generate_two_interfaces.py` / `fixtures/generated/two-interfaces.dex`：有效双接口 fixture。
- `make_fixtures.py` / `evidence/duplicate-content.apk`：内容相同的 APK（精确重复行）。
- `probe_definition.rs` / `probe_members.rs`：native 事实探针（真实 file_id + 门控）。
- `run_evidence.py`：主 harness，输出 `result.json`。
- `readback.py` / `readback.json`：重读 captured 输出、重算比较与负控制、复核源 SHA256。
- `evidence/`：`native-<case>/`、`a0-<case>-<relation>-<projection>/`、
  `compile-probe_*`、`native-duplicate-interface-reject/`。
- `result.json`：107 列逐列 verdict、104 个比较、负控制、门控、拒绝控制、源 SHA256。

## 5. 使用的源 SHA256（关键项）

| 文件 | SHA256 |
|---|---|
| tests/fixtures/definitions/generated/definitions-035.dex | 4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc |
| tests/fixtures/definitions/generated/duplicate-interface.dex | 6dd171bf8a235353905bbb876a97c65ad3c6d96ec7435155f93a5016e7b5a176 |
| artifacts/mdd-026/evidence-definition-members-fix-20261111/fixtures/generated/two-interfaces.dex | 1c2eb98c8dd937c2c9e6769fd45ace66c7374944d84eef8c81b69130ab8bdca9 |
| artifacts/mdd-026/evidence-definition-members-fix-20261111/evidence/duplicate-content.apk | 5d3ad17e18fd25c956523911015a018742e1c238dba1d974c69d7b98b4fc6590 |
| artifacts/mdd-026/evidence-members-20261111T064757Z/fixtures/members-dup-035.dex | 5df38a9c768e50cc47de8eac943e88b422b5da8d2dd75ce84e00535ba09a59e7 |
| tests/fixtures/references/generated/classic-035.dex | 076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8 |
| tests/fixtures/class_source_boundary/generated/null-source.dex | 5e4198d669ae1bca0d620f255d85c4d5e8688811e716641fdc71a93f4df24603 |
| tests/fixtures/class_source_boundary/generated/empty-source.dex | 2a25adbe587475853fa544789113dffea5c885cdb9bab37ed21422d0a2e02b40 |
| tests/fixtures/class_source_boundary/generated/surrogate-source.dex | daf037df44bfa95b2cd0b3b3237bcc704fc83fc54eb1d994f8a4d6c7ff84fe2a |
| tests/fixtures/class_source_boundary/generated/root-empty-source.dex | 68409be64333a8b5737faab6219f0d48f3b998e4a02a60bb09d9728a4fdd4ab7 |
| A0 dexsql | f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448 |

全部源文件（含 crates/mdd-{dex,input,types,facts,query} 全部 .rs、Cargo.toml/lock、
rust-toolchain.toml、ledger、audit 脚本）的 SHA256 见 `result.json` 的 `sources` 字段，
`readback.py` 逐个复核。

## 6. 限制

- 小合成 fixture，不覆盖私有输入、完整 HostLab 语料、SQL transport、跨平台或性能。
- A0 是独立实现但不是规范；一致是证据不是证明。
- `method_field_accesses.using_type` 的 NULL 分支结构性不可观测，如实记 missing。
- `methods.param_descriptors` / `opcode_count` / `opcode_hex` 的探针侧推导不能替代
  引擎合格关系列，如实记 partial。
- `dex_files.string_pool_id` / `strings.string_pool_id` 的声明类型与引擎语义不一致，
  如实记 partial；未用任一语义伪造另一侧。
- 本目录不修改任何生产代码或共享文件；不签发 MDD-026。
