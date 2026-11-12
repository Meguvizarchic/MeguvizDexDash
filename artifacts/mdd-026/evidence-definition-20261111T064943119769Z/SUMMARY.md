# MDD-026 定义/头部关系组证据汇总

目录：`artifacts/mdd-026/evidence-definition-20261111T064943119769Z/`
生成时间：2026-11-11（UTC）
性质：**只是证据记录，不签发 MDD-026，不声称 task_complete_proven / profile_admitted。**

## 范围与结果

- 范围内关系：`dex_files`(28)、`strings`(3)、`types`(4)、`classes`(8)、`class_interfaces`(5)，共 **48 列**。
- 新闭合为六类全满足的列：**40 列**。
- 仍为 partial 的列：**8 列**（全部是各关系的 occurrence 主键列，multiplicity 只能 partial）。
- 仍为 missing 的列：**0 列**。

### 新闭合的 40 列

| 关系 | 列 | 闭合类别 |
|---|---|---|
| dex_files | 24 个 header 字节列（byte_len…data_off） | multiplicity 由 missing → satisfied |
| strings | string_idx、value | multiplicity 由 partial → satisfied |
| types | type_idx、descriptor、java_name | multiplicity 由 partial → satisfied |
| classes | class_def_idx、class_idx、descriptor、access_flags、superclass_descriptor、interface_count、source_file | multiplicity 由 partial → satisfied |
| class_interfaces | class_idx、ordinal、interface_type_idx、interface_descriptor | multiplicity 由 partial/missing → satisfied；order 由 missing → satisfied |

### 仍缺的 8 列及原因

| 列 | 状态 | 原因 |
|---|---|---|
| dex_files.file_id | partial | 两个 occurrence 的 file_id 必然不同，比较输出中不存在逐字节相同的行；只能证明行数（2）来自独立 oracle 且比较对丢行敏感，无法锻炼 exact-duplicate 保持 |
| dex_files.string_pool_id | partial | 同上；且 native 物理 pool id 是内容派生标识，与 A0 的 occurrence 局部编号语义不同，不能混为一行 |
| dex_files.source_path | partial | 同上 |
| dex_files.entry_name | partial | 同上 |
| strings.string_pool_id | partial | 同上 |
| types.file_id | partial | 同上 |
| classes.file_id | partial | 同上 |
| class_interfaces.file_id | partial | 同上 |

这 8 列的其余五类（field_type/null/order/source/raw_fingerprint）均为 satisfied。

## 独立 oracle 与独立性论据

- `oracle_bytes.py`：纯 Python 标准库（zipfile/struct/hashlib/zlib）逐字节读取 DEX/APK，从 header、string_ids、type_ids、class_defs、interface type_list 枚举行。
  - 不 import 任何 Rust crate、不 import mdd-*、不调用 A0、不读取任何已记录输出。
  - 行数、行内容、行序均来自同一份源字节；丢行/去重/换序会改变输出序列并使比较失败。
- A0（dexsql，sha256 `f354ebcf…`）作为第三方独立 parser，提供同投影的表。
- native `probe_all.exe` 只通过 mdd-facts 公共 API 读取事实并打印 JSON，自身不做比较。
- 三者在 `run_evidence.py` 中做**序列比较**（列表相等），不用 Counter/multiset。

## 证据布局

- `oracle_bytes.py`：独立字节 oracle。
- `make_fixtures.py` + `fixtures.json`：合成 `duplicate-content.apk`（classes.dex 与 classes2.dex 内容完全相同的合成 APK）。
- `probe_all.rs`：native 事实探针；`run_evidence.py` 用 rustc 链接 workspace rlib 编译，命令记录在 `evidence/compile-probe/record.json`。
- `run_evidence.py`：主 harness，输出 `result.json`。
- `readback.py`：独立重读 captured A0/native 输出并重算比较，输出 `readback.json`（passed，33 个投影、288 条 verdict、70 个源文件）。
- `evidence/`：
  - `native-<case>/stdout.txt`：native 探针输出（definitions-single、duplicate-content-apk、null-coverage-classes）。
  - `a0-<case>-<relation>-{full,content}/stdout.txt`：A0 表。
  - `compile-probe/`：编译记录。

## 关键做法

- **multiplicity**：合成 APK 中两个 DEX 成员内容完全一致。对非主键列使用 content 投影（去掉 file_id/string_pool_id），两个 occurrence 的行逐字节相同，因此比较输出含 exact duplicate；行数由 Python oracle 枚举，丢行或去重会改变计数并失败。`exact_duplicate_rows_compared` 被单独记录（header 1、strings 32、types 9、classes 4、class_interfaces 2）。主键列单独用 full 投影比较，无 exact duplicate，如实记 partial。
- **order**：native 探针按引擎自然发射顺序输出，oracle 按 class_def/type_ids/string_ids 物理顺序枚举；直接比较序列。class_interfaces 的 5 列由此从 missing 变为 satisfied。其余关系的 order 也用同一序列比较复核。
- **null**：新增 `null-coverage-classes`（4 个既有 class_source fixture），观察到 `superclass_descriptor` 与 `source_file` 同时存在 NULL 与非 NULL；非可空列全部非 NULL。

## 使用的源 SHA256（关键项）

| 文件 | SHA256 |
|---|---|
| tests/fixtures/definitions/generated/definitions-035.dex | 4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc |
| tests/fixtures/class_source_boundary/generated/null-source.dex | 5e4198d669ae1bca0d620f255d85c4d5e8688811e716641fdc71a93f4df24603 |
| tests/fixtures/class_source_boundary/generated/empty-source.dex | 2a25adbe587475853fa544789113dffea5c885cdb9bab37ed21422d0a2e02b40 |
| tests/fixtures/class_source_boundary/generated/surrogate-source.dex | daf037df44bfa95b2cd0b3b3237bcc704fc83fc54eb1d994f8a4d6c7ff84fe2a |
| tests/fixtures/class_source_boundary/generated/root-empty-source.dex | 68409be64333a8b5737faab6219f0d48f3b998e4a02a60bb09d9728a4fdd4ab7 |
| evidence/duplicate-content.apk | 5d3ad17e18fd25c956523911015a018742e1c238dba1d974c69d7b98b4fc6590 |
| artifacts/mdd-026/column-audit-v10/audit_six_categories.py | 1ab6083520e6829960819d8d5cff879703c492e9f043814352fd4c4356c6926c |
| artifacts/mdd-026/column-ledger-v9/20261029T051751932521Z/column-ledger.json | 3fdb8fa0d565bd094c64cd786c8289a7dac4abb69d2713856f4e3f3e1d8c7676 |
| Cargo.toml | 4c4d63619571e87e67d85457ecda584dc0e23ad3634fb7901caeda81bdcbc571 |
| Cargo.lock | 954c2066815c971595782dc799f9dcd64c4e3d1c748cc1133991788fb3942844 |
| A0 dexsql | f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448 |
| native probe_all.exe | 见 `result.json` 的 `probe_binary_sha256`（rustc 输出不保证逐位可复现；源码 `probe_all.rs` 与所链接 rlib 路径均已记录，readback 会核对当前二进制） |

全部 70 个源文件（含 crates/mdd-{dex,input,types,facts} 全部 .rs）的 SHA256 见 `result.json` 的 `sources` 字段，`readback.py` 会逐个复核。

## 限制

- 小合成 fixture，不覆盖私有输入、完整 HostLab 语料、SQL transport、跨平台或性能。
- content 投影去掉 occurrence 主键列，因此 exact duplicate 来自两个内容相同的 occurrence；主键列本身只能 partial，未降低标准。
- 本目录不修改任何生产代码、共享配置或 column-audit-v10/conformance 既有 harness；现有 harness 仅被只读引用。
