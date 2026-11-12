# MDD-026 成员/方法关系组证据 SUMMARY

- 证据目录：`artifacts/mdd-026/evidence-members-20261111T064757Z/`
- 范围：`methods`、`class_fields`、`class_methods`、`method_strings`、`method_field_accesses`、`method_used_types`，共 59 列。
- 结论：**28 列六类完全资格；31 列仍缺一类**（30 列 multiplicity=partial，1 列 null=missing）。
- 不声称 admitted / task_complete_proven；只提交证据与 verdict。

## 1. 相对 v10 矩阵的变化

v10（`column-audit-v10/six-category-audit.json`）中本范围 59 列全部 incomplete。
本次新证据闭合情况：

| 关系 | 列数 | v10 完全资格 | 现在完全资格 | 新闭合的类别 |
|---|---:|---:|---:|---|
| methods | 14 | 0 | 0 | 无（multiplicity 结构性 partial） |
| class_fields | 8 | 0 | 0 | order 8；multiplicity 3 列由 missing→partial |
| class_methods | 8 | 0 | 0 | order 8；multiplicity 2 列由 missing→partial |
| method_strings | 8 | 0 | 8 | null/order/multiplicity 全部 |
| method_field_accesses | 12 | 0 | 11 | order 12；multiplicity 12 由 partial→satisfied |
| method_used_types | 9 | 0 | 9 | order 9 |
| 合计 | 59 | 0 | 28 | |

逐列 `v10_to_now` 见 `result.json`。

## 2. 仍缺的列与原因

### 2.1 multiplicity = partial（30 列）

`methods` 14 列、`class_fields` 8 列、`class_methods` 8 列。

- 这三类关系的行标识（`method_idx` / `field_idx` / `class_idx+field_idx` /
  `class_idx+method_idx`）在**一个合法 DEX 内唯一**，因此不可能出现整行字节相同的
  compared row；exact-duplicate preservation 结构性不可观测。
- 独立 oracle 已证明行数来自字节枚举：删行会使计数比较失败（`dropped_first_row_rejected`）；
  在存在重复 key 的 slice 上按 key 去重也会失败（`key_dedup_changes_count=True`），
  无重复 key 的 slice 该控制为空转（见 `comparisons.json` 的 `negative_control_interpretation`）。
- 其中 `class_fields.field_idx/field_descriptor`、`class_methods.method_idx/method_descriptor`
  在单 fixture 内不重复，其 partial 来自**跨 fixture 合并比较**（与 v10 对 methods 的
  multiplicity 合并多 dump 的规则一致）；单 fixture 内它们仍是 missing。

### 2.2 null = missing（1 列）

`method_field_accesses.using_type`（schema nullable）。

- 引擎只在字段访问指令 mnemonic 以 `iget/sget` 或 `iput/sput` 开头时给出
  `get`/`put`，否则为 NULL；而 DEX 中所有字段操作数指令（0x52–0x6d）都在这四类里，
  因此**合法 DEX 的字段站点不可能产生 NULL using_type**。
- 证据观察到全部非 NULL 单元格，并验证了非 NULL 路径与 NULL 注入会被比较拒绝；
  NULL 分支不可观测，故如实报 missing。

## 3. 独立 oracle 与证据文件

| 文件 | 作用 |
|---|---|
| `oracle_members.py` | 纯 Python stdlib `struct` 字节级 DEX reader；不 import 任何 Rust crate、不 import 仓库 reference oracle。枚举 6 关系行、NULL、重复行、行数。 |
| `generate_fixture.py` / `fixtures/members-dup-035.dex` | 合成 DEX 035 fixture：重复 field/method 名、同方法内重复 sget-object/const-string/const-class（产生 exact duplicate 行）、一个无定义 method_id（产生 NULL 单元格）。生成器与 readback 一起记录。 |
| `readback_fixture.py` / `fixtures/members-dup-035.readback.json` | 独立的物理 readback：遍历 map_list、校验小端 header、string_data 的 ULEB 起点、code_item 4 字节对齐起点、class_data ULEB 起点，并与生成器 layout 对齐。 |
| `build_and_run_native.py` / `native/` | 原样编译仓库 conformance probe（`native_probe.rs`、`definition_projection_probe.rs`）并运行；记录 argv、stdout/stderr、sha256。 |
| `run_evidence.py` / `comparisons.json` | native 行序列 vs 独立 oracle 行序列的 order 比较；行数/重复/KEY 去重负控制；NULL 计数与 NULL 注入负控制；A0 SQL 表独立复核。 |
| `a0/` | 冻结 A0（dexsql）对 5 关系 10 个 slice 的有序表，与 oracle 有序相等。 |
| `result.json` | 逐列 verdict（relation/column/category/state/evidence_path/oracle/independence_argument）。 |

### 独立性论据

- Python oracle 只读取 fixture 字节，自行解析 header/map/string_ids/type_ids/proto_ids/
  field_ids/method_ids/class_defs/class_data/code_items/instructions；与 Rust 引擎无共享代码。
- native 行来自仓库 conformance probe 的进程终端，probe 源码 sha256 已记录，未修改。
- A0 是独立的 dexsql 实现，仅作第二 oracle；A0 与 oracle 的有序行相等。
- 负控制（交换两行、删行、改单元格、NULL 注入）均在所有 slice 上实际失败；key/exact 去重
  负控制在有重复的 slice 上失败，无重复的 slice 为空转，不是被接受的变异。

## 4. 使用的源文件 SHA256

见 `result.json` 的 `source_sha256`。关键项：

- `oracle_members.py`：`result.json` 中记录
- `fixtures/members-dup-035.dex`：`5df38a9c768e50cc47de8eac943e88b422b5da8d2dd75ce84e00535ba09a59e7`
- `tests/fixtures/references/generated/classic-035.dex`：`076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8`
- `tests/fixtures/definitions/generated/definitions-035.dex`：`4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc`
- A0：`f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448`

## 5. 限制

- 仅 tiny 合成 fixture；无 HostLab 工作负载、私有输入、跨平台或性能声明。
- A0 是独立实现但不是规范；一致是证据不是证明。
- `methods/class_fields/class_methods` 的 multiplicity 结构性 partial；`using_type` 的
  NULL 分支结构性不可观测。
- 本目录不修改任何生产代码或共享文件；不签发 MDD-026。
