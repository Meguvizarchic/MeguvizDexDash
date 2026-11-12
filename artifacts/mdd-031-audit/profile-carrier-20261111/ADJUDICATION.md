# 归属研判：MDD-031「阻断对应 profile」vs MDD-035「profile 准入门禁」

- 日期：2026-11-11（UTC+8）
- 角色：MDD-031 profile 准入载体子代理
- 只读参考：`tasks/backlog.json`、`docs/01_DECISIONS_AND_DEPENDENCIES.md`、`docs/02_ARCHITECTURE_AND_CONTRACTS.md`、`docs/03_HOSTLAB_MIGRATION.md`、`docs/04_VALIDATION_AND_PERFORMANCE.md`、`compatibility/ledger.json`、`conformance/manifests/profile-requirements.json`
- 结论先行：**是两个层次，不是同一机制。MDD-031 应在自身范围内提供「阻断」载体；「准入」仍归 MDD-035。**

## 1. 原文对照

MDD-031（`in_progress`，depends_on MDD-006、MDD-030），第 5 条 acceptance：

> 所有查询绑定统一 snapshot/session；兼容失败保留具体反例并**阻断对应 profile**

MDD-035（`todo`，depends_on MDD-026/032/033/034）标题与 acceptance：

> 完成必需查询组合验证与 **profile 准入门禁**
>
> 1. 冻结 HostLab 全部必需语句在完整 facts 上逐字段、逐类型、重复性和要求的顺序一致
> 2. complete 只有在 required scope 的 input/facts 完整、执行完成且无剩余页时成立
> 3. 同一请求在 typed IR、SQL 桥与保守参考路径之间没有静默语义差异
> 4. 分页/取消/TEMP/损坏输入组合反例通过，失败和未知格式不被记作正常 MISSING
> 5. 仅登记查询层通过，整个 hostlab-audit-v1 工作流需 MDD-055 后才可宣称可替代

MDD-035 的 scope 是「组合验证 facts、SQL/typed IR、TEMP、分页和预算」「建立 hostlab-audit-v1 查询层资格及兼容 profile 分项状态」。它的输出是 `conformance/manifests/query-profile-qualification.json` 与 `artifacts/mdd-035/required-query-results.json`，都是**外部资格产物**，不是引擎内的运行时机制。

## 2. 语义层级

两者方向相反：

| | MDD-031 第 5 条 | MDD-035 |
| --- | --- | --- |
| 判定方向 | 负向：某个 shape 不成立 → 该 profile 不可用 | 正向：必需集合全部成立 → 才允许 admitted |
| 触发时机 | 运行时、单条查询即可产生 | 离线、需要完整 facts 上的冻结语料全量比较 |
| 依赖 | 只需本 crate 已知的 `UNSUPPORTED_QUERY` | 需完整 facts、typed IR 对照、分页/取消/TEMP/预算组合、MDD-026/032/033/034 |
| 产物 | 引擎内可查询的阻断状态 + 反例 | `query-profile-qualification.json` + ledger 更新 |
| 失败后果 | profile 当场不可用（fail-closed） | 该 profile 不进入 admitted |

关键点：**准入需要 MDD-031..034 的产物，反过来不成立。** 如果「阻断」也一起推迟到 MDD-035，那么在 MDD-035 开始之前，一个已知会让 `hostlab-audit-v1` 失败的 shape 在运行时不会有任何后果——这恰好是第 5 条要禁止的状态。反过来，若把「准入」提前放进 MDD-031，则等于在无完整 facts 语料的情况下签发资格，直接违反 `docs/01` ADR-002 的「准备一个 query 能成功不意味着 profile 已 admitted」与 `conformance/manifests/profile-requirements.json` 的 `full_process_fallback_allowed_for_qualification: false`。

因此：**阻断必须在产生阻断证据的那一层就地强制（MDD-031 的 SQL 桥）；准入只能在拿到全部证据后由独立验证方判定（MDD-035）。** 二者共用 profile 名字与 ledger 记录，但不是同一机制。

## 3. 与 Reviewer 第二轮判断的关系

Reviewer 第二轮称「该机制应归 MDD-035，MDD-031 提前建注册表属越界」。该判断成立于一个特定读法：把 registry 理解为「准入登记表」。本轮的边界是：

- 提供的是 **block-only registry**：只有 `block()`，没有任何 `admit()`/`issue()` 接口，也没有从 registry 回写 `compatibility/ledger.json` 的路径；
- 不改变 `SqlResult.profiles_admitted`（仍恒空），不签发资格；
- 阻断只作用于显式声明了 profile 的 `SqlBridge`，默认构造的桥行为完全不变。

MDD-035 需要的正向登记表（哪些语句通过了）仍然由 MDD-035 自己产出，本 crate 不参与。

## 4. 结论

1. 该机制是**两个层次**：MDD-031 的「阻断」是运行时负向门禁；MDD-035 的「准入」是离线正向资格判定。
2. MDD-031 **应当在自身范围内提供最小阻断载体**，否则第 5 条的后半句在整个 M3 期间是真空。
3. 阻断载体**不得**扩张为准入载体；`profiles_admitted` 保持恒空，ledger 不改写。
4. 因此本轮选择「实现最小载体」分支，而非「归 MDD-035」分支。
