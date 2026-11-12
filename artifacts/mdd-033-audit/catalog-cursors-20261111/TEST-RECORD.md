# MDD-033 测试记录（含反例与变异验证）

代码位置：`crates/mdd-session/src/catalog.rs`、`crates/mdd-session/src/cursors.rs`（行号为写入后实测）。

## 1. 命令与结果

| 命令 | 结果 | 原始输出 |
| --- | --- | --- |
| `cargo test --offline -p mdd-session` | **53 passed; 0 failed**；doc-test 0 passed | `test.stdout.txt` |
| `cargo clippy --offline -p mdd-session --all-targets -- -D warnings` | **0 warning, 0 error**，exit 0 | `clippy.stdout.txt` |
| `cargo test --offline -p mdd-query -p mdd-sql` | 201 passed + 213 passed；doc-test 3 + 1 passed | 见 §5 |
| `cargo test --offline -p mdd-worker` | 1 passed | 见 §5 |

本轮新增 23 条测试（catalog 10 条 + cursors 13 条），原有 30 条 lib 测试未删改；当前 lib 合计 53 条，全绿。

## 2. catalog 语义测试（acceptance 2 与 5）

| 测试 | 断言要点 | 反例 / 边界 |
| --- | --- | --- |
| `create_publishes_names_and_binds_generations` | 首次 create 返回 `Created{epoch:"1"}`；依赖定义 `epoch:"2"`；`resolve_at("derived", 1)` 为 `None` | 依赖名在自身代次之前不可见 |
| `cycle_and_self_reference_are_rejected_without_advancing_the_epoch` | `a→b→a` 报 `temp_error=cycle`、`path="a -> b -> a"`；`c→c` 同样失败；**两次失败后 epoch 不变、`a` 的 hash 与依赖不变** | 反例：环 + 自引用；且验证失败定义完全没有副作用 |
| `if_not_exists_keeps_the_original_definition_and_ignores_the_new_body` | `t` 已存在为 TABLE，用 `IF NOT EXISTS` 定义成 VIEW 且依赖 `never_defined`，返回 `Unchanged{kind:Table}`，epoch 不变，原 hash 保留 | 反例：新 body 引用不存在的名字也必须被整段忽略（对齐 preflight「原值 1 保留」） |
| `redefine_replaces_kind_and_drop_requires_the_matching_kind` | 同名替换返回 `Replaced{previous_kind:Table}`；对 VIEW 用 `DROP TABLE`（`if_exists` 取 true/false 各一次）都报 `drop_kind_mismatch`、消息 `use DROP VIEW to delete item`、epoch 与对象不变；正确 DROP 返回 `Dropped{epoch:"3"}`；`resolve_at("t",2)` 仍可见、`resolve_at("t",3)` 不可见 | 反例：`IF EXISTS` 不能吞种类错误 |
| `drop_of_an_absent_name_reports_the_kind_and_if_exists_is_a_noop` | `no such table: absent` / `no such view: absent`；`IF EXISTS` 返回 `Absent{epoch:"0"}` 且 epoch 保持 0 | 两种 kind 各测一次 |
| `forward_reference_is_rejected_and_the_definition_is_not_published` | `derived → future` 报 `unknown_relation`、消息 ``unknown relation `future` ``、epoch 0、`derived` 不存在；创建 `future` 之后 `derived` 仍不存在 | 反例：失败定义不自动复活（对齐 preflight） |
| `as_select_stays_deferred_until_the_sql_layer_injects_a_matching_handle` | 创建后为 `Deferred`；用错误 hash 注入报 `definition_changed`；正确 hash 注入返回 `Injected{epoch:"2"}`；重复注入报 `already_materialized`；重定义后回到 `Deferred` | 注入点契约：handle 必须与定义 hash 绑定 |
| `catalog_is_session_local_and_generations_do_not_leak` | session A 的 `local` 在 B 中不可见；B 可用同名不同 kind 定义；A 的 DROP 不影响 B | 跨会话隔离 |
| `prepared_query_keeps_its_temp_generation_after_a_redefinition` | 旧 query 绑定 epoch `"1"` 与旧 hash；redefine 后 `verify_query_temp_binding` 仍返回旧 hash/旧 kind；新 query 冻结 epoch `"2"` 且绑到新 hash/新 kind；对已 start 的 query 再 bind 报 `InvalidArgument` | 验收 2 核心反例：新定义**不**迁移旧 cursor |
| `drop_retains_the_generation_an_existing_query_already_bound` | DROP 之后当前解析为 `None`，但旧 query 的 `verify_query_temp_binding` 仍成功；新 query 绑定同名报 `unknown_relation` | 退役代次仍可被旧 query 读取 |

## 3. cursors 绑定测试（acceptance 1）

| 测试 | 断言要点 | 反例 / 边界 |
| --- | --- | --- |
| `native_cursor_binds_every_identity_component` | `CursorBinding` 同时含非空 `snapshot_id`、`session_id`、`query_id`、`catalog_epoch=0`、`worker_generation=0`、`request_key`、`schema_id`、`semantic_version`、三个 64 位指纹、`mode=NativeSnapshot`；无指纹的旧 `open_cursor` 进分页路径报 `cursor_binding_incomplete` | 缺失指纹不能被当作原生分页游标 |
| `forged_worker_generation_is_rejected` | 直接把存储的 `worker_generation` +1 后调用 `cursor_binding`，报 `InvalidCursor` + `page_error=worker_generation_changed` | 反例：伪造代次 |
| `a_new_worker_generation_invalidates_older_cursors` | 正常绑定 `worker_generation=0`；`claim_supervision` 后旧 cursor 报 `worker_generation_changed`（`worker_generation=0` vs `current=1`）；新开 cursor 为 `1`；drop lease 后旧 cursor 依旧被拒 | 代次只前进，不回退复活 |
| `cursor_requires_a_complete_fingerprint_spec` | 非 hex 的 AST 指纹、大写参数类型指纹各自被拒并指明字段 | 输入校验边界 |
| `native_page_envelope_and_metadata_agree` | 真实 `TerminalBuilder::page` 产出 envelope，`next_cursor`、`more_available`、`emitted_rows` 与 metadata 全部一致；空 token 报 `InvalidArgument`；所有行交付完后 `page()` 拒绝再声称续页；`native_complete()` 仍为 native 且无 continuation | `TerminalBuilder::page` 的首个生产形态调用 |

## 4. 混合页与 offset 反例（acceptance 3 与 4）

| 测试 | 断言要点 | 反例 |
| --- | --- | --- |
| `same_sql_same_schema_different_source_cannot_be_stitched` | 首页以 `source-a` 建立 claim；第二页 SQL/schema/total 全同、只有来源为 `source-b` → `source_changed`，回显期望指纹；随后用 `source-a` 的同类页仍被接受 | **验收 3 的直接反例**：来源变化但行数与 schema 相同 |
| `changed_schema_or_total_between_pages_is_rejected` | total `4→5`、total `4→None`、schema 改变三种都报 `query_schema_or_total_changed`；`cursor_page_count` 证明三次拒绝没有计入页数（仍为 1），之后合法页使其变为 2 | 三种 change 都是反例；并证明拒绝无副作用 |
| `inexact_total_is_also_fixed_by_the_first_page` | 首页 `total=None`，第二页声称 `Some(2)` → `query_schema_or_total_changed`，`total_rows="none"` | 反例：无精确总数也不能在页间"变成"有 |
| `response_paging_over_a_relational_limit_is_rejected` | `relation_limit=Some(100)` → `response_paging_over_relation_limit`；`relation_offset=Some(5)` 同样被拒；两者都无时才通过 | 反例：响应分页 + 关系 LIMIT/OFFSET 混用 |
| `paging_modes_never_share_a_token` | native+offset → `compat_offset_under_native_cursor`；compat+cursor token → `native_cursor_under_compat_offset`；两者同时 → `ambiguous_continuation`；`page_limit=0` → `page_limit_zero`；超上限 → `QuotaExceeded`；响应侧伪造双 continuation → `paging_mode_conflict`；`more_available` 与 continuation 不符 → `paging_more_available_mismatch` | 五个反例 + 合法对照 |
| `compat_offset_walks_pages_with_lookahead_and_no_cursor` | 首页 `next_request{offset:0,limit:2}`；admit 后 `more_available=true`、`next_offset="2"`、`reexecutions="1"`；`metadata()` 的 `mode=CompatOffset` 且 `next_cursor=None`；末页 `lookahead_exhausted` 后 `is_done()`、`next_request()` 为 `None`；再提交报 `offset_sequence_complete` | 正常路径 + 终态后继续提交 |
| `compat_offset_rejects_offset_gaps_source_change_and_missing_lookahead` | offset 跳到 4 → `query_page_identity_or_limit_mismatch`；来源变 → `source_changed`；短页无 lookahead → `lookahead_required`；带 `relation_limit` → `response_paging_over_relation_limit`；**四次拒绝后 `reexecutions()` 与 `admitted_rows()` 都还是 0**；随后合法页仍成功 | 四个反例 + 证明拒绝不计成本 |
| `compat_offset_budget_and_epoch_observation_are_explicit` | 两次重执行分别观察 epoch `0` 和 `1`（`catalog_epochs_observed` 逐页累积）；第三次超 `max_executions=2` → `QuotaExceeded` + `budget=max_executions`；`admitted_rows()` 停在 2 | 说明 offset 允许看到新 epoch，但成本硬上限 |

## 5. 回归（其他 crate）

依赖本 crate 的三个 crate 全部重新编译并跑测试，确认没有破坏：

```
cargo test --offline -p mdd-query   -> 201 passed; 0 failed （+ 3 doc-tests passed）
cargo test --offline -p mdd-sql     -> 213 passed; 0 failed （+ 1 doc-test passed）
cargo test --offline -p mdd-worker  ->   1 passed; 0 failed
```

`mdd-worker` 的 supervisor 测试覆盖 `claim_supervision` 成功/失败，因此它也验证了本轮新增的 `worker_generation` 递增没有破坏 supervision 的前置条件。

## 6. 变异验证（证明测试确实有效）

为了证明关键断言不是恒真，临时引入 6 处变异后重跑，确认对应测试变红，然后完整恢复源码（`grep "false &&"` 与 `git diff` 已确认无残留）。

### 6.1 cursors 变异（`mutation-cursors.red.txt`）

| 变异 | 变红的测试 |
| --- | --- |
| 删除 `source_fingerprint` 比对 | `same_sql_same_schema_different_source_cannot_be_stitched` |
| 删除 `worker_generation` 比对 | `forged_worker_generation_is_rejected`、`a_new_worker_generation_invalidates_older_cursors` |
| 删除 `relation_limit`/`relation_offset` 拒绝 | `response_paging_over_a_relational_limit_is_rejected` |

结果：`49 passed; 4 failed`（含上述 4 条）。

### 6.2 catalog 变异（`mutation-catalog.red.txt`）

| 变异 | 变红的测试 |
| --- | --- |
| 跳过依赖存在性校验 | `forward_reference_is_rejected_and_the_definition_is_not_published` |
| 跳过环检测 | `cycle_and_self_reference_are_rejected_without_advancing_the_epoch` |
| 跳过 DROP 种类比对 | `redefine_replaces_kind_and_drop_requires_the_matching_kind` |

结果：`50 passed; 3 failed`（含上述 3 条）。

## 7. 未执行的验证（如实声明）

- **not_run**：真实引擎 oracle 逐条对照（preflight 的 A0/A1 观测只作为语义依据，未在本轮重跑 A0/A1）。
- **not_run**：真实 APK 上的端到端分页链（需要 `mdd-sql` 提供真实指纹与 `CREATE TEMP` 语法，尚未接线）。
- **not_run**：`conformance/session/catalog-and-paging.json` 的机读条目（文件不在本子代理可写范围）。
- **not_run**：`mdd-cli` 的 `pagination_modes` 能力声明（`crates/mdd-cli/src/main.rs:74` 仍为 `[]`）。
- **blocked**：`SqlResult` 分页字段需要修改 `crates/mdd-sql/src/bridge.rs`，属跨 crate 改动，等待主代理决定。
