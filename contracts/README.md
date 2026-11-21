# MeguvizDexDash 接口契约与约束

本目录中的 JSON Schema 面向引擎与工具链实现者。Schema 校验仅能证明 JSON 载荷格式及基础约束合法，不代表 DEX 解析正确、方言等价通过或性能达标。具体版本策略与资格门槛详见 [核心架构](../docs/02_ARCHITECTURE_AND_CONTRACTS.md) 与 [验证规范](../docs/04_VALIDATION_AND_PERFORMANCE.md)。

## 文件清单

| 文件 | Schema ID | 用途 |
| --- | --- | --- |
| [result.schema.json](result.schema.json) | `mdd.result.v1` | 单次终态或分页请求响应包（不是流式每批重复帧） |
| [capabilities.schema.json](capabilities.schema.json) | `mdd.capabilities.v1` | 构建身份、输入格式、profile、传输通道、有效预算与 provider 清单 |
| [benchmark_result.schema.json](benchmark_result.schema.json) | `mdd.benchmark-run.v1` | 单次实测观测记录，保留身份、环境、完整性、指标与证据摘要 |
| [examples](examples/README.md) | 示例载荷 | 正常、分页、错误及未认证能力等协议形状参考数据 |

上述文件均基于 JSON Schema `2020-12` 编写，`$id` 采用 URN，离线校验无需外网请求。发生破坏性变更时应新增带版本号的 schema 或 profile，避免就地篡改已发布版本的语义。

## 必须在运行时落实的 10 项约束

1. **精确整数编码**：64 位大整数以十进制字符串编码，禁止正号、前导零、科学计数法与浮点近似。除正则长度限制外，运行时还需核验 `0 <= n <= 18446744073709551615`。行数、`catalog_epoch`、`offset` 与来源 ID 遵循同样规则。
2. **状态维度独立**：`operation_status` 为请求总状态字段；`ok` 不代表输入或事实覆盖完整。`execution.complete` 表示服务端计算是否结束，与响应是否被全部取走无关：例如服务端计算结束后在传输途中被取消，`cancelled` 与 `execution.complete = true` 可以共存，不可将已完成的计算事实强行降级；反之，任何错误、取消或流中途断开均不可视作完整审计成功。
3. **完整消费对账**：`emitted_rows` 在分页响应中表示当页行数，在流结束消息中表示累计交付行数；`total_rows_exact` 标明总数是否精确。消费方必须逐批对账，不能仅凭单一包络字段推断完整性。
4. **分页与游标一致性**：`more_available = true` 时必须返回非空 `next_cursor`，`false` 时 `next_cursor` 必须为 `null`。原生游标固定绑定查询时的 `catalog_epoch` 与快照，不受后续目录变化影响；兼容 `OFFSET` 重执行需单独命名。游标过期、关闭或 worker 丢失时禁止悄悄重开并拼接分页。
5. **覆盖与阻断清单**：`coverage` 须绑定可追溯的 `scope_manifest`；`required_layers` 由实际业务需求决定，不得为凑通过而删减必需层。`issues` 中的阻断项必须反映到 `input` / `facts` 覆盖状态，且由实际检查证明，不接受客户端单方面声明。
6. **错误码与重试边界**：`error` 结构必须与 `operation_status` 一致。`retryable` 仅提示同一策略下是否适合重试，**不构成自动切换引擎的许可**；禁止将 SQL 语法错误包装为 `UNSUPPORTED_*` 来绕过校验。
7. **文本与原始字节保真**：具体列通过位置序号（ordinal）、稳定列 ID 与类型识别，允许重复 `display_name`。DEX MUTF-8、孤立 UTF-16 代理项、`NULL`、空字符串、字节数组与非有限浮点数必须经版本化 codec 无损编码后参与比较或哈希。
8. **Profile 合格认证（`admitted`）**：`admitted = true` 必须提供真实存在且覆盖声明范围的 `conformance_manifest_sha256`；运行时须分别维护单点能力可用性、格式支持与整体 profile 资格状态，同时校验 profile、方言、通道与 provider ID 的语义唯一性。
9. **传输通道隔离**：`capabilities` 中 `mcp` / `mcp-stdio` 通道的 `result_encodings` 仅限 `["json"]`，禁止向 MCP 标准输出写入非 JSON-RPC 二进制帧；worker 与 SDK 通道可按需声明列式或 JSON 批次。
10. **基准观测真实性**：benchmark schema 仅接收实际运行产出的 `observed_run` 记录，不接受模型推演的 `projected` 占位记录；所有引擎、输入、harness、机器与证据文件的 SHA-256 必须可核验。预测模型结果须另存独立文件，不得混写成实测基线记录。

## 有效预算与基准统计口径

- **`effective_limits` 表示规则**：每个限额对象包含 `value`（十进制 u64 字符串或 `null`）、`unit`、`scope` 与 `enforcement`。`hard` / `soft` 必须给出非空数值，`unavailable` / `unbounded` 必须为 `null`；`0` 表示明确零额度而非无限制。各级限额按最严格者生效，且核心预算字段应覆盖 `max_input_bytes`、`max_archive_members`、`max_member_uncompressed_bytes`、`max_total_uncompressed_bytes`、`max_fact_rows`、`max_build_memory_bytes`、`max_resident_facts_bytes`、`max_query_workspace_bytes`、`max_result_bytes`、`max_buffered_bytes`、`max_cursors`、`max_spool_bytes`、`max_threads` 与 `deadline_ms`（未实现内核硬限须如实标为 `unavailable`）。
- **基准配对记录要求**：每条 `benchmark-run` 记录单轮单个变体的实测数据，并通过 `pair_id` 与 `block_id` 标识配对顺序与测量时间块。指标缺失时写 `null` 并附带原因，禁止以 `0` 占位；并发重叠阶段禁止作为串行耗时直接相加。`comparison_mode` 支持 `ordered`、`bag`、`structured` 与 `expected_failure`，未指定 `ORDER BY` 时保留行多重性。仅当记录满足 `completed`、`complete_output`、`fallback_count = 0`、无污染且完整性与等价证书全部通过时，才可作为有效速度样本。

## 契约校验命令

运行 `python tools/verify_kit.py` 可核验原始快照与 schema 一致性（在已安装 `jsonschema` 的环境中会同步校对 3 份 schema 与 `examples/`）；若缺少对应依赖，脚本会明确提示未校验范围。schema 校验通过不能替代后续等价、边界与集成 gate。
