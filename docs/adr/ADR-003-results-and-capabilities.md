# ADR-003：独立完成状态与无损 JSON 基线

- 状态：accepted（M0 契约与编码路线）；运行接口/完整差分资格未完成。
- 日期、作者、关联任务：2026-10-28，查询/传输代理，MDD-006。
- 替代/被替代：无；落实工程包 ADR-003。
- 范围：mdd.result.v1、mdd.capabilities.v1 与首轮机器 JSON 路径。

## 背景与约束

现有三个 JSON Schema 是设计契约，不是引擎实现。一次请求成功、输入覆盖、事实覆盖、计算完成、交付完成必须分别判定。零行只能在完整 scope 中作为阴性规则证据，未消费页、截断、取消或 worker 丢失不能成为完整成功。

## 决策

保留现有 schema 名称与错误枚举，catalog_epoch/计数/offset 使用规范十进制 u64 字符串，运行时检查上界。mdd.result.v1 保留 operation_status、三态 coverage、execution.complete 与 response 分页状态。能力的 available 与 profile 的 admitted 独立，所有未验证 profile 维持 false。

首轮机器接口采用结构化 JSON 批。MCP stdout 仅合法 MCP JSON，二进制仅在独立 worker 通道/SDK 协商。日志写 stderr，不将表格或 hex wire 作为默认机器接口。列批仅在完整 producer→consumer 同 DTO 比较后决定。

实验性 scoped SDK 入口从实际快照、所选 inventory 与同源事实重建覆盖，并仅允许 `native-unqualified`、SQL 方言为 null 的类型化预览；它不授予任何 profile 准入。`AllCapturedInputs` 只涉及已捕获来源，不证明全部成员或安装 split，外部来源授权、解析器独立正确性与消费交付仍分别验证。注解与资源层在当前入口明确拒绝，MDD-022 重开期间不得以该入口恢复注解资格。

文本/bytes/整数/浮点保留类型，重复 display_name 以列 ordinal 和稳定列 ID 区分。MUTF-8/NUL/孤立代理采用显式无损编码；非有限浮点和 bit-exact 值使用原始位型标签。不得将坏文本或精度损失写成正常 UTF-8/浮点数。

## 候选与取舍

JSON 易检查和跨语言接入；列批可能减少逐行开销但增加布局、所有权与验证成本。原工程包的消费端 6.78 倍是组件历史观察，不能推导端到端优势。先落实完成状态和完整消费，再比较编码。

## 验证与退出条件

验证 u64 边界/重复 JSON 键、NULL/空串/空 bytes、重复列、原始文本、正常空结果、未消费页、计算完成后取消、跨 snapshot cursor、缺失 End、worker crash、背压和总期限。能力发现只列实际实现，不以空数组伪装尚未实现的资源工具。

本轮基准消费校验器 `benchmarks/run-existing-baselines.py` 仅是独立验证工具，定义保守 canonical-json codec 并拒绝浮点隐式转换；不是 mdd-wire、SDK 或引擎结果实现。其测试不得计为 HostLab/profile conformance。Rust serde 的十进制 u64/UTF-16/NULL 往返已在 MDD-002 实际运行；实际生产结果流、分页和完整 HostLab 消费继续待后续实现。原包 schema 的独立校验结果由 bootstrap 记录；它不能替代运行接口资格。

## 迁移与回滚

破坏性 schema/profile 变化使用新版本与迁移文档；未来旧缓存/游标按版本失效，禁止重开后拼接。当前未启用任何生产路径；本轮可撤回验证工具和 ADR，不修改 HostLab。

## 证据

- `contracts/README.md` 与三个原始 JSON Schema。
- `artifacts/mdd-006/sql-bridge-probes.json` 记录未运行部分。
- `artifacts/mdd-005/harness-self-test.json` 记录消费验证器实际运行；不作引擎资格。
