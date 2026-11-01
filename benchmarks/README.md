# 基准与完整消费

当前没有本机 A0/A1/A2/B0/B1 的合格测量，不能从历史观测计算新引擎成绩。`baseline-manifest.json` v2 已绑定实际用户输入、独立固定 HostLab checkout、A0/A1 Windows二进制和资源要求；`measurement-schema.json` 仍约束正式 observed_run，资格准备不能填充正式 trials。

实际可用命令（工作目录为工程根）：

```powershell
python benchmarks/run-existing-baselines.py --self-test
python benchmarks/run-existing-baselines.py --preflight --output artifacts/mdd-005/preflight.json
```

前一命令仅测试严格 JSON、完整结果消费和 canonical 规则。后一命令派给隔离baseline-venv中的真实preflight，核验固定来源/版本/SDK/静态导入，私有输入只按根代理完整SHA取得回执及未变stat核对，不做分析。`ready_for_qualification_window` 只表示准备完成，不能签发正式性能资格。

Windows Job监督已用微小父/孙进程实际验证：挂起创建、入Job后恢复、kill-on-close、超时/父退出遗留子树清理，以及ActiveProcesses=0。嵌套Job下通过显式只读命名句柄短暂查询并关闭，不能把QueryInformationJobObject(NULL)的外层Job误当本次Job。正式worker仍须root资源lease和启动前内存检查；当前根实测7,672,709,120 bytes低于预注册10GiB，lease未授予，不降低门槛、不杀其他项目进程、不轮询。

可审查的单次资格入口为 `--qualify --variant A0|A1 --sample <manifest id> --output <新artifacts/local目录> --lease <root实际授予文件>`。缺lease会在私有读取/worker启动前失败。资源为4逻辑CPU(mask15)、native threads2、8GiB Job commit、可用物理内存至少10GiB、每worker最多1500秒；现请求一次约30分钟窗口，仅一份A0起步，结束后由root重新决定后续。lease总期限不自动续期，worker清理预留15秒。

固定源码为8782f43d537c442905123e35af325c412caa5188；97个运行相关文件实际字节逐个匹配Git blobs，Windows EOL/stat观察另存。driver复用原analyze.main的本地full native+surface、27FEATURE、独立intake/home门禁和verify_audits.evidence的完整20组；只隔离输出/网络入口，A1使用公开可审计的外部版本pin适配，不改旧源码或固定A0安装器。A1实际SHA为602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6，官方API、SHA256SUMS与实际字节一致。原始业务DTO不改，输出证书由父监督器再次完整读取并验证全部20组与文件SHA。

A2已实测A1原生MCP的12工具与query compact参数，未打开数据集；现有完整audit是CLI shape/hex/marker消费者，CLI无compact开关。完整MCP适配及20组结果等价尚未取得，A2不准入完整审计分母，不能只因存在compact就称最佳现成路径已验证。

候选生命周期适配器对同时出现的文本和结构化回执按 JSON 类型逐项比对，打开后的列表回读也使用同样规则；布尔、整数和浮点数不能因 Python 相等规则而混同，非 JSON 值和非有限数字被拒绝。合成回归见 `artifacts/mdd-005/a2-lifecycle-json-20261030/`；该检查不建立真实生产者快照或 A2 资格，也不单独限制 JSON 解析时的内存。

未来 driver 用参数数组执行，禁止 shell 字符串；其单个 `mdd.benchmark-output.v1` JSON 包含 `input_manifest`、稳定 `request_key`、`row_schema`、`comparison_mode`、`final_dto`、`fallback_count`、最终 `mdd.result.v1`。只有 input/facts complete、计算完成、全部交付、无截断/剩余cursor、零fallback及完全物化才可进入结果比较。输入manifest保留有序 occurrence，业务DTO与原始代码/资源指纹均不得删除。

当前通用读取器尚无按工作负载核验嵌套 DTO 完整消费的实现，因此 `structured` 模式明确拒绝资格；不能仅凭响应中自报的行数证明 DTO 完整。`ordered`／`bag` 保持现有完整行数检查。此限制不改变最终验收，结构化验证器仍须后续实现。

消费者检查查询身份、覆盖范围和结果 schema 字段是否存在，并拒绝重复事实层；这些字段存在并不证明 scope manifest 与实际输入匹配，实际来源绑定仍需独立验证。限定自检见 `artifacts/mdd-005/result-identity-20261030/`。

`consume` 还要求调用方传入独立可信的 `expected_identity`，逐项匹配请求、查询、快照、范围、profile 和响应 schema 等身份。当前只有模块自测调用；匹配结果不认证期望值本身，也不能替代输入清单和实际分页消费证据，见 `artifacts/mdd-005/result-identity-binding-20261030/`。

`scope_commitment.py` 可用调用方独立核验的有序输入与 DEX 清单、快照身份及捕获来源数检查 v1 预像和摘要；输入数、DEX 数及捕获来源数分别受条目额度限制。该检查不认证这些外部依据，也不证明覆盖、事实完整或结果交付，因此尚不授予基准资格。

`snapshot_commitment.py` 可对照调用方独立提供的来源摘要、长度、种类和顺序，检查捕获清单并重算内容键；同内容的多次输入仍逐次保留。快照句柄和输入身份的可信性需另行建立，清单一致不证明生产者确实使用该快照或所有成员和页面已消费。

`capture_scope_binding.py` 将上述捕获清单与 scope 预像的期望输入按 ordinal 和摘要关联，允许显式子范围；`all_captured_sources_selected` 只表示捕获来源均被选择，不表示所选策略覆盖了全部成员或事实。清单和 DEX 成员期望仍必须由调用方独立核验。

结果信封及 coverage、execution、response 对象按现有契约检查必需和未知字段；结构检查不能替代实际 scope manifest、快照或工作负载证明。合成反例见 `artifacts/mdd-005/result-envelope-shape-20261030/`。

覆盖问题与警告按结果契约检查必需字段、可选身份和数据类型；畸形或阻断性诊断不能作为完整输出，合成检查见 `artifacts/mdd-005/diagnostic-contract-20261030/`。此检查不证明诊断内容已覆盖所有真实错误。

当前 `ordered`／`bag` 读取器要求有序列描述中的 ordinal 从零连续、type 非空，并要求每行是与列数一致的数组；形状检查不验证单元格类型、语义或来源。局部反例见 `artifacts/mdd-005/row-shape-20261030/`，真实工作负载的 schema 和完整性仍需单独冻结验证。

`mdd-canonical-json-v1` 使用 UTF-8 严格 JSON、对象键按 Unicode 标量排序、无空白、数组保持次序。NULL、bool、整数、文本类型分明；拒绝浮点隐式编码、孤立代理和超 i64/u64 整数。原始位型、bytes和DEX文本必须先由稳定DTO标签编码。bag模式仅排序完整 typed row，重复行保留；ordered模式不排序。该保守codec是基准工具范围，不代替引擎未来的值codec。

`compare_complete_rows` 在两侧分别经过现有完整物化检查后，定位有序结果或 bag 结果的首个不同单元格、行数、列 schema 或其余上下文；bag 的行号是规范化排序后的序号。不同操作不会被报告为相等；该 codec 原样比较覆盖层列表顺序，顺序不同可能报告上下文差异。该诊断仍依赖调用者独立提供可信身份，不校验单元格与 schema 的类型一致性，不认证真实分页消费或来源，也不授予审计／性能资格。合成边界和现有自检见 `artifacts/mdd-005/row-difference-20261101/`。

正式性能区间使用同输入/规则/最终DTO/缓存/总线程预算的交替配对，至少10对并在第二独立时间块复测；失败、超时、污染均保留。版本中位比与配对中位比分开，不由少样本生成p95。当前资格driver的E包含本地APK SDK身份/copy与原静态消费，缺少HF元数据/下载路径；与历史Linux E不是同一无条件窗口，必须独立登记归因与重校准。E/P/S/F/R/O不把重叠producer/consumer相加。历史37%/47%仅是条件目标。

补齐平台、引擎、私有输入和真实driver后先完成完整等价，再测量最佳合格A0/A1/A2；A2排除必须保留具体语义/部署证据。功能预览不等于 MDD-082 正式性能资格。
