# A2 compact 查询转换候选

`a2_compact_adapter.py` 是 MDD-005 的局部开发候选，接收调用者已打开、独占使用的 DexSQL 0.1.1 MCP dataset；它不启动或安装生产者，也不修改原 HostLab 仓库。它复用固定 HostLab CLI 的 shape 查询和 `hex(CAST(... AS TEXT))` 单元转换，完整消费所有页面后才返回 DTO；生产者错误、源检查失败、超时、异常页面、超出额度或消费者取消都会明确失败，不能作为完整输出或触发自动 fallback。完成失败后适配器不再复用。

调用者必须提供四项检查：固定来源身份、生产者 dataset 与不可变来源代次的绑定、**投影查询**跨重执行时包含同值并列情况的确定总序、冻结 HostLab 的 continuation guard。单纯对输入路径做 SHA 检查不能证明生产者已经绑定该快照；原查询文本包含 `ORDER BY` 也不能证明外层投影顺序。当前仓库未提供这些检查的已验收生产实现，因而此候选不能用于签署审计完成或 A2 资格。

可选的 `ordering_terms` 回调可按每次查询及实际 shape 列名返回 `OrderTerm` 列表，生成外层 `ORDER BY hostlab_rows."列名" ASC|DESC`；只接受发现的列，拒绝重复项及 SQL 片段，并引用原始列值而非排序 HEX。生成排序语法不证明与原查询等价或包含同值并列的确定总序，现有 `verify_ordering` 仍必须独立确认。外层排序可能改变执行计划及成本，后续完整 B0/A2 测量须分别记录。

固定 A1 二进制和合成 structured-035.dex 曾在旧候选接口上完成每页两行的七行传输，并与标准 MCP DTO 相等；证据为 `artifacts/mdd-005/a2-adapter-development-20261030/probe6-run/stdout.txt` 和 `probe6-admission.json`。此前超时和页面大小配置错误的真实记录原样保留。该观测发生在新增快照和顺序证明要求之前，不验证当前接口、跨代一致性、完整 20 组 HostLab 审计或性能。

受限范围：A1 offset 加 limit 不得超过 100000；请求上限、源检查成本、调用方及 MCP 解码副本的内存未覆盖整体 RSS。该候选未连接 HostLab 原生同步 session，未解决进程生命周期、完整 inventory、marker 调度和大于 offset 上限的查询。保留旧后端和报告身份，直到后续统一验证与显式授权完成。

候选实现可在生产者明确返回 `output_too_large`、同时明确声明当前 dataset 未关闭且身份匹配时，将同一 offset 的页大小逐次减半；重试前仍要求冻结 continuation guard 允许重新执行。字段缺失、dataset 已关闭、最小单行仍超额及其他错误均保留原始错误并终止，不将任何页前缀作为完整输出。此新增分支尚未执行真实生产者验证。

`a2_hostlab_session.py` 新增候选同步桥，可让已绑定真实 MCP dataset 的调用方交给冻结 HostLab 消费者使用 `.rows()`、`.all()`、`.files` 和 `.queries`。桥要求调用方提供固定 inventory 核验、可确认的 dataset 关闭以及可确认的进程树中止；禁止在相同事件循环线程同步等待，失败、超时或未完整消费不能作为完整会话。桥会在返回第一行之前先物化整个查询，因此改变生产者与消费者的重叠及驻留范围，必须在后续 B0/A2 测量中单独归因。

同步桥不启动 MCP 生产者、不建立后台循环、不提供或伪造来源代次和总序证明，也不自动注入冻结 HostLab 工作流。使用方必须在独立的受控 owner 中建立这些能力；生产者生命周期、真实 inventory、失败/取消、未消费及完整 20 组审计都需要后续统一验证。同步桥仅做过语法检查，不能据此声称其可用于审计。

`a2_dataset_close.py` 提供 A1 独占数据集的关闭候选：确认 `close_dataset` 返回相同 dataset ID 和 `closed=true`，再通过 `list_datasets` 确认没有数据集、已接收/运行请求或输入字节。结构化与文本回执同时存在时必须一致；超时、取消、字段不符或非空状态均失败且禁止复用。此组件需要调用者独占 MCP client，关闭后不得再提交工作；它不终止或证明 OS 进程树退出。失败时仍由实际 owner 执行并确认进程树终止。完整生产管线和中途故障、并发路径留待统一验证。

`a2_dataset_open.py` 提供 A1 独占打开候选：先核对输入身份和空闲状态，再请求打开并核对输入路径、返回的数据集身份及单数据集空闲回读。它只记录 producer 的 `prepare_ms`，不把该值解释为纯解析成本；重复的来源摘要计算也须单独归因。候选不启动或终止进程，不证明生产者绑定不可变快照。调用者在失败或取消时必须检查 `abort_required`；已提交请求的结果不确定时，owner 必须实际终止并确认其所属进程树。收到明确的前置空闲拒绝且尚未打开数据集时，不得据此中止其他使用者。打开成功后仍须正常关闭数据集并保留独立的快照、排序和消费证明。

打开候选的取消、超时、错误身份和回执一致性仅做了合成客户端局部检查，见 `artifacts/mdd-005/a2-dataset-open-20261030/run2/record.json`；最终源码尚未执行固定 A1 真实打开联调，不代表完整 HostLab 或 A2 资格。

`a2_dataset_lifecycle.py` 将同一独占 client、来源和 deadline 的打开与关闭候选组合；正常退出须确认关闭及服务端空闲，消费失败、取消或关闭失败时须由外部 owner 在单独期限内确认中止其所属进程树。原始错误不会被关闭或中止错误替换；中止未确认会附加到原始错误。明确的打开前 busy 拒绝不会中止其他使用者。该组件不启动生产者，不证明真实 owner、快照、总序、进程已退出或完整审计；局部合成结果见 `artifacts/mdd-005/a2-dataset-lifecycle-20261030/run2/record.json`。

`a2_windows_job_owner.py` 是 Windows 本地开发候选：对自身创建的隐藏子进程先挂起、分配并核验无名 Job 再恢复；保留 Job/子进程句柄，取消或期限到达时只终止自有 Job，只有子进程退出及 Job 活动数归零才记录确认终态。它不按 PID 附着或结束其他进程，禁用句柄继承，也不提供 stdin/stdout 或 MCP 通道。固定可执行文件 SHA 是创建前后的观察，不证明 OS 加载字节不可变。需在隔离基线环境使用现有 pywin32；Job 分配、嵌套 Job 或权限失败均保持失败。自有短命子进程局部检查和创建阶段失败记录分别见 `artifacts/mdd-005/a2-windows-job-owner-20261030/run5/record.json`、`run1/`、`run3/`；run5 在注入创建失败后明确保留直接终止访问拒绝，并单独确认了同一子进程退出和 Job 归零。这不证明真实 MCP owner、快照、完整 A2、Linux 行为或正式资源资格。

同步桥的 `deliveries` 仅在适配器收到完整终态、消费者遍历完所有行后记录查询 SHA-256、行数、列顺序与有序 DTO 摘要。新增 `result()` 将同一查询的 shape 列、每页结果和终态绑定返回，零行也保留该查询实测列；原有 `rows()` 返回的列表接口不变。摘要版本 `mdd-a2-hostlab-delivered-rows-v2` 对列、带长度的 UTF-8 和 NULL 标记编码，保留重复和顺序，不能与旧版 v1 摘要直接比较。回执不包含行内容，也不证明 producer 快照、完整 HostLab 审计或性能资格。摘要计算增加消费者 CPU 与字符串编码成本，任何 B0/A2 测量都须单独记录该开销。

`a2_input_inventory.py` 提供单输入的完整 SHA-256 复核和受界物理 DEX 成员检查，遵循固定 HostLab 的 `classes*.dex` 名称和 041 逻辑成员后缀规则，并拒绝重复物理成员。原始 DEX 不具有归档成员清单，不能仅凭它声称物理覆盖完整。检查会重复读取整个输入，应在性能测量时单独归因；即使摘要始终相同，也不能由路径检查证明 producer 实际使用了不可变快照。生产者绑定和投影总序仍需外部独立证明。

`a2_windows_pipe_owner.py` 是独立的 Windows 自有 Job 异步管道候选：隐藏子进程挂起创建、只继承显式 stdin/stdout/stderr 句柄并在确认 Job 归属后恢复；读写额度、后台 stderr 超额、期限及取消只做过自有短命合成进程局部检查。前台在异步等待后重新检查后台失败；关闭取消会保留取消并尽力清理，自有 transport 关闭异常会记录并继续处理其余资源，任何错误均不构成完整清理确认。EOF、写入返回和 owner 关闭都不是协议结果或消费者完成回执。

stdout 累计上限只统计经 `read()` 消费的字节，不证明 child 的全部写入量；Windows/asyncio 管道及 StreamReader 缓冲、allocator 和 RSS 不在该上限内。stderr 目前后台计数后丢弃，不保留原始诊断内容。可执行文件与目录身份检查、SHA 扫描，以及 watchdog 安装前的同步管道／进程启动阶段，不受 `io_seconds` 或 Job 生命周期的完整硬期限约束；仍需外部监督器。

`artifacts/mdd-005/a2-windows-pipe-owner-20261030/` 保留所有局部记录：首次哨兵测试失败时测试未显式关闭 owner，该次没有 Job 树空证明；第二次只按句柄数值判断也不能证明真实继承。之后改用内核事件对象身份检查；run7 的 13 项合成局部检查包含关闭异常继续清理和取消。随后又补首个异常对象链及取消类型保留，最终源码仅运行了 run8 两项定向检查，run7 的 13 项未在最终源码全部重跑。该候选没有 MCP 协议或可靠结果帧、不提供快照／总序证明，也没有 Linux、完整 A2、性能或正式资源资格。

`a2_mcp_transport.py` 是固定 MCP 2.2.0／mcp-types 2.2.0 的实验性标准消息流，绑定一个已创建的自有 Windows Job 管道。它对换行分帧、UTF-8、JSON 对象重复键、JSON-RPC 类型以及逐帧／累计字节和帧数设限；stderr 不进入 JSON 流。局部合成检查覆盖部分帧、错误 JSON、无效 UTF-8、额度与读写取消；固定 A1 和合成 DEX 的 open/query/close 也有局部运行记录 `artifacts/mdd-005/a2-mcp-transport-20261030/run4/record.json`。首次两次 A1 退出时 AnyIO 取消导致 Job 树空未确认，原始失败保留。

SDK 正常关闭会取消其读任务；调用方可在自行确认无需再发送后声明 `expect_session_shutdown()`，但该声明仅为关闭意图，不能证明查询结果或页面已完整消费。此时底层 owner 可能记录预期的 reader `CancelledError`，不代表应用查询成功或失败。其他取消、部分帧、EOF 和错误保持失败；SDK 可能以 connection-closed 唤醒等待请求，原始传输失败另保存在 `transport.failure`，不得据此静默 fallback。SDK 序列化、JSON 解码、系统管道缓冲与 allocator/RSS 不在逻辑帧额度内，启动前同步身份扫描也不受 Job watchdog 全程约束。

该传输只能证明局部消息交换与自身 Job 清理，不能证明 producer 输入快照、查询总序、未消费页面、完整 HostLab 审计或 A2／性能资格；全量与跨平台验证仍未执行。
