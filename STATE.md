# MeguvizDexDash 当前状态

更新：2026-10-30（Asia/Shanghai）。唯一任务图：tasks/backlog.json；当前产品仍在实施，所有产品 profile admitted=false。

## Checkout 与交付

工程目录 D:\MeguvisDexDash（保留目录原拼写）。私有远端 https://github.com/jichuo1/MeguvizDexDash；当前审查分支 codex/m2-facts-20261028，草稿 PR #1。main 当前 abdcdf4；检查点 3c334c5 的 Windows/Linux 原生 CI 和有限 Linux ASan/fuzz 均通过。此前 a8fb9a6 两平台各170项测试及10条实际命令原始记录已核验，见 artifacts/integration/20261029/ci-a8fb9a6.json。更晚的工作区变更须另行验证。

大范围 push main 曾被自动审批以缺少本次默认分支推送明确授权为由拒绝；后续采用独立分支和草稿 PR。没有合并、默认后端切换、部署或正式发布。

原工程包 SHA-256 b5f2f3859a5a7753f83f8edc24c73ce15781075afb899e4e63b274fdcc161844，原始规格提交 3bbf1088137e70c5d3d722534a5eeab8b69a596c；handoff/original/MeguvizDexDash 保持不变。原包 verify_kit/recompute_targets 实际通过（56 文件、23 历史证据、51 DAG 任务）；这些不是引擎测试。

## 已验收的实现范围

- M0：MDD-001/002/003/004/006 已完成各自验收；005 尚未完成。
- M1：MDD-010/011/012/013/014 已完成限定任务范围，包括不可变快照、逻辑出现次数、ZIP32/ZIP64 物理成员、生命周期与真实 worker 故障。012 曾重新打开补齐 ZIP64，52 向量及 65,535/65,536 成员边界已重验。
- M2：MDD-020/021/022/023 已完成字符串/类型/原型、定义、注解与编码代码布局。020 曾因内部 item 引用反例重新打开，已用物理起点、合法 orphan、SDK 正反例与公开样本重新验收。Ready facts 对外只读。
- MDD-024：9 引用测试、18 手工 fixture（11 所需层成功、7 真损坏）、43 个固定 A0 完整小关系比较通过。公开 NewPipe 两 DEX 共 509,322 operand sites 完整读取。精确声明查找不等于运行时分派/继承解析；合法非 scalar 文本保留 UTF-16，拒绝有损 UTF-8 投影。
- MDD-025：原始方法体、资源和 Manifest 所需事实验收完成。公开 55,763 方法、8,540 类聚合 recipe、792 资源逐项/摘要对齐固定 A0、Python 和原 HostLab 规则；76 Manifest 向量、AAPT2 完整树及 A0 六页结果通过。方法无 body 与空 body 区分，Manifest 与资源持有同一 Arc，源改写/重命名/释放后仍保持同快照证据。见 artifacts/mdd-025/raw-evidence-conformance.json。

公开样本为官方 NewPipe 0.28.6，10,885,562 字节，SHA-256 e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58。APK 位于 ignored artifacts/local/inputs，不进入 Git。上述均非 ART 完整验证、完整 HostLab 替代或性能资格。

## 当前推进与阻塞

MDD-026 的索引和三态 coverage 已有测试证据，但逐列事实验收尚未完成；MDD-030 类型化 IR/基础算子已完成Windows限定范围验收：7单元+2compilefail、36查询case、20LIKE、322正/12负Base64均实际通过，源码稳定且根复验通过。031 SQL桥与034预算/取消/终态的前置依赖已满足。未通过的 Methods 代码列、参数文本编码与参数注解 slot Unknown 均须显式阻断相应查询，不能填零/空值制造完整结果。

解析安全独立 fuzz workspace 已实际完成 10,400 次本地 mutation、2 Rust 与 2 Python oracle/驱动测试、严格 Clippy。b29933d 两平台原生 CI 已通过，原始十份命令记录均 exit0。Linux ASan run40692557250 也真实通过：正控制非零检测到预期越界，六个各 15 秒目标共 2,426,570 次执行、无 crash 文件或超时，原 ZIP 的 GitHub 摘要及每份日志计数/锁参数均独立核验。见 artifacts/conformance/parser-safety/ci-readback.json。G1 未签发；固定预算不是完备证明，测试 nightly 不改变发布 stable 1.99.0。

两个授权 APK 已核验完整 SHA/长度和 33/35 DEX，原位置未改变且不入 Git：9161100=226,519,215 字节/41efb1c9acb07badab5296953fb3da1def6925e2b34662120ca96df9d17bbfb2；9170100=243,687,778 字节/f0f880e841d017db335b3919e6d4792961f2e08aa9993da661b626d52cfcb955。实际路径及 mtime 前后核验见 artifacts/bootstrap/20261028/private-input-acquisition.json。两个私有输入另有实际受限 CLI 成员/头部检查通过：68 个 DEX 全为 037，进程树均清空，峰值 Job commit 623,386,624/676,052,992 字节；原始输出留在 artifacts/local，摘要为 artifacts/integration/20261028/private-headers-20261028T130804307935Z.json。该检查不含完整事实、业务审计或性能试次。

MDD-005 的固定 HostLab 驱动、A0/A1 身份、隔离 Python 环境及 Windows Job 监督器已就绪。2026-10-29 可用内存重新达到原定10 GiB准入后，已对两个授权输入各执行一次 A0 与 A1 完整静态资格检查；每份覆盖27 FEATURE、20组证据，零 fallback、完整交付、子进程树清空，同输入的20组结果全部相等。四次业务程序返回码均为1，完整运行与等价不表示业务审计结论通过。重新读取原始证据及身份见 artifacts/mdd-005/static-qualification-20261029.json；私有原始输出留在 artifacts/local/baseline-runs。项目代理在该时段暂停，但系统其他应用未隔离；本轮不是性能试次。A2 完整适配、正式配对测量和最强合格基线选择仍未完成，历史约37%/47%仅条件目标。

## 锁定与恢复

发布 Rust/Cargo 1.99.0，Windows x86_64 MSVC；Linux 同版本原生验证按不可变 CI checkout 单独登记。十项直接生产依赖均获用户批准：serde、serde_json、sha2、sha1、zip、rusqlite、getrandom、quick-xml、sqlparser、log；根 lock 目前46个外部 package。SHA-1 仅 DEX 兼容校验；来源身份 SHA-256。SQLite 3.53.2 只读虚表桥正在 MDD-031 实施，兼容性尚未验收。Python 本地 3.12.14，CI 3.12.10；依赖与许可证见 conformance/manifests/dependencies.json。

root 单写共享 Cargo/lock、exports、STATE/backlog/ledger/index 和 CI；026 索引/coverage、030 查询、独立全事实验证分开文件所有权。性能测量先暂停其它 CPU/IO 工作并取得真实资源窗口。并行检查点用 refresh_artifact_index.py --from-index 登记精确暂存 blob，再重建检查点运行 check_progress.py，不能混入活动文件。

恢复先检查 Git/任务/进程，不重建任务图。现有 BIL/HostLab 外部工作树、配置和用户修改保持原状。原始成功/失败记录保留；当前回滚为在审查分支创建范围 revert 提交，保留初始规格和失败证据，不 reset/clean/强推。完整审计、SQL、MCP、FFI、桌面、ARSC、正式发行与 MDD-082 性能资格仍未取得。

031 SQL桥正在实施，034预算/取消/终态限定机制已完成本机验收。用户已另行批准sqlparser0.63.0（仅std）与log0.4.34，独立探针实际构建/AST往返通过；根锁仅增这两包，无其他外部升级。两个私有Manifest完整树与原始属性逐项通过：2115/2119节点、5275/5291属性，含exact float32 bits、TYPE_REFERENCE零值与TYPE_NULL分开；首轮日志quota及显示比较失败原样保留，见private-manifest-captured-conformance.json。这些仍不代表完整HostLab审计或性能通过。

私有完整raw诊断另行在启动前被4GiB开发任务准入拒绝（并非正式基线阈值调整），没有开始编译或解析；后续独立WMI观察仅2404388KiB可用。失败记录private-raw-diagnostic-20261028T135952890645Z.json保留，不能推断引擎解析失败或性能结果。

内存条件变化后重试：固定 e56db3e 二进制受限诊断在两份授权 APK 上完成原始事实计算，分别覆盖33/35 DEX、1,731,482/1,848,430方法记录及310,716/345,907类记录；输入与二进制身份、完整输出摘要和进程树终态已回读。证据 artifacts/integration/20261028/private-raw-diagnostic-20261028T172024248736Z-readback.json，原始输出留在本机忽略目录。它不是逐字段 A0 等价、完整HostLab审计或性能资格。

两个APK的资源指纹另完成三方逐项核对：e56原生、固定A0/HostLab和从原始归档独立流式重算的 resources.arsc 与 res/*.xml 解压字节 SHA-256 分别17,755/17,770项一致。证据 artifacts/integration/20261028/private-resource-readback-20261028T173518129052Z.json；摘要不含私有逐项内容。类/方法输出覆盖和聚合粒度不同，尚未比较；业务退出码1不等于审计业务通过。

MDD-026 已重新打开：独立复核发现资格脚本对17关系156列主要检查原子可用性声明，尚不能证明每列的字段/类型、NULL、顺序、重复性、来源及 raw 指纹均有独立证据；例如 dex_files.file_id 已有原生分配代码，但尚缺固定旧实现和全部来源场景的端到端逐列验证。已有219候选请求（55残余反例）、35 facts+4 compile-fail组件测试、11索引/coverage根测试及8场景43关系比较仍有效，69个兼容投影缺口仍明确阻断。原 conformance/manifests/hostlab-fact-qualification.json 保留为限定原生原子检查的历史记录，不代表 MDD-026 原验收完成。G1/G2、完整私有事实与 HostLab 资格仍未签。033正在只读预研，依赖031尚未完成，不先假解锁。

补充事实对照：合成样本中三个定义关系的21列与固定A0完整行多重集合一致，含错误编号、NULL和缺行负例；三个合成DEX的24个头字段与独立原始字节解码及A0单输入结果一致，含四个损坏/篡改负例。原始记录和回读分别为 artifacts/mdd-026/new-audit/definition-projections/readback.json、artifacts/mdd-026/header-audit/20261028T163754102728Z/readback.json。完整A0多输入编号和兼容关系装配仍未证明。

随后真实 A0 多输入合成实验完整消费三组79行，验证原生六个来源出现及字符串坐标。相同内容两次输入在 A0 有两个兼容池编号，而原生物理池身份共享；兼容层必须显式映射，不能直接将物理池 ID 作为旧编号。证据 artifacts/mdd-026/cross-dex-audit/20261028T164250980578Z/readback.json；生产兼容映射和完整 HostLab 尚未完成。

方法代码项补充对照：classic/shared 合成 DEX 的12列与原始字节 oracle 和 A0 有序结果相等，共享物理方法体仍保留多个方法行；无体为 NULL。非空 try/handler 只在无方法所有者的物理项上验证，不能算 A0 非空兼容行。证据 artifacts/mdd-026/code-item-audit/20261028T164825508666Z/readback.json。

后续两份合成DEX补充了方法实际拥有的非空 try/handler，覆盖偶数和奇数 code-unit 对齐；12列与 A0/原生/独立字节 oracle 一致，SDK dexdump 通过。损坏 handler 被原生及 SDK 拒绝，A0 却返回行，原始反例保留；该对照不改变真实错误或授予设备/ART资格。证据 artifacts/mdd-026/owned-try-audit/20261028T171328758066Z/result.json。

四类注解关系在双来源合成样本中验证行序、NULL和来源；A0 的116行在数值零符号归一化后匹配，其中两处原生 -0.0 被 A0 文本 CAST 显示为 0.0，不能称逐位相等。参数位置 Unknown 继续阻断。证据 artifacts/mdd-026/annotation-order-audit/20261028T165221569757Z/readback.json。

三份合成DEX的24个方法、14个字段由独立字节 oracle、原生事实组合和A0数值顺序逐行对照，覆盖纯引用NULL、无体定义、三参数及共享体多所有者；生产 methods 关系仍未装配。首轮因测试查询文本别名排序失败的记录已保留，修正数值排序后通过。证据 artifacts/mdd-026/method-atom-audit/20261028T165707192974Z/readback.json。

四份合成DEX的67个字符串与独立 UTF-16/MUTF-8 字节 oracle 一致，两个类型样本的16个 descriptor/java_name 与 A0 一致；严格 UTF-8 拒绝孤立代理项，坏 checksum 与不支持版本分别保留真实错误。A0 的 NUL/孤立代理项/补充字符 CAST hex 是 MUTF-8 字节，不能称为普通 UTF-8 兼容。生产 java_name 行尚未装配。证据 artifacts/mdd-026/type-text-audit/20261028T170219193130Z/readback.json。

四个合成来源的类事实验证了 NULL/空 source_file、孤立代理项、NULL superclass 和重复 descriptor 的来源及顺序；非标量仅以原始 MUTF-8 比较。越界 source_file 索引被原生与 SDK 拒绝，A0 则显示 NULL，差异保留在 artifacts/mdd-026/class-source-audit/20261028T174234924728Z/result.json。

多DEX引用边界新增三个来源出现、同一目标不同本地索引、40个精确操作数站点、16行固定A0调用结果和共享物理代码的两个方法所有者对照；跨来源查找真实返回INVALID_ARGUMENT。证据 artifacts/mdd-026/mixed-reference-audit/20261029T004552809470Z/result.json，仅为合成静态样本。

字段及类型引用另以三个来源核验不同本地索引、重复出现及各6个目标位点，A0字段访问7行与类型引用6行的多重集合一致；跨来源查找返回INVALID_ARGUMENT。A0不提供站点PC，PC仅由原生与独立字节oracle对照。证据 artifacts/mdd-026/field-type-audit/20261029T010629766313Z/result.json。

动态引用及孤立代码以四个合成来源对照57个编码位点，4个invoke-custom目标保持未知，未归属物理代码不生成调用者；A0方法调用20行的多重集合一致。位点PC来自原生与独立字节oracle，不推断运行时分派。证据 artifacts/mdd-026/dynamic-source-audit/20261029T012418079194Z/result.json。

有效与坏索引DEX以两种顺序同快照验证：联合范围保留原始INVALID_INPUT、input complete/facts partial；只选有效来源时虽complete但covers_all_captured_sources=false。SDK和A0对该坏索引均退出0，不能当完整成功。证据 artifacts/mdd-026/mixed-failure-audit/20261029T015522772300Z/result.json。

非空partial引用反例中，不完整来源仍有10个真实位点和2个匹配，但严格关系及全范围索引/标量查询保持INCOMPLETE_FACTS；完整兄弟子范围明确covers_all_captured_sources=false。A0的8行仅对照完整来源，不能证明partial完整。证据 artifacts/mdd-026/partial-reference-audit/20261029T021708996807Z/result.json。

合成资源身份验证：同一APK两次输入中保留6个物理资源出现，包括同名不同字节成员；捕获后源文件改写不改变快照读取。缺成员时facts为unknown，完整子来源不宣称覆盖全部输入，外源注册返回INVALID_ARGUMENT。证据 artifacts/mdd-026/resource-scope-audit/20261029T043749212277Z/result.json，仅覆盖合成资源身份与coverage。

同一路径合成APK真实改写前后分别捕获两代快照，独立ZIP字节oracle核对6个物理资源出现：旧代保留旧字节，新代读取新字节；跨代登记返回INVALID_ARGUMENT且缺失覆盖仍unknown，本代登记后才complete。证据 artifacts/mdd-026/resource-generation-audit/20261029T050623250919Z/result.json，仅覆盖资源事实，不证明SQL/Smali/分页跨代绑定。

同一路径合成DEX真实改写合法指令引用并重算签名/校验和后捕获第二代；原生方法体与独立字节oracle及A0范围一致，旧快照保留旧字节，新代有不同指纹。跨代方法EntityRef及混合definitions/code均返回INVALID_ARGUMENT，native无体保持None。证据 artifacts/mdd-026/raw-generation-audit/20261029T062620399999Z/result.json；不证明完整类指纹、SQL/Smali/分页或profile。

逐列总表 artifacts/mdd-026/column-ledger/20261028T170548736531Z/column-ledger.json 固定17关系156列，逐项列出已有证据与剩余边界；追加式独立重算和4项负例通过，但所有列的完整资格均为false，不据汇总签发MDD-026或产品profile。

v2总表 artifacts/mdd-026/column-ledger-v2/20261028T171808763956Z/column-ledger.json 增量关联方法持有 try/handler 的12列证据，并保留损坏输入在A0与原生之间的真实差异；追加式回读和负例通过，全部字段完整资格仍为false。

v3总表 artifacts/mdd-026/column-ledger-v3/20261028T174511331094Z/column-ledger.json 增量关联8个 classes 字段的多来源边界，追加式回读和5项篡改负例通过；仍不签发 MDD-026。

v4总表 artifacts/mdd-026/column-ledger-v4/20261029T005209769816Z/column-ledger.json 增量关联10个 method_calls 和4个类身份字段的多来源引用证据，独立重算和7项篡改负例通过；156列完整资格仍均为false。

v5总表 artifacts/mdd-026/column-ledger-v5/20261029T013609946354Z/column-ledger.json 再关联字段、类型及动态/孤立代码来源证据，独立重算和9项篡改负例通过；156列完整资格仍均为false，69个兼容投影未装配。

v6总表 artifacts/mdd-026/column-ledger-v6/20261029T020323493739Z/column-ledger.json 增量关联混合损坏来源的引用层传播证据，独立重算和11项篡改负例通过；关联39列仅表示该层传播证据，不证明其字段值全部验收。任务、profile及156列完整资格仍为false。

v7总表 artifacts/mdd-026/column-ledger-v7/20261029T021940078907Z/column-ledger.json 增量关联非空partial引用与兄弟来源覆盖证据；独立追加重算及11项篡改负例通过，关联39列仅证明所列引用层边界，不代表字段值完整验收。原分母17关系156列、69个未装配兼容投影及所有字段完整资格false保持不变，MDD-026和profile仍未完成。

v8总表 artifacts/mdd-026/column-ledger-v8/20261029T044457978884Z/column-ledger.json 追加合成资源物理成员及覆盖证据，独立重算和9项篡改负例通过；资源切片独立于DEX字段，156列完整资格、MDD-026及profile仍为false。

v9总表 artifacts/mdd-026/column-ledger-v9/20261029T051611066996Z/column-ledger.json 追加同一路径实际改写前后两代快照的资源证据，独立重算和10项负例通过；初次负例因未拦截旧版读取入口失败并保留。该切片不证明SQL/Smali/分页跨代绑定，不提升字段或profile资格。

MDD-034 已重新打开：独立真实组合反例中，executor向有界队列发送4行后消费者尚未读取，查询却报告成功且delivery_complete；随后消费者因查询已结束被拒绝。原始输出 artifacts/mdd-034-audit/delivery-boundary-independent-20261029/probe/stdout.txt。先前27 query、10 session、7 types、2 compile-fail、SQLite双连接及子进程deadline的限定机制证据仍保留，但不能代替未消费数据的交付验收。生产worker/MCP/FFI尚未接线，不推断生产已发生；进程树隔离未由先前探针证明。

消费者确认候选现以绑定队列逐包ack和显式End换取对应收据，再取得最终envelope；零行也需End，旧受信回调限制为测试私有入口。独立真实会话16场景、20次并发（完成先胜2、取消先胜18）、伪造收据及旧入口编译负例通过；未释放生命周期缓冲另有真实红绿修复。证据 artifacts/mdd-034-audit/delivery-confirmation-independent-20261029/final-20261029/verify-run/record.json。Windows工作区232项测试、严格Clippy通过；生产worker/IPC、完整分页和各兼容profile尚未验证，MDD-034保持in_progress。

后续队列行将wire字节与Row持有容量分别做checked逻辑计量：稀疏数组低额度红绿与UTF-16、bytes、Entity内部容量、四级额度和取消持有测试通过；与拼接计步组合的Windows工作区241项测试、严格Clippy通过。独立探针在保留两次低内存准入阻断及两次测试预期失败后，按原3GiB门槛重建并完成8个限定场景；相同wire的紧凑/稀疏行分别按各自容量计费，工作区、输出与队列quota发生阶段分别核对，证据 artifacts/mdd-034/row-capacity-independent-20261029/readback-1/record.json。provider入队前分配、消费者克隆、allocator/RSS及生产传输仍未覆盖；流式计数候选尚待最终独立验收。

流式JSON候选对固定serde_json writer进行逐块Bytes编码和精确计数，成功后原子charge；真实低额度单线程红绿的最大单次分配申请由699108降至632字节，原始quota维度与截断终态保留。Windows工作区247项测试与严格Clippy通过。独立探针保留首次180秒超时、低内存未启动及缺少pywintypes的启动失败；满足原3GiB准入后在2GiB Job内完成7个合成真实队列场景，25项独立回读通过，见 artifacts/mdd-034-audit/streaming-json-independent-20261029/verify-probe4-run/record.json。长Entity探针首次编译根进程退出时仍有子进程，被作业判失败且探针未启动；独立重试完成，合成50万字节普通字符用54步完成，等长转义字符在64步额度下报QUOTA，见 artifacts/mdd-034-audit/long-entity-steps-20261029/runs/20261030T014930199186Z/probe/stdout.txt。该对比不证明取消延迟或实际产品缺陷。provider预分配、部分值的临时对象、其他serializer、allocator/RSS与传输未覆盖。长Entity字符串的serde内部扫描仍是待验证的细粒度取消风险。

MDD-034累计驻留反例与修复：两行各3989字节、额度5983时，旧代码在第二行计数时仅预约首行3989，随后入队才报7978超额；现将当前行的累计工作区预约移至计数前并交由队列持有。独立红绿回读确认第二行计数回调为0、输出仅首行427字节、首行确认后预约归零且最终不完整，见 artifacts/mdd-034-audit/prequeue-resident-fixed-20261030/readback-record.json。修复后Windows工作区248项测试和严格Clippy通过；这是合成进程内队列的逻辑容量证据，不代表provider预分配、RSS、生产传输或任务资格。

MDD-034入队前取消边界：独立代码复核指出流式输出行已计数但output_row检查失败时未标记丢弃；真实回归先因truncated=false失败，修复后保留原取消错误并标记截断，计数中取消和入队前取消的QueryWorkspaceBytes及ResidentBytes预约均验证归零。最终源码Windows工作区249项测试、严格Clippy通过，见 artifacts/mdd-034/output-row-truncation-20261030/；未重新执行先前7场景独立流式矩阵，不代表生产worker/传输或MDD-034整体准入。

MDD-031尾部转义与字节拼接实测：固定A0/A1在合成DEX上完成12个CLI查询，尾部LIKE为0、NOT LIKE为1，普通转义为1、NULL保持NULL；bytes拼接为text，含NUL和非UTF-8的HEX分别41C0804243/EFBFBD41。旧方言此前误报INVALID_ARGUMENT；现仅对DexSql010/011返回false，NativeV1保留原错误，配额/取消仍传播。该修复检查点独立桥探针21场景和8项旧引擎语义对照通过，见 artifacts/mdd-031-audit/legacy-escape-bridge-20261030/runs/20261030T020805554030Z/readback-run/record.json；Windows工作区251项测试、严格Clippy通过。旧版NULL wire与候选不同；当时bytes拼接类型和编码不等价，完整corpus及MDD-031资格未通过。

MDD-031拼接候选：A0/A1合成矩阵32项与独立replacement/MUTF-8 oracle一致，覆盖跨操作数字节、无效/截断、混合类型、NULL和DEX来源；候选旧方言按操作数增量解码Bytes、保留DEX UTF-16并在分配前检查额度与预约，Native路径保持原样。目标红绿及SQL模块测试通过；首次严格Clippy报manual_contains并保留失败，修正后最终源码Windows工作区255项测试和严格Clippy通过，见 artifacts/mdd-031/legacy-concat-20261030-final/。最终源码独立桥探针构建完成后，运行前可用内存2082922496字节低于原3GiB门槛，未启动，见 artifacts/mdd-031-audit/legacy-concat-independent-20261030/runs/20261030T022444872913Z/report.json；不能将旧引擎矩阵等同最终桥对照。输入载体复制、SQLite副本、allocator及RSS未覆盖，完整语料和profile仍未准入。

MDD-005 A2 查询转换候选位于 benchmarks/a2_compact_adapter.py，涵盖shape、HEX DTO、分页终态、额度、错误透传与失败后禁止复用。固定A1及公开合成DEX在旧接口上曾完成7行分页并与标准MCP DTO一致，前期生产者参数配置失败保留在 artifacts/mdd-005/a2-adapter-development-20261030/。最终接口新增强制快照绑定与投影确定总序检查，仅做Python语法检查，尚无已验证回调或真实producer重跑；未连接完整HostLab pipeline，20组等价与A2性能资格均not_run，MDD-005仍in_progress。

2026-10-30 功能推进（统一验证待后续执行）：MDD-026 新增按 FieldSymbol 跨输入出现次数查询编码字段引用的懒索引、精确复验、独立标量扫描和失败重试；局部 field_symbol_indexes_preserve_sites_and_source_occurrences 通过，不推断运行时解析。MDD-034 实体来源标识在固定 JSON writer 路径按 UTF-8 边界分段，单次扫描最多约1024字节；局部 long_entity_text_is_chunked_without_changing_json 通过，其他序列化器与完整取消/性能资格未验证。MDD-031 旧方言新增无数值前缀文本/字节的零转换，逐单元检查预算和取消；数字、符号及小数点前缀仍显式未实现，Native 不变；相关三个局部测试通过，旧版 DTO 与完整数值语义未验证。依用户要求，完整工作区、跨平台、独立 oracle 及正式资格验证均留待统一执行，三项任务保持 in_progress。

2026-10-30 后续功能候选（统一验证待后续）：MDD-026 新增跨出现次数的UTF-16字符串编码引用站点查询与标量路径，孤立代理项等一项局部测试通过，未推断原始MUTF-8字节相等或运行时值。MDD-031 两个旧方言增加直接字符串字面量CAST AS TEXT与非负i64字面量比较，局部测试通过并保留白名单失败记录 artifacts/mdd-031-audit/direct-text-affinity-20261030/；Native、列、CTE、VARCHAR/CHAR、浮点及动态表达式未扩大。A2候选增加只在明确output_too_large、相同dataset未关闭且continuation guard允许时缩小页面的重试，最终分支仅语法检查，真实producer验证not_run。完整工作区、跨平台、独立oracle和资格统一留待后续，任务状态不变。

2026-10-30 第三批功能候选（统一验证待后续）：MDD-026 增加精确类型描述符跨出现次数的编码operand站点索引及标量路径，一项局部测试通过，不推断运行时解析/继承。MDD-031 增加严格完整ASCII有符号i64文本的旧方言算术候选，逐单元计步并用checked运算，小数/指数/尾部非空白、浮点混合及溢出仍未实现；两项局部测试通过，A0/A1现有54项为CAST而非算术证据，故算术等价未验证，记录 artifacts/mdd-031-audit/legacy-integer-text-candidate-20261030/。MDD-005 新增 benchmarks/a2_hostlab_session.py 同步桥候选，要求外部producer快照/总序、真实inventory、可确认close及进程树abort；仅py_compile通过，未接真实HostLab与未消费/取消完整验证。先物化查询改变管线重叠，后续性能归因须单列；统一验证和各任务资格均未完成。

2026-10-30 持续功能推进（全量验证后续统一执行）：MDD-026 增加按原型描述符跨输入出现查询编码Prototype operand站点的懒索引、精确复验和标量路径，038/039及重复出现等一项局部测试通过，不推断运行时分派。MDD-031 对无亲和性的字面量BETWEEN/NOT BETWEEN、简单CASE使用已有存储类型比较，并将旧方言直接TEXT CAST字面量对非负i64字面量的限定规则扩至上述结构；两个局部测试通过，A0/A1对照、跨平台及全量not_run。MDD-005 新增 benchmarks/a2_input_inventory.py 完整SHA与物理DEX清单候选，合成输入十项局部检查与固定HostLab清单规则对照通过，记录 artifacts/mdd-005/a2-input-inventory-20261030/record.json；文件观测不证明producer不可变快照、041逻辑完整性或SQL总序。任务和profile均未签发。

2026-10-30 持续功能推进续（全量验证后续统一执行）：MDD-026 方法句柄跨来源候选按完整句柄kind及FieldSymbol/MethodSymbol精确键返回实际编码operand站点，039字段/方法句柄、重复来源、无句柄引用和缺层/预算等一项局部测试通过；不推断实际调用、字段访问或运行时解析。MDD-031 两个旧方言对当前无歧义基础表I64/U64列的IN/NOT IN支持规范十进制i64字符串字面量；局部覆盖NULL、负数、未知列和Native边界，非规范文本、越界、浮点、参数、派生表/CTE仍保守未实现，最终A0/A1对照not_run。MDD-005 A2同步桥新增完成迭代后的有序DTO消费回执，区分NULL/空值、重复与顺序；原候选的零行schema未知、未消费不发回执，局部合成检查通过。回执不证明producer快照、总序或完整审计，编码开销需单独性能归因。

2026-10-30 继续功能候选（全量验证后续统一执行）：MDD-026 动态调用点新增同一快照、同DEX内容身份与完整原始encoded_array字节键查询，保留所有来源出现与编码引用站点，不声称不同DEX语义相等或推断运行时目标；局部fixture仅含前三个必需元素，合法附加参数、浮点和独立oracle未验证。MDD-031 旧方言对直接INTEGER CAST字符串字面量与规范i64文本字面量补充IN/NOT IN及=/<>限定候选；局部测试通过，首次编译因并行facts中间态失败，稳定后重跑通过；旧DTO uint64与候选i64仍不同，完整A0/A1差分未运行。A2 compact外层可选排序只接收shape中存在的列及固定方向，并引用原值；局部合成客户端/SQLite检查通过，最终语义等价、确定总序和producer快照仍须独立证明，额外排序成本需单独归因。各任务及profile仍未准入。

2026-10-30 继续功能候选续（全量验证后续统一执行）：MDD-026 支持按精确类descriptor跨出现次数查询直接声明字段/方法，复验候选及owner，不推断继承；一项局部测试通过，独立oracle未运行。MDD-031 旧方言仅对直接非负i64数字字面量 CAST AS TEXT 与非负i64字面量的等值比较补充候选，局部测试通过，旧wire uint64与候选i64仍不同，完整对照not_run。MDD-005 compact result()将同一次查询shape列、完整页、总行数与页数一并交付，同步桥v2消费回执可保留零行实际schema，原rows()保持列表；局部合成检查通过，最终真实producer、快照、总序及HostLab验证not_run。任务与profile均未准入。

2026-10-30 本轮后续功能候选（统一验证延后）：MDD-026 增加借用式方法事实视图，按同一DEX出现的method-id连接引用、prototype及可选真实definition，区分reference-only、native、abstract、present；未建代码和注解不填NULL，局部测试通过，HostLab methods关系及独立oracle未完成。MDD-031 对无关WITH保留可证明且未被可见CTE遮蔽的基础表IN作用域；局部检查覆盖别名、大小写遮蔽、派生表、歧义及未知列、递归拒绝，该次facts编译与并行修改有时间重叠，不当作最终工作区验证，A0/A1对照not_run。MDD-005 新增固定A1独占dataset关闭及空闲回读候选，合成DEX实际受控运行通过，见 artifacts/mdd-005/a2-dataset-close-20261030/record.json；两次环境/目录错误发生在作业创建前，非producer失败。此回读不证明快照、总序、生产进程树或A2资格，真实完整HostLab及全量验证均未运行。

2026-10-30 后续功能候选（统一验证延后）：MDD-026 新增借用式字段与类事实视图，完整metadata/definitions前提下分别保留同DEX field-id的引用/类型/可选定义及class_def顺序、NO_INDEX父类/源文件、直接接口ordinal；不合成初始值或注解、不推断继承，各一项局部测试通过，类/接口条数预算不等于扫描字节或RSS预算。MDD-031 共享Text/Bytes/DexMutf8比较逐单元检查额度和取消，保持原有UTF-16/原始字节排序；函数与真实SQL桥各一项局部测试通过，逐单元成本及A0/A1/独立oracle待统一验证。MDD-005 新增A1独占dataset打开候选：前后检查来源、空闲状态、输入路径与dataset回执，任何已提交生命周期请求在取消/超时/不确定结果时要求owner中止；12项模拟客户端局部检查通过，原始记录 artifacts/mdd-005/a2-dataset-open-20261030/run2/record.json。最终源码未连接真实producer，不证明快照、总序或A2资格。

2026-10-30 继续功能候选（统一验证延后）：MDD-026 新增同源method→code借用视图，绑定snapshot/occurrence/member/content并逐项核对真实物理code item起点和指令范围；区分reference-only、native、abstract、present及有体空指令，scoped缺项/partial明确失败，局部一项测试通过；旧opcode_count/hex、真实跨代和独立oracle未验证。MDD-031 对相关子查询IN按作用域由内向外解析可证明的基础表列，未知CTE/派生scope阻断推断、遮蔽/歧义/缺列保留真实绑定错误；局部首测发现合法CTE内部READ被预检误拒，后仅对当前AST可见CTE且database=None/column空的容器读取放行，局部测试及sqlite_master/DELETE/ATTACH拒绝检查通过。合成反例不证明真实HostLab corpus，A0/A1、独立安全及全量验证not_run。MDD-005 新增A1独占dataset生命周期组合，共享client/source/deadline，open/消费/close失败或取消要求owner确认中止；9项模拟客户端局部检查通过，记录 artifacts/mdd-005/a2-dataset-lifecycle-20261030/run2/record.json，不证明真实producer、快照、总序或A2资格。

2026-10-30 持续功能候选（全量验证后续统一执行）：MDD-026 增加同快照和DEX出现内的方法参数借用视图，区分未编码列表、显式零槽、非零集合及短列表Unknown；注解未建或位置不完整返回INCOMPLETE_FACTS，局部一项测试通过，兼容文本映射和独立oracle未运行。MDD-031 已解析CTE名称随PreparedSql传递；执行authorizer只放行database=None、空列名且名称命中的SQLite内部CTE容器读取，局部红绿覆盖直接/嵌套CTE及系统表、写入、ATTACH拒绝，A0/A1、独立安全和全量not_run。MDD-005 增加Windows自有Job持有期候选：隐藏无继承子进程挂起创建，分配验证后恢复，取消/期限/关闭核验自有child及Job归零；首次Job参数错误和中间清理竞态失败保留，最终 run5 注入创建失败时实际直接终止访问拒绝保留，随后确认同一子进程退出和树空，见 artifacts/mdd-005/a2-windows-job-owner-20261030/run5/record.json。无MCP双向通道，不证明Linux、输入快照、完整A2或资源资格。

2026-10-30 后续功能候选（统一验证延后）：MDD-026 同源MethodCodeBody增加无分配已解码普通指令opcode迭代，保留reference-only/native/abstract/present-empty区别，单独保存的switch/array payload不当普通指令；两项局部测试通过，旧HEX表示及独立A0对照未运行。MDD-031 对明确要求SQLite语法确认的AST未实现错误统一传递当时可见、已解析CTE名称；局部检查合法CTE仍返回真实UNSUPPORTED、缺列/禁用函数保持INVALID_ARGUMENT，相关IN回归通过，完整A0/A1/安全验证not_run。MDD-005 Windows受控双向管道仅有自有短命进程原型：两次准入分别3004952576与2064080896字节，低于原3221225472字节，均未创建Job或子进程；记录 artifacts/mdd-005/a2-windows-pipe-prototype-20261030/。Job句柄白名单、挂起恢复与双向IPC未运行、未实现，MCP及快照资格不推断。

2026-10-30 继续功能候选（统一验证延后）：MDD-026 增加借用式字符串引用站点视图，保留同源调用方法/PC/operand、原始MUTF-8及UTF-16、字符串池和每次输入出现；partial拒绝，完整消费预留两次遍历2N逻辑站点访问，局部1项测试含2N边界通过，字节/CPU/RSS及独立oracle未验收。MDD-031 Bytes/DEX MUTF-8文本解码逐编码点检查预算/取消，每次最多读取4字节；局部真实红绿及facts冻结后桥单项通过，见 artifacts/mdd-031-audit/text-decode-budget-20261030/bridge-final/record.json；输入载体、Text克隆、SQLite副本/RSS未覆盖。MDD-005 Windows显式handle_list自有Job管道候选有受界读写、stderr drain、后台首错传播、期限与取消清理；run6真实复现单个transport.close异常导致后续清理被跳过，修复后run7自有隐藏合成子进程13项检查通过；随后补保留首个异常对象链与取消原类型，最终源码run8两项定向检查通过，见 artifacts/mdd-005/a2-windows-pipe-owner-20261030/run8/record.json；run7的13项未在最终源码全部重跑，清理异常汇总并使cleanup不予确认。run1哨兵断言失败时未显式关闭owner，进程结束后只读未见该特征进程，但无该次Job树空证明；run2仅按句柄数值判断不能证明继承，后续才用内核事件身份；失败原始记录保留。stdout上限只计read消费量，OS/asyncio缓冲、RSS及启动前SHA/路径扫描不由此限额证明；EOF/close不是协议成功。真实MCP、快照、Linux、A2与完整验证均not_run。

2026-10-30 持续功能候选（统一验证延后）：MDD-026 新增同源借用式 Method/Field/Type 编码引用站点视图，保留 caller、target、operand位置与各输入出现，完整覆盖必需，2N逻辑站点访问与结果额度受限；一项局部测试通过，不推断运行时分派或字段访问。MDD-031 对已持有Text的LIKE、length和substr路径改用借用，避免预算检查前额外整段克隆；两项局部真实桥回归通过，见 artifacts/mdd-031-audit/text-borrow-20261030/，Bytes/MUTF解码及结果所有权保持，SQLite/输入/结果副本、RSS与性能未证明。MDD-005 新增固定MCP 2.2.0的Windows自有Job管道实验传输，受限换行JSON-RPC帧、UTF-8、重复键、帧/总量和取消/EOF错误；run4中14项局部检查包括固定A1+合成DEX open/query/close及Job树空通过，见 artifacts/mdd-005/a2-mcp-transport-20261030/run4/record.json。run1/2 AnyIO取消导致树空未确认的失败原样保留；SDK正常关闭可能让owner记录预期reader CancelledError，关闭意图/协议交流不证明页面已消费、快照或审计完成；SDK pending可能只报告connection-closed，原始传输错误需检查transport.failure。完整HostLab、A2、Linux、性能和profile均未准入。

2026-10-30 继续功能候选（统一验证延后）：MDD-026 增加按同snapshot/occurrence的MethodDefinition查找编码operand站点的懒索引及标量路径，可选TargetKind并精确复验caller，保留PC/ordinal/重数；扫描与结果额度、partial和失败重试的局部1项测试通过，不推断dispatch。MDD-031 Q08 lower/upper的Text/DexMutf8输出按checked UTF-16长度先预约QueryWorkspaceBytes及SQLite载体逻辑容量再构造，租约保持至ToSql；低额度、NUL/孤立代理、取消/释放三项真实会话局部检查通过，见 artifacts/mdd-031-audit/case-output-workspace-20261030/；输入载体、SQLite副本、allocator/RSS、性能与A0/A1未证明。MDD-005 A1BoundedCandidate组合自有Job、SDK、A1打开/查询/关闭；查询在rows()调用时登记，未启动、未消费、取消或worker loss阻断正常退出；固定A1和合成DEX的七项局部检查通过，见 artifacts/mdd-005/a2-bounded-candidate-20261030/run2/record.json。snapshot/order/inventory回调在测试中均为明确标注的模拟调用方断言，固定A1无generation/hash证明，qualified只读恒false；不证明完整HostLab、A2或性能资格。

2026-10-30 持续功能候选（统一验证延后）：MDD-026 按同snapshot/occurrence的物理AnnotationRef提供借用式完整encoded值节点及原始字节，保留序号/嵌套、NULL和float bits；局部测试对照现有oracle并覆盖假起点、跨来源、partial与逻辑访问额度，首次缺DecimalU64导入失败已修正，全量与独立整体验证not_run。MDD-034 QueryCancellation::checkpoint在同一生命周期锁内检查期限/worker错误与phase；取消、首个deadline、worker loss及完成态3项局部测试通过，见 artifacts/mdd-034-audit/checkpoint-atomic-20261030/record.json；原二次锁竞态是源码推断，未独立受控复现。MDD-031 增加单基础表、直接单列且与左侧已知类型相同的I64/U64/Text IN子查询，WHERE仍走原AST/readonly/依赖；局部三方言检查NULL/重复/空集/相关/别名、U64极值及Text非scalar，见 artifacts/mdd-031-audit/typed-in-subquery-20261030/cte-final/record.json。派生表深层CTE容器错误分类的静态担忧未复现：合法情况保持UNSUPPORTED，真实缺列为INVALID_ARGUMENT，未扩大授权；混合/F64、子查询WITH/ORDER/GROUP/DISTINCT/派生及完整Q14仍未支持，A0/A1及profile未准入。本批A2组合暂存后出现的跨task退出未暂存补丁来源未确认，未覆盖或收入本批；本地run3-cross-task仅针对该工作区补丁，未收入证据索引，不作为已提交版本验证。

2026-10-30 目标持续功能（统一验证延后）：MDD-005 基线consumer真实合成反例证明空structured DTO自报2行、字符串rows自报2行及布尔false fallback先前均被误认完整；现structured在缺少工作负载完整性验证器时明确拒绝资格，ordered/bag要求真实行列表、fallback要求整数0，合法零行仍接受，3项红绿及5项局部测试通过，见 artifacts/mdd-005/structured-completeness-20261030/result2.json。structured验证器仍待实现，未缩减任务原验收；首次反例因夹具类名称错误未运行，后按实际类重跑。MDD-026 增加同snapshot/occurrence的受界Java类型名渲染，primitive/对象/数组保留原descriptor及Unicode/嵌套，1项局部测试通过，见 artifacts/mdd-026/java-type-name-20261030/record.json；仅7个样本有历史A0观察。MDD-034 绑定队列deadline先登记query首错，防止receiver释放改为CANCELLED；实际红例及3项局部绿例见 artifacts/mdd-034-audit/queue-deadline-20261030/，非绑定、先前取消/worker loss保留原语义。MDD-031 旧方言单来源单列CTE直接CAST字符串AS TEXT与非负i64字面量比较候选，局部红绿及原混合比较回归通过，见 artifacts/mdd-031-audit/cte-text-affinity-20261030/；A0/A1未重跑、DTO和完整CTE资格未通过。现有A2未暂存补丁与run3证据按原样保留，本批未触碰。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 增加同一snapshot/DEX出现的method prototype参数类型借用视图，按ordinal保留真实TypeFact、引用及可选定义，不要求注解层，也不推断注解或旧参数文本；双来源、reference-only/definition、零/多参数、额度及错误身份一项局部测试通过，见 artifacts/mdd-026/prototype-parameters-20261030/record.json。MDD-031 冻结HostLab Q13的HEX输出现在按既有Native/legacy字节语义先计数、预约内部TEXT载体逻辑工作区，再构造并持有至ToSql；原512红例在元数据先触发quota而未触及HEX，调整后red2真实101、最终额度/编码/取消局部绿例通过，见 artifacts/mdd-031-audit/hex-output-workspace-20261030/；输入载体、SQLite副本、allocator/RSS与性能未覆盖。MDD-034 真实反例显示绑定send的quota后仍可发布Ok End，且在途发送或execute_into JSON计数时外部finish可提前发布成功；现发送在途和同队列producer整程租约阻断外部成功End/发送，首错和显式失败回执保留。真实竞态红绿、零/多行、quota、取消、弃置、预检、背压与未绑定局部检查见 artifacts/mdd-034-audit/bound-send-quota-20261030/；记录脚本的历史source_before未包括executor.rs，因此不能由该记录单独证明执行器源身份，status检查后并发取消的极窄窗口也未独立受控证明。以上任务/profile未准入，全量、跨平台与独立oracle后续统一执行；既有A2未暂存源码及记录本轮未修改。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 RawCodeEvidence 直接从完整验证的当前 method definition 构造同源实体并拒绝重复定义，避免逐项重复线性查找；双occurrence、共享code、原始bytes及既有手写/Python摘要局部检查通过，见 artifacts/mdd-026/raw-method-identity-20261030/。此为合成正确性范围，不是性能测量或全格式资格。MDD-031 MetadataSqlProvider 增加 native_types、native_prototypes 和有序 native_prototype_parameters，保留同snapshot各occurrence、原始MUTF-8、参数ordinal及真实offset NULL；真实桥单项和既有字符串回归通过，见 artifacts/mdd-031-audit/native-metadata-20261030/green/ 与 string-regression/。首次在max_cell=1时SQLite于虚表构造前返回INVALID_ARGUMENT而非游标QUOTA，原始失败与诊断保留；直接游标额度已单独验证，该极小SQLite长度下的桥接错误分类仍未解决。Owned行/SQLite副本/RSS和HostLab兼容未准入。MDD-034 真实零行红例在BudgetPool软期限到期后仍返回delivery_complete；候选从budget树复制不可变截止见证，session同一锁内核验query owner、cursor token/session/snapshot/epoch/request/schema/语义、其他游标/缓冲及较早截止，并原子确认cursor与最终交付，保留先前首错与计算完成状态。session两项及query两项局部绿例通过，见 artifacts/mdd-034-audit/receipt-budget-deadline-20261030/；query green2源码快照早于后续SQL provider测试诊断修改，不能当最终全部源码身份；完整并发、生产worker、跨平台及profile均not_run。本批未修改现有A2未暂存内容。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 类精确查询绑定所选快照、范围和覆盖，旧接口对空事实、partial和重复出现显式拒绝，不把所选范围缺失当全部输入缺失；两项局部检查见 artifacts/mdd-026/class-scope-20261030/，逐列及profile资格未通过。MDD-034 查询接收前拒绝已有记录的终态构造器；交付时的期限、取消及worker丢失保留覆盖与计算状态并产生错误终态，清理错误及详情键冲突保留首错。真实红绿、局部检查及最终源码两项检查见 artifacts/mdd-034-audit/nonpristine-terminal-20261030/ 和 artifacts/mdd-034-audit/late-delivery-envelope-20261030/；计数不一致为测试注入，分配器耗尽不保证追加详情。MDD-031 小单元格限额下仅对所需虚表进行受界预连接，恢复并回读SQLite长度后才准备用户SQL；最终源码7项局部检查包含真实单字节额度和2001列虚表失败后的恢复，见 artifacts/mdd-031-audit/vtab-prewarm-20261030/candidate/record.json。取消仅检查限额提升前，工作区逻辑额度不覆盖SQLite内部分配或RSS；下游完整编译、真实HostLab corpus、跨平台、性能及完整验收均未运行。各任务及profile状态不因局部候选改变；已有A2未暂存工作保留。

2026-10-30 目标持续功能（统一验证延后）：MDD-026 新增同快照和DEX出现内的物理annotation项到编码owner反查，保留共享集合、每个owner、set ordinal和参数编码槽，不推断参数语义；局部1项见 artifacts/mdd-026/annotation-owner-view-20261030/run2/record.json，孤儿及损坏集合由测试注入，逻辑访问额度不含结果向量/allocator/RSS。MDD-031 对同类型直接列的Bytes/Bool IN/NOT IN子查询增加候选支持，三方言和SQLite对照含NULL、重复、空集及相关子查询，既有类型回归也通过，见 artifacts/mdd-031-audit/in-subquery-bytes-bool-20261030/；记录只固定SQL两文件及lock，未锁全部依赖，A0/A1、混合类型/F64、完整Q14和profile未通过。MDD-005 生命周期文本与结构化回执现在类型敏感比较，打开后的嵌套回读同样比较，拒绝非JSON和非有限数；布尔/数字误认的合成红例、固定Python 3.12.14下5项检查及既有12项打开流程见 artifacts/mdd-005/a2-lifecycle-json-20261030/，解析递归错误为显式注入；两轮默认递归深度测试假设失败原样保留。不证明真实生产者兼容、输入快照或A2资格，也不单独限制解析内存。全量和跨平台验证未运行，用户既有A2未暂存补丁保留。

MDD-034 期限顺序补充：真实受控反例中两个期限都到期后，查询检查和绑定队列分别可能先报告较晚的期限；候选复制同owner预算截止见证并在生命周期锁内使用同一时刻比较，等时按原生命周期规则。另实际构造预算互斥锁中毒，修复见证读取错误未登记终态的问题并保留已登记首错。最终10项局部检查通过，记录 artifacts/mdd-034-audit/checkpoint-deadline-order-20261030/final/；不代表完整并发或生产worker验收。SQL新类型对照在本批query/session源码上又单项通过，见 artifacts/mdd-031-audit/in-subquery-bytes-bool-20261030/integrated/record.json；该记录仅固定列出的源码，非全量。

MDD-031 SQL桥仍进行中：受限虚表、会话预算绑定、U64真值、USING和子串路径有本机测试；独立真值18例及固定A0/A1子串16例通过，合成Q15结果与SQLite一致。真实完整corpus、legacy适配及生产工作区内存绑定尚未验收。检查点862b3dd的 Windows 离线测试161项、0失败/跳过，工作区严格Clippy通过，命令记录在 artifacts/integration/20261029/workspace-tests/ 与 workspace-clippy/。

后续 SQL 结果驻留预算修复在 Windows 工作区重新运行165项测试、0失败/跳过及严格Clippy；零行 schema 的零预算错误、结果持有与释放独立复现。该计量是保守逻辑额度，SQLite内部分配、provider/调用方副本、传输缓冲及租约自身元数据仍需单独准入，不能称 RSS 硬上限。证据 artifacts/mdd-031-audit/result-memory-probe/after-fix.json、artifacts/integration/20261029/workspace-tests-result-budget/record.json。

SQL 附加对照：真实合成DEX和无损参数两条路径覆盖空字符串、NUL、普通字符、孤立代理项与补充字符；固定A0/A1各7行 CAST TEXT 的 HEX 与原始MUTF-8一致，普通显示对孤立代理项有替换，与原始字节分开。冻结Q10聚合在合成provider上与SQLite对照，并验证缺事实及源变化真实错误。证据 artifacts/mdd-031/text-projection-20261029/runs/20261028T170439632106Z/readback.json、artifacts/mdd-031-audit/q10-aggregation-audit/qualification.json；不代表完整查询集资格。

SQL 比较路径已修复派生表同名遮蔽造成的 IN/NOT IN 静默错行，并支持可证明直接基础表 JOIN 的列作用域；Q03 合成provider与独立SQLite的重复行/别名反例通过，A0/A1固定小DEX另实际返回完整零行。未证明的亲和性返回明确未实现；旧版文本算术与部分文本转整数仍不兼容。该版 Windows 工作区168项测试及严格Clippy通过，见 artifacts/integration/20261029/workspace-tests-join-scope/record.json；本版Linux CI需对应提交后验证。

后续文本/bytes→INTEGER 转换在固定A0/A1的54项小样本上数值一致，但30项有 signed/unsigned DTO 类型差异，完整兼容仍受阻；Windows工作区170项测试和严格Clippy通过，见 artifacts/mdd-031/integer-cast-20261029/runs/20261028T174502714475Z/readback.json。Q04非零注解查询与A0/A1/SQLite的数值和顺序对照通过，但候选类型标签与旧wire不同，未签传输或profile资格。

LIKE模式预处理与尾部扫描现按单元计步并检查取消，token逻辑容量在分配前预留并在成功、配额失败和取消后释放。最终源码的Windows工作区176项测试、严格Clippy通过；独立真实会话实测低额度QUOTA、结果释放归零，以及观察到token预留后请求取消最终CANCELLED并归零，证据 artifacts/mdd-031-audit/like-workspace-independent-20261029/readback/record.json。该额度不覆盖SQLite、参数缓冲、allocator额外容量、RSS或传输；取消到达的具体内部指令不可观测。此历史检查点的尾部ESCAPE为INVALID_ARGUMENT；后续A0/A1及修复证据见下。

ORDER BY投影别名遮蔽输入列的静默错行已修复，含括号、位置编号、wildcard和NULL等限定反例；同一合成DEX的排序从10/9/8纠正为SQLite的-2/-1/0。独立桥探针72项覆盖排序、NULL、聚合及注入错误终态；SQLite限定对照通过，但已有A0 NULL结果的DTO包装仍不同，其他旧版方言未重新采样。Windows工作区177项测试和严格Clippy通过；见 artifacts/mdd-031-audit/null-aggregate-independent-20261029/qualification.json。

GROUP BY括号位置被误认常量的错分组已修复：同一13行样本从(0,13)改为SQLite的(0,7)/(1,6)；涵盖嵌套括号、符号、超32位位置范围常量、NULL/HAVING和真实绑定错误。最终源码Windows工作区179项测试、严格Clippy通过，独立桥90项含78项SQLite对照；未重启A0/A1，注入的源变化不等于真实磁盘变化。证据 artifacts/mdd-031-audit/group-ordinal-boundary-20261029/qualification.json。

多参数 min/max 已与单参数聚合分开，Windows工作区181项测试和严格Clippy通过。独立合成provider三方言69例中，45项默认BINARY结果与SQLite一致，6项零参数返回真实INVALID_ARGUMENT，18项显式COLLATE保持UNSUPPORTED_QUERY；provider尚无逐列collation元数据，不称NOCASE schema等价。未重启A0/A1，DTO/profile仍未准入。证据 artifacts/mdd-031-audit/multi-minmax-independent-20261029/qualification.json。

Q08使用的lower及对应upper现逐UTF-16单元计步骤并检查取消，真实会话长参数低额度反例由成功变为QUOTA；Windows工作区184项测试与严格Clippy通过。独立三方言60例涵盖SQLite可表示文本、孤立代理、长结果、配额和取消，证据 artifacts/mdd-031-audit/case-budget-independent-20261029/qualification.json。旧A0/A1对应完整语义未找到可比较记录，仍为not_run；参数复制、SQLite及传输内存不在该计步证明内。

Q15拼接路径对实际UTF-16或bytes复制计步骤，低额度真实红绿与隔离快照48项会话验证通过。SQLite对bytes拼接的HEX与候选相同但类型为TEXT而候选为Bytes，A0/A1该类型未采样，不能签DTO等价。参数解码、部分转换、结果载体、SQLite及RSS不在本轮计步范围。证据 artifacts/mdd-031-audit/concat-independent-20261029/verify-run/record.json。

`substr` 文本偏移表在分配前按 UTF-16 单元数量预留逻辑工作区并逐单元计步，配额失败和取消后释放；Windows工作区189项测试、严格Clippy通过，独立真实会话36例及固定A0/A1各5个已有参考对照通过，见 artifacts/mdd-031-audit/substring-independent-20261029/verify-run/record.json。SQLite截取含NUL文本返回空串，旧版与候选旧方言保留NUL及后续字符；Native按UTF-16单元、旧方言按有效代理对截取。旧版NULL DTO仍不同，参数/结果副本、SQLite、分配器实际容量、RSS和传输未由此额度覆盖；旧版其余3项已有样本未在该轮比较。

旧方言 `length` 对UTF-16的实际扫描现逐单元计步并检查取消；Native直接长度仍为常数时间。冻结源码的Windows工作区193项测试和严格Clippy通过，独立真实会话33例回读见 artifacts/mdd-031-audit/length-independent-20261029/verify-run/record.json。既有A0对补充字符和含NUL样本分别为1和3，SQLite为1和1，Native对补充字符按两个UTF-16单元计数；A1参考本轮未运行。额度仅为逻辑步骤，不覆盖参数副本、SQLite内存、分配器、RSS或传输。

HEX的字节输出和共享文本转字节扫描现计步骤并检查取消；独立真实会话45例保留 SQLite UTF-8 与 A0/A1 已存 MUTF-8 的不同字节，见 artifacts/mdd-031-audit/hex-independent-final-20261029/verify-run/record.json。前次因源码漂移导致独立回读失败的记录保留；参数和输出缓冲、SQLite、分配器及RSS/传输未由此计步覆盖。

Q09的NOT BETWEEN因生成SQL缺少括号而静默漏行，现使用显式嵌套修复；同一合成provider由空行恢复为SQLite的9、12。独立三方言27例中21项与SQLite一致、6项混合类型亲和性明确未支持，见 artifacts/mdd-031-audit/between-independent-20261029/after-readback/record.json；未重新运行A0/A1。最终源码Windows工作区200项测试、严格Clippy通过，完整SQL profile仍未准入。

DISTINCT/GROUP/ORDER文本或字节键构造现逐单元计步骤并检查取消，四个真实低步骤红例由错误完整成功改为QUOTA。冻结源码Windows工作区206项测试、严格Clippy通过；独立合成provider的三方言9个长键请求均返回QUOTA，见 artifacts/mdd-031-audit/hostlab-case-hex-independent-20261029/verify-run/record.json。键Vec、SQLite TRANSIENT及排序器副本、输入和RSS尚未受该步骤计量约束。

后续键Vec和带类型标记的Rust载体在分配前按检查过的上界预留逻辑工作区，租约持续至rusqlite设置结果调用返回；隔离快照48项真实会话、实际ToSql回调和低额度/取消释放独立验证，见 artifacts/mdd-031-audit/key-lease-independent-20261029/verify-run/record.json。SQLite TRANSIENT副本及排序器后续内存、参数/输入复制、分配器额外开销与RSS仍未覆盖。

固定HostLab CASE/HEX包装的合成对照发现：对旧方言输出的MUTF-8 NUL、代理对及孤立代理字节，现有CLI严格UTF-8解码步骤会抛UnicodeDecodeError；只直接复现了解码步骤，未运行完整HostLab。该适配边界、旧版NULL DTO和signed/unsigned差异仍阻断完整兼容。

旧版 NULL 单元包含 `value: null`，当前原生 SQL 单元仅含 `type: null`，固定 HostLab 消费者会读取 `value`；适配层必须明确补齐并验证。字面 CAST 的非负结果与DEX列 CAST 的类型不同，不能仅按数值正负推断旧类型。扩展旧版类型采样两次在打开样本时超时，未执行查询；错误保留于 artifacts/mdd-031-audit/dto-type-observations/，不能由此推断规则。

检查点862b3dd的 Windows 和 Linux CI 均通过，各161项测试、10条构建/检查/Clippy/探针命令原始记录已核验；有限 Linux ASan/fuzz workflow 通过，但本次执行次数尚未回读。见 artifacts/integration/20261029/ci-862b3dd.json。后续源码修改须另行验证，不能继承此检查点的CI结论。
