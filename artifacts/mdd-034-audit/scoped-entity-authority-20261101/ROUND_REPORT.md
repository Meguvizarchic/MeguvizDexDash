# MDD-034 独立实体键索引：本轮记录

范围：基于已实际绑定 Snapshot、SelectedScope 和捕获 DEX 的 ScopedCatalog 建立受额度约束的实体键索引。该索引只检查 provider 返回的实体键相对于所选事实集合是否存在；不认证 provider 的其他事实、字节内容、输入授权或覆盖完整性。原 generic FactSource 执行入口仍未修复，不能据此关闭 MDD-034。来源身份核对不能证明 provider 内部并发变化的完整历史；provider 自身回调、析构、分配器开销不受该索引预算证明。

实际红例：
- `scan-red`：scan 期间改变来源后直接返回迭代器，原包装未在返回前核对；退出 101。
- `drop-red`：已观察 SourceChanged 后 provider 析构取消查询，原未绑定 runtime 时取消可掩盖首错；退出 101。
- `runtime-swap-red`：将绑定查询 A 的旧公开 runtime 包装用于查询 B，错误地停止 A；退出 101。现有 runtime 包装已私有，只在新严格执行入口从相同 Control 获取，不对外暴露。
- `eof-drop-red`：EOF 后迭代器析构改变 provider 身份，原代码返回成功；退出 101。
- `limit-positive`：测试消费者丢弃未确认数据包，队列返回 `queue.delivery` Cancelled；属测试消费错误，不是可忽略的成功。现消费者确认每个数据包再消费终态，保留原失败与诊断。
- `run1` 为最初夹具缺少仅引用、不定义实体的失败；`run2` 为调整夹具后的针对性运行，具体以原日志为准。

当前通过：`strict-internal` 实体索引 3/3、扫描和首错 5/5、不同 query 与预算树 1/1；`limit-positive-fixed` 使用真实扫描的 LIMIT 1，在 streaming/reference、SDK/JSON、正常/析构改变来源共 8 场景执行，1 项测试通过。`final-strict` 的 `cargo check --locked -p mdd-query` 与 JSON 定向回归 13/13 通过；其前后所列源码与 Cargo.lock 哈希一致。各项结果并非全量测试或 HostLab 替代资格。

边界：严格入口依然不认证提供者事实内容；public 无 runtime 包装仅返回可观察错误，不承担 lifecycle 首错保证。任意 provider 回调/析构内部的变更与取消不可原子排序；已观测错误在释放对应 provider 值前登记，但析构内部先发生的取消不得重写成 SourceChanged。JSON consumer 若使用无 runtime 包装，不能据此声称完整认证。尚需独立复核及兼容/任务完整验收，未执行全量、跨平台、性能或真实 HostLab 差分。

索引与检查的条目、逻辑字节、查找步数和行数是独立额度，不自动计入 `RuntimeBudget` 的 `QuerySteps` 或 `QueryWorkBytes`；provider 回调的实际工作、排序耗时、分配器额外容量和 RSS 也不由这些额度证明。
