# M1 生命周期注册表（`mdd-session`）

本 crate 负责管理快照、会话、查询、游标与批次句柄的生命周期及逻辑资源预留；自身不执行 SQL 或类型化查询，也不签发任何已认证的 profile。

## 句柄与所有权模型

- `Lifecycle` 可通过 `Arc` / `Mutex` 在多线程间安全共享。快照（`SnapshotHandle`）、会话（`SessionHandle`）、查询（`QueryHandle`）与游标（`CursorHandle`）均为相互独立的 Rust 类型，运行时会同时校验随机 runtime owner、对象身份、代次（generation）与父对象归属。
- 原始句柄不可自行反序列化；对象释放后旧句柄会被明确拒绝。有效句柄的 `close` 操作具备幂等性，`release` 则非幂等。
- 注册表与会话/查询各自持有 `Arc<Snapshot>`：`close_snapshot` 仅停止接收新的会话创建，已存在的会话继续有效；`release_snapshot` 移除注册记录，已有租约继续保留同一份不可变字节。
- `close_session` 仅取消所属未完成查询并关闭其游标，不影响其他会话。原生 `catalog_epoch` 在 prepare 阶段即固定，后续目录代次变化不会替换旧游标的绑定。

## 执行阶段、消费确认与监督边界

- `QueryPhase` 严格区分执行态（`Prepared` / `Queued` / `Active`）与终态（`Completed` / `Cancelled` / `Failed`）。`complete_execution` 释放计算线程预留，并保留 `Active` 交付阶段；`finish_cursor` 用于确认对应结果已消费。
- 若关闭或释放尚未消费确认的游标，对应查询的交付会被永久标记为已放弃，不能通过删除游标再调用 `finish_delivery` 伪造成功。只有在计算完成且全部游标已消费后，`finish_delivery` 才会标记成功；计算完成后的取消保留 `execution_complete = true`。
- `ResourceLimits` 在全局、会话与查询层级中取最严格的值，覆盖线程预留、句柄数、缓冲字节预留与总期限。额度设置为 `0` 即表示零配额；所有缓冲预留均属于逻辑配额检查，不代表内核 RSS 硬限，未实现的硬限制能力继续上报为 `unavailable`。
- 每个 `Lifecycle` 实例同一时刻最多绑定一个 `WorkerSupervisionLease`；worker 丢失会将所有未完成请求一次性标记为失败，已完成终态保持不变，失效运行时不会自动重开或复用旧会话与旧游标。
