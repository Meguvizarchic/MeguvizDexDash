# M1 直接 Worker 监督（`mdd-worker`）

`Supervisor` 负责启动调用方提供的 `Command`（固定 `stdin = null`、`stdout = pipe`、`stderr = null`），仅承担进程生命周期观察与输出监督；本模块不解析查询协议或 MCP 格式，收到任意 stdout 文本均不视为请求成功。

## 管道轮询、配额与终止传播

- Windows 平台通过 `PeekNamedPipe` 检查可读字节，Linux 平台使用非阻塞 pipe；每次轮询受固定读取上限约束，累计 stdout 字节预算与总期限直接继承自 `mdd-session` 的 `ResourceLimits`，不引入额外后台读取线程或无界队列。
- 遇到管道提前 EOF、子进程零或非零退出以及管道 I/O 错误时，所有未完成请求均标记为失败；超出 stdout 字节上限或总期限分别保留 `QUOTA_EXCEEDED` 与 `DEADLINE_EXCEEDED` 错误码，不会将其混淆为正常结束或不支持能力。已经进入有效终态的请求继续保留其终态。

## 进程清理与平台验收边界

- 监督结束时会终止（kill）并等待（wait）直接子进程，随后关闭管道读取端。当前实现尚未集成 Windows Job Object、Linux 进程组或 cgroup，因此不负责多级子孙进程清理，也不提供安全沙箱或进程树硬隔离资格；若未来 worker 允许再派生辅助子进程，须先补齐真实进程树管理。
- 当前模块测试通过启动本 crate 测试二进制的独立子进程，覆盖非零退出、零退出但缺失终态、子进程存活时提前关闭 stdout、输出超限及超时场景（测试专用环境变量不构成对外服务接口）。Linux 平台实现须在原生 Linux 环境实测，不得以 Windows 通过替代 Linux 验证。
