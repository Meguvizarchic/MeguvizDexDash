# MeguvizDexDash 桌面工作台（功能预览）

引擎之上的一个窗口：打开 DEX/APK 输入，看每个事实的来源，跑 SQL（分页如实标注“是否已读完”），读 smali 并顺着引用走，看 Manifest 与资源，比较两个输入集，导出完整结果。

它**没有**自己的解析器或查询引擎，也不链接任何 `mdd-*` crate：窗口启动一个 `meguvizdexdash mcp` 子进程，用 HostLab 同一套 MCP 协议（逐行 JSON-RPC）问它。窗口能做什么，完全由引擎的 `tools/list` 决定。

状态：**功能预览**。不准入任何 profile，不带性能结论，没有安装器、签名和自动更新。决策与取舍见 [ADR-desktop-shell](../../docs/adr/ADR-desktop-shell.md)，任务 MDD-073。

## 结构

| 位置 | 内容 |
|---|---|
| `src/engine.rs` | 工作进程监督：一个 MCP 子进程，一次一个请求；取消 = 结束进程，输入按路径记住、下次使用时重新打开；看门狗 |
| `src/api.rs`、`src/main.rs` | 窗口能向壳要什么（Tauri 命令只是它们的外壳） |
| `src/export.rs` | 完整导出：先 `count(*)`，再按全部列排序分页，行数核对一致才保留文件 |
| `src/diff.rs` | 两个输入集的比较：两边都完整读完才比较（行数对账 + 键唯一），逐方法 smali 行差异（Myers） |
| `ui/` | 静态 HTML/CSS/ES 模块，没有 npm、没有打包器；`ui/lib/` 是不碰 DOM 的纯函数 |
| `ui-tests/` | 前端纯函数的 Node 测试 |
| `tests/` | 壳对真实引擎进程的测试（没有替身引擎） |
| `e2e/` | 驱动**真实窗口**的用户流程（WebView2 走 DevTools 协议，Linux 的 WebKitGTK 走 WebDriver） |
| `check_boundaries.py` | 边界检查：不链接核心、依赖图里没有 HTTP 客户端、窗口没有文件/shell/HTTP 权限、CSP 不放行外连 |
| `package.py`、`verify_package.py` | 便携包（zip / tar.gz）与按包内清单的校验，再用解包后的副本跑用户流程 |

这是一个独立的 Cargo 工作区（自带 `Cargo.lock`，约 390 个包）：核心工作区的锁文件、CI 与默认构建都不依赖它。

## 构建与运行

先构建引擎（工作台在自己旁边或 `MDD_ENGINE` 找它）：

```powershell
cargo build -p mdd-cli                 # 仓库根目录
cd apps/desktop
cargo run                              # 开发构建的窗口
```

引擎的查找顺序：环境变量 `MDD_ENGINE`；与窗口程序同目录的 `meguvizdexdash`；仓库的 `target/debug` 或 `target/release`。

运行条件：Windows 需要 WebView2 运行时（Windows 11 自带）；Linux 需要 GTK 3 与 WebKitGTK 4.1。

## 测试

```powershell
cd apps/desktop
cargo test                             # 单元测试 + 壳对真实引擎的测试（要先构建引擎）
node --test ui-tests/*.test.mjs        # 前端纯函数
python check_boundaries.py             # 边界
node e2e/run.mjs                       # 真实窗口的用户流程（先 cargo build）
python package.py                      # 发布构建 + 便携包
python verify_package.py dist/<包> --run-flows
```

用户流程的定义在 `conformance/desktop/user-flow-cases.json`，实现在 `e2e/flows.mjs`；一条流程只有它的所有检查都通过才算通过，跑不了的记 `not_run`。依赖本地被忽略文件的流程（公开的 NewPipe APK）在文件不在时记 `not_run`，不会被算作通过。

## 已知限制

- 引擎一次只处理一个请求；取消就是结束进程，下次操作要重新打开输入（NewPipe 约 3 秒）。
- 比较只比较**定义**，方法按操作码序列比；“操作码序列相同”不证明操作数相同，要点开一对方法做 smali 对比。引擎一次最多分页 10 万行，更大的输入用类前缀缩小范围。
- 引擎的 `capabilities` 命令输出落后于 MCP 工具面（只列 `cli-*` 传输），窗口原样展示它并以 `tools/list` 为准。
- 引擎的 SQL 不支持递归 CTE、`instr`、`group_concat`；窗口用 `LIKE … ESCAPE`。
- 默认 SQL 预算比引擎默认值宽（2 亿步、5 千万扫描行），可在“引擎与设置”页看到并恢复。
- 只有中文界面；没有评估键盘可达性与读屏。
