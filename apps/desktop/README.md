# MeguvizDexDash 桌面工作台（功能预览）

MeguvizDexDash 桌面工作台是引擎之上的交互式图形界面：支持打开 DEX/APK 输入、查看每个事实的物理来源、运行 SQL 查询（分页明确标注是否已读完）、浏览 Smali 并按引用跳转、检视 Manifest 与资源、对比两个输入集并导出完整结果。

工作台**没有**内置解析器或查询引擎，也不链接任何 `mdd-*` crate：窗口通过启动 `meguvizdexdash mcp` 子进程，使用逐行 JSON-RPC 2.0 MCP 协议与引擎通信，界面功能完全由引擎返回的 `tools/list` 决定。

## 目录结构

| 位置 | 职责说明 |
| --- | --- |
| `src/engine.rs` | 工作进程监督：单进程串行处理，同一时间最多执行一个在途请求；取消即终止子进程，输入按路径记录并在下次使用时重新打开，内置看门狗 |
| `src/api.rs`、`src/main.rs` | 工作台后端命令接口（Tauri 命令仅为外层转发壳） |
| `src/export.rs` | 完整导出：先执行 `count(*)`，再按全列排序分页拉取，行数核对一致后才保留输出文件 |
| `src/diff.rs` | 双输入集对比：确认两边均完整读完后（行数对账 + 键唯一性校验）才进行对比，支持逐方法 Smali 行级 Myers 差异 |
| `ui/` | 静态 HTML/CSS/ES 模块，无 npm 构建链与打包器；`ui/lib/` 为不接触 DOM 的纯函数 |
| `ui-tests/` | 前端纯函数的 Node.js 单元测试 |
| `tests/` | 桌面壳对真实引擎子进程的集成测试（不使用替身引擎） |
| `e2e/` | 真实窗口端到端用户流程测试（Windows WebView2 走 DevTools 协议，Linux WebKitGTK 走 WebDriver） |
| `check_boundaries.py` | 边界脚本：校验不链接核心 crate、依赖图无 HTTP 客户端、窗口无直接文件/shell/网络权限且 CSP 禁止外连 |
| `package.py`、`verify_package.py` | 生成便携包（zip / tar.gz）并按包内清单校验，随后使用解包副本复跑用户流程 |

`apps/desktop` 是独立的 Cargo 工作区（自带 `Cargo.lock`，约 390 个依赖包），引擎主工作区的锁文件、默认构建与 CI 均不依赖它。更多架构取舍见 [ADR-desktop-shell](../../docs/adr/ADR-desktop-shell.md)。

## 构建与运行

首先在仓库根目录构建引擎二进制（工作台默认在同级目录或通过 `MDD_ENGINE` 环境变量查找）：

```powershell
cargo build -p mdd-cli
cd apps/desktop
cargo run
```

引擎查找顺序：`MDD_ENGINE` 环境变量 -> 与桌面可执行文件同目录的 `meguvizdexdash` -> 主仓库 `target/debug` 或 `target/release`。

系统运行依赖：Windows 需要 WebView2 运行时（Windows 11 默认自带）；Linux 需要 GTK 3 与 WebKitGTK 4.1。

## 测试命令

```powershell
cd apps/desktop
cargo test                             # 单元测试与真实引擎集成测试（须先构建 mdd-cli）
node --test ui-tests/*.test.mjs        # 前端纯函数测试
python check_boundaries.py             # 依赖与权限边界检查
node e2e/run.mjs                       # 真实窗口用户流程（须先执行 cargo build）
python package.py                      # 发布构建并打便携包
python verify_package.py dist/<包名> --run-flows
```

用户流程用例定义在 `conformance/desktop/user-flow-cases.json`，测试脚本位于 `e2e/flows.mjs`；某条流程仅当所有检查均通过时记为通过，缺失本地忽略测试文件（如公开的 NewPipe APK）时对应流程记为 `not_run`，不会计入通过。

Windows 下端到端驱动通过 WebView2 调试端口通信，默认经 `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` 注入端口参数。自 WebView2 Runtime 150 起，管理员提升权限运行的宿主会忽略 `WEBVIEW2_*` 环境变量；当设置 `MDD_WEBVIEW2_POLICY=1` 时，驱动改为写入 `HKLM\SOFTWARE\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments\<exe 名>` 并在窗口关闭后清理，适合提升权限的 CI 环境，本机普通开发无需设置。

## 已知限制与适用范围

- **状态定位**：工作台当前处于**功能预览**阶段，尚未签发任何正式 profile，不附带性能结论，亦不提供安装器、代码签名与自动更新机制。
- **并发与取消**：引擎子进程同一时间仅处理一个请求；取消操作会结束当前子进程，下次操作须重新打开输入（以 NewPipe 为例约 3 秒）。
- **对比与分页**：对比功能只针对定义层，方法按操作码序列匹配（操作码序列相同不保证操作数完全相同，须点开具体方法核对 Smali 差异）；单次分页最多 10 万行，超大输入需按类名前缀缩小查询范围。
- **SQL 与工具面**：`capabilities` 命令输出暂只列 `cli-*` 传输，工作台已原样展示并以 MCP `tools/list` 为准；引擎 SQL 不支持递归 CTE、`instr` 与 `group_concat`，工作台检索改用 `LIKE ... ESCAPE`；桌面端默认 SQL 预算放宽至 2 亿步、5 千万扫描行（可在“引擎与设置”页查看或重置）。
- **界面与无障碍**：当前仅提供中文界面，尚未进行键盘可达性与读屏器无障碍评估。
