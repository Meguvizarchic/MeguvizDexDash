# ADR-desktop-shell：桌面工作台用 Tauri 2 加静态 HTML/JS，事实只经 MCP 工作进程取得

- 状态：accepted（外壳的选择与新增依赖由所有者于 2026-11-18 确认；Windows 已实测，Linux 运行证据来自 CI，见“验证与退出条件”）
- 日期、作者、关联任务：2026-11-18，root，MDD-073
- 替代 ADR：无；沿用 ADR-001 的工具链与边界、ADR-003 的结果与能力语义
- 范围：`apps/desktop/`、`conformance/desktop/`、`artifacts/mdd-073/`；不含 profile 准入、性能资格和对外发布

## 背景与约束

ENGINEERING_PLAN 6.6 与 `docs/01_DECISIONS_AND_DEPENDENCIES.md` 的 UI 行要求：桌面工作台复用同一 SDK/worker，提供输入与来源检查、查询、xref、Smali、差异、取消和导出；不得在 UI 里另写查询/解析器，也不得先做漂亮空壳；默认可评估 Rust 加轻量 WebView，具体框架以可支持的平台和打包实测决定。AGENTS.md 要求新生产依赖先经用户确认并锁定实际构建过的版本，核心不依赖 UI 的工具链。MDD-073 验收：真实 UI 流程、差异保留来源/重复/unknown 边界且不把未加载页显示成完整无结果、长任务不阻塞界面且取消后资源有界释放、默认本地无上传且能力来自同一份能力清单、Linux/Windows 运行与打包可复验。

引擎的事实（实测）：MCP 服务逐行 JSON-RPC，一次只处理一个请求，没有取消通知；超期的查询会关闭它所在的输入集；`query` 的偏移加行数最多 10 万；`methods` 关系同时列出定义与只被引用的方法；SQL 不支持递归 CTE、`instr`、`group_concat`；`capabilities` 命令的能力清单落后于 MCP 工具面。

## 决策

1. **外壳**：Tauri 2（`tauri 2.12.6`、`tauri-plugin-dialog 2.8.4`、`tauri-build 2.7.5`，传递的 `wry 0.57.2`、`tao 0.37.2`），前端是静态 HTML/CSS/ES 模块，没有 npm、没有打包器。原生的“打开文件/另存为”对话框由 Rust 侧调用，窗口本身不被授予文件系统权限。
2. **独立 Cargo 工作区**：`apps/desktop` 自带 `Cargo.lock`（约 390 个包），核心工作区的 `Cargo.lock`、默认构建和 CI 不受影响；用 `check_boundaries.py` 持续检查。
3. **不链接任何 `mdd-*` crate**：壳启动 `meguvizdexdash mcp` 子进程，用 HostLab 同一套十二个工具取事实。哪些视图可用由引擎的 `tools/list` 决定，窗口里没有写死工具清单。规则只在两种情况下停用视图：引擎起不来，或引擎列出了工具而缺视图所需的那个；**空清单表示“此刻未知”，不是“引擎什么都没列”**（引擎进程没在运行时，例如设置变更正在重启它，壳报告的就是空清单），空清单不停用任何视图；“引擎正忙于别的请求”（`ENGINE_BUSY`）也不是“无法启动”，不覆盖已知的引擎信息。这是包验证时发现并修复的竞态，规则在 `ui/lib/availability.js`，有单元测试、变异检查和一个连续重启引擎时采样按钮的真实窗口检查。
4. **一次一个请求；取消 = 结束进程**：壳保持引擎的“单飞”槽，第二个请求立即得到 `ENGINE_BUSY` 并说明是谁占着；取消、壳的看门狗和引擎的期限都会结束进程。已打开的输入集按路径记住，壳给每个输入集一个稳定的句柄（引擎侧的 dataset id 每次打开都变），下一次用到时再打开。窗口轮询的状态（引擎是否运行、工具清单）不与请求争同一把锁，否则长查询会卡住窗口。
5. **完整性靠对账，不靠约定**：导出先 `count(*)`，再按全部列排序、用语句自己的 `LIMIT … OFFSET …` 分页，行数对得上才改名为最终文件，否则删除半成品。比较把两边的类与方法完整读完（先计数，行数必须到达，键必须两两不同——这同时证明分页没有漏行或重复行），读不完整就整体失败。界面上每一页都说明“是否已读完”，空结果只有在引擎确认完整时才写“结果为空”。
6. **比较的措辞**：只比较定义（`access_flags` 非 NULL）；方法按引擎给出的操作码序列比，`opcodes_equal` 明确写成“操作数未比较”，要证明相同只能对一对方法做 smali 行差异（Myers）；没有 code item 的定义与空方法体分开；重复定义按出现次数保留；每个出现位置带着它的 DEX 成员名。
7. **本地且不外连**：窗口的 CSP 为 `default-src 'none'`，`connect-src` 只有壳自己的 IPC；窗口权限只有 `core:default`；Windows、Linux、macOS 三个目标的依赖图里没有 HTTP 客户端 crate（Android 目标里有 `reqwest`，不在发布范围）。
8. **SQL 预算**：窗口的默认预算比引擎默认值宽（2 亿步、5 千万扫描行），因为一个人浏览一个应用时常要扫描它最大的关系；预算、方言和期限在“引擎与设置”页可见、可改、可恢复引擎默认值，预算耗尽按 `QUOTA_EXCEEDED` 如实显示。
9. **打包**：便携包（Windows zip，Linux tar.gz），含窗口、同目录的引擎、README 和带每个文件 sha256 的 manifest；确定性归档（排序、固定时间戳）。不做安装器、签名、自动更新。

## 候选与取舍

- **egui/eframe**：单个可执行文件、没有 WebView 依赖，可用 egui_kittest 做进程内 UI 测试。未采用：偏离文档默认路线；中文字体要自己加载，大表和 smali 视图要自己做虚拟化。
- **Tkinter + 现有 Python SDK**：零新增依赖。未采用：打包成桌面制品要再引入 PyInstaller 之类，界面能力最弱，Linux 还要额外装 python3-tk，难以满足“运行与打包可复验”。
- **链接 `mdd-service` 进程内调用**：更快，但引擎崩溃或长查询会拖垮窗口，取消也无法有界释放，且在 UI 里形成第二个核心的入口；违背工作进程隔离。
- **用 `serve` 的二进制帧协议（有取消帧）**：未采用：它只有查询，没有 decode、Manifest、资源工具，还要在壳里再实现一遍帧协议。
- **Electron / 浏览器加本地 HTTP 服务**：体积与运行时未评估；后者不是桌面集成。
- **tauri 的 opener/fs/shell/http 等插件**：不引入；窗口不需要它们，也不应被授予。

## 实测（Windows 11，本机）

- 干净的开发构建 70 秒；依赖图约 390 个包；开发构建的窗口程序 14.8 MB，发布构建见 `artifacts/mdd-073/desktop-workflows.json` 的打包记录。
- WebView2 运行时 140.0.3485.94；真实窗口用户流程 15 条中 15 条通过（含公开的 NewPipe 0.28.6 APK 一条）。
- 取消一个正在跑的长查询：壳的测试断言引擎进程在 2 秒内结束；用户流程断言按下“取消”后 3 秒内窗口显示 `CANCELLED`，期间忙状态条的计时继续前进、切换视图仍然响应；取消后同一个输入集的下一次查询自动重新打开输入。
- 开发这个任务时，真实窗口测试暴露了三个单靠接口测试看不到的缺陷，都已修并有回归测试：轮询引擎状态会等长查询（取消失灵）、点引用会打开只被引用的行（没有代码）、比较把只被引用的方法当成“没有代码”。

## 已知限制（诚实声明）

- 取消即结束进程：重新打开大输入要时间（NewPipe 约 3 秒）。
- 引擎一次最多分页 10 万行：更大的输入的比较要用类前缀缩小范围，读不完整会报错，不会给出“没有差异”。
- 比较的方法粒度是操作码序列，不含操作数；方法体差异只能一对一对地用 smali 对比看。
- 导出按全部列排序分页，宽表的大结果可能触发 SQL 预算，需要在设置页调高。
- 引擎的 `capabilities` 命令输出落后于 MCP 工具面；窗口原样展示它并标明以 `tools/list` 为准。
- Windows 上需要 WebView2 运行时（Windows 11 自带，旧版 Windows 10 可能没有）；Linux 需要 GTK 3 与 WebKitGTK 4.1。
- 只有中文界面；没有评估键盘可达性与读屏；没有安装器、签名、自动更新。
- 只在一台 Windows 主机上验证过本地窗口；macOS 没有运行证据，不 advertise。

## 验证与退出条件

- `cargo test`（单元 14、对真实引擎进程的测试 17）、前端 31 项、`cargo clippy -- -D warnings`、`cargo fmt --check` 通过；工作区边界与 `check_boundaries.py` 通过。
- 用户流程 `conformance/desktop/user-flow-cases.json` 的每一条由 `e2e/run.mjs` 驱动真实窗口执行；一条只有它所有检查都通过才算通过，跑不了的记 `not_run`。
- Linux：同一批用户流程在 CI 的 ubuntu-24.04 上通过 `tauri-driver`/WebKitWebDriver 驱动解包后的包；在此之前 Linux 一律记为 `not_run`，不从 Windows 结果推断。
- 本 ADR 不授予任何 profile 准入，也不代表性能资格；MDD-082 仍是正式发行的前提。

## 迁移与兼容

窗口只依赖引擎的公开 MCP 面；引擎升级后重新跑 `tools/list` 与用户流程即可，不需要改核心。要换外壳（egui 等），只需重写 `ui/` 和 `src/main.rs` 的 Tauri 绑定，`engine.rs`、`export.rs`、`diff.rs` 与测试不变。回滚：删除 `apps/desktop` 与 `.github/workflows/desktop.yml`，核心不受影响。

## 证据

- `artifacts/mdd-073/desktop-workflows.json`
- `conformance/desktop/user-flow-cases.json`
- `apps/desktop/check_boundaries.py` 的输出（记录在上面的文件里）
