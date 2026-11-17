# HostLab 的 surface 与原始指纹（MDD-052）

`surface_provider.py` 把 HostLab 的类/方法 surface、原始 code 指纹和原始资源指纹交给 MeguvizDexDash 引擎。通用核心（`crates/mdd-*`）仍然不认识 BIL 包名、family 或协议；这些规则（`FAMILIES`、`PROTOCOLS`、`family()`、`summarize`、`compare`、`resource_changes`、`verdict`）仍是 HostLab 自己的 `surface_workers.py` / `priority_analysis.py`，通过 `Host` 注入，不复制。

## 文件

| 文件 | 作用 |
|---|---|
| `surface_provider.py` | 提供者本体：开关、两层过滤的 SQL、按 DEX 文件扫描、`serve` 流客户端、报告与哈希、独立缓存 |
| `surface_gate.py` | 原样运行并完整计时 HostLab 的独立 intake/home 门禁；记账里没有“门禁复用收益”这一项 |
| `surface_support.py`、`surface_fake_serve.py` | 测试与生成器共用：冻结源码装载（先核 SHA-256）、关系型引擎替身、可按脚本说话的假 `serve` |
| `surface_make_goldens.py` | 用参考引擎（dexsql 0.1.0）驱动冻结的 `native_cli.CliSession` 与 `native_surface.scan`，写 `conformance/hostlab/surface-goldens.json`；`--check` 离线复核 |
| `surface_make_equivalence.py` | 在真引擎上跑，写 `artifacts/mdd-052/surface-equivalence.json`（输入全部哈希，负向对照全部真执行）；`--check` 比对 |
| `test_surface_provider.py`、`test_surface_switch.py`、`test_surface_gate.py`、`test_surface_goldens.py` | 离线单测，不联网、不需要引擎 |
| `test_surface_live.py` | 用真实 `meguvizdexdash`；找不到二进制就失败，不会跳过 |
| `../../conformance/hostlab/surface-source-8782f43/` | 冻结语料缺的三份 HostLab 源码（`surface_workers.py`、`audit_common.py`、`priority_analysis.py`），字节级复制，SHA-256 与已入库的 `evidence/hostlab_verification.json` 逐字相同（`surface_import_sources.py --check`） |
| `../../tests/fixtures/surface/` | 5 个合成 APK 与手工推导的期望（`generate.py --check`） |

## 开关与回滚

`surface_provider` 是**独立**的设置（`dexsql` 默认，也是回滚值；`meguvizdexdash`）。它不依赖 `provider.py` 的 `native_engine`：引擎可以只服务 surface，也可以只服务结构审计。

- `dexsql`：调用原来的 `native_surface.scan`，什么都不启动；引擎文件在不在都一样。
- `meguvizdexdash`：`provider.launch` 重新核验引擎，再用 `serve` 流读事实；引擎不可用是错误，不会悄悄退回原路径。
- 缓存只有一份：`<state>/mdd-engine/reports/<engine>/surface/`，由 `SCHEMA.json` 占位；条目按“源 SHA-256 + 规则哈希 + 引擎 build + 二进制摘要 + 方言”寻址，**不符合就拒绝，不读不改**，已写入的不覆盖。`dexsql` 路径既不读也不写它，旧缓存格式从不进入这里。

接入 HostLab（本任务没有改 HostLab 本体）：`native_audit.run` 里 surface 那一段

```python
report = native_surface.scan(session)
report["resource_fingerprints"] = resource_fingerprints(apk)
report["scan_execution"] = {...}
```

换成 `surface_provider.run_surface(apk, sha256=..., surface=<SurfaceConfig>, config=<provider.Config>, host=default_host(), state=..., legacy_session=NativeSession)["report"]`。`SurfaceConfig` 由 `load_surface_config()` 读（环境变量 `HOSTLAB_SURFACE_CONFIG`、文件或字典）。

## 与原路径的差异（逐条有测试，理由写在 `surface-goldens.json` 的 `declared_differences`）

1. **DIFF-1** 某个 DEX 里的家族类都没有方法时，原路径在 `summarize` 抛 `KeyError('compose_signatures')`（已用真参考引擎复现）；新路径把这些类当作无方法的类，摘要是空内容的 SHA-256。
2. **DIFF-2** 读到的每个关系（classes、class_fields、class_methods、method_calls、code_items）都 SELECT 出 `file_id` 并逐行核对是不是所问的 DEX 文件的，跨文件的回答拒绝（`SourceMismatch`）；归档里读到的字节先与引擎事实记录的头部字段（长度、版本、checksum、signature）绑定，再用偏移。**绑定只比较这些头部字段，不重算 adler32/SHA-1**；整文件同一性靠运行前后两次 APK SHA-256 校验兜底，ZIP 读取器自带每个成员的 CRC 校验。
3. **DIFF-3** 同一 DEX 内一个 `method_idx` 对应两个方法，或一个方法有两行 code，原路径静默取最后一个；新路径拒绝。
4. **DIFF-4** 引擎的回答只有在终止行说“ok、完整、未截断、同一快照”时才被接纳；局部、截断、出错都是错误，不是空结果或更短的结果。
5. **DIFF-5** 家族过滤的 SQL 写成等价的平衡树（动态页的三个关键词展开成三条腿）。原因是引擎 debug 构建遇到 20 项以上的 OR 链（或约十层括号嵌套）会**整个进程栈溢出**——见下。提供者在发送前设硬上限：OR 项数超过 `MAX_OR_TERMS=64`、或整条语句括号嵌套超过 `MAX_SQL_DEPTH=9` 就拒绝（`SurfaceError`），不把引擎会溢出的条件发出去。实测家族过滤本身深度 8，按文件包装 `AND (...)` 后实际最深语句深度 9（classes/class_fields/class_methods/method_calls），引擎深度 9 通过、10 溢出。
6. **DIFF-6** `scan_execution.backend` 写实际引擎；它不进报告哈希。
7. **DIFF-7** 归档里有两个成员与数据集中某个 DEX 同名时，原路径用 `zipfile.getinfo` 静默取最后一个；新路径在用其字节前拒绝（`SourceMismatch`）。物理出现次数不被去重消除：无法判定事实描述的是哪个成员的字节，就拒绝而不是替它选。
8. **DIFF-8** 一个 `file_id` 对应两个 DEX 文件、或两个 DEX 文件共用一个 entry name 时，原路径 `session.files` 是 dict（重 id 静默取最后），同名要到扫描开始后才落进“数字编号歧义”拒绝；新路径 `read_identities` 在读任何事实前就拒绝两者（`SourceMismatch`）。

分页契约：`serve` 流（`mdd.cli-stream.v1`）按请求里的 `batch_rows` 分批，请求只认 `id/sql/batch_rows/max_rows/deadline_ms`（`deny_unknown_fields`，没有 `page_size`）。`ServeSession.rows(page_size=...)` 的非默认值被拒绝（`ValueError`），不静默忽略；原 CLI 传输同样接受却从不使用 `page_size`，新路径选择 fail-closed 拒绝。

方法无 body：不进摘要的字节部分，只贡献 `name+proto`；“有 code item 但 insns 为空”在摘要里与无 body 相同（与原路径一致），但证据里分开写 `none` / `empty` / `present`。资源重名：与原路径一致，后者覆盖前者，证据里列出全部出现。

## 发现但没改的引擎问题

`meguvizdexdash serve` / `mcp`（debug 构建，Windows）收到一个由 20 个 `LIKE` 用 OR 链起来的条件时，进程以 `0xC00000FD`（栈溢出）直接退出，没有错误消息；条件嵌套到约十层括号也一样（实测深度 9 通过、10 溢出）。HostLab 的原家族过滤有 35 项，所以原样把 SQL 发给引擎会崩。这在 `artifacts/mdd-052/surface-equivalence.json` 的 `observed.or_chain_of_the_original_filter` 里每次重生成时都会重新观察。引擎应在大栈线程里解析/求值，或把深度超限变成 `INVALID_ARGUMENT`。**本任务不改引擎（零 Rust 改动）**；集成侧用平衡树把深度降到 8/9，并在发送前以 `MAX_OR_TERMS=64`、`MAX_SQL_DEPTH=9` 硬上限拒绝会溢出的条件（DIFF-5），作为 fail-closed 守卫。引擎栈溢出缺陷由主代理另开 backlog 任务。

**更新（2026-11-17，MDD-084）**：引擎已修复——`predicate` 改成小栈帧递归（叶子求值拆成不内联的独立函数），SQL 改写在 16 MiB 线程上进行并限深 64，深度超限给出 QUOTA_EXCEEDED。用修复后的构建重生成 `surface-equivalence.json` 后，原家族过滤的 35 项 OR 链已能回答（`answered: true`，`exit_status: 0`）。本提供者的 `MAX_OR_TERMS`、`MAX_SQL_DEPTH` 和平衡树写法**保持不变**：放宽它们是 MDD-084 约定的独立变更，而且对早于该修复的引擎构建仍是必要的保护。

## 命令

```bash
python -I -m unittest discover -s integrations/hostlab -p "test_surface_*.py"      # 含 live，需要 target/debug 下的二进制或 MDD_WORKER_BINARY
python -I tests/fixtures/surface/generate.py --check
python -I conformance/hostlab/surface_import_sources.py --check
python -I integrations/hostlab/surface_make_goldens.py --check
python -I integrations/hostlab/surface_make_goldens.py --declare                 # 离线只刷新 declared_differences 块，再 --check
python -I integrations/hostlab/surface_make_equivalence.py --check                  # 需要引擎二进制
python -I integrations/hostlab/surface_make_goldens.py --a0 <dexsql-windows-amd64.exe>   # 重新冻结 golden，需要参考引擎（不入库）
python -I artifacts/mdd-052/mutation/mutate_surface.py                              # 变异检查，写 results.txt（尾部 sources sha256 绑定），本机跑一次约半小时以上
```
