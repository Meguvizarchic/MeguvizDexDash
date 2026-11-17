# HostLab 结构审计适配（MDD-051）

通用核心（`crates/mdd-*`）不认识 BIL 包名、FEATURE、family 或 HostLab 的业务协议。这里的文件只做接线：让 HostLab **原样**的 `native_graph`、`native_rules`（Graph 与 27 条 FEATURE 业务规则）跑在 MeguvizDexDash 引擎上，并把“业务结论”和“引擎失败 / 覆盖不完整”分开记录。

| 文件 | 作用 |
|---|---|
| `native_session.py` | HostLab `native_session` 模块的替身：`literal`/`in_list`（与冻结源码同一行为）、`NativeSession(...)`。按提供方设置 `native_engine` 选路：`dexsql`（默认，即回滚值）返回 HostLab 自己的 `native_cli.CliSession`，不启动任何新引擎进程；`meguvizdexdash` 返回 `B0Session` 或 `B1Session` |
| `structural_provider.py` | 结构审计事务（对应 `native_audit.run`）：四种结局 `complete` / `audit_refused` / `incomplete_coverage` / `failed`，引擎身份、覆盖、可发布路径（只在 `<state>/mdd-engine/` 之下） |
| `structural_frozen.py`、`structural_compare.py`、`structural_equivalence.py` | 测试与生成器支持：冻结源码（先核对 SHA-256）作为对照、比较规则、负向对照。提供方本身不导入它们 |
| `make_structural_equivalence.py` | 生成 `artifacts/mdd-051/structural-equivalence.json`；`--check` 比对 |
| `test_structural_session.py`、`test_structural_provider.py`、`test_structural_equivalence.py` | 前两个不需要真引擎；第三个用真二进制，找不到就失败，不会跳过 |
| `../../conformance/hostlab/` | 合成输入的构造器（`structural_dex.py`、`structural_worlds.py`）、合成目录（`structural-catalog/`）、参考引擎黄金（`structural-goldens.json`）及其生成器（`structural_a0_golden.py`） |

## 两条线

- **B0**：HostLab 的语句、顺序与 DTO 原样：每次 `rows()` 先发 `LIMIT 0` 形状查询，再发十六进制投影；护栏（必须有 `ORDER BY`、列名不重、行数与字节预算、严格 UTF-8）相同。只换了线上格式（`mdd.cli-stream.v1` 的 JSON 行）。与 A0 比较，发出的 SQL 序列逐条相同。
- **B1**：直接读 typed 批：每次 `rows()` 只发数据语句一次（线上请求减半），不做十六进制往返；`batches()` 给想要类型值的消费者。DTO 与 B0 相同；REAL、BLOB、bool 单元格被拒绝而不是渲染；`dex_mutf8` 按 MUTF-8 解码（B0 与 DexSQL 对含增补字符的字符串直接拒绝，B1 能读，已登记为 W-B1-3）。

`native_session.WIRE_CHANGES` 登记了每一处与 DexSQL 传输层的差异（W-B0-1…6、W-B1-1…4）。

本任务只比较**结构**：Graph 的类记录、27 条 FEATURE 规则的结果，以及 call-count / protocol / family 形状的证据语句**作为语句**逐条比对（`structural_compare.EVIDENCE`）。family / protocol 的**分类**是 HostLab `surface_workers` 的能力，延至 MDD-052：这里不实现，也不声称具备该能力。

## 四种结局

| 结局 | 含义 | 例子 |
|---|---|---|
| `complete` | 所有语句覆盖完整，数据集层无问题，27 条 FEATURE 齐全，源文件未变 | FOUND / MISSING / PARTIAL / AMBIGUOUS 都是**结果** |
| `audit_refused` | 审计自己的结论（`UnsupportedAudit`）：重复类定义、不接受的签名、参考文件变化。类型与消息原样保留，**不是**引擎故障 | `duplicate class definitions in native structural audit` |
| `incomplete_coverage` | 引擎答了但没覆盖全：语句未完成、层构建失败（`layer_issues`）、DEX 清单不全。**不产生 MISSING**，也不回退 | `INCOMPLETE_FACTS` |
| `failed` | 其余：引擎拒绝（带引擎自己的 code）、没起来、丢失、协议错、超时、源文件不匹配 | `INVALID_INPUT`、`QUOTA_EXCEEDED`、`WORKER_LOST`、`DEADLINE_EXCEEDED`、`SOURCE_CHANGED` |

`run(...)` 与 `native_audit.run` 同行为：完整时返回记录，否则抛出**原来的**异常（`UnsupportedAudit` 仍是 `UnsupportedAudit`）。`run_structural(...)` 总是返回带 `outcome` 的记录。`provider.run_with_policy` 可以包住它：只有“这里没有”的三种 code 才可能回退，不完整覆盖和审计拒绝永远不回退。

## 配置

提供方设置（`provider.py`，已有）：

```json
{"schema": "mdd.hostlab-provider-config.v1", "native_engine": "meguvizdexdash",
 "meguvizdexdash": {"manifest": "<pin 清单>", "profile_policy": "allow_unadmitted"}}
```

结构设置（本模块，`HOSTLAB_STRUCTURAL_CONFIG` 指向文件，或直接传 dict；严格解析，未知键即错误）：

```json
{"schema": "mdd.hostlab-structural-config.v1", "wire": "b1",
 "sql_limits": {"result_rows": 1000000}}
```

`wire` 缺省为 `b0`；`sql_limits` 对应引擎的 `--sql-max-steps/-scanned-rows/-result-rows`（默认用引擎自己的预算；真实 APK 需要多大未知，见“未证明”）。

## 回滚

只改一处：`native_engine` 设回 `dexsql`。此后 `NativeSession(...)` 返回 HostLab 自己的 `CliSession`，不启动新引擎；业务规则（`native_rules.py`、`native_graph.py`）与目录没有被改动。新引擎已写的结果留在 `<state>/mdd-engine/reports/<engine>/structural/` 下，记录里仍写着是哪个引擎、哪条线（`backend`、`wire`）。

## 接入 HostLab 的方式

HostLab 里 `native_audit.py` 写的是 `from native_session import NativeSession`。把本目录放在 `sys.path` 中 HostLab 自己的 `tools/hostlab` 之前，该导入就得到本模块；其余 HostLab 代码一行不改。HostLab 不在本仓库，这一步没有实际执行（见“未证明”）。

## 命令

```bash
python -I -m unittest discover -s integrations/hostlab -p "test_structural_session.py"
python -I -m unittest discover -s integrations/hostlab -p "test_structural_provider.py"
python -I -m unittest discover -s integrations/hostlab -p "test_structural_equivalence.py"   # 需要 target/debug 下的二进制，或 MDD_WORKER_BINARY
python -I conformance/hostlab/structural_a0_golden.py --verify-inputs                        # 不需要任何二进制
python -I integrations/hostlab/make_structural_equivalence.py --check                        # 需要引擎二进制
python -I artifacts/mdd-051/mutation/mutate_structural.py                                    # 变异检查，需要引擎二进制
```

重新生成黄金需要参考引擎（dexsql 0.1.0，不入库）：`python -I conformance/hostlab/structural_a0_golden.py --a0 <dexsql 路径>`。

## 未证明

见 `artifacts/mdd-051/structural-equivalence.json` 的 `not_proven`：没有真实 APK 与真实 `audit_catalog.json`（目录与输入都是合成的）；`surface_workers.py` 不在冻结语料里（family/protocol 分类属 MDD-052）；没有对 HostLab 本体运行；没有计时；没有任何 profile 被准入；只在一台 Windows 主机验证。
