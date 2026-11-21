# HostLab 集成层（MDD-050）

这里只放 HostLab 专用的接线。通用核心（`crates/mdd-*`）不认识 BIL 包名、FEATURE、family 或 HostLab 的业务协议。

| 文件 | 作用 |
|---|---|
| `provider.py` | 后端选择与规划、启动参数与环境、错误分类与 fallback 策略、报告身份、独立目录、仍然有效的门禁（输入根目录、物理 DEX 清单、源 SHA） |
| `install_meguvizdexdash.py` | 把本地构建的引擎按**钉死的摘要**核验、登记（`pin`）、安装（`install`）。没有任何网络代码 |
| `config-schema.json` | 配置的 JSON Schema；`provider.parse_config` 与它接受/拒绝同一批文档（测试对比） |
| `make_provider_selection.py` | 生成 `artifacts/mdd-050/provider-selection.json`；`--check` 比对是否最新 |
| `hostlab_test_support.py` | 测试和生成器共用的桩引擎、冻结源码装载器（先核对 SHA-256）、小型 JSON Schema 校验器 |
| `test_install.py`、`test_provider.py` | 不联网、不需要引擎；冻结的 HostLab 源码（`conformance/corpus/hostlab/source-8782f43`）做对照 |
| `test_live_engine.py` | 用真实的 `meguvizdexdash` 二进制；找不到二进制就失败，不会跳过 |

## 选择规则

- 请求写 `sqlite` 或 `dexsql`：由 HostLab 自己的规划器处理，去向与以前完全一样，任何配置都不会把它们挪到新引擎。
- 请求写 `meguvizdexdash`：只由新引擎服务，或被拒绝；绝不由别的后端代替。
- 请求写 `auto`：看配置里的 `native_engine`。`dexsql`（默认，也是回滚值）得到与原规划器逐字节相同的计划；`meguvizdexdash` 把原本给 DexSQL 的那部分工作交给新引擎，`sqlite` 专属的工作（如 `refs` 的 `sites`）仍归 sqlite。
- 回滚只改一处：`native_engine` 设回 `dexsql`。此后写 `meguvizdexdash` 的请求会得到 `ProviderDisabled`，不会被悄悄改成 DexSQL。新引擎已经写下的报告、缓存、完成记录原样保留在 `<state>/mdd-engine/` 下，报告里仍写着是哪个引擎产生的。

## 安装

没有已发布的 `meguvizdexdash`，所以不下载。用本地构建：

```bash
python -I integrations/hostlab/install_meguvizdexdash.py --binary target/debug/meguvizdexdash pin --output integrations/hostlab/vendor/meguvizdexdash/manifest.json
python -I integrations/hostlab/install_meguvizdexdash.py --binary target/debug/meguvizdexdash install
python -I integrations/hostlab/install_meguvizdexdash.py --deep check
```

`pin` 运行二进制的 `version`、`capabilities` 和 `mcp` 的 `tools/list`，把摘要、版本、build id、profile、方言和工具集写进清单。清单是否入库由运维决定；`vendor/` 已被 `.gitignore` 忽略。

## 测试

```bash
python -I -m unittest discover -s integrations/hostlab -p "test_install.py"
python -I -m unittest discover -s integrations/hostlab -p "test_provider.py"
python -I -m unittest discover -s integrations/hostlab -p "test_live_engine.py"   # 需要 target/debug 下的二进制，或 MDD_WORKER_BINARY
python -I integrations/hostlab/make_provider_selection.py --check
```

## 完整审计 shadow（MDD-054）

| 文件 | 作用 |
|---|---|
| `run_shadow.py` | 在独立的状态/缓存/TEMP/结果目录里，各用一个 Windows Job（同样的内存、CPU、进程限制）跑 HostLab 原样的 `analyze.main audit --mode full`：A 用参考引擎，B 用本引擎（只替换 `native_session` 和 `install_dexsql`）。禁止 HostLab 的 config/远程/AI/发布入口和 Python 网络访问，试图触碰即记录并失败。目录互相重叠就拒绝启动 |
| `../../conformance/hostlab/compare_full_reports.py` | 两个完整运行的四层比较：运行身份、报告（只忽略引擎身份与时钟）、发布的 FEATURE 行、20 组证据（六组按多重集）。差异保留证据，不写“diff failed” |
| `make_full_equivalence.py` | 从已完成的运行写 `artifacts/mdd-054/full-equivalence.json`（只含身份、计数、摘要，不含证据内容或本机路径），并在真实证据的副本上做负向对照 |
| `test_compare_full_reports.py`、`test_run_shadow.py` | 不需要引擎也不需要 APK；变异检查 `artifacts/mdd-054/mutation/mutate_compare.py` |

```bash
# 需要隔离基线解释器（pywin32）、HostLab 参考源码、授权 APK；路径放在一个本地文件里，不入库
<baseline-venv>/Scripts/python.exe -B integrations/hostlab/run_shadow.py --manifest artifacts/mdd-054/shadow-manifest.json --paths <本地路径文件> --sample hostlab-9161100 --sides A,B --out artifacts/local/<新目录>
python -I -m unittest discover -s integrations/hostlab -p "test_compare_full_reports.py"
python -I -m unittest discover -s integrations/hostlab -p "test_run_shadow.py"
python -I artifacts/mdd-054/mutation/mutate_compare.py
```

状态：已完成两个授权真实样本（`9.16.1 / 9161100` 33 DEX 与 `9.17.0 / 9170100` 35 DEX）的完整 HostLab A/B shadow 审计并签发等价结论，详见 [full-equivalence.json](../../artifacts/mdd-054/full-equivalence.json)（`status = "equivalence_shown_on_the_runs_listed"`，`run`/`report`/逐字节 `tsv`/全部 20 组证据与 27 项 FEATURE 差异数为 0，`fallback_count = 0`，`violations = []`，并与 2026-10-29 历史 A0 基线交叉验证一致）。该结果是在 `non_scalar_text = "lossy-replacement"`（对非法单独代理项投影为 `U+FFFD` 以对齐 A0，引擎默认严格模式仍为 `reject`）及 `allow_unadmitted` 下取得，仅声明功能等价，不构成 `MDD-082` 性能替代资格。

## 可切换后端配置与单一配置回退（MDD-055）

| 文件 | 作用 |
|---|---|
| `enablement-config.example.json` | 显式启用与回退配置示例（`default_production_cutover = false`） |
| `ROLLBACK.md` | 启用前校验、报告溯源还原及单一配置回退操作手册 |
| `rehearse_cutover.py`、`test_rehearse_cutover.py` | 复演基线 `dexsql` → 显式切换 `meguvizdexdash` → 报告溯源还原 → 单步回退且不污染旧 cache |

```bash
python -I integrations/hostlab/rehearse_cutover.py --output artifacts/mdd-055/cutover-rehearsal.json
python -I -m unittest discover -s integrations/hostlab -p "test_*.py"
```

## 已知差异（对旧 dexsql 的调用方）

- 新引擎没有全局 `--threads`；`provider.mcp_arguments` 不传它，线程数通过环境变量 `MDD_FACTS_THREADS` 传入。直接把 DexSQL 的参数表换成新二进制会被引擎以 `INVALID_ARGUMENT` 拒绝（`test_live_engine.py` 有断言）。
- 引擎目前没有读取 `MDD_CACHE_DIR` 的代码；适配层仍然把独立目录交给它，是为了引擎接入持久缓存时已经隔离。`artifacts/mdd-050/provider-selection.json` 的 `engine_cache_variable` 记录了这一点。
- 所有 profile 的 `admitted` 目前都是 `false`。默认策略 `require_admitted` 因此会认为引擎不可用；要在开发中使用，把 `profile_policy` 设为 `allow_unadmitted`，报告里仍然写 `admitted=false`。
