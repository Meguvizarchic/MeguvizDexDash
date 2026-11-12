# `file_id` 序裁决：A0 是归档枚举序，不是 `classes<N>.dex` 数值序

- 日期：2026-11-12（Asia/Shanghai）
- 范围：裁决 STATE 第四轮「明日待办 2」——A0 的 `dex_files.file_id` 顺序与项目内两处数值序实现的冲突
- 性质：实施与取证记录。**不**宣称 HostLab 等价、profile 准入或 MDD-032 完成

## 结论

| 项 | 裁决 |
|---|---|
| A0（`dexsql 0.1.0`，sha256 `f354ebcf…c448`）的 `file_id` | **归档枚举序**（ZIP 中央目录顺序，选中 DEX 成员的 0 起编号），不重新按 `classes<N>.dex` 数值排序 |
| `NativeSession::hostlab_file_ids()`（`mdd-facts/src/hostlab/mod.rs`） | **旧实现错误**：把 `classes<N>.dex` 映射为 `N-1`。已改为恒等映射（`file_id == dex_ordinal`，裸 DEX 为 0） |
| `SEMANTIC_DIVERGENCES["file-id-vs-dex-ordinal"]`（`rules.rs`） | 文案同步更正 |
| `surface::dex_file_order()`（`mdd-facts/src/surface.rs`） | **保持数值序，不是错误**：它复现 `native_surface.scan` 的 `names.index(name)`（A0 `file_id` → 数值名次的二次映射），属 native_surface 指纹契约，不是 DexSQL `file_id`。字段名 `file_id` 易误导，建议 MDD-052 处理（本轮未改） |
| `mdd-sql` 的 `dex_files.file_id`（`SelectedDex.file_id`） | 与 A0 一致，无需改动（032-A 子代理的取证结论成立） |

## 证据

`reproduce.py` 在临时目录合成 4 个乱序归档并对 A0 取原始表，另取真实 Bilibili 9.16.1，结果在 `a0-observations.json`：

- 4 个合成归档（`zip-lex`/`zip-numeric`/`zip-reverse`/`zip-twelve`，后者 12 个成员乱序）`a0_order_equals_zip_order` 全为 `true`。
- 真实 APK（sha256 `41efb1c9…bfb2`）：`file_id` 0..7 = `classes.dex`、`classes10.dex`、`classes11.dex`…`classes16.dex`；`file_id=4` 是 `classes13.dex`，在 A0 里有 **7,328** 个类，**不是** `classes5.dex`（本引擎 skeleton 记录为 12,038 个类）。旧注释所称「file_id=4 恰为 classes5.dex 的类」被 A0 直接反证。
- 参考实现 `hostlab/analysis_batch.py` 的 `Session.open` 用 `SELECT file_id,entry_name FROM dex_files ORDER BY file_id` 取原始坐标；`native_surface.py:scan` 再用 `names.index(name)` 另行映射到数值名次。两层是不同契约。

## 代码改动

| 文件 | 变更 |
|---|---|
| `crates/mdd-facts/src/hostlab/mod.rs` | `hostlab_file_ids()` 改为恒等映射；非稠密 ordinal、多出现裸 DEX 仍显式报错；不再因 `classes<N>.dex` 命名拒绝输入 |
| `crates/mdd-facts/src/hostlab/rules.rs` | 更正 `file-id-vs-dex-ordinal` 的 reference/native 文案 |
| `crates/mdd-facts/tests/hostlab_skeleton.rs` | 新增 `hostlab_file_id_follows_archive_enumeration_not_numeric_member_order`（`member-policy.apk`：ZIP 序 `classes10.dex`,`classes2.dex` → `[0,1]`；旧实现会得 `[9,1]`）；更正旧断言注释 |

旧实现下新增测试的失败值 `[9,1]` 由旧代码逻辑推得，**未**在旧代码上实际运行（旧代码已被替换）。

## 未做 / 不覆盖

- 未对「A0 的 `file_id` 是否按中央目录序、还是按本地头偏移序」做区分：真实 Bilibili APK 与全部合成归档两种顺序一致，没有判别样本。
- A0 遇到非 DEX 或策略排除的成员时的编号行为，仅有 `member-policy.apk` 一例，未穷举。
- `surface.rs` 中 `SurfaceDexFile.file_id` 的命名误导未改（范围外，仅在此建议）。
