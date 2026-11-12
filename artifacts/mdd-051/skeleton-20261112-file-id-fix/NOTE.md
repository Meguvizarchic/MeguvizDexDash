# MDD-051 skeleton 复跑：`file_id` 映射更正

- 日期：2026-11-12。命令：`target/release/examples/hostlab_audit.exe <apk> [sha256]`，由 `cargo build --release -p mdd-facts --example hostlab_audit` 构建，源码为本工作区当时状态。
- `skeleton-20261110/` 中 `hostlab_file_id_by_dex_ordinal` 字段（Bilibili 9.16.1 为 `[0, 9, 10, 11, ...]`）来自旧的数值序映射，已被 A0 实测反证（见 `artifacts/mdd-032-audit/file-id-adjudication-20261112/SUMMARY.md`）。旧记录没有被改写，只是整体移出了仓库（见下）。
- 对真实 Bilibili 9.16.1 APK（sha256 `41efb1c9…bfb2`，私有输入）的复跑结果：`hostlab_file_id_by_dex_ordinal` 为 `0..32` 恒等映射；`class_count` = 310,716，与旧记录相同，并与 A0 `SELECT count(*) FROM classes` 的 310,716 一致；`features` 与旧记录逐项相等，`admitted=false`、`complete=false` 不变。该次运行的原始 JSON（含应用内部类名）属于私有输入的派生记录，**不入库**，只保留在本机被忽略的 `artifacts/local/mdd-051-private/`；旧的 `skeleton-20261110/` 同名记录同样移出。
- `member-policy.json`：ZIP 序 `classes10.dex`,`classes2.dex` 的合成样本，用于覆盖乱序归档（对应测试 `hostlab_file_id_follows_archive_enumeration_not_numeric_member_order`）。
- 范围：只证明 `file_id` 坐标更正与 class 总数一致，不构成 FEATURE 等价、profile 准入或性能结论。
