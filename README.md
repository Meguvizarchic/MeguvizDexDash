<p align="center"><img src="docs/brand/MeguvizDexDash.svg" width="96" height="96" alt="MeguvizDexDash"></p>

# MeguvizDexDash

MeguvizDexDash 是面向桌面与服务端的 Rust DEX 静态分析引擎（当前版本 `1.2.2`）。开发者既可以通过命令行与 MCP 服务检查 APK 和 DEX，也可以在 Rust、Python 或 C/C++ 应用中按需读取定义、代码布局、引用与资源数据。

## 核心能力

- 读取 APK 中的多个 DEX 成员，支持单磁盘 ZIP32/ZIP64 中的 STORE 与 DEFLATE 条目，保留同路径或同内容的重复成员。
- 解析标准小端 DEX 035、037、038、039、040，读取字符串、类型、原型、定义、注解、代码布局与操作数引用。
- 基于单次捕获的不可变快照复用分析结果，支持类型化查询 IR、只读 SQL 查询、Smali 输出、Manifest/资源解析以及 MCP 工具服务；当前所有 profile 的 `admitted` 均为 `false`（功能预览阶段）。

## 快速开始

在仓库根目录运行以下命令。Rust 工具链版本由 [rust-toolchain.toml](rust-toolchain.toml) 固定为 `1.99.0`。

```sh
cargo build --locked -p mdd-cli
cargo run --locked -p mdd-cli -- capabilities
cargo run --locked -p mdd-cli -- inspect-apk app.apk
```

`inspect-apk` 与 `inspect-dex` 用于清点归档成员和检查 DEX 文件头结构。需要读取方法定义、代码布局等高层数据时，可通过 Rust 示例按需访问各事实层：

```sh
cargo run --locked -p mdd-facts --example quickstart -- app.apk
```

## 文档与接入工具

- [AI 接入与迁移技能](.agents/skills/meguviz-dex-dash/SKILL.md)：包含工程盘点、Rust/CLI/MCP/Python/C ABI/桌面五种消费形态选型、完整性校验与排障指南
- [接入指南（Rust API、输入限制与错误处理）](docs/guide/README.md)
- [桌面工作台（功能预览）](apps/desktop/README.md) · [Python SDK](python/mdd/__init__.py) · [C ABI 头文件](include/mdd.h)
- [命令行参数](crates/mdd-cli/src/args.rs) · [Rust 示例](crates/mdd-facts/examples/quickstart.rs)
- [提交问题](https://github.com/Meguvizarchic/MeguvizDexDash/issues)

## 适用范围与验证说明

当前版本处于功能预览与源码接入阶段，尚未通过生产 profile 合格认证，不可用于直接替换已认证的生产 DexSQL 环境；所有分析结果的完整性应结合各自接口返回的多轴完整性字段共同判定。复制、修改或分发前，请联系维护者确认授权。
