<p align="center"><img src="docs/brand/MeguvizDexDash.svg" width="96" height="96" alt="MeguvizDexDash"></p>

# MeguvizDexDash

MeguvizDexDash 是面向桌面与服务端的 Rust DEX 静态分析引擎。可以通过命令行检查 APK 和 DEX，也可以在 Rust 应用中按需读取定义、代码和引用等结构化数据。

## 能力

- 读取 APK 的多个 DEX 成员，支持单磁盘 ZIP32/ZIP64 中的 STORE 和 DEFLATE 条目，保留重复出现的成员。
- 解析标准小端 DEX 035、037、038、039、040，读取字符串、类型、定义、注解、代码布局和引用。
- 基于同一次输入读取复用分析结果，支持类型化查询。命令行提供 SQL 查询与 MCP 查询服务，可用的关系和查询限制由接口报告。

当前提供源码接入，适合独立文件分析与集成评估。分析范围以所用接口为准，查询结果应结合其完整性标记使用。[接入指南](docs/guide/README.md)

## 快速开始

从仓库根目录运行以下命令。Rust 工具链版本由 [rust-toolchain.toml](rust-toolchain.toml) 管理。

```sh
cargo build --locked -p mdd-cli
cargo run --locked -p mdd-cli -- capabilities
cargo run --locked -p mdd-cli -- inspect-apk app.apk
```

`inspect-apk` 和 `inspect-dex` 用于清点成员和检查 DEX 文件结构。需要读取方法定义、代码布局等信息时，可用 Rust 示例按需访问各层数据。

```sh
cargo run --locked -p mdd-facts --example quickstart -- app.apk
```

## 文档

- [Rust API、输入限制与错误处理](docs/guide/README.md)
- [命令行参数](crates/mdd-cli/src/args.rs)
- [Rust 示例](crates/mdd-facts/examples/quickstart.rs)
- [提交问题](https://github.com/Meguvizarchic/MeguvizDexDash/issues)

复制、修改或分发前，请联系维护者确认授权。
