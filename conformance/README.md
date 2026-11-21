# 当前可执行验证清单

本目录及配套工具用于复验 MeguvizDexDash 的契约一致性与源码完整性。运行环境固定为 Rust `1.99.0` 与 `requirements-dev.lock` 指定的 Python 环境（Windows 本地使用 `.venv/Scripts/python.exe` `3.12.14`，双平台 CI 固定为 Python `3.12.10`）。

## 验证命令

- `python tools/verify_original_handoff.py`：从不可变初始 Git 提交重建原包并严格校验其指纹，不用于替代引擎功能测试。
- `python conformance/oracles/reproduce.py`：生成并比对小型语料、手工期望、独立解析器编码及变形用例。
- `cargo test --locked --workspace`：运行当前工作区各模块单元测试与集成测试。
- `cargo build --locked -p mdd-cli` 后运行 `python conformance/check-cli-contract.py --binary <实际二进制路径>`：核对真实 `capabilities` JSON 输出与各 profile 的未认证状态。
- `python conformance/check-workspace-boundaries.py`：检查工作区依赖图不存在对外部业务包或桌面壳的反向依赖。
- `cargo run --locked -p mdd-build-probe`：运行真实依赖与只读 SQLite 虚表有限实验，如实保留并输出语义差异。
- `python tools/check_progress.py`：校验 `tasks/backlog.json` 唯一任务图、已完成任务的依赖与产物存在性以及证据摘要；该校验通过不自动授予任何 profile 合格认证。

## 适用范围与记录说明

- 所有命令记录由 `tools/record_command.py` 自动保存执行参数（argv）、工作目录、退出码、原始 stdout/stderr 与摘要；记录中的耗时仅为开发过程观测，不可当作正式性能试次。
- 大型私有 HostLab 语料、A0/A1/A2 正式配对性能基准以及完整 AOSP 格式资格认证仍按 `STATE.md` 中列出的阻断项逐项恢复，不得将未运行或跳过的用例计为通过。
