# MeguvizDexDash `1.2.2` 可复验发行清单目录（MDD-083）

本目录包含标准 DEX 发行所需的无构建噪声清单、 cyclonedx `SBOM.json`、HostLab 显式启用模板、`python/mdd` 与 C ABI `1.0` 源码库存摘要，以及跨平台统一摘要 `SHA256SUMS`（编译出的二进制可执行文件与 `.zip`/`.tar.gz` 安装包由可锁定复现命令本地产出，不直接提交至 Git 仓库）。

- 查看详细发布边界与实测数据：`docs/RELEASE_NOTES.md`
- 查看 HostLab 分阶段启用与单步回滚手册：`docs/OPERATIONS_AND_ROLLBACK.md`
- 运行离线发布检验与实时环境复演：
  - `python -O -I tools/verify_mdd082.py --check`
  - `python -O -I tools/verify_mdd083.py --check`
