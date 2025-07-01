# RPaWoMaster

之前使用python写了一个密码管理器，但是不是每个同事都有python，所以一直计划着写个新的通用性更强的版本。
而且都这么多年了，对于公司同事的密码管理现状，真的是依然不敢恭维。各种蜜汁操作。

安全不能只是口号吧，所以这个密码管理器在我写完python版本好几年之后，可算有了个雏形。

这就是这个使用rust构建的密码管理器的由来。

## 概述

刚刚开始使用Rust写的密码管理器，目前还只有少数功能可用，后续功能还在开发中。

## 安装指南

目前仅提供源码安装方式。

```bash
# 克隆仓库
git clone https://github.com/SidneyLYZhang/rpawomaster.git
cd rpawomaster

# 构建项目
cargo build --release
```

## 使用方法

因为目前只完成了部分功能，以下使用方式仅作测试参考使用。

```bash
# 运行程序
cargo run -- [参数]

# 查看帮助
cargo run -- --help
```

使用的第一步：

```bash
# 密码库的使用，第一步就是初始化密码库
cargo run -- init
```

## 工程进度

| 功能/任务 | 状态 | 完成时间 |
|----------|------|------------|
| 命令行参数解析 | :heavy_check_mark: 已完成 | 2025-06-30 |
| 密码创建 | :heavy_check_mark: 已完成 | 2025-06-30 |
| 密码强度检验 | :heavy_check_mark: 已完成 | 2025-06-30 |
| 密码库初始化 | :soon: 进行中 |  |
| 增加密码 | :soon: 进行中 |  |
| 支持保存[动态令牌](https://2fasolution.com/index.html) | 📋 未开始 |  |
| 更新密码 | :bookmark_tabs: 未开始 |  |
| 查找密码 | :bookmark_tabs: 未开始 |  |
| 单元测试 | :bookmark_tabs: 未开始 |  |
| 文档完善 | :bookmark_tabs: 未开始 |  |
| 发布v1.0版本 | :bookmark_tabs: 未开始 |  |

目前，密码库初始化部分已经初步完成了，但是迁移部分（通过文件导入密码库）还是毛坯房，可能要在导出功能完善后再继续开发。

现阶段主要搞增加密码和保存密码的部分，希望这部分可以顺利完成。

## 贡献指南
1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## LICENSE

Copyright (c) 2025 Sidney Zhang <zly@lyzhang.me>

rpawomaster is licensed under [Mulan PSL v2](LICENSE) .