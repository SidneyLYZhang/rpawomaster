# RPaWoMaster

一个使用rust构建的密码管理器。

## 项目概述

刚刚开始使用Rust开始写的密码管理器，目前还只有少数功能可用。

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

因为目前只完成了部分功能，以下使用方式仅作测试使用。

```bash
# 运行程序
cargo run -- [参数]

# 查看帮助
cargo run -- --help
```

## 工程进度

| 功能/任务 | 状态 | 完成时间 |
|----------|------|------------|
| 命令行参数解析 | ✅ 已完成 | 2025-06-30 |
| 密码创建 | ✅ 已完成 | 2025-06-30 |
| 密码强度检验 | ✅ 已完成 | 2025-06-30 |
| 密码库初始化 | 📋 未开始 |  |
| 增加密码 | 📋 未开始 |  |
| 支持保存[动态令牌](https://2fasolution.com/index.html) | 📋 未开始 |  |
| 更新密码 | 📋 未开始 |  |
| 查找密码 | 📋 未开始 |  |
| 单元测试 | 📋 未开始 |  |
| 文档完善 | 📋 未开始 |  |
| 发布v1.0版本 | 📋 未开始 |  |

已经开始做密码库初始化功能……


## 贡献指南
1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## LICENSE

Copyright (c) 2025 Sidney Zhang <zly@lyzhang.me>

rpawomaster is licensed under [Mulan PSL v2](LICENSE) .