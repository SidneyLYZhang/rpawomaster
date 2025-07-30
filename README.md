# RPaWoMaster

之前使用python写了一个密码管理器，但是不是每个同事都有python，所以一直计划着写个新的通用性更强的版本。
而且都这么多年了，对于公司同事的密码管理现状，真的是依然不敢恭维。各种蜜汁操作。

安全不能只是口号吧，所以这个密码管理器在我写完python版本好几年之后，可算有了个雏形。

这就是这个使用rust构建的密码管理器的由来。

另外还有一个很重要的问题：为什么执着于自己写一个密码管理器。因为不是自己写的，在单位就是用不了啊。
还有一个额外的原因，我也先练习一下自己写rust代码的能力，现在不长写Haskell、lean4、racket了……
就有很多地方不太会写了……

## 概述

使用Rust写的密码管理器，目前可用功能有：

1. 密码库初始化（含密码库导入）
2. 密码生成
3. 密码强度检验
4. 增加密码
5. 查找密码
6. 导出密码库
7. 列出密码/密码库
8. 简单的加密/解密功能

## 密码安全吗？

我看到过很多人说密码保存一处，甚至和2FA也保存在一起，是个隐患，因为一损俱损。听起来也是蛮有道理的。
但是，无论如何分开保存，加密方法终有穷尽，安全永远只是相对而言的。

安全、好用、便捷，总归是相互矛盾的，从可控的角度来看。所有这些问题都在不可控的范围里，
无论对谁，都是认为我是无名小卒，不会被特别对待，从而获得相对的密码安全。

绝对安全，当然还是依赖绝对的物理隔离，这就没有好用和便捷可言。
好用，也意味着安全只是暂时的。分开保存密码和2FA，也是为了多一个隔离而已。
其实也并非是安全的。

这也是现在很多加密都是嵌套多层来加强保密安全性，或者使用具有更高数学难度/复杂度的算法，
实现加密安全。都是一种妥协。

分开密码和2FA，但使用同样的（相似的）密码管理，一样是高风险的行为。保证密码本身的难以被破解，
和不被泄露，可能才是相对安全所真正需要的。

所以我自己搞的这个密码管理器，会强制检查核心密码，并会设定不可更改的核心密码更新周期。
也能管理2FA（一次性密码），但是也要求2FA的验证密码和核心密码需要不同，验证密码也要求达到密码等级要求。
同时，更严格的离线保存模式，麻烦而且要多次验证的导入和导出返航，适合要求保密要求较高的情况，
当然如果完全物理隔离，这也不失为另一个还行的选择。

但我的这些设定都是被动的，并不能避免密码有人来破解，核心要点依然是核心密码和2FA使用的验证密码，
这两个关键密码的复杂度和保存方式。至少默记密码的难度还是下降了一些，不是吗？

## 安装指南

可使用源码安装，或使用`Cargo`安装。

源码安装方式：

```bash
# 克隆仓库
git clone https://github.com/SidneyLYZhang/rpawomaster.git
cd rpawomaster

# 构建项目
cargo build --release
```

Cargo安装：

```bash
cargo install rpawomaster
```

## 使用方法

因为目前只完成了部分功能，以下使用方式仅作测试参考使用。

```bash
# 查看帮助
$ rpawomaster --help

A secure password manager written in Rust

Usage: rpawomaster.exe <COMMAND>

Commands:
  init      Initialize a new password vault
  gen       Generate a new password
  add       Add a password to the vault
  update    Update an existing password
  delete    Delete an existing password
  list      list all existing passwords
  search    Search passwords in the vault
  testpass  Test password strength and properties
  vaults    List all password vaults
  crypt     Encrypt or decrypt files/directories
  export    Export password vault
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

使用的第一步：

```bash
# 密码库的使用，第一步就是初始化密码库
rpawomaster init
```

## 工程进度

| 功能/任务 | 状态 | 完成时间 |
|----------|------|------------|
| 命令行参数解析 | :heavy_check_mark: 已完成 | 2025-06-30 |
| 密码创建 | :heavy_check_mark: 已完成 | 2025-06-30 |
| 密码强度检验 | :heavy_check_mark: 已完成 | 2025-06-30 |
| 密码库初始化 | :heavy_check_mark: 已完成 | 2025-07-29 |
| 增加密码 | :heavy_check_mark: 已完成 | 2025-07-29 |
| 支持保存[动态令牌（TOTP/HOTP）](https://2fasolution.com/index.html) | 📋 未开始 |  |
| 更新密码 | :heavy_check_mark: 已完成 | 2025-07-30 |
| 查找密码 | :heavy_check_mark: 已完成 | 2025-07-29 |
| 单元测试 | :heavy_check_mark: 已完成 | 2025-07-29 |
| 文档完善 | :bookmark_tabs: 未开始 |  |
| 发布v1.0版本 | :bookmark_tabs: 未开始 |  |

目前，密码库基本功能已经大体完成，目前还在修改部分功能的实现方案。目前密码查询可能还存在一些问题。
如果你在使用时遇到了其他问题，欢迎提出issue。

TOTP/HOTP，目前还没开始，还有一些保存与输出的逻辑有待解决。

## 贡献指南
1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## LICENSE

Copyright (c) 2025 Sidney Zhang <zly@lyzhang.me>

rpawomaster is licensed under [Mulan PSL v2](LICENSE) .

