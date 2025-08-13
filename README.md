# RPaWoMaster

[English](README_EN.md) | 中文

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

以下为目前的核心功能简洁，详细使用方法可以参看 [zread](https://zread.ai) 生成的 [中文说明文档](https://zread.ai/SidneyLYZhang/rpawomaster) 。
也可以参考我写的使用例子 [Examples](examples/README.md) 。


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

（1）使用的第一步：初始化密码库。

```bash
# 密码库的使用，第一步就是初始化密码库
rpawomaster init
```

这个功能，主要解决需要为哪个用户设立密码库，设立一个什么名称的密码库，并且需要确认密码库的保存位置。

为什么还要指定哪个用户呢？因为在某些公司的设备安全领域，比如保密电脑上，可能涉及多个用户共同使用，
每个用户需要的密码也不尽相同，所以为了更好的处理多用户共用的情况，确定使用者和密码库就是必须的了。

（2）现在就可以添加密码了。

```bash
# 添加密码
rpawomaster add [password-name] -u yourname
```

和传统的直接明文添加不同，这里需要按照基本顺序逐一填写，但可以更好的处理密码生成的过程，以及密码规则的保存，
为后续自动更新密码提供基础。

（3）添加完密码，就可以后续查询了。

```bash
# 查询密码
rpawomaster search [password-name] -u yourname
```

这里支持模糊查询和精确查询，默认是模糊查询。所以，密码名有的时候记不清也完全可以，甚至只要密码记录中有这个字段，
也能帮助搜索出来。

精确查询时，需要增加精确查询的参数：`--exact`。

（4）更新密码也并不复杂。

```bash
# 更新密码
rpawomaster update -p password-name -u yourname
```

或者你想更新所有到期密码：

```bash
rpawomaster update -a -u yourname
```

更新密码主要根据当前用户密码库中密码的有效期来进行选择，如果在保存密码时，已经确认了密码生成的策略，
则会在更新密码时直接使用既有密码策略生成新的密码。否则还是需要用户自己再手动进行密码输入。

（5）当然，你也可以单纯的把 `rpawomaster` 当作一个密码生成器：

```bash
# 生成随机密码
rpawomaster gen random -l 22
```

## 工程进度

| 功能/任务 | 状态 | 完成时间 |
|----------|------|------------|
| 命令行参数解析 | :heavy_check_mark: 已完成 | 2025-06-30 |
| 密码创建 | :heavy_check_mark: 已完成 | 2025-06-30 |
| 密码强度检验 | :heavy_check_mark: 已完成 | 2025-06-30 |
| 密码库初始化 | :heavy_check_mark: 已完成 | 2025-07-29 |
| 增加密码 | :heavy_check_mark: 已完成 | 2025-07-29 |
| 更新密码 | :heavy_check_mark: 已完成 | 2025-07-30 |
| 查找密码 | :heavy_check_mark: 已完成 | 2025-07-29 |
| 删除密码 | :heavy_check_mark: 已完成 | 2025-07-30 |
| 导出密码库 | :heavy_check_mark: 已完成 | 2025-07-30 |
| 加密/解密文件 | :heavy_check_mark: 已完成 | 2025-07-30 |
| 支持保存[动态令牌（TOTP/HOTP）](https://2fasolution.com/index.html) | :construction: 进行中 | 2025-07-31 |
| 粘贴板功能（自动清除） | :heavy_check_mark: 部分完成，未实装 | 2025-07-31 |
| 易记密码生成 | :heavy_check_mark: 已完成 | 2025-07-31 |
| 单元测试 | :heavy_check_mark: 已完成 | 2025-07-29 |
| 文档完善 | 完善中 ... | 2025-07-31 |
| 发布v0.1.8版本 | :heavy_check_mark: 已完成 | 2025-07-31 |
| 发布v1.0版本 | :bookmark_tabs: 计划中 |  |

目前，密码库核心功能已基本完成，v0.1.8版本已发布。TOTP/HOTP功能正在开发中，预计将在后续版本中完成。

## 贡献指南
1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## LICENSE

Copyright (c) 2025 Sidney Zhang <zly@lyzhang.me>

rpawomaster is licensed under [Mulan PSL v2](LICENSE) .

另，可记忆密码所使用的 [`wordlist.txt`](data/wordlist.txt) 来自 [EFF](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt) .

