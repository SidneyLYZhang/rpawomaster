# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.8]

### Added
- 新增了安全密码生成器功能，支持随机密码和易记密码两种模式
- 添加了基于AES和RSA的混合加密模块
- 实现了密码管理功能，支持密码存储、历史记录和过期提醒
- 新增了配置管理工具，支持多保险库管理
- 添加了剪贴板操作功能，支持自动清除敏感信息

### Changed
- 优化了命令行界面交互体验
- 改进了密码强度评估算法

### Deprecated
- 弃用了旧的简单加密接口

### Removed
- 移除了不安全的明文密码存储方式

### Fixed
- 修复了密码生成器中的潜在安全漏洞
- 解决了配置文件读写时的权限问题

### Security
- 增强了数据加密强度，使用AES-256-CBC和RSA-2048混合加密
- 强化了核心密码的定期更新机制