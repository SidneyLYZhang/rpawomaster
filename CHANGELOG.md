# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.2.0]

### Added
- 新增完整的HOTP/TOTP双因素认证功能，支持Google Authenticator标准
- 添加一键安装脚本（install.ps1），支持Windows系统自动配置环境变量
- 新增多平台构建和发布工作流，支持Windows、Linux、macOS自动构建
- 添加OTP URI解析功能，支持从二维码文本导入OTP配置
- 新增剪贴板守护进程功能，支持敏感信息自动清除
- 添加密码软删除功能，允许标记密码为已删除而非永久删除
- 新增密码过期天数设置功能，可自定义密码有效期
- 添加用户和保险库过滤选项，支持更精确的密码列表查询
- 新增测试命令，支持文本加密和解密功能测试

### Changed
- 重构加密和解密方法，支持目标路径参数并优化目录处理
- 重构密码生成逻辑，优化随机和记忆密码生成策略
- 改进密钥对保存和读取功能，增强密钥管理安全性
- 更新配置文件结构，将metadata.json改为隐藏文件.metadata.json
- 重构命令行界面，统一密码输入和确认流程
- 优化错误处理机制，提供更详细的错误信息

### Fixed
- 解决密码更新功能的逻辑错误
- 修复搜索功能中的查询问题
- 修正文档中的作者拼写错误

### Security
- 强化OTP密钥的安全存储机制
- 改进私钥加密保护，增强密钥文件安全性
- 优化敏感信息的内存管理和清除策略

### Documentation
- 添加完整的英文版README文档（README_EN.md）
- 更新安装指南，添加Cargo安装方式说明
- 完善使用方法和功能说明，提供更清晰的示例
- 添加zread.ai项目链接和相关文档

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