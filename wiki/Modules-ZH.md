# SecuBox 模块

[English](Modules) | [Francais](Modules-FR)

SecuBox 软件包及其功能的完整列表。

## 核心模块

### secubox-core
**共享库与框架**

- Python 共享库 (`secubox_core`)
- JWT 认证框架
- 配置管理（TOML）
- 日志工具
- nginx 基础配置

### secubox-hub
**中央仪表板**

- 主 Web 界面
- 模块状态概览
- 系统健康监控
- 告警聚合
- 动态菜单生成

### secubox-portal
**认证门户**

- JWT 登录/登出
- 会话管理
- 密码重置
- 多用户支持

## 安全模块

### secubox-crowdsec
**IDS/IPS（CrowdSec）**

- 实时威胁检测
- 社区封锁列表
- 决策管理（封禁/验证码）
- Bouncer 集成
- 自定义场景

### secubox-waf
**Web 应用防火墙**

- 300+ ModSecurity 规则
- OWASP 核心规则集
- 自定义规则支持
- 请求/响应过滤
- SQL 注入防护
- XSS 防护

### secubox-auth
**OAuth2 与强制门户**

- OAuth2/OIDC 提供者
- 访客强制门户
- 凭证系统
- 社交登录集成
- RADIUS 后端

### secubox-nac
**网络访问控制**

- 设备指纹识别
- MAC 地址访问控制
- VLAN 分配
- 访客隔离
- 隔离网络

### secubox-users
**统一身份管理**

- 中央用户数据库
- 7 服务同步
- LDAP 集成
- 组管理
- 密码策略

## 网络模块

### secubox-wireguard
**VPN 仪表板**

- 接口管理
- 对等节点配置
- 密钥生成
- 二维码导出
- 流量统计

### secubox-haproxy
**负载均衡器与代理**

- 后端服务器池
- 健康检查
- SSL/TLS 终止
- ACL 规则
- 统计仪表板

### secubox-dpi
**深度包检测**

- 应用检测（netifyd）
- 协议分类
- 流量分析
- 带宽监控
- 流量排行

### secubox-qos
**服务质量**

- HTB 流量整形
- 优先级队列
- 带宽限制
- 按设备规则
- 实时统计

### secubox-netmodes
**网络模式**

- 路由器模式
- 网桥模式
- 接入点模式
- Netplan 配置
- 接口绑定

### secubox-vhost
**虚拟主机**

- nginx vhost 管理
- ACME 证书
- 反向代理
- SSL 配置
- 域名路由

### secubox-cdn
**CDN 缓存**

- Squid 代理缓存
- nginx 缓存
- 缓存清除 API
- 存储管理
- 命中率统计

## 监控模块

### secubox-netdata
**实时监控**

- 系统指标
- 网络统计
- 自定义仪表板
- 告警配置
- 历史数据

### secubox-mediaflow
**媒体流检测**

- 流检测
- 带宽使用
- 协议识别
- 质量指标

### secubox-metrics
**指标收集**

- Prometheus 格式
- 自定义指标
- API 端点
- 仪表板集成

## DNS 与邮件模块

### secubox-dns
**DNS 服务器**

- BIND9 区域
- DNSSEC 支持
- 动态更新
- 区域管理界面
- 查询日志

### secubox-mail
**邮件服务器**

- Postfix MTA
- Dovecot IMAP/POP3
- SpamAssassin
- DKIM 签名
- 虚拟域

### secubox-mail-lxc
**邮件 LXC 容器**

- 隔离邮件环境
- 资源限制
- 简易部署

### secubox-webmail
**Webmail 界面**

- Roundcube / SOGo
- 日历集成
- 通讯录
- Sieve 过滤器

## 发布模块

### secubox-droplet
**文件发布器**

- 拖放上传
- 公开/私密分享
- 过期链接
- 访问日志

### secubox-streamlit
**Streamlit 平台**

- Python 应用托管
- 数据仪表板
- 交互式应用
- 多实例

### secubox-streamforge
**Streamlit 管理器**

- 应用部署
- 版本控制
- 资源管理

### secubox-metablogizer
**静态站点生成器**

- Markdown 内容
- Tor 隐藏服务
- 主题支持
- RSS 订阅

### secubox-publish
**发布仪表板**

- 统一界面
- 所有发布工具
- 内容管理

## 系统模块

### secubox-system
**系统管理**

- 服务控制
- 日志查看器
- 软件包更新
- 重启/关机
- 备份/恢复

### secubox-hardening
**安全加固**

- 内核参数
- 服务锁定
- 文件权限
- 审计日志

## 元软件包

### secubox-full
安装所有模块。推荐用于：
- MOCHAbin
- 2+ GB 内存的虚拟机
- 完整功能部署

### secubox-lite
仅安装核心模块。推荐用于：
- ESPRESSObin（内存有限）
- 最小化部署
- 边缘设备

## 另请参阅

- [[Installation-ZH]] - 如何安装
- [[API-Reference-ZH]] - 模块 API
- [[Configuration-ZH]] - 配置指南
