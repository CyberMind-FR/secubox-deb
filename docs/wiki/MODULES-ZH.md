# SecuBox模块

*完整的模块文档*

**模块总数:** 47

[🇬🇧 English](MODULES-EN.md) | [🇫🇷 Français](MODULES-FR.md) | [🇩🇪 Deutsch](MODULES-DE.md) | [🇨🇳 中文](MODULES-ZH.md)

---

## 概述

| 模块 | 类别 | 描述 |
|--------|----------|-------------|
| 🏠 **SecuBox Hub** | Dashboard | 中央仪表板 |
| 🛡️ **Security Operations Center** | Dashboard | 安全运营中心 |
| 📋 **Migration Roadmap** | Dashboard | OpenWRT到Debian迁移跟踪 |
| 🛡️ **CrowdSec** | Security | 协作式安全引擎 |
| 🔥 **Web Application Firewall** | Security | 300+规则的WAF |
| 🔥 **Vortex Firewall** | Security | nftables威胁执行 |
| 🔒 **System Hardening** | Security | 内核和系统加固 |
| 🔍 **MITM Proxy** | Security | 流量检查和WAF代理 |
| 🔐 **Auth Guardian** | Security | 认证管理 |
| 🛡️ **Network Access Control** | Security | 客户端守护和NAC |
| 🌐 **Network Modes** | Network | 网络拓扑配置 |
| 📊 **QoS Manager** | Network | HTB/VLAN服务质量 |
| 📈 **Traffic Shaping** | Network | TC/CAKE流量整形 |
| ⚡ **HAProxy** | Network | 负载均衡器仪表板 |
| 🚀 **CDN Cache** | Network | 内容分发缓存 |
| 🏗️ **Virtual Hosts** | Network | Nginx虚拟主机管理 |
| 🌍 **DNS Server** | DNS | BIND DNS区域管理 |
| 🛡️ **Vortex DNS** | DNS | 带RPZ的DNS防火墙 |
| 📡 **Mesh DNS** | DNS | Mesh网络域名解析 |
| 🔗 **WireGuard VPN** | VPN | 现代VPN管理 |
| 🕸️ **Mesh Network** | VPN | Mesh网络(Yggdrasil) |
| 🔗 **P2P Network** | VPN | 点对点网络 |
| 🧅 **Tor Network** | Privacy | Tor匿名和隐藏服务 |
| 🌐 **Exposure Settings** | Privacy | 统一暴露设置(Tor, SSL, DNS, Mesh) |
| 🔐 **Zero-Knowledge Proofs** | Privacy | ZKP哈密顿管理 |
| 📊 **Netdata** | Monitoring | 实时系统监控 |
| 🔬 **Deep Packet Inspection** | Monitoring | 使用netifyd的DPI |
| 📱 **Device Intelligence** | Monitoring | 资产发现和指纹识别 |
| 👁️ **Watchdog** | Monitoring | 服务和容器监控 |
| 🎬 **Media Flow** | Monitoring | 媒体流量分析 |
| 🔐 **Login Portal** | Access | JWT认证门户 |
| 👥 **User Management** | Access | 统一身份管理 |
| 📦 **Services Portal** | Services | C3Box服务门户 |
| 🦊 **Gitea** | Services | Git服务器(LXC) |
| ☁️ **Nextcloud** | Services | 文件同步(LXC) |
| 📧 **Mail Server** | Email | Postfix/Dovecot邮件服务器 |
| 💌 **Webmail** | Email | Roundcube/SOGo网页邮箱 |
| 📰 **Publishing Platform** | Publishing | 统一发布仪表板 |
| 💧 **Droplet** | Publishing | 文件上传和发布 |
| 📝 **Metablogizer** | Publishing | 带Tor的静态站点发布器 |
| 🎨 **Streamlit** | Apps | Streamlit应用平台 |
| ⚡ **StreamForge** | Apps | Streamlit应用开发 |
| 📦 **APT Repository** | Apps | APT仓库管理 |
| ⚙️ **System Hub** | System | 系统配置和管理 |
| 💾 **Backup Manager** | System | 系统和LXC备份 |

---

## 模块

### 🏠 SecuBox Hub

**类别:** Dashboard

中央仪表板

**Features:**
- 系统概览
- 服务监控
- 快速操作
- 指标

![SecuBox Hub](screenshots/vm/hub.png)

---

### 🛡️ Security Operations Center

**类别:** Dashboard

安全运营中心

**Features:**
- 世界时钟
- 威胁地图
- 工单系统
- P2P情报
- 告警

![Security Operations Center](screenshots/vm/soc.png)

---

### 📋 Migration Roadmap

**类别:** Dashboard

OpenWRT到Debian迁移跟踪

**Features:**
- 进度跟踪
- 模块状态
- 分类视图

![Migration Roadmap](screenshots/vm/roadmap.png)

---

### 🛡️ CrowdSec

**类别:** Security

协作式安全引擎

**Features:**
- 决策管理
- 告警
- Bouncer
- 集合

![CrowdSec](screenshots/vm/crowdsec.png)

---

### 🔥 Web Application Firewall

**类别:** Security

300+规则的WAF

**Features:**
- OWASP规则
- 自定义规则
- CrowdSec集成

![Web Application Firewall](screenshots/vm/waf.png)

---

### 🔥 Vortex Firewall

**类别:** Security

nftables威胁执行

**Features:**
- IP黑名单
- nftables集合
- 威胁源

![Vortex Firewall](screenshots/vm/vortex-firewall.png)

---

### 🔒 System Hardening

**类别:** Security

内核和系统加固

**Features:**
- sysctl加固
- 模块黑名单
- 安全评分

![System Hardening](screenshots/vm/hardening.png)

---

### 🔍 MITM Proxy

**类别:** Security

流量检查和WAF代理

**Features:**
- 流量检查
- 请求日志
- 自动封禁

![MITM Proxy](screenshots/vm/mitmproxy.png)

---

### 🔐 Auth Guardian

**类别:** Security

认证管理

**Features:**
- OAuth2
- LDAP
- 双因素
- 会话管理

![Auth Guardian](screenshots/vm/auth.png)

---

### 🛡️ Network Access Control

**类别:** Security

客户端守护和NAC

**Features:**
- 设备控制
- MAC过滤
- 隔离

![Network Access Control](screenshots/vm/nac.png)

---

### 🌐 Network Modes

**类别:** Network

网络拓扑配置

**Features:**
- 路由模式
- 桥接模式
- AP模式
- VLAN

![Network Modes](screenshots/vm/netmodes.png)

---

### 📊 QoS Manager

**类别:** Network

HTB/VLAN服务质量

**Features:**
- 带宽控制
- VLAN策略
- 802.1p PCP

![QoS Manager](screenshots/vm/qos.png)

---

### 📈 Traffic Shaping

**类别:** Network

TC/CAKE流量整形

**Features:**
- 每接口QoS
- CAKE算法
- 统计

![Traffic Shaping](screenshots/vm/traffic.png)

---

### ⚡ HAProxy

**类别:** Network

负载均衡器仪表板

**Features:**
- 后端管理
- 统计
- ACL
- SSL终止

![HAProxy](screenshots/vm/haproxy.png)

---

### 🚀 CDN Cache

**类别:** Network

内容分发缓存

**Features:**
- 缓存管理
- 清除
- 统计

![CDN Cache](screenshots/vm/cdn.png)

---

### 🏗️ Virtual Hosts

**类别:** Network

Nginx虚拟主机管理

**Features:**
- 站点管理
- SSL证书
- 反向代理

![Virtual Hosts](screenshots/vm/vhost.png)

---

### 🌍 DNS Server

**类别:** DNS

BIND DNS区域管理

**Features:**
- 区域管理
- 记录
- DNSSEC

![DNS Server](screenshots/vm/dns.png)

---

### 🛡️ Vortex DNS

**类别:** DNS

带RPZ的DNS防火墙

**Features:**
- 黑名单
- RPZ
- 威胁源

![Vortex DNS](screenshots/vm/vortex-dns.png)

---

### 📡 Mesh DNS

**类别:** DNS

Mesh网络域名解析

**Features:**
- mDNS/Avahi
- 本地DNS
- 服务发现

![Mesh DNS](screenshots/vm/meshname.png)

---

### 🔗 WireGuard VPN

**类别:** VPN

现代VPN管理

**Features:**
- 节点管理
- 二维码
- 流量统计

![WireGuard VPN](screenshots/vm/wireguard.png)

---

### 🕸️ Mesh Network

**类别:** VPN

Mesh网络(Yggdrasil)

**Features:**
- 节点发现
- 路由
- 加密

![Mesh Network](screenshots/vm/mesh.png)

---

### 🔗 P2P Network

**类别:** VPN

点对点网络

**Features:**
- 直接连接
- NAT穿透
- 加密

![P2P Network](screenshots/vm/p2p.png)

---

### 🧅 Tor Network

**类别:** Privacy

Tor匿名和隐藏服务

**Features:**
- 电路
- 隐藏服务
- 桥接

![Tor Network](screenshots/vm/tor.png)

---

### 🌐 Exposure Settings

**类别:** Privacy

统一暴露设置(Tor, SSL, DNS, Mesh)

**Features:**
- Tor暴露
- SSL证书
- DNS记录
- Mesh访问

![Exposure Settings](screenshots/vm/exposure.png)

---

### 🔐 Zero-Knowledge Proofs

**类别:** Privacy

ZKP哈密顿管理

**Features:**
- 证明生成
- 验证
- 密钥管理

![Zero-Knowledge Proofs](screenshots/vm/zkp.png)

---

### 📊 Netdata

**类别:** Monitoring

实时系统监控

**Features:**
- 指标
- 告警
- 图表
- 插件

![Netdata](screenshots/vm/netdata.png)

---

### 🔬 Deep Packet Inspection

**类别:** Monitoring

使用netifyd的DPI

**Features:**
- 协议检测
- 应用识别
- 流量分析

![Deep Packet Inspection](screenshots/vm/dpi.png)

---

### 📱 Device Intelligence

**类别:** Monitoring

资产发现和指纹识别

**Features:**
- ARP扫描
- MAC厂商查询
- OS检测

![Device Intelligence](screenshots/vm/device-intel.png)

---

### 👁️ Watchdog

**类别:** Monitoring

服务和容器监控

**Features:**
- 健康检查
- 自动重启
- 告警

![Watchdog](screenshots/vm/watchdog.png)

---

### 🎬 Media Flow

**类别:** Monitoring

媒体流量分析

**Features:**
- 流检测
- 带宽使用
- 协议分析

![Media Flow](screenshots/vm/mediaflow.png)

---

### 🔐 Login Portal

**类别:** Access

JWT认证门户

**Features:**
- JWT认证
- 会话
- 密码恢复

![Login Portal](screenshots/vm/portal.png)

---

### 👥 User Management

**类别:** Access

统一身份管理

**Features:**
- 用户CRUD
- 组
- 服务配置

![User Management](screenshots/vm/users.png)

---

### 📦 Services Portal

**类别:** Services

C3Box服务门户

**Features:**
- 服务链接
- 状态概览
- 快速访问

![Services Portal](screenshots/vm/c3box.png)

---

### 🦊 Gitea

**类别:** Services

Git服务器(LXC)

**Features:**
- 仓库
- 用户
- SSH/HTTP
- LFS

![Gitea](screenshots/vm/gitea.png)

---

### ☁️ Nextcloud

**类别:** Services

文件同步(LXC)

**Features:**
- 文件同步
- WebDAV
- CalDAV
- CardDAV

![Nextcloud](screenshots/vm/nextcloud.png)

---

### 📧 Mail Server

**类别:** Email

Postfix/Dovecot邮件服务器

**Features:**
- 域名
- 邮箱
- DKIM
- SpamAssassin
- ClamAV

![Mail Server](screenshots/vm/mail.png)

---

### 💌 Webmail

**类别:** Email

Roundcube/SOGo网页邮箱

**Features:**
- Web界面
- 通讯录
- 日历

![Webmail](screenshots/vm/webmail.png)

---

### 📰 Publishing Platform

**类别:** Publishing

统一发布仪表板

**Features:**
- 多平台
- 计划
- 分析

![Publishing Platform](screenshots/vm/publish.png)

---

### 💧 Droplet

**类别:** Publishing

文件上传和发布

**Features:**
- 文件上传
- 分享链接
- 过期

![Droplet](screenshots/vm/droplet.png)

---

### 📝 Metablogizer

**类别:** Publishing

带Tor的静态站点发布器

**Features:**
- 静态站点
- Tor发布
- 模板

![Metablogizer](screenshots/vm/metablogizer.png)

---

### 🎨 Streamlit

**类别:** Apps

Streamlit应用平台

**Features:**
- 应用托管
- 部署
- 管理

![Streamlit](screenshots/vm/streamlit.png)

---

### ⚡ StreamForge

**类别:** Apps

Streamlit应用开发

**Features:**
- 模板
- 代码编辑器
- 预览

![StreamForge](screenshots/vm/streamforge.png)

---

### 📦 APT Repository

**类别:** Apps

APT仓库管理

**Features:**
- 包管理
- GPG签名
- 多发行版

![APT Repository](screenshots/vm/repo.png)

---

### ⚙️ System Hub

**类别:** System

系统配置和管理

**Features:**
- 设置
- 日志
- 服务
- 更新

![System Hub](screenshots/vm/system.png)

---

### 💾 Backup Manager

**类别:** System

系统和LXC备份

**Features:**
- 配置备份
- LXC快照
- 恢复

![Backup Manager](screenshots/vm/backup.png)

---

