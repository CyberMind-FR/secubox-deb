# SecuBox模块

*完整的模块文档*

**模块总数:** 105

[🇬🇧 English](MODULES-EN.md) | [🇫🇷 Français](MODULES-FR.md) | [🇩🇪 Deutsch](MODULES-DE.md) | [🇨🇳 中文](MODULES-ZH.md)

---

## 概述

| 模块 | 类别 | 描述 |
|--------|----------|-------------|
| 🏠 **SecuBox Hub** | Dashboard | 中央仪表板和控制中心 |
| 🛡️ **Security Operations Center** | Dashboard | 安全运营中心，包含世界时钟、威胁地图、工单 |
| 📋 **Migration Roadmap** | Dashboard | OpenWRT到Debian迁移跟踪 |
| 📈 **System Metrics** | Dashboard | 实时系统指标仪表板 |
| ⚙️ **Admin Panel** | Dashboard | 系统管理面板 |
| 🛡️ **CrowdSec** | Security | 具有行为分析的协作式安全引擎 |
| 🔥 **Web Application Firewall** | Security | 具有300+条OWASP安全规则的WAF |
| 🔥 **Vortex Firewall** | Security | 基于nftables的威胁执行防火墙 |
| 🔒 **System Hardening** | Security | 符合ANSSI CSPN的内核和系统加固 |
| 🔍 **MITM Proxy** | Security | 具有自动封禁功能的流量检查和WAF代理 |
| 🔐 **Auth Guardian** | Security | 统一认证管理 |
| 🛡️ **Network Access Control** | Security | 具有隔离功能的客户端守护和NAC |
| 🚫 **IP Block Manager** | Security | IP和网络封锁管理 |
| 🔐 **MAC Guard** | Security | MAC地址访问控制 |
| 📡 **Traffic Interceptor** | Security | 网络流量拦截和分析 |
| 🍪 **Cookie Manager** | Security | Cookie和会话安全管理 |
| ⚠️ **Threat Dashboard** | Security | 统一威胁可视化 |
| 🔬 **Threat Analyst** | Security | AI驱动的威胁分析 |
| 🔴 **CVE Triage** | Security | CVE漏洞跟踪和分类 |
| 🛡️ **Wazuh SIEM** | Security | Wazuh SIEM集成 |
| 🔒 **OSSEC HIDS** | Security | OSSEC主机入侵检测 |
| 🦞 **OpenClaw Scanner** | Security | 网络漏洞扫描器 |
| 🔌 **IoT Guard** | Security | IoT设备安全监控 |
| 🌐 **Network Modes** | Network | 网络拓扑配置 |
| 📊 **QoS Manager** | Network | HTB/VLAN服务质量 |
| 📈 **Traffic Shaping** | Network | TC/CAKE流量整形 |
| ⚡ **HAProxy** | Network | 支持TLS 1.3的负载均衡器 |
| 🚀 **CDN Cache** | Network | 内容分发缓存 |
| 🏗️ **Virtual Hosts** | Network | Nginx虚拟主机管理 |
| 🛤️ **Routing Manager** | Network | 静态和基于策略的路由 |
| 🔧 **Network Tweaks** | Network | 网络内核参数调优 |
| 🔍 **Network Diagnostics** | Network | 网络故障排除工具 |
| 📉 **Network Anomaly** | Network | 网络异常检测 |
| 📶 **Modem Manager** | Network | 3G/4G/5G调制解调器管理 |
| 🌍 **DNS Server** | DNS | BIND DNS区域管理 |
| 🛡️ **Vortex DNS** | DNS | 带RPZ黑名单的DNS防火墙 |
| 📡 **Mesh DNS** | DNS | Mesh网络域名解析 |
| 🛡️ **DNS Guard** | DNS | 基于DNS的威胁防护 |
| 🌐 **DNS Provider** | DNS | 外部DNS提供商集成 |
| 🚫 **AdGuard** | DNS | AdGuard Home DNS拦截 |
| 🔗 **WireGuard VPN** | VPN | 具有内核集成的现代VPN |
| 🕸️ **Mesh Network** | VPN | 使用Yggdrasil的Mesh网络 |
| 🔗 **P2P Network** | VPN | 点对点网络 |
| 🔗 **MasterLink** | VPN | SecuBox网格联邦 |
| 🧅 **Tor Network** | Privacy | Tor匿名和隐藏服务 |
| 🌐 **Exposure Settings** | Privacy | 统一暴露管理 |
| 🔐 **Zero-Knowledge Proofs** | Privacy | ZKP哈密顿认证 |
| 💬 **SimpleX Chat** | Privacy | 注重隐私的消息 |
| 🔐 **Secret Vault** | Privacy | 密钥和凭据管理 |
| 📊 **Netdata** | Monitoring | 实时系统监控 |
| 🔬 **Deep Packet Inspection** | Monitoring | 使用netifyd/nDPId的DPI |
| 🔬 **Netifyd DPI** | Monitoring | Netifyd深度包检测 |
| 🔬 **nDPId** | Monitoring | 用于流量分析的nDPI守护进程 |
| 📱 **Device Intelligence** | Monitoring | 资产发现和指纹识别 |
| 👁️ **Watchdog** | Monitoring | 服务和容器监控 |
| 🎬 **Media Flow** | Monitoring | 媒体流量分析 |
| 👀 **Glances** | Monitoring | 系统监控仪表板 |
| 🔐 **Login Portal** | Access | JWT认证门户 |
| 👥 **User Management** | Access | 统一身份管理 |
| 🪪 **Identity Provider** | Access | SAML/OIDC身份提供者 |
| 📦 **Services Portal** | Services | C3Box服务门户 |
| 🦊 **Gitea** | Services | Git服务器(LXC) |
| ☁️ **Nextcloud** | Services | 文件同步(LXC) |
| 🦙 **Ollama** | AI | 本地LLM服务器 |
| 🤖 **LocalAI** | AI | 兼容OpenAI的本地API |
| 🚪 **AI Gateway** | AI | AI模型API网关 |
| 💡 **AI Insights** | AI | AI驱动的安全洞察 |
| 🧠 **LocalRecall** | AI | 本地RAG记忆系统 |
| 🔌 **MCP Server** | AI | 模型上下文协议服务器 |
| 📧 **Mail Server** | Email | Postfix/Dovecot邮件服务器 |
| 💌 **Webmail** | Email | Roundcube/SOGo网页邮箱 |
| 📤 **SMTP Relay** | Email | SMTP中继和智能主机 |
| 💬 **Jabber/XMPP** | Email | XMPP消息服务器 |
| 🎬 **Jellyfin** | Media | 媒体服务器 |
| 🎵 **Lyrion Music** | Media | 音乐流媒体服务器 |
| 📻 **Web Radio** | Media | 网络电台流媒体 |
| 📸 **PhotoPrism** | Media | AI驱动的照片管理 |
| 📺 **PeerTube** | Media | 联邦视频平台 |
| 🌊 **Torrent** | Media | BitTorrent客户端 |
| 📰 **Newsbin** | Media | Usenet/NNTP客户端 |
| 📰 **Publishing Platform** | Publishing | 统一发布仪表板 |
| 💧 **Droplet** | Publishing | 文件上传和发布 |
| 📝 **Metablogizer** | Publishing | 带Tor的静态站点发布器 |
| ✏️ **Hexo Blog** | Publishing | 静态博客生成器 |
| 🐘 **GoToSocial** | Publishing | ActivityPub社交服务器 |
| 📡 **CyberFeed** | Publishing | RSS/Atom订阅聚合器 |
| 🎨 **Streamlit** | Apps | Streamlit应用平台 |
| ⚡ **StreamForge** | Apps | Streamlit应用开发 |
| 📦 **APT Repository** | Apps | APT仓库管理 |
| 🏠 **Domoticz** | IoT | 家庭自动化 |
| 🏡 **Home Assistant** | IoT | 家庭自动化中心 |
| 📡 **Zigbee Gateway** | IoT | Zigbee2MQTT网关 |
| 📡 **MQTT Broker** | IoT | Mosquitto MQTT代理 |
| 💬 **Matrix Server** | Communication | Matrix/Synapse聊天服务器 |
| 📹 **Jitsi Meet** | Communication | 视频会议 |
| 📞 **VoIP Server** | Communication | Asterisk/FreePBX VoIP |
| 🔄 **TURN Server** | Communication | TURN/STUN中继服务器 |
| ⚙️ **System Hub** | System | 系统配置和管理 |
| 💾 **Backup Manager** | System | 系统和LXC备份 |
| 📋 **Config Advisor** | System | 配置建议 |
| 📊 **Reporter** | System | 系统报告和分析 |
| 🪞 **Mirror Manager** | System | APT镜像管理 |
| 📀 **System Cloner** | System | 系统镜像克隆 |
| 👁️ **Eye Remote** | System | 远程管理界面 |
| 🖥️ **RTTY Console** | System | 远程终端访问 |

---

## 模块

### AI

#### 🦙 Ollama

本地LLM服务器

**功能:** 模型管理, API, 聊天, GPU支持

![Ollama](screenshots/vm/ollama.png)

#### 🤖 LocalAI

兼容OpenAI的本地API

**功能:** OpenAI API, 多模型, 嵌入, 图像生成

![LocalAI](screenshots/vm/localai.png)

#### 🚪 AI Gateway

AI模型API网关

**功能:** 速率限制, 负载均衡, 缓存, 日志

![AI Gateway](screenshots/vm/ai-gateway.png)

#### 💡 AI Insights

AI驱动的安全洞察

**功能:** 异常检测, 建议, 预测, 报告

![AI Insights](screenshots/vm/ai-insights.png)

#### 🧠 LocalRecall

本地RAG记忆系统

**功能:** 向量存储, 语义搜索, 文档索引, API

![LocalRecall](screenshots/vm/localrecall.png)

#### 🔌 MCP Server

模型上下文协议服务器

**功能:** 工具集成, 上下文管理, 多模型, API

![MCP Server](screenshots/vm/mcp-server.png)

---

### Access

#### 🔐 Login Portal

JWT认证门户

**功能:** JWT认证, 会话, 密码恢复, 强制门户

![Login Portal](screenshots/vm/portal.png)

#### 👥 User Management

统一身份管理

**功能:** 用户CRUD, 组, 服务配置, RBAC

![User Management](screenshots/vm/users.png)

#### 🪪 Identity Provider

SAML/OIDC身份提供者

**功能:** SAML 2.0, OpenID Connect, 联邦, SSO

![Identity Provider](screenshots/vm/identity.png)

---

### Apps

#### 🎨 Streamlit

Streamlit应用平台

**功能:** 应用托管, 部署, 管理, 日志

![Streamlit](screenshots/vm/streamlit.png)

#### ⚡ StreamForge

Streamlit应用开发

**功能:** 模板, 代码编辑器, 预览, 部署

![StreamForge](screenshots/vm/streamforge.png)

#### 📦 APT Repository

APT仓库管理

**功能:** 包管理, GPG签名, 多发行版, 上传

![APT Repository](screenshots/vm/repo.png)

---

### Communication

#### 💬 Matrix Server

Matrix/Synapse聊天服务器

**功能:** 端到端加密, 联邦, 桥接, 通话

![Matrix Server](screenshots/vm/matrix.png)

#### 📹 Jitsi Meet

视频会议

**功能:** 视频通话, 屏幕共享, 录制, 等候室

![Jitsi Meet](screenshots/vm/jitsi.png)

#### 📞 VoIP Server

Asterisk/FreePBX VoIP

**功能:** 分机, 中继, IVR, 语音信箱

![VoIP Server](screenshots/vm/voip.png)

#### 🔄 TURN Server

TURN/STUN中继服务器

**功能:** NAT穿透, WebRTC, TLS, 统计

![TURN Server](screenshots/vm/turn.png)

---

### DNS

#### 🌍 DNS Server

BIND DNS区域管理

**功能:** 区域管理, 记录, DNSSEC, 反向DNS

![DNS Server](screenshots/vm/dns.png)

#### 🛡️ Vortex DNS

带RPZ黑名单的DNS防火墙

**功能:** 黑名单, RPZ, 威胁源, DoH/DoT

![Vortex DNS](screenshots/vm/vortex-dns.png)

#### 📡 Mesh DNS

Mesh网络域名解析

**功能:** mDNS/Avahi, 本地DNS, 服务发现, Mesh集成

![Mesh DNS](screenshots/vm/meshname.png)

#### 🛡️ DNS Guard

基于DNS的威胁防护

**功能:** 恶意软件拦截, 钓鱼防护, 分析, 白名单

![DNS Guard](screenshots/vm/dns-guard.png)

#### 🌐 DNS Provider

外部DNS提供商集成

**功能:** Cloudflare, Route53, DigitalOcean, 动态DNS

![DNS Provider](screenshots/vm/dns-provider.png)

#### 🚫 AdGuard

AdGuard Home DNS拦截

**功能:** 广告拦截, 追踪保护, 家长控制, 统计

![AdGuard](screenshots/vm/ad-guard.png)

---

### Dashboard

#### 🏠 SecuBox Hub

中央仪表板和控制中心

**功能:** 系统概览, 服务监控, 快速操作, 指标

![SecuBox Hub](screenshots/vm/hub.png)

#### 🛡️ Security Operations Center

安全运营中心，包含世界时钟、威胁地图、工单

**功能:** 世界时钟, 威胁地图, 工单系统, P2P情报, 告警

![Security Operations Center](screenshots/vm/soc.png)

#### 📋 Migration Roadmap

OpenWRT到Debian迁移跟踪

**功能:** 进度跟踪, 模块状态, 分类视图

![Migration Roadmap](screenshots/vm/roadmap.png)

#### 📈 System Metrics

实时系统指标仪表板

**功能:** CPU/内存, 网络统计, 磁盘I/O, 历史数据

![System Metrics](screenshots/vm/metrics.png)

#### ⚙️ Admin Panel

系统管理面板

**功能:** 用户管理, 系统配置, 日志, 诊断

![Admin Panel](screenshots/vm/admin.png)

---

### Email

#### 📧 Mail Server

Postfix/Dovecot邮件服务器

**功能:** 域名, 邮箱, DKIM, SpamAssassin, ClamAV

![Mail Server](screenshots/vm/mail.png)

#### 💌 Webmail

Roundcube/SOGo网页邮箱

**功能:** Web界面, 通讯录, 日历, 移动端

![Webmail](screenshots/vm/webmail.png)

#### 📤 SMTP Relay

SMTP中继和智能主机

**功能:** 中继, 认证, 速率限制, 日志

![SMTP Relay](screenshots/vm/smtp-relay.png)

#### 💬 Jabber/XMPP

XMPP消息服务器

**功能:** 聊天, 群组, 文件传输, 联邦

![Jabber/XMPP](screenshots/vm/jabber.png)

---

### IoT

#### 🏠 Domoticz

家庭自动化

**功能:** 设备, 场景, 脚本, 历史

![Domoticz](screenshots/vm/domoticz.png)

#### 🏡 Home Assistant

家庭自动化中心

**功能:** 集成, 自动化, 仪表板, 语音

![Home Assistant](screenshots/vm/homeassistant.png)

#### 📡 Zigbee Gateway

Zigbee2MQTT网关

**功能:** 设备配对, MQTT, 群组, OTA更新

![Zigbee Gateway](screenshots/vm/zigbee.png)

#### 📡 MQTT Broker

Mosquitto MQTT代理

**功能:** 主题, ACL, TLS, WebSocket

![MQTT Broker](screenshots/vm/mqtt.png)

---

### Media

#### 🎬 Jellyfin

媒体服务器

**功能:** 视频流, 直播电视, 转码, 移动应用

![Jellyfin](screenshots/vm/jellyfin.png)

#### 🎵 Lyrion Music

音乐流媒体服务器

**功能:** 音乐库, 播放列表, 电台, 多房间

![Lyrion Music](screenshots/vm/lyrion.png)

#### 📻 Web Radio

网络电台流媒体

**功能:** 电台, 录制, 计划, 收藏

![Web Radio](screenshots/vm/webradio.png)

#### 📸 PhotoPrism

AI驱动的照片管理

**功能:** 人脸识别, 自动标签, 搜索, 相册

![PhotoPrism](screenshots/vm/photoprism.png)

#### 📺 PeerTube

联邦视频平台

**功能:** 视频托管, 联邦, 直播, 评论

![PeerTube](screenshots/vm/peertube.png)

#### 🌊 Torrent

BitTorrent客户端

**功能:** 下载, RSS, 远程控制, 带宽限制

![Torrent](screenshots/vm/torrent.png)

#### 📰 Newsbin

Usenet/NNTP客户端

**功能:** NZB下载, 自动处理, 搜索, 分类

![Newsbin](screenshots/vm/newsbin.png)

---

### Monitoring

#### 📊 Netdata

实时系统监控

**功能:** 指标, 告警, 图表, 插件

![Netdata](screenshots/vm/netdata.png)

#### 🔬 Deep Packet Inspection

使用netifyd/nDPId的DPI

**功能:** 协议检测, 应用识别, 流量分析, 统计

![Deep Packet Inspection](screenshots/vm/dpi.png)

#### 🔬 Netifyd DPI

Netifyd深度包检测

**功能:** 应用检测, 协议分析, 流量统计, API

![Netifyd DPI](screenshots/vm/netifyd.png)

#### 🔬 nDPId

用于流量分析的nDPI守护进程

**功能:** 协议检测, 流量跟踪, JSON API, 实时

![nDPId](screenshots/vm/ndpid.png)

#### 📱 Device Intelligence

资产发现和指纹识别

**功能:** ARP扫描, MAC厂商查询, OS检测, 服务

![Device Intelligence](screenshots/vm/device-intel.png)

#### 👁️ Watchdog

服务和容器监控

**功能:** 健康检查, 自动重启, 告警, 日志

![Watchdog](screenshots/vm/watchdog.png)

#### 🎬 Media Flow

媒体流量分析

**功能:** 流检测, 带宽使用, 协议分析, QoE

![Media Flow](screenshots/vm/mediaflow.png)

#### 👀 Glances

系统监控仪表板

**功能:** CPU/内存, 磁盘/网络, Docker, Web界面

![Glances](screenshots/vm/glances.png)

---

### Network

#### 🌐 Network Modes

网络拓扑配置

**功能:** 路由模式, 桥接模式, AP模式, VLAN

![Network Modes](screenshots/vm/netmodes.png)

#### 📊 QoS Manager

HTB/VLAN服务质量

**功能:** 带宽控制, VLAN策略, 802.1p PCP, 每用户限制

![QoS Manager](screenshots/vm/qos.png)

#### 📈 Traffic Shaping

TC/CAKE流量整形

**功能:** 每接口QoS, CAKE算法, 统计, 实时图表

![Traffic Shaping](screenshots/vm/traffic.png)

#### ⚡ HAProxy

支持TLS 1.3的负载均衡器

**功能:** 后端管理, 统计, ACL, SSL终止, 健康检查

![HAProxy](screenshots/vm/haproxy.png)

#### 🚀 CDN Cache

内容分发缓存

**功能:** 缓存管理, 清除, 统计, 边缘规则

![CDN Cache](screenshots/vm/cdn.png)

#### 🏗️ Virtual Hosts

Nginx虚拟主机管理

**功能:** 站点管理, SSL证书, 反向代理, Let's Encrypt

![Virtual Hosts](screenshots/vm/vhost.png)

#### 🛤️ Routing Manager

静态和基于策略的路由

**功能:** 静态路由, 策略路由, 多WAN, 故障转移

![Routing Manager](screenshots/vm/routes.png)

#### 🔧 Network Tweaks

网络内核参数调优

**功能:** TCP调优, 缓冲区大小, 拥塞控制, 配置文件

![Network Tweaks](screenshots/vm/nettweak.png)

#### 🔍 Network Diagnostics

网络故障排除工具

**功能:** Ping/Traceroute, DNS查询, 端口扫描, 速度测试

![Network Diagnostics](screenshots/vm/netdiag.png)

#### 📉 Network Anomaly

网络异常检测

**功能:** 流量基线, 异常告警, ML检测, 可视化

![Network Anomaly](screenshots/vm/network-anomaly.png)

#### 📶 Modem Manager

3G/4G/5G调制解调器管理

**功能:** 连接状态, 信号强度, 短信, 故障转移

![Modem Manager](screenshots/vm/modem.png)

---

### Privacy

#### 🧅 Tor Network

Tor匿名和隐藏服务

**功能:** 电路, 隐藏服务, 桥接, 透明代理

![Tor Network](screenshots/vm/tor.png)

#### 🌐 Exposure Settings

统一暴露管理

**功能:** Tor暴露, SSL证书, DNS记录, Mesh访问

![Exposure Settings](screenshots/vm/exposure.png)

#### 🔐 Zero-Knowledge Proofs

ZKP哈密顿认证

**功能:** 证明生成, 验证, 密钥管理, MirrorNet

![Zero-Knowledge Proofs](screenshots/vm/zkp.png)

#### 💬 SimpleX Chat

注重隐私的消息

**功能:** 端到端加密, 无用户ID, 自托管, 群组

![SimpleX Chat](screenshots/vm/simplex.png)

#### 🔐 Secret Vault

密钥和凭据管理

**功能:** 加密存储, 访问控制, 轮换, 审计

![Secret Vault](screenshots/vm/vault.png)

---

### Publishing

#### 📰 Publishing Platform

统一发布仪表板

**功能:** 多平台, 计划, 分析, 模板

![Publishing Platform](screenshots/vm/publish.png)

#### 💧 Droplet

文件上传和发布

**功能:** 文件上传, 分享链接, 过期, 密码保护

![Droplet](screenshots/vm/droplet.png)

#### 📝 Metablogizer

带Tor的静态站点发布器

**功能:** 静态站点, Tor发布, 模板, Markdown

![Metablogizer](screenshots/vm/metablogizer.png)

#### ✏️ Hexo Blog

静态博客生成器

**功能:** Markdown, 主题, 插件, 部署

![Hexo Blog](screenshots/vm/hexo.png)

#### 🐘 GoToSocial

ActivityPub社交服务器

**功能:** 兼容Mastodon, 联邦, 媒体, 隐私

![GoToSocial](screenshots/vm/gotosocial.png)

#### 📡 CyberFeed

RSS/Atom订阅聚合器

**功能:** 订阅管理, 分类, 搜索, 导出

![CyberFeed](screenshots/vm/cyberfeed.png)

---

### Security

#### 🛡️ CrowdSec

具有行为分析的协作式安全引擎

**功能:** 决策管理, 告警, Bouncer, 集合, 社区黑名单

![CrowdSec](screenshots/vm/crowdsec.png)

#### 🔥 Web Application Firewall

具有300+条OWASP安全规则的WAF

**功能:** OWASP规则, 自定义规则, CrowdSec集成, 请求日志

![Web Application Firewall](screenshots/vm/waf.png)

#### 🔥 Vortex Firewall

基于nftables的威胁执行防火墙

**功能:** IP黑名单, nftables集合, 威胁源, 地理封锁

![Vortex Firewall](screenshots/vm/vortex-firewall.png)

#### 🔒 System Hardening

符合ANSSI CSPN的内核和系统加固

**功能:** sysctl加固, 模块黑名单, 安全评分, AppArmor

![System Hardening](screenshots/vm/hardening.png)

#### 🔍 MITM Proxy

具有自动封禁功能的流量检查和WAF代理

**功能:** 流量检查, 请求日志, 自动封禁, SSL拦截

![MITM Proxy](screenshots/vm/mitmproxy.png)

#### 🔐 Auth Guardian

统一认证管理

**功能:** OAuth2, LDAP, 双因素/TOTP, 会话管理

![Auth Guardian](screenshots/vm/auth.png)

#### 🛡️ Network Access Control

具有隔离功能的客户端守护和NAC

**功能:** 设备控制, MAC过滤, 隔离, VLAN分配

![Network Access Control](screenshots/vm/nac.png)

#### 🚫 IP Block Manager

IP和网络封锁管理

**功能:** IP黑名单, 网络范围, 临时封禁, 导入/导出

![IP Block Manager](screenshots/vm/ipblock.png)

#### 🔐 MAC Guard

MAC地址访问控制

**功能:** MAC白名单/黑名单, 自动发现, 告警, VLAN绑定

![MAC Guard](screenshots/vm/mac-guard.png)

#### 📡 Traffic Interceptor

网络流量拦截和分析

**功能:** 数据包捕获, 协议分析, 会话跟踪, 取证

![Traffic Interceptor](screenshots/vm/interceptor.png)

#### 🍪 Cookie Manager

Cookie和会话安全管理

**功能:** Cookie策略, 会话安全, SameSite执行, 审计

![Cookie Manager](screenshots/vm/cookies.png)

#### ⚠️ Threat Dashboard

统一威胁可视化

**功能:** 威胁源, 攻击时间线, 严重级别, 关联

![Threat Dashboard](screenshots/vm/threats.png)

#### 🔬 Threat Analyst

AI驱动的威胁分析

**功能:** ML检测, 行为分析, IOC提取, 报告

![Threat Analyst](screenshots/vm/threat-analyst.png)

#### 🔴 CVE Triage

CVE漏洞跟踪和分类

**功能:** CVE数据库, 受影响包, 风险评分, 修复

![CVE Triage](screenshots/vm/cve-triage.png)

#### 🛡️ Wazuh SIEM

Wazuh SIEM集成

**功能:** 日志分析, 文件完整性, 漏洞检测, 合规

![Wazuh SIEM](screenshots/vm/wazuh.png)

#### 🔒 OSSEC HIDS

OSSEC主机入侵检测

**功能:** 日志分析, Rootkit检测, 文件完整性, 主动响应

![OSSEC HIDS](screenshots/vm/ossec.png)

#### 🦞 OpenClaw Scanner

网络漏洞扫描器

**功能:** 端口扫描, 服务检测, 漏洞检查, 报告

![OpenClaw Scanner](screenshots/vm/openclaw.png)

#### 🔌 IoT Guard

IoT设备安全监控

**功能:** 设备指纹, 异常检测, 隔离, 固件检查

![IoT Guard](screenshots/vm/iot-guard.png)

---

### Services

#### 📦 Services Portal

C3Box服务门户

**功能:** 服务链接, 状态概览, 快速访问, 分类

![Services Portal](screenshots/vm/c3box.png)

#### 🦊 Gitea

Git服务器(LXC)

**功能:** 仓库, 用户, SSH/HTTP, LFS, Actions

![Gitea](screenshots/vm/gitea.png)

#### ☁️ Nextcloud

文件同步(LXC)

**功能:** 文件同步, WebDAV, CalDAV, CardDAV, Talk

![Nextcloud](screenshots/vm/nextcloud.png)

---

### System

#### ⚙️ System Hub

系统配置和管理

**功能:** 设置, 日志, 服务, 更新

![System Hub](screenshots/vm/system.png)

#### 💾 Backup Manager

系统和LXC备份

**功能:** 配置备份, LXC快照, 恢复, 计划

![Backup Manager](screenshots/vm/backup.png)

#### 📋 Config Advisor

配置建议

**功能:** 安全审计, 最佳实践, 优化, 报告

![Config Advisor](screenshots/vm/config-advisor.png)

#### 📊 Reporter

系统报告和分析

**功能:** 报告, 计划, 导出, 邮件

![Reporter](screenshots/vm/reporter.png)

#### 🪞 Mirror Manager

APT镜像管理

**功能:** 镜像同步, 带宽, 计划, 缓存

![Mirror Manager](screenshots/vm/mirror.png)

#### 📀 System Cloner

系统镜像克隆

**功能:** 磁盘镜像, 克隆到USB, 恢复, 压缩

![System Cloner](screenshots/vm/cloner.png)

#### 👁️ Eye Remote

远程管理界面

**功能:** USB设备, 串口控制台, 启动媒体, 恢复

![Eye Remote](screenshots/vm/eye-remote.png)

#### 🖥️ RTTY Console

远程终端访问

**功能:** Web终端, SSH, 文件传输, 录制

![RTTY Console](screenshots/vm/rtty.png)

---

### VPN

#### 🔗 WireGuard VPN

具有内核集成的现代VPN

**功能:** 节点管理, 二维码, 流量统计, 多隧道

![WireGuard VPN](screenshots/vm/wireguard.png)

#### 🕸️ Mesh Network

使用Yggdrasil的Mesh网络

**功能:** 节点发现, 路由, 加密, IPv6覆盖

![Mesh Network](screenshots/vm/mesh.png)

#### 🔗 P2P Network

点对点网络

**功能:** 直接连接, NAT穿透, 加密, DHT

![P2P Network](screenshots/vm/p2p.png)

#### 🔗 MasterLink

SecuBox网格联邦

**功能:** 盒子发现, 联邦, 共享策略, 同步

![MasterLink](screenshots/vm/master-link.png)

---

