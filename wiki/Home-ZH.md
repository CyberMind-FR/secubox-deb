# SecuBox-DEB

**Debian 安全设备** | [English](Home) | [Francais](Home-FR) | **v1.4.0**

SecuBox 是一个完整的安全设备解决方案，从 OpenWrt 移植到 Debian bookworm，专为 GlobalScale ARM64 开发板（MOCHAbin、ESPRESSObin）和 x86_64 系统设计。现在包含 61 个软件包和 1200+ 个 API 端点。

## 快速开始

### Live USB（最快方式）

直接从 USB 启动 - 无需安装：

```bash
# 下载
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz

# 写入 USB 驱动器
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

完整指南请参阅 [[Live-USB-ZH]]。

### APT 安装

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full
```

## 功能特性

| 类别 | 模块 |
|------|------|
| **安全** | CrowdSec IDS/IPS、WAF、NAC、Auth |
| **网络** | WireGuard VPN、HAProxy、DPI、QoS |
| **监控** | Netdata、MediaFlow、Metrics |
| **邮件** | Postfix/Dovecot、Webmail |
| **发布** | Droplet、Streamlit、MetaBlogizer |

## 支持的硬件

| 开发板 | SoC | 用途 |
|--------|-----|------|
| MOCHAbin | Armada 7040 | SecuBox Pro |
| ESPRESSObin v7 | Armada 3720 | SecuBox Lite |
| ESPRESSObin Ultra | Armada 3720 | SecuBox Lite+ |
| VM x86_64 | 任意 | 测试/开发 |

## 文档

- [[Live-USB-ZH]] - USB 启动盘指南
- [[Installation-ZH]] - 完整安装
- [[Configuration-ZH]] - 系统配置
- [[API-Reference-ZH]] - REST API 文档
- [[Troubleshooting-ZH]] - 常见问题

## 默认凭据

| 服务 | 用户名 | 密码 |
|------|--------|------|
| Web 界面 | admin | admin |
| SSH | root | secubox |

## 链接

- [GitHub 仓库](https://github.com/CyberMind-FR/secubox-deb)
- [发布版本](https://github.com/CyberMind-FR/secubox-deb/releases)
- [问题反馈](https://github.com/CyberMind-FR/secubox-deb/issues)
