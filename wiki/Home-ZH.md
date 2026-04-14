# SecuBox-DEB

**Debian 安全设备** | [English](Home) | [Français](Home-FR)

SecuBox 是一个完整的安全设备解决方案，从 OpenWrt 移植到 Debian bookworm，专为 GlobalScale ARM64 开发板（MOCHAbin、ESPRESSObin）和 x86_64 系统设计。现在包含 **93 个软件包**和 **2000+ 个 API 端点**。

---

## 快速开始

### VirtualBox（2 分钟）⭐

在 VirtualBox 中即时测试 SecuBox - 无需 USB 驱动器：

```bash
# 下载镜像
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
gunzip secubox-live-amd64-bookworm.img.gz

# 转换为 VDI 格式
VBoxManage convertfromraw secubox-live-amd64-bookworm.img secubox-live.vdi --format VDI

# 创建并启动虚拟机（使用我们的脚本）
curl -sLO https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh
chmod +x create-secubox-vm.sh
./create-secubox-vm.sh secubox-live.vdi
```

**或者一行命令自动下载：**

```bash
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh | bash -s -- --download
```

**访问方式（等待 30-60 秒启动）：**

| 服务 | 访问方式 |
|------|----------|
| **SSH** | `ssh -p 2222 root@localhost` |
| **Web 界面** | https://localhost:9443 |
| **密码** | `secubox` |

完整文档和故障排除请参阅 [[Live-USB-VirtualBox]]。

---

### Live USB（硬件）

在物理硬件上直接从 USB 启动：

```bash
# 下载
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz

# 写入 USB 驱动器（将 /dev/sdX 替换为您的设备）
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

完整指南请参阅 [[Live-USB-ZH]]。

---

### APT 安装（现有 Debian）

```bash
# 添加仓库并安装
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full   # 或 secubox-lite
```

详细说明请参阅 [[Installation-ZH]]。

---

## VM 创建脚本选项

`create-secubox-vm.sh` 脚本支持：

```bash
./create-secubox-vm.sh [选项] <image.vdi|image.img>

选项:
    --download        自动下载最新镜像
    --name 名称       VM 名称（默认：SecuBox-Live）
    --memory MB       内存大小（默认：4096）
    --cpus N          CPU 数量（默认：2）
    --ssh-port 端口   SSH 端口（默认：2222）
    --https-port 端口 HTTPS 端口（默认：9443）
    --headless        无界面模式启动
    --no-start        创建 VM 但不启动
```

**示例：**

```bash
# 下载并创建无界面 VM
./create-secubox-vm.sh --download --headless

# 自定义配置
./create-secubox-vm.sh secubox.vdi --name "SecuBox-Dev" --memory 8192 --cpus 4

# 不同端口（如果默认端口已被使用）
./create-secubox-vm.sh secubox.vdi --ssh-port 2223 --https-port 9444
```

---

## 功能特性

| 类别 | 模块 | 数量 |
|------|------|------|
| **安全** | CrowdSec、WAF、NAC、Auth、加固、AI-Insights、IPBlock | 15 |
| **网络** | WireGuard、HAProxy、DPI、QoS、网络模式、Interceptor | 12 |
| **SOC** | Fleet 监控、告警关联、威胁地图、控制台 TUI | 6 |
| **监控** | Netdata、Metrics、Threats、OpenClaw OSINT | 8 |
| **应用** | Ollama、Jellyfin、HomeAssistant、Matrix、Jitsi、PeerTube | 21 |
| **系统工具** | Glances、MQTT、TURN、Vault、Cloner、VM | 22 |
| **邮件和 DNS** | Postfix/Dovecot、Webmail、DNS Provider | 9 |

**总计：93 个软件包**

---

## 支持的硬件

| 开发板 | SoC | 配置 | 用途 |
|--------|-----|------|------|
| MOCHAbin | Armada 7040 | Full | 企业网关 |
| ESPRESSObin v7 | Armada 3720 | Lite | 家庭/中小企业路由器 |
| ESPRESSObin Ultra | Armada 3720 | Lite+ | 带 Wi-Fi 的家庭网关 |
| Raspberry Pi 4/5 | BCM2711/2712 | Lite/Full | 创客项目 |
| VM x86_64 | 任意 | Full | 测试/开发 |

---

## 文档

- [[Live-USB-VirtualBox]] - **VirtualBox 快速入门** ⭐
- [[Live-USB-ZH]] - USB 启动盘指南
- [[Installation-ZH]] - 完整安装
- [[MODULES-ZH|模块]] - 所有 93 个模块
- [[API-Reference-ZH]] - REST API（2000+ 端点）
- [[Troubleshooting-ZH]] - 常见问题

---

## 默认凭据

| 服务 | 用户名 | 密码 |
|------|--------|------|
| Web 界面 | admin | secubox |
| SSH | root | secubox |

---

## 链接

- [GitHub 仓库](https://github.com/CyberMind-FR/secubox-deb)
- [发布版本](https://github.com/CyberMind-FR/secubox-deb/releases)
- [问题反馈](https://github.com/CyberMind-FR/secubox-deb/issues)
- [CyberMind](https://cybermind.fr)
