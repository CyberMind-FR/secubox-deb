# 安装指南

[English](Installation) | [Francais](Installation-FR)

## 快速安装（APT）

```bash
# 添加 SecuBox 软件源
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# 安装完整套件
sudo apt install secubox-full

# 或最小安装
sudo apt install secubox-lite
```

## 手动配置 APT

```bash
# 导入 GPG 密钥
curl -fsSL https://apt.secubox.in/gpg.key | gpg --dearmor -o /etc/apt/keyrings/secubox.gpg

# 添加软件源
echo "deb [signed-by=/etc/apt/keyrings/secubox.gpg] https://apt.secubox.in bookworm main" \
  | sudo tee /etc/apt/sources.list.d/secubox.list

# 更新并安装
sudo apt update
sudo apt install secubox-full
```

## 系统镜像安装

### 下载镜像

| 开发板 | 镜像 |
|--------|------|
| MOCHAbin | `secubox-mochabin-bookworm.img.gz` |
| ESPRESSObin v7 | `secubox-espressobin-v7-bookworm.img.gz` |
| ESPRESSObin Ultra | `secubox-espressobin-ultra-bookworm.img.gz` |
| VM x64 | `secubox-vm-x64-bookworm.img.gz` |

### 写入 SD 卡 / eMMC

```bash
# 下载
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-mochabin-bookworm.img.gz

# 写入 SD 卡
gunzip -c secubox-mochabin-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

### VirtualBox 设置

```bash
# 解压
gunzip secubox-vm-x64-bookworm.img.gz

# 转换为 VDI
VBoxManage convertfromraw secubox-vm-x64-bookworm.img secubox.vdi --format VDI

# 创建虚拟机
VBoxManage createvm --name SecuBox --ostype Debian_64 --register
VBoxManage modifyvm SecuBox --memory 2048 --cpus 2 --nic1 nat --firmware efi
VBoxManage storagectl SecuBox --name SATA --add sata
VBoxManage storageattach SecuBox --storagectl SATA --port 0 --device 0 --type hdd --medium secubox.vdi

# 启动
VBoxManage startvm SecuBox
```

### QEMU 设置

```bash
gunzip secubox-vm-x64-bookworm.img.gz
qemu-system-x86_64 \
  -drive file=secubox-vm-x64-bookworm.img,format=raw \
  -enable-kvm \
  -m 2048 \
  -smp 2 \
  -bios /usr/share/ovmf/OVMF.fd
```

## 软件包选择

### 元软件包

| 软件包 | 描述 |
|--------|------|
| `secubox-full` | 全部模块（推荐用于 MOCHAbin/VM） |
| `secubox-lite` | 核心模块（用于 ESPRESSObin） |

### 单独软件包

**核心：**
- `secubox-core` - 共享库、认证框架
- `secubox-hub` - 中央仪表板
- `secubox-portal` - Web 认证

**安全：**
- `secubox-crowdsec` - IDS/IPS（CrowdSec）
- `secubox-waf` - Web 应用防火墙
- `secubox-auth` - OAuth2、强制门户
- `secubox-nac` - 网络访问控制

**网络：**
- `secubox-wireguard` - VPN 仪表板
- `secubox-haproxy` - 负载均衡器
- `secubox-dpi` - 深度包检测
- `secubox-qos` - 带宽管理
- `secubox-netmodes` - 网络模式

**应用：**
- `secubox-mail` - 邮件服务器
- `secubox-dns` - DNS 服务器
- `secubox-netdata` - 监控

## 安装后配置

### 首次启动

1. 访问 Web 界面：`https://<IP>:8443`
2. 登录：admin / admin
3. 立即更改密码
4. 配置网络设置
5. 启用所需模块

### 安全加固

```bash
# 更改默认密码
passwd root
passwd secubox

# 更新系统
apt update && apt upgrade

# 启用防火墙
systemctl enable --now nftables
```

## 系统要求

### 硬件

| 规格 | 最低 | 推荐 |
|------|------|------|
| 内存 | 1 GB | 2+ GB |
| 存储 | 4 GB | 16+ GB |
| CPU | ARM64/x86_64 | 2+ 核心 |

### 软件

- Debian 12 (bookworm)
- systemd
- Python 3.11+

## 另请参阅

- [[Live-USB-ZH]] - 免安装试用
- [[Configuration-ZH]] - 系统配置
- [[Modules-ZH]] - 模块详情
