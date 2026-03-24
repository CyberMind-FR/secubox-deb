# Live USB 指南

[English](Live-USB) | [Francais](Live-USB-FR)

直接从 USB 启动 SecuBox，所有软件包已预装。

## 下载

**最新版本：** [secubox-live-amd64-bookworm.img.gz](https://github.com/CyberMind-FR/secubox-deb/releases/latest)

## 功能特性

| 功能 | 描述 |
|------|------|
| UEFI 启动 | 现代 GRUB 引导程序 |
| SquashFS | 压缩根文件系统（约250MB） |
| 持久化 | 重启后保留更改 |
| 预装 | 包含全部30+个 SecuBox 软件包 |

## 写入 USB

### Linux / macOS

```bash
# 查找 USB 设备
lsblk

# 写入（将 /dev/sdX 替换为你的设备！）
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

### Windows

1. 下载 [Rufus](https://rufus.ie/) 或 [balenaEtcher](https://etcher.balena.io/)
2. 解压 `.img.gz` 文件得到 `.img`
3. 选择 `.img` 文件
4. 选择你的 USB 驱动器
5. 点击写入/烧录

## 启动菜单选项

| 选项 | 描述 |
|------|------|
| **SecuBox Live** | 正常启动（带持久化） |
| **安全模式** | 最小驱动，用于故障排除 |
| **无持久化** | 全新启动，不保存更改 |
| **加载到内存** | 将整个系统加载到内存 |

## 默认凭据

| 服务 | 用户名 | 密码 |
|------|--------|------|
| Web 界面 | admin | admin |
| SSH | root | secubox |
| SSH | secubox | secubox |

**重要：** 首次启动后请修改密码！

## 网络访问

启动后：

1. 查找 IP：`ip addr` 或查看路由器 DHCP 租约
2. Web 界面：`https://<IP>:8443`
3. SSH：`ssh root@<IP>`

默认网络配置：
- 所有接口使用 DHCP 客户端
- 备用：192.168.1.1/24

## 持久化

自动保存的更改：
- `/home/*` - 用户文件
- `/etc/*` - 配置
- `/var/log/*` - 日志
- 已安装的软件包

### 重置持久化

```bash
# 使用"无持久化"启动，然后：
sudo mkfs.ext4 -L persistence /dev/sdX3
```

## 分区布局

| 分区 | 大小 | 类型 | 用途 |
|------|------|------|------|
| p1 | 512MB | EFI | GRUB 引导程序 |
| p2 | 2GB | FAT32 | Live 系统（SquashFS） |
| p3 | 剩余空间 | ext4 | 持久化存储 |

## 验证

```bash
# 下载校验和
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/SHA256SUMS

# 验证
sha256sum -c SHA256SUMS --ignore-missing
```

## 故障排除

### USB 无法启动

1. 进入 BIOS/UEFI（F2、F12、Del、Esc）
2. 启用 USB 启动
3. 禁用安全启动
4. 将 USB 设为第一启动设备

### 黑屏

1. 从启动菜单选择"安全模式"
2. 添加 `nomodeset` 到内核参数：
   - 在 GRUB 按 `e`
   - 在 `linux` 行添加 `nomodeset`
   - 按 Ctrl+X

### 无网络

```bash
ip link show
sudo systemctl restart networking
sudo dhclient eth0
```

## 从源码构建

```bash
git clone https://github.com/CyberMind-FR/secubox-deb
cd secubox-deb
sudo bash image/build-live-usb.sh --size 8G --slipstream
```

## 另请参阅

- [[Installation-ZH]] - 永久安装
- [[Configuration-ZH]] - 系统配置
- [[Troubleshooting-ZH]] - 更多解决方案
