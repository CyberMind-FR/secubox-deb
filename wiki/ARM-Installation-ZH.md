# ARM 安装指南 - 通过 U-Boot

[English](ARM-Installation) | [Français](ARM-Installation-FR)

本指南介绍如何在 ARM 开发板（Marvell Armada）上使用 U-Boot 将镜像从 USB 或 SD 卡刷写到 eMMC 来安装 SecuBox。

## 支持的开发板

| 开发板 | SoC | 内存 | 配置文件 |
|-------|-----|-----|---------|
| ESPRESSObin v7 | Armada 3720 | 1-2 GB | secubox-lite |
| ESPRESSObin Ultra | Armada 3720 | 1-4 GB | secubox-lite |
| MOCHAbin | Armada 7040 | 4 GB | secubox-full |

## eMMC 存储限制

| 开发板 | eMMC | 最大镜像 | 默认值 |
|-------|------|-----------|---------|
| ESPRESSObin v7 (无 eMMC) | — | 仅支持 SD 卡 | — |
| ESPRESSObin v7 (4GB) | 4 GB | **3.5 GB** | 使用 `--size 3.5G` |
| ESPRESSObin v7 (8GB) | 8 GB | 6 GB | 4 GB |
| ESPRESSObin Ultra | 8 GB | 6 GB | 4 GB |
| MOCHAbin | 8 GB | 6 GB | 4 GB |

**注意事项：**
- 为数据分区和磨损均衡预留约 500MB-2GB 的空间
- 对于 4GB eMMC 的开发板：使用 `--size 3.5G` 构建
- MOCHAbin 可以使用 SATA/NVMe 进行更大容量的安装
- `gzwrite` 需要内存来解压（约 350MB 缓冲区）

## 前提条件

- 串口控制台适配器（USB-TTL）
- 包含镜像的 USB 驱动器或 SD 卡
- 串口终端软件：`screen`、`minicom` 或 PuTTY

### 串口控制台设置

```
Baud rate:    115200
Data bits:    8
Parity:       None
Stop bits:    1
Flow control: None
```

```bash
# Linux
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200
```

## 准备启动介质

### 选项 A：USB 驱动器（推荐）

将 USB 驱动器格式化为 FAT32 或 ext4 分区并复制镜像：

```bash
# Download the image
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz

# Mount USB drive (assuming /dev/sdb1)
sudo mount /dev/sdb1 /mnt

# Copy image
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/

# Unmount
sudo umount /mnt
```

### 选项 B：SecuBox Live USB

如果使用 SecuBox Live USB，将镜像复制到持久化分区（分区 4）：

```bash
# The persistence partition is already ext4
sudo mount /dev/sdX4 /mnt
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/
sudo umount /mnt
```

## U-Boot 刷写流程

### 1. 进入 U-Boot

连接串口控制台并启动开发板。按任意键停止自动启动：

```
Hit any key to stop autoboot:  0
=>
```

### 2. 初始化 USB

```
=> usb reset
resetting USB...
USB XHCI 1.00
scanning bus usb@58000 for devices... 2 USB Device(s) found
scanning usb for storage devices... 1 Storage Device(s) found
```

### 3. 验证存储设备

```
=> usb storage
  Device 0: Vendor: Kingston Rev:  Prod: DataTraveler 3.0
            Type: Removable Hard Disk
            Capacity: 29510.4 MB = 28.8 GB
```

### 4. 列出文件

对于 FAT32 分区（分区 1）：
```
=> ls usb 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz
```

对于 ext4 分区（Live USB 上的分区 4）：
```
=> ls usb 0:4
       314543223 secubox-espressobin-v7-bookworm.img.gz
```

### 5. 刷写到 eMMC

```bash
# Set load address (needs ~350MB free RAM)
=> setenv loadaddr 0x1000000

# Load image from USB
# For FAT32 (partition 1):
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz

# For ext4 (partition 4):
=> load usb 0:4 $loadaddr secubox-espressobin-v7-bookworm.img.gz

# Write to eMMC with automatic decompression
=> gzwrite mmc 1 $loadaddr $filesize
```

`gzwrite` 命令会解压并直接写入 eMMC。根据镜像大小，此过程需要 2-5 分钟。

### 6. 配置启动顺序

```bash
# Set eMMC as primary boot device
=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
Saving Environment to SPI Flash... done

# Reboot
=> reset
```

## 替代方案：从 SD 卡刷写

如果镜像在 SD 卡而非 USB 上：

```bash
=> mmc dev 0                    # Select SD card
=> ls mmc 0:1                   # List files
=> setenv loadaddr 0x1000000
=> load mmc 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize    # Write to eMMC
```

## 启动设备参考

| 设备 | U-Boot | 描述 |
|--------|--------|-------------|
| SD 卡 | `mmc 0` | microSD 卡槽 |
| eMMC | `mmc 1` | 内置 eMMC（安装目标）|
| USB | `usb 0` | USB 存储设备 |
| SATA | `scsi 0` | SATA 驱动器（MOCHAbin）|

## 开发板特定说明

### ESPRESSObin v7

- **eMMC**：可选，如果没有可能需要从 SD 卡启动
- **内存**：1GB 型号空间有限，使用 `loadaddr 0x1000000`
- **网络**：eth0=WAN, lan0/lan1=LAN (DSA switch)

### ESPRESSObin Ultra

- **eMMC**：内置 8GB
- **内存**：最高 4GB
- **网络**：与 v7 相同

### MOCHAbin

- **eMMC**：内置 8GB
- **内存**：4GB（可以容纳更大的镜像）
- **网络**：多个 10GbE + GbE 端口
- **SATA**：也可以安装到 SATA 驱动器

```bash
# MOCHAbin: Flash to SATA instead of eMMC
=> scsi scan
=> gzwrite scsi 0 $loadaddr $filesize
```

## 故障排除

### USB 未检测到

```bash
=> usb reset
=> usb tree        # Show USB device tree
=> usb info        # Detailed USB info
```

### eMMC 未检测到

```bash
=> mmc list        # List MMC devices
=> mmc dev 1       # Select eMMC
=> mmc info        # Show eMMC info
```

### 加载失败（找不到文件）

```bash
=> ls usb 0        # List all partitions
=> ls usb 0:1      # Try partition 1
=> ls usb 0:2      # Try partition 2
```

### 内存不足

对于 1GB 的开发板，确保没有加载其他数据：

```bash
=> setenv loadaddr 0x1000000    # Use lower address
```

### 重置环境变量

```bash
=> env default -a
=> saveenv
```

### 检查当前环境变量

```bash
=> print                    # Show all variables
=> print boot_targets       # Show boot order
=> print loadaddr           # Show load address
```

## 安装后配置

刷写完成后，开发板会自动启动 SecuBox。

### 默认凭据

| 用户 | 密码 |
|------|----------|
| root | secubox |
| secubox | secubox |

### 首要步骤

1. 通过 SSH 连接：`ssh root@<IP>`
2. 更改密码：`passwd`
3. 访问 Web 界面：`https://<IP>:8443`

### 网络接口

| 开发板 | WAN | LAN |
|-------|-----|-----|
| ESPRESSObin | eth0 | lan0, lan1 |
| MOCHAbin | eth0 | eth1-eth4, sfp0-sfp1 |

## 另请参阅

- [[Installation]] - 通用安装指南
- [[Live-USB]] - 免安装试用
- [[Modules]] - 可用模块
