# ESPRESSObin — SecuBox 安装指南

[English](ESPRESSObin) | [Français](ESPRESSObin-FR)

通过 U-Boot 在 GlobalScale ESPRESSObin 开发板上安装 SecuBox 的完整指南。

## 硬件型号

| 型号 | SoC | CPU | 内存 | eMMC | 发布年份 |
|-------|-----|-----|-----|------|---------|
| ESPRESSObin v5 | Armada 3720 | 2× A53 @ 800MHz | 512MB-1GB | — | 2017 |
| ESPRESSObin v7 | Armada 3720 | 2× A53 @ 1.2GHz | 1-2GB | 0/4/8GB | 2019 |
| ESPRESSObin Ultra | Armada 3720 | 2× A53 @ 1.2GHz | 1-4GB | 8GB | 2020 |

**SecuBox 支持情况:**
- ✅ ESPRESSObin v7（推荐）
- ✅ ESPRESSObin Ultra
- ⚠️ ESPRESSObin v5（有限支持 — 512MB/1GB 内存，不支持 SECUBOX_LITE 配置）

## eMMC 存储限制

| 配置 | eMMC | 最大镜像大小 | 构建参数 |
|---------------|------|----------------|------------|
| 无 eMMC | — | 仅 SD 卡 | — |
| 4GB eMMC | 4 GB | **3.5 GB** | `--size 3.5G` |
| 8GB eMMC | 8 GB | 6 GB | 默认 4G 可用 |

**重要提示:**
- 默认 SecuBox 镜像大小：**3.5GB**（适合所有 eMMC 型号）
- `gzwrite` 需要约 350MB 内存用于解压缓冲区
- eMMC 上需保留 500MB 以上空间用于磨损均衡

## 开发板布局与接口

```
┌─────────────────────────────────────────────────────────┐
│  ESPRESSObin v7 / Ultra                                 │
│                                                         │
│  ┌─────┐  ┌─────┐  ┌─────┐     ┌──────────┐            │
│  │ WAN │  │LAN 1│  │LAN 2│     │ USB 3.0  │            │
│  │ RJ45│  │ RJ45│  │ RJ45│     │  (blue)  │            │
│  └─────┘  └─────┘  └─────┘     └──────────┘            │
│    eth0     lan0     lan1         USB                  │
│                                                         │
│  [PWR]  [RST]                  ┌──────────┐  ┌──────┐  │
│                                │  µSD     │  │ USB  │  │
│  ○○○○○○ ← UART (J1)            │  slot    │  │ 2.0  │  │
│  123456                        └──────────┘  └──────┘  │
│                                    mmc0       USB      │
│  [DIP SW] ← Boot mode                                  │
│  1 2 3 4 5                                             │
│                                                         │
│           ┌─────────────────┐                          │
│           │     eMMC        │ ← mmc1 (under board)     │
│           │     (8GB)       │                          │
│           └─────────────────┘                          │
└─────────────────────────────────────────────────────────┘
```

## 串口控制台 (UART)

### 引脚定义 — J1 排针（6 针）

```
Pin 1: GND    ← 连接到 USB-TTL 的 GND
Pin 2: NC
Pin 3: NC
Pin 4: RX     ← 连接到 USB-TTL 的 TX
Pin 5: TX     ← 连接到 USB-TTL 的 RX
Pin 6: NC
```

**参数设置:** 115200 波特率, 8N1, 无流控

```bash
# Linux
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200

# macOS
screen /dev/tty.usbserial-* 115200

# Windows: PuTTY → Serial → COM3 → 115200
```

## DIP 开关启动模式

5 位 DIP 开关控制启动源和 CPU 速度。

### 启动源 (SW1-SW3)

| SW1 | SW2 | SW3 | 启动源 |
|-----|-----|-----|-------------|
| OFF | OFF | OFF | SPI NOR Flash（默认 U-Boot） |
| ON  | OFF | OFF | eMMC |
| OFF | ON  | OFF | SD 卡 |
| ON  | ON  | OFF | UART（恢复模式） |
| OFF | OFF | ON  | SATA（如有） |

### CPU 速度 (SW4)

| SW4 | CPU 频率 |
|-----|---------------|
| OFF | 1.2 GHz（默认） |
| ON  | 800 MHz（低功耗） |

### 调试模式 (SW5)

| SW5 | 模式 |
|-----|------|
| OFF | 正常 |
| ON  | 调试 / JTAG 启用 |

**正常 SecuBox 运行时:** 所有开关置于 OFF（从 SPI NOR 启动加载 U-Boot → 然后从 eMMC/SD 启动）

## U-Boot 刷写流程

### 方法 1: 使用 USB 驱动器和 gzwrite（推荐）

#### 准备 USB 驱动器

```bash
# On your PC
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz

# Format USB as FAT32 or ext4
sudo mkfs.vfat /dev/sdb1
# or
sudo mkfs.ext4 /dev/sdb1

# Copy image
sudo mount /dev/sdb1 /mnt
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/
sudo umount /mnt
```

#### 通过 U-Boot 刷写

```
=> usb reset
resetting USB...
USB XHCI 1.00
scanning bus usb@58000 for devices... 2 USB Device(s) found
scanning usb for storage devices... 1 Storage Device(s) found

=> usb storage
  Device 0: Vendor: Kingston Rev:  Prod: DataTraveler 3.0
            Type: Removable Hard Disk
            Capacity: 29510.4 MB = 28.8 GB

=> ls usb 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz

=> setenv loadaddr 0x1000000
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
314543223 bytes read in 3422 ms (87.7 MiB/s)

=> gzwrite mmc 1 $loadaddr $filesize
Uncompressed size: 3758096384 bytes (3.5 GiB)
writing to mmc 1...
3758096384 bytes written in 142568 ms (25.1 MiB/s)
```

### 方法 2: 使用 SD 卡和 gzwrite

```
=> mmc dev 0
=> ls mmc 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz

=> setenv loadaddr 0x1000000
=> load mmc 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize
```

### 方法 3: TFTP 网络启动

如果您有 TFTP 服务器：

```
=> setenv serverip 192.168.1.100
=> setenv ipaddr 192.168.1.50
=> setenv loadaddr 0x1000000
=> tftpboot $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize
```

### 方法 4: 原始 mmc write（未压缩）

对于未压缩的 `.img` 文件（较慢，需要更大的 USB 驱动器）：

```
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img
=> mmc dev 1
=> mmc write $loadaddr 0 $filesize
```

**注意:** `mmc write` 需要块计数，而非字节数。计算公式：`blocks = filesize / 512`

## 配置启动顺序

刷写完成后，将 eMMC 设置为首选启动设备：

```
=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
Saving Environment to SPI Flash... done

=> reset
```

## 自动启动方法

SecuBox 镜像包含两种自动启动方法：

### 方法 A: boot.scr（推荐）

U-Boot 会自动在启动分区搜索 `boot.scr`：

```
=> load mmc 1:2 $loadaddr /boot/boot.scr
=> source $loadaddr
```

或手动设置：
```
=> setenv bootcmd "load mmc 1:2 0x1000000 /boot/boot.scr; source 0x1000000"
=> saveenv
```

### 方法 B: extlinux.conf (Distroboot)

如果 U-Boot 支持 distroboot：

```
=> run distro_bootcmd
```

这会自动搜索 `/boot/extlinux/extlinux.conf`。

### 手动启动（备用方案）

如果自动启动失败：

```
=> setenv loadaddr 0x1000000
=> setenv fdt_addr 0x2000000

=> load mmc 1:2 $loadaddr /boot/Image
=> load mmc 1:2 $fdt_addr /boot/dtbs/marvell/armada-3720-espressobin-v7.dtb

=> setenv bootargs "root=LABEL=rootfs rootfstype=ext4 rootwait console=ttyMV0,115200"
=> booti $loadaddr - $fdt_addr
```

## U-Boot 设备参考

| 设备 | U-Boot | Linux | 描述 |
|--------|--------|-------|-------------|
| SD 卡 | `mmc 0` | `/dev/mmcblk0` | microSD 插槽 |
| eMMC | `mmc 1` | `/dev/mmcblk1` | 内置 eMMC |
| USB | `usb 0` | `/dev/sda` | USB 存储设备 |
| SPI NOR | `sf 0` | `/dev/mtd0` | U-Boot 固件 |

## 网络接口 (Linux)

ESPRESSObin 使用 Marvell 88E6341 DSA 交换机：

| 接口 | U-Boot | Linux | 角色 | IP（默认） |
|-----------|--------|-------|------|--------------|
| eth0 | — | eth0 | WAN（上行链路） | DHCP 客户端 |
| lan0 | — | lan0 | LAN 端口 1 | br-lan 成员 |
| lan1 | — | lan1 | LAN 端口 2 | br-lan 成员 |
| — | — | br-lan | LAN 网桥 | 192.168.1.1/24 |

## 故障排除

### USB 未检测到

```
=> usb reset
=> usb tree
=> usb info
```

尝试使用其他 USB 端口或 USB 2.0 驱动器（某些 USB 3.0 驱动器可能存在兼容问题）。

### eMMC 未检测到

```
=> mmc list
mmc@d0000: 0 (SD)
mmc@d8000: 1 (eMMC)

=> mmc dev 1
=> mmc info
Device: mmc@d8000
Manufacturer ID: 15
OEM: 100
Name: 8GTF4
Bus Speed: 52000000
Mode: MMC High Speed (52MHz)
Capacity: 7.3 GiB
```

如果 `mmc dev 1` 失败，则开发板可能没有 eMMC — 请使用 SD 卡。

### gzwrite 失败 — 内存不足

```
=> setenv loadaddr 0x1000000
```

对于 1GB 内存的开发板，请确保使用压缩镜像（`.img.gz`）。

### 启动失败 — boot_targets 配置错误

```
=> print boot_targets
boot_targets=mmc0 usb0 mmc1

=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
=> reset
```

### 重置 U-Boot 环境

```
=> env default -a
=> saveenv
=> reset
```

### 检查环境变量

```
=> print
=> print bootcmd
=> print boot_targets
```

## 恢复 — UART 启动

如果 U-Boot 已损坏：

1. 设置 DIP 开关：SW1=ON, SW2=ON, SW3=OFF（UART 启动模式）
2. 使用 `mvebu_xmodem` 或 `kwboot` 通过串口加载 U-Boot
3. 将新的 U-Boot 刷写到 SPI NOR
4. 将 DIP 开关恢复到正常状态

```bash
# Linux recovery (requires kwboot)
sudo kwboot -t -b u-boot-espressobin.bin /dev/ttyUSB0 -B 115200
```

## 安装后配置

### 默认凭据

| 用户 | 密码 |
|------|----------|
| root | secubox |
| secubox | secubox |

### 首要步骤

```bash
# Connect via serial or SSH
ssh root@192.168.1.1

# Change passwords
passwd root
passwd secubox

# Check status
secubox-status

# Access Web UI
# https://192.168.1.1:8443
```

### 验证网络

```bash
# Check interfaces
ip link show

# Check bridge
bridge link show

# Check IP addresses
ip addr show
```

## 性能对比 (ESPRESSObin vs MOCHAbin)

| 指标 | ESPRESSObin v7 | MOCHAbin |
|--------|----------------|----------|
| CPU | 2× A53 @ 1.2GHz | 4× A72 @ 1.4GHz |
| 内存 | 1-2 GB | 4 GB |
| 网络 | 3× GbE | 4× GbE + 2× 10GbE |
| DPI 模式 | 仅被动模式 | 支持内联模式 |
| CrowdSec | 精简模式 | 完整模式 |
| SecuBox 配置 | secubox-lite | secubox-full |

## 另请参阅

- [[ARM-Installation]] — 通用 ARM 安装指南
- [[Installation]] — x86/VM 安装
- [[Live-USB]] — 无需安装即可试用
- [[Modules]] — 可用的 SecuBox 模块
- [ESPRESSObin Wiki](http://wiki.espressobin.net/) — 官方硬件 Wiki
- [Marvell Armada 3720](https://www.marvell.com/embedded-processors/armada-3700/) — SoC 文档
