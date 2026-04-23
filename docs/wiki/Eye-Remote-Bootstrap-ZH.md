# Eye Remote Bootstrap 启动媒体管理

**版本:** 2.1.0
**最后更新:** 2026-04-23
**状态:** 生产环境
**作者:** CyberMind — Gerald Kerma

---

## 概述

Eye Remote Bootstrap 系统扩展了 Pi Zero W USB OTG 小工具，为 ESPRESSObin 板提供托管启动媒体通道。通过单个 USB OTG 电缆，Eye Remote 同时提供：

1. **指标传输** (ECM) — 10.55.0.0/30 上的 USB 以太网网络
2. **串行控制台** (ACM) — /dev/ttyACM0（主机）/ /dev/ttyGS0（小工具）上的调试控制台
3. **启动媒体** (Mass Storage) — 提供内核、DTB、initrd 和 rootfs 镜像的 USB LUN

这使得恢复工作流程无需物理干预：从 Eye Remote Web 仪表板刷写新内核，在目标板上测试它，然后使用原子交换语义将其提升到活动槽。

### 架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Eye Remote Pi Zero W                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐    ┌──────────────────┐    ┌───────────────┐  │
│  │ FastAPI Router  │───▶│ core/boot_media  │───▶│ gadget-setup  │  │
│  │ /boot-media/*   │    │ (Python)         │    │ (Bash)        │  │
│  └────────┬────────┘    └────────┬─────────┘    └───────┬───────┘  │
│           │                      │                      │          │
│           ▼                      ▼                      ▼          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              /var/lib/secubox/eye-remote/boot-media/        │   │
│  │  ┌─────────┐  ┌─────────┐  ┌──────────────────────────────┐  │   │
│  │  │ active  │  │ shadow  │  │ images/<sha256>.img          │  │   │
│  │  │ (link)  │  │ (link)  │  │ images/<sha256>.img.tmp (UP) │  │   │
│  │  └────┬────┘  └────┬────┘  └──────────────────────────────┘  │   │
│  │       │            │                                         │   │
│  │       ▼            ▼                                         │   │
│  │  ┌─────────────────────────────┐    ┌────────────────────┐  │   │
│  │  │ LUN 0 (mass_storage.usb0)   │    │ tftp/ (symlinks)   │  │   │
│  │  │ points to active slot       │    │ serves shadow slot │  │   │
│  │  └─────────────────────────────┘    └────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                    libcomposite configfs                       │ │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────────┐           │ │
│  │  │ ecm.usb0 │  │ acm.usb0 │  │ mass_storage.usb0  │           │ │
│  │  │ 10.55.0.2│  │ ttyGS0   │  │ LUN 0 (removable)  │           │ │
│  │  └──────────┘  └──────────┘  └────────────────────┘           │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ USB OTG cable
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     ESPRESSObin U-Boot                              │
│  Option 1: usb start → fatload usb 0 Image                          │
│  Option 2: dhcp → tftpboot $kernel_addr_r Image (shadow channel)    │
└─────────────────────────────────────────────────────────────────────┘
```

### 启动媒体目录结构

Eye Remote 维护双缓冲 4R 存储布局：

```
/var/lib/secubox/eye-remote/boot-media/
├── state.json                    ← 启动媒体元数据和状态
├── active                        ← 符号链接 → images/<sha256>.img
├── shadow                        ← 符号链接 → images/<sha256>.img（或 NULL）
├── images/
│   ├── a1b2c3d4e5f6.img         ← FAT32 或 ext4 镜像（只读，去重）
│   ├── f0e1d2c3b4a5.img.tmp     ← 上传进行中（临时）
│   ├── rollback-r1/             ← 先前活动（4R #1）
│   │   └── a1b2c3d4e5f6.img
│   ├── rollback-r2/             ← 先前活动（4R #2）
│   ├── rollback-r3/             ← 先前活动（4R #3）
│   └── rollback-r4/             ← 先前活动（4R #4）
└── tftp/                        ← TFTP 服务根目录（指向 shadow 的符号链接）
    ├── Image → ../images/f0e1d2c3b4a5.img
    ├── device-tree.dtb
    └── initrd.img
```

### 状态机

```
初始状态：空（无 active，无 shadow）
                    │
                    ▼
    ┌─────────────────────────────────┐
    │   UPLOAD SHADOW                 │
    │ (通过 /api/v1/eye-remote/       │
    │  boot-media/upload)             │
    └────────────┬────────────────────┘
                 │
                 ▼
    ┌─────────────────────────────────┐
    │   SHADOW READY                  │
    │ (镜像有效，可提取)               │
    │                                 │
    │ [分支 A] 通过 TFTP 测试 ──┐    │
    │            (可选)          │    │
    │                             ▼   │
    │                      测试中...  │
    │                             │   │
    │ [分支 B] ◄───────────────┘     │
    │ 将 Shadow 提升为 Active         │
    │ (通过 /api/v1/eye-remote/       │
    │  boot-media/swap)               │
    └────────────┬────────────────────┘
                 │
                 ▼
    ┌─────────────────────────────────┐
    │   ACTIVE ONLY                   │
    │ (shadow 已清除，active 已设置)  │
    │ (LUN 已弹出并重新附加)          │
    └────────────┬────────────────────┘
                 │
    [可选]       │ 上传新 shadow
                 ▼
    ┌─────────────────────────────────┐
    │   READY TO SWAP                 │
    │ (active + shadow 均已设置)      │
    │ 可以测试 shadow 或回滚          │
    └────────────┬────────────────────┘
                 │
    ┌────────────┴───────────┐
    │                        │
    │ Swap（提升 shadow）    │  Rollback（恢复 R1）
    │                        │
    └────────────┬───────────┘
                 │
                 ▼
    ┌─────────────────────────────────┐
    │   SWAPPED                       │
    │ (shadow → active, active → R1)  │
    └─────────────────────────────────┘
```

---

## 功能特性

### 1. USB Mass Storage LUN

- **功能:** 通过 libcomposite configfs 的 `mass_storage.usb0`
- **LUN 0:** 指向 **active** 启动槽
- **可移动媒体:** 是（允许弹出而无需卸载）
- **大小:** 16 MiB–4 GiB（文件系统无关）
- **支持格式:** FAT16、FAT32、ext2、ext3、ext4
- **访问:** 读+写（刷写 U-Boot 环境、日志等）

### 2. 双缓冲与 4R 回滚

Eye Remote 维护 **4 个回滚快照（4R）**：

- **Active:** 当前通过 USB LUN 向 ESPRESSObin 提供服务
- **Shadow:** 待验证（已上传但未提升）
- **R1–R4:** 先前的活动状态，可用于回滚

每次状态更改（交换、回滚）都会原子链接并记录。

### 3. TFTP Shadow 通道

与 USB LUN 并行，Eye Remote 在 10.55.0.2 端口 69 上运行 **dnsmasq TFTP**：

- **根目录:** `/var/lib/secubox/eye-remote/boot-media/tftp/`
- **内容:** 指向 shadow 槽的符号链接（`Image`、`device-tree.dtb`、`initrd.img`）
- **使用场景:** 测试新内核而不交换活动槽
- **启动命令（ESPRESSObin U-Boot）:**
  ```
  => setenv serverip 10.55.0.2
  => setenv ipaddr 10.55.0.1
  => tftpboot $kernel_addr_r Image
  => booti $kernel_addr_r - $fdt_addr_r
  ```

### 4. 防崩溃原子交换

提升 shadow 到 active 时：

1. **从小工具弹出 LUN**（强制断开连接）
2. **原子交换符号链接**（重命名，而不是取消链接然后链接）
3. **更新元数据**（state.json）
4. **重新附加 LUN** 到小工具
5. **验证** LUN 文件与预期路径匹配

所有操作都受 **文件锁 + 进程锁**（PARAMETERS 模块样式）保护。

### 5. API 管理

**基本路径:** `/api/v1/eye-remote/boot-media/`

所有端点都需要 **JWT 身份验证**，POST 需要 `boot:write` 范围，GET 需要 `boot:read` 范围。

---

## API 端点

| 方法 | 路径 | 身份验证 | 描述 |
|--------|------|------|---|
| **GET** | `/state` | `boot:read` | 获取当前启动媒体状态（槽、元数据） |
| **POST** | `/upload` | `boot:write` | 流式传输镜像到 shadow 槽（分块 multipart） |
| **POST** | `/swap` | `boot:write` | 将 shadow 提升为 active，active 轮换到 R1 |
| **POST** | `/rollback` | `boot:write` | 从 R1–R4 恢复先前的 active |
| **GET** | `/tftp/status` | `boot:read` | TFTP 服务状态和 shadow 内容 |
| **GET** | `/images` | `boot:read` | 列出可用镜像及元数据 |

### 端点详细规范

#### GET `/api/v1/eye-remote/boot-media/state`

**请求:**
```bash
curl -H "Authorization: Bearer $JWT" \
     http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state
```

**响应 (200 OK):**
```json
{
  "active": {
    "path": "images/a1b2c3d4e5f6.img",
    "sha256": "a1b2c3d4e5f6...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T10:30:00Z",
    "label": "debian-bookworm-arm64-espressobin"
  },
  "shadow": {
    "path": "images/f0e1d2c3b4a5.img",
    "sha256": "f0e1d2c3b4a5...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T11:45:00Z",
    "label": "debian-bookworm-arm64-espressobin-rc1"
  },
  "lun_attached": true,
  "last_swap_at": "2026-04-23T10:00:00Z",
  "tftp_armed": true,
  "rollback_available": ["r1", "r2", "r3"]
}
```

#### POST `/api/v1/eye-remote/boot-media/upload`

**请求 (multipart/form-data):**
```bash
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  -F "image=@debian-bookworm-arm64.img" \
  -F "label=debian-bookworm-arm64-espressobin-rc1" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload
```

**参数:**
- `image`（文件，必需）：启动镜像（FAT32/ext4）
- `label`（字符串，可选）：人类可读标签

**处理:**
1. 流式传输到带 `.tmp` 后缀的临时文件
2. 在流式传输期间计算 SHA256
3. 验证文件系统魔数和大小（16 MiB–4 GiB）
4. 提取启动文件到 `tftp/`（如果可提取：Image、dtb、initrd）
5. 原子重命名为 `images/<sha256>.img`
6. 更新 shadow 符号链接

**响应 (201 Created):**
```json
{
  "path": "images/f0e1d2c3b4a5.img",
  "sha256": "f0e1d2c3b4a5...",
  "size_bytes": 268435456,
  "created_at": "2026-04-23T11:45:00Z",
  "label": "debian-bookworm-arm64-espressobin-rc1",
  "tftp_ready": true
}
```

**响应 (400 Bad Request) — 镜像无效:**
```json
{
  "error": "Invalid filesystem",
  "detail": "Image size must be 16 MiB–4 GiB"
}
```

#### POST `/api/v1/eye-remote/boot-media/swap`

**请求:**
```bash
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/swap
```

**可选参数:**
- `verify=true`（默认）：验证 LUN 重新附加成功

**处理:**
1. 检查 shadow 存在且有效
2. 从小工具弹出 LUN
3. 交换符号链接：`active` ← `shadow`，`r1` ← 旧 `active`
4. 移动回滚链：`r2` ← `r1`，`r3` ← `r2`，`r4` ← `r3`
5. 清除 shadow 槽
6. 重新附加 LUN
7. 更新 state.json

**响应 (200 OK):**
```json
{
  "success": true,
  "message": "Boot slot swapped successfully",
  "active": {
    "path": "images/f0e1d2c3b4a5.img",
    "sha256": "f0e1d2c3b4a5...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T11:45:00Z"
  },
  "rollback_available": ["r1", "r2", "r3", "r4"]
}
```

**响应 (409 Conflict) — Shadow 未准备好:**
```json
{
  "error": "No shadow to swap",
  "detail": "Upload an image to shadow before promoting"
}
```

#### POST `/api/v1/eye-remote/boot-media/rollback`

**请求:**
```bash
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/rollback?target=r1
```

**参数:**
- `target`（字符串）：要恢复的回滚槽（`r1`、`r2`、`r3` 或 `r4`）

**处理:**
1. 检查目标存在
2. 弹出 LUN
3. 将目标提升为 active，轮换链
4. 重新附加 LUN

**响应 (200 OK):**
```json
{
  "success": true,
  "message": "Restored from r1",
  "active": {
    "path": "images/a1b2c3d4e5f6.img",
    "sha256": "a1b2c3d4e5f6...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T10:30:00Z"
  }
}
```

#### GET `/api/v1/eye-remote/boot-media/tftp/status`

**请求:**
```bash
curl -H "Authorization: Bearer $JWT" \
     http://10.55.0.1:8000/api/v1/eye-remote/boot-media/tftp/status
```

**响应 (200 OK):**
```json
{
  "enabled": true,
  "dnsmasq_running": true,
  "port": 69,
  "root": "/var/lib/secubox/eye-remote/boot-media/tftp",
  "shadow": {
    "path": "images/f0e1d2c3b4a5.img",
    "label": "debian-bookworm-arm64-espressobin-rc1"
  },
  "files": [
    {
      "name": "Image",
      "size": 12582912,
      "type": "kernel"
    },
    {
      "name": "device-tree.dtb",
      "size": 65536,
      "type": "devicetree"
    },
    {
      "name": "initrd.img",
      "size": 8388608,
      "type": "initramfs"
    }
  ]
}
```

---

## 工作流程示例

### 工作流程 1：上传新镜像

```bash
#!/bin/bash

# 1. 生成 JWT token（以 boot:write 用户身份登录）
JWT=$(curl -s -X POST http://10.55.0.1:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"boot-admin","password":"secubox-bootstrap"}' | jq -r .access_token)

# 2. 上传新镜像到 shadow
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  -F "image=@debian-bookworm-arm64-espressobin-rc1.img" \
  -F "label=RC1 Build $(date +%Y%m%d)" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload

# 3. 检查当前状态
curl -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state | jq .

# 输出:
# {
#   "active": { ... 旧镜像 ... },
#   "shadow": { ... 刚上传的新镜像 ... },
#   "tftp_armed": true,
#   ...
# }
```

### 工作流程 2：通过 TFTP 测试（可选）

无需 API 调用！shadow 立即通过 TFTP 可用。

```bash
# 在 ESPRESSObin U-Boot 控制台上:
=> setenv serverip 10.55.0.2
=> setenv ipaddr 10.55.0.1
=> tftpboot $kernel_addr_r Image
=> booti $kernel_addr_r - $fdt_addr_r

# 启动日志通过 Eye Remote 显示在串行控制台上
```

如果测试内核崩溃或失败，只需重新启动：U-Boot 将从 USB LUN 加载 **active** 槽（未更改）。

### 工作流程 3：将 Shadow 提升为 Active

一旦 shadow 经过测试且稳定：

```bash
# 1. 获取 JWT（已从上传获得）
JWT=$(...)

# 2. 将 shadow 提升为 active
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/swap

# 响应显示 active 现在包含 RC1 镜像，
# 旧 active 保存在 r1 中，shadow 已清除。

# 3. 重启 ESPRESSObin（或电源循环）
# U-Boot 现在将从 LUN 加载新内核
```

### 工作流程 4：从 LUN 启动

在 ESPRESSObin U-Boot 控制台上：

```bash
=> usb start
=> usb tree

# 输出:
# USB device tree:
#   1  Hub (480 Mb/s, 0mA)
#   |  ├─ 1.1 Mass Storage (active boot media)
#   └─ ...

=> fatload usb 0 $kernel_addr_r Image
=> fatload usb 0 $fdt_addr_r device-tree.dtb
=> fatload usb 0 $initrd_addr_r initrd.img
=> booti $kernel_addr_r $initrd_addr_r:$initrd_size $fdt_addr_r
```

### 工作流程 5：回滚到先前版本

如果活动镜像损坏或不稳定：

```bash
# 1. 检查可用的回滚点
curl -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state | \
  jq .rollback_available

# 输出: ["r1", "r2", "r3", "r4"]

# 2. 回滚到 r1（最近的先前版本）
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/rollback?target=r1

# 响应确认 active 现已从 r1 恢复
# r1 内容移至 r2，r2→r3，r3→r4，r4 清除

# 3. 重启 ESPRESSObin — 再次启动旧内核
```

---

## 镜像要求

### 格式

- **支持:** FAT16、FAT32、ext2、ext3、ext4
- **推荐:** FAT32（最大 U-Boot 兼容性）

### 大小

- **最小:** 16 MiB（允许内核 + DTB + initrd 的空间）
- **最大:** 4 GiB（USB 大容量存储实际限制）
- **典型:** 256 MiB–1 GiB

### 内容

**必需（用于 USB LUN 启动）:**
- 内核镜像（arm64 为 `Image`，arm32 为 `zImage`）
- 设备树二进制文件（`device-tree.dtb` 或 `<board>.dtb`）

**可选:**
- 初始 ramdisk（`initrd.img`）
- U-Boot 环境变量
- 启动脚本

**FAT32 结构示例:**
```
/Image                   ← 内核（必需）
/device-tree.dtb        ← 设备树（必需）
/initrd.img             ← Initramfs（可选）
/uEnv.txt               ← U-Boot 环境（可选）
/boot.scr               ← 启动脚本（可选）
```

### 验证

Eye Remote 在上传时验证镜像：

1. **文件系统魔数:** 检查 FAT 或 ext 的魔数字节
2. **大小检查:** 强制执行 16 MiB–4 GiB 边界
3. **可提取性:** 对于 TFTP，尝试提取 Image、dtb、initrd
4. **SHA256 摘要:** 计算并存储以进行完整性跟踪

如果验证失败，上传将以 400 Bad Request 拒绝。

---

## 配置

### secubox.conf

Eye Remote bootstrap 遵循 `/etc/secubox/secubox.conf` 中的以下设置：

```toml
[eye_remote]
enabled = true
bootstrap_enabled = true
bootstrap_root = "/var/lib/secubox/eye-remote/boot-media"
max_image_size_gb = 4
min_image_size_mb = 16

[eye_remote.tftp]
enabled = true
dnsmasq_config = "/etc/dnsmasq.d/secubox-eye-remote-tftp.conf"
port = 69

[eye_remote.gadget]
ecm_enabled = true
acm_enabled = true
mass_storage_enabled = true
```

### TFTP DHCP 配置 (dnsmasq)

**文件:** `/etc/dnsmasq.d/secubox-eye-remote-tftp.conf`

```ini
# TFTP service for Eye Remote bootstrap
enable-tftp
tftp-root=/var/lib/secubox/eye-remote/boot-media/tftp
tftp-port=69
listen-address=10.55.0.2
# Allow read from tftp root only (security)
tftp-secure
# Increase timeout for large initrd
tftp-max-block-size=1024
```

### 上电顺序

**注意:** Eye Remote 小工具在启动时立即附加 LUN。ESPRESSObin U-Boot 负责检测 LUN 并启动 `usb start`。

**推荐序列:**
1. 给 ESPRESSObin 上电（U-Boot 启动，等待用户输入）
2. 将 USB OTG 电缆插入 Eye Remote
3. 等待 2 秒进行 USB 枚举
4. 在 U-Boot 上按 Enter 中断自动启动
5. 执行 `usb start` 命令
6. 执行 `fatload usb 0 ...` 加载内核

---

## 故障排除

### 问题："ESPRESSObin 上 LUN 不可见"

**症状:**
- `usb start` 不显示大容量存储设备
- `usb tree` 仅列出集线器，无 LUN

**诊断:**
```bash
# 在 Eye Remote（主机）上:
ssh pi@eye-remote.local
systemctl status secubox-eye-remote-gadget

# 检查小工具树是否存在:
ls -la /sys/kernel/config/usb_gadget/secubox/functions/mass_storage.usb0/
```

**解决方案:**
1. **重启小工具:**
   ```bash
   systemctl restart secubox-eye-remote-gadget
   ```

2. **检查 active 符号链接存在:**
   ```bash
   ls -la /var/lib/secubox/eye-remote/boot-media/active
   # 应指向真实镜像文件
   ```

3. **验证文件可读:**
   ```bash
   ls -lah /var/lib/secubox/eye-remote/boot-media/images/
   # 文件应具有读取权限
   ```

4. **物理检查 USB 连接:**
   - 使用 DATA 端口（中间），而不是 PWR 端口
   - 尝试不同的 USB 电缆或端口
   - 验证 Eye Remote 和 ESPRESSObin 之间没有 USB 集线器

### 问题："TFTP 超时 / 未找到镜像"

**症状:**
- `tftpboot` 挂起或报告 "not found"
- TFTP 根路径不正确

**诊断:**
```bash
# 检查 TFTP 服务:
curl http://10.55.0.1:8000/api/v1/eye-remote/boot-media/tftp/status | jq .

# 检查 shadow 符号链接:
ls -la /var/lib/secubox/eye-remote/boot-media/tftp/

# 验证 dnsmasq TFTP 正在运行:
ps aux | grep dnsmasq
netstat -tlnup | grep :69
```

**解决方案:**
1. **首先上传镜像到 shadow:**
   ```bash
   curl -X POST \
     -H "Authorization: Bearer $JWT" \
     -F "image=@debian-bookworm.img" \
     http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload
   ```

2. **验证网络连接:**
   ```bash
   # 在 ESPRESSObin U-Boot 上:
   => ping 10.55.0.2
   # 应使用主机 IP 响应
   ```

3. **检查文件提取是否成功:**
   - TFTP 状态应显示非空 `files` 数组
   - 如果镜像是原始的（无文件系统），提取必须优雅失败
   - 改为使用 LUN 启动

### 问题："交换失败 / LUN 弹出超时"

**症状:**
- `POST /swap` 返回 500 错误
- LUN 在小工具中卡住

**诊断:**
```bash
# 检查小工具锁:
lsof | grep /var/lib/secubox/eye-remote/boot-media/

# 检查 gadget-setup.sh 日志:
journalctl -u secubox-eye-remote-gadget -n 50

# 验证文件锁未被持有:
ps aux | grep eye-remote
```

**解决方案:**
1. **通过 shell 强制弹出（小心！）:**
   ```bash
   sudo /usr/sbin/gadget-setup.sh swap-lun ""
   sleep 0.5
   sudo /usr/sbin/gadget-setup.sh swap-lun \
     "/var/lib/secubox/eye-remote/boot-media/active"
   ```

2. **重启小工具服务:**
   ```bash
   systemctl stop secubox-eye-remote-gadget
   sleep 2
   systemctl start secubox-eye-remote-gadget
   ```

3. **检查过时进程:**
   ```bash
   systemctl status secubox-eye-remote-api
   # 如果 API 进程持有锁，重启它
   systemctl restart secubox-eye-remote-api
   ```

### 问题："上传时文件系统无效"

**症状:**
- `POST /upload` 返回 400 Bad Request
- 错误："Invalid filesystem" 或 "Size out of range"

**解决方案:**
1. **验证镜像格式:**
   ```bash
   file debian-bookworm.img
   # 应输出: FAT boot sector, x86 or x64 boot loader binary
   # 或: Linux rev 1.0 ext4 filesystem
   ```

2. **检查镜像大小:**
   ```bash
   ls -lh debian-bookworm.img
   # 应在 16 MiB 到 4 GiB 之间
   ```

3. **如果需要，创建有效的 FAT32 镜像:**
   ```bash
   # 创建 256 MiB FAT32 镜像
   fallocate -l 256M debian-bookworm.img
   mkfs.vfat -F32 debian-bookworm.img

   # 挂载并复制内核文件
   sudo mount debian-bookworm.img /mnt/boot
   sudo cp Image /mnt/boot/
   sudo cp device-tree.dtb /mnt/boot/
   sudo umount /mnt/boot
   ```

---

## 另请参阅

- **[Eye Remote Hardware](Eye-Remote-Hardware.md)** — 物理连接，引脚分配
- **[Eye Remote Gateway](Eye-Remote-Gateway.md)** — 网络配置，DHCP/DNS
- **[Eye Remote Implementation](Eye-Remote-Implementation.md)** — Python/Bash 内部，代码库结构
- **[Architecture Boot](Architecture-Boot.md)** — SecuBox-Deb 的整体启动架构
- **[U-Boot Documentation](../eye-remote/uboot-bootcmd.md)** — ESPRESSObin U-Boot 命令

---

**CyberMind · SecuBox-Deb · Eye Remote Bootstrap v2.1.0**

*最后审查: 2026-04-23 · 维护者: Gerald Kerma <gandalf@cybermind.fr>*
