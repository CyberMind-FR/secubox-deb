# API 参考文档

[English](API-Reference) | [Français](API-Reference-FR)

所有 SecuBox 模块通过 Unix 套接字暴露 REST API，由 nginx 代理至 `/api/v1/<module>/`。

**总计：48 个模块 | ~1000+ API 端点**

---

## 认证

### 登录

```bash
curl -X POST https://localhost/api/v1/portal/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

响应：
```json
{
  "success": true,
  "token": "eyJ...",
  "username": "admin",
  "role": "admin"
}
```

### 使用令牌

```bash
curl https://localhost/api/v1/hub/status \
  -H 'Authorization: Bearer <token>'
```

---

## 通用端点

所有模块实现：

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 否 | 模块状态 |
| `/health` | GET | 否 | 健康检查 |

---

## 核心模块

### Hub API (`/api/v1/hub/`)

仪表板和模块管理。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 是 | 系统状态和模块健康 |
| `/modules` | GET | 是 | 列出所有已安装模块 |
| `/alerts` | GET | 否 | 系统告警 |
| `/monitoring` | GET | 是 | CPU、内存、负载指标 |
| `/dashboard` | GET | 否 | 完整仪表板数据 |
| `/menu` | GET | 否 | 动态侧边栏菜单 |
| `/security_summary` | GET | 是 | 安全概览 |
| `/network_summary` | GET | 否 | 网络接口摘要 |
| `/module_control` | POST | 是 | 启动/停止/重启模块 |
| `/notifications` | GET | 是 | 系统通知 |
| `/system_health` | GET | 否 | 系统健康评分 |
| `/check_updates` | GET | 是 | 检查更新 |
| `/apply_updates` | POST | 是 | 应用更新 |

### Portal API (`/api/v1/portal/`)

认证和会话管理。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/login` | POST | 否 | 用户认证 |
| `/logout` | POST | 否 | 结束会话 |
| `/verify` | GET | 否 | 验证当前会话 |
| `/sessions` | GET | 是 | 列出活动会话 |
| `/users` | GET | 是 | 列出所有用户（管理员） |
| `/users/create` | POST | 是 | 创建新用户（管理员） |
| `/users/change-password` | POST | 是 | 更改密码 |

### System API (`/api/v1/system/`)

系统管理和诊断。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/info` | GET | 否 | 系统信息 |
| `/resources` | GET | 否 | CPU/内存/磁盘使用 |
| `/services` | GET | 否 | 服务列表 |
| `/restart_services` | POST | 是 | 重启 SecuBox 服务 |
| `/reload_firewall` | POST | 是 | 重载 nftables |
| `/shutdown` | POST | 是 | 关机 |
| `/reboot` | POST | 是 | 重启系统 |
| `/logs` | GET | 是 | 系统日志 |
| `/diagnostics` | GET | 是 | 诊断报告 |
| `/backup` | POST | 是 | 创建配置备份 |
| `/restore_config` | POST | 是 | 从备份恢复 |

---

## 安全模块

### CrowdSec API (`/api/v1/crowdsec/`)

入侵检测与防御。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/components` | GET | 否 | 系统组件 |
| `/metrics` | GET | 是 | CrowdSec 指标 |
| `/decisions` | GET | 是 | 活动决策（封禁） |
| `/alerts` | GET | 是 | 安全告警 |
| `/bouncers` | GET | 是 | Bouncer 状态 |
| `/ban` | POST | 是 | 封禁 IP 地址 |
| `/unban` | POST | 是 | 解封 IP 地址 |
| `/nftables` | GET | 是 | nftables 统计 |
| `/service/start` | POST | 是 | 启动 CrowdSec |
| `/service/stop` | POST | 是 | 停止 CrowdSec |
| `/console/enroll` | POST | 是 | 注册到 CrowdSec 控制台 |

#### 封禁 IP 示例
```bash
curl -X POST https://localhost/api/v1/crowdsec/ban \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.1.100","duration":"24h","reason":"手动"}'
```

### WAF API (`/api/v1/waf/`)

Web 应用防火墙，300+ 规则。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 否 | WAF 状态 |
| `/categories` | GET | 否 | WAF 规则分类 |
| `/rules` | GET | 是 | 所有 WAF 规则 |
| `/rules/{category}` | GET | 是 | 分类规则 |
| `/category/{category}/toggle` | POST | 是 | 启用/禁用分类 |
| `/stats` | GET | 否 | 威胁统计 |
| `/alerts` | GET | 否 | 近期威胁告警 |
| `/bans` | GET | 否 | 活动 IP 封禁 |
| `/ban` | POST | 是 | 手动封禁 IP |
| `/unban/{ip}` | POST | 是 | 移除 IP 封禁 |
| `/whitelist` | GET | 是 | 获取白名单 IP |

### NAC API (`/api/v1/nac/`)

网络访问控制。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 是 | NAC 系统状态 |
| `/clients` | GET | 是 | 已连接客户端 |
| `/zones` | GET | 是 | 网络区域 |
| `/parental_rules` | GET | 是 | 家长控制规则 |
| `/add_to_zone` | POST | 是 | 移动客户端到区域 |
| `/approve_client` | POST | 是 | 批准新客户端 |
| `/ban_client` | POST | 是 | 封禁客户端 |
| `/quarantine_client` | POST | 是 | 隔离客户端 |

### Hardening API (`/api/v1/hardening/`)

内核和系统加固。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 否 | 加固状态 |
| `/components` | GET | 否 | 加固组件 |
| `/benchmark` | POST | 是 | 运行安全基准测试 |
| `/apply` | POST | 是 | 应用加固设置 |

---

## 网络模块

### Network Modes API (`/api/v1/netmodes/`)

网络拓扑配置。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 是 | 当前网络模式 |
| `/get_available_modes` | GET | 是 | 可用网络模式 |
| `/get_interfaces` | GET | 是 | 网络接口 |
| `/set_mode` | POST | 是 | 准备模式更改 |
| `/apply_mode` | POST | 是 | 应用网络模式 |
| `/rollback` | POST | 是 | 回滚到之前 |
| `/router_config` | GET | 是 | 路由器模式配置 |
| `/ap_config` | GET | 是 | 接入点配置 |

### WireGuard API (`/api/v1/wireguard/`)

VPN 隧道管理。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/interfaces` | GET | 否 | WireGuard 接口 |
| `/interface/{name}/up` | POST | 是 | 启用接口 |
| `/interface/{name}/down` | POST | 是 | 禁用接口 |
| `/peers` | GET | 否 | 对等节点列表 |
| `/peer` | POST | 是 | 添加新对等节点 |
| `/peer` | DELETE | 是 | 移除对等节点 |
| `/peer/{name}/config` | GET | 是 | 对等节点配置文件 |
| `/peer/{name}/qr` | GET | 是 | 对等节点二维码 |
| `/genkey` | POST | 是 | 生成密钥对 |

#### 添加对等节点示例
```bash
curl -X POST https://localhost/api/v1/wireguard/peer \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"mobile","allowed_ips":"10.0.0.2/32"}'
```

### QoS API (`/api/v1/qos/`)

流量整形和带宽管理。80+ 端点。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 是 | QoS 状态 |
| `/classes` | GET | 是 | 流量类别 |
| `/rules` | GET | 是 | 分类规则 |
| `/quotas` | GET | 是 | 带宽配额 |
| `/usage` | GET | 是 | 当前带宽使用 |
| `/apply_qos` | POST | 是 | 应用 QoS 配置 |
| `/realtime` | GET | 是 | 实时带宽 |
| `/top_talkers` | GET | 是 | 最大带宽消费者 |
| `/vlans` | GET | 是 | VLAN 接口 |
| `/vlan/create` | POST | 是 | 创建 VLAN |
| `/parental` | GET | 是 | 家长控制 |

### DPI API (`/api/v1/dpi/`)

深度包检测。40+ 端点。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 是 | DPI 状态 |
| `/flows` | GET | 是 | 活动流 |
| `/applications` | GET | 是 | 检测到的应用 |
| `/devices` | GET | 是 | 已连接设备 |
| `/top_apps` | GET | 是 | 顶级应用 |
| `/bandwidth_by_app` | GET | 是 | 按应用带宽 |
| `/block_rules` | GET | 是 | 应用阻止规则 |
| `/add_block_rule` | POST | 是 | 创建阻止规则 |
| `/dns_queries` | GET | 是 | DNS 查询 |
| `/ssl_flows` | GET | 是 | SSL/TLS 流 |

---

## 服务模块

### HAProxy API (`/api/v1/haproxy/`)

负载均衡器管理。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 否 | HAProxy 状态 |
| `/stats` | GET | 是 | HAProxy 统计 |
| `/backends` | GET | 是 | 后端服务器 |
| `/frontends` | GET | 是 | 前端监听器 |
| `/acls` | GET | 是 | 访问控制列表 |
| `/waf/status` | GET | 是 | WAF 集成状态 |
| `/waf/toggle` | POST | 是 | 切换 WAF |
| `/reload` | POST | 是 | 重载配置 |

### VHost API (`/api/v1/vhost/`)

虚拟主机管理。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/vhosts` | GET | 是 | 列出虚拟主机 |
| `/vhost/{domain}` | GET | 是 | 虚拟主机详情 |
| `/vhost` | POST | 是 | 创建虚拟主机 |
| `/vhost/{domain}` | PUT | 是 | 更新虚拟主机 |
| `/vhost/{domain}` | DELETE | 是 | 删除虚拟主机 |
| `/certificates` | GET | 否 | SSL 证书 |
| `/certificate/issue` | POST | 是 | 签发 Let's Encrypt 证书 |
| `/reload` | POST | 是 | 重载 nginx |

### Netdata API (`/api/v1/netdata/`)

系统监控代理。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 否 | Netdata 状态 |
| `/charts` | GET | 是 | 可用图表 |
| `/data` | GET | 是 | 图表数据 |
| `/cpu` | GET | 是 | CPU 指标 |
| `/memory` | GET | 是 | 内存指标 |
| `/disk` | GET | 是 | 磁盘指标 |
| `/alerts` | GET | 是 | 活动告警 |

---

## 应用模块

### Mail API (`/api/v1/mail/`)

邮件服务器管理（Postfix/Dovecot）。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 否 | 邮件服务器状态 |
| `/users` | GET | 是 | 邮件用户 |
| `/user` | POST | 是 | 创建用户 |
| `/user/{email}` | DELETE | 是 | 删除用户 |
| `/aliases` | GET | 是 | 邮件别名 |
| `/domains` | GET | 是 | 邮件域 |
| `/dkim/status` | GET | 是 | DKIM 状态 |
| `/dkim/setup` | POST | 是 | 配置 DKIM |
| `/spam/status` | GET | 是 | SpamAssassin 状态 |
| `/spam/setup` | POST | 是 | 配置反垃圾邮件 |
| `/av/status` | GET | 是 | ClamAV 状态 |
| `/av/setup` | POST | 是 | 配置防病毒 |
| `/acme/issue` | POST | 是 | 签发证书 |
| `/webmail/install` | POST | 是 | 安装网页邮件 |

### DNS API (`/api/v1/dns/`)

BIND DNS 服务器管理。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/zones` | GET | 是 | DNS 区域 |
| `/zone/{name}` | GET | 是 | 区域详情 |
| `/zone` | POST | 是 | 创建区域 |
| `/records/{zone}` | GET | 是 | 区域记录 |
| `/record` | POST | 是 | 添加记录 |
| `/dnssec/enable/{zone}` | POST | 是 | 启用 DNSSEC |
| `/reload` | POST | 是 | 重载 BIND |

### Users API (`/api/v1/users/`)

7 个服务的统一身份管理。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/users` | GET | 是 | 列出用户 |
| `/user` | POST | 是 | 创建用户 |
| `/user/{username}` | PUT | 是 | 更新用户 |
| `/user/{username}` | DELETE | 是 | 删除用户 |
| `/user/{username}/passwd` | POST | 是 | 更改密码 |
| `/groups` | GET | 是 | 列出组 |
| `/import` | POST | 是 | 批量导入用户 |
| `/export` | GET | 是 | 导出用户 |
| `/sync` | POST | 是 | 同步到服务 |

---

## 情报模块

### SOC API (`/api/v1/soc/`)

安全运营中心仪表板。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 否 | SOC 状态 |
| `/clock` | GET | 否 | 世界时钟（10 个时区） |
| `/map` | GET | 否 | 世界威胁地图 |
| `/tickets` | GET | 是 | 安全工单 |
| `/ticket` | POST | 是 | 创建工单 |
| `/intel` | GET | 是 | 威胁情报 IOC |
| `/intel` | POST | 是 | 添加 IOC |
| `/alerts` | GET | 是 | 安全告警 |
| `/ws` | WebSocket | 是 | 实时更新 |

### Metrics API (`/api/v1/metrics/`)

实时系统指标仪表板。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 否 | 指标状态 |
| `/overview` | GET | 否 | 系统概览 |
| `/waf_stats` | GET | 否 | WAF 统计 |
| `/connections` | GET | 否 | TCP 连接 |
| `/all` | GET | 否 | 所有指标合并 |
| `/certs` | GET | 否 | SSL 证书 |
| `/vhosts` | GET | 否 | 虚拟主机 |

### Device Intel API (`/api/v1/device-intel/`)

资产发现和指纹识别。

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/devices` | GET | 是 | 发现的设备 |
| `/device/{mac}` | GET | 是 | 设备详情 |
| `/scan` | POST | 是 | 触发主动扫描 |
| `/vendors` | GET | 是 | MAC 厂商查询 |
| `/dhcp_leases` | GET | 是 | DHCP 租约 |
| `/arp_table` | GET | 是 | ARP 表 |
| `/trust/{mac}` | POST | 是 | 标记为可信 |

---

## 错误响应

```json
{
  "success": false,
  "error": "未授权",
  "code": 401
}
```

| 代码 | 描述 |
|------|------|
| 400 | 错误请求 |
| 401 | 未授权 |
| 403 | 禁止 |
| 404 | 未找到 |
| 500 | 服务器错误 |

---

## 速率限制

- 每 IP 100 请求/分钟（未认证）
- 每用户 1000 请求/分钟（已认证）

---

## WebSocket

实时更新可用于 `wss://localhost/api/v1/<module>/ws`：

```javascript
const ws = new WebSocket('wss://localhost/api/v1/soc/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('更新:', data);
};
```

支持 WebSocket 的模块：
- `/api/v1/soc/ws` — SOC 实时告警
- `/api/v1/dpi/ws` — 流更新
- `/api/v1/qos/ws` — 带宽统计

---

## 架构说明

**基于 Socket 的通信：**
- 每个模块运行在 Unix 套接字：`/run/secubox/<module>.sock`
- Nginx 代理：`http+unix:///run/secubox/<module>.sock`

**认证模式：**
- JWT 令牌通过 `Authorization: Bearer <token>`
- 由 `/api/v1/portal/login` 签发
- 默认 24 小时过期

---

## 另请参阅

- [[Installation-ZH]] - 安装指南
- [[Modules-ZH]] - 模块详情
- [[Configuration-ZH]] - API 配置
