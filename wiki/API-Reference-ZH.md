# API 参考

[English](API-Reference) | [Francais](API-Reference-FR)

所有 SecuBox 模块通过 Unix 套接字暴露 REST API，由 nginx 代理到 `/api/v1/<module>/`。

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

## 通用端点

所有模块实现：

| 端点 | 方法 | 认证 | 描述 |
|------|------|------|------|
| `/status` | GET | 否 | 模块状态 |
| `/health` | GET | 否 | 健康检查 |

## Hub API (`/api/v1/hub/`)

| 端点 | 方法 | 描述 |
|------|------|------|
| `/dashboard` | GET | 仪表板数据 |
| `/menu` | GET | 动态侧边栏菜单 |
| `/modules` | GET | 模块状态列表 |
| `/alerts` | GET | 活跃告警 |
| `/system_health` | GET | 系统健康评分 |
| `/network_summary` | GET | 网络状态 |

## CrowdSec API (`/api/v1/crowdsec/`)

| 端点 | 方法 | 描述 |
|------|------|------|
| `/metrics` | GET | CrowdSec 指标 |
| `/decisions` | GET | 活跃决策 |
| `/alerts` | GET | 安全告警 |
| `/bouncers` | GET | Bouncer 状态 |
| `/ban` | POST | 封禁 IP |
| `/unban` | POST | 解封 IP |

## WireGuard API (`/api/v1/wireguard/`)

| 端点 | 方法 | 描述 |
|------|------|------|
| `/interfaces` | GET | WG 接口 |
| `/peers` | GET | 对等节点列表 |
| `/peer` | POST | 添加对等节点 |
| `/peer/{id}` | DELETE | 删除对等节点 |
| `/qrcode/{peer}` | GET | 对等节点二维码 |

## HAProxy API (`/api/v1/haproxy/`)

| 端点 | 方法 | 描述 |
|------|------|------|
| `/stats` | GET | HAProxy 统计 |
| `/backends` | GET | 后端服务器 |
| `/frontends` | GET | 前端监听器 |

## DPI API (`/api/v1/dpi/`)

| 端点 | 方法 | 描述 |
|------|------|------|
| `/flows` | GET | 活跃流量 |
| `/applications` | GET | 检测到的应用 |
| `/protocols` | GET | 协议统计 |

## QoS API (`/api/v1/qos/`)

| 端点 | 方法 | 描述 |
|------|------|------|
| `/status` | GET | QoS 状态 |
| `/classes` | GET | 流量类别 |
| `/rules` | GET | 整形规则 |

## 系统 API (`/api/v1/system/`)

| 端点 | 方法 | 描述 |
|------|------|------|
| `/info` | GET | 系统信息 |
| `/services` | GET | 服务状态 |
| `/logs` | GET | 系统日志 |
| `/reboot` | POST | 重启系统 |
| `/update` | POST | 更新软件包 |

## 错误响应

| 代码 | 描述 |
|------|------|
| 400 | 请求无效 |
| 401 | 未授权 |
| 403 | 禁止访问 |
| 404 | 未找到 |
| 500 | 服务器错误 |

## 另请参阅

- [[Configuration-ZH]] - API 配置
- [[Modules-ZH]] - 模块详情
