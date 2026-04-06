# SecuBox 配置

[English](Configuration) | [Français](Configuration-FR)

## 配置文件

SecuBox 使用位于 `/etc/secubox/` 目录下的 TOML 配置文件。

### 主配置结构

```
/etc/secubox/
├── secubox.toml          # 主配置文件
├── modules/              # 各模块配置
│   ├── crowdsec.toml
│   ├── wireguard.toml
│   ├── dpi.toml
│   └── ...
├── tls/                  # TLS 证书
│   ├── cert.pem
│   └── key.pem
└── secrets/              # 敏感数据 (chmod 600)
    └── jwt.key
```

### secubox.toml

```toml
[general]
hostname = "secubox"
timezone = "Europe/Paris"
locale = "en_US.UTF-8"

[network]
wan_interface = "eth0"
lan_interfaces = ["lan0", "lan1"]
bridge_name = "br-lan"
lan_ip = "192.168.1.1"
lan_netmask = "255.255.255.0"
dhcp_enabled = true
dhcp_range_start = "192.168.1.100"
dhcp_range_end = "192.168.1.200"

[security]
firewall_enabled = true
default_policy = "drop"
crowdsec_enabled = true
waf_enabled = true

[services]
nginx_enabled = true
haproxy_enabled = true
ssh_enabled = true
ssh_port = 22
```

## 模块配置

每个模块在 `/etc/secubox/modules/` 目录下都有自己的配置文件。

### 示例：CrowdSec

```toml
# /etc/secubox/modules/crowdsec.toml
[crowdsec]
enabled = true
api_url = "http://127.0.0.1:8080"
log_level = "info"

[bouncers]
firewall = true
nginx = true

[scenarios]
ssh_bruteforce = true
http_bad_user_agent = true
```

### 示例：WireGuard

```toml
# /etc/secubox/modules/wireguard.toml
[wireguard]
enabled = true
interface = "wg0"
listen_port = 51820
private_key_file = "/etc/secubox/secrets/wg_private.key"

[peers]
# 对等节点通过 API 管理
```

## 环境变量

部分设置可以通过环境变量覆盖：

```bash
SECUBOX_DEBUG=1              # 启用调试模式
SECUBOX_LOG_LEVEL=debug      # 设置日志级别
SECUBOX_CONFIG=/path/to/cfg  # 自定义配置路径
```

## 应用更改

修改配置后：

```bash
# 验证配置
secubox-config validate

# 应用更改
secubox-config apply

# 或重启特定模块
systemctl restart secubox-<module>
```

## 双缓冲系统 (CSPN)

对于安全关键的更改，SecuBox 使用双缓冲系统：

```
/etc/secubox/
├── active/     # 当前生效配置（只读）
├── shadow/     # 待生效更改（可编辑）
└── rollback/   # 4 个历史版本 (R1-R4)
```

### 工作流程

1. 在 `shadow/` 中编辑
2. 验证：`secubox-config validate --shadow`
3. 交换生效：`secubox-config swap`
4. 如需回滚：`secubox-config rollback R1`

## 另请参阅

- [[Installation]] — 初始安装
- [[API-Reference]] — REST API 文档
- [[Modules]] — 可用模块
- [[Troubleshooting]] — 常见问题
