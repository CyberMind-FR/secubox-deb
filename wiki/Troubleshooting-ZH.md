# SecuBox 故障排除

[English](Troubleshooting) | [Français](Troubleshooting-FR)

## 快速诊断

```bash
# 系统状态
secubox-status

# 检查所有服务
systemctl status secubox-* --no-pager

# 查看日志
journalctl -u secubox-* -f

# 网络诊断
secubox-netdiag
```

## 常见问题

### 无法访问 Web UI

**症状:** 浏览器显示连接被拒绝或超时

**解决方案:**

1. 检查 nginx 是否运行:
   ```bash
   systemctl status nginx
   systemctl restart nginx
   ```

2. 检查防火墙:
   ```bash
   nft list ruleset | grep 443
   ```

3. 验证 IP 地址:
   ```bash
   ip addr show br-lan
   ```

4. 检查证书:
   ```bash
   openssl x509 -in /etc/secubox/tls/cert.pem -text -noout
   ```

### SSH 连接被拒绝

**解决方案:**

1. 检查 SSH 服务:
   ```bash
   systemctl status sshd
   ```

2. 检查防火墙是否允许 SSH:
   ```bash
   nft list ruleset | grep 22
   ```

3. 验证监听端口:
   ```bash
   ss -tlnp | grep ssh
   ```

### LAN 客户端无法上网

**解决方案:**

1. 检查 NAT 是否已启用:
   ```bash
   nft list table inet nat
   ```

2. 检查 IP 转发:
   ```bash
   sysctl net.ipv4.ip_forward
   ```

3. 检查 DHCP 服务器:
   ```bash
   systemctl status dnsmasq
   ```

4. 检查 WAN 接口是否有 IP:
   ```bash
   ip addr show eth0
   ```

### CrowdSec 未阻止攻击

**解决方案:**

1. 检查 CrowdSec 是否运行:
   ```bash
   systemctl status crowdsec
   cscli metrics
   ```

2. 检查 bouncer:
   ```bash
   cscli bouncers list
   ```

3. 检查决策:
   ```bash
   cscli decisions list
   ```

### WireGuard 无法连接

**解决方案:**

1. 检查接口是否启用:
   ```bash
   wg show
   ```

2. 检查端口是否开放:
   ```bash
   ss -ulnp | grep 51820
   nft list ruleset | grep 51820
   ```

3. 检查密钥是否已配置:
   ```bash
   cat /etc/wireguard/wg0.conf
   ```

### CPU/内存占用过高

**解决方案:**

1. 检查资源使用情况:
   ```bash
   htop
   # 或
   secubox-glances
   ```

2. 检查卡死的进程:
   ```bash
   ps aux --sort=-%cpu | head -10
   ```

3. 在 ESPRESSObin (低内存设备) 上:
   ```bash
   # 如果尚未启用交换分区，请启用
   swapon --show
   free -h
   ```

## 日志位置

| 服务 | 日志位置 |
|---------|--------------|
| 系统 | `journalctl` |
| Nginx | `/var/log/nginx/` |
| HAProxy | `/var/log/haproxy.log` |
| CrowdSec | `cscli metrics` / `journalctl -u crowdsec` |
| SecuBox 模块 | `journalctl -u secubox-*` |
| 审计 | `/var/log/secubox/audit.log` |

## 恢复模式

### 通过串口控制台 (ARM)

1. 连接串口控制台 (115200 8N1)
2. 启动并中断 U-Boot
3. 启动到单用户模式:
   ```
   => setenv bootargs "root=LABEL=rootfs single"
   => boot
   ```

### 通过 GRUB (x86)

1. 在 GRUB 菜单中按 `e`
2. 在内核行添加 `single`
3. 按 F10 启动

### 恢复出厂设置

```bash
# 警告: 这将重置所有配置!
secubox-factory-reset

# 或手动执行:
rm -rf /etc/secubox/modules/*
cp /usr/share/secubox/defaults/* /etc/secubox/
systemctl restart secubox-*
```

## 网络调试

### 抓包

```bash
# 在 WAN 接口
tcpdump -i eth0 -w /tmp/wan.pcap

# 在 LAN 网桥
tcpdump -i br-lan -w /tmp/lan.pcap
```

### 检查路由

```bash
ip route show
ip rule show
```

### DNS 问题

```bash
# 检查 DNS 解析
dig @127.0.0.1 google.com

# 检查 dnsmasq
systemctl status dnsmasq
cat /etc/resolv.conf
```

## 获取帮助

1. 检查日志: `journalctl -xe`
2. 查看 wiki: [[Modules]] 获取模块相关帮助
3. GitHub Issues: [报告 bug](https://github.com/CyberMind-FR/secubox-deb/issues)

## 另请参阅

- [[Configuration]] — 配置参考
- [[Installation]] — 安装指南
- [[ARM-Installation]] — ARM 相关问题
- [[ESPRESSObin]] — ESPRESSObin 专用指南
