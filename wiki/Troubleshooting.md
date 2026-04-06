# SecuBox Troubleshooting

[English](Troubleshooting) | [Français](Troubleshooting-FR)

## Quick Diagnostics

```bash
# System status
secubox-status

# Check all services
systemctl status secubox-* --no-pager

# View logs
journalctl -u secubox-* -f

# Network diagnostics
secubox-netdiag
```

## Common Issues

### Cannot Access Web UI

**Symptoms:** Browser shows connection refused or timeout

**Solutions:**

1. Check nginx is running:
   ```bash
   systemctl status nginx
   systemctl restart nginx
   ```

2. Check firewall:
   ```bash
   nft list ruleset | grep 443
   ```

3. Verify IP address:
   ```bash
   ip addr show br-lan
   ```

4. Check certificate:
   ```bash
   openssl x509 -in /etc/secubox/tls/cert.pem -text -noout
   ```

### SSH Connection Refused

**Solutions:**

1. Check SSH service:
   ```bash
   systemctl status sshd
   ```

2. Check firewall allows SSH:
   ```bash
   nft list ruleset | grep 22
   ```

3. Verify listening port:
   ```bash
   ss -tlnp | grep ssh
   ```

### No Internet on LAN Clients

**Solutions:**

1. Check NAT is enabled:
   ```bash
   nft list table inet nat
   ```

2. Check IP forwarding:
   ```bash
   sysctl net.ipv4.ip_forward
   ```

3. Check DHCP server:
   ```bash
   systemctl status dnsmasq
   ```

4. Check WAN interface has IP:
   ```bash
   ip addr show eth0
   ```

### CrowdSec Not Blocking

**Solutions:**

1. Check CrowdSec is running:
   ```bash
   systemctl status crowdsec
   cscli metrics
   ```

2. Check bouncers:
   ```bash
   cscli bouncers list
   ```

3. Check decisions:
   ```bash
   cscli decisions list
   ```

### WireGuard Not Connecting

**Solutions:**

1. Check interface is up:
   ```bash
   wg show
   ```

2. Check port is open:
   ```bash
   ss -ulnp | grep 51820
   nft list ruleset | grep 51820
   ```

3. Check keys are configured:
   ```bash
   cat /etc/wireguard/wg0.conf
   ```

### High CPU/Memory Usage

**Solutions:**

1. Check what's using resources:
   ```bash
   htop
   # or
   secubox-glances
   ```

2. Check for stuck processes:
   ```bash
   ps aux --sort=-%cpu | head -10
   ```

3. On ESPRESSObin (low RAM):
   ```bash
   # Enable swap if not already
   swapon --show
   free -h
   ```

## Logs Location

| Service | Log Location |
|---------|--------------|
| System | `journalctl` |
| Nginx | `/var/log/nginx/` |
| HAProxy | `/var/log/haproxy.log` |
| CrowdSec | `cscli metrics` / `journalctl -u crowdsec` |
| SecuBox modules | `journalctl -u secubox-*` |
| Audit | `/var/log/secubox/audit.log` |

## Recovery Mode

### Via Serial Console (ARM)

1. Connect serial console (115200 8N1)
2. Boot and interrupt U-Boot
3. Boot to single-user mode:
   ```
   => setenv bootargs "root=LABEL=rootfs single"
   => boot
   ```

### Via GRUB (x86)

1. At GRUB menu, press `e`
2. Add `single` to kernel line
3. Press F10 to boot

### Reset to Factory Defaults

```bash
# WARNING: This resets all configuration!
secubox-factory-reset

# Or manually:
rm -rf /etc/secubox/modules/*
cp /usr/share/secubox/defaults/* /etc/secubox/
systemctl restart secubox-*
```

## Network Debugging

### Capture Traffic

```bash
# On WAN interface
tcpdump -i eth0 -w /tmp/wan.pcap

# On LAN bridge
tcpdump -i br-lan -w /tmp/lan.pcap
```

### Check Routing

```bash
ip route show
ip rule show
```

### DNS Issues

```bash
# Check DNS resolution
dig @127.0.0.1 google.com

# Check dnsmasq
systemctl status dnsmasq
cat /etc/resolv.conf
```

## Getting Help

1. Check logs: `journalctl -xe`
2. Check wiki: [[Modules]] for module-specific help
3. GitHub Issues: [Report a bug](https://github.com/CyberMind-FR/secubox-deb/issues)

## See Also

- [[Configuration]] — Configuration reference
- [[Installation]] — Installation guide
- [[ARM-Installation]] — ARM-specific issues
- [[ESPRESSObin]] — ESPRESSObin-specific guide
