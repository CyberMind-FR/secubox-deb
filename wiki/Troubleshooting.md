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

### API 502 Bad Gateway / Authentication Errors (v2.1.1 Fix)

**Symptoms:** Web UI shows "Invalid credentials", "NetworkError", or API returns 502

**Cause:** Debian bookworm ships pydantic v1, but SecuBox requires pydantic v2.

**Solutions:**

1. Upgrade Python dependencies:
   ```bash
   pip3 install --break-system-packages 'pydantic>=2.0' 'fastapi>=0.100' 'uvicorn>=0.25'
   ```

2. Restart all SecuBox services:
   ```bash
   systemctl restart secubox-hub secubox-auth secubox-system
   ```

3. Verify sockets are created:
   ```bash
   ls -la /run/secubox/*.sock
   ```

4. Check service logs:
   ```bash
   journalctl -u secubox-hub --no-pager -n 20
   ```

**Note:** This issue is fixed in v2.1.1+ builds. Upgrade your image or run the pip command above.

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

### DSA Switch Detection Loop (ESPRESSObin)

**Symptoms:** Boot log shows repeated messages:
```
mv88e6085 d0032004.mdio-mii:01: switch 0x3410 detected: Marvell 88E6341, revision 0
hwmon hwmon0: temp1_input not attached to any thermal zone
```

This is a known issue with the Marvell 88E6341 DSA (Distributed Switch Architecture) driver on some ESPRESSObin boards.

**Solutions:**

1. **Boot with DSA disabled** (select option 2 in boot menu):
   - At boot menu, select "Live Boot + No DSA Switch"
   - This adds `modprobe.blacklist=mv88e6xxx,dsa_core` to boot args

2. **Manually blacklist the driver**:
   ```bash
   echo "blacklist mv88e6xxx" | sudo tee /etc/modprobe.d/no-dsa.conf
   echo "blacklist dsa_core" | sudo tee -a /etc/modprobe.d/no-dsa.conf
   sudo update-initramfs -u
   ```

3. **Use a different DTB**:
   - Some DTB variants handle the switch differently
   - Try `armada-3720-espressobin.dtb` instead of v7 variant

4. **Kernel parameters** (add to cmdline):
   ```
   mv88e6xxx.blacklist=1
   ```

**Note:** Disabling DSA means you lose the hardware switch functionality. The LAN ports will not work as a switch but can still be configured as individual interfaces.

### Boot Stuck or Kernel Panic

**Symptoms:** Boot hangs or shows panic after loading kernel

**Solutions:**

1. Connect serial console (115200 8N1) to see actual error
2. Try different DTB variants from boot menu
3. Increase rootdelay: add `rootdelay=15` to boot args
4. Boot with minimal options:
   ```
   root=/dev/sda2 rootwait console=ttyMV0,115200 single
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
