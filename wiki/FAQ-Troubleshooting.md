# SecuBox FAQ & Troubleshooting

Quick solutions to common issues. **For the latest fixes, always check [GitHub Issues](https://github.com/CyberMind-FR/secubox-deb/issues)** - community-reported problems often have solutions there before documentation is updated.

---

## Quick Links

- **GitHub Issues (check here first!)**: https://github.com/CyberMind-FR/secubox-deb/issues
- **Known Bugs Label**: https://github.com/CyberMind-FR/secubox-deb/issues?q=label%3Abug
- **Wiki Home**: [Home](Home.md)

---

## VirtualBox Issues

### Kiosk doesn't start / "No usable sandbox" error

**Symptom**: Chromium fails with sandbox error, kiosk service keeps restarting.

**Solution**: The VirtualBox image includes a fix for this. If using an older image:

```bash
# SSH into VM
ssh -p 2222 root@localhost   # password: secubox

# Add --no-sandbox flag
echo '--disable-gpu --disable-gpu-compositing --disable-software-rasterizer --no-sandbox' > /home/secubox-kiosk/.chromium-gpu-flags
chown secubox-kiosk:secubox-kiosk /home/secubox-kiosk/.chromium-gpu-flags
systemctl restart secubox-kiosk
```

**Related Issue**: [#34](https://github.com/CyberMind-FR/secubox-deb/issues/34)

### VM tries PXE boot instead of disk

**Symptom**: VirtualBox attempts network boot.

**Solution**: Disable network boot or ensure disk is first in boot order:
```bash
VBoxManage modifyvm "SecuBox" --boot1 disk --boot2 none --boot3 none --boot4 none
```

### WebUI not accessible via port forward

**Symptom**: https://localhost:9443 doesn't connect.

**Solution**: nginx listens on port 443, not 9443. Fix port forwarding:
```bash
VBoxManage controlvm "SecuBox" natpf1 delete https 2>/dev/null
VBoxManage controlvm "SecuBox" natpf1 "https,tcp,,9443,,443"
```

---

## Authentication Issues

### Login fails with "Invalid credentials"

**Default credentials**:
- **WebUI**: `admin` / `secubox` (NOT root)
- **SSH**: `root` / `secubox`

### Menu/Sidebar fails to load ("Invalid menu data")

**Symptom**: After login, sidebar shows error, pages don't load.

**Cause**: The menu endpoint required JWT authentication, but the sidebar loads before user login.

**Status**: ✅ **FIXED** in v1.7.1+ (commit `b2c9f01`)

**Resolution**:
1. Added public menu endpoint at `/api/v1/hub/public/menu` (no auth required)
2. Fixed Pydantic 1.x compatibility: changed `HTTPAuthorizationCredentials = Depends()` to `Optional[HTTPAuthorizationCredentials] = Depends()`
3. Updated `sidebar.js` to use the public menu endpoint

**If running older version**, update packages:
```bash
apt update && apt install secubox-hub secubox-core
systemctl restart secubox-hub
```

See [#34](https://github.com/CyberMind-FR/secubox-deb/issues/34) for full discussion.

---

## Network Issues

### No IP address after boot

**Check DHCP**:
```bash
# Inside SecuBox
ip addr show
dhclient -v enp0s3    # or appropriate interface
```

**Check NetworkManager vs systemd-networkd**:
```bash
systemctl status NetworkManager
systemctl status systemd-networkd
```

### Bridged mode shows wrong subnet

**Symptom**: VM gets IP from different network (e.g., 10.x instead of 192.168.x).

**Solution**: Verify bridge adapter in VirtualBox settings matches your host interface.

---

## Service Issues

### coturn.service keeps failing

**Symptom**: Boot shows repeated coturn failures.

**Solution**: Disable if not using TURN/STUN:
```bash
systemctl disable coturn
systemctl mask coturn
```

### secubox-hub socket not created

**Symptom**: API returns 502 Bad Gateway, `/run/secubox/hub.sock` missing.

**Workaround**: Service was switched to TCP binding. If you have an old image:
```bash
# Update service to use TCP
sed -i 's/--uds.*sock/--host 127.0.0.1 --port 8001/' /lib/systemd/system/secubox-hub.service
systemctl daemon-reload
systemctl restart secubox-hub
```

---

## Hardware-Specific Issues

### ESPRESSObin / MOCHAbin

See [Board-Specific-Notes.md](Board-Specific-Notes.md)

### AMD64 / Bare Metal

- Ensure UEFI boot mode (GPT partition table)
- For kiosk: verify X11/DRM drivers are loaded

---

## Getting Help

1. **Check GitHub Issues first**: https://github.com/CyberMind-FR/secubox-deb/issues
2. **Search closed issues** for solutions already found
3. **Create new issue** with:
   - SecuBox version (`cat /etc/secubox/version`)
   - Board type
   - Full error messages
   - Steps to reproduce

---

## See Also

- [VirtualBox-Setup.md](VirtualBox-Setup.md)
- [Installation-Guide.md](Installation-Guide.md)
- [API-Reference.md](API-Reference.md)
