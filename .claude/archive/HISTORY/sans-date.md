## Project Statistics

| Metric | Value |
|--------|-------|
| Debian packages | 61 |
| API endpoints | ~1200+ |
| OpenWRT packages (total) | 103 |
| Remaining to port | 46 |
| Phases completed | 7 of 10 (Phase 8: 9/21) |
| Current release | v1.4.0 |
| Target completion | Phases 8-10 remaining |

### Session 99 (continued) — MOCHAbin Migration Execution

**Date:** 2026-05-06

**Completed:**
1. ✅ Exported from C3BOX:
   - 93 SSL certificates
   - 99 nginx secubox.d configs
   - HAProxy config
   - 4 LXC container configs
   - Error pages (400, 403, 408, 500, 502, 503, 504)

2. ✅ Transferred to MOCHAbin (192.168.255.1)

3. ✅ HAProxy configured:
   - All 93 SSL certs in `/data/haproxy/certs/`
   - LXC routing: gitea, nextcloud, mail, matrix
   - Default backend: nginx_vhosts (port 9080)
   - All backends UP

4. ✅ Nginx configured:
   - Default 503 server for unknown domains
   - WebUI served only for specific hostnames
   - 99 module API configs in secubox.d

5. ✅ CTL tools deployed:
   - 14 CTL tools copied to /usr/sbin/
   - Tools Debian-native (OpenWrt refs only in migrate commands)
   - Tested: vhostctl, metablogizerctl, crowdsecctl, streamlitctl

6. ✅ Vhost auto-creation:
   - Created `/usr/local/bin/secubox-vhost-create`
   - Supports: proxy, streamlit, static vhost types

**Verified:**
- admin.gk2.secubox.in → 200 (WebUI)
- git.maegia.tv → 200 (Gitea LXC)
- unknown.test.com → 503 (blocked)

---


7. ✅ WAF configured:
   - HAProxy ACL-based WAF active
   - Blocks: SQLi, XSS, Path Traversal, Scanners
   - Mitmproxy WAF disabled (pyOpenSSL ARM64 incompatibility)
   - Full mitmproxy WAF requires internet to install updated packages

**Test Results:**
```
Normal request:     200 ✓
SQLi attempt:       403 ✓ (blocked)
XSS attempt:        403 ✓ (blocked)
Path traversal:     403 ✓ (blocked)
Scanner UA:         403 ✓ (blocked)
```


---

