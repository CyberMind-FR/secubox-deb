<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Migration: OpenWrt to Debian (Big Bang)

**Date:** 2026-05-05
**Status:** Approved
**Author:** Claude + Gérald Kerma

---

## Overview

Full replacement migration from OpenWrt-based C3BOX (192.168.255.1) to SecuBox-DEB Debian system (192.168.255.10). Target becomes the primary internet gateway.

### Systems

| Role | Current IP | OS | Hardware |
|------|------------|----|---------|
| **Source** | 192.168.255.1 | OpenWrt 24.10.5 | MOCHAbin (C3BOX) |
| **Target** | 192.168.255.10 → .1 | Debian 12 bookworm | MOCHAbin (SecuBox-DEB) |

### Key Decisions

| Aspect | Decision |
|--------|----------|
| Migration type | Big Bang — full prep, single cutover |
| Downtime tolerance | Flexible — no time pressure |
| Data scope | Service data only (no media libraries) |
| Container technology | LXC only (no Docker) |
| LXC storage | /data (916GB SSD) |
| MUSIC drive (1.8TB) | Physically move post-cutover |
| DNS | Static IP on Freebox, no changes needed |

### Day 1 Services

**Gateway (host-native):**
- Firewall (nftables)
- NAT
- DHCP (dnsmasq)
- DNS
- HAProxy + 94 SSL certs
- CrowdSec

**Core Apps (LXC containers):**
- Mail (Postfix/Dovecot with mailboxes)
- NextCloud
- Matrix (Synapse)
- Gitea

**Phase 2 (later):**
- Jellyfin, PeerTube, Jitsi, and other media apps

---

## Phase 1: Prepare

Configure target infrastructure before any migration.

### 1.1 LXC Storage Pool

```bash
# Create LXC directory structure on /data
mkdir -p /data/lxc
mkdir -p /data/volumes/{mail,nextcloud,matrix,gitea}
mkdir -p /data/haproxy/{certs,config}
mkdir -p /data/crowdsec
mkdir -p /data/backups
mkdir -p /data/music  # Mount point for later

# Configure LXC to use /data/lxc
# /etc/lxc/lxc.conf
lxc.lxcpath = /data/lxc
```

### 1.2 LXC Network Bridge

```yaml
# /etc/netplan/10-lxc-bridge.yaml
network:
  version: 2
  bridges:
    br-lxc:
      addresses:
        - 10.100.0.1/24
      mtu: 1500
```

### 1.3 Gateway Netplan (ready for cutover)

```yaml
# /etc/netplan/01-secubox-gateway.yaml (applied at cutover)
network:
  version: 2
  ethernets:
    eth0:  # WAN
      dhcp4: true
    eth2:  # WAN secondary (if needed)
      dhcp4: true
      optional: true
  bridges:
    br-lan:
      interfaces: [lan0, lan1, lan2, lan3]
      addresses:
        - 192.168.255.1/24
    br-lxc:
      addresses:
        - 10.100.0.1/24
```

### 1.4 nftables Rules

Prepare firewall rules for gateway role:
- Default DROP on input/forward
- Allow established/related
- NAT for LAN → WAN
- Port forwards for mail (25,465,587,993,995) → mail LXC
- Port forward 2222 → gitea LXC SSH

### 1.5 Verify Host Services

Ensure these are installed and configured:
- HAProxy (for reverse proxy)
- CrowdSec + firewall-bouncer
- dnsmasq (DHCP + DNS)
- All 87 secubox-* services operational

---

## Phase 2: Build

Create LXC containers and install services.

### 2.1 Storage Layout

```
/data/
├── lxc/                          # LXC container rootfs
│   ├── mail/
│   ├── nextcloud/
│   ├── matrix/
│   └── gitea/
├── volumes/                      # Persistent data (bind-mounted)
│   ├── mail/
│   │   ├── vmail/                # Mailboxes
│   │   ├── config/               # Postfix/Dovecot configs
│   │   └── ssl/                  # Mail SSL certs
│   ├── nextcloud/
│   │   ├── data/                 # User files
│   │   ├── config/               # NextCloud config
│   │   └── db/                   # MariaDB data
│   ├── matrix/
│   │   ├── data/                 # Synapse data + media
│   │   └── db/                   # PostgreSQL data
│   └── gitea/
│       ├── repos/                # Git repositories
│       ├── data/                 # Gitea data
│       └── db/                   # Database
├── haproxy/
│   ├── certs/                    # 94 SSL certificates
│   └── config/                   # HAProxy configs
├── crowdsec/                     # CrowdSec data
├── backups/                      # Migration backups
└── music/                        # MUSIC drive mount (post-cutover)
```

### 2.2 LXC Container Specifications

| Container | IP | Base | Services | Bind Mounts |
|-----------|-----|------|----------|-------------|
| mail | 10.100.0.10 | Debian 12 | Postfix, Dovecot, OpenDKIM | /data/volumes/mail/* |
| nextcloud | 10.100.0.20 | Debian 12 | Apache, PHP-FPM, MariaDB | /data/volumes/nextcloud/* |
| matrix | 10.100.0.30 | Debian 12 | Synapse, PostgreSQL | /data/volumes/matrix/* |
| gitea | 10.100.0.40 | Debian 12 | Gitea, SQLite/PostgreSQL | /data/volumes/gitea/* |

### 2.3 LXC Creation Template

```bash
# Example for mail container
lxc-create -n mail -t download -- -d debian -r bookworm -a arm64

# Configure container
cat > /data/lxc/mail/config << 'EOF'
lxc.include = /usr/share/lxc/config/debian.common.conf
lxc.arch = linux64
lxc.rootfs.path = dir:/data/lxc/mail/rootfs
lxc.uts.name = mail

# Network (br-lxc, mail ports via nftables DNAT)
lxc.net.0.type = veth
lxc.net.0.link = br-lxc
lxc.net.0.flags = up
lxc.net.0.ipv4.address = 10.100.0.10/24
lxc.net.0.ipv4.gateway = 10.100.0.1

# Bind mounts
lxc.mount.entry = /data/volumes/mail/vmail var/vmail none bind 0 0
lxc.mount.entry = /data/volumes/mail/config etc/mail-config none bind 0 0
lxc.mount.entry = /data/volumes/mail/ssl etc/ssl/mail none bind 0 0

# Unprivileged
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536
EOF
```

### 2.4 HAProxy Configuration

Convert OpenWrt HAProxy vhosts to Debian format:
- Frontend: 80 (redirect), 443 (SSL termination)
- SNI-based routing to backends
- Backend pools for each LXC container

### 2.5 Port Exposure

| Port | Protocol | Destination | Method |
|------|----------|-------------|--------|
| 80 | TCP | HAProxy | Direct |
| 443 | TCP | HAProxy | Direct |
| 25 | TCP | mail LXC | nftables DNAT |
| 465 | TCP | mail LXC | nftables DNAT |
| 587 | TCP | mail LXC | nftables DNAT |
| 993 | TCP | mail LXC | nftables DNAT |
| 995 | TCP | mail LXC | nftables DNAT |
| 8448 | TCP | matrix LXC | HAProxy |
| 22 | TCP | Host SSH | Direct |
| 2222 | TCP | gitea LXC | nftables DNAT |

---

## Phase 3: Sync

Copy data from source to target.

### 3.1 Migration Order

1. SSL certificates (required first)
2. HAProxy config (adapt vhosts)
3. CrowdSec data (security baseline)
4. Gitea (simplest LXC app)
5. NextCloud (medium complexity)
6. Matrix (federation complexity)
7. Mail (most critical, last)

### 3.2 SSL Certificates

```bash
# From source
rsync -avz --progress \
  root@192.168.255.1:/opt/haproxy/certs/*.pem \
  /data/haproxy/certs/
```

### 3.3 CrowdSec

```bash
# Sync decisions and config
rsync -avz root@192.168.255.1:/srv/crowdsec/ /data/crowdsec/

# Adapt paths for Debian
# Reconfigure bouncer for nftables
```

### 3.4 Mail

```bash
# Mailboxes (CRITICAL - largest dataset)
rsync -avz --progress \
  root@192.168.255.1:/srv/mailserver/vmail/ \
  /data/volumes/mail/vmail/

# Configs
rsync -avz \
  root@192.168.255.1:/srv/mailserver/config/ \
  /data/volumes/mail/config/

# Adapt configs for LXC paths
# Update postfix main.cf, dovecot.conf
```

### 3.5 NextCloud

```bash
# Data files
rsync -avz --progress \
  root@192.168.255.1:/srv/nextcloud/data/ \
  /data/volumes/nextcloud/data/

# Config
rsync -avz \
  root@192.168.255.1:/srv/nextcloud/config/ \
  /data/volumes/nextcloud/config/

# Database
ssh root@192.168.255.1 "mysqldump -u root nextcloud" > /tmp/nextcloud.sql
# Import in LXC:
lxc-attach -n nextcloud -- mysql -u root nextcloud < /tmp/nextcloud.sql

# Update config.php: trusted_domains, datadirectory
```

### 3.6 Matrix

```bash
# Synapse data + media
rsync -avz --progress \
  root@192.168.255.1:/srv/matrix/data/ \
  /data/volumes/matrix/data/

# PostgreSQL dump
ssh root@192.168.255.1 "pg_dump -U synapse synapse" > /tmp/synapse.sql
# Import in LXC:
lxc-attach -n matrix -- sudo -u postgres psql synapse < /tmp/synapse.sql
```

### 3.7 Gitea

```bash
# Repositories (CRITICAL)
rsync -avz --progress \
  root@192.168.255.1:/srv/gitea/repos/ \
  /data/volumes/gitea/repos/

# Data and config
rsync -avz \
  root@192.168.255.1:/srv/gitea/data/ \
  /data/volumes/gitea/data/

# Database (if PostgreSQL)
ssh root@192.168.255.1 "pg_dump -U gitea gitea" > /tmp/gitea.sql
# Import in LXC
```

---

## Phase 4: Cutover

Execute the switchover.

### 4.1 Pre-Cutover Checklist

- [ ] All LXC containers created and start successfully
- [ ] All data synced (verify file counts/sizes)
- [ ] HAProxy config valid (`haproxy -c -f /etc/haproxy/haproxy.cfg`)
- [ ] All 94 SSL certs loaded
- [ ] CrowdSec running, bouncer active
- [ ] nftables rules tested
- [ ] Netplan gateway config ready
- [ ] Each service tested via /etc/hosts override
- [ ] Backup of source created

### 4.2 Cutover Steps

```
STEP 1: FINAL SYNC
────────────────────────────────────────────────
# Stop writes on source (optional, safer)
ssh root@192.168.255.1 "systemctl stop haproxy"

# Final rsync for all data
rsync -avz --delete root@192.168.255.1:/srv/mailserver/vmail/ /data/volumes/mail/vmail/
# Repeat for other services

# Fresh database dumps
ssh root@192.168.255.1 "mysqldump nextcloud" > /tmp/nc-final.sql
ssh root@192.168.255.1 "pg_dump synapse" > /tmp/matrix-final.sql
# Import into LXC containers


STEP 2: STOP SOURCE SERVICES
────────────────────────────────────────────────
ssh root@192.168.255.1 << 'EOF'
  /etc/init.d/haproxy stop
  /etc/init.d/postfix stop
  /etc/init.d/dovecot stop
  # Stop other services...
EOF


STEP 3: NETWORK CUTOVER
────────────────────────────────────────────────
# Physical: Unplug WAN cable from source, plug into target

# On target: Apply gateway netplan
cp /etc/netplan/01-secubox-gateway.yaml.ready /etc/netplan/01-secubox-gateway.yaml
netplan apply

# Verify WAN IP from Freebox (may take 1-5 min)
ip addr show eth0

# Verify LAN is now .1
ip addr show br-lan


STEP 4: START SERVICES
────────────────────────────────────────────────
# Start LXC containers
lxc-start -n mail
lxc-start -n nextcloud
lxc-start -n matrix
lxc-start -n gitea

# Verify HAProxy
systemctl restart haproxy
systemctl status haproxy

# Verify CrowdSec
systemctl status crowdsec
cscli decisions list


STEP 5: VERIFICATION
────────────────────────────────────────────────
# Test from external network (phone 4G):

# Mail
- Send email to hosted address
- Check delivery
- Send email from hosted address

# NextCloud
- Login via browser
- Upload/download file

# Matrix
- Login to Element
- Send message
- Check federation (message to external server)

# Gitea
- Clone repository via HTTPS
- Clone repository via SSH (port 2222)
- Push a commit


STEP 6: POST-CUTOVER
────────────────────────────────────────────────
# After 24-48h stable operation:

# Physically move MUSIC drive
# - Shutdown target
# - Connect drive
# - Boot target
# - Mount drive (replace sdX1 with actual device)
blkid  # Find the MUSIC drive UUID
mount /dev/sdX1 /data/music

# Add to fstab (use actual UUID from blkid output)
echo "UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx /data/music ext4 defaults 0 2" >> /etc/fstab
```

### 4.3 Rollback Procedure

If critical issues occur:

```bash
# 1. Unplug WAN from target
# 2. Plug WAN back into source
# 3. Start source services
ssh root@192.168.255.1 << 'EOF'
  /etc/init.d/haproxy start
  /etc/init.d/postfix start
  /etc/init.d/dovecot start
  # etc.
EOF

# 4. Debug target issues
# 5. Re-attempt cutover when fixed
```

---

## Success Criteria

### Day 1 Pass/Fail

| Service | Test | Pass Criteria |
|---------|------|---------------|
| Internet | LAN client browses web | Pages load |
| Firewall | Port scan from WAN | Only expected ports open |
| DHCP | LAN client gets IP | 192.168.255.x, gateway .1 |
| DNS | Resolve internal + external | Both work |
| HAProxy | curl any domain | Valid SSL, correct backend |
| CrowdSec | Dashboard check | Decisions loaded, bouncer active |
| Mail | Send + receive | Delivery both directions |
| NextCloud | Login + file ops | Auth + storage work |
| Matrix | Login + message | Local + federation work |
| Gitea | Clone + push | SSH + HTTPS work |

### Monitoring (post-cutover)

| Check | Frequency | Tool |
|-------|-----------|------|
| Service status | 5 min | secubox-watchdog |
| SSL expiry | Daily | certbot |
| Disk space | Hourly | Glances |
| CrowdSec alerts | Real-time | Dashboard |
| Mail queue | Hourly | postqueue |

---

## Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Data loss during sync | Low | High | Final sync with services stopped |
| Mail delivery issues | Medium | High | Test MX before cutover, monitor queue |
| SSL cert mismatch | Low | Medium | Copy all 94, verify HAProxy loads |
| LXC network issues | Medium | Medium | Test br-lxc before cutover |
| Freebox DHCP delay | Low | Low | Allow 5 min for WAN IP |
| Matrix federation break | Medium | Medium | Test federation before cutover |

---

## Appendix: Service Inventory

### Source Services to Migrate (Day 1)

| Service | Source Path | Container | Priority |
|---------|-------------|-----------|----------|
| HAProxy | /opt/haproxy/ | Host | P1 |
| CrowdSec | /srv/crowdsec/ | Host | P1 |
| Mail | /srv/mailserver/ | mail LXC | P1 |
| NextCloud | /srv/nextcloud/ | nextcloud LXC | P1 |
| Matrix | /srv/matrix/ | matrix LXC | P1 |
| Gitea | /srv/gitea/ | gitea LXC | P1 |

### Source Services for Phase 2 (Later)

| Service | Source Path | Notes |
|---------|-------------|-------|
| Jellyfin | /srv/jellyfin/ | Media server |
| PeerTube | /srv/peertube/ | Video platform |
| Jitsi | /srv/jitsi/ | Video conferencing |
| GoToSocial | /srv/gotosocial/ | Fediverse |
| Domoticz | /srv/domoticz/ | Home automation |
| And ~50 more... | Various | Migrate as needed |

---

## Document History

| Date | Author | Changes |
|------|--------|---------|
| 2026-05-05 | Claude + GK | Initial design |
